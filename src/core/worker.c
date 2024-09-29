/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This module coordinates processing for operations. The operations for a
    given connection are processed by a single thread, and connections are
    distributed over the set of available processors to balance the work.

    A "worker" maintains a queue of connections (each of which has a queue of
    operations to be processed), a queue of stateless operations and a timer
    wheel containing all the connections assigned to this worker that have
    active timers running.

    Each connection is assigned to a single worker, and is queued whenever it
    has operations to be processed.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "worker.c.clog.h"
#endif

BOOLEAN
QuicWorkerLoop(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

//
// Thread callback for processing the work queued for the worker.
//
CXPLAT_THREAD_CALLBACK(QuicWorkerThread, Context);

void
QuicWorkerThreadWake(
    _In_ QUIC_WORKER* Worker
    )
{
    Worker->ExecutionContext.Ready = TRUE; // Run the execution context
    if (Worker->IsExternal) {
        CxPlatWakeExecutionContext(&Worker->ExecutionContext);
    } else {
        CxPlatEventSet(Worker->Ready);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerUninitialize(
    _In_ QUIC_WORKER* Worker
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicWorkerInitialize(
    _In_ const QUIC_REGISTRATION* Registration,
    _In_ QUIC_EXECUTION_PROFILE ExecProfile,
    _In_ uint16_t PartitionIndex,
    _Inout_ QUIC_WORKER* Worker
    )
{
    QuicTraceEvent(
        WorkerCreated,
        "[wrkr][%p] Created, IdealProc=%hu Owner=%p",
        Worker,
        QuicLibraryGetPartitionProcessor(PartitionIndex),
        Registration);

    Worker->Enabled = TRUE;
    Worker->PartitionIndex = PartitionIndex;
    CxPlatDispatchLockInitialize(&Worker->Lock);
    CxPlatEventInitialize(&Worker->Done, TRUE, FALSE);
    CxPlatEventInitialize(&Worker->Ready, FALSE, FALSE);
    CxPlatListInitializeHead(&Worker->Connections);
    Worker->PriorityConnectionsTail = &Worker->Connections.Flink;
    CxPlatListInitializeHead(&Worker->Operations);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_STREAM), QUIC_POOL_STREAM, &Worker->StreamPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_RECV_CHUNK)+QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE, QUIC_POOL_SBUF, &Worker->DefaultReceiveBufferPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_SEND_REQUEST), QUIC_POOL_SEND_REQUEST, &Worker->SendRequestPool);
    QuicSentPacketPoolInitialize(&Worker->SentPacketPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_API_CONTEXT), QUIC_POOL_API_CTX, &Worker->ApiContextPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_STATELESS_CONTEXT), QUIC_POOL_STATELESS_CTX, &Worker->StatelessContextPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_OPERATION), QUIC_POOL_OPER, &Worker->OperPool);

    QUIC_STATUS Status = QuicTimerWheelInitialize(&Worker->TimerWheel);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Worker->ExecutionContext.Context = Worker;
    Worker->ExecutionContext.Callback = QuicWorkerLoop;
    Worker->ExecutionContext.NextTimeUs = UINT64_MAX;
    Worker->ExecutionContext.Ready = TRUE;

#ifndef _KERNEL_MODE // Not supported on kernel mode
    if (ExecProfile != QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT) {
        Worker->IsExternal = TRUE;
        CxPlatAddExecutionContext(&MsQuicLib.WorkerPool, &Worker->ExecutionContext, PartitionIndex);
    } else
#endif // _KERNEL_MODE
    {
        uint16_t ThreadFlags;
        switch (ExecProfile) {
        default:
        case QUIC_EXECUTION_PROFILE_LOW_LATENCY:
        case QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT:
            ThreadFlags = CXPLAT_THREAD_FLAG_SET_IDEAL_PROC;
            break;
        case QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER:
            ThreadFlags = CXPLAT_THREAD_FLAG_NONE;
            break;
        case QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME:
            ThreadFlags = CXPLAT_THREAD_FLAG_SET_AFFINITIZE | CXPLAT_THREAD_FLAG_HIGH_PRIORITY;
            break;
        }

        if (MsQuicLib.ExecutionConfig && MsQuicLib.ExecutionConfig->Flags & QUIC_EXECUTION_CONFIG_FLAG_HIGH_PRIORITY) {
            ThreadFlags |= CXPLAT_THREAD_FLAG_HIGH_PRIORITY;
        }

        CXPLAT_THREAD_CONFIG ThreadConfig = {
            ThreadFlags,
            QuicLibraryGetPartitionProcessor(PartitionIndex),
            "quic_worker",
            QuicWorkerThread,
            Worker
        };

        Status = CxPlatThreadCreate(&ThreadConfig, &Worker->Thread);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                WorkerErrorStatus,
                "[wrkr][%p] ERROR, %u, %s.",
                Worker,
                Status,
                "CxPlatThreadCreate");
            goto Error;
        }
    }

Error:

    if (QUIC_FAILED(Status)) {
        CxPlatEventSet(Worker->Done);
        QuicWorkerUninitialize(Worker);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerUninitialize(
    _In_ QUIC_WORKER* Worker
    )
{
    QuicTraceEvent(
        WorkerCleanup,
        "[wrkr][%p] Cleaning up",
        Worker);

    //
    // Clean up the worker execution context.
    //
    Worker->Enabled = FALSE;
    if (Worker->ExecutionContext.Context) {
        QuicWorkerThreadWake(Worker);
        CxPlatEventWaitForever(Worker->Done);
    }
    CxPlatEventUninitialize(Worker->Done);

    if (!Worker->IsExternal) {
        //
        // Wait for the thread to finish.
        //
        if (Worker->Thread) {
            CxPlatThreadWait(&Worker->Thread);
            CxPlatThreadDelete(&Worker->Thread);
        }
    }
    CxPlatEventUninitialize(Worker->Ready);

    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Worker->Connections));
    Worker->PriorityConnectionsTail = NULL;
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Worker->Operations));

    CxPlatPoolUninitialize(&Worker->StreamPool);
    CxPlatPoolUninitialize(&Worker->DefaultReceiveBufferPool);
    CxPlatPoolUninitialize(&Worker->SendRequestPool);
    QuicSentPacketPoolUninitialize(&Worker->SentPacketPool);
    CxPlatPoolUninitialize(&Worker->ApiContextPool);
    CxPlatPoolUninitialize(&Worker->StatelessContextPool);
    CxPlatPoolUninitialize(&Worker->OperPool);
    CxPlatDispatchLockUninitialize(&Worker->Lock);
    QuicTimerWheelUninitialize(&Worker->TimerWheel);

    QuicTraceEvent(
        WorkerDestroyed,
        "[wrkr][%p] Destroyed",
        Worker);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerAssignConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(Connection->Worker != Worker);
    Connection->Worker = Worker;
    QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Worker);
}

BOOLEAN
QuicWorkerIsIdle(
    _In_ const QUIC_WORKER* Worker
    )
{
    return
        CxPlatListIsEmpty(&Worker->Connections) &&
        CxPlatListIsEmpty(&Worker->Operations);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueueConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(Connection->Worker != NULL);
    BOOLEAN ConnectionQueued = FALSE;
    BOOLEAN WakeWorkerThread = FALSE;

    CxPlatDispatchLockAcquire(&Worker->Lock);

    if (!Connection->WorkerProcessing && !Connection->HasQueuedWork) {
        WakeWorkerThread = QuicWorkerIsIdle(Worker);
        Connection->Stats.Schedule.LastQueueTime = CxPlatTimeUs32();
        QuicTraceEvent(
            ConnScheduleState,
            "[conn][%p] Scheduling: %u",
            Connection,
            QUIC_SCHEDULE_QUEUED);
        QuicConnAddRef(Connection, QUIC_CONN_REF_WORKER);
        CxPlatListInsertTail(&Worker->Connections, &Connection->WorkerLink);
        ConnectionQueued = TRUE;
    }

    Connection->HasQueuedWork = TRUE;

    CxPlatDispatchLockRelease(&Worker->Lock);

    if (ConnectionQueued) {
        if (WakeWorkerThread) {
            QuicWorkerThreadWake(Worker);
        }
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueuePriorityConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(Connection->Worker != NULL);
    BOOLEAN ConnectionQueued = FALSE;
    BOOLEAN WakeWorkerThread = FALSE;

    CxPlatDispatchLockAcquire(&Worker->Lock);

    if (!Connection->WorkerProcessing && !Connection->HasPriorityWork) {
        if (!Connection->HasQueuedWork) { // Not already queued for normal priority work
            WakeWorkerThread = QuicWorkerIsIdle(Worker);
            Connection->Stats.Schedule.LastQueueTime = CxPlatTimeUs32();
            QuicTraceEvent(
                ConnScheduleState,
                "[conn][%p] Scheduling: %u",
                Connection,
                QUIC_SCHEDULE_QUEUED);
            QuicConnAddRef(Connection, QUIC_CONN_REF_WORKER);
            ConnectionQueued = TRUE;
        } else { // Moving from normal priority to high priority
            CxPlatListEntryRemove(&Connection->WorkerLink);
        }
        CxPlatListInsertTail(*Worker->PriorityConnectionsTail, &Connection->WorkerLink);
        Worker->PriorityConnectionsTail = &Connection->WorkerLink.Flink;
        Connection->HasPriorityWork = TRUE;
    }

    Connection->HasQueuedWork = TRUE;

    CxPlatDispatchLockRelease(&Worker->Lock);

    if (ConnectionQueued) {
        if (WakeWorkerThread) {
            QuicWorkerThreadWake(Worker);
        }
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerMoveConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsPriority
    )
{
    CXPLAT_DBG_ASSERT(Connection->Worker != NULL);
    CXPLAT_DBG_ASSERT(Connection->HasQueuedWork);

    CxPlatDispatchLockAcquire(&Worker->Lock);

    const BOOLEAN WakeWorkerThread = QuicWorkerIsIdle(Worker);
    Connection->Stats.Schedule.LastQueueTime = CxPlatTimeUs32();
    if (IsPriority) {
        CxPlatListInsertTail(*Worker->PriorityConnectionsTail, &Connection->WorkerLink);
        Worker->PriorityConnectionsTail = &Connection->WorkerLink.Flink;
        Connection->HasPriorityWork = TRUE;
    } else {
        CxPlatListInsertTail(&Worker->Connections, &Connection->WorkerLink);
    }
    QuicTraceEvent(
        ConnScheduleState,
        "[conn][%p] Scheduling: %u",
        Connection,
        QUIC_SCHEDULE_QUEUED);
    QuicConnAddRef(Connection, QUIC_CONN_REF_WORKER);

    CxPlatDispatchLockRelease(&Worker->Lock);

    if (WakeWorkerThread) {
        QuicWorkerThreadWake(Worker);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerQueueOperation(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_OPERATION* Operation
    )
{
    CxPlatDispatchLockAcquire(&Worker->Lock);

    BOOLEAN WakeWorkerThread;
    if (Worker->OperationCount < MsQuicLib.Settings.MaxStatelessOperations &&
        QuicLibraryTryAddRefBinding(Operation->STATELESS.Context->Binding)) {
        Operation->STATELESS.Context->HasBindingRef = TRUE;
        WakeWorkerThread = QuicWorkerIsIdle(Worker);
        CxPlatListInsertTail(&Worker->Operations, &Operation->Link);
        Worker->OperationCount++;
        Operation = NULL;
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH);
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_WORK_OPER_QUEUED);
    } else {
        WakeWorkerThread = FALSE;
        Worker->DroppedOperationCount++;
    }

    CxPlatDispatchLockRelease(&Worker->Lock);

    if (Operation != NULL) {
        const QUIC_BINDING* Binding = Operation->STATELESS.Context->Binding;
        const QUIC_RX_PACKET* Packet = Operation->STATELESS.Context->Packet;
        QuicPacketLogDrop(Binding, Packet, "Worker operation limit reached");
        QuicOperationFree(Worker, Operation);
    } else if (WakeWorkerThread) {
        QuicWorkerThreadWake(Worker);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerUpdateQueueDelay(
    _In_ QUIC_WORKER* Worker,
    _In_ uint32_t TimeInQueueUs
    )
{
    Worker->AverageQueueDelay = (7 * Worker->AverageQueueDelay + TimeInQueueUs) / 8;
    QuicTraceEvent(
        WorkerQueueDelayUpdated,
        "[wrkr][%p] QueueDelay = %u",
        Worker,
        Worker->AverageQueueDelay);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerResetQueueDelay(
    _In_ QUIC_WORKER* Worker
    )
{
    Worker->AverageQueueDelay = 0;
    QuicTraceEvent(
        WorkerQueueDelayUpdated,
        "[wrkr][%p] QueueDelay = %u",
        Worker,
        Worker->AverageQueueDelay);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CONNECTION*
QuicWorkerGetNextConnection(
    _In_ QUIC_WORKER* Worker
    )
{
    QUIC_CONNECTION* Connection = NULL;

    if (Worker->Enabled &&
        !CxPlatListIsEmptyNoFence(&Worker->Connections)) {
        CxPlatDispatchLockAcquire(&Worker->Lock);
        if (!CxPlatListIsEmpty(&Worker->Connections)) {
            Connection =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Worker->Connections), QUIC_CONNECTION, WorkerLink);
            if (Worker->PriorityConnectionsTail == &Connection->WorkerLink.Flink) {
                Worker->PriorityConnectionsTail = &Worker->Connections.Flink;
            }
            CXPLAT_DBG_ASSERT(!Connection->WorkerProcessing);
            CXPLAT_DBG_ASSERT(Connection->HasQueuedWork);
            Connection->HasQueuedWork = FALSE;
            Connection->HasPriorityWork = FALSE;
            Connection->WorkerProcessing = TRUE;
            QuicPerfCounterDecrement(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH);
        }
        CxPlatDispatchLockRelease(&Worker->Lock);
    }

    return Connection;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_OPERATION*
QuicWorkerGetNextOperation(
    _In_ QUIC_WORKER* Worker
    )
{
    QUIC_OPERATION* Operation = NULL;

    if (Worker->Enabled && Worker->OperationCount != 0) {
        CxPlatDispatchLockAcquire(&Worker->Lock);
        Operation =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Worker->Operations), QUIC_OPERATION, Link);
#if DEBUG
        Operation->Link.Flink = NULL;
#endif
        Worker->OperationCount--;
        QuicPerfCounterDecrement(QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH);
        CxPlatDispatchLockRelease(&Worker->Lock);
    }

    return Operation;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerProcessTimers(
    _In_ QUIC_WORKER* Worker,
    _In_ CXPLAT_THREAD_ID ThreadID,
    _In_ uint64_t TimeNow
    )
{
    //
    // Get the list of all connections with expired timers from the timer wheel.
    //
    CXPLAT_LIST_ENTRY ExpiredTimers;
    CxPlatListInitializeHead(&ExpiredTimers);
    QuicTimerWheelGetExpired(&Worker->TimerWheel, TimeNow, &ExpiredTimers);

    //
    // Indicate to all the connections that have expired timers.
    //
    while (!CxPlatListIsEmpty(&ExpiredTimers)) {
        CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&ExpiredTimers);
        Entry->Flink = NULL;

        QUIC_CONNECTION* Connection =
            CXPLAT_CONTAINING_RECORD(Entry, QUIC_CONNECTION, TimerLink);

        Connection->WorkerThreadID = ThreadID;
        QuicConfigurationAttachSilo(Connection->Configuration);
        QuicConnTimerExpired(Connection, TimeNow);
        QuicConfigurationDetachSilo();
        Connection->WorkerThreadID = 0;
        QuicConnRelease(Connection, QUIC_CONN_REF_WORKER);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerProcessConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection,
    _In_ CXPLAT_THREAD_ID ThreadID,
    _Inout_ uint64_t* TimeNow
    )
{
    QuicTraceEvent(
        ConnScheduleState,
        "[conn][%p] Scheduling: %u",
        Connection,
        QUIC_SCHEDULE_PROCESSING);
    QuicConfigurationAttachSilo(Connection->Configuration);

    if (Connection->Stats.Schedule.LastQueueTime != 0) {
        uint32_t Delay =
            CxPlatTimeDiff32(
                Connection->Stats.Schedule.LastQueueTime,
                (uint32_t)*TimeNow);
        if (Delay >= (UINT32_MAX >> 1)) {
            //
            // Since we're using a cached time (to reduce the number of calls)
            // it's possible that TimeNow is actually before LastQueueTime.
            // Account for this and just set the delay to 0 if it happens.
            //
            Delay = 0;
        }

        QuicWorkerUpdateQueueDelay(Worker, Delay);
    }

    //
    // Set the thread ID so reentrant API calls will execute inline.
    //
    Connection->WorkerThreadID = ThreadID;
    Connection->Stats.Schedule.DrainCount++;

    if (Connection->State.UpdateWorker) {
        //
        // The connection was recently placed into this worker and needs any
        // pre-existing timers to be transitioned to this worker for processing.
        //
        Connection->State.UpdateWorker = FALSE;
        QuicTimerWheelUpdateConnection(&Worker->TimerWheel, Connection);

        //
        // When the worker changes the app layer needs to be informed so that
        // it can stay in sync with the per-processor partitioning state.
        //
        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED;
        Event.IDEAL_PROCESSOR_CHANGED.IdealProcessor = QuicLibraryGetPartitionProcessor(Worker->PartitionIndex);
        Event.IDEAL_PROCESSOR_CHANGED.PartitionIndex = Worker->PartitionIndex;
        QuicTraceLogConnVerbose(
            IndicateIdealProcChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED (Proc=%hu,Indx=%hu)",
            Event.IDEAL_PROCESSOR_CHANGED.IdealProcessor,
            Event.IDEAL_PROCESSOR_CHANGED.PartitionIndex);
        (void)QuicConnIndicateEvent(Connection, &Event);
    }

    //
    // Process some operations.
    //
    BOOLEAN StillHasPriorityWork = FALSE;
    BOOLEAN StillHasWorkToDo =
        QuicConnDrainOperations(Connection, &StillHasPriorityWork) | Connection->State.UpdateWorker;
    Connection->WorkerThreadID = 0;

    //
    // Determine whether the connection needs to be requeued.
    //
    CxPlatDispatchLockAcquire(&Worker->Lock);
    Connection->WorkerProcessing = FALSE;
    Connection->HasQueuedWork |= StillHasWorkToDo;

    BOOLEAN DoneWithConnection = TRUE;
    if (!Connection->State.UpdateWorker) {
        if (Connection->HasQueuedWork) {
            Connection->Stats.Schedule.LastQueueTime = CxPlatTimeUs32();
            if (StillHasPriorityWork) {
                CxPlatListInsertTail(*Worker->PriorityConnectionsTail, &Connection->WorkerLink);
                Worker->PriorityConnectionsTail = &Connection->WorkerLink.Flink;
                Connection->HasPriorityWork = TRUE;
            } else {
                CxPlatListInsertTail(&Worker->Connections, &Connection->WorkerLink);
            }
            QuicTraceEvent(
                ConnScheduleState,
                "[conn][%p] Scheduling: %u",
                Connection,
                QUIC_SCHEDULE_QUEUED);
            DoneWithConnection = FALSE;
        } else {
            QuicTraceEvent(
                ConnScheduleState,
                "[conn][%p] Scheduling: %u",
                Connection,
                QUIC_SCHEDULE_IDLE);
        }
    }
    CxPlatDispatchLockRelease(&Worker->Lock);

    QuicConfigurationDetachSilo();

    if (DoneWithConnection) {
        if (Connection->State.UpdateWorker) {
            //
            // Now that we know we want to process this connection, assign it
            // to the correct registration. Remove it from the current worker's
            // timer wheel, and it will be added to the new one, when first
            // processed on the other worker.
            //
            QuicTimerWheelRemoveConnection(&Worker->TimerWheel, Connection);
            CXPLAT_FRE_ASSERT(Connection->Registration != NULL);
            QuicRegistrationQueueNewConnection(Connection->Registration, Connection);
            CXPLAT_DBG_ASSERT(Worker != Connection->Worker);
            QuicWorkerMoveConnection(Connection->Worker, Connection, StillHasPriorityWork);
        }

        //
        // This worker is no longer managing the connection, so we can
        // release its connection reference.
        //
        QuicConnRelease(Connection, QUIC_CONN_REF_WORKER);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerLoopCleanup(
    _In_ QUIC_WORKER* Worker
    )
{
    //
    // Because the registration layer only waits for the rundown to complete,
    // and because the connection releases the rundown on handle close,
    // not free, it's possible that the worker thread still had the connection
    // in it's list by the time clean up started. So it needs to release any
    // remaining references on connections.
    //
    int64_t Dequeue = 0;
    while (!CxPlatListIsEmpty(&Worker->Connections)) {
        QUIC_CONNECTION* Connection =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Worker->Connections), QUIC_CONNECTION, WorkerLink);
        if (Worker->PriorityConnectionsTail == &Connection->WorkerLink.Flink) {
            Worker->PriorityConnectionsTail = &Worker->Connections.Flink;
        }
        if (!Connection->State.ExternalOwner) {
            //
            // If there is no external owner, shut down the connection so
            // that it's not leaked.
            //
            QuicTraceLogConnVerbose(
                AbandonOnLibShutdown,
                Connection,
                "Abandoning on shutdown");
            QuicConnOnShutdownComplete(Connection);
        }
        QuicConnRelease(Connection, QUIC_CONN_REF_WORKER);
        --Dequeue;
    }
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH, Dequeue);

    Dequeue = 0;
    while (!CxPlatListIsEmpty(&Worker->Operations)) {
        QUIC_OPERATION* Operation =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Worker->Operations), QUIC_OPERATION, Link);
#if DEBUG
        Operation->Link.Flink = NULL;
#endif
        QuicOperationFree(Worker, Operation);
        --Dequeue;
    }
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH, Dequeue);
}

//
// Runs one iteration of the worker loop. Returns FALSE when it's time to exit.
//
BOOLEAN
QuicWorkerLoop(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    QUIC_WORKER* Worker = (QUIC_WORKER*)Context;

    if (!Worker->Enabled) {
        QuicWorkerLoopCleanup(Worker);
        CxPlatEventSet(Worker->Done);
        return FALSE;
    }

    if (!Worker->IsActive) {
        Worker->IsActive = TRUE;
        QuicTraceEvent(
            WorkerActivityStateUpdated,
            "[wrkr][%p] IsActive = %hhu, Arg = %u",
            Worker,
            Worker->IsActive,
            (uint32_t)State->TimeNow);
    }

    //
    // Opportunistically try to snap-shot performance counters and do some
    // validation.
    //
    QuicPerfCounterTrySnapShot(State->TimeNow);

    //
    // For every loop of the worker thread, in an attempt to balance things,
    // first the timer wheel is checked and any expired timers are processed.
    // Then, a single connection will be processed (if available), followed by a
    // single stateless operation (if available).
    //

    if (Worker->TimerWheel.NextExpirationTime != UINT64_MAX &&
        Worker->TimerWheel.NextExpirationTime <= State->TimeNow) {
        QuicWorkerProcessTimers(Worker, State->ThreadID, State->TimeNow);
        State->NoWorkCount = 0;
    }

    QUIC_CONNECTION* Connection = QuicWorkerGetNextConnection(Worker);
    if (Connection != NULL) {
        QuicWorkerProcessConnection(Worker, Connection, State->ThreadID, &State->TimeNow);
        Worker->ExecutionContext.Ready = TRUE;
        State->NoWorkCount = 0;
    }

    QUIC_OPERATION* Operation = QuicWorkerGetNextOperation(Worker);
    if (Operation != NULL) {
        QuicBindingProcessStatelessOperation(
            Operation->Type,
            Operation->STATELESS.Context);
        QuicOperationFree(Worker, Operation);
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_WORK_OPER_COMPLETED);
        Worker->ExecutionContext.Ready = TRUE;
        State->NoWorkCount = 0;
    }

    if (Worker->ExecutionContext.Ready) {
        //
        // There is more work to be done.
        //
        return TRUE;
    }

    if (MsQuicLib.ExecutionConfig &&
        (uint64_t)MsQuicLib.ExecutionConfig->PollingIdleTimeoutUs >
            CxPlatTimeDiff64(State->LastWorkTime, State->TimeNow)) {
        //
        // Busy loop for a while to keep the thread hot in case new work comes
        // in.
        //
        Worker->ExecutionContext.Ready = TRUE;
        return TRUE;
    }

    //
    // We have no other work to process at the moment. Wait for work to come in
    // or any timer to expire.
    //
    Worker->IsActive = FALSE;
    Worker->ExecutionContext.NextTimeUs = Worker->TimerWheel.NextExpirationTime;
    QuicTraceEvent(
        WorkerActivityStateUpdated,
        "[wrkr][%p] IsActive = %hhu, Arg = %u",
        Worker,
        Worker->IsActive,
        (uint32_t)Worker->TimerWheel.NextExpirationTime);
    QuicWorkerResetQueueDelay(Worker);
    return TRUE;
}

CXPLAT_THREAD_CALLBACK(QuicWorkerThread, Context)
{
    QUIC_WORKER* Worker = (QUIC_WORKER*)Context;
    CXPLAT_EXECUTION_CONTEXT* EC = &Worker->ExecutionContext;

    CXPLAT_EXECUTION_STATE State = {
        0, 0, 0, UINT32_MAX, 0, CxPlatCurThreadID()
    };

    QuicTraceEvent(
        WorkerStart,
        "[wrkr][%p] Start",
        Worker);

    while (TRUE) {

        ++State.NoWorkCount;
        State.TimeNow = CxPlatTimeUs64();
        if (!QuicWorkerLoop(EC, &State)) {
            break;
        }

        BOOLEAN Ready = InterlockedFetchAndClearBoolean(&EC->Ready);
        if (!Ready) {
            if (EC->NextTimeUs == UINT64_MAX) {
                CxPlatEventWaitForever(Worker->Ready);

            } else if (EC->NextTimeUs > State.TimeNow) {
                uint64_t Delay = US_TO_MS(EC->NextTimeUs - State.TimeNow) + 1;
                if (Delay >= (uint64_t)UINT32_MAX) {
                    Delay = UINT32_MAX - 1; // Max has special meaning for most platforms.
                }
                CxPlatEventWaitWithTimeout(Worker->Ready, (uint32_t)Delay);
            }
        }
        if (State.NoWorkCount == 0) {
            State.LastWorkTime = State.TimeNow;
        }
    }

    QuicTraceEvent(
        WorkerStop,
        "[wrkr][%p] Stop",
        Worker);
    CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicWorkerPoolInitialize(
    _In_ const QUIC_REGISTRATION* Registration,
    _In_ QUIC_EXECUTION_PROFILE ExecProfile,
    _Out_ QUIC_WORKER_POOL** NewWorkerPool
    )
{
    const uint16_t WorkerCount =
        ExecProfile == QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER ? 1 : MsQuicLib.PartitionCount;
    const size_t WorkerPoolSize =
        sizeof(QUIC_WORKER_POOL) + WorkerCount * sizeof(QUIC_WORKER);

    QUIC_WORKER_POOL* WorkerPool = CXPLAT_ALLOC_NONPAGED(WorkerPoolSize, QUIC_POOL_WORKER);
    if (WorkerPool == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_WORKER_POOL",
            WorkerPoolSize);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(WorkerPool, WorkerPoolSize);
    WorkerPool->WorkerCount = WorkerCount;

    //
    // Create the set of worker threads and soft affinitize them in order to
    // attempt to spread the connection workload out over multiple processors.
    //

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    for (uint16_t i = 0; i < WorkerCount; i++) {
        Status = QuicWorkerInitialize(Registration, ExecProfile, i, &WorkerPool->Workers[i]);
        if (QUIC_FAILED(Status)) {
            for (uint16_t j = 0; j < i; j++) {
                QuicWorkerUninitialize(&WorkerPool->Workers[j]);
            }
            goto Error;
        }
    }

    *NewWorkerPool = WorkerPool;

Error:

    if (QUIC_FAILED(Status)) {
        CXPLAT_FREE(WorkerPool, QUIC_POOL_WORKER);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerPoolUninitialize(
    _In_ QUIC_WORKER_POOL* WorkerPool
    )
{
    for (uint16_t i = 0; i < WorkerPool->WorkerCount; i++) {
        QuicWorkerUninitialize(&WorkerPool->Workers[i]);
    }

    CXPLAT_FREE(WorkerPool, QUIC_POOL_WORKER);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicWorkerPoolIsOverloaded(
    _In_ QUIC_WORKER_POOL* WorkerPool
    )
{
    for (uint16_t i = 0; i < WorkerPool->WorkerCount; ++i) {
        if (!QuicWorkerIsOverloaded(&WorkerPool->Workers[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicWorkerPoolGetLeastLoadedWorker(
    _In_ QUIC_WORKER_POOL* WorkerPool
    )
{
    //
    // In order to prevent bursts of calls to this function always returning
    // the same worker (because the worker's queue delay doesn't actually
    // increase until the connection is processed), we test all other workers
    // first to see if an equal or less loaded worker is available.
    //

    uint16_t Worker = (WorkerPool->LastWorker + 1) % WorkerPool->WorkerCount;
    uint64_t MinQueueDelay = WorkerPool->Workers[Worker].AverageQueueDelay;
    uint16_t MinQueueDelayWorker = Worker;

    while ((Worker != WorkerPool->LastWorker) && (MinQueueDelay > 0)) {
        Worker = (Worker + 1) % WorkerPool->WorkerCount;
        uint64_t QueueDelayTime = WorkerPool->Workers[Worker].AverageQueueDelay;
        if (QueueDelayTime < MinQueueDelay) {
            MinQueueDelay = QueueDelayTime;
            MinQueueDelayWorker = Worker;
        }
    }

    WorkerPool->LastWorker = MinQueueDelayWorker;
    return MinQueueDelayWorker;
}