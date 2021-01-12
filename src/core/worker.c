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

//
// Thread callback for processing the work queued for the worker.
//
CXPLAT_THREAD_CALLBACK(QuicWorkerThread, Context);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerUninitialize(
    _In_ QUIC_WORKER* Worker
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicWorkerInitialize(
    _In_opt_ const void* Owner,
    _In_ uint16_t ThreadFlags,
    _In_ uint16_t IdealProcessor,
    _Inout_ QUIC_WORKER* Worker
    )
{
    QUIC_STATUS Status;

    QuicTraceEvent(
        WorkerCreated,
        "[wrkr][%p] Created, IdealProc=%hu Owner=%p",
        Worker,
        IdealProcessor,
        Owner);

    Worker->Enabled = TRUE;
    Worker->IdealProcessor = IdealProcessor;
    CxPlatDispatchLockInitialize(&Worker->Lock);
    CxPlatEventInitialize(&Worker->Ready, FALSE, FALSE);
    CxPlatListInitializeHead(&Worker->Connections);
    CxPlatListInitializeHead(&Worker->Operations);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_STREAM), CXPLAT_POOL_STREAM, &Worker->StreamPool);
    CxPlatPoolInitialize(FALSE, QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE, CXPLAT_POOL_SBUF, &Worker->DefaultReceiveBufferPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_SEND_REQUEST), CXPLAT_POOL_SEND_REQUEST, &Worker->SendRequestPool);
    QuicSentPacketPoolInitialize(&Worker->SentPacketPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_API_CONTEXT), CXPLAT_POOL_API_CTX, &Worker->ApiContextPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_STATELESS_CONTEXT), CXPLAT_POOL_STATELESS_CTX, &Worker->StatelessContextPool);
    CxPlatPoolInitialize(FALSE, sizeof(QUIC_OPERATION), CXPLAT_POOL_OPER, &Worker->OperPool);

    Status = QuicTimerWheelInitialize(&Worker->TimerWheel);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        ThreadFlags,
        IdealProcessor,
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

Error:

    if (QUIC_FAILED(Status)) {
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
    // Prevent the thread from processing any more operations.
    //
    Worker->Enabled = FALSE;

    //
    // Wait for the thread to finish.
    //
    CxPlatEventSet(Worker->Ready);
    if (Worker->Thread) {
        CxPlatThreadWait(&Worker->Thread);
        CxPlatThreadDelete(&Worker->Thread);
    }

    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Worker->Connections));
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Worker->Operations));

    CxPlatPoolUninitialize(&Worker->StreamPool);
    CxPlatPoolUninitialize(&Worker->DefaultReceiveBufferPool);
    CxPlatPoolUninitialize(&Worker->SendRequestPool);
    QuicSentPacketPoolUninitialize(&Worker->SentPacketPool);
    CxPlatPoolUninitialize(&Worker->ApiContextPool);
    CxPlatPoolUninitialize(&Worker->StatelessContextPool);
    CxPlatPoolUninitialize(&Worker->OperPool);
    CxPlatEventUninitialize(Worker->Ready);
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

    CxPlatDispatchLockAcquire(&Worker->Lock);

    BOOLEAN WakeWorkerThread;
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
    } else {
        WakeWorkerThread = FALSE;
    }

    Connection->HasQueuedWork = TRUE;

    CxPlatDispatchLockRelease(&Worker->Lock);

    if (ConnectionQueued) {
        QuicPerfCounterIncrement(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH);
    }

    if (WakeWorkerThread) {
        CxPlatEventSet(Worker->Ready);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicWorkerMoveConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(Connection->Worker != NULL);

    CxPlatDispatchLockAcquire(&Worker->Lock);

    BOOLEAN WakeWorkerThread = QuicWorkerIsIdle(Worker);

    if (Connection->HasQueuedWork) {
        Connection->Stats.Schedule.LastQueueTime = CxPlatTimeUs32();
        QuicTraceEvent(
            ConnScheduleState,
            "[conn][%p] Scheduling: %u",
            Connection,
            QUIC_SCHEDULE_QUEUED);
        QuicConnAddRef(Connection, QUIC_CONN_REF_WORKER);
        CxPlatListInsertTail(&Worker->Connections, &Connection->WorkerLink);
    }

    CxPlatDispatchLockRelease(&Worker->Lock);

    if (WakeWorkerThread) {
        CxPlatEventSet(Worker->Ready);
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
        const QUIC_RECV_PACKET* Packet =
            CxPlatDataPathRecvDataToRecvPacket(
                Operation->STATELESS.Context->Datagram);
        QuicPacketLogDrop(Binding, Packet, "Worker operation limit reached");
        QuicOperationFree(Worker, Operation);
    } else if (WakeWorkerThread) {
        CxPlatEventSet(Worker->Ready);
    }
}

//
// Called when a worker changes between the idle and active state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerToggleActivityState(
    _In_ QUIC_WORKER* Worker,
    _In_ uint32_t Arg
    )
{
    Worker->IsActive = !Worker->IsActive;
    QuicTraceEvent(
        WorkerActivityStateUpdated,
        "[wrkr][%p] IsActive = %hhu, Arg = %u",
        Worker,
        Worker->IsActive,
        Arg);
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
    QUIC_CONNECTION* Connection;

    if (Worker->Enabled) {
        CxPlatDispatchLockAcquire(&Worker->Lock);

        if (CxPlatListIsEmpty(&Worker->Connections)) {
            Connection = NULL;
        } else {
            Connection =
                QUIC_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Worker->Connections), QUIC_CONNECTION, WorkerLink);
            CXPLAT_DBG_ASSERT(!Connection->WorkerProcessing);
            CXPLAT_DBG_ASSERT(Connection->HasQueuedWork);
            Connection->HasQueuedWork = FALSE;
            Connection->WorkerProcessing = TRUE;
            QuicPerfCounterDecrement(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH);
        }

        CxPlatDispatchLockRelease(&Worker->Lock);
    } else {
        Connection = NULL;
    }

    return Connection;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_OPERATION*
QuicWorkerGetNextOperation(
    _In_ QUIC_WORKER* Worker
    )
{
    QUIC_OPERATION* Operation;

    if (Worker->Enabled) {
        CxPlatDispatchLockAcquire(&Worker->Lock);

        if (Worker->OperationCount == 0) {
            Operation = NULL;
        } else {
            Operation =
                QUIC_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Worker->Operations), QUIC_OPERATION, Link);
#if DEBUG
            Operation->Link.Flink = NULL;
#endif
            Worker->OperationCount--;
            QuicPerfCounterDecrement(QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH);
        }

        CxPlatDispatchLockRelease(&Worker->Lock);
    } else {
        Operation = NULL;
    }

    return Operation;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerProcessTimers(
    _In_ QUIC_WORKER* Worker
    )
{
    //
    // Get the list of all connections with expired timers from the timer wheel.
    //
    QUIC_LIST_ENTRY ExpiredTimers;
    CxPlatListInitializeHead(&ExpiredTimers);
    uint64_t TimeNow = CxPlatTimeUs64();
    QuicTimerWheelGetExpired(&Worker->TimerWheel, TimeNow, &ExpiredTimers);

    //
    // Indicate to all the connections that have expired timers.
    //
    while (!CxPlatListIsEmpty(&ExpiredTimers)) {
        QUIC_LIST_ENTRY* Entry = CxPlatListRemoveHead(&ExpiredTimers);
        Entry->Flink = NULL;

        QUIC_CONNECTION* Connection =
            QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, TimerLink);

        Connection->WorkerThreadID = Worker->ThreadID;
        QuicConfigurationAttachSilo(Connection->Configuration);
        QuicConnTimerExpired(Connection, TimeNow);
        QuicConfigurationDetachSilo();
        Connection->WorkerThreadID = 0;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicWorkerProcessConnection(
    _In_ QUIC_WORKER* Worker,
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnScheduleState,
        "[conn][%p] Scheduling: %u",
        Connection,
        QUIC_SCHEDULE_PROCESSING);
    QuicConfigurationAttachSilo(Connection->Configuration);

    if (Connection->Stats.Schedule.LastQueueTime != 0) {
        QuicWorkerUpdateQueueDelay(
            Worker,
            CxPlatTimeDiff32(
                Connection->Stats.Schedule.LastQueueTime,
                CxPlatTimeUs32()));
    }

    //
    // Set the thread ID so reentrant API calls will execute inline.
    //
    Connection->WorkerThreadID = Worker->ThreadID;
    Connection->Stats.Schedule.DrainCount++;

    if (Connection->State.UpdateWorker) {
        //
        // If the connection is uninitialized already, it shouldn't have been
        // queued to move to a new worker in the first place.
        //
        CXPLAT_DBG_ASSERT(!Connection->State.Uninitialized);

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
        Event.IDEAL_PROCESSOR_CHANGED.IdealProcessor = Worker->IdealProcessor;
        QuicTraceLogConnVerbose(
            IndicateIdealProcChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED");
        (void)QuicConnIndicateEvent(Connection, &Event);
    }

    //
    // Process some operations.
    //
    BOOLEAN StillHasWorkToDo =
        QuicConnDrainOperations(Connection) | Connection->State.UpdateWorker;
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
            CxPlatListInsertTail(&Worker->Connections, &Connection->WorkerLink);
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
            // The connection should never be queued to a new worker if it's
            // already been uninitialized.
            //
            CXPLAT_DBG_ASSERT(!Connection->State.Uninitialized);
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
            QuicWorkerMoveConnection(Connection->Worker, Connection);
        }

        //
        // This worker is no longer managing the connection, so we can
        // release its connection reference.
        //
        QuicConnRelease(Connection, QUIC_CONN_REF_WORKER);
    }
}

CXPLAT_THREAD_CALLBACK(QuicWorkerThread, Context)
{
    QUIC_WORKER* Worker = (QUIC_WORKER*)Context;

    Worker->ThreadID = CxPlatCurThreadID();
    Worker->IsActive = TRUE;
    QuicTraceEvent(
        WorkerStart,
        "[wrkr][%p] Start",
        Worker);

    //
    // TODO - Review how often CxPlatTimeUs64() is called in the thread. Perhaps
    // we can get it down to once per loop, passing the value along.
    //

    while (Worker->Enabled) {

        //
        // For every loop of the worker thread, in an attempt to balance things,
        // a single connection will be processed (if available), followed by a
        // single stateless operation (if available), and then by any expired
        // timers (which just queue more operations on connections).
        //

        QUIC_CONNECTION* Connection = QuicWorkerGetNextConnection(Worker);
        if (Connection != NULL) {
            QuicWorkerProcessConnection(Worker, Connection);
        }

        QUIC_OPERATION* Operation = QuicWorkerGetNextOperation(Worker);
        if (Operation != NULL) {
            QuicBindingProcessStatelessOperation(
                Operation->Type,
                Operation->STATELESS.Context);
            QuicOperationFree(Worker, Operation);
            QuicPerfCounterIncrement(QUIC_PERF_COUNTER_WORK_OPER_COMPLETED);
        }

        //
        // Get the delay until the next timer expires. Check to see if any
        // timers have expired; if so, process them. If not, only wait for the
        // next timer if we have run out of connections and stateless operations
        // to process.
        //
        uint64_t Delay = QuicTimerWheelGetWaitTime(&Worker->TimerWheel);

        if (Delay == 0) {
            //
            // Timers are ready to be processed.
            //
            QuicWorkerProcessTimers(Worker);

        } else if (Connection != NULL || Operation != NULL) {
            //
            // There still may be more connections or stateless operations to be
            // processed. Continue processing until there are no more. Then the
            // thread can wait for the timer delay.
            //
            continue;

        } else if (Delay != UINT64_MAX) {
            //
            // Since we have no connections and no stateless operations to
            // process at the moment, we need to wait for the ready event or the
            // next timer to expire.
            //
            if (Delay >= (uint64_t)UINT32_MAX) {
                Delay = UINT32_MAX - 1; // Max has special meaning for most platforms.
            }
            QuicWorkerToggleActivityState(Worker, (uint32_t)Delay);
            QuicWorkerResetQueueDelay(Worker);
            BOOLEAN ReadySet =
                CxPlatEventWaitWithTimeout(Worker->Ready, (uint32_t)Delay);
            QuicWorkerToggleActivityState(Worker, ReadySet);

            if (!ReadySet) {
                QuicWorkerProcessTimers(Worker);
            }

        } else {
            //
            // No active timers running, so just wait for the ready event.
            //
            QuicWorkerToggleActivityState(Worker, UINT32_MAX);
            QuicWorkerResetQueueDelay(Worker);
            CxPlatEventWaitForever(Worker->Ready);
            QuicWorkerToggleActivityState(Worker, TRUE);
        }
    }

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
            QUIC_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Worker->Connections), QUIC_CONNECTION, WorkerLink);
        if (!Connection->State.ExternalOwner) {
            //
            // If there is no external owner, shut down the connection so that
            // it's not leaked.
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
            QUIC_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Worker->Operations), QUIC_OPERATION, Link);
#if DEBUG
        Operation->Link.Flink = NULL;
#endif
        QuicOperationFree(Worker, Operation);
        --Dequeue;
    }
    QuicPerfCounterAdd(QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH, Dequeue);

    QuicTraceEvent(
        WorkerStop,
        "[wrkr][%p] Stop",
        Worker);
    CXPLAT_THREAD_RETURN(QUIC_STATUS_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicWorkerPoolInitialize(
    _In_opt_ const void* Owner,
    _In_ uint16_t ThreadFlags,
    _In_ uint16_t WorkerCount,
    _Out_ QUIC_WORKER_POOL** NewWorkerPool
    )
{
    QUIC_STATUS Status;

    QUIC_WORKER_POOL* WorkerPool =
        CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_WORKER_POOL) + WorkerCount * sizeof(QUIC_WORKER), CXPLAT_POOL_WORKER);
    if (WorkerPool == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_WORKER_POOL",
            sizeof(QUIC_WORKER_POOL) + WorkerCount * sizeof(QUIC_WORKER));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    WorkerPool->WorkerCount = WorkerCount;
    WorkerPool->LastWorker = 0;
    CxPlatZeroMemory(WorkerPool->Workers, sizeof(QUIC_WORKER) * WorkerCount);

    //
    // Create the set of worker threads and soft affinitize them in order to
    // attempt to spread the connection workload out over multiple processors.
    //

    for (uint16_t i = 0; i < WorkerCount; i++) {
        Status = QuicWorkerInitialize(Owner, ThreadFlags, i, &WorkerPool->Workers[i]);
        if (QUIC_FAILED(Status)) {
            for (uint16_t j = 0; j < i; j++) {
                QuicWorkerUninitialize(&WorkerPool->Workers[j]);
            }
            goto Error;
        }
    }

    *NewWorkerPool = WorkerPool;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (WorkerPool != NULL) {
            CXPLAT_FREE(WorkerPool, CXPLAT_POOL_WORKER);
        }
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

    CXPLAT_FREE(WorkerPool, CXPLAT_POOL_WORKER);
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
