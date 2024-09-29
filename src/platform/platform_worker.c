/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Platform abstraction for generic, per-processor worker threads.

--*/

#include "platform_internal.h"

#ifdef QUIC_CLOG
#include "platform_worker.c.clog.h"
#endif

const uint32_t WorkerWakeEventPayload = CXPLAT_CQE_TYPE_WORKER_WAKE;
const uint32_t WorkerUpdatePollEventPayload = CXPLAT_CQE_TYPE_WORKER_UPDATE_POLL;

typedef struct QUIC_CACHEALIGN CXPLAT_WORKER {

    //
    // Thread used to drive the worker.
    //
    CXPLAT_THREAD Thread;

    //
    // Event queue to drive execution.
    //
    CXPLAT_EVENTQ EventQ;

#ifdef CXPLAT_SQE
    //
    // Submission queue entry for shutting down the worker thread.
    //
    CXPLAT_SQE ShutdownSqe;

    //
    // Submission queue entry for waking the thread to poll.
    //
    CXPLAT_SQE WakeSqe;

    //
    // Submission queue entry for update the polling set.
    //
    CXPLAT_SQE UpdatePollSqe;
#endif

    //
    // Serializes access to the execution contexts.
    //
    CXPLAT_LOCK ECLock;

    //
    // List of dynamic pools to manage.
    //
    CXPLAT_LIST_ENTRY DynamicPoolList;

    //
    // Execution contexts that are waiting to be added to CXPLAT_WORKER::ExecutionContexts.
    //
    CXPLAT_SLIST_ENTRY* PendingECs;

    //
    // The set of actively registered execution contexts.
    //
    CXPLAT_SLIST_ENTRY* ExecutionContexts;

#if DEBUG // Debug statistics
    uint64_t LoopCount;
    uint64_t EcPollCount;
    uint64_t EcRunCount;
    uint64_t CqeCount;
#endif

    //
    // The ideal processor for the worker thread.
    //
    uint16_t IdealProcessor;

    //
    // Flags to indicate what has been initialized.
    //
    BOOLEAN InitializedEventQ : 1;
#ifdef CXPLAT_SQE_INIT
    BOOLEAN InitializedShutdownSqe : 1;
    BOOLEAN InitializedWakeSqe : 1;
    BOOLEAN InitializedUpdatePollSqe : 1;
#endif
    BOOLEAN InitializedThread : 1;
    BOOLEAN InitializedECLock : 1;
    BOOLEAN StoppingThread : 1;
    BOOLEAN DestroyedThread : 1;
#if DEBUG // Debug flags - Must not be in the bitfield.
    BOOLEAN ThreadStarted;
    BOOLEAN ThreadFinished;
#endif

    //
    // Must not be bitfield.
    //
    BOOLEAN Running;

} CXPLAT_WORKER;

CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context);

void
CxPlatWorkerPoolInit(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CxPlatZeroMemory(WorkerPool, sizeof(*WorkerPool));
    CxPlatLockInitialize(&WorkerPool->WorkerLock);
}

#pragma warning(push)
#pragma warning(disable:6385)
#pragma warning(disable:6386) // SAL is confused about the worker size
BOOLEAN
CxPlatWorkerPoolLazyStart(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CxPlatLockAcquire(&WorkerPool->WorkerLock);
    if (WorkerPool->Workers != NULL) {
        CxPlatLockRelease(&WorkerPool->WorkerLock);
        return TRUE;
    }

    const uint16_t* ProcessorList;
    if (Config && Config->ProcessorCount) {
        WorkerPool->WorkerCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        WorkerPool->WorkerCount = CxPlatProcCount();
        ProcessorList = NULL;
    }
    CXPLAT_DBG_ASSERT(WorkerPool->WorkerCount > 0 && WorkerPool->WorkerCount <= UINT16_MAX);

    const size_t WorkersSize = sizeof(CXPLAT_WORKER) * WorkerPool->WorkerCount;
    WorkerPool->Workers = (CXPLAT_WORKER*)CXPLAT_ALLOC_PAGED(WorkersSize, QUIC_POOL_PLATFORM_WORKER);
    if (WorkerPool->Workers == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER",
            WorkersSize);
        WorkerPool->WorkerCount = 0;
        goto Error;
    }

    uint16_t ThreadFlags = CXPLAT_THREAD_FLAG_SET_IDEAL_PROC;
    if (Config) {
        if (Config->Flags & QUIC_EXECUTION_CONFIG_FLAG_NO_IDEAL_PROC) {
            ThreadFlags &= ~CXPLAT_THREAD_FLAG_SET_IDEAL_PROC; // Remove the flag
        }
        if (Config->Flags & QUIC_EXECUTION_CONFIG_FLAG_HIGH_PRIORITY) {
            ThreadFlags |= CXPLAT_THREAD_FLAG_HIGH_PRIORITY;
        }
    }

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        ThreadFlags,
        0,
        "cxplat_worker",
        CxPlatWorkerThread,
        NULL
    };

    CxPlatZeroMemory(WorkerPool->Workers, WorkersSize);
    for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
        CxPlatLockInitialize(&WorkerPool->Workers[i].ECLock);
        CxPlatListInitializeHead(&WorkerPool->Workers[i].DynamicPoolList);
        WorkerPool->Workers[i].InitializedECLock = TRUE;
        WorkerPool->Workers[i].IdealProcessor = ProcessorList ? ProcessorList[i] : (uint16_t)i;
        CXPLAT_DBG_ASSERT(WorkerPool->Workers[i].IdealProcessor < CxPlatProcCount());
        ThreadConfig.IdealProcessor = WorkerPool->Workers[i].IdealProcessor;
        ThreadConfig.Context = &WorkerPool->Workers[i];
        if (!CxPlatEventQInitialize(&WorkerPool->Workers[i].EventQ)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatEventQInitialize");
            goto Error;
        }
        WorkerPool->Workers[i].InitializedEventQ = TRUE;
#ifdef CXPLAT_SQE_INIT
        WorkerPool->Workers[i].ShutdownSqe = (CXPLAT_SQE)WorkerPool->Workers[i].EventQ;
        if (!CxPlatSqeInitialize(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].ShutdownSqe, NULL)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(shutdown)");
            goto Error;
        }
        WorkerPool->Workers[i].InitializedShutdownSqe = TRUE;
        WorkerPool->Workers[i].WakeSqe = (CXPLAT_SQE)WorkerWakeEventPayload;
        if (!CxPlatSqeInitialize(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].WakeSqe, (void*)&WorkerWakeEventPayload)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(wake)");
            goto Error;
        }
        WorkerPool->Workers[i].InitializedWakeSqe = TRUE;
        WorkerPool->Workers[i].UpdatePollSqe = (CXPLAT_SQE)WorkerUpdatePollEventPayload;
        if (!CxPlatSqeInitialize(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].UpdatePollSqe, (void*)&WorkerUpdatePollEventPayload)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(updatepoll)");
            goto Error;
        }
        WorkerPool->Workers[i].InitializedUpdatePollSqe = TRUE;
#endif
        if (QUIC_FAILED(
            CxPlatThreadCreate(&ThreadConfig, &WorkerPool->Workers[i].Thread))) {
            goto Error;
        }
        WorkerPool->Workers[i].InitializedThread = TRUE;
    }

    CxPlatRundownInitialize(&WorkerPool->Rundown);

    CxPlatLockRelease(&WorkerPool->WorkerLock);

    return TRUE;

Error:

    if (WorkerPool->Workers) {
        for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
            if (WorkerPool->Workers[i].InitializedThread) {
                WorkerPool->Workers[i].StoppingThread = TRUE;
                CxPlatEventQEnqueue(
                    &WorkerPool->Workers[i].EventQ,
                    &WorkerPool->Workers[i].ShutdownSqe,
                    NULL);
                CxPlatThreadWait(&WorkerPool->Workers[i].Thread);
                CxPlatThreadDelete(&WorkerPool->Workers[i].Thread);
#if DEBUG
                CXPLAT_DBG_ASSERT(WorkerPool->Workers[i].ThreadStarted);
                CXPLAT_DBG_ASSERT(WorkerPool->Workers[i].ThreadFinished);
#endif
                WorkerPool->Workers[i].DestroyedThread = TRUE;
            }
#ifdef CXPLAT_SQE_INIT
            if (WorkerPool->Workers[i].InitializedUpdatePollSqe) {
                CxPlatSqeCleanup(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].UpdatePollSqe);
            }
            if (WorkerPool->Workers[i].InitializedWakeSqe) {
                CxPlatSqeCleanup(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].WakeSqe);
            }
            if (WorkerPool->Workers[i].InitializedShutdownSqe) {
                CxPlatSqeCleanup(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].ShutdownSqe);
            }
#endif // CXPLAT_SQE_INIT
            if (WorkerPool->Workers[i].InitializedEventQ) {
                CxPlatEventQCleanup(&WorkerPool->Workers[i].EventQ);
            }
            if (WorkerPool->Workers[i].InitializedECLock) {
                CxPlatLockUninitialize(&WorkerPool->Workers[i].ECLock);
            }
        }

        CXPLAT_FREE(WorkerPool->Workers, QUIC_POOL_PLATFORM_WORKER);
        WorkerPool->Workers = NULL;
    }

    CxPlatLockRelease(&WorkerPool->WorkerLock);
    return FALSE;
}
#pragma warning(pop)

void
CxPlatWorkerPoolUninit(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    if (WorkerPool->Workers != NULL) {
        CxPlatRundownReleaseAndWait(&WorkerPool->Rundown);

        for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
            WorkerPool->Workers[i].StoppingThread = TRUE;
            CxPlatEventQEnqueue(
                &WorkerPool->Workers[i].EventQ,
                &WorkerPool->Workers[i].ShutdownSqe,
                NULL);
            CxPlatThreadWait(&WorkerPool->Workers[i].Thread);
            CxPlatThreadDelete(&WorkerPool->Workers[i].Thread);
#if DEBUG
            CXPLAT_DBG_ASSERT(WorkerPool->Workers[i].ThreadStarted);
            CXPLAT_DBG_ASSERT(WorkerPool->Workers[i].ThreadFinished);
#endif
            WorkerPool->Workers[i].DestroyedThread = TRUE;
#ifdef CXPLAT_SQE_INIT
            CxPlatSqeCleanup(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].UpdatePollSqe);
            CxPlatSqeCleanup(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].WakeSqe);
            CxPlatSqeCleanup(&WorkerPool->Workers[i].EventQ, &WorkerPool->Workers[i].ShutdownSqe);
#endif // CXPLAT_SQE_INIT
            CxPlatEventQCleanup(&WorkerPool->Workers[i].EventQ);
            CXPLAT_DBG_ASSERT(CxPlatListIsEmpty(&WorkerPool->Workers[i].DynamicPoolList));
            CxPlatLockUninitialize(&WorkerPool->Workers[i].ECLock);
        }

        CXPLAT_FREE(WorkerPool->Workers, QUIC_POOL_PLATFORM_WORKER);
        WorkerPool->Workers = NULL;

        CxPlatRundownUninitialize(&WorkerPool->Rundown);
    }

    CxPlatLockUninitialize(&WorkerPool->WorkerLock);
}

#define DYNAMIC_POOL_PROCESSING_PERIOD  1000000 // 1 second
#define DYNAMIC_POOL_PRUNE_COUNT        8

void
CxPlatAddDynamicPoolAllocator(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Inout_ CXPLAT_POOL_EX* Pool,
    _In_ uint16_t Index // Into the execution config processor array
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CXPLAT_FRE_ASSERT(Index < WorkerPool->WorkerCount);
    CXPLAT_WORKER* Worker = &WorkerPool->Workers[Index];
    Pool->Owner = Worker;
    CxPlatLockAcquire(&Worker->ECLock);
    CxPlatListInsertTail(&Worker->DynamicPoolList, &Pool->Link);
    CxPlatLockRelease(&Worker->ECLock);
}

void
CxPlatRemoveDynamicPoolAllocator(
    _Inout_ CXPLAT_POOL_EX* Pool
    )
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Pool->Owner;
    CxPlatLockAcquire(&Worker->ECLock);
    CxPlatListEntryRemove(&Pool->Link);
    CxPlatLockRelease(&Worker->ECLock);
}

void
CxPlatProcessDynamicPoolAllocator(
    _Inout_ CXPLAT_POOL_EX* Pool
    )
{
    for (uint32_t i = 0; i < DYNAMIC_POOL_PRUNE_COUNT; ++i) {
        if (!CxPlatPoolPrune((CXPLAT_POOL*)Pool)) {
            return;
        }
    }
}

void
CxPlatProcessDynamicPoolAllocators(
    _In_ CXPLAT_WORKER* Worker
    )
{
    QuicTraceLogVerbose(
        PlatformWorkerProcessPools,
        "[ lib][%p] Processing pools",
        Worker);

    CxPlatLockAcquire(&Worker->ECLock);
    CXPLAT_LIST_ENTRY* Entry = Worker->DynamicPoolList.Flink;
    while (Entry != &Worker->DynamicPoolList) {
        CXPLAT_POOL_EX* Pool = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_POOL_EX, Link);
        Entry = Entry->Flink;
        CxPlatProcessDynamicPoolAllocator(Pool);
    }
    CxPlatLockRelease(&Worker->ECLock);
}

CXPLAT_EVENTQ*
CxPlatWorkerPoolGetEventQ(
    _In_ const CXPLAT_WORKER_POOL* WorkerPool,
    _In_ uint16_t Index
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CXPLAT_FRE_ASSERT(Index < WorkerPool->WorkerCount);
    return &WorkerPool->Workers[Index].EventQ;
}

void
CxPlatAddExecutionContext(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Inout_ CXPLAT_EXECUTION_CONTEXT* Context,
    _In_ uint16_t Index
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CXPLAT_FRE_ASSERT(Index < WorkerPool->WorkerCount);
    CXPLAT_WORKER* Worker = &WorkerPool->Workers[Index];

    Context->CxPlatContext = Worker;
    CxPlatLockAcquire(&Worker->ECLock);
    const BOOLEAN QueueEvent = Worker->PendingECs == NULL;
    Context->Entry.Next = Worker->PendingECs;
    Worker->PendingECs = &Context->Entry;
    CxPlatLockRelease(&Worker->ECLock);

    if (QueueEvent) {
        CxPlatEventQEnqueue(
            &Worker->EventQ,
            &Worker->UpdatePollSqe,
            (void*)&WorkerUpdatePollEventPayload);
    }
}

void
CxPlatWakeExecutionContext(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    )
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Context->CxPlatContext;
    if (!InterlockedFetchAndSetBoolean(&Worker->Running)) {
        CxPlatEventQEnqueue(&Worker->EventQ, &Worker->WakeSqe, (void*)&WorkerWakeEventPayload);
    }
}

void
CxPlatUpdateExecutionContexts(
    _In_ CXPLAT_WORKER* Worker
    )
{
    if (QuicReadPtrNoFence(&Worker->PendingECs)) {
        CxPlatLockAcquire(&Worker->ECLock);
        CXPLAT_SLIST_ENTRY* Head = Worker->PendingECs;
        Worker->PendingECs = NULL;
        CxPlatLockRelease(&Worker->ECLock);

        CXPLAT_SLIST_ENTRY** Tail = &Head;
        while (*Tail) {
            Tail = &(*Tail)->Next;
        }

        *Tail = Worker->ExecutionContexts;
        Worker->ExecutionContexts = Head;
    }
}

void
CxPlatRunExecutionContexts(
    _In_ CXPLAT_WORKER* Worker,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    if (Worker->ExecutionContexts == NULL) {
        State->WaitTime = UINT32_MAX;
        return;
    }

#if DEBUG // Debug statistics
    ++Worker->EcPollCount;
#endif

    uint64_t NextTime = UINT64_MAX;
    CXPLAT_SLIST_ENTRY** EC = &Worker->ExecutionContexts;
    do {
        CXPLAT_EXECUTION_CONTEXT* Context =
            CXPLAT_CONTAINING_RECORD(*EC, CXPLAT_EXECUTION_CONTEXT, Entry);
        BOOLEAN Ready = InterlockedFetchAndClearBoolean(&Context->Ready);
        if (Ready || Context->NextTimeUs <= State->TimeNow) {
#if DEBUG // Debug statistics
            ++Worker->EcRunCount;
#endif
            CXPLAT_SLIST_ENTRY* Next = Context->Entry.Next;
            if (!Context->Callback(Context->Context, State)) {
                *EC = Next; // Remove Context from the list.
                continue;
            }
            if (Context->Ready) {
                NextTime = 0;
            }
        }
        if (Context->NextTimeUs < NextTime) {
            NextTime = Context->NextTimeUs;
        }
        EC = &Context->Entry.Next;
    } while (*EC != NULL);

    if (NextTime == 0) {
        State->WaitTime = 0;
    } else if (NextTime != UINT64_MAX) {
        uint64_t Diff = NextTime - State->TimeNow;
        Diff = US_TO_MS(Diff);
        if (Diff == 0) {
            State->WaitTime = 1;
        } else if (Diff < UINT32_MAX) {
            State->WaitTime = (uint32_t)Diff;
        } else {
            State->WaitTime = UINT32_MAX-1;
        }
    } else {
        State->WaitTime = UINT32_MAX;
    }
}

BOOLEAN
CxPlatProcessEvents(
    _In_ CXPLAT_WORKER* Worker,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    CXPLAT_CQE Cqes[16];
    uint32_t CqeCount = CxPlatEventQDequeue(&Worker->EventQ, Cqes, ARRAYSIZE(Cqes), State->WaitTime);
    InterlockedFetchAndSetBoolean(&Worker->Running);
    if (CqeCount != 0) {
#if DEBUG // Debug statistics
        Worker->CqeCount += CqeCount;
#endif
        State->NoWorkCount = 0;
        for (uint32_t i = 0; i < CqeCount; ++i) {
            if (CxPlatCqeUserData(&Cqes[i]) == NULL) {
#if DEBUG
                CXPLAT_DBG_ASSERT(Worker->StoppingThread);
#endif
                return TRUE; // NULL user data means shutdown.
            }
            switch (CxPlatCqeType(&Cqes[i])) {
            case CXPLAT_CQE_TYPE_WORKER_WAKE:
                break; // No-op, just wake up to do polling stuff.
            case CXPLAT_CQE_TYPE_WORKER_UPDATE_POLL:
                CxPlatUpdateExecutionContexts(Worker);
                break;
            default: // Pass the rest to the datapath
                CxPlatDataPathProcessCqe(&Cqes[i]);
                break;
            }
        }
        CxPlatEventQReturn(&Worker->EventQ, CqeCount);
    }
    return FALSE;
}

//
// The number of iterations to run before yielding our thread to the scheduler.
//
#define CXPLAT_WORKER_IDLE_WORK_THRESHOLD_COUNT 10

CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context)
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Context;
    CXPLAT_DBG_ASSERT(Worker != NULL);

    QuicTraceLogInfo(
        PlatformWorkerThreadStart,
        "[ lib][%p] Worker start",
        Worker);
#if DEBUG
    Worker->ThreadStarted = TRUE;
#endif

    CXPLAT_EXECUTION_STATE State = { 0, 0, 0, UINT32_MAX, 0, CxPlatCurThreadID() };

    Worker->Running = TRUE;

    while (TRUE) {

        ++State.NoWorkCount;
#if DEBUG // Debug statistics
        ++Worker->LoopCount;
#endif
        State.TimeNow = CxPlatTimeUs64();

        CxPlatRunExecutionContexts(Worker, &State);
        if (State.WaitTime && InterlockedFetchAndClearBoolean(&Worker->Running)) {
            State.TimeNow = CxPlatTimeUs64();
            CxPlatRunExecutionContexts(Worker, &State); // Run once more to handle race conditions
        }

        if (CxPlatProcessEvents(Worker, &State)) {
            goto Shutdown;
        }

        if (State.NoWorkCount == 0) {
            State.LastWorkTime = State.TimeNow;
        } else if (State.NoWorkCount > CXPLAT_WORKER_IDLE_WORK_THRESHOLD_COUNT) {
            CxPlatSchedulerYield();
            State.NoWorkCount = 0;
        }

        if (State.TimeNow - State.LastPoolProcessTime > DYNAMIC_POOL_PROCESSING_PERIOD) {
            CxPlatProcessDynamicPoolAllocators(Worker);
            State.LastPoolProcessTime = State.TimeNow;
        }
    }

Shutdown:

    Worker->Running = FALSE;

#if DEBUG
    Worker->ThreadFinished = TRUE;
#endif

    QuicTraceLogInfo(
        PlatformWorkerThreadStop,
        "[ lib][%p] Worker stop",
        Worker);

    CXPLAT_THREAD_RETURN(0);
}
