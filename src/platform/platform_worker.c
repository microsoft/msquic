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

CXPLAT_LOCK CxPlatWorkerLock;
CXPLAT_RUNDOWN_REF CxPlatWorkerRundown;
uint32_t CxPlatWorkerCount;
CXPLAT_WORKER* CxPlatWorkers;
CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context);

void
CxPlatWorkersInit(
    void
    )
{
    CxPlatLockInitialize(&CxPlatWorkerLock);
}

#pragma warning(push)
#pragma warning(disable:6385)
#pragma warning(disable:6386) // SAL is confused about the worker size
BOOLEAN
CxPlatWorkersLazyStart(
    _In_opt_ QUIC_EXECUTION_CONFIG* Config
    )
{
    CxPlatLockAcquire(&CxPlatWorkerLock);
    if (CxPlatWorkers != NULL) {
        CxPlatLockRelease(&CxPlatWorkerLock);
        return TRUE;
    }

    const uint16_t* ProcessorList;
    if (Config && Config->ProcessorCount) {
        CxPlatWorkerCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        CxPlatWorkerCount = CxPlatProcCount();
        ProcessorList = NULL;
    }
    CXPLAT_DBG_ASSERT(CxPlatWorkerCount > 0 && CxPlatWorkerCount <= UINT16_MAX);

    const size_t WorkersSize = sizeof(CXPLAT_WORKER) * CxPlatWorkerCount;
    CxPlatWorkers = (CXPLAT_WORKER*)CXPLAT_ALLOC_PAGED(WorkersSize, QUIC_POOL_PLATFORM_WORKER);
    if (CxPlatWorkers == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER",
            WorkersSize);
        CxPlatWorkerCount = 0;
        goto Error;
    }

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        CXPLAT_THREAD_FLAG_SET_IDEAL_PROC,
        0,
        "cxplat_worker",
        CxPlatWorkerThread,
        NULL
    };

    CxPlatZeroMemory(CxPlatWorkers, WorkersSize);
    for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
        CxPlatLockInitialize(&CxPlatWorkers[i].ECLock);
        CxPlatWorkers[i].InitializedECLock = TRUE;
        CxPlatWorkers[i].IdealProcessor = ProcessorList ? ProcessorList[i] : (uint16_t)i;
        CXPLAT_DBG_ASSERT(CxPlatWorkers[i].IdealProcessor < CxPlatProcCount());
        ThreadConfig.IdealProcessor = CxPlatWorkers[i].IdealProcessor;
        ThreadConfig.Context = &CxPlatWorkers[i];
        if (!CxPlatEventQInitialize(&CxPlatWorkers[i].EventQ)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatEventQInitialize");
            goto Error;
        }
        CxPlatWorkers[i].InitializedEventQ = TRUE;
#ifdef CXPLAT_SQE_INIT
        CxPlatWorkers[i].ShutdownSqe = (CXPLAT_SQE)CxPlatWorkers[i].EventQ;
        if (!CxPlatSqeInitialize(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].ShutdownSqe, NULL)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(shutdown)");
            goto Error;
        }
        CxPlatWorkers[i].InitializedShutdownSqe = TRUE;
        CxPlatWorkers[i].WakeSqe = (CXPLAT_SQE)WorkerWakeEventPayload;
        if (!CxPlatSqeInitialize(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].WakeSqe, (void*)&WorkerWakeEventPayload)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(wake)");
            goto Error;
        }
        CxPlatWorkers[i].InitializedWakeSqe = TRUE;
        CxPlatWorkers[i].UpdatePollSqe = (CXPLAT_SQE)WorkerUpdatePollEventPayload;
        if (!CxPlatSqeInitialize(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].UpdatePollSqe, (void*)&WorkerUpdatePollEventPayload)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(updatepoll)");
            goto Error;
        }
        CxPlatWorkers[i].InitializedUpdatePollSqe = TRUE;
#endif
        if (QUIC_FAILED(
            CxPlatThreadCreate(&ThreadConfig, &CxPlatWorkers[i].Thread))) {
            goto Error;
        }
        CxPlatWorkers[i].InitializedThread = TRUE;
    }

    CxPlatRundownInitialize(&CxPlatWorkerRundown);

    CxPlatLockRelease(&CxPlatWorkerLock);

    return TRUE;

Error:

    if (CxPlatWorkers) {
        for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
            if (CxPlatWorkers[i].InitializedThread) {
                CxPlatWorkers[i].StoppingThread = TRUE;
                CxPlatEventQEnqueue(
                    &CxPlatWorkers[i].EventQ,
                    &CxPlatWorkers[i].ShutdownSqe,
                    NULL);
                CxPlatThreadWait(&CxPlatWorkers[i].Thread);
                CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
#if DEBUG
                CXPLAT_DBG_ASSERT(CxPlatWorkers[i].ThreadStarted);
                CXPLAT_DBG_ASSERT(CxPlatWorkers[i].ThreadFinished);
#endif
                CxPlatWorkers[i].DestroyedThread = TRUE;
            }
#ifdef CXPLAT_SQE_INIT
            if (CxPlatWorkers[i].InitializedUpdatePollSqe) {
                CxPlatSqeCleanup(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].UpdatePollSqe);
            }
            if (CxPlatWorkers[i].InitializedWakeSqe) {
                CxPlatSqeCleanup(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].WakeSqe);
            }
            if (CxPlatWorkers[i].InitializedShutdownSqe) {
                CxPlatSqeCleanup(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].ShutdownSqe);
            }
#endif // CXPLAT_SQE_INIT
            if (CxPlatWorkers[i].InitializedEventQ) {
                CxPlatEventQCleanup(&CxPlatWorkers[i].EventQ);
            }
            if (CxPlatWorkers[i].InitializedECLock) {
                CxPlatLockUninitialize(&CxPlatWorkers[i].ECLock);
            }
        }

        CXPLAT_FREE(CxPlatWorkers, QUIC_POOL_PLATFORM_WORKER);
        CxPlatWorkers = NULL;
    }

    CxPlatLockRelease(&CxPlatWorkerLock);
    return FALSE;
}
#pragma warning(pop)

void
CxPlatWorkersUninit(
    void
    )
{
    if (CxPlatWorkers != NULL) {
        CxPlatRundownReleaseAndWait(&CxPlatWorkerRundown);

        for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
            CxPlatWorkers[i].StoppingThread = TRUE;
            CxPlatEventQEnqueue(
                &CxPlatWorkers[i].EventQ,
                &CxPlatWorkers[i].ShutdownSqe,
                NULL);
            CxPlatThreadWait(&CxPlatWorkers[i].Thread);
            CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
#if DEBUG
            CXPLAT_DBG_ASSERT(CxPlatWorkers[i].ThreadStarted);
            CXPLAT_DBG_ASSERT(CxPlatWorkers[i].ThreadFinished);
#endif
            CxPlatWorkers[i].DestroyedThread = TRUE;
#ifdef CXPLAT_SQE_INIT
            CxPlatSqeCleanup(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].UpdatePollSqe);
            CxPlatSqeCleanup(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].WakeSqe);
            CxPlatSqeCleanup(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].ShutdownSqe);
#endif // CXPLAT_SQE_INIT
            CxPlatEventQCleanup(&CxPlatWorkers[i].EventQ);
            CxPlatLockUninitialize(&CxPlatWorkers[i].ECLock);
        }

        CXPLAT_FREE(CxPlatWorkers, QUIC_POOL_PLATFORM_WORKER);
        CxPlatWorkers = NULL;

        CxPlatRundownUninitialize(&CxPlatWorkerRundown);
    }

    CxPlatLockUninitialize(&CxPlatWorkerLock);
}

CXPLAT_EVENTQ*
CxPlatWorkerGetEventQ(
    _In_ uint16_t Index
    )
{
    CXPLAT_FRE_ASSERT(Index < CxPlatWorkerCount);
    return &CxPlatWorkers[Index].EventQ;
}

void
CxPlatAddExecutionContext(
    _Inout_ CXPLAT_EXECUTION_CONTEXT* Context,
    _In_ uint16_t Index
    )
{
    CXPLAT_FRE_ASSERT(Index < CxPlatWorkerCount);
    CXPLAT_WORKER* Worker = &CxPlatWorkers[Index];

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
    State->TimeNow = CxPlatTimeUs64();

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

    CXPLAT_EXECUTION_STATE State = { 0, CxPlatTimeUs64(), UINT32_MAX, 0, CxPlatCurThreadID() };

    Worker->Running = TRUE;

    while (TRUE) {

        ++State.NoWorkCount;
#if DEBUG // Debug statistics
        ++Worker->LoopCount;
#endif

        CxPlatRunExecutionContexts(Worker, &State);
        if (State.WaitTime && InterlockedFetchAndClearBoolean(&Worker->Running)) {
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
