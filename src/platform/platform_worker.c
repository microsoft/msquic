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

CXPLAT_RUNDOWN_REF CxPlatWorkerRundown;

const uint32_t WorkerWakeEventPayload = CXPLAT_CQE_TYPE_WORKER_WAKE;
const uint32_t WorkerUpdatePollEventPayload = CXPLAT_CQE_TYPE_WORKER_UPDATE_POLL;

typedef struct QUIC_CACHEALIGN CXPLAT_WORKER {

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

    //
    // Thread used to drive the worker.
    //
    CXPLAT_THREAD Thread;

    //
    // The ID of the above Thread.
    //
    CXPLAT_THREAD_ID ThreadId;

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

} CXPLAT_WORKER;

uint32_t CxPlatWorkerCount;
CXPLAT_WORKER* CxPlatWorkers;
CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context);

void
CxPlatWorkerWake(
    _In_ CXPLAT_WORKER* Worker
    )
{
    CxPlatEventQEnqueue(&Worker->EventQ, &Worker->WakeSqe, (void*)&WorkerWakeEventPayload);
}

CXPLAT_EVENTQ*
CxPlatWorkerGetEventQ(
    _In_ uint16_t IdealProcessor,
    _Out_opt_ CXPLAT_THREAD_ID* ThreadId
    )
{
    if (ThreadId) {
        while (!CxPlatWorkers[IdealProcessor % CxPlatWorkerCount].ThreadId) {
            CxPlatSchedulerYield();
        }
        *ThreadId = CxPlatWorkers[IdealProcessor % CxPlatWorkerCount].ThreadId;
    }
    return &CxPlatWorkers[IdealProcessor % CxPlatWorkerCount].EventQ;
}

#pragma warning(push)
#pragma warning(disable:6385)
#pragma warning(disable:6386) // SAL is confused about the worker size
BOOLEAN
CxPlatWorkersInit(
    void
    )
{
    CxPlatWorkerCount = CxPlatProcActiveCount(); // TODO - use max instead?
    CXPLAT_DBG_ASSERT(CxPlatWorkerCount > 0 && CxPlatWorkerCount <= UINT16_MAX);

    const size_t WorkersSize = sizeof(CXPLAT_WORKER) * CxPlatWorkerCount;

    CxPlatWorkers = (CXPLAT_WORKER*)CXPLAT_ALLOC_PAGED(WorkersSize, QUIC_POOL_PLATFORM_WORKER);
    if (CxPlatWorkers == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER",
            WorkersSize);
        return FALSE;
    }

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        CXPLAT_THREAD_FLAG_SET_AFFINITIZE,
        0,
        "cxplat_worker",
        CxPlatWorkerThread,
        NULL
    };

    CxPlatZeroMemory(CxPlatWorkers, WorkersSize);
    for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
        CxPlatLockInitialize(&CxPlatWorkers[i].ECLock);
        CxPlatWorkers[i].InitializedECLock = TRUE;
        ThreadConfig.IdealProcessor = (uint16_t)i;
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

    return TRUE;

Error:

    for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
        if (CxPlatWorkers[i].InitializedThread) {
            CxPlatThreadWait(&CxPlatWorkers[i].Thread);
            CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
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

    return FALSE;
}
#pragma warning(pop)

void
CxPlatWorkersUninit(
    void
    )
{
    CxPlatRundownReleaseAndWait(&CxPlatWorkerRundown);

    for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
        CxPlatEventQEnqueue(
            &CxPlatWorkers[i].EventQ,
            &CxPlatWorkers[i].ShutdownSqe,
            NULL);
        CxPlatThreadWait(&CxPlatWorkers[i].Thread);
        CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
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

void
CxPlatAddExecutionContext(
    _Inout_ CXPLAT_EXECUTION_CONTEXT* Context,
    _In_ uint16_t IdealProcessor
    )
{
    CXPLAT_WORKER* Worker = &CxPlatWorkers[IdealProcessor % CxPlatWorkerCount];
    Context->CxPlatContext = Worker;
    CxPlatLockAcquire(&Worker->ECLock);
    Context->Entry.Next = Worker->PendingECs;
    Worker->PendingECs = &Context->Entry;
    CxPlatLockRelease(&Worker->ECLock);
    CxPlatEventQEnqueue(
        &Worker->EventQ,
        &Worker->UpdatePollSqe,
        (void*)&WorkerUpdatePollEventPayload);
}

void
CxPlatWakeExecutionContext(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    )
{
    CxPlatWorkerWake((CXPLAT_WORKER*)Context->CxPlatContext);
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
        return;
    }

    State->TimeNow = CxPlatTimeUs64();

    uint64_t NextTime = UINT64_MAX;
    CXPLAT_SLIST_ENTRY** EC = &Worker->ExecutionContexts;
    do {
        CXPLAT_EXECUTION_CONTEXT* Context =
            CXPLAT_CONTAINING_RECORD(*EC, CXPLAT_EXECUTION_CONTEXT, Entry);
        BOOLEAN Ready = InterlockedFetchAndClearBoolean(&Context->Ready);
        if (Ready || Context->NextTimeUs <= State->TimeNow) {
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
    }
}

//
// The number of iterations to run before yielding our thread to the scheduler.
//
#define CXPLAT_WORKER_IDLE_WORK_THRESHOLD_COUNT 10

CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context)
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Context;
    CXPLAT_DBG_ASSERT(Worker != NULL);
    Worker->ThreadId = CxPlatCurThreadID();

    QuicTraceLogInfo(
        PlatformWorkerThreadStart,
        "[ lib][%p] Worker start",
        Worker);

    uint32_t CqeCount;
    CXPLAT_CQE Cqes[16];
    CXPLAT_EXECUTION_STATE State = { 0, UINT32_MAX, 0, CxPlatCurThreadID() };

    while (TRUE) {

        State.WaitTime = UINT32_MAX;
        ++State.NoWorkCount;

        CxPlatRunExecutionContexts(Worker, &State);

        CqeCount = CxPlatEventQDequeue(&Worker->EventQ, Cqes, ARRAYSIZE(Cqes), State.WaitTime);

        if (CqeCount != 0) {
            State.NoWorkCount = 0;
            for (uint32_t i = 0; i < CqeCount; ++i) {
                if (CxPlatCqeUserData(&Cqes[i]) == NULL) {
                    goto Shutdown; // NULL user data means shutdown.
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

        } else if (State.NoWorkCount > CXPLAT_WORKER_IDLE_WORK_THRESHOLD_COUNT) {
            CxPlatSchedulerYield();
            State.NoWorkCount = 0;
        }
    }

Shutdown:

    QuicTraceLogInfo(
        PlatformWorkerThreadStop,
        "[ lib][%p] Worker stop",
        Worker);

    CXPLAT_THREAD_RETURN(0);
}
