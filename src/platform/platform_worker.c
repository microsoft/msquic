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

const uint32_t QuicEventPayload = CXPLAT_CQE_TYPE_QUIC_BASE;

typedef struct QUIC_CACHEALIGN CXPLAT_WORKER {

    //
    // Flags to indicate what has been initialized.
    //
    BOOLEAN InitializedEventQ : 1;
#ifdef CXPLAT_SQE
    BOOLEAN InitializedShutdownSqe : 1;
    BOOLEAN InitializedQueSqe : 1;
#endif
    BOOLEAN InitializedThread : 1;
#ifdef QUIC_USE_EXECUTION_CONTEXTS
    BOOLEAN InitializedECLock : 1;
#endif

    //
    // Thread used to drive the worker.
    //
    CXPLAT_THREAD Thread;

    //
    // The ID of the thread.
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
    // Submission queue entry for waking the thread to process QUIC work.
    //
    CXPLAT_SQE QuicSqe; // TODO - refactor to expose EventQ to QUIC
#endif

    //
    // The datapath execution context running on this worker.
    //
    //void* DatapathEC;

#ifdef QUIC_USE_EXECUTION_CONTEXTS

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

    //
    // Indicates if there are execution contexts ready to be executed.
    //
    BOOLEAN ECsReady;

    //
    // Indicates the next time that execution contexts should be executed.
    //
    uint64_t ECsReadyTime;

#endif // QUIC_USE_EXECUTION_CONTEXTS

} CXPLAT_WORKER;

uint32_t CxPlatWorkerCount;
CXPLAT_WORKER* CxPlatWorkers;
CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context);

void
CxPlatWorkerWake(
    _In_ CXPLAT_WORKER* Worker
    )
{
    CxPlatEventQEnqueue(&Worker->EventQ, &Worker->QuicSqe, (void*)&QuicEventPayload);
}

CXPLAT_EVENTQ*
CxPlatWorkerGetEventQ(
    _In_ uint16_t IdealProcessor
    )
{
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
#ifdef QUIC_USE_EXECUTION_CONTEXTS
        CxPlatLockInitialize(&CxPlatWorkers[i].ECLock);
        CxPlatWorkers[i].InitializedECLock = TRUE;
#endif // QUIC_USE_EXECUTION_CONTEXTS
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
        if (!CxPlatSqeInitialize(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].ShutdownSqe, NULL)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(shutdown)");
            goto Error;
        }
        CxPlatWorkers[i].InitializedShutdownSqe = TRUE;
        if (!CxPlatSqeInitialize(&CxPlatWorkers[i].EventQ, &CxPlatWorkers[i].QuicSqe, NULL)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatSqeInitialize(quic)");
            goto Error;
        }
        CxPlatWorkers[i].InitializedQuicSqe = TRUE;
#endif
        if (QUIC_FAILED(
            CxPlatThreadCreate(&ThreadConfig, &CxPlatWorkers[i].Thread))) {
            goto Error;
        }
        CxPlatWorkers[i].InitializedThread = TRUE;
    }

    return TRUE;

Error:

    for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
        if (CxPlatWorkers[i].InitializedThread) {
            CxPlatThreadWait(&CxPlatWorkers[i].Thread);
            CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
        }
#ifdef CXPLAT_SQE_INIT
        if (CxPlatWorkers[i].InitializedQuicSqe) {
            CxPlatSqeCleanup(&CxPlatWorkers[i].QuicSqe);
        }
        if (CxPlatWorkers[i].InitializedShutdownSqe) {
            CxPlatSqeCleanup(&CxPlatWorkers[i].ShutdownSqe);
        }
#endif // CXPLAT_SQE_INIT
        if (CxPlatWorkers[i].InitializedEventQ) {
            CxPlatEventQCleanup(&CxPlatWorkers[i].EventQ);
        }
#ifdef QUIC_USE_EXECUTION_CONTEXTS
        if (CxPlatWorkers[i].InitializedECLock) {
            CxPlatLockUninitialize(&CxPlatWorkers[i].ECLock);
        }
#endif // QUIC_USE_EXECUTION_CONTEXTS
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
    for (uint32_t i = 0; i < CxPlatWorkerCount; ++i) {
        CxPlatEventQEnqueue(
            &CxPlatWorkers[i].EventQ,
            &CxPlatWorkers[i].ShutdownSqe,
            NULL);
        CxPlatThreadWait(&CxPlatWorkers[i].Thread);
        CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
#ifdef CXPLAT_SQE_INIT
        CxPlatSqeCleanup(&CxPlatWorkers[i].QuicSqe);
        CxPlatSqeCleanup(&CxPlatWorkers[i].ShutdownSqe);
#endif // CXPLAT_SQE_INIT
        CxPlatEventQCleanup(&CxPlatWorkers[i].EventQ);
#ifdef QUIC_USE_EXECUTION_CONTEXTS
        CxPlatLockUninitialize(&CxPlatWorkers[i].ECLock);
#endif // QUIC_USE_EXECUTION_CONTEXTS
    }

    CXPLAT_FREE(CxPlatWorkers, QUIC_POOL_PLATFORM_WORKER);
    CxPlatWorkers = NULL;
}

#ifdef QUIC_USE_EXECUTION_CONTEXTS

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
}

void
CxPlatWakeExecutionContext(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    )
{
    CxPlatWorkerWake((CXPLAT_WORKER*)Context->CxPlatContext);
}

BOOLEAN // Did work?
CxPlatRunExecutionContexts(
    _In_ CXPLAT_WORKER* Worker,
    _Inout_ uint64_t* TimeNow
    )
{
    Worker->ECsReady = FALSE;
    Worker->ECsReadyTime = UINT64_MAX;

    if (QuicReadPtrNoFence(&Worker->PendingECs)) {
        CXPLAT_SLIST_ENTRY** Tail = NULL;
        CXPLAT_SLIST_ENTRY* Head = NULL;
        CxPlatLockAcquire(&Worker->ECLock);
        Head = Worker->PendingECs;
        Worker->PendingECs = NULL;
        CxPlatLockRelease(&Worker->ECLock);

        Tail = &Head;
        while (*Tail) {
            Tail = &(*Tail)->Next;
        }

        *Tail = Worker->ExecutionContexts;
        Worker->ExecutionContexts = Head;
    }

    BOOLEAN DidWork = FALSE;
    CXPLAT_SLIST_ENTRY** EC = &Worker->ExecutionContexts;
    while (*EC != NULL) {
        CXPLAT_EXECUTION_CONTEXT* Context =
            CXPLAT_CONTAINING_RECORD(*EC, CXPLAT_EXECUTION_CONTEXT, Entry);
        BOOLEAN Ready = InterlockedFetchAndClearBoolean(&Context->Ready);
        if (Ready || Context->NextTimeUs <= *TimeNow) {
            CXPLAT_SLIST_ENTRY* Next = Context->Entry.Next;
            DidWork = TRUE;
            if (!Context->Callback(Context->Context, TimeNow, Worker->ThreadId)) {
                *EC = Next; // Remove Context from the list.
                continue;
            } else if (Context->Ready) {
                Worker->ECsReady = TRUE;
            }
        }
        if (Context->NextTimeUs < Worker->ECsReadyTime) {
            Worker->ECsReadyTime = Context->NextTimeUs;
        }
        EC = &Context->Entry.Next;
    }

    return DidWork;
}

#endif

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

    Worker->ThreadId = CxPlatCurThreadID();

    uint32_t NoWorkCount = 0;
    uint32_t CqeCount;
    CXPLAT_CQE Cqes[16];

    while (TRUE) {

        uint32_t WaitTime = UINT32_MAX;
        ++NoWorkCount;

#ifdef QUIC_USE_EXECUTION_CONTEXTS
        uint64_t TimeNow = CxPlatTimeUs64();
        if (CxPlatRunExecutionContexts(Worker, &TimeNow)) {
            NoWorkCount = 0;
        }
        if (Worker->ECsReady) {
            WaitTime = 0;
        } else if (Worker->ECsReadyTime != UINT64_MAX) {
            uint64_t Diff = Worker->ECsReadyTime - TimeNow;
            Diff = US_TO_MS(Diff);
            if (Diff == 0) {
                WaitTime = 1;
            } else if (Diff < UINT32_MAX) {
                WaitTime = (uint32_t)Diff;
            } else {
                WaitTime = UINT32_MAX-1;
            }
        }
#endif

        CqeCount = CxPlatEventQDequeue(&Worker->EventQ, Cqes, ARRAYSIZE(Cqes), WaitTime);

        if (CqeCount != 0) {
            NoWorkCount = 0;
            for (uint32_t i = 0; i < CqeCount; ++i) {
                if (CxPlatCqeUserData(&Cqes[i]) == NULL) {
                    goto Shutdown; // NULL user data means shutdown.
                }
                if (CxPlatCqeType(&Cqes[i]) != CXPLAT_CQE_TYPE_QUIC_BASE) {
                    CxPlatDataPathProcessCqe(&Cqes[i]);
                }
            }
            CxPlatEventQReturnCqes(&Worker->EventQ, CqeCount);

        } else if (NoWorkCount > CXPLAT_WORKER_IDLE_WORK_THRESHOLD_COUNT) {
            CxPlatSchedulerYield();
            NoWorkCount = 0;
        }
    }

Shutdown:

    QuicTraceLogInfo(
        PlatformWorkerThreadStop,
        "[ lib][%p] Worker stop",
        Worker);

    CXPLAT_THREAD_RETURN(0);
}
