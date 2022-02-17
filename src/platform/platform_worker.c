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

typedef struct QUIC_CACHEALIGN CXPLAT_WORKER {

    //
    // Indicates if the worker is currently running.
    //
    BOOLEAN Running;

    //
    // Event to wake the worker.
    //
    CXPLAT_EVENT WakeEvent;

    //
    // Thread used to drive the worker.
    //
    CXPLAT_THREAD Thread;

    //
    // The ID of the thread.
    //
    CXPLAT_THREAD_ID ThreadId;

    //
    // The datapath execution context running on this worker.
    //
    void* DatapathEC;

#ifdef QUIC_USE_EXECUTION_CONTEXTS

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
#ifdef QUIC_USE_EXECUTION_CONTEXTS
    Worker->ECsReady = TRUE;
#endif // QUIC_USE_EXECUTION_CONTEXTS
    if (Worker->DatapathEC) {
        CxPlatDataPathWake(Worker->DatapathEC);
    } else {
        CxPlatEventSet(Worker->WakeEvent);
    }
}

void
CxPlatWorkerRegisterDataPath(
    _In_ uint16_t IdealProcessor,
    _In_ void* Context
    )
{
    CXPLAT_WORKER* Worker = &CxPlatWorkers[IdealProcessor % CxPlatWorkerCount];
    CXPLAT_FRE_ASSERTMSG(Worker->DatapathEC == NULL, "Only one datapath allowed!");
    Worker->DatapathEC = Context;
    CxPlatEventSet(Worker->WakeEvent);
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
        CxPlatWorkers[i].Running = TRUE;
        CxPlatEventInitialize(&CxPlatWorkers[i].WakeEvent, FALSE, FALSE);
        ThreadConfig.IdealProcessor = (uint16_t)i;
        ThreadConfig.Context = &CxPlatWorkers[i];
        if (QUIC_FAILED(
            CxPlatThreadCreate(&ThreadConfig, &CxPlatWorkers[i].Thread))) {
            CxPlatWorkers[i].Running = FALSE;
            goto Error;
        }
    }

    return TRUE;

Error:

    for (uint32_t i = 0; i < CxPlatWorkerCount && CxPlatWorkers[i].Running; ++i) {
        CxPlatWorkers[i].Running = FALSE;
        CxPlatEventSet(CxPlatWorkers[i].WakeEvent);
        CxPlatThreadWait(&CxPlatWorkers[i].Thread);
        CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
        CxPlatEventUninitialize(CxPlatWorkers[i].WakeEvent);
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
        CxPlatWorkers[i].Running = FALSE;
        CxPlatEventSet(CxPlatWorkers[i].WakeEvent);
        CxPlatThreadWait(&CxPlatWorkers[i].Thread);
        CxPlatThreadDelete(&CxPlatWorkers[i].Thread);
        CxPlatEventUninitialize(CxPlatWorkers[i].WakeEvent);
    }

    CXPLAT_FREE(CxPlatWorkers, QUIC_POOL_PLATFORM_WORKER);
    CxPlatWorkers = NULL;
}

#ifdef QUIC_USE_EXECUTION_CONTEXTS

//
// TODO - Add synchronization around ExecutionContexts
//

void
CxPlatAddExecutionContext(
    _Inout_ CXPLAT_EXECUTION_CONTEXT* Context,
    _In_ uint16_t IdealProcessor
    )
{
    CXPLAT_WORKER* Worker = &CxPlatWorkers[IdealProcessor % CxPlatWorkerCount];
    Context->CxPlatContext = Worker;
    Context->Entry.Next = Worker->ExecutionContexts;
    Worker->ExecutionContexts = &Context->Entry;
}

void
CxPlatWakeExecutionContext(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    )
{
    CxPlatWorkerWake((CXPLAT_WORKER*)Context->CxPlatContext);
}

void
CxPlatRunExecutionContexts(
    _In_ CXPLAT_WORKER* Worker,
    _Inout_ uint64_t* TimeNow
    )
{
    Worker->ECsReady = FALSE;
    Worker->ECsReadyTime = UINT64_MAX;

    if (Worker->ExecutionContexts == NULL) {
        return;
    }

    CXPLAT_SLIST_ENTRY** EC = &Worker->ExecutionContexts;
    while (*EC != NULL) {
        CXPLAT_EXECUTION_CONTEXT* Context =
            CXPLAT_CONTAINING_RECORD(*EC, CXPLAT_EXECUTION_CONTEXT, Entry);
        if (Context->Ready || Context->NextTimeUs <= *TimeNow) {
            CXPLAT_SLIST_ENTRY* Next = Context->Entry.Next;
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
}

#endif

CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context)
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Context;
    CXPLAT_DBG_ASSERT(Worker != NULL);

    QuicTraceLogInfo(
        PlatformWorkerThreadStart,
        "[ lib][%p] Worker start",
        Worker);

    Worker->ThreadId = CxPlatCurThreadID();

    while (Worker->Running) {

        uint32_t WaitTime = UINT32_MAX;

#ifdef QUIC_USE_EXECUTION_CONTEXTS
        uint64_t TimeNow = CxPlatTimeUs64();
        CxPlatRunExecutionContexts(Worker, &TimeNow);
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

        if (Worker->DatapathEC) {
            CxPlatDataPathRunEC(&Worker->DatapathEC, Worker->ThreadId, WaitTime);
        } else if (WaitTime != 0) {
            CxPlatEventWaitWithTimeout(Worker->WakeEvent, WaitTime);
        }
    }

    QuicTraceLogInfo(
        PlatformWorkerThreadStop,
        "[ lib][%p] Worker stop",
        Worker);

    CXPLAT_THREAD_RETURN(0);
}
