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
    // Thread used to drive the worker. Only set when the worker is created and
    // managed internally (default case).
    //
    CXPLAT_THREAD Thread;

    //
    // Event queue to drive execution.
    //
    CXPLAT_EVENTQ EventQ;

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

    //
    // Serializes access to the execution contexts.
    //
    CXPLAT_LOCK ECLock;

    //
    // The current execution state for the worker.
    //
    CXPLAT_EXECUTION_STATE State;

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
    BOOLEAN InitializedShutdownSqe : 1;
    BOOLEAN InitializedWakeSqe : 1;
    BOOLEAN InitializedUpdatePollSqe : 1;
    BOOLEAN InitializedThread : 1;
    BOOLEAN InitializedECLock : 1;
    BOOLEAN StoppingThread : 1;
    BOOLEAN StoppedThread : 1;
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

typedef struct CXPLAT_WORKER_POOL {

    CXPLAT_RUNDOWN_REF Rundown;
    uint32_t WorkerCount;

#if DEBUG
    //
    // Detailed ref counts.
    // Note: These ref counts are biased by 1, so lowest they go is 1. It is an
    // error for them to ever be zero.
    //
    CXPLAT_REF_COUNT RefTypeBiasedCount[CXPLAT_WORKER_POOL_REF_COUNT];
#endif

    CXPLAT_WORKER Workers[0];

} CXPLAT_WORKER_POOL;

CXPLAT_THREAD_CALLBACK(CxPlatWorkerThread, Context);

static void
ShutdownCompletion(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_WORKER* Worker =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_WORKER, ShutdownSqe);
    Worker->StoppedThread = TRUE;
}

static void
WakeCompletion(
    _In_ CXPLAT_CQE* Cqe
    )
{
    //
    // No-op as the goal is simply to wake the event queue thread
    //
    UNREFERENCED_PARAMETER(Cqe);
}

void
CxPlatUpdateExecutionContexts(
    _In_ CXPLAT_WORKER* Worker
    );

static void
UpdatePollCompletion(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_WORKER* Worker =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_WORKER, UpdatePollSqe);
    CxPlatUpdateExecutionContexts(Worker);
}

BOOLEAN
CxPlatWorkerPoolInitWorker(
    _Inout_ CXPLAT_WORKER* Worker,
    _In_ uint16_t IdealProcessor,
    _In_opt_ CXPLAT_EVENTQ* EventQ, // Only for external workers
    _In_opt_ CXPLAT_THREAD_CONFIG* ThreadConfig // Only for internal workers
    )
{
    CxPlatLockInitialize(&Worker->ECLock);
    CxPlatListInitializeHead(&Worker->DynamicPoolList);
    Worker->InitializedECLock = TRUE;
    Worker->IdealProcessor = IdealProcessor;
    Worker->State.WaitTime = UINT32_MAX;
    Worker->State.ThreadID = UINT32_MAX;

    if (EventQ != NULL) {
        Worker->EventQ = *EventQ;
    } else {
        if (!CxPlatEventQInitialize(&Worker->EventQ)) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatEventQInitialize");
            return FALSE;
        }
        Worker->InitializedEventQ = TRUE;
    }

    if (!CxPlatSqeInitialize(&Worker->EventQ, ShutdownCompletion, &Worker->ShutdownSqe)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CxPlatSqeInitialize(shutdown)");
        return FALSE;
    }
    Worker->InitializedShutdownSqe = TRUE;

    if (!CxPlatSqeInitialize(&Worker->EventQ, WakeCompletion, &Worker->WakeSqe)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CxPlatSqeInitialize(wake)");
        return FALSE;
    }
    Worker->InitializedWakeSqe = TRUE;

    if (!CxPlatSqeInitialize(&Worker->EventQ, UpdatePollCompletion, &Worker->UpdatePollSqe)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CxPlatSqeInitialize(updatepoll)");
        return FALSE;
    }
    Worker->InitializedUpdatePollSqe = TRUE;

    if (ThreadConfig != NULL) {
        ThreadConfig->IdealProcessor = IdealProcessor;
        ThreadConfig->Context = Worker;
        if (QUIC_FAILED(
            CxPlatThreadCreate(ThreadConfig, &Worker->Thread))) {
            return FALSE;
        }
        Worker->InitializedThread = TRUE;
    }

    return TRUE;
}

void
CxPlatWorkerPoolDestroyWorker(
    _In_ CXPLAT_WORKER* Worker
    )
{
    if (Worker->InitializedThread) {
        Worker->StoppingThread = TRUE;
        CxPlatEventQEnqueue(&Worker->EventQ, &Worker->ShutdownSqe);
        CxPlatThreadWait(&Worker->Thread);
        CxPlatThreadDelete(&Worker->Thread);
#if DEBUG
        CXPLAT_DBG_ASSERT(Worker->ThreadStarted);
        CXPLAT_DBG_ASSERT(Worker->ThreadFinished);
#endif
        Worker->DestroyedThread = TRUE;
    } else {
        // TODO - Handle synchronized cleanup for external event queues?
    }
    if (Worker->InitializedUpdatePollSqe) {
        CxPlatSqeCleanup(&Worker->EventQ, &Worker->UpdatePollSqe);
    }
    if (Worker->InitializedWakeSqe) {
        CxPlatSqeCleanup(&Worker->EventQ, &Worker->WakeSqe);
    }
    if (Worker->InitializedShutdownSqe) {
        CxPlatSqeCleanup(&Worker->EventQ, &Worker->ShutdownSqe);
    }
    if (Worker->InitializedEventQ) {
        CxPlatEventQCleanup(&Worker->EventQ);
    }
    if (Worker->InitializedECLock) {
        CxPlatLockUninitialize(&Worker->ECLock);
    }
}

CXPLAT_WORKER_POOL*
CxPlatWorkerPoolCreate(
    _In_opt_ QUIC_GLOBAL_EXECUTION_CONFIG* Config,
    _In_ CXPLAT_WORKER_POOL_REF RefType
    )
{
    //
    // Build up the processor list either from the config or default to one per
    // system processor.
    //
    const uint16_t* ProcessorList;
    uint32_t ProcessorCount;
    if (Config && Config->ProcessorCount) {
        ProcessorCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        ProcessorCount = CxPlatProcCount();
        ProcessorList = NULL;
    }
    CXPLAT_DBG_ASSERT(ProcessorCount > 0 && ProcessorCount <= UINT16_MAX);

    //
    // Allocate enough space for the pool and worker structs.
    //
    const size_t WorkerPoolSize =
        sizeof(CXPLAT_WORKER_POOL) +
        sizeof(CXPLAT_WORKER) * ProcessorCount;
    CXPLAT_WORKER_POOL* WorkerPool =
        CXPLAT_ALLOC_PAGED(WorkerPoolSize, QUIC_POOL_PLATFORM_WORKER);
    if (WorkerPool == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER_POOL",
            WorkerPoolSize);
        return NULL;
    }
    CxPlatZeroMemory(WorkerPool, WorkerPoolSize);
    WorkerPool->WorkerCount = ProcessorCount;

    //
    // Build up the configuration for creating the worker threads.
    //
    uint16_t ThreadFlags = CXPLAT_THREAD_FLAG_SET_IDEAL_PROC;
    if (Config) {
        if (Config->Flags & QUIC_GLOBAL_EXECUTION_CONFIG_FLAG_NO_IDEAL_PROC) {
            ThreadFlags &= ~CXPLAT_THREAD_FLAG_SET_IDEAL_PROC; // Remove the flag
        }
        if (Config->Flags & QUIC_GLOBAL_EXECUTION_CONFIG_FLAG_HIGH_PRIORITY) {
            ThreadFlags |= CXPLAT_THREAD_FLAG_HIGH_PRIORITY;
        }
        if (Config->Flags & QUIC_GLOBAL_EXECUTION_CONFIG_FLAG_AFFINITIZE) {
            ThreadFlags |= CXPLAT_THREAD_FLAG_SET_AFFINITIZE;
        }
    }

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        ThreadFlags,
        0,
        "cxplat_worker",
        CxPlatWorkerThread,
        NULL
    };

    //
    // Set up each worker thread with the configuration initialized above. Also
    // creates the event queue and all the SQEs used to shutdown, wake and poll
    // the worker.
    //
    for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
        const uint16_t IdealProcessor = ProcessorList ? ProcessorList[i] : (uint16_t)i;
        CXPLAT_DBG_ASSERT(IdealProcessor < CxPlatProcCount());

        CXPLAT_WORKER* Worker = &WorkerPool->Workers[i];
        if (!CxPlatWorkerPoolInitWorker(
                Worker, IdealProcessor, NULL, &ThreadConfig)) {
            goto Error;
        }
    }

    CxPlatRundownInitialize(&WorkerPool->Rundown);
#if DEBUG
    CxPlatRefInitializeMultiple(WorkerPool->RefTypeBiasedCount, CXPLAT_WORKER_POOL_REF_COUNT);
    CxPlatRefIncrement(&WorkerPool->RefTypeBiasedCount[RefType]);
#else
    UNREFERENCED_PARAMETER(RefType);
#endif

    return WorkerPool;

Error:

    //
    // On failure, clean up all the workers that did get started.
    //
    for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
        CXPLAT_WORKER* Worker = &WorkerPool->Workers[i];
        CxPlatWorkerPoolDestroyWorker(Worker);
    }

    CXPLAT_FREE(WorkerPool, QUIC_POOL_PLATFORM_WORKER);

    return NULL;
}

_Success_(return != NULL)
CXPLAT_WORKER_POOL*
CxPlatWorkerPoolCreateExternal(
    _In_ uint32_t Count,
    _In_reads_(Count) QUIC_EXECUTION_CONFIG* Configs,
    _Out_writes_(Count) QUIC_EXECUTION** Executions
    )
{
    CXPLAT_DBG_ASSERT(Count > 0 && Count <= UINT16_MAX);

    //
    // Allocate enough space for the pool and worker structs.
    //
    const size_t WorkerPoolSize =
        sizeof(CXPLAT_WORKER_POOL) + sizeof(CXPLAT_WORKER) * Count;
    CXPLAT_WORKER_POOL* WorkerPool =
        CXPLAT_ALLOC_PAGED(WorkerPoolSize, QUIC_POOL_PLATFORM_WORKER);
    if (WorkerPool == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER_POOL",
            WorkerPoolSize);
        return NULL;
    }
    CxPlatZeroMemory(WorkerPool, WorkerPoolSize);
    WorkerPool->WorkerCount = Count;

    //
    // Set up each worker thread with the configuration initialized above. Also
    // creates the event queue and all the SQEs used to shutdown, wake and poll
    // the worker.
    //
    for (uint32_t i = 0; i < Count; ++i) {
        const uint16_t IdealProcessor = (uint16_t)Configs[i].IdealProcessor;
        CXPLAT_DBG_ASSERT(IdealProcessor < CxPlatProcCount());

        CXPLAT_WORKER* Worker = &WorkerPool->Workers[i];
        if (!CxPlatWorkerPoolInitWorker(
                Worker, IdealProcessor, Configs[i].EventQ, NULL)) {
            goto Error;
        }
        Executions[i] = (QUIC_EXECUTION*)Worker;
    }

    CxPlatRundownInitialize(&WorkerPool->Rundown);

#if DEBUG
    CxPlatRefInitializeMultiple(WorkerPool->RefTypeBiasedCount, CXPLAT_WORKER_POOL_REF_COUNT);
    CxPlatRefIncrement(&WorkerPool->RefTypeBiasedCount[CXPLAT_WORKER_POOL_REF_EXTERNAL]);
#endif

    return WorkerPool;

Error:

    //
    // On failure, clean up all the workers that did get started.
    //
    for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
        CXPLAT_WORKER* Worker = &WorkerPool->Workers[i];
        CxPlatWorkerPoolDestroyWorker(Worker);
    }

    CXPLAT_FREE(WorkerPool, QUIC_POOL_PLATFORM_WORKER);

    return NULL;
}

void
CxPlatWorkerPoolDelete(
    _In_opt_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ CXPLAT_WORKER_POOL_REF RefType
    )
{
    if (WorkerPool != NULL) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!CxPlatRefDecrement(&WorkerPool->RefTypeBiasedCount[RefType]));
#else
        UNREFERENCED_PARAMETER(RefType);
#endif
        CxPlatRundownReleaseAndWait(&WorkerPool->Rundown);

#if DEBUG
        for (uint32_t i = 0; i < CXPLAT_WORKER_POOL_REF_COUNT; i++) {
            CXPLAT_DBG_ASSERT(WorkerPool->RefTypeBiasedCount[i] == 1);
        }
#endif

        for (uint32_t i = 0; i < WorkerPool->WorkerCount; ++i) {
            CXPLAT_WORKER* Worker = &WorkerPool->Workers[i];
            CxPlatWorkerPoolDestroyWorker(Worker);
        }

        CxPlatRundownUninitialize(&WorkerPool->Rundown);
        CXPLAT_FREE(WorkerPool, QUIC_POOL_PLATFORM_WORKER);
    }
}

uint32_t
CxPlatWorkerPoolGetCount(
    _In_ CXPLAT_WORKER_POOL* WorkerPool
    )
{
    return WorkerPool->WorkerCount;
}

BOOLEAN
CxPlatWorkerPoolAddRef(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ CXPLAT_WORKER_POOL_REF RefType
    )
{
    BOOLEAN Result = CxPlatRundownAcquire(&WorkerPool->Rundown);
#if DEBUG
    if (Result) {
        CxPlatRefIncrement(&WorkerPool->RefTypeBiasedCount[RefType]);
    }
#else
    UNREFERENCED_PARAMETER(RefType);
#endif
    return Result;
}

void
CxPlatWorkerPoolRelease(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ CXPLAT_WORKER_POOL_REF RefType
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!CxPlatRefDecrement(&WorkerPool->RefTypeBiasedCount[RefType]));
#else
    UNREFERENCED_PARAMETER(RefType);
#endif
    CxPlatRundownRelease(&WorkerPool->Rundown);
}

uint32_t
CxPlatWorkerPoolGetIdealProcessor(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ uint32_t Index
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CXPLAT_FRE_ASSERT(Index < WorkerPool->WorkerCount);
    return WorkerPool->Workers[Index].IdealProcessor;
}

CXPLAT_EVENTQ*
CxPlatWorkerPoolGetEventQ(
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ uint16_t Index
    )
{
    CXPLAT_DBG_ASSERT(WorkerPool);
    CXPLAT_FRE_ASSERT(Index < WorkerPool->WorkerCount);
    return &WorkerPool->Workers[Index].EventQ;
}

void
CxPlatWorkerPoolAddExecutionContext(
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
        CxPlatEventQEnqueue(&Worker->EventQ, &Worker->UpdatePollSqe);
    }
}

void
CxPlatWakeExecutionContext(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    )
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Context->CxPlatContext;
    if (!InterlockedFetchAndSetBoolean(&Worker->Running)) {
        CxPlatEventQEnqueue(&Worker->EventQ, &Worker->WakeSqe);
    }
}

BOOLEAN
CxPlatWorkerIsThisThread(
    _In_ CXPLAT_EXECUTION_CONTEXT* Context
    )
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Context->CxPlatContext;
    return Worker->State.ThreadID == CxPlatCurThreadID();
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
    _In_ CXPLAT_WORKER* Worker
    )
{
    if (Worker->ExecutionContexts == NULL) {
        Worker->State.WaitTime = UINT32_MAX;
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
        if (Ready || Context->NextTimeUs <= Worker->State.TimeNow) {
#if DEBUG // Debug statistics
            ++Worker->EcRunCount;
#endif
            CXPLAT_SLIST_ENTRY* Next = Context->Entry.Next;
            if (!Context->Callback(Context->Context, &Worker->State)) {
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
        Worker->State.WaitTime = 0;
    } else if (NextTime != UINT64_MAX) {
        uint64_t Diff = NextTime - Worker->State.TimeNow;
        Diff = US_TO_MS(Diff);
        if (Diff == 0) {
            Worker->State.WaitTime = 1;
        } else if (Diff < UINT32_MAX) {
            Worker->State.WaitTime = (uint32_t)Diff;
        } else {
            Worker->State.WaitTime = UINT32_MAX-1;
        }
    } else {
        Worker->State.WaitTime = UINT32_MAX;
    }
}

uint32_t
CxPlatWorkerPoolWorkerPoll(
    _In_ QUIC_EXECUTION* Execution
    )
{
    CXPLAT_WORKER* Worker = (CXPLAT_WORKER*)Execution;
    Worker->State.TimeNow = CxPlatTimeUs64();
    Worker->State.ThreadID = CxPlatCurThreadID();

    CxPlatRunExecutionContexts(Worker);
    if (Worker->State.WaitTime && InterlockedFetchAndClearBoolean(&Worker->Running)) {
        Worker->State.TimeNow = CxPlatTimeUs64();
        CxPlatRunExecutionContexts(Worker); // Run once more to handle race conditions
    }

    return Worker->State.WaitTime;
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

void
CxPlatProcessEvents(
    _In_ CXPLAT_WORKER* Worker
    )
{
    CXPLAT_CQE Cqes[16];
    uint32_t CqeCount =
        CxPlatEventQDequeue(
            &Worker->EventQ,
            Cqes,
            ARRAYSIZE(Cqes),
            Worker->State.WaitTime);
    uint32_t CurrentCqeCount = CqeCount;
    CXPLAT_CQE* CurrentCqe = Cqes;

#if DEBUG && defined(CXPLAT_USE_IO_URING)
    //
    // On Ubuntu 24.04, at least, CQE addresses are not mapped into the
    // debugger. To simplify debugging, copy the CQE contents into the stack
    // address space.
    //
    struct io_uring_cqe IoCqes[ARRAYSIZE(Cqes)];
    for (uint32_t i = 0; i < CqeCount; i++) {
        IoCqes[i] = *Cqes[i];
    }
    UNREFERENCED_PARAMETER(IoCqes);
#endif

    InterlockedFetchAndSetBoolean(&Worker->Running);
    if (CqeCount != 0) {
#if DEBUG // Debug statistics
        Worker->CqeCount += CqeCount;
#endif
        Worker->State.NoWorkCount = 0;
        while (CurrentCqeCount > 0) {
            CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(CurrentCqe);
#ifdef CXPLAT_USE_EVENT_BATCH_COMPLETION
            Sqe->Completion(&CurrentCqe, &CurrentCqeCount);
#else
            Sqe->Completion(CurrentCqe);
            CurrentCqe++;
            CurrentCqeCount--;
#endif
        }
        CxPlatEventQReturn(&Worker->EventQ, CqeCount);
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

    QuicTraceLogInfo(
        PlatformWorkerThreadStart,
        "[ lib][%p] Worker start",
        Worker);
#if DEBUG
    Worker->ThreadStarted = TRUE;
#endif

    Worker->State.ThreadID = CxPlatCurThreadID();
    Worker->Running = TRUE;

    while (!Worker->StoppedThread) {

        ++Worker->State.NoWorkCount;
#if DEBUG // Debug statistics
        ++Worker->LoopCount;
#endif
        Worker->State.TimeNow = CxPlatTimeUs64();

        CxPlatRunExecutionContexts(Worker);
        if (Worker->State.WaitTime && InterlockedFetchAndClearBoolean(&Worker->Running)) {
            Worker->State.TimeNow = CxPlatTimeUs64();
            CxPlatRunExecutionContexts(Worker); // Run once more to handle race conditions
        }

        CxPlatProcessEvents(Worker);

        if (Worker->State.NoWorkCount == 0) {
            Worker->State.LastWorkTime = Worker->State.TimeNow;
        } else if (Worker->State.NoWorkCount > CXPLAT_WORKER_IDLE_WORK_THRESHOLD_COUNT) {
            CxPlatSchedulerYield();
            Worker->State.NoWorkCount = 0;
        }

        if (Worker->State.TimeNow - Worker->State.LastPoolProcessTime > DYNAMIC_POOL_PROCESSING_PERIOD) {
            CxPlatProcessDynamicPoolAllocators(Worker);
            Worker->State.LastPoolProcessTime = Worker->State.TimeNow;
        }
    }

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
