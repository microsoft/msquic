/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    General library functions

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "library.c.clog.h"
#endif

QUIC_LIBRARY MsQuicLib = { 0 };

QUIC_TRACE_RUNDOWN_CALLBACK QuicTraceRundown;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibApplyLoadBalancingSetting(
    void
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryEvaluateSendRetryState(
    void
    );

CXPLAT_DATAPATH_FEATURES
QuicLibraryGetDatapathFeatures(
    void
    )
{
    CXPLAT_SOCKET_FLAGS SocketFlags = CXPLAT_SOCKET_FLAG_NONE;
    if (MsQuicLib.Settings.XdpEnabled) {
        SocketFlags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    CXPLAT_DBG_ASSERT(MsQuicLib.Datapath != NULL);
    return CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath, SocketFlags);
}

//
// Initializes all global variables if not already done.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryLoad(
    void
    )
{
    if (InterlockedIncrement16(&MsQuicLib.LoadRefCount) == 1) {
        //
        // Load the library.
        //
        CxPlatSystemLoad();
        CxPlatLockInitialize(&MsQuicLib.Lock);
        CxPlatDispatchLockInitialize(&MsQuicLib.DatapathLock);
        CxPlatListInitializeHead(&MsQuicLib.Registrations);
        CxPlatListInitializeHead(&MsQuicLib.Bindings);
        QuicTraceRundownCallback = QuicTraceRundown;
        MsQuicLib.Loaded = TRUE;
        MsQuicLib.Version[0] = VER_MAJOR;
        MsQuicLib.Version[1] = VER_MINOR;
        MsQuicLib.Version[2] = VER_PATCH;
        MsQuicLib.Version[3] = VER_BUILD_ID;
        MsQuicLib.GitHash = VER_GIT_HASH_STR;
    }
}

//
// Uninitializes global variables if necessary.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUnload(
    void
    )
{
    CXPLAT_FRE_ASSERT(MsQuicLib.Loaded);
    if (InterlockedDecrement16(&MsQuicLib.LoadRefCount) == 0) {
        QUIC_LIB_VERIFY(MsQuicLib.OpenRefCount == 0);
        QUIC_LIB_VERIFY(!MsQuicLib.InUse);
        MsQuicLib.Loaded = FALSE;
        CxPlatDispatchLockUninitialize(&MsQuicLib.DatapathLock);
        CxPlatLockUninitialize(&MsQuicLib.Lock);
        CxPlatSystemUnload();
    }
}

void
MsQuicCalculatePartitionMask(
    void
    )
{
    CXPLAT_DBG_ASSERT(MsQuicLib.PartitionCount != 0);
    CXPLAT_DBG_ASSERT(MsQuicLib.PartitionCount != 0xFFFF);

    uint16_t PartitionCount = MsQuicLib.PartitionCount;

    //
    // The following operations set all bits following the higest bit to one.
    //
    PartitionCount |= (PartitionCount >> 1);
    PartitionCount |= (PartitionCount >> 2);
    PartitionCount |= (PartitionCount >> 4);
    PartitionCount |= (PartitionCount >> 8);

    MsQuicLib.PartitionMask = PartitionCount;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryFreePartitions(
    void
    )
{
    if (MsQuicLib.Partitions) {
        for (uint16_t i = 0; i < MsQuicLib.PartitionCount; ++i) {
            QuicPartitionUninitialize(&MsQuicLib.Partitions[i]);
        }
        CXPLAT_FREE(MsQuicLib.Partitions, QUIC_POOL_PERPROC);
        MsQuicLib.Partitions = NULL;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryInitializePartitions(
    void
    )
{
    CXPLAT_DBG_ASSERT(MsQuicLib.Partitions == NULL);
    MsQuicLib.PartitionCount = (uint16_t)CxPlatProcCount();
    CXPLAT_FRE_ASSERT(MsQuicLib.PartitionCount > 0);

    uint16_t* ProcessorList = NULL;
#ifndef _KERNEL_MODE
    if (MsQuicLib.WorkerPool != NULL) {
        MsQuicLib.CustomPartitions = TRUE;
        MsQuicLib.PartitionCount = (uint16_t)CxPlatWorkerPoolGetCount(MsQuicLib.WorkerPool);
    } else if (
#else
    if (
#endif
        MsQuicLib.ExecutionConfig &&
        MsQuicLib.ExecutionConfig->ProcessorCount &&
        MsQuicLib.ExecutionConfig->ProcessorCount != MsQuicLib.PartitionCount) {
        //
        // The app has specified a non-default custom set of processors to
        // create partitions one.
        //
        MsQuicLib.CustomPartitions = TRUE;
        MsQuicLib.PartitionCount = (uint16_t)MsQuicLib.ExecutionConfig->ProcessorCount;
        ProcessorList = MsQuicLib.ExecutionConfig->ProcessorList;

    } else {
        MsQuicLib.CustomPartitions = FALSE;

        uint32_t MaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
        if (MsQuicLib.Storage != NULL) {
            uint32_t MaxPartitionCountLen = sizeof(MaxPartitionCount);
            CxPlatStorageReadValue(
                MsQuicLib.Storage,
                QUIC_SETTING_MAX_PARTITION_COUNT,
                (uint8_t*)&MaxPartitionCount,
                &MaxPartitionCountLen);
            if (MaxPartitionCount == 0) {
                MaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
            }
        }
        if (MsQuicLib.PartitionCount > MaxPartitionCount) {
            MsQuicLib.PartitionCount = (uint16_t)MaxPartitionCount;
        }
    }

    CXPLAT_FRE_ASSERT(MsQuicLib.PartitionCount > 0);
    MsQuicCalculatePartitionMask();

    const size_t PartitionsSize = MsQuicLib.PartitionCount * sizeof(QUIC_PARTITION);
    MsQuicLib.Partitions = CXPLAT_ALLOC_NONPAGED(PartitionsSize, QUIC_POOL_PERPROC);
    if (MsQuicLib.Partitions == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Library Partitions",
            PartitionsSize);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(MsQuicLib.Partitions, PartitionsSize);

    uint8_t ResetHashKey[20];
    CxPlatRandom(sizeof(ResetHashKey), ResetHashKey);
    CxPlatRandom(sizeof(MsQuicLib.BaseRetrySecret), MsQuicLib.BaseRetrySecret);

    uint16_t i;
    QUIC_STATUS Status;
    for (i = 0; i < MsQuicLib.PartitionCount; ++i) {
        Status =
            QuicPartitionInitialize(
                &MsQuicLib.Partitions[i],
                i,
#ifndef _KERNEL_MODE
                ProcessorList ? ProcessorList[i] :
                    (MsQuicLib.CustomPartitions ?
                        (uint16_t)CxPlatWorkerPoolGetIdealProcessor(MsQuicLib.WorkerPool, i) :
                        i),
#else
                ProcessorList ? ProcessorList[i] : i,
#endif
                CXPLAT_HASH_SHA256,
                ResetHashKey,
                sizeof(ResetHashKey));
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    CxPlatSecureZeroMemory(ResetHashKey, sizeof(ResetHashKey));

    return QUIC_STATUS_SUCCESS;

Error:

    CxPlatSecureZeroMemory(ResetHashKey, sizeof(ResetHashKey));

    for (uint16_t j = 0; j < i; ++j) {
        QuicPartitionUninitialize(&MsQuicLib.Partitions[j]);
    }

    CXPLAT_FREE(MsQuicLib.Partitions, QUIC_POOL_PERPROC);
    MsQuicLib.Partitions = NULL;

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCounters(
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    if (MsQuicLib.Partitions == NULL) {
        CxPlatZeroMemory(Buffer, BufferLength);
        return;
    }

    CXPLAT_DBG_ASSERT(BufferLength == (BufferLength / sizeof(uint64_t) * sizeof(uint64_t)));
    CXPLAT_DBG_ASSERT(BufferLength <= sizeof(MsQuicLib.Partitions[0].PerfCounters));
    const uint32_t CountersPerBuffer = BufferLength / sizeof(int64_t);
    int64_t* const Counters = (int64_t*)Buffer;
    memcpy(Buffer, MsQuicLib.Partitions[0].PerfCounters, BufferLength);

    for (uint32_t ProcIndex = 1; ProcIndex < MsQuicLib.PartitionCount; ++ProcIndex) {
        for (uint32_t CounterIndex = 0; CounterIndex < CountersPerBuffer; ++CounterIndex) {
            Counters[CounterIndex] += MsQuicLib.Partitions[ProcIndex].PerfCounters[CounterIndex];
        }
    }

    //
    // Zero any counters that are still negative after summation.
    //
    for (uint32_t CounterIndex = 0; CounterIndex < CountersPerBuffer; ++CounterIndex) {
        if (Counters[CounterIndex] < 0) {
            Counters[CounterIndex] = 0;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCountersExternal(
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    CxPlatLockAcquire(&MsQuicLib.Lock);

    if (MsQuicLib.OpenRefCount == 0) {
        CxPlatZeroMemory(Buffer, BufferLength);
    } else {
        QuicLibrarySumPerfCounters(Buffer, BufferLength);
    }

    CxPlatLockRelease(&MsQuicLib.Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPerfCounterSnapShot(
    _In_ uint64_t TimeDiffUs
    )
{
    UNREFERENCED_PARAMETER(TimeDiffUs); // Only used in asserts below.

    int64_t PerfCounterSamples[QUIC_PERF_COUNTER_MAX];
    QuicLibrarySumPerfCounters(
        (uint8_t*)PerfCounterSamples,
        sizeof(PerfCounterSamples));

    QuicTraceEvent(
        PerfCountersRundown,
        "[ lib] Perf counters Rundown, Counters=%!CID!",
        CASTED_CLOG_BYTEARRAY16(sizeof(PerfCounterSamples), PerfCounterSamples));

// Ensure a perf counter stays below a given max Hz/frequency.
#define QUIC_COUNTER_LIMIT_HZ(TYPE, LIMIT_PER_SECOND) \
    CXPLAT_TEL_ASSERT( \
        ((1000 * 1000 * (PerfCounterSamples[TYPE] - MsQuicLib.PerfCounterSamples[TYPE])) / TimeDiffUs) < LIMIT_PER_SECOND)

// Ensures a perf counter doesn't consistently (both samples) go above a give max value.
#define QUIC_COUNTER_CAP(TYPE, MAX_LIMIT) \
    CXPLAT_TEL_ASSERT( \
        PerfCounterSamples[TYPE] < MAX_LIMIT && \
        MsQuicLib.PerfCounterSamples[TYPE] < MAX_LIMIT)

#ifndef DEBUG // Only in release mode
    //
    // Some heuristics to ensure that bad things aren't happening. TODO - these
    // values should be configurable dynamically, somehow.
    //
    QUIC_COUNTER_LIMIT_HZ(QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL, 1000000); // Don't have 1 million failed handshakes per second
    QUIC_COUNTER_CAP(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH, 100000); // Don't maintain huge queue depths
#endif

    CxPlatCopyMemory(
        MsQuicLib.PerfCounterSamples,
        PerfCounterSamples,
        sizeof(PerfCounterSamples));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryOnSettingsChanged(
    _In_ BOOLEAN UpdateRegistrations
    )
{
    if (!MsQuicLib.InUse) {
        //
        // Load balancing settings can only change before the library is
        // officially "in use", otherwise existing connections would be
        // destroyed.
        //
        QuicLibApplyLoadBalancingSetting();
    }

    MsQuicLib.HandshakeMemoryLimit =
        (MsQuicLib.Settings.RetryMemoryLimit * CxPlatTotalMemory) / UINT16_MAX;
    QuicLibraryEvaluateSendRetryState();

    if (UpdateRegistrations) {
        CxPlatLockAcquire(&MsQuicLib.Lock);

        for (CXPLAT_LIST_ENTRY* Link = MsQuicLib.Registrations.Flink;
            Link != &MsQuicLib.Registrations;
            Link = Link->Flink) {
            QuicRegistrationSettingsChanged(
                CXPLAT_CONTAINING_RECORD(Link, QUIC_REGISTRATION, Link));
        }

        CxPlatLockRelease(&MsQuicLib.Lock);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_STORAGE_CHANGE_CALLBACK)
void
MsQuicLibraryReadSettings(
    _In_opt_ void* Context
    )
{
    QuicSettingsSetDefault(&MsQuicLib.Settings);
    if (MsQuicLib.Storage != NULL) {
        QuicSettingsLoad(&MsQuicLib.Settings, MsQuicLib.Storage);
    }

    QuicTraceLogInfo(
        LibrarySettingsUpdated,
        "[ lib] Settings %p Updated",
        &MsQuicLib.Settings);
    QuicSettingsDump(&MsQuicLib.Settings);

    MsQuicLibraryOnSettingsChanged(Context != NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MsQuicLibraryInitialize(
    void
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN PlatformInitialized = FALSE;

    Status = CxPlatInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error; // Cannot log anything if platform failed to initialize.
    }
    PlatformInitialized = TRUE;

    CXPLAT_DBG_ASSERT(US_TO_MS(CxPlatGetTimerResolution()) + 1 <= UINT8_MAX);
    MsQuicLib.TimerResolutionMs = (uint8_t)US_TO_MS(CxPlatGetTimerResolution()) + 1;

    MsQuicLib.PerfCounterSamplesTime = CxPlatTimeUs64();
    CxPlatZeroMemory(MsQuicLib.PerfCounterSamples, sizeof(MsQuicLib.PerfCounterSamples));

    CxPlatRandom(sizeof(MsQuicLib.ToeplitzHash.HashKey), MsQuicLib.ToeplitzHash.HashKey);
    MsQuicLib.ToeplitzHash.InputSize = CXPLAT_TOEPLITZ_INPUT_SIZE_QUIC;
    CxPlatToeplitzHashInitialize(&MsQuicLib.ToeplitzHash);

    CxPlatZeroMemory(&MsQuicLib.Settings, sizeof(MsQuicLib.Settings));
    Status =
        CxPlatStorageOpen(
            NULL,
            MsQuicLibraryReadSettings,
            (void*)TRUE, // Non-null indicates registrations should be updated
            &MsQuicLib.Storage);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            LibraryStorageOpenFailed,
            "[ lib] Failed to open global settings, 0x%x",
            Status);
        // Non-fatal, as the process may not have access
        Status = QUIC_STATUS_SUCCESS;
    }

    MsQuicLibraryReadSettings(NULL); // NULL means don't update registrations.

    uint32_t CompatibilityListByteLength = 0;
    QuicVersionNegotiationExtGenerateCompatibleVersionsList(
        QUIC_VERSION_LATEST,
        DefaultSupportedVersionsList,
        ARRAYSIZE(DefaultSupportedVersionsList),
        NULL,
        &CompatibilityListByteLength);
    MsQuicLib.DefaultCompatibilityList =
        CXPLAT_ALLOC_NONPAGED(CompatibilityListByteLength, QUIC_POOL_DEFAULT_COMPAT_VER_LIST);
    if (MsQuicLib.DefaultCompatibilityList == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "default compatibility list",
            CompatibilityListByteLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    MsQuicLib.DefaultCompatibilityListLength = CompatibilityListByteLength / sizeof(uint32_t);
    if (QUIC_FAILED(
        QuicVersionNegotiationExtGenerateCompatibleVersionsList(
            QUIC_VERSION_LATEST,
            DefaultSupportedVersionsList,
            ARRAYSIZE(DefaultSupportedVersionsList),
            (uint8_t*)MsQuicLib.DefaultCompatibilityList,
            &CompatibilityListByteLength))) {
         goto Error;
    }

    QuicTraceEvent(
        LibraryInitializedV3,
        "[ lib] Initialized");
    QuicTraceEvent(
        LibraryVersion,
        "[ lib] Version %u.%u.%u.%u",
        MsQuicLib.Version[0],
        MsQuicLib.Version[1],
        MsQuicLib.Version[2],
        MsQuicLib.Version[3]);

#ifdef CxPlatVerifierEnabled
    uint32_t Flags;
    MsQuicLib.IsVerifying = CxPlatVerifierEnabled(Flags);
    if (MsQuicLib.IsVerifying) {
#ifdef CxPlatVerifierEnabledByAddr
        QuicTraceLogInfo(
            LibraryVerifierEnabledPerRegistration,
            "[ lib] Verifing enabled, per-registration!");
#else
        QuicTraceLogInfo(
            LibraryVerifierEnabled,
            "[ lib] Verifing enabled for all!");
#endif
    }
#endif

Error:

    if (QUIC_FAILED(Status)) {
        if (MsQuicLib.Storage != NULL) {
            CxPlatStorageClose(MsQuicLib.Storage);
            MsQuicLib.Storage = NULL;
        }
        if (MsQuicLib.DefaultCompatibilityList != NULL) {
            CXPLAT_FREE(MsQuicLib.DefaultCompatibilityList, QUIC_POOL_DEFAULT_COMPAT_VER_LIST);
            MsQuicLib.DefaultCompatibilityList = NULL;
        }
        if (PlatformInitialized) {
            CxPlatUninitialize();
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUninitialize(
    void
    )
{
#if DEBUG
    CXPLAT_DATAPATH* CleanUpDatapath = NULL;
#endif
    //
    // The library's stateless registration may still have half-opened
    // connections that need to be cleaned up before all the bindings and
    // sockets can be cleaned up. Kick off a clean up of those connections.
    //
    if (MsQuicLib.StatelessRegistration != NULL) {
        //
        // Best effort to clean up existing connections.
        //
        MsQuicRegistrationShutdown(
            (HQUIC)MsQuicLib.StatelessRegistration,
            QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
            0);
    }

    //
    // Clean up the stateless registration that might have any leftovers.
    //
    if (MsQuicLib.StatelessRegistration != NULL) {
        MsQuicRegistrationClose(
            (HQUIC)MsQuicLib.StatelessRegistration);
        MsQuicLib.StatelessRegistration = NULL;
    }

    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first closing all registrations.
    //
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&MsQuicLib.Registrations));

    //
    // Clean up the data path, which will start the final clean up of the
    // socket layer. This is generally async and doesn't block until the
    // call to CxPlatUninitialize below.
    //
    if (MsQuicLib.Datapath != NULL) {
#if DEBUG
        CleanUpDatapath = MsQuicLib.Datapath;
        UNREFERENCED_PARAMETER(CleanUpDatapath);
#endif
        CxPlatDataPathUninitialize(MsQuicLib.Datapath);
        MsQuicLib.Datapath = NULL;
    }

    if (MsQuicLib.Storage != NULL) {
        CxPlatStorageClose(MsQuicLib.Storage);
        MsQuicLib.Storage = NULL;
    }

#if DEBUG
    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first cleaning up all connections.
    //
    CXPLAT_TEL_ASSERT(MsQuicLib.ConnectionCount == 0);
#endif

#if DEBUG
    uint64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
    QuicLibrarySumPerfCounters((uint8_t*)PerfCounters, sizeof(PerfCounters));

    //
    // All active/current counters should be zero by cleanup.
    //
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_ACTIVE] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_CONNECTED] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_STRM_ACTIVE] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH] == 0);
#endif

    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first being cleaned up all listeners and connections.
    //
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&MsQuicLib.Bindings));

    MsQuicLibraryFreePartitions();

    QuicSettingsCleanup(&MsQuicLib.Settings);

    CXPLAT_FREE(MsQuicLib.DefaultCompatibilityList, QUIC_POOL_DEFAULT_COMPAT_VER_LIST);
    MsQuicLib.DefaultCompatibilityList = NULL;

    if (MsQuicLib.ExecutionConfig != NULL) {
        CXPLAT_FREE(MsQuicLib.ExecutionConfig, QUIC_POOL_EXECUTION_CONFIG);
        MsQuicLib.ExecutionConfig = NULL;
    }

    MsQuicLib.LazyInitComplete = FALSE;

    QuicTraceEvent(
        LibraryUninitialized,
        "[ lib] Uninitialized");

#ifndef _KERNEL_MODE
    CxPlatWorkerPoolDelete(MsQuicLib.WorkerPool);
    MsQuicLib.WorkerPool = NULL;
#endif
    CxPlatUninitialize();
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MsQuicAddRef(
    void
    )
{
    //
    // If you hit this assert, you are trying to call MsQuic API without
    // actually loading/starting the library/driver.
    //
    CXPLAT_TEL_ASSERT(MsQuicLib.Loaded);
    if (!MsQuicLib.Loaded) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatLockAcquire(&MsQuicLib.Lock);

    //
    // Increment global ref count, and if this is the first ref, initialize all
    // the global library state.
    //
    if (++MsQuicLib.OpenRefCount == 1) {
        Status = MsQuicLibraryInitialize();
        if (QUIC_FAILED(Status)) {
            MsQuicLib.OpenRefCount--;
            goto Error;
        }
    }

    QuicTraceEvent(
        LibraryAddRef,
        "[ lib] AddRef");

Error:

    CxPlatLockRelease(&MsQuicLib.Lock);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicRelease(
    void
    )
{
    CxPlatLockAcquire(&MsQuicLib.Lock);

    //
    // Decrement global ref count and uninitialize the library if this is the
    // last ref.
    //

    CXPLAT_FRE_ASSERT(MsQuicLib.OpenRefCount > 0);
    QuicTraceEvent(
        LibraryRelease,
        "[ lib] Release");

    if (--MsQuicLib.OpenRefCount == 0) {
        MsQuicLibraryUninitialize();
    }

    CxPlatLockRelease(&MsQuicLib.Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryLazyInitialize(
    BOOLEAN AcquireLock
    )
{
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        QuicBindingReceive,
        QuicBindingUnreachable,
    };

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN CreatedWorkerPool = FALSE;

    if (AcquireLock) {
        CxPlatLockAcquire(&MsQuicLib.Lock);
    }

    if (MsQuicLib.LazyInitComplete) {
        goto Exit;
    }

    CXPLAT_DBG_ASSERT(MsQuicLib.Partitions == NULL);
    CXPLAT_DBG_ASSERT(MsQuicLib.Datapath == NULL);

    Status = QuicLibraryInitializePartitions();
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

#ifndef _KERNEL_MODE
    if (MsQuicLib.WorkerPool == NULL) {
        MsQuicLib.WorkerPool = CxPlatWorkerPoolCreate(MsQuicLib.ExecutionConfig);
        if (!MsQuicLib.WorkerPool) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            MsQuicLibraryFreePartitions();
            goto Exit;
        }
        CreatedWorkerPool = TRUE;
    }
#endif

    Status =
        CxPlatDataPathInitialize(
            sizeof(QUIC_RX_PACKET),
            &DatapathCallbacks,
            NULL,                   // TcpCallbacks
            MsQuicLib.WorkerPool,
            &MsQuicLib.Datapath);
    if (QUIC_SUCCEEDED(Status)) {
        QuicTraceEvent(
            DataPathInitialized,
            "[data] Initialized, DatapathFeatures=%u",
            QuicLibraryGetDatapathFeatures());
        if (MsQuicLib.ExecutionConfig &&
            MsQuicLib.ExecutionConfig->PollingIdleTimeoutUs != 0) {
            CxPlatDataPathUpdatePollingIdleTimeout(
                MsQuicLib.Datapath,
                MsQuicLib.ExecutionConfig->PollingIdleTimeoutUs);
        }
    } else {
        MsQuicLibraryFreePartitions();
#ifndef _KERNEL_MODE
        if (CreatedWorkerPool) {
            CxPlatWorkerPoolDelete(MsQuicLib.WorkerPool);
            MsQuicLib.WorkerPool = NULL;
        }
#endif
        goto Exit;
    }

    CXPLAT_DBG_ASSERT(MsQuicLib.Partitions != NULL);
    CXPLAT_DBG_ASSERT(MsQuicLib.Datapath != NULL);
    MsQuicLib.LazyInitComplete = TRUE;

Exit:

    if (AcquireLock) {
        CxPlatLockRelease(&MsQuicLib.Lock);
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicSetContext(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ void* Context
    )
{
    if (Handle != NULL) {
        Handle->ClientContext = Context;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void*
QUIC_API
MsQuicGetContext(
    _In_ _Pre_defensive_ HQUIC Handle
    )
{
    return Handle == NULL ? NULL : Handle->ClientContext;
}

#pragma warning(disable:28023) // The function being assigned or passed should have a _Function_class_ annotation

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicSetCallbackHandler(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ void* Handler,
    _In_opt_ void* Context
    )
{
    if (Handle == NULL) {
        return;
    }

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_LISTENER:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_LISTENER*)Handle)->ClientCallbackHandler =
            (QUIC_LISTENER_CALLBACK_HANDLER)Handler;
        break;

    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_CONNECTION*)Handle)->ClientCallbackHandler =
            (QUIC_CONNECTION_CALLBACK_HANDLER)Handler;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_STREAM*)Handle)->ClientCallbackHandler =
            (QUIC_STREAM_CALLBACK_HANDLER)Handler;
        break;

    default:
        return;
    }

    Handle->ClientContext = Context;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibApplyLoadBalancingSetting(
    void
    )
{
    switch (MsQuicLib.Settings.LoadBalancingMode) {
    case QUIC_LOAD_BALANCING_DISABLED:
    default:
        MsQuicLib.CidServerIdLength = 0;
        break;
    case QUIC_LOAD_BALANCING_SERVER_ID_IP:    // 1 + 4 for IP address/suffix
    case QUIC_LOAD_BALANCING_SERVER_ID_FIXED: // 1 + 4 for fixed value
        MsQuicLib.CidServerIdLength = 5;
        break;
    }

    MsQuicLib.CidTotalLength =
        MsQuicLib.CidServerIdLength +
        QUIC_CID_PID_LENGTH +
        QUIC_CID_PAYLOAD_LENGTH;

    CXPLAT_FRE_ASSERT(MsQuicLib.CidServerIdLength <= QUIC_MAX_CID_SID_LENGTH);
    CXPLAT_FRE_ASSERT(MsQuicLib.CidTotalLength >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
    CXPLAT_FRE_ASSERT(MsQuicLib.CidTotalLength <= QUIC_CID_MAX_LENGTH);

    QuicTraceLogInfo(
        LibraryCidLengthSet,
        "[ lib] CID Length = %hhu",
        MsQuicLib.CidTotalLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetGlobalParam(
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SETTINGS_INTERNAL InternalSettings = {0};

    CXPLAT_DBG_ASSERT(MsQuicLib.Loaded);

    switch (Param) {
    case QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT:

        if (BufferLength != sizeof(MsQuicLib.Settings.RetryMemoryLimit)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        MsQuicLib.Settings.RetryMemoryLimit = *(uint16_t*)Buffer;
        MsQuicLib.Settings.IsSet.RetryMemoryLimit = TRUE;

        QuicTraceLogInfo(
            LibraryRetryMemoryLimitSet,
            "[ lib] Updated retry memory limit = %hu",
            MsQuicLib.Settings.RetryMemoryLimit);

        MsQuicLib.HandshakeMemoryLimit =
            (MsQuicLib.Settings.RetryMemoryLimit * CxPlatTotalMemory) / UINT16_MAX;
        QuicLibraryEvaluateSendRetryState();

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE: {

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (*(uint16_t*)Buffer > QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (MsQuicLib.InUse &&
            MsQuicLib.Settings.LoadBalancingMode != *(uint16_t*)Buffer) {
            QuicTraceLogError(
                LibraryLoadBalancingModeSetAfterInUse,
                "[ lib] Tried to change load balancing mode after library in use!");
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        MsQuicLib.Settings.LoadBalancingMode = *(uint16_t*)Buffer;
        MsQuicLib.Settings.IsSet.LoadBalancingMode = TRUE;

        QuicLibApplyLoadBalancingSetting();

        QuicTraceLogInfo(
            LibraryLoadBalancingModeSet,
            "[ lib] Updated load balancing mode = %hu",
            MsQuicLib.Settings.LoadBalancingMode);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");

        Status =
            QuicSettingsSettingsToInternal(
                BufferLength,
                (QUIC_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicSettingApply(
                &MsQuicLib.Settings,
                TRUE,
                TRUE,
                &InternalSettings)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_SUCCEEDED(Status)) {
            MsQuicLibraryOnSettingsChanged(TRUE);
        }

        break;

    case QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");

        Status =
            QuicSettingsGlobalSettingsToInternal(
                BufferLength,
                (QUIC_GLOBAL_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicSettingApply(
                &MsQuicLib.Settings,
                TRUE,
                TRUE,
                &InternalSettings)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_SUCCEEDED(Status)) {
            MsQuicLibraryOnSettingsChanged(TRUE);
        }

        break;

    case QUIC_PARAM_GLOBAL_VERSION_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");

        Status =
            QuicSettingsVersionSettingsToInternal(
                BufferLength,
                (QUIC_VERSION_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicSettingApply(
                &MsQuicLib.Settings,
                TRUE,
                TRUE,
                &InternalSettings)) {
            QuicSettingsCleanup(&InternalSettings);
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        QuicSettingsCleanup(&InternalSettings);

        if (QUIC_SUCCEEDED(Status)) {
            MsQuicLibraryOnSettingsChanged(TRUE);
        }

        break;

    case QUIC_PARAM_GLOBAL_EXECUTION_CONFIG: {
        if (BufferLength == 0) {
            if (MsQuicLib.ExecutionConfig != NULL) {
                CXPLAT_FREE(MsQuicLib.ExecutionConfig, QUIC_POOL_EXECUTION_CONFIG);
                MsQuicLib.ExecutionConfig = NULL;
            }
            return QUIC_STATUS_SUCCESS;
        }

        if (Buffer == NULL || BufferLength < QUIC_GLOBAL_EXECUTION_CONFIG_MIN_SIZE) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QUIC_GLOBAL_EXECUTION_CONFIG* Config = (QUIC_GLOBAL_EXECUTION_CONFIG*)Buffer;

        if (BufferLength < QUIC_GLOBAL_EXECUTION_CONFIG_MIN_SIZE + sizeof(uint16_t) * Config->ProcessorCount) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        for (uint32_t i = 0; i < Config->ProcessorCount; ++i) {
            if (Config->ProcessorList[i] >= CxPlatProcCount()) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        }

        CxPlatLockAcquire(&MsQuicLib.Lock);
        if (MsQuicLib.LazyInitComplete) {

            //
            // We only allow for updating the polling idle timeout after MsQuic library has
            // finished up lazy initialization, which initializes both PerProc struct and
            // the datapath; and only if the app set some custom config to begin with.
            //
            CXPLAT_DBG_ASSERT(MsQuicLib.Partitions != NULL);
            CXPLAT_DBG_ASSERT(MsQuicLib.Datapath != NULL);

            CxPlatDataPathUpdatePollingIdleTimeout(
                MsQuicLib.Datapath, Config->PollingIdleTimeoutUs);
            Status = QUIC_STATUS_SUCCESS;
            CxPlatLockRelease(&MsQuicLib.Lock);
            break;
        }

        QUIC_GLOBAL_EXECUTION_CONFIG* NewConfig =
            CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_EXECUTION_CONFIG);
        if (NewConfig == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Execution config",
                BufferLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            CxPlatLockRelease(&MsQuicLib.Lock);
            break;
        }

        if (MsQuicLib.ExecutionConfig != NULL) {
            CXPLAT_FREE(MsQuicLib.ExecutionConfig, QUIC_POOL_EXECUTION_CONFIG);
        }

        CxPlatCopyMemory(NewConfig, Config, BufferLength);
        MsQuicLib.ExecutionConfig = NewConfig;
        CxPlatLockRelease(&MsQuicLib.Lock);

        QuicTraceLogInfo(
            LibraryExecutionConfigSet,
            "[ lib] Setting execution config");

        Status = QUIC_STATUS_SUCCESS;
        break;
    }
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    case QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS:

        if (BufferLength != sizeof(QUIC_TEST_DATAPATH_HOOKS*)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        MsQuicLib.TestDatapathHooks = *(QUIC_TEST_DATAPATH_HOOKS**)Buffer;
        QuicTraceLogWarning(
            LibraryTestDatapathHooksSet,
            "[ lib] Updated test datapath hooks");

        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
    case QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR: {
        if (BufferLength != sizeof(int32_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        int32_t Value;
        CxPlatCopyMemory(&Value, Buffer, sizeof(Value));
        if (Value < 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        CxPlatSetAllocFailDenominator(Value);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE: {
        if (BufferLength != sizeof(int32_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        int32_t Value;
        CxPlatCopyMemory(&Value, Buffer, sizeof(Value));
        if (Value < 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        CxPlatSetAllocFailDenominator(-Value);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }
#endif

    case QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED:

        if (Buffer == NULL ||
            BufferLength < sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        MsQuicLib.Settings.IsSet.VersionNegotiationExtEnabled = TRUE;
        MsQuicLib.Settings.VersionNegotiationExtEnabled = *(BOOLEAN*)Buffer;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY:
        if (!MsQuicLib.LazyInitComplete) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }
        if (BufferLength != QUIC_STATELESS_RESET_KEY_LENGTH * sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status = QUIC_STATUS_SUCCESS;
        for (uint16_t i = 0; i < MsQuicLib.PartitionCount; ++i) {
            Status =
                QuicPartitionUpdateStatelessResetKey(
                    &MsQuicLib.Partitions[i],
                    CXPLAT_HASH_SHA256,
                    (uint8_t*)Buffer,
                    QUIC_STATELESS_RESET_KEY_LENGTH * sizeof(uint8_t));
            if (QUIC_FAILED(Status)) {
                break;
            }
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetGlobalParam(
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;
    uint32_t GitHashLength;

    CXPLAT_DBG_ASSERT(MsQuicLib.Loaded);

    switch (Param) {
    case QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT:

        if (*BufferLength < sizeof(MsQuicLib.Settings.RetryMemoryLimit)) {
            *BufferLength = sizeof(MsQuicLib.Settings.RetryMemoryLimit);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(MsQuicLib.Settings.RetryMemoryLimit);
        *(uint16_t*)Buffer = MsQuicLib.Settings.RetryMemoryLimit;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS:

        if (*BufferLength < sizeof(QuicSupportedVersionList)) {
            *BufferLength = sizeof(QuicSupportedVersionList);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QuicSupportedVersionList);
        CxPlatCopyMemory(
            Buffer,
            QuicSupportedVersionList,
            sizeof(QuicSupportedVersionList));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE:

        if (*BufferLength < sizeof(uint16_t)) {
            *BufferLength = sizeof(uint16_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t);
        *(uint16_t*)Buffer = MsQuicLib.Settings.LoadBalancingMode;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_PERF_COUNTERS: {

        if (*BufferLength < sizeof(int64_t)) {
            *BufferLength = sizeof(int64_t) * QUIC_PERF_COUNTER_MAX;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (*BufferLength < QUIC_PERF_COUNTER_MAX * sizeof(int64_t)) {
            //
            // Copy as many counters will fit completely in the buffer.
            //
            *BufferLength = (*BufferLength / sizeof(int64_t)) * sizeof(int64_t);
        } else {
            *BufferLength = QUIC_PERF_COUNTER_MAX * sizeof(int64_t);
        }

        QuicLibrarySumPerfCounters(Buffer, *BufferLength);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_SETTINGS:

        Status = QuicSettingsGetSettings(&MsQuicLib.Settings, BufferLength, (QUIC_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_GLOBAL_VERSION_SETTINGS:

        Status = QuicSettingsGetVersionSettings(&MsQuicLib.Settings, BufferLength, (QUIC_VERSION_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS:

        Status = QuicSettingsGetGlobalSettings(&MsQuicLib.Settings, BufferLength, (QUIC_GLOBAL_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_GLOBAL_LIBRARY_VERSION:

        if (*BufferLength < sizeof(MsQuicLib.Version)) {
            *BufferLength = sizeof(MsQuicLib.Version);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(MsQuicLib.Version);
        CxPlatCopyMemory(Buffer, MsQuicLib.Version, sizeof(MsQuicLib.Version));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH:

        GitHashLength = (uint32_t)strlen(MsQuicLib.GitHash) + 1;

        if (*BufferLength < GitHashLength) {
            *BufferLength = GitHashLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = GitHashLength;
        CxPlatCopyMemory(Buffer, MsQuicLib.GitHash, GitHashLength);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_EXECUTION_CONFIG: {
        if (MsQuicLib.ExecutionConfig == NULL) {
            *BufferLength = 0;
            Status = QUIC_STATUS_SUCCESS;
            break;
        }

        const uint32_t ConfigLength =
            QUIC_GLOBAL_EXECUTION_CONFIG_MIN_SIZE +
            sizeof(uint16_t) * MsQuicLib.ExecutionConfig->ProcessorCount;

        if (*BufferLength < ConfigLength) {
            *BufferLength = ConfigLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = ConfigLength;
        CxPlatCopyMemory(Buffer, MsQuicLib.ExecutionConfig, ConfigLength);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_TLS_PROVIDER:

        if (*BufferLength < sizeof(QUIC_TLS_PROVIDER)) {
            *BufferLength = sizeof(QUIC_TLS_PROVIDER);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_TLS_PROVIDER);
        *(QUIC_TLS_PROVIDER*)Buffer = CxPlatTlsGetProvider();

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_DATAPATH_FEATURES: {
        if (*BufferLength < sizeof(uint32_t)) {
            *BufferLength = sizeof(uint32_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (MsQuicLib.Datapath == NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(uint32_t);
        *(uint32_t*)Buffer = QuicLibraryGetDatapathFeatures();

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = MsQuicLib.Settings.VersionNegotiationExtEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_IN_USE:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = MsQuicLib.InUse;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL:

        if (*BufferLength != sizeof(CXPLAT_WORKER_POOL*)) {
            *BufferLength = sizeof(CXPLAT_WORKER_POOL*);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *(CXPLAT_WORKER_POOL**)Buffer = MsQuicLib.WorkerPool;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES: {
        static const uint32_t StatSizes[] = {
            QUIC_STATISTICS_V2_SIZE_1,
            QUIC_STATISTICS_V2_SIZE_2,
            QUIC_STATISTICS_V2_SIZE_3,
            QUIC_STATISTICS_V2_SIZE_4
        };
        static const uint32_t NumStatSizes = ARRAYSIZE(StatSizes);
        uint32_t MaxSizes = *BufferLength / sizeof(uint32_t);
        if (MaxSizes == 0) {
            *BufferLength = NumStatSizes * sizeof(uint32_t); // Indicate the max size.
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        const uint32_t ToCopy =
            CXPLAT_MIN(MaxSizes, NumStatSizes) * sizeof(uint32_t);
        CxPlatCopyMemory(Buffer, StatSizes, ToCopy);
        *BufferLength = ToCopy;
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetParam(
    _In_ HQUIC Handle,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_CONFIGURATION* Configuration;
    QUIC_LISTENER* Listener;
    QUIC_CONNECTION* Connection;
    QUIC_STREAM* Stream;

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_REGISTRATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
        Configuration = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Registration = (QUIC_REGISTRATION*)Handle;
        break;

    case QUIC_HANDLE_TYPE_CONFIGURATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Configuration = (QUIC_CONFIGURATION*)Handle;
        Registration = Configuration->Registration;
        break;

    case QUIC_HANDLE_TYPE_LISTENER:
        Stream = NULL;
        Connection = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Listener = (QUIC_LISTENER*)Handle;
        Configuration = NULL;
        Registration = Listener->Registration;
        break;

    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
        Stream = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Stream = (QUIC_STREAM*)Handle;
        Connection = Stream->Connection;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    default:
        CXPLAT_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    switch (Param & 0x7F000000)
    {
    case QUIC_PARAM_PREFIX_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamSet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_CONFIGURATION:
        if (Configuration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConfigurationParamSet(Configuration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamSet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamSet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_TLS:
    case QUIC_PARAM_PREFIX_TLS_SCHANNEL:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = CxPlatTlsParamSet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_STREAM:
        if (Stream == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicStreamParamSet(Stream, Param, BufferLength, Buffer);
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetParam(
    _In_ HQUIC Handle,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_CONFIGURATION* Configuration;
    QUIC_LISTENER* Listener;
    QUIC_CONNECTION* Connection;
    QUIC_STREAM* Stream;

    CXPLAT_DBG_ASSERT(BufferLength);

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_REGISTRATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
        Configuration = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Registration = (QUIC_REGISTRATION*)Handle;
        break;

    case QUIC_HANDLE_TYPE_CONFIGURATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Configuration = (QUIC_CONFIGURATION*)Handle;
        Registration = Configuration->Registration;
        break;

    case QUIC_HANDLE_TYPE_LISTENER:
        Stream = NULL;
        Connection = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Listener = (QUIC_LISTENER*)Handle;
        Configuration = NULL;
        Registration = Listener->Registration;
        break;

    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
        Stream = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Stream = (QUIC_STREAM*)Handle;
        Connection = Stream->Connection;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    default:
        CXPLAT_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    switch (Param & 0x7F000000)
    {
    case QUIC_PARAM_PREFIX_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamGet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_CONFIGURATION:
        if (Configuration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConfigurationParamGet(Configuration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamGet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamGet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_TLS:
    case QUIC_PARAM_PREFIX_TLS_SCHANNEL:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else if (Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
        } else {
            Status = CxPlatTlsParamGet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_PREFIX_STREAM:
        if (Stream == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicStreamParamGet(Stream, Param, BufferLength, Buffer);
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Check_return_
QUIC_STATUS
QUIC_API
MsQuicOpenVersion(
    _In_ uint32_t Version,
    _Out_ _Pre_defensive_ const void** QuicApi
    )
{
    QUIC_STATUS Status;
    BOOLEAN ReleaseRefOnFailure = FALSE;

    if (Version != QUIC_API_VERSION_2) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Only v2 is supported in MsQuicOpenVersion");
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    MsQuicLibraryLoad();

    if (QuicApi == NULL) {
        QuicTraceLogVerbose(
            LibraryMsQuicOpenVersionNull,
            "[ api] MsQuicOpenVersion, NULL");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicTraceLogVerbose(
        LibraryMsQuicOpenVersionEntry,
        "[ api] MsQuicOpenVersion");

    Status = MsQuicAddRef();
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    ReleaseRefOnFailure = TRUE;

    QUIC_API_TABLE* Api = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_API_TABLE), QUIC_POOL_API);
    if (Api == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    Api->SetContext = MsQuicSetContext;
    Api->GetContext = MsQuicGetContext;
    Api->SetCallbackHandler = MsQuicSetCallbackHandler;

    Api->SetParam = MsQuicSetParam;
    Api->GetParam = MsQuicGetParam;

    Api->RegistrationOpen = MsQuicRegistrationOpen;
    Api->RegistrationClose = MsQuicRegistrationClose;
    Api->RegistrationShutdown = MsQuicRegistrationShutdown;

    Api->ConfigurationOpen = MsQuicConfigurationOpen;
    Api->ConfigurationClose = MsQuicConfigurationClose;
    Api->ConfigurationLoadCredential = MsQuicConfigurationLoadCredential;

    Api->ListenerOpen = MsQuicListenerOpen;
    Api->ListenerClose = MsQuicListenerClose;
    Api->ListenerStart = MsQuicListenerStart;
    Api->ListenerStop = MsQuicListenerStop;

    Api->ConnectionOpen = MsQuicConnectionOpen;
    Api->ConnectionOpenInPartition = MsQuicConnectionOpenInPartition;
    Api->ConnectionClose = MsQuicConnectionClose;
    Api->ConnectionShutdown = MsQuicConnectionShutdown;
    Api->ConnectionStart = MsQuicConnectionStart;
    Api->ConnectionSetConfiguration = MsQuicConnectionSetConfiguration;
    Api->ConnectionSendResumptionTicket = MsQuicConnectionSendResumptionTicket;
    Api->ConnectionResumptionTicketValidationComplete = MsQuicConnectionResumptionTicketValidationComplete;
    Api->ConnectionCertificateValidationComplete = MsQuicConnectionCertificateValidationComplete;

    Api->StreamOpen = MsQuicStreamOpen;
    Api->StreamClose = MsQuicStreamClose;
    Api->StreamShutdown = MsQuicStreamShutdown;
    Api->StreamStart = MsQuicStreamStart;
    Api->StreamSend = MsQuicStreamSend;
    Api->StreamReceiveComplete = MsQuicStreamReceiveComplete;
    Api->StreamReceiveSetEnabled = MsQuicStreamReceiveSetEnabled;
    Api->StreamProvideReceiveBuffers = MsQuicStreamProvideReceiveBuffers;

    Api->DatagramSend = MsQuicDatagramSend;

#ifndef _KERNEL_MODE
    Api->ExecutionCreate = MsQuicExecutionCreate;
    Api->ExecutionDelete = MsQuicExecutionDelete;
    Api->ExecutionPoll = MsQuicExecutionPoll;
#endif

    Api->ConnectionPoolCreate = MsQuicConnectionPoolCreate;

    *QuicApi = Api;

Exit:

    QuicTraceLogVerbose(
        LibraryMsQuicOpenVersionExit,
        "[ api] MsQuicOpenVersion, status=0x%x",
        Status);

    if (QUIC_FAILED(Status)) {
        if (ReleaseRefOnFailure) {
            MsQuicRelease();
        }

        MsQuicLibraryUnload();
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicClose(
    _In_ _Pre_defensive_ const void* QuicApi
    )
{
    if (QuicApi != NULL) {
        QuicTraceLogVerbose(
            LibraryMsQuicClose,
            "[ api] MsQuicClose");
        CXPLAT_FREE(QuicApi, QUIC_POOL_API);
        MsQuicRelease();
        MsQuicLibraryUnload();
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_BINDING*
QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
    _In_ QUIC_COMPARTMENT_ID CompartmentId,
#endif
    _In_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress
    )
{
    for (CXPLAT_LIST_ENTRY* Link = MsQuicLib.Bindings.Flink;
        Link != &MsQuicLib.Bindings;
        Link = Link->Flink) {

        QUIC_BINDING* Binding =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_BINDING, Link);

#ifdef QUIC_COMPARTMENT_ID
        if (CompartmentId != Binding->CompartmentId) {
            continue;
        }
#endif

        QUIC_ADDR BindingLocalAddr;
        QuicBindingGetLocalAddress(Binding, &BindingLocalAddr);

        if (Binding->Connected) {
            //
            // For client/connected bindings we need to match on both local and
            // remote addresses/ports.
            //
            if (RemoteAddress &&
                QuicAddrCompare(LocalAddress, &BindingLocalAddr)) {
                QUIC_ADDR BindingRemoteAddr;
                QuicBindingGetRemoteAddress(Binding, &BindingRemoteAddr);
                if (QuicAddrCompare(RemoteAddress, &BindingRemoteAddr)) {
                    return Binding;
                }
            }

        } else {
            //
            // For server (unconnected/listening) bindings we always use wildcard
            // addresses, so we simply need to match on local port.
            //
            if (QuicAddrGetPort(&BindingLocalAddr) == QuicAddrGetPort(LocalAddress)) {
                //
                // Note: We don't check the remote address, because we want to
                // return a match even if the caller is looking for a connected
                // socket so that we can inform them there is already a listening
                // socket using the local port.
                //
                return Binding;
            }
        }
    }

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetBinding(
    _In_ const CXPLAT_UDP_CONFIG* UdpConfig,
    _Outptr_ QUIC_BINDING** NewBinding
    )
{
    QUIC_STATUS Status;
    QUIC_BINDING* Binding;
    QUIC_ADDR NewLocalAddress;
    const BOOLEAN PortUnspecified =
        UdpConfig->LocalAddress == NULL || QuicAddrGetPort(UdpConfig->LocalAddress) == 0;
    const BOOLEAN ShareBinding = !!(UdpConfig->Flags & CXPLAT_SOCKET_FLAG_SHARE);
    const BOOLEAN ServerOwned = !!(UdpConfig->Flags & CXPLAT_SOCKET_SERVER_OWNED);

#ifdef QUIC_SHARED_EPHEMERAL_WORKAROUND
    //
    // To work around the Linux bug where the stack sometimes gives us a "new"
    // empheral port that matches an existing one, we retry, starting from that
    // port and incrementing the number until we get one that works.
    //
    BOOLEAN SharedEphemeralWorkAround = FALSE;
SharedEphemeralRetry:
#endif // QUIC_SHARED_EPHEMERAL_WORKAROUND

    //
    // First check to see if a binding already exists that matches the
    // requested addresses.
    //
#ifdef QUIC_SHARED_EPHEMERAL_WORKAROUND
    if (PortUnspecified && !SharedEphemeralWorkAround) {
#else
    if (PortUnspecified) {
#endif // QUIC_SHARED_EPHEMERAL_WORKAROUND
        //
        // No specified local port, so we always create a new binding, and let
        // the networking stack assign us a new ephemeral port. We can skip the
        // lookup because the stack **should** always give us something new.
        //
        goto NewBinding;
    }

    Status = QUIC_STATUS_NOT_FOUND;
    CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);

    Binding =
        QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
            UdpConfig->CompartmentId,
#endif
            UdpConfig->LocalAddress,
            UdpConfig->RemoteAddress);
    if (Binding != NULL) {
        if (!ShareBinding || Binding->Exclusive ||
            (ServerOwned != Binding->ServerOwned)) {
            //
            // The binding does already exist, but cannot be shared with the
            // requested configuration.
            //
            QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                Binding,
                "Binding already in use");
            Status = QUIC_STATUS_ADDRESS_IN_USE;
        } else {
            //
            // Match found and can be shared.
            //
            CXPLAT_DBG_ASSERT(Binding->RefCount > 0);
            Binding->RefCount++;
            *NewBinding = Binding;
            Status = QUIC_STATUS_SUCCESS;
        }
    }

    CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Status != QUIC_STATUS_NOT_FOUND) {
#ifdef QUIC_SHARED_EPHEMERAL_WORKAROUND
        if (QUIC_FAILED(Status) && SharedEphemeralWorkAround) {
            CXPLAT_DBG_ASSERT(UdpConfig->LocalAddress);
            QuicAddrSetPort((QUIC_ADDR*)UdpConfig->LocalAddress, QuicAddrGetPort(UdpConfig->LocalAddress) + 1);
            goto SharedEphemeralRetry;
        }
#endif // QUIC_SHARED_EPHEMERAL_WORKAROUND
        goto Exit;
    }

NewBinding:

    //
    // Create a new binding since there wasn't a match.
    //

    Status =
        QuicBindingInitialize(
            UdpConfig,
            NewBinding);
    if (QUIC_FAILED(Status)) {
#ifdef QUIC_SHARED_EPHEMERAL_WORKAROUND
        if (SharedEphemeralWorkAround) {
            CXPLAT_DBG_ASSERT(UdpConfig->LocalAddress);
            QuicAddrSetPort((QUIC_ADDR*)UdpConfig->LocalAddress, QuicAddrGetPort(UdpConfig->LocalAddress) + 1);
            goto SharedEphemeralRetry;
        }
#endif // QUIC_SHARED_EPHEMERAL_WORKAROUND
        goto Exit;
    }

    QuicBindingGetLocalAddress(*NewBinding, &NewLocalAddress);

    CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);

    //
    // Now that we created the binding, we need to insert it into the list of
    // all bindings. But we need to make sure another thread didn't race this
    // one and already create the binding.
    //

    if (QuicLibraryGetDatapathFeatures() & CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING) {
        //
        // The datapath supports multiple connected sockets on the same local
        // tuple, so we need to do collision detection based on the whole
        // 4-tuple.
        //
        Binding =
            QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
                UdpConfig->CompartmentId,
#endif
                &NewLocalAddress,
                UdpConfig->RemoteAddress);
    } else {
        //
        // The datapath does not supports multiple connected sockets on the same
        // local tuple, so we just do collision detection based on the local
        // tuple.
        //
        Binding =
            QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
                UdpConfig->CompartmentId,
#endif
                &NewLocalAddress,
                NULL);
    }

    if (Binding != NULL) {
        if (!PortUnspecified && !Binding->Exclusive) {
            //
            // Another thread got the binding first, but it's not exclusive,
            // and it's not what should be a new ephemeral port.
            //
            CXPLAT_DBG_ASSERT(Binding->RefCount > 0);
            Binding->RefCount++;
        }
    } else {
        //
        // No other thread beat us, insert this binding into the list.
        //
        if (CxPlatListIsEmpty(&MsQuicLib.Bindings)) {
            QuicTraceLogInfo(
                LibraryInUse,
                "[ lib] Now in use.");
            MsQuicLib.InUse = TRUE;
        }
        (*NewBinding)->RefCount++;
        CxPlatListInsertTail(&MsQuicLib.Bindings, &(*NewBinding)->Link);
    }

    CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Binding != NULL) {
        if (PortUnspecified) {
            //
            // The datapath somehow returned us a "new" ephemeral socket that
            // already matched one of our existing ones. We've seen this on
            // Linux occasionally. This shouldn't happen, but it does.
            //
            QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                *NewBinding,
                "Binding ephemeral port reuse encountered");
            QuicBindingUninitialize(*NewBinding);
            *NewBinding = NULL;

#ifdef QUIC_SHARED_EPHEMERAL_WORKAROUND
            //
            // Use the invalid address as a starting point to search for a new
            // one.
            //
            SharedEphemeralWorkAround = TRUE;
            ((CXPLAT_UDP_CONFIG*)UdpConfig)->LocalAddress = &NewLocalAddress;
            QuicAddrSetPort((QUIC_ADDR*)UdpConfig->LocalAddress, QuicAddrGetPort(UdpConfig->LocalAddress) + 1);
            goto SharedEphemeralRetry;
#else
            Status = QUIC_STATUS_INTERNAL_ERROR;
#endif // QUIC_SHARED_EPHEMERAL_WORKAROUND

        } else if (Binding->Exclusive) {
            QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                Binding,
                "Binding already in use");
            QuicBindingUninitialize(*NewBinding);
            *NewBinding = NULL;
#ifdef QUIC_SHARED_EPHEMERAL_WORKAROUND
            if (SharedEphemeralWorkAround) {
                CXPLAT_DBG_ASSERT(UdpConfig->LocalAddress);
                QuicAddrSetPort((QUIC_ADDR*)UdpConfig->LocalAddress, QuicAddrGetPort(UdpConfig->LocalAddress) + 1);
                goto SharedEphemeralRetry;
            }
#endif // QUIC_SHARED_EPHEMERAL_WORKAROUND
            Status = QUIC_STATUS_ADDRESS_IN_USE;

        } else {
            QuicBindingUninitialize(*NewBinding);
            *NewBinding = Binding;
            Status = QUIC_STATUS_SUCCESS;
        }
    }

Exit:

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLibraryTryAddRefBinding(
    _In_ QUIC_BINDING* Binding
    )
{
    BOOLEAN Success = FALSE;

    CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);
    if (Binding->RefCount > 0) {
        Binding->RefCount++;
        Success = TRUE;
    }
    CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);

    return Success;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibraryReleaseBinding(
    _In_ QUIC_BINDING* Binding
    )
{
    BOOLEAN Uninitialize = FALSE;

    CXPLAT_PASSIVE_CODE();

    CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);
    CXPLAT_DBG_ASSERT(Binding->RefCount > 0);
    if (--Binding->RefCount == 0) {
        CxPlatListEntryRemove(&Binding->Link);
        Uninitialize = TRUE;

        if (CxPlatListIsEmpty(&MsQuicLib.Bindings)) {
            QuicTraceLogInfo(
                LibraryNotInUse,
                "[ lib] No longer in use.");
            MsQuicLib.InUse = FALSE;
        }
    }
    CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Uninitialize) {
        QuicBindingUninitialize(Binding);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLibraryOnListenerRegistered(
    _In_ QUIC_LISTENER* Listener
    )
{
    BOOLEAN Success = TRUE;

    UNREFERENCED_PARAMETER(Listener);

    CxPlatLockAcquire(&MsQuicLib.Lock);

    if (MsQuicLib.StatelessRegistration == NULL) {
        //
        // Lazily initialize server specific state.
        //
        QuicTraceEvent(
            LibraryServerInit,
            "[ lib] Shared server state initializing");

        const QUIC_REGISTRATION_CONFIG Config = {
            "Stateless",
            QUIC_EXECUTION_PROFILE_TYPE_INTERNAL
        };

        if (QUIC_FAILED(
            MsQuicRegistrationOpen(
                &Config,
                (HQUIC*)&MsQuicLib.StatelessRegistration))) {
            Success = FALSE;
            goto Fail;
        }
    }

Fail:

    CxPlatLockRelease(&MsQuicLib.Lock);

    return Success;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_WORKER*
QUIC_NO_SANITIZE("implicit-conversion")
QuicLibraryGetWorker(
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    CXPLAT_DBG_ASSERT(MsQuicLib.StatelessRegistration != NULL);
    return
        &MsQuicLib.StatelessRegistration->WorkerPool->Workers[
            Packet->PartitionIndex % MsQuicLib.StatelessRegistration->WorkerPool->WorkerCount];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_TRACE_RUNDOWN_CALLBACK)
void
QuicTraceRundown(
    void
    )
{
    if (!MsQuicLib.Loaded) {
        return;
    }

    CxPlatLockAcquire(&MsQuicLib.Lock);

    if (MsQuicLib.OpenRefCount > 0) {
        QuicTraceEvent(
            LibraryRundownV2,
            "[ lib] Rundown, PartitionCount=%u",
            MsQuicLib.PartitionCount);

        if (MsQuicLib.Datapath != NULL) {
            QuicTraceEvent(
                DataPathRundown,
                "[data] Rundown, DatapathFeatures=%u",
                QuicLibraryGetDatapathFeatures());
        }

        QuicTraceEvent(
            LibraryVersion,
            "[ lib] Version %u.%u.%u.%u",
            MsQuicLib.Version[0],
            MsQuicLib.Version[1],
            MsQuicLib.Version[2],
            MsQuicLib.Version[3]);

        QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            MsQuicLib.SendRetryEnabled);

        if (MsQuicLib.StatelessRegistration) {
            QuicRegistrationTraceRundown(MsQuicLib.StatelessRegistration);
        }

        for (CXPLAT_LIST_ENTRY* Link = MsQuicLib.Registrations.Flink;
            Link != &MsQuicLib.Registrations;
            Link = Link->Flink) {
            QuicRegistrationTraceRundown(
                CXPLAT_CONTAINING_RECORD(Link, QUIC_REGISTRATION, Link));
        }

        CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);
        for (CXPLAT_LIST_ENTRY* Link = MsQuicLib.Bindings.Flink;
            Link != &MsQuicLib.Bindings;
            Link = Link->Flink) {
            QuicBindingTraceRundown(
                CXPLAT_CONTAINING_RECORD(Link, QUIC_BINDING, Link));
        }
        CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);

        int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
        QuicLibrarySumPerfCounters((uint8_t*)PerfCounters, sizeof(PerfCounters));
        QuicTraceEvent(
            PerfCountersRundown,
            "[ lib] Perf counters Rundown, Counters=%!CID!",
            CASTED_CLOG_BYTEARRAY16(sizeof(PerfCounters), PerfCounters));
    }

    CxPlatLockRelease(&MsQuicLib.Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryOnHandshakeConnectionAdded(
    void
    )
{
    InterlockedExchangeAdd64(
        (int64_t*)&MsQuicLib.CurrentHandshakeMemoryUsage,
        (int64_t)QUIC_CONN_HANDSHAKE_MEMORY_USAGE);
    QuicLibraryEvaluateSendRetryState();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryOnHandshakeConnectionRemoved(
    void
    )
{
    InterlockedExchangeAdd64(
        (int64_t*)&MsQuicLib.CurrentHandshakeMemoryUsage,
        -1 * (int64_t)QUIC_CONN_HANDSHAKE_MEMORY_USAGE);
    QuicLibraryEvaluateSendRetryState();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryEvaluateSendRetryState(
    void
    )
{
    BOOLEAN NewSendRetryState =
        MsQuicLib.CurrentHandshakeMemoryUsage >= MsQuicLib.HandshakeMemoryLimit;

    if (NewSendRetryState != MsQuicLib.SendRetryEnabled) {
        MsQuicLib.SendRetryEnabled = NewSendRetryState;
        QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            NewSendRetryState);

        //
        // Notify all bindings and listeners about the state change.
        //
        CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);
        for (CXPLAT_LIST_ENTRY* Link = MsQuicLib.Bindings.Flink;
            Link != &MsQuicLib.Bindings;
            Link = Link->Flink) {

            QUIC_BINDING* Binding = CXPLAT_CONTAINING_RECORD(Link, QUIC_BINDING, Link);
            QuicBindingHandleDosModeStateChange(Binding, MsQuicLib.SendRetryEnabled);
        }
        CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);
    }
}

CXPLAT_STATIC_ASSERT(
    CXPLAT_HASH_SHA256_SIZE >= QUIC_STATELESS_RESET_TOKEN_LENGTH,
    "Stateless reset token must be shorter than hash size used");

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGenerateStatelessResetToken(
    _In_ QUIC_PARTITION* Partition,
    _In_reads_(MsQuicLib.CidTotalLength)
        const uint8_t* const CID,
    _Out_writes_all_(QUIC_STATELESS_RESET_TOKEN_LENGTH)
        uint8_t* ResetToken
    )
{
    uint8_t HashOutput[CXPLAT_HASH_SHA256_SIZE];
    CxPlatLockAcquire(&Partition->ResetTokenLock);
    QUIC_STATUS Status =
        CxPlatHashCompute(
            Partition->ResetTokenHash,
            CID,
            MsQuicLib.CidTotalLength,
            sizeof(HashOutput),
            HashOutput);
    CxPlatLockRelease(&Partition->ResetTokenLock);
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatCopyMemory(
            ResetToken,
            HashOutput,
            QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }
    return Status;
}

#ifndef _KERNEL_MODE

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicExecutionCreate(
    _In_ QUIC_GLOBAL_EXECUTION_CONFIG_FLAGS Flags, // Used for datapath type
    _In_ uint32_t PollingIdleTimeoutUs,
    _In_ uint32_t Count,
    _In_reads_(Count) QUIC_EXECUTION_CONFIG* Configs,
    _Out_writes_(Count) QUIC_EXECUTION** Executions
    )
{
    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_EXECUTION_CREATE,
        NULL);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(PollingIdleTimeoutUs);

    if (MsQuicLib.LazyInitComplete) {
        //
        // Not allowed to change the execution config after we've already
        // started running the library.
        //
        Status = QUIC_STATUS_INVALID_STATE;

    } else {
        //
        // Clean up any previous worker pool and create a new one.
        //
        CxPlatWorkerPoolDelete(MsQuicLib.WorkerPool);
        MsQuicLib.WorkerPool =
            CxPlatWorkerPoolCreateExternal(Count, Configs, Executions);
        if (MsQuicLib.WorkerPool == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
        }

        MsQuicLib.CustomExecutions = TRUE;
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicExecutionDelete(
    _In_ uint32_t Count,
    _In_reads_(Count) QUIC_EXECUTION** Executions
    )
{
    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_EXECUTION_DELETE,
        NULL);

    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(Executions);
    CxPlatWorkerPoolDelete(MsQuicLib.WorkerPool);
    MsQuicLib.WorkerPool = NULL;

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
uint32_t
QUIC_API
MsQuicExecutionPoll(
    _In_ QUIC_EXECUTION* Execution
    )
{
    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_EXECUTION_POLL,
        NULL);

    uint32_t Result = CxPlatWorkerPoolWorkerPoll(Execution);

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");

    return Result;
}

#endif
