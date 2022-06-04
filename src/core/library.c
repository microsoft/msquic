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
        CxPlatDispatchLockInitialize(&MsQuicLib.StatelessRetryKeysLock);
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
        CxPlatDispatchLockUninitialize(&MsQuicLib.StatelessRetryKeysLock);
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

    PartitionCount |= (PartitionCount >> 1);
    PartitionCount |= (PartitionCount >> 2);
    PartitionCount |= (PartitionCount >> 4);
    PartitionCount |= (PartitionCount >> 8);
    uint16_t HighBitSet = PartitionCount - (PartitionCount >> 1);

    MsQuicLib.PartitionMask = (HighBitSet << 1) - 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCounters(
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    CXPLAT_DBG_ASSERT(BufferLength == (BufferLength / sizeof(uint64_t) * sizeof(uint64_t)));
    CXPLAT_DBG_ASSERT(BufferLength <= sizeof(MsQuicLib.PerProc[0].PerfCounters));
    const uint32_t CountersPerBuffer = BufferLength / sizeof(int64_t);
    int64_t* const Counters = (int64_t*)Buffer;
    memcpy(Buffer, MsQuicLib.PerProc[0].PerfCounters, BufferLength);

    for (uint32_t ProcIndex = 1; ProcIndex < MsQuicLib.ProcessorCount; ++ProcIndex) {
        for (uint32_t CounterIndex = 0; CounterIndex < CountersPerBuffer; ++CounterIndex) {
            Counters[CounterIndex] += MsQuicLib.PerProc[ProcIndex].PerfCounters[CounterIndex];
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

// Ensure a perf counter stays below a given max Hz/frequency.
#define QUIC_COUNTER_LIMIT_HZ(TYPE, LIMIT_PER_SECOND) \
    CXPLAT_TEL_ASSERT( \
        ((1000 * 1000 * (PerfCounterSamples[TYPE] - MsQuicLib.PerfCounterSamples[TYPE])) / TimeDiffUs) < LIMIT_PER_SECOND)

// Ensures a perf counter doesn't consistently (both samples) go above a give max value.
#define QUIC_COUNTER_CAP(TYPE, MAX_LIMIT) \
    CXPLAT_TEL_ASSERT( \
        PerfCounterSamples[TYPE] < MAX_LIMIT || \
        MsQuicLib.PerfCounterSamples[TYPE] < MAX_LIMIT)

    //
    // Some heuristics to ensure that bad things aren't happening. TODO - these
    // values should be configurable dynamically, somehow.
    //
    QUIC_COUNTER_LIMIT_HZ(QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL, 1000000); // Don't have 1 million failed handshakes per second
    QUIC_COUNTER_CAP(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH, 100000); // Don't maintain huge queue depths

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
    uint32_t DefaultMaxPartitionCount = QUIC_MAX_PARTITION_COUNT;

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
    }

    MsQuicLibraryReadSettings(NULL); // NULL means don't update registrations.

    CxPlatZeroMemory(&MsQuicLib.StatelessRetryKeys, sizeof(MsQuicLib.StatelessRetryKeys));
    CxPlatZeroMemory(&MsQuicLib.StatelessRetryKeysExpiration, sizeof(MsQuicLib.StatelessRetryKeysExpiration));

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

    //
    // TODO: Add support for CPU hot swap/add.
    //

    if (MsQuicLib.Storage != NULL) {
        uint32_t DefaultMaxPartitionCountLen = sizeof(DefaultMaxPartitionCount);
        CxPlatStorageReadValue(
            MsQuicLib.Storage,
            QUIC_SETTING_MAX_PARTITION_COUNT,
            (uint8_t*)&DefaultMaxPartitionCount,
            &DefaultMaxPartitionCountLen);
        if (DefaultMaxPartitionCount > QUIC_MAX_PARTITION_COUNT) {
            DefaultMaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
        }
    }
    MsQuicLib.ProcessorCount = (uint16_t)CxPlatProcActiveCount();
    CXPLAT_FRE_ASSERT(MsQuicLib.ProcessorCount > 0);
    MsQuicLib.PartitionCount = (uint16_t)CXPLAT_MIN(MsQuicLib.ProcessorCount, DefaultMaxPartitionCount);

    MsQuicCalculatePartitionMask();

    MsQuicLib.PerProc =
        CXPLAT_ALLOC_NONPAGED(
            MsQuicLib.ProcessorCount * sizeof(QUIC_LIBRARY_PP),
            QUIC_POOL_PERPROC);
    if (MsQuicLib.PerProc == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "connection pools",
            MsQuicLib.ProcessorCount * sizeof(QUIC_LIBRARY_PP));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    uint8_t ResetHashKey[20];
    CxPlatRandom(sizeof(ResetHashKey), ResetHashKey);

    for (uint16_t i = 0; i < MsQuicLib.ProcessorCount; ++i) {
        CxPlatZeroMemory(&MsQuicLib.PerProc[i], sizeof(QUIC_LIBRARY_PP));
        CxPlatPoolInitialize(
            FALSE,
            sizeof(QUIC_CONNECTION),
            QUIC_POOL_CONN,
            &MsQuicLib.PerProc[i].ConnectionPool);
        CxPlatPoolInitialize(
            FALSE,
            sizeof(QUIC_TRANSPORT_PARAMETERS),
            QUIC_POOL_TP,
            &MsQuicLib.PerProc[i].TransportParamPool);
        CxPlatPoolInitialize(
            FALSE,
            sizeof(QUIC_PACKET_SPACE),
            QUIC_POOL_TP,
            &MsQuicLib.PerProc[i].PacketSpacePool);
        CxPlatLockInitialize(&MsQuicLib.PerProc[i].ResetTokenLock);
        MsQuicLib.PerProc[i].ResetTokenHash = NULL;
        CxPlatZeroMemory(
            &MsQuicLib.PerProc[i].PerfCounters,
            sizeof(MsQuicLib.PerProc[i].PerfCounters));
    }

    for (uint16_t i = 0; i < MsQuicLib.ProcessorCount; ++i) {
        Status =
            CxPlatHashCreate(
                CXPLAT_HASH_SHA256,
                ResetHashKey,
                sizeof(ResetHashKey),
                &MsQuicLib.PerProc[i].ResetTokenHash);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Create reset token hash");
            goto Error;
        }
    }

    QuicTraceEvent(
        LibraryInitializedV2,
        "[ lib] Initialized, PartitionCount=%u",
        MsQuicLib.PartitionCount);
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
        if (MsQuicLib.PerProc != NULL) {
            for (uint16_t i = 0; i < MsQuicLib.ProcessorCount; ++i) {
                CxPlatPoolUninitialize(&MsQuicLib.PerProc[i].ConnectionPool);
                CxPlatPoolUninitialize(&MsQuicLib.PerProc[i].TransportParamPool);
                CxPlatPoolUninitialize(&MsQuicLib.PerProc[i].PacketSpacePool);
                CxPlatLockUninitialize(&MsQuicLib.PerProc[i].ResetTokenLock);
                CxPlatHashFree(MsQuicLib.PerProc[i].ResetTokenHash);
            }
            CXPLAT_FREE(MsQuicLib.PerProc, QUIC_POOL_PERPROC);
            MsQuicLib.PerProc = NULL;
        }
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

    CxPlatSecureZeroMemory(ResetHashKey, sizeof(ResetHashKey));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUninitialize(
    void
    )
{
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
    // Clean up the data path first, which can continue to cause new connections
    // to get created.
    //
    if (MsQuicLib.Datapath != NULL) {
        CxPlatDataPathUninitialize(MsQuicLib.Datapath);
        MsQuicLib.Datapath = NULL;
        if (MsQuicLib.DataPathProcList != NULL) {
            CXPLAT_FREE(MsQuicLib.DataPathProcList, QUIC_POOL_RAW_DATAPATH_PROCS);
            MsQuicLib.DataPathProcList = NULL;
            MsQuicLib.DataPathProcListLength = 0;
        }
    }

    //
    // Wait for the final clean up of everything in the stateless registration
    // and then free it.
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

    for (uint16_t i = 0; i < MsQuicLib.ProcessorCount; ++i) {
        CxPlatPoolUninitialize(&MsQuicLib.PerProc[i].ConnectionPool);
        CxPlatPoolUninitialize(&MsQuicLib.PerProc[i].TransportParamPool);
        CxPlatPoolUninitialize(&MsQuicLib.PerProc[i].PacketSpacePool);
        CxPlatLockUninitialize(&MsQuicLib.PerProc[i].ResetTokenLock);
        CxPlatHashFree(MsQuicLib.PerProc[i].ResetTokenHash);
    }
    CXPLAT_FREE(MsQuicLib.PerProc, QUIC_POOL_PERPROC);
    MsQuicLib.PerProc = NULL;

    for (size_t i = 0; i < ARRAYSIZE(MsQuicLib.StatelessRetryKeys); ++i) {
        CxPlatKeyFree(MsQuicLib.StatelessRetryKeys[i]);
        MsQuicLib.StatelessRetryKeys[i] = NULL;
    }

    QuicSettingsCleanup(&MsQuicLib.Settings);

    CXPLAT_FREE(MsQuicLib.DefaultCompatibilityList, QUIC_POOL_DEFAULT_COMPAT_VER_LIST);
    MsQuicLib.DefaultCompatibilityList = NULL;

    QuicTraceEvent(
        LibraryUninitialized,
        "[ lib] Uninitialized");

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
    case QUIC_LOAD_BALANCING_SERVER_ID_IP:
        MsQuicLib.CidServerIdLength = 5; // 1 + 4 for v4 IP address
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

    case QUIC_PARAM_GLOBAL_DATAPATH_PROCESSORS: {
        if (BufferLength == 0) {
            if (MsQuicLib.DataPathProcList != NULL) {
                CXPLAT_FREE(MsQuicLib.DataPathProcList, QUIC_POOL_RAW_DATAPATH_PROCS);
                MsQuicLib.DataPathProcList = NULL;
                MsQuicLib.DataPathProcListLength = 0;
            }
            Status = QUIC_STATUS_SUCCESS;
            break;
        }

        if (Buffer == NULL || BufferLength < sizeof(uint16_t) || BufferLength % sizeof(uint16_t) != 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (MsQuicLib.Datapath != NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Tried to change raw datapath procs after datapath initialization");
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        uint32_t DataPathProcListLength = BufferLength / sizeof(uint16_t);
        uint16_t* Cpus = (uint16_t*)Buffer;
        for (uint32_t i = 0; i < DataPathProcListLength; ++i) {
            if (*(Cpus + i) >= CxPlatProcActiveCount()) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }
        }

        if (Status == QUIC_STATUS_INVALID_PARAMETER) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Tried to set invalid raw datapath procs");
            break;
        }

        uint16_t* DataPathProcList = CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_RAW_DATAPATH_PROCS);
        if (DataPathProcList == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Raw datapath procs",
                BufferLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            break;
        }

        if (MsQuicLib.DataPathProcList != NULL) {
            CXPLAT_FREE(MsQuicLib.DataPathProcList, QUIC_POOL_RAW_DATAPATH_PROCS);
            MsQuicLib.DataPathProcList = NULL;
            MsQuicLib.DataPathProcListLength = 0;
        }

        CxPlatCopyMemory(DataPathProcList, Buffer, BufferLength);
        MsQuicLib.DataPathProcList = DataPathProcList;
        MsQuicLib.DataPathProcListLength = DataPathProcListLength;

        QuicTraceLogInfo(
            LibraryDataPathProcsSet,
            "[ lib] Setting datapath procs");

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

    case QUIC_PARAM_GLOBAL_DATAPATH_PROCESSORS:
        if (*BufferLength == 0 && MsQuicLib.DataPathProcListLength == 0) {
            Status = QUIC_STATUS_SUCCESS;
            break;
        }

        if (*BufferLength < sizeof(uint16_t) * MsQuicLib.DataPathProcListLength) {
            *BufferLength = sizeof(uint16_t) * MsQuicLib.DataPathProcListLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t) * MsQuicLib.DataPathProcListLength;
        if (MsQuicLib.DataPathProcList != NULL) {
            CxPlatCopyMemory(Buffer, MsQuicLib.DataPathProcList, *BufferLength);
        }
        Status = QUIC_STATUS_SUCCESS;
        break;

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
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
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
    Api->ConnectionClose = MsQuicConnectionClose;
    Api->ConnectionShutdown = MsQuicConnectionShutdown;
    Api->ConnectionStart = MsQuicConnectionStart;
    Api->ConnectionSetConfiguration = MsQuicConnectionSetConfiguration;
    Api->ConnectionSendResumptionTicket = MsQuicConnectionSendResumptionTicket;

    Api->StreamOpen = MsQuicStreamOpen;
    Api->StreamClose = MsQuicStreamClose;
    Api->StreamShutdown = MsQuicStreamShutdown;
    Api->StreamStart = MsQuicStreamStart;
    Api->StreamSend = MsQuicStreamSend;
    Api->StreamReceiveComplete = MsQuicStreamReceiveComplete;
    Api->StreamReceiveSetEnabled = MsQuicStreamReceiveSetEnabled;

    Api->DatagramSend = MsQuicDatagramSend;

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

        if (!QuicAddrCompare(LocalAddress, &BindingLocalAddr)) {
            continue;
        }

        if (Binding->Connected) {
            if (RemoteAddress == NULL) {
                continue;
            }

            QUIC_ADDR BindingRemoteAddr;
            QuicBindingGetRemoteAddress(Binding, &BindingRemoteAddr);
            if (!QuicAddrCompare(RemoteAddress, &BindingRemoteAddr)) {
                continue;
            }

        } else  if (RemoteAddress != NULL) {
            continue;
        }

        return Binding;
    }

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetBinding(
    _In_ const CXPLAT_UDP_CONFIG* UdpConfig,
    _Out_ QUIC_BINDING** NewBinding
    )
{
    QUIC_STATUS Status;
    QUIC_BINDING* Binding;
    QUIC_ADDR NewLocalAddress;
    BOOLEAN PortUnspecified = UdpConfig->LocalAddress == NULL || QuicAddrGetPort(UdpConfig->LocalAddress) == 0;
    BOOLEAN ShareBinding = !!(UdpConfig->Flags & CXPLAT_SOCKET_FLAG_SHARE);
    BOOLEAN ServerOwned = !!(UdpConfig->Flags & CXPLAT_SOCKET_SERVER_OWNED);

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

    if (CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath) & CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING) {
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
    _In_ const _In_ CXPLAT_RECV_DATA* Datagram
    )
{
    CXPLAT_DBG_ASSERT(MsQuicLib.StatelessRegistration != NULL);
    return
        &MsQuicLib.StatelessRegistration->WorkerPool->Workers[
            Datagram->PartitionIndex % MsQuicLib.StatelessRegistration->WorkerPool->WorkerCount];
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
                CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));
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
            CASTED_CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters));
    }

    CxPlatLockRelease(&MsQuicLib.Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicLibraryGetStatelessRetryKeyForTimestamp(
    _In_ int64_t Timestamp
    )
{
    if (Timestamp < MsQuicLib.StatelessRetryKeysExpiration[!MsQuicLib.CurrentStatelessRetryKey] - QUIC_STATELESS_RETRY_KEY_LIFETIME_MS) {
        //
        // Timestamp is before the beginning of the previous key's validity window.
        //
        return NULL;
    }

    if (Timestamp < MsQuicLib.StatelessRetryKeysExpiration[!MsQuicLib.CurrentStatelessRetryKey]) {
        if (MsQuicLib.StatelessRetryKeys[!MsQuicLib.CurrentStatelessRetryKey] == NULL) {
            return NULL;
        }
        return MsQuicLib.StatelessRetryKeys[!MsQuicLib.CurrentStatelessRetryKey];
    }

    if (Timestamp < MsQuicLib.StatelessRetryKeysExpiration[MsQuicLib.CurrentStatelessRetryKey]) {
        if (MsQuicLib.StatelessRetryKeys[MsQuicLib.CurrentStatelessRetryKey] == NULL) {
            return NULL;
        }
        return MsQuicLib.StatelessRetryKeys[MsQuicLib.CurrentStatelessRetryKey];
    }

    //
    // Timestamp is after the end of the latest key's validity window.
    //
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicLibraryGetCurrentStatelessRetryKey(
    void
    )
{
    int64_t Now = CxPlatTimeEpochMs64();
    int64_t StartTime = (Now / QUIC_STATELESS_RETRY_KEY_LIFETIME_MS) * QUIC_STATELESS_RETRY_KEY_LIFETIME_MS;

    if (StartTime < MsQuicLib.StatelessRetryKeysExpiration[MsQuicLib.CurrentStatelessRetryKey]) {
        return MsQuicLib.StatelessRetryKeys[MsQuicLib.CurrentStatelessRetryKey];
    }

    //
    // If the start time for the current key interval is greater-than-or-equal
    // to the expiration time of the latest stateless retry key, generate a new
    // key, and rotate the old.
    //

    int64_t ExpirationTime = StartTime + QUIC_STATELESS_RETRY_KEY_LIFETIME_MS;

    CXPLAT_KEY* NewKey;
    uint8_t RawKey[CXPLAT_AEAD_AES_256_GCM_SIZE];
    CxPlatRandom(sizeof(RawKey), RawKey);
    QUIC_STATUS Status =
        CxPlatKeyCreate(
            CXPLAT_AEAD_AES_256_GCM,
            RawKey,
            &NewKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Create stateless retry key");
        return NULL;
    }

    MsQuicLib.StatelessRetryKeysExpiration[!MsQuicLib.CurrentStatelessRetryKey] = ExpirationTime;
    CxPlatKeyFree(MsQuicLib.StatelessRetryKeys[!MsQuicLib.CurrentStatelessRetryKey]);
    MsQuicLib.StatelessRetryKeys[!MsQuicLib.CurrentStatelessRetryKey] = NewKey;
    MsQuicLib.CurrentStatelessRetryKey = !MsQuicLib.CurrentStatelessRetryKey;

    return NewKey;
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
    }
}

CXPLAT_STATIC_ASSERT(
    CXPLAT_HASH_SHA256_SIZE >= QUIC_STATELESS_RESET_TOKEN_LENGTH,
    "Stateless reset token must be shorter than hash size used");

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGenerateStatelessResetToken(
    _In_reads_(MsQuicLib.CidTotalLength)
        const uint8_t* const CID,
    _Out_writes_all_(QUIC_STATELESS_RESET_TOKEN_LENGTH)
        uint8_t* ResetToken
    )
{
    uint8_t HashOutput[CXPLAT_HASH_SHA256_SIZE];
    uint32_t CurProcIndex = CxPlatProcCurrentNumber();
    CxPlatLockAcquire(&MsQuicLib.PerProc[CurProcIndex].ResetTokenLock);
    QUIC_STATUS Status =
        CxPlatHashCompute(
            MsQuicLib.PerProc[CurProcIndex].ResetTokenHash,
            CID,
            MsQuicLib.CidTotalLength,
            sizeof(HashOutput),
            HashOutput);
    CxPlatLockRelease(&MsQuicLib.PerProc[CurProcIndex].ResetTokenLock);
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatCopyMemory(
            ResetToken,
            HashOutput,
            QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }
    return Status;
}
