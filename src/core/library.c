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
// Initializes all global variables.
//
INITCODE
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryLoad(
    void
    )
{
    CxPlatLockInitialize(&MsQuicLib.Lock);
    CxPlatDispatchLockInitialize(&MsQuicLib.DatapathLock);
    CxPlatListInitializeHead(&MsQuicLib.Registrations);
    CxPlatListInitializeHead(&MsQuicLib.Bindings);
    MsQuicLib.Loaded = TRUE;
}

//
// Uninitializes global variables.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUnload(
    void
    )
{
    CXPLAT_FRE_ASSERT(MsQuicLib.Loaded);
    QUIC_LIB_VERIFY(MsQuicLib.RefCount == 0);
    QUIC_LIB_VERIFY(!MsQuicLib.InUse);
    MsQuicLib.Loaded = FALSE;
    CxPlatDispatchLockUninitialize(&MsQuicLib.DatapathLock);
    CxPlatLockUninitialize(&MsQuicLib.Lock);
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

    if (MsQuicLib.RefCount == 0) {
        CxPlatZeroMemory(Buffer, BufferLength);
    } else {
        QuicLibrarySumPerfCounters(Buffer, BufferLength);
    }

    CxPlatLockRelease(&MsQuicLib.Lock);
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
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        QuicBindingReceive,
        QuicBindingUnreachable
    };

    Status = CxPlatInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error; // Cannot log anything if platform failed to initialize.
    }
    PlatformInitialized = TRUE;

    CXPLAT_DBG_ASSERT(US_TO_MS(CxPlatGetTimerResolution()) + 1 <= UINT8_MAX);
    MsQuicLib.TimerResolutionMs = (uint8_t)US_TO_MS(CxPlatGetTimerResolution()) + 1;

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

    CxPlatDispatchLockInitialize(&MsQuicLib.StatelessRetryKeysLock);
    CxPlatZeroMemory(&MsQuicLib.StatelessRetryKeys, sizeof(MsQuicLib.StatelessRetryKeys));
    CxPlatZeroMemory(&MsQuicLib.StatelessRetryKeysExpiration, sizeof(MsQuicLib.StatelessRetryKeysExpiration));

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
    MsQuicLib.PartitionCount = (uint16_t)min(MsQuicLib.ProcessorCount, DefaultMaxPartitionCount);

    MsQuicCalculatePartitionMask();

    MsQuicLib.PerProc =
        CXPLAT_ALLOC_NONPAGED(
            MsQuicLib.ProcessorCount * sizeof(QUIC_LIBRARY_PP),
            QUIC_POOL_PERPROC);
    if (MsQuicLib.PerProc == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "connection pools",
            MsQuicLib.PartitionCount * sizeof(QUIC_LIBRARY_PP));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    for (uint16_t i = 0; i < MsQuicLib.ProcessorCount; ++i) {
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
        CxPlatZeroMemory(
            &MsQuicLib.PerProc[i].PerfCounters,
            sizeof(MsQuicLib.PerProc[i].PerfCounters));
    }

    Status =
        CxPlatDataPathInitialize(
            sizeof(CXPLAT_RECV_PACKET),
            &DatapathCallbacks,
            NULL,                   // TcpCallbacks
            &MsQuicLib.Datapath);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatDataPathInitialize");
        goto Error;
    }

    QuicTraceEvent(
        LibraryInitialized,
        "[ lib] Initialized, PartitionCount=%u DatapathFeatures=%u",
        MsQuicLib.PartitionCount,
        CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));

#ifdef QuicVerifierEnabled
    uint32_t Flags;
    MsQuicLib.IsVerifying = QuicVerifierEnabled(Flags);
    if (MsQuicLib.IsVerifying) {
#ifdef QuicVerifierEnabledByAddr
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
            }
            CXPLAT_FREE(MsQuicLib.PerProc, QUIC_POOL_PERPROC);
            MsQuicLib.PerProc = NULL;
        }
        if (MsQuicLib.Storage != NULL) {
            CxPlatStorageClose(MsQuicLib.Storage);
            MsQuicLib.Storage = NULL;
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
    //
    // Clean up the data path first, which can continue to cause new connections
    // to get created.
    //
    CxPlatDataPathUninitialize(MsQuicLib.Datapath);
    MsQuicLib.Datapath = NULL;

    //
    // The library's stateless registration for processing half-opened
    // connections needs to be cleaned up next, as it's the last thing that can
    // be holding on to connection objects.
    //
    if (MsQuicLib.StatelessRegistration != NULL) {
        MsQuicRegistrationShutdown(
            (HQUIC)MsQuicLib.StatelessRegistration,
            QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
            0);
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
    }
    CXPLAT_FREE(MsQuicLib.PerProc, QUIC_POOL_PERPROC);
    MsQuicLib.PerProc = NULL;

    for (size_t i = 0; i < ARRAYSIZE(MsQuicLib.StatelessRetryKeys); ++i) {
        CxPlatKeyFree(MsQuicLib.StatelessRetryKeys[i]);
        MsQuicLib.StatelessRetryKeys[i] = NULL;
    }
    CxPlatDispatchLockUninitialize(&MsQuicLib.StatelessRetryKeysLock);

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
    if (++MsQuicLib.RefCount == 1) {
        Status = MsQuicLibraryInitialize();
        if (QUIC_FAILED(Status)) {
            MsQuicLib.RefCount--;
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

    CXPLAT_FRE_ASSERT(MsQuicLib.RefCount > 0);
    QuicTraceEvent(
        LibraryRelease,
        "[ lib] Release");

    if (--MsQuicLib.RefCount == 0) {
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
        MSQUIC_CID_PID_LENGTH +
        MSQUIC_CID_PAYLOAD_LENGTH;

    CXPLAT_FRE_ASSERT(MsQuicLib.CidServerIdLength <= MSQUIC_MAX_CID_SID_LENGTH);
    CXPLAT_FRE_ASSERT(MsQuicLib.CidTotalLength >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
    CXPLAT_FRE_ASSERT(MsQuicLib.CidTotalLength <= MSQUIC_CID_MAX_LENGTH);

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
    QUIC_STATUS Status;

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

        if (BufferLength != sizeof(QUIC_SETTINGS)) {
            Status = QUIC_STATUS_INVALID_PARAMETER; // TODO - Support partial
            break;
        }

        QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");

        if (!QuicSettingApply(
                &MsQuicLib.Settings,
                TRUE,
                BufferLength,
                (QUIC_SETTINGS*)Buffer)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicSettingsDumpNew(BufferLength, (QUIC_SETTINGS*)Buffer);
        MsQuicLibraryOnSettingsChanged(TRUE);

        Status = QUIC_STATUS_SUCCESS;
        break;

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

        if (*BufferLength < sizeof(QUIC_SETTINGS)) {
            *BufferLength = sizeof(QUIC_SETTINGS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL; // TODO - Support partial
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_SETTINGS);
        CxPlatCopyMemory(Buffer, &MsQuicLib.Settings, sizeof(QUIC_SETTINGS));

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
    _In_ QUIC_PARAM_LEVEL Level,
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

    switch (Level)
    {
    case QUIC_PARAM_LEVEL_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamSet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONFIGURATION:
        if (Configuration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConfigurationParamSet(Configuration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamSet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamSet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_TLS:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = CxPlatTlsParamSet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_STREAM:
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
    _In_ QUIC_PARAM_LEVEL Level,
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

    switch (Level)
    {
    case QUIC_PARAM_LEVEL_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamGet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONFIGURATION:
        if (Configuration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConfigurationParamGet(Configuration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamGet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamGet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_TLS:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = CxPlatTlsParamGet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_STREAM:
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
QUIC_STATUS
QUIC_API
MsQuicOpen(
    _Out_ _Pre_defensive_ const QUIC_API_TABLE** QuicApi
    )
{
    QUIC_STATUS Status;

    if (QuicApi == NULL) {
        QuicTraceLogVerbose(
            LibraryMsQuicOpenNull,
            "[ api] MsQuicOpen, NULL");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicTraceLogVerbose(
        LibraryMsQuicOpenEntry,
        "[ api] MsQuicOpen");

    Status = MsQuicAddRef();
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    QUIC_API_TABLE* Api = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_API_TABLE), QUIC_POOL_API);
    if (Api == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
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

Error:

    if (QUIC_FAILED(Status)) {
        MsQuicRelease();
    }

Exit:

    QuicTraceLogVerbose(
        LibraryMsQuicOpenExit,
        "[ api] MsQuicOpen, status=0x%x",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicClose(
    _In_ _Pre_defensive_ const QUIC_API_TABLE* QuicApi
    )
{
    if (QuicApi != NULL) {
        QuicTraceLogVerbose(
            LibraryMsQuicClose,
            "[ api] MsQuicClose");
        CXPLAT_FREE(QuicApi, QUIC_POOL_API);
        MsQuicRelease();
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
        CxPlatSocketGetLocalAddress(Binding->Socket, &BindingLocalAddr);

        if (!QuicAddrCompare(LocalAddress, &BindingLocalAddr)) {
            continue;
        }

        if (Binding->Connected) {
            if (RemoteAddress == NULL) {
                continue;
            }

            QUIC_ADDR BindingRemoteAddr;
            CxPlatSocketGetRemoteAddress(Binding->Socket, &BindingRemoteAddr);
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
#ifdef QUIC_COMPARTMENT_ID
    _In_ QUIC_COMPARTMENT_ID CompartmentId,
#endif
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN ServerOwned,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _Out_ QUIC_BINDING** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_FOUND;
    QUIC_BINDING* Binding;
    QUIC_ADDR NewLocalAddress;

    //
    // First check to see if a binding already exists that matches the
    // requested addresses.
    //

    if (LocalAddress == NULL) {
        //
        // No specified local address, so we just always create a new binding.
        //
        goto NewBinding;
    }

    CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);

    Binding =
        QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
            CompartmentId,
#endif
            LocalAddress,
            RemoteAddress);
    if (Binding != NULL) {
        if (!ShareBinding || Binding->Exclusive ||
            (ServerOwned != Binding->ServerOwned)) {
            //
            // The binding does already exist, but cannot be shared with the
            // requested configuration.
            //
            Status = QUIC_STATUS_INVALID_STATE;
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
        goto Exit;
    }

NewBinding:

    //
    // Create a new binding since there wasn't a match.
    //

    Status =
        QuicBindingInitialize(
#ifdef QUIC_COMPARTMENT_ID
            CompartmentId,
#endif
            ShareBinding,
            ServerOwned,
            LocalAddress,
            RemoteAddress,
            NewBinding);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    CxPlatSocketGetLocalAddress((*NewBinding)->Socket, &NewLocalAddress);

    CxPlatDispatchLockAcquire(&MsQuicLib.DatapathLock);

    //
    // Now that we created the binding, we need to insert it into the list of
    // all bindings. But we need to make sure another thread didn't race this
    // one and already create the binding.
    //

#if 0
    Binding = QuicLibraryLookupBinding(&NewLocalAddress, RemoteAddress);
#else
    //
    // Don't allow multiple sockets on the same local tuple currently. So just
    // do collision detection based on local tuple.
    //
    Binding =
        QuicLibraryLookupBinding(
#ifdef QUIC_COMPARTMENT_ID
            CompartmentId,
#endif
            &NewLocalAddress,
            NULL);
#endif
    if (Binding != NULL) {
        if (!Binding->Exclusive) {
            //
            // Another thread got the binding first, but it's not exclusive.
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
        CxPlatListInsertTail(&MsQuicLib.Bindings, &(*NewBinding)->Link);
    }

    CxPlatDispatchLockRelease(&MsQuicLib.DatapathLock);

    if (Binding != NULL) {
        if (Binding->Exclusive) {
            Status = QUIC_STATUS_INVALID_STATE;
        } else {
            (*NewBinding)->RefCount--;
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
            Datagram->PartitionIndex % MsQuicLib.PartitionCount];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTraceRundown(
    void
    )
{
    if (!MsQuicLib.Loaded) {
        return;
    }

    CxPlatLockAcquire(&MsQuicLib.Lock);

    if (MsQuicLib.RefCount > 0) {
        QuicTraceEvent(
            LibraryRundown,
            "[ lib] Rundown, PartitionCount=%u DatapathFeatures=%u",
            MsQuicLib.PartitionCount,
            CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));

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
            CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters));
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
