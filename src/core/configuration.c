/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A configurations is a container for multiple different settings, including
    TLS security configuration and QUIC settings. On Windows it also manages
    silo and network compartment state.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "configuration.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConfigurationOpen(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_CONFIGURATION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Configuration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* NewConfiguration
    )
{
    QUIC_STATUS Status = QUIC_STATUS_INVALID_PARAMETER;
    QUIC_REGISTRATION* Registration = (QUIC_REGISTRATION*)Handle;
    QUIC_CONFIGURATION* Configuration;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_OPEN,
        Handle);

    if (Handle == NULL || Handler == NULL ||
        Handle->Type != QUIC_HANDLE_TYPE_REGISTRATION) {
        goto Error;
    }

    Configuration = QUIC_ALLOC_NONPAGED(sizeof(QUIC_CONFIGURATION));
    if (Configuration == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_CONFIGURATION" ,
            sizeof(QUIC_CONFIGURATION));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    QuicZeroMemory(Configuration, sizeof(QUIC_CONFIGURATION));
    Configuration->Type = QUIC_HANDLE_TYPE_CONFIGURATION;
    Configuration->ClientContext = Context;
    Configuration->ClientCallbackHandler = Handler;
    Configuration->Registration = Registration;
    QuicRundownInitialize(&Configuration->Rundown);

#ifdef QUIC_COMPARTMENT_ID
    Configuration->CompartmentId = QuicCompartmentIdGetCurrent();
#endif

#ifdef QUIC_SILO
    Configuration->Silo = QuicSiloGetCurrentServer();
    QuicSiloAddRef(Configuration->Silo);
    if (Configuration->Silo != NULL) {
        //
        // Only need to load base key if in a silo. Otherwise, the library already
        // read in the default silo settings.
        //
        Status =
            QuicStorageOpen(
                NULL,
                (QUIC_STORAGE_CHANGE_CALLBACK_HANDLER)QuicConfigurationSettingsChanged,
                Configuration,
                &Configuration->Storage);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                ConfigurationOpenStorageFailed,
                "[cnfg][%p] Failed to open settings, 0x%x",
                Configuration,
                Status);
            Status = QUIC_STATUS_SUCCESS; // Non-fatal, as the process may not have access
        }
    }
#endif

    if (Registration->AppNameLength != 0) {
        char SpecificAppKey[UINT8_MAX + sizeof(QUIC_SETTING_APP_KEY)] = QUIC_SETTING_APP_KEY;
        QuicCopyMemory(
            SpecificAppKey + sizeof(QUIC_SETTING_APP_KEY) - 1,
            Registration->AppName,
            Registration->AppNameLength);
        Status =
            QuicStorageOpen(
                SpecificAppKey,
                (QUIC_STORAGE_CHANGE_CALLBACK_HANDLER)QuicConfigurationSettingsChanged,
                Configuration,
                &Configuration->AppSpecificStorage);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                ConfigurationOpenAppStorageFailed,
                "[cnfg][%p] Failed to open app specific settings, 0x%x",
                Configuration,
                Status);
            Status = QUIC_STATUS_SUCCESS; // Non-fatal, as the process may not have access
        }
    }

    QuicTraceEvent(
        ConfigurationCreated,
        "[cnfg][%p] Created, Registration=%p",
        Configuration,
        Registration);

    QuicConfigurationSettingsChanged(Configuration);

    BOOLEAN Result = QuicRundownAcquire(&Registration->ConfigRundown);
    QUIC_FRE_ASSERT(Result);

    QuicLockAcquire(&Registration->ConfigLock);
    QuicListInsertTail(&Registration->Configurations, &Configuration->Link);
    QuicLockRelease(&Registration->ConfigLock);

    *NewConfiguration = Configuration;

Error:

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicConfigurationClose(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Handle
    )
{
    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_CLOSE,
        Handle);

    if (Handle != NULL && Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION) {

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_CONFIGURATION* Configuration = (QUIC_CONFIGURATION*)Handle;

        QuicTraceEvent(
            ConfigurationCleanup,
            "[cnfg][%p] Cleaning up",
            Configuration);

        QuicLockAcquire(&Configuration->Registration->ConfigLock);
        QuicListEntryRemove(&Configuration->Link);
        QuicLockRelease(&Configuration->Registration->ConfigLock);

        if (Configuration->SecurityConfig != NULL) {
            QuicTlsSecConfigDelete(Configuration->SecurityConfig);
        }

        QuicRundownReleaseAndWait(&Configuration->Rundown);

        QuicStorageClose(Configuration->AppSpecificStorage);
#ifdef QUIC_SILO
        QuicStorageClose(Configuration->Storage);
        QuicSiloRelease(Configuration->Silo);
#endif

        QuicRundownRelease(&Configuration->Registration->ConfigRundown);

        QuicRundownUninitialize(&Configuration->Rundown);
        QuicTraceEvent(
            ConfigurationDestroyed,
            "[cnfg][%p] Destroyed",
            Configuration);
        QUIC_FREE(Configuration);
    }

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
void
QUIC_API
MsQuicConfigurationLoadCredentialComplete(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    QUIC_CONFIGURATION* Configuration = (QUIC_CONFIGURATION*)Context;

    if (QUIC_SUCCEEDED(Status)) {
        QUIC_DBG_ASSERT(SecurityConfig);
        Configuration->SecurityConfig = SecurityConfig;
    } else {
        QUIC_DBG_ASSERT(SecurityConfig == NULL);
    }

    QUIC_CONFIGURATION_EVENT* Event;
    Event->Type = QUIC_CONFIGURATION_EVENT_LOAD_COMPLETE;
    Event->LOAD_CREDENTIAL_COMPLETE.Status = Status;
    (void)Configuration->ClientCallbackHandler(
        Configuration,
        Configuration->ClientCallbackHandler,
        &Event);

    QuicRundownRelease(&Configuration->Rundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConfigurationLoadCredential(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    )
{
    QUIC_STATUS Status = QUIC_STATUS_INVALID_PARAMETER;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
        Handle);

    if (Handle != NULL && CredConfig == NULL &&
        Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION) {

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_CONFIGURATION* Configuration = (QUIC_CONFIGURATION*)Handle;

        BOOLEAN Result = QuicRundownAcquire(&Configuration->Rundown);
        QUIC_FRE_ASSERT(Result);

        Status =
            QuicTlsSecConfigCreate(
                CredConfig,
                Configuration,
                MsQuicConfigurationLoadCredentialComplete);
    }

    QuicTraceEvent(
        ApiExit,
        "[ api] Exit");

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConfigurationTraceRundown(
    _In_ QUIC_CONFIGURATION* Configuration
    )
{
    QuicTraceEvent(
        ConfigurationRundown,
        "[cnfg][%p] Rundown, Registration=%p",
        Configuration,
        Configuration->Registration);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STORAGE_CHANGE_CALLBACK)
void
QuicConfigurationSettingsChanged(
    _Inout_ QUIC_CONFIGURATION* Configuration
    )
{
#ifdef QUIC_SILO
    if (Configuration->Storage != NULL) {
        QuicSettingsSetDefault(&Configuration->Settings);
        QuicSettingsLoad(&Configuration->Settings, Configuration->Storage);
    } else {
        QuicSettingsCopy(&Configuration->Settings, &MsQuicLib.Settings);
    }
#else
    QuicSettingsCopy(&Configuration->Settings, &MsQuicLib.Settings);
#endif

    if (Configuration->AppSpecificStorage != NULL) {
        QuicSettingsLoad(&Configuration->Settings, Configuration->AppSpecificStorage);
    }

    QuicTraceLogInfo(
        ConfigurationSettingsUpdated,
        "[cnfg][%p] Settings %p Updated",
        Configuration,
        &Configuration->Settings);
    QuicSettingsDump(&Configuration->Settings);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConfigurationRegisterConnection(
    _Inout_ QUIC_CONFIGURATION* Configuration,
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    QuicConfigurationUnregisterConnection(Connection);
    Connection->Configuration = Configuration;

    if (Configuration->Registration != NULL) {
        Connection->Registration = Configuration->Registration;
        QuicRundownAcquire(&Configuration->Registration->ConnectionRundown);
#ifdef QuicVerifierEnabledByAddr
        Connection->State.IsVerifying = Configuration->Registration->IsVerifying;
#endif
        QuicConnApplySettings(Connection, &Configuration->Settings);
    }

    QuicTraceEvent(
        ConnRegisterConfiguration,
        "[conn][%p] Registered with session: %p",
        Connection,
        Configuration);
    BOOLEAN Success = QuicRundownAcquire(&Configuration->Rundown);
    QUIC_DBG_ASSERT(Success); UNREFERENCED_PARAMETER(Success);
    QuicDispatchLockAcquire(&Configuration->ConnectionsLock);
    QuicListInsertTail(&Configuration->Connections, &Connection->ConfigurationLink);
    QuicDispatchLockRelease(&Configuration->ConnectionsLock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConfigurationUnregisterConnection(
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->Configuration == NULL) {
        return;
    }
    QUIC_CONFIGURATION* Configuration = Connection->Configuration;
    Connection->Configuration = NULL;
    QuicTraceEvent(
        ConnUnregisterConfiguration,
        "[conn][%p] Unregistered from session: %p",
        Connection,
        Configuration);
    QuicDispatchLockAcquire(&Configuration->ConnectionsLock);
    QuicListEntryRemove(&Connection->ConfigurationLink);
    QuicDispatchLockRelease(&Configuration->ConnectionsLock);
    QuicRundownRelease(&Configuration->Rundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConfigurationParamGet(
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

    case QUIC_PARAM_CONFIG_PEER_BIDI_STREAM_COUNT:

        if (*BufferLength < sizeof(Configuration->Settings.BidiStreamCount)) {
            *BufferLength = sizeof(Configuration->Settings.BidiStreamCount);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Configuration->Settings.BidiStreamCount);
        *(uint16_t*)Buffer = Configuration->Settings.BidiStreamCount;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_PEER_UNIDI_STREAM_COUNT:

        if (*BufferLength < sizeof(Configuration->Settings.UnidiStreamCount)) {
            *BufferLength = sizeof(Configuration->Settings.UnidiStreamCount);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Configuration->Settings.UnidiStreamCount);
        *(uint16_t*)Buffer = Configuration->Settings.UnidiStreamCount;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_IDLE_TIMEOUT:

        if (*BufferLength < sizeof(Configuration->Settings.IdleTimeoutMs)) {
            *BufferLength = sizeof(Configuration->Settings.IdleTimeoutMs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Configuration->Settings.IdleTimeoutMs);
        *(uint64_t*)Buffer = Configuration->Settings.IdleTimeoutMs;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_DISCONNECT_TIMEOUT:

        if (*BufferLength < sizeof(Configuration->Settings.DisconnectTimeoutMs)) {
            *BufferLength = sizeof(Configuration->Settings.DisconnectTimeoutMs);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Configuration->Settings.DisconnectTimeoutMs);
        *(uint32_t*)Buffer = Configuration->Settings.DisconnectTimeoutMs;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_MAX_BYTES_PER_KEY:
        if (*BufferLength < sizeof(Configuration->Settings.MaxBytesPerKey)) {
            *BufferLength = sizeof(Configuration->Settings.MaxBytesPerKey);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Configuration->Settings.MaxBytesPerKey);
        *(uint64_t*)Buffer = Configuration->Settings.MaxBytesPerKey;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_MIGRATION_ENABLED:
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
        *(BOOLEAN*)Buffer = Configuration->Settings.MigrationEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_DATAGRAM_RECEIVE_ENABLED:
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
        *(BOOLEAN*)Buffer = Configuration->Settings.DatagramReceiveEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONFIG_SERVER_RESUMPTION_LEVEL:
        if (*BufferLength  < sizeof(QUIC_SERVER_RESUMPTION_LEVEL)) {
            *BufferLength = sizeof(QUIC_SERVER_RESUMPTION_LEVEL);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_SERVER_RESUMPTION_LEVEL);
        *(QUIC_SERVER_RESUMPTION_LEVEL*)Buffer =
            (QUIC_SERVER_RESUMPTION_LEVEL)Configuration->Settings.ServerResumptionLevel;

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
QuicConfigurationParamSet(
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

    case QUIC_PARAM_CONFIG_TLS_TICKET_KEY: {

        if (BufferLength != 44) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        /*Status =
            QuicTlsConfigurationSetTicketKey(
                Configuration->TlsConfiguration,
                Buffer);*/
        break;
    }

    case QUIC_PARAM_CONFIG_PEER_BIDI_STREAM_COUNT: {

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.BidiStreamCount = TRUE;
        Configuration->Settings.BidiStreamCount = *(uint16_t*)Buffer;

        QuicTraceLogInfo(
            ConfigurationBiDiStreamCountSet,
            "[cnfg][%p] Updated bidirectional stream count = %hu",
            Configuration,
            Configuration->Settings.BidiStreamCount);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_PEER_UNIDI_STREAM_COUNT: {

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.UnidiStreamCount = TRUE;
        Configuration->Settings.UnidiStreamCount = *(uint16_t*)Buffer;

        QuicTraceLogInfo(
            ConfigurationUniDiStreamCountSet,
            "[cnfg][%p] Updated unidirectional stream count = %hu",
            Configuration,
            Configuration->Settings.UnidiStreamCount);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_IDLE_TIMEOUT: {

        if (BufferLength != sizeof(Configuration->Settings.IdleTimeoutMs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.IdleTimeoutMs = TRUE;
        Configuration->Settings.IdleTimeoutMs = *(uint64_t*)Buffer;

        QuicTraceLogInfo(
            ConfigurationIdleTimeoutSet,
            "[cnfg][%p] Updated idle timeout to %llu milliseconds",
            Configuration,
            Configuration->Settings.IdleTimeoutMs);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_DISCONNECT_TIMEOUT: {

        if (BufferLength != sizeof(Configuration->Settings.DisconnectTimeoutMs)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.DisconnectTimeoutMs = TRUE;
        Configuration->Settings.DisconnectTimeoutMs = *(uint32_t*)Buffer;

        QuicTraceLogInfo(
            ConfigurationDisconnectTimeoutSet,
            "[cnfg][%p] Updated disconnect timeout to %u milliseconds",
            Configuration,
            Configuration->Settings.DisconnectTimeoutMs);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_ADD_RESUMPTION_STATE: {

        const QUIC_SERIALIZED_RESUMPTION_STATE* State =
            (const QUIC_SERIALIZED_RESUMPTION_STATE*)Buffer;

        if (BufferLength < sizeof(QUIC_SERIALIZED_RESUMPTION_STATE) ||
            BufferLength < sizeof(QUIC_SERIALIZED_RESUMPTION_STATE) + State->ServerNameLength) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        const char* ServerName = (const char*)State->Buffer;

        const uint8_t* TicketBuffer = State->Buffer + State->ServerNameLength;
        uint32_t TicketBufferLength =
            BufferLength -
            sizeof(QUIC_SERIALIZED_RESUMPTION_STATE) -
            State->ServerNameLength;

        /*QuicConfigurationServerCacheSetStateInternal(
            Configuration,
            State->ServerNameLength,
            ServerName,
            State->QuicVersion,
            &State->TransportParameters,
            NULL);

        Status =
            QuicTlsConfigurationAddTicket(
                Configuration->TlsConfiguration,
                TicketBufferLength,
                TicketBuffer);*/
        break;
    }

    case QUIC_PARAM_CONFIG_MAX_BYTES_PER_KEY: {
        if (BufferLength != sizeof(Configuration->Settings.MaxBytesPerKey)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        uint64_t NewValue = *(uint64_t*)Buffer;
        if (NewValue > QUIC_DEFAULT_MAX_BYTES_PER_KEY) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.MaxBytesPerKey = TRUE;
        Configuration->Settings.MaxBytesPerKey = NewValue;

        QuicTraceLogInfo(
            ConfigurationMaxBytesPerKeySet,
            "[cnfg][%p] Updated max bytes per key to %llu bytes",
            Configuration,
            Configuration->Settings.MaxBytesPerKey);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_MIGRATION_ENABLED: {
        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.MigrationEnabled = TRUE;
        Configuration->Settings.MigrationEnabled = *(BOOLEAN*)Buffer;

        QuicTraceLogInfo(
            ConfigurationMigrationEnabledSet,
            "[cnfg][%p] Updated migration enabled to %hhu",
            Configuration,
            Configuration->Settings.MigrationEnabled);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_DATAGRAM_RECEIVE_ENABLED: {
        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.DatagramReceiveEnabled = TRUE;
        Configuration->Settings.DatagramReceiveEnabled = *(BOOLEAN*)Buffer;

        QuicTraceLogInfo(
            ConfigurationDatagramReceiveEnabledSet,
            "[cnfg][%p] Updated datagram receive enabled to %hhu",
            Configuration,
            Configuration->Settings.DatagramReceiveEnabled);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONFIG_SERVER_RESUMPTION_LEVEL: {
        if (BufferLength != sizeof(QUIC_SERVER_RESUMPTION_LEVEL) ||
            Buffer == NULL ||
            *(QUIC_SERVER_RESUMPTION_LEVEL*)Buffer > QUIC_SERVER_RESUME_AND_ZERORTT) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Configuration->Settings.AppSet.ServerResumptionLevel = TRUE;
        Configuration->Settings.ServerResumptionLevel =
            *(QUIC_SERVER_RESUMPTION_LEVEL*)Buffer;

        QuicTraceLogInfo(
            ConfigurationServerResumptionLevelSet,
            "[cnfg][%p] Updated Server resume/0-RTT to %hhu",
            Configuration,
            Configuration->Settings.ServerResumptionLevel);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
