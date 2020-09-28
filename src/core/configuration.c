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
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_reads_bytes_opt_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _In_ uint32_t SettingsSize,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Configuration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* NewConfiguration
    )
{
    QUIC_STATUS Status = QUIC_STATUS_INVALID_PARAMETER;
    QUIC_REGISTRATION* Registration = (QUIC_REGISTRATION*)Handle;
    QUIC_CONFIGURATION* Configuration = NULL;
    uint8_t* AlpnList;
    uint32_t AlpnListLength;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_OPEN,
        Handle);

    if (Handle == NULL ||
        Handle->Type != QUIC_HANDLE_TYPE_REGISTRATION ||
        AlpnBuffers == NULL ||
        AlpnBufferCount == 0 ||
        NewConfiguration == NULL) {
        goto Error;
    }

    if (Settings != NULL &&
        SettingsSize < (uint32_t)FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    AlpnListLength = 0;
    for (uint32_t i = 0; i < AlpnBufferCount; ++i) {
        if (AlpnBuffers[i].Length == 0 ||
            AlpnBuffers[i].Length > QUIC_MAX_ALPN_LENGTH) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
        AlpnListLength += sizeof(uint8_t) + AlpnBuffers[i].Length;
    }
    if (AlpnListLength > UINT16_MAX) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }
    QUIC_ANALYSIS_ASSERT(AlpnListLength <= UINT16_MAX);

    Configuration = QUIC_ALLOC_NONPAGED(sizeof(QUIC_CONFIGURATION) + AlpnListLength);
    if (Configuration == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_CONFIGURATION" ,
            sizeof(QUIC_CONFIGURATION));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicZeroMemory(Configuration, sizeof(QUIC_CONFIGURATION));
    Configuration->Type = QUIC_HANDLE_TYPE_CONFIGURATION;
    Configuration->ClientContext = Context;
    Configuration->Registration = Registration;
    QuicRefInitialize(&Configuration->RefCount);

    Configuration->AlpnListLength = (uint16_t)AlpnListLength;
    AlpnList = Configuration->AlpnList;

    for (uint32_t i = 0; i < AlpnBufferCount; ++i) {
        AlpnList[0] = (uint8_t)AlpnBuffers[i].Length;
        AlpnList++;

        QuicCopyMemory(
            AlpnList,
            AlpnBuffers[i].Buffer,
            AlpnBuffers[i].Length);
        AlpnList += AlpnBuffers[i].Length;
    }

#ifdef QUIC_COMPARTMENT_ID
    Configuration->CompartmentId = QuicCompartmentIdGetCurrent();
#endif

    //
    // TODO - Optimize the settings code below:
    //
    //  1. When there is no silo support, the per-app name settings can live in
    //     the registration.
    //
    //  2. When there is silo support (Windows kernel mode), then there will be
    //     a ton of duplication between every single configuration (multiple
    //     server certificate scenarios), so we should have an intermediate
    //     object (ref counted) that is per-silo, per-app to handle these.
    //

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

    if (Settings != NULL && Settings->IsSetFlags != 0) {
        QUIC_DBG_ASSERT(SettingsSize >= (uint32_t)FIELD_OFFSET(QUIC_SETTINGS, MaxBytesPerKey));
        if (!QuicSettingApply(
                &Configuration->Settings,
                TRUE,
                SettingsSize,
                Settings)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
    }

    QuicTraceEvent(
        ConfigurationCreated,
        "[cnfg][%p] Created, Registration=%p",
        Configuration,
        Registration);

    QuicConfigurationSettingsChanged(Configuration);

    BOOLEAN Result = QuicRundownAcquire(&Registration->Rundown);
    QUIC_FRE_ASSERT(Result);

    QuicLockAcquire(&Registration->ConfigLock);
    QuicListInsertTail(&Registration->Configurations, &Configuration->Link);
    QuicLockRelease(&Registration->ConfigLock);

    *NewConfiguration = (HQUIC)Configuration;

Error:

    if (QUIC_FAILED(Status) && Configuration != NULL) {
        QuicStorageClose(Configuration->AppSpecificStorage);
#ifdef QUIC_SILO
        QuicStorageClose(Configuration->Storage);
        QuicSiloRelease(Configuration->Silo);
#endif
        QUIC_FREE(Configuration);
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConfigurationUninitialize(
    _In_ __drv_freesMem(Mem) QUIC_CONFIGURATION* Configuration
    )
{
    QUIC_DBG_ASSERT(Configuration != NULL);

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

    QuicStorageClose(Configuration->AppSpecificStorage);
#ifdef QUIC_SILO
    QuicStorageClose(Configuration->Storage);
    QuicSiloRelease(Configuration->Silo);
#endif

    QuicRundownRelease(&Configuration->Registration->Rundown);

    QuicTraceEvent(
        ConfigurationDestroyed,
        "[cnfg][%p] Destroyed",
        Configuration);
    QUIC_FREE(Configuration);
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
        QuicConfigurationRelease((QUIC_CONFIGURATION*)Handle);
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
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    QUIC_CONFIGURATION* Configuration = (QUIC_CONFIGURATION*)Context;

    QUIC_DBG_ASSERT(Configuration != NULL);
    QUIC_DBG_ASSERT(CredConfig != NULL);

    if (QUIC_SUCCEEDED(Status)) {
        QUIC_DBG_ASSERT(SecurityConfig);
        Configuration->SecurityConfig = SecurityConfig;
    } else {
        QUIC_DBG_ASSERT(SecurityConfig == NULL);
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        QUIC_DBG_ASSERT(CredConfig->AsyncHandler != NULL);
        CredConfig->AsyncHandler(
            (HQUIC)Configuration,
            Configuration->ClientContext,
            Status);
        QuicConfigurationRelease(Configuration);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicConfigurationLoadCredential(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    )
{
    QUIC_STATUS Status = QUIC_STATUS_INVALID_PARAMETER;

    QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
        Handle);

    if (Handle != NULL &&
        CredConfig != NULL &&
        Handle->Type == QUIC_HANDLE_TYPE_CONFIGURATION) {

#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        QUIC_CONFIGURATION* Configuration = (QUIC_CONFIGURATION*)Handle;

        QuicConfigurationAddRef(Configuration);

        Status =
            QuicTlsSecConfigCreate(
                CredConfig,
                Configuration,
                MsQuicConfigurationLoadCredentialComplete);
        if (!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) ||
            QUIC_FAILED(Status)) {
            //
            // Release ref for synchronous calls or asynchronous failures.
            //
            QuicConfigurationRelease(Configuration);
        }
    }

    QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);

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
    case QUIC_PARAM_CONFIGURATION_SETTINGS:

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
        QuicCopyMemory(Buffer, &Configuration->Settings, sizeof(QUIC_SETTINGS));

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
    case QUIC_PARAM_GLOBAL_SETTINGS:

        if (BufferLength != sizeof(QUIC_SETTINGS)) {
            Status = QUIC_STATUS_INVALID_PARAMETER; // TODO - Support partial
            break;
        }

        QuicTraceLogInfo(
            ConfigurationSetSettings,
            "[cnfg][%p] Setting new settings",
            Configuration);

        if (!QuicSettingApply(
                &Configuration->Settings,
                TRUE,
                BufferLength,
                (QUIC_SETTINGS*)Buffer)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicSettingsDumpNew(BufferLength, (QUIC_SETTINGS*)Buffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
