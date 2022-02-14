/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Represents a set of TLS and QUIC configurations and settings.
//
typedef struct QUIC_CONFIGURATION {

    struct QUIC_HANDLE;

    //
    // Parent registration.
    //
    QUIC_REGISTRATION* Registration;

    //
    // Link in the parent registration's Configurations list.
    //
    CXPLAT_LIST_ENTRY Link;

    //
    // Reference count for tracking lifetime.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The TLS security configurations.
    //
    CXPLAT_SEC_CONFIG* SecurityConfig;

#ifdef QUIC_COMPARTMENT_ID
    //
    // The network compartment ID.
    //
    QUIC_COMPARTMENT_ID CompartmentId;
#endif

#ifdef QUIC_SILO
    //
    // The silo.
    //
    QUIC_SILO Silo;

    //
    // Handle to persistent storage (registry).
    //
    CXPLAT_STORAGE* Storage; // Only necessary if it could be in a different silo.
#endif

#ifdef QUIC_OWNING_PROCESS
    //
    // The process token of the owning process
    //
    QUIC_PROCESS OwningProcess;
#endif
    CXPLAT_STORAGE* AppSpecificStorage;

    //
    // Configurable (app & registry) settings.
    //
    QUIC_SETTINGS_INTERNAL Settings;

    uint16_t AlpnListLength;
    uint8_t AlpnList[0];

} QUIC_CONFIGURATION;

#ifdef QUIC_SILO

#define QuicConfigurationAttachSilo(Configuration) \
    QUIC_SILO PrevSilo = (Configuration == NULL || Configuration->Silo == NULL) ? \
        QUIC_SILO_INVALID : QuicSiloAttach(Configuration->Silo)

#define QuicConfigurationDetachSilo() \
    if (PrevSilo != QUIC_SILO_INVALID) {\
        QuicSiloDetatch(PrevSilo); \
    }

#else

#define QuicConfigurationAttachSilo(Configuration)
#define QuicConfigurationDetachSilo()

#endif // #ifdef QUIC_SILO

//
// Cleans up the configuration memory.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConfigurationUninitialize(
    _In_ __drv_freesMem(Mem) QUIC_CONFIGURATION* Configuration
    );

//
// Adds a new references to the configuration.
//
inline
void
QuicConfigurationAddRef(
    _In_ QUIC_CONFIGURATION* Configuration
    )
{
    CxPlatRefIncrement(&Configuration->RefCount);
}

//
// Releases a reference to the configuration and cleans it up if it's the last.
//
inline
void
QuicConfigurationRelease(
    _In_ QUIC_CONFIGURATION* Configuration
    )
{
    if (CxPlatRefDecrement(&Configuration->RefCount)) {
        QuicConfigurationUninitialize(Configuration);
    }
}

//
// Tracing rundown for the configuration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConfigurationTraceRundown(
    _In_ QUIC_CONFIGURATION* Configuration
    );

//
// Global or local settings were changed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_STORAGE_CHANGE_CALLBACK)
void
QuicConfigurationSettingsChanged(
    _Inout_ QUIC_CONFIGURATION* Configuration
    );

//
// Gets a configuration parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConfigurationParamGet(
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );

//
// Sets a configuration parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConfigurationParamSet(
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );
