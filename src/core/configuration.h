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
    QUIC_LIST_ENTRY Link;

    //
    // Rundown for clean up.
    //
    QUIC_RUNDOWN_REF Rundown;

    //
    // The TLS security configurations.
    //
    QUIC_SEC_CONFIG* SecurityConfig;

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
    QUIC_STORAGE* Storage; // Only necessary if it could be in a different silo.
#endif
    QUIC_STORAGE* AppSpecificStorage;

    //
    // Configurable (app & registry) settings.
    //
    QUIC_SETTINGS Settings;

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
// Tracing rundown for the session.
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
_Function_class_(QUIC_STORAGE_CHANGE_CALLBACK)
void
QuicConfigurationSettingsChanged(
    _Inout_ QUIC_CONFIGURATION* Configuration
    );

//
// Gets a session parameter.
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
// Sets a session parameter.
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

//
// Gets a previously cached server state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return!=FALSE)
BOOLEAN
QuicConfigurationServerCacheGetState(
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_z_ const char* ServerName,
    _Out_ uint32_t* QuicVersion,
    _Out_ QUIC_TRANSPORT_PARAMETERS* Parameters,
    _Out_ QUIC_SEC_CONFIG** SecConfig
    );

//
// Sets/updates cached server state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConfigurationServerCacheSetState(
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_z_ const char* ServerName,
    _In_ uint32_t QuicVersion,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Parameters,
    _In_ QUIC_SEC_CONFIG* SecConfig
    );
