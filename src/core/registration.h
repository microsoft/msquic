/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Special internal type to indicate registration created for global listener
// processing.
//
#define QUIC_EXECUTION_PROFILE_TYPE_INTERNAL ((QUIC_EXECUTION_PROFILE)0xFF)

//
// Different outcomes for a new incoming connection.
//
typedef enum QUIC_CONNECTION_ACCEPT_RESULT {
    QUIC_CONNECTION_ACCEPT,
    QUIC_CONNECTION_REJECT_NO_LISTENER,
    QUIC_CONNECTION_REJECT_BUSY,
    QUIC_CONNECTION_REJECT_APP
} QUIC_CONNECTION_ACCEPT_RESULT;

//
// Represents per application registration state.
//
typedef struct QUIC_REGISTRATION {

    struct QUIC_HANDLE;

#ifdef CxPlatVerifierEnabledByAddr
    //
    // The calling app is being verified (app or driver verifier).
    //
    BOOLEAN IsVerifying : 1;
#endif

    //
    // Indicates whether or not the registration is partitioned into multiple
    // workers.
    //
    BOOLEAN NoPartitioning : 1;

    //
    // Indicates whether if the QUIC worker is partitioned split from the RSS
    // core.
    //
    BOOLEAN SplitPartitioning : 1;

    BOOLEAN ShuttingDown : 1;

    //
    // App (optionally) configured execution profile.
    //
    QUIC_EXECUTION_PROFILE ExecProfile;

    QUIC_CONNECTION_SHUTDOWN_FLAGS ShutdownFlags;

    //
    // Link into the global library's Registrations list.
    //
    CXPLAT_LIST_ENTRY Link;

    //
    // Set of workers that manage most of the processing work.
    //
    QUIC_WORKER_POOL* WorkerPool;

    //
    // Protects access to the Configurations list.
    //
    CXPLAT_LOCK ConfigLock;

    //
    // List of all configurations for this registration.
    //
    CXPLAT_LIST_ENTRY Configurations;

    //
    // Protects access to the Connections list.
    //
    CXPLAT_DISPATCH_LOCK ConnectionLock;

    //
    // List of all connections for this registration.
    //
    CXPLAT_LIST_ENTRY Connections;

    //
    // Rundown for all child objects.
    //
    CXPLAT_RUNDOWN_REF Rundown;

    //
    // Shutdown error code if set.
    //
    uint64_t ShutdownErrorCode;

    //
    // Name of the application layer.
    //
    uint8_t AppNameLength;
    char AppName[0];

} QUIC_REGISTRATION;

#ifdef CxPlatVerifierEnabledByAddr
#define QUIC_REG_VERIFY(Registration, Expr) \
    if (Registration->IsVerifying) { CXPLAT_FRE_ASSERT(Expr); }
#elif defined(CxPlatVerifierEnabled)
#define QUIC_REG_VERIFY(Registration, Expr) \
    if (MsQuicLib.IsVerifying) { CXPLAT_FRE_ASSERT(Expr); }
#else
#define QUIC_REG_VERIFY(Registration, Expr)
#endif

//
// Tracing rundown for the registration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationTraceRundown(
    _In_ QUIC_REGISTRATION* Registration
    );

//
// Global settings were changed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicRegistrationSettingsChanged(
    _Inout_ QUIC_REGISTRATION* Registration
    );

//
// Determines whether this new connection can be accepted by the registration
// or not.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicRegistrationAcceptConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Queues a new (client or server) connection to be processed. The worker that
// the connection is queued on is determined by the connection's partition ID.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRegistrationQueueNewConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Sets a registration parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicRegistrationParamSet(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

//
// Gets a registration parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicRegistrationParamGet(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );
