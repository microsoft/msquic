/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

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

#ifdef QuicVerifierEnabledByAddr
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
    // App configured network profile type.
    //
    uint8_t ExecProfileType; // QUIC_EXEC_PROF_TYPE_*

    //
    // An app configured prefix for all connection IDs in this registration.
    //
    uint8_t CidPrefixLength;
    uint8_t* CidPrefix;

    //
    // Link into the global library's Registrations list.
    //
    QUIC_LIST_ENTRY Link;

    //
    // Set of workers that manage most of the processing work.
    //
    QUIC_WORKER_POOL* WorkerPool;

    //
    // Protects access to the Sessions list.
    //
    QUIC_LOCK Lock;

    //
    // List of all sessions for this registration.
    //
    QUIC_LIST_ENTRY Sessions;

    //
    // Rundown for all outstanding security configs.
    //
    QUIC_RUNDOWN_REF SecConfigRundown;

    //
    // Name of the application layer.
    //
    char AppName[0];

} QUIC_REGISTRATION;

#ifdef QuicVerifierEnabledByAddr
#define QUIC_REG_VERIFY(Registration, Expr) \
    if (Registration->IsVerifying) { QUIC_FRE_ASSERT(Expr); }
#elif defined(QuicVerifierEnabled)
#define QUIC_REG_VERIFY(Registration, Expr) \
    if (MsQuicLib.IsVerifying) { QUIC_FRE_ASSERT(Expr); }
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
QUIC_CONNECTION_ACCEPT_RESULT
QuicRegistrationAcceptConnection(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_CONNECTION* Connection
    );

//
// Queues a new (client or server) connection to be processed. The worker that
// the connection is queued on is determined by the connection's partition ID.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
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
