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

typedef enum QUIC_REGISTRATION_REF {

    QUIC_REG_REF_HANDLE_OWNER,
    QUIC_REG_REF_CONFIGURATION,
    QUIC_REG_REF_CONNECTION,
    QUIC_REG_REF_LISTENER,

    QUIC_REG_REF_COUNT

} QUIC_REGISTRATION_REF;

//
// Represents per application registration state.
//
typedef struct QUIC_REGISTRATION {

#ifdef __cplusplus
    struct QUIC_HANDLE _;
#else
    struct QUIC_HANDLE;
#endif

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
    // Indicates the registration is in the proces of shutting down.
    //
    BOOLEAN ShuttingDown : 1;

    //
    // App (optionally) configured execution profile.
    //
    QUIC_EXECUTION_PROFILE ExecProfile;

    //
    // When shutdown, the set of flags passed to each connection for shutdown.
    //
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
    // Protects access to the Connections list and the Listeners list.
    //
    CXPLAT_DISPATCH_LOCK ConnectionLock;

    //
    // List of all connections for this registration.
    //
    CXPLAT_LIST_ENTRY Connections;

    //
    // List of all Listeners for this registration.
    //
    CXPLAT_LIST_ENTRY Listeners;

    //
    // Rundown for all child objects.
    //
    CXPLAT_RUNDOWN_REF Rundown;

#if DEBUG
    //
    // Detailed ref counts. The actual reference count is in the Rundown.
    // Note: These ref counts are biased by 1, so lowest they go is 1. It is an
    // error for them to ever be zero.
    //
    CXPLAT_REF_COUNT RefTypeBiasedCount[QUIC_REG_REF_COUNT];
#endif

    //
    // Shutdown error code if set.
    //
    uint64_t ShutdownErrorCode;

    //
    // Close request event, to support async close.
    //
    CXPLAT_EVENT CloseEvent;

    //
    // Close thread, to support async close.
    //
    CXPLAT_THREAD CloseThread;

    //
    // Entry in the registration close cleanup list, to support async close.
    //
    CXPLAT_LIST_ENTRY CloseCleanupEntry;

    //
    // The app's close complete handler, if async close is used.
    //
    QUIC_REGISTRATION_CLOSE_CALLBACK_HANDLER CloseCompleteHandler;

    //
    // The app's close complete handler context, if async close is used.
    //
    void* CloseCompleteContext;

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
// Adds a rundown reference to the Registration.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
BOOLEAN
QuicRegistrationRundownAcquire(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_REGISTRATION_REF Ref
    )
{
    BOOLEAN Result = CxPlatRundownAcquire(&Registration->Rundown);
#if DEBUG
    if (Result) {
        //
        // Only increment the detailed ref count if the Rundown acquire succeeded.
        //
        CxPlatRefIncrement(&Registration->RefTypeBiasedCount[Ref]);
    }
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    return Result;
}

//
// Releases a rundown reference on the Registration.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
void
QuicRegistrationRundownRelease(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_REGISTRATION_REF Ref
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!CxPlatRefDecrement(&Registration->RefTypeBiasedCount[Ref]));
#else
    UNREFERENCED_PARAMETER(Ref);
#endif

    CxPlatRundownRelease(&Registration->Rundown);
}

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
_IRQL_requires_max_(DISPATCH_LEVEL)
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
