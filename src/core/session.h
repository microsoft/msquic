/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_SERIALIZED_RESUMPTION_STATE {

    uint32_t QuicVersion;
    QUIC_TRANSPORT_PARAMETERS TransportParameters;
    uint16_t ServerNameLength;
    uint8_t Buffer[0]; // ServerName and TLS Session/Ticket

} QUIC_SERIALIZED_RESUMPTION_STATE;

//
// Represents cached (in memory) state from previous connections to a server.
//
typedef struct QUIC_SERVER_CACHE {

    QUIC_HASHTABLE_ENTRY Entry;

    const char* ServerName;

    uint16_t ServerNameLength;

    uint32_t QuicVersion;

    QUIC_TRANSPORT_PARAMETERS TransportParameters;

    QUIC_SEC_CONFIG* SecConfig;

} QUIC_SERVER_CACHE;

//
// Represents a library session context.
//
typedef struct QUIC_SESSION {

    struct QUIC_HANDLE;

    //
    // Parent registration.
    //
    QUIC_REGISTRATION* Registration;

    //
    // Link in the parent registration's Sessions list.
    //
    QUIC_LIST_ENTRY Link;

    //
    // Rundown for clean up.
    //
    QUIC_RUNDOWN_REF Rundown;

    //
    // List of all connections in the session.
    //
    QUIC_LIST_ENTRY Connections;
    QUIC_DISPATCH_LOCK ConnectionsLock;

} QUIC_SESSION;

//
// Initializes an empty session object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSessionAlloc(
    _In_opt_ QUIC_REGISTRATION* Registration,
    _In_opt_ void* Context,
    _Outptr_ _At_(*NewSession, __drv_allocatesMem(Mem))
        QUIC_SESSION** NewSession
    );

//
// Tracing rundown for the session.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSessionTraceRundown(
    _In_ QUIC_SESSION* Session
    );

//
// Registers the connection with the session.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSessionRegisterConnection(
    _Inout_ QUIC_SESSION* Session,
    _Inout_ QUIC_CONNECTION* Connection
    );

//
// Unregisters the connection with the session.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSessionUnregisterConnection(
    _Inout_ QUIC_CONNECTION* Connection
    );

//
// Gets a previously cached server state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return!=FALSE)
BOOLEAN
QuicSessionServerCacheGetState(
    _In_ QUIC_SESSION* Session,
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
QuicSessionServerCacheSetState(
    _In_ QUIC_SESSION* Session,
    _In_z_ const char* ServerName,
    _In_ uint32_t QuicVersion,
    _In_ const QUIC_TRANSPORT_PARAMETERS* Parameters,
    _In_ QUIC_SEC_CONFIG* SecConfig
    );
