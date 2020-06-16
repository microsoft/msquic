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
    // TLS Session Context.
    //
    QUIC_TLS_SESSION* TlsSession;

#ifdef QUIC_SILO
    //
    // The silo.
    //
    QUIC_SILO Silo;
#endif

#ifdef QUIC_COMPARTMENT_ID
    //
    // The network compartment ID.
    //
    QUIC_COMPARTMENT_ID CompartmentId;
#endif

    //
    // Handle to persistent storage (registry).
    //
#ifdef QUIC_SILO
    QUIC_STORAGE* Storage; // Only necessary if it could be in a different silo.
#endif
    QUIC_STORAGE* AppSpecificStorage;

    //
    // Configurable (app & registry) settings.
    //
    QUIC_SETTINGS Settings;

    //
    // Per server cached state information.
    //
    QUIC_HASHTABLE ServerCache;
    QUIC_RW_LOCK ServerCacheLock;

    //
    // List of all connections in the session.
    //
    QUIC_LIST_ENTRY Connections;
    QUIC_DISPATCH_LOCK ConnectionsLock;

    //
    // The application layer protocol negotiation buffers. Encoded in the TLS
    // extension format.
    //
    uint16_t AlpnListLength;
    _Field_size_(AlpnListLength)
    uint8_t AlpnList[0];

} QUIC_SESSION;

#ifdef QUIC_SILO

#define QuicSessionAttachSilo(Session) \
    QUIC_SILO PrevSilo = (Session == NULL || Session->Silo == NULL) ? \
        QUIC_SILO_INVALID : QuicSiloAttach(Session->Silo)

#define QuicSessionDetachSilo() \
    if (PrevSilo != QUIC_SILO_INVALID) {\
        QuicSiloDetatch(PrevSilo); \
    }

#else

#define QuicSessionAttachSilo(Session)
#define QuicSessionDetachSilo()

#endif // #ifdef QUIC_SILO

//
// Initializes an empty session object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSessionAlloc(
    _In_opt_ QUIC_REGISTRATION* Registration,
    _In_opt_ void* Context,
    _When_(AlpnBufferCount > 0, _In_reads_(AlpnBufferCount))
    _When_(AlpnBufferCount == 0, _In_opt_)
        const QUIC_BUFFER* const AlpnBuffers,
    _In_ uint32_t AlpnBufferCount,
    _Outptr_ _At_(*NewSession, __drv_allocatesMem(Mem))
        QUIC_SESSION** NewSession
    );

//
// Returns TRUE if the two sessions have an overlapping ALPN.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSessionHasAlpnOverlap(
    _In_ const QUIC_SESSION* Session1,
    _In_ const QUIC_SESSION* Session2
    );

//
// Returns TRUE if the session has a matching ALPN. Also updates the new
// connection info with the matching ALPN.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSessionMatchesAlpn(
    _In_ const QUIC_SESSION* Session,
    _In_ QUIC_NEW_CONNECTION_INFO* Info
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
// Global or local settings were changed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STORAGE_CHANGE_CALLBACK)
void
QuicSessionSettingsChanged(
    _Inout_ QUIC_SESSION* Session
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
// Gets a session parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSessionParamGet(
    _In_ QUIC_SESSION* Session,
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
QuicSessionParamSet(
    _In_ QUIC_SESSION* Session,
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
