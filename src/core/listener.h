/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Represents the Listener specific state.
//
typedef struct QUIC_LISTENER {

    struct QUIC_HANDLE;

    //
    // Indicates the listener is listening on a wildcard address (v4/v6/both).
    //
    BOOLEAN WildCard;

    //
    // Indicates the listener has called ListenerClose.
    //
    BOOLEAN AppClosed;

    //
    // Indicates the listener is completely stopped.
    //
    BOOLEAN Stopped;

    //
    // Indicates the listener was closed by the app in the stop complete event.
    //
    BOOLEAN NeedsCleanup;

    //
    // The thread ID that the listener is actively indicating a stop compelete
    // callback on.
    //
    CXPLAT_THREAD_ID StopCompleteThreadID;

    //
    // The link in the binding's list of listeners.
    //
    CXPLAT_LIST_ENTRY Link;

    //
    // The top level registration.
    //
    QUIC_REGISTRATION* Registration;

#ifdef QUIC_SILO
    //
    // The silo.
    //
    QUIC_SILO Silo;
#endif

    //
    // Active reference count on the listener.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Event to signal when the listener is stopped.
    //
    CXPLAT_EVENT StopEvent;

    //
    // The address that the listener is listening on.
    //
    QUIC_ADDR LocalAddress;

    //
    // The UDP binding this Listener is associated with.
    //
    QUIC_BINDING* Binding;

    //
    // The handler for the API client's callbacks.
    //
    QUIC_LISTENER_CALLBACK_HANDLER ClientCallbackHandler;

    //
    // Stats for the Listener.
    //
    uint64_t TotalAcceptedConnections;
    uint64_t TotalRejectedConnections;

    //
    // The application layer protocol negotiation buffers. Encoded in the TLS
    // extension format.
    //
    uint16_t AlpnListLength;
    _Field_size_(AlpnListLength)
    uint8_t* AlpnList;

    //
    // An app configured prefix for all connection IDs in this listener. The
    // first byte indicates the length of the ID, the second byte the offset of
    // the ID in the CID and the rest payload of the identifier.
    //
    uint8_t CibirId[2 + QUIC_MAX_CIBIR_LENGTH];

} QUIC_LISTENER;

#ifdef QUIC_SILO

#define QuicListenerAttachSilo(Listener) \
    QUIC_SILO PrevSilo = Listener->Silo == NULL ? \
        QUIC_SILO_INVALID : QuicSiloAttach(Listener->Silo)

#define QuicListenerDetachSilo() \
    if (PrevSilo != QUIC_SILO_INVALID) {\
        QuicSiloDetatch(PrevSilo); \
    }

#else

#define QuicListenerAttachSilo(Listener)
#define QuicListenerDetachSilo()

#endif // #ifdef QUIC_SILO

//
// Tracing rundown for the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicListenerTraceRundown(
    _In_ QUIC_LISTENER* Listener
    );

//
// Releases an active reference on the listener.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerRelease(
    _In_ QUIC_LISTENER* Listener,
    _In_ BOOLEAN IndicateEvent
    );

//
// Returns TRUE if the two listeners have an overlapping ALPN.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicListenerHasAlpnOverlap(
    _In_ const QUIC_LISTENER* Listener1,
    _In_ const QUIC_LISTENER* Listener2
    );

//
// Returns TRUE if the listener has a matching ALPN. Also updates the new
// connection info with the matching ALPN.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicListenerMatchesAlpn(
    _In_ const QUIC_LISTENER* Listener,
    _In_ QUIC_NEW_CONNECTION_INFO* Info
    );

//
// Passes the connection to the listener to (possibly) accept it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicListenerAcceptConnection(
    _In_ QUIC_LISTENER* Listener,
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_NEW_CONNECTION_INFO* Info
    );

//
// Sets a Listener parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicListenerParamSet(
    _In_ QUIC_LISTENER* Listener,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

//
// Gets a Listener parameter.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicListenerParamGet(
    _In_ QUIC_LISTENER* Listener,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );
