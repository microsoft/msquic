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
    BOOLEAN WildCard : 1;

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
    // Rundown for unregistering from a binding.
    //
    CXPLAT_RUNDOWN_REF Rundown;

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
