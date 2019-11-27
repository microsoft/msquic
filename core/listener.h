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
    QUIC_LIST_ENTRY Link;

    //
    // The top level session.
    //
    QUIC_SESSION* Session;

    //
    // Rundown for unregistering from a binding.
    //
    QUIC_RUNDOWN_REF Rundown;

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

} QUIC_LISTENER;

//
// Tracing rundown for the binding.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicListenerTraceRundown(
    _In_ QUIC_LISTENER* Listener
    );

//
// Indicates an event to the application layer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicListenerIndicateEvent(
    _In_ QUIC_LISTENER* Listener,
    _Inout_ QUIC_LISTENER_EVENT* Event
    );

//
// Passes the connection to the listener to (possibly) accept it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CONNECTION_ACCEPT_RESULT
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
