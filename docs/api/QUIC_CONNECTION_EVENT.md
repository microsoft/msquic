QUIC_CONNECTION_EVENT structure
======

The payload for QUIC connection events.

# Syntax

```C
typedef struct QUIC_CONNECTION_EVENT {
    QUIC_CONNECTION_EVENT_TYPE Type;
    union {
        struct {
            BOOLEAN SessionResumed;
            _Field_range_(>, 0)
            uint8_t NegotiatedAlpnLength;
            _Field_size_(NegotiatedAlpnLength)
            const uint8_t* NegotiatedAlpn;
        } CONNECTED;
        struct {
            QUIC_STATUS Status;
        } SHUTDOWN_INITIATED_BY_TRANSPORT;
        struct {
            QUIC_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_PEER;
        struct {
            BOOLEAN HandshakeCompleted          : 1;
            BOOLEAN PeerAcknowledgedShutdown    : 1;
            BOOLEAN AppCloseInProgress          : 1;
        } SHUTDOWN_COMPLETE;
        struct {
            const QUIC_ADDR* Address;
        } LOCAL_ADDRESS_CHANGED;
        struct {
            const QUIC_ADDR* Address;
        } PEER_ADDRESS_CHANGED;
        struct {
            HQUIC Stream;
            QUIC_STREAM_OPEN_FLAGS Flags;
        } PEER_STREAM_STARTED;
        struct {
            uint16_t BidirectionalCount;
            uint16_t UnidirectionalCount;
        } STREAMS_AVAILABLE;
        struct {
            uint16_t IdealProcessor;
        } IDEAL_PROCESSOR_CHANGED;
        struct {
            BOOLEAN SendEnabled;
            uint16_t MaxSendLength;
        } DATAGRAM_STATE_CHANGED;
        struct {
            const QUIC_BUFFER* Buffer;
            QUIC_RECEIVE_FLAGS Flags;
        } DATAGRAM_RECEIVED;
        struct {
            /* inout */ void* ClientContext;
            QUIC_DATAGRAM_SEND_STATE State;
        } DATAGRAM_SEND_STATE_CHANGED;
        struct {
            uint16_t ResumptionStateLength;
            const uint8_t* ResumptionState;
        } RESUMED;
        struct {
            _Field_range_(>, 0)
            uint32_t ResumptionTicketLength;
            _Field_size_(ResumptionTicketLength)
            const uint8_t* ResumptionTicket;
        } RESUMPTION_TICKET_RECEIVED;
        struct {
            QUIC_CERTIFICATE* Certificate;
            uint32_t DeferredErrorFlags;
            QUIC_STATUS DeferredStatus;
            QUIC_CERTIFICATE_CHAIN* Chain;
        } PEER_CERTIFICATE_RECEIVED;
    };
} QUIC_CONNECTION_EVENT;
```

# Parameters

`Type`

The `QUIC_CONNECTION_EVENT_TYPE` that indicates which type of event this is, and which payload to reference (if any) for additional information.

# Remarks

## QUIC_CONNECTION_EVENT_CONNECTED

This event is delivered when the handshake has completed. This means the peer has been securely authenticated. This happens after one full round trip on the client side. The server side considers the handshake complete once the client responds after this. Additional state can be found in the `CONNECTED` struct/union.

`SessionResumed`

A flag that indicates if a previous TLS session was successfully resumed.

`NegotiatedAlpnLength`

The length of the `NegotiatedAlpn` field.

`NegotiatedAlpn`

The buffer (not null terminated) that holds the ALPN that was negotiated during the handshake.

## QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT

This event is delivered whenever the transport (e.g. QUIC layer) determines the connection has been terminated. This can happen for a number of different reasons. Some are as follows.

- The handshake fails (any number of reasons).
- The connection is idle for long enough.
- The connection disconnects (loses contact with peer; no acknowledgements).
- The connection encounters a protocol violation.

`Status`

The platform status code that indicates the reason for the shutdown.

## QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER

This event is delivered when the peer application has terminated the application, with an application's protocol specific, 62-bit error code.

`ErrorCode`

The error code received from the peer for the shutdown.

## QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE

This event is the last one delivered to the application, and indicates the connection may now be safely closed.

`HandshakeCompleted`

`PeerAcknowledgedShutdown`

`AppCloseInProgress`

## QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED

This event is delivered when the local address used for the primary/active path communication has changed.

`Address`

## QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED

This event is delivered when the remote address used for the primary/active path communication has changed.

`Address`

## QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED

This event is delivered when the peer has created a new stream.

`Stream`

`Flags`

## QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE

This event indicates the number of streams the peer is willing to accept has changed.

`BidirectionalCount`

`UnidirectionalCount`

## QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS

This event indicates the peer is currently blocked on the number of parallel streams the app has configured it is willing to accept.

## QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED

This event indicates the processor or CPU that MsQuic has determined would be the best for processing the given connection.

`IdealProcessor`

## QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED

This event indicates the current state for sending unreliable datagrams has changed.

`SendEnabled`

`MaxSendLength`

## QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED

This event indicates a received unreliable datagram from the peer.

`Buffer`

`Flags`

## QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED

This event indicates a state change for a previous unreliable datagram send.

`ClientContext`

`State`

## QUIC_CONNECTION_EVENT_RESUMED

This event indicates that a previous TLS session has been successfully resumed.

`ResumptionStateLength`

`ResumptionState`

## QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED

This event indicates a TLS resumption ticket has been received from the peer.

`ResumptionTicketLength`

`ResumptionTicket`

## QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED

This event indicates a certificate has been received from the peer.

`Certificate`

`DeferredErrorFlags`

`DeferredStatus`

`Chain`

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
