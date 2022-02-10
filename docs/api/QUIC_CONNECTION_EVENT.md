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

A flag indicating if the QUIC handshake completed before the connection was shutdown.

`PeerAcknowledgedShutdown`

A flag indicating if the peer explicitly acknowledged the connection shutdown.

`AppCloseInProgress`

A flag indicating that the application called [ConnectionClose](ConnectionClose.md) on this connection.

## QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED

This event is delivered when the local address used for the primary/active path communication has changed.

`Address`

The new local IP address.

## QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED

This event is delivered when the remote address used for the primary/active path communication has changed.

`Address`

The new peer IP address.

## QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED

This event is delivered when the peer has created a new stream.

`Stream`

A handle to the newly peer-created stream.

`Flags`

A set of flags indicating describing the newly opened stream:

Value | Meaning
--- | ---
**QUIC_STREAM_OPEN_FLAG_NONE**<br>0 | No special behavior. Defaults to bidirectional stream.
**QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL**<br>1 | A unidirectional stream.
**QUIC_STREAM_OPEN_FLAG_0_RTT**<br>2 | The stream was received in 0-RTT.

## QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE

This event indicates the number of streams the peer is willing to accept has changed.

`BidirectionalCount`

The number of bidirectional streams the peer is willing to accept.

`UnidirectionalCount`

The number of unidirectional streams the peer is willing to accept.

## QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS

This event indicates the peer is currently blocked on the number of parallel streams the app has configured it is willing to accept.

## QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED

This event indicates the processor or CPU that MsQuic has determined would be the best for processing the given connection.

`IdealProcessor`

The processor number that should be ideally used for processing the connection.

## QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED

This event indicates the current state for sending unreliable datagrams has changed.

`SendEnabled`

A flag that indicates datagrams are allowed to be sent.

`MaxSendLength`

When enabled, indicates the maximum length of a single datagram that can fit in a packet.

## QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED

This event indicates a received unreliable datagram from the peer.

`Buffer`

Contains a pointer to the received data along with the length of the data.

`Flags`

A set of flags indicating describing the received datagram data:

Value | Meaning
--- | ---
**QUIC_RECEIVE_FLAG_NONE**<br>0 | No special behavior.
**QUIC_RECEIVE_FLAG_0_RTT**<br>1 | The data was received in 0-RTT.
**QUIC_RECEIVE_FLAG_FIN**<br>2 | N/A. Only used for Stream data. Unused for datagrams.

## QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED

This event indicates a state change for a previous unreliable datagram send via [DatagramSend](DatagramSend.md).

`ClientContext`

The context pointer passed into [DatagramSend](DatagramSend.md) as `ClientSendContext`.

`State`

The latest state for the sent datagram.

Value | Meaning
--- | ---
**QUIC_DATAGRAM_SEND_SENT**<br>1 | Indicates the datagram has now been sent out on the network. This is the earliest the app may free the `Buffers` passed into [DatagramSend](DatagramSend.md).
**QUIC_DATAGRAM_SEND_LOST_SUSPECT**<br>2 | The sent datagram is suspected to be lost. If desired, the app could retransmit the data now.
**QUIC_DATAGRAM_SEND_LOST_DISCARDED**<br>3 | The sent datagram is lost and no longer tracked by MsQuic.
**QUIC_DATAGRAM_SEND_ACKNOWLEDGED**<br>4 | The sent datagram has been acknowledged.
**QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS**<br>5 | The sent datagram has been acknowledged after previously being suspected as lost.
**QUIC_DATAGRAM_SEND_CANCELED**<br>6 | The queued datagram was canceled; either because the connection was shutdown or the peer did not negotiate the feature.

## QUIC_CONNECTION_EVENT_RESUMED

This event indicates that a previous session has been successfully resumed at the TLS layer. This event is delivered for the server side only. The server app must indicate acceptance or rejection of the resumption ticket by returning a successful or failure status code from the event. If rejected by the server app, then resumption is rejected and a normal handshake will be performed.

`ResumptionStateLength`

The length of the `ResumptionState` buffer.

`ResumptionState`

The resumption ticket data previously sent to the client via [ConnectionSendResumptionTicket](ConnectionSendResumptionTicket.md).

## QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED

This event indicates a TLS resumption ticket has been received from the server.

`ResumptionTicketLength`

The length of the `ResumptionTicket` buffer.

`ResumptionTicket`

The resumption ticket data received from the server. For a client to later resume the session in a new connection, it must pass this data to the new connection via the `QUIC_PARAM_CONN_RESUMPTION_TICKET` parameter.

## QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED

This event indicates a certificate has been received from the peer.

`Certificate`

Pointer to a platform/TLS specific certificate. Valid only during the callback.

If `QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES` was specified in the [QUIC_CREDENTIAL_CONFIG](QUIC_CREDENTIAL_CONFIG.md), this will be a `QUIC_BUFFER` containing the DER (binary) encoded remote X.509 certificate.

`DeferredErrorFlags`

Bit flag of errors encountered when doing deferring validation of the certificate. Valid only with QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION flag specified upfront. Only supported with Schannel currently.

`DeferredStatus`

Most severe error status when doing deferred validation of the certificate. Valid only with QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION flag specified upfront.

`Chain`

Pointer to a platform/TLS specific certificate chain. Valid only during the callback.

If `QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES` was specified in the [QUIC_CREDENTIAL_CONFIG](QUIC_CREDENTIAL_CONFIG.md), this will be a `QUIC_BUFFER` containing the PKCS #7 DER (binary) encoded certificate chain.

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[QUIC_CONNECTION_CALLBACK](QUIC_CONNECTION_CALLBACK.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
[QUIC_CREDENTIAL_CONFIG](QUIC_CREDENTIAL_CONFIG.md)<br>
