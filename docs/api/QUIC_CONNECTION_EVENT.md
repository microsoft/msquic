QUIC_CONNECTION_EVENT structure
======

QUIC connection events and the corresponding payload

# Syntax

```C
typedef enum QUIC_CONNECTION_EVENT_TYPE {
    QUIC_CONNECTION_EVENT_CONNECTED                         = 0,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT   = 1,    // The transport started the shutdown process.
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER        = 2,    // The peer application started the shutdown process.
    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE                 = 3,    // Ready for the handle to be closed.
    QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED             = 4,
    QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED              = 5,
    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED               = 6,
    QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE                 = 7,
    QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS                = 8,
    QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED           = 9,
    QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED            = 10,
    QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED                 = 11,
    QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED       = 12,
    QUIC_CONNECTION_EVENT_RESUMED                           = 13,   // Server-only; provides resumption data, if any.
    QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED        = 14,   // Client-only; provides ticket to persist, if any.
    QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED         = 15    // Only with QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED set

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED         = 16,   // Only indicated if QUIC_SETTINGS.ReliableResetEnabled is TRUE.
    QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED          = 17,   // Only indicated if QUIC_SETTINGS.OneWayDelayEnabled is TRUE.
    QUIC_CONNECTION_EVENT_NETWORK_STATISTICS                = 18,   // Only indicated if QUIC_SETTINGS.EnableNetStatsEvent is TRUE.
    QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS           = 19,
    QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_ADDED       = 20,   // Only indicated if QUIC_SETTINGS.AddAddressMode is MANUAL
    QUIC_CONNECTION_EVENT_PATH_VALIDATED                    = 21,
    QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED     = 22,   // Only indicated if QUIC_SETTINGS.AddAddressMode is MANUAL
#endif

} QUIC_CONNECTION_EVENT_TYPE;
```

The payload for QUIC connection events.

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
            QUIC_UINT62 ErrorCode; // Wire format error code.
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

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        struct {
            BOOLEAN IsNegotiated;
        } RELIABLE_RESET_NEGOTIATED;
        struct {
            BOOLEAN SendNegotiated;             // TRUE if sending one-way delay timestamps is negotiated.
            BOOLEAN ReceiveNegotiated;          // TRUE if receiving one-way delay timestamps is negotiated.
        } ONE_WAY_DELAY_NEGOTIATED;
        QUIC_NETWORK_STATISTICS NETWORK_STATISTICS;
        struct {
            QUIC_ADDR *LocalAddress;
            QUIC_ADDR *ObservedAddress;
        } NOTIFY_OBSERVED_ADDRESS;
        struct {
            QUIC_ADDR *Address;
            QUIC_UINT62 SequenceNumber;
        } NOTIFY_REMOTE_ADDRESS_ADDED;
        struct {
            QUIC_ADDR *LocalAddress;
            QUIC_ADDR *RemoteAddress;
        } PATH_VALIDATED;
        struct {
            QUIC_UINT62 SequenceNumber;
        } NOTIFY_REMOTE_ADDRESS_REMOVED;
#endif

    };
} QUIC_CONNECTION_EVENT;
```

# Parameters

`Type`

The `QUIC_CONNECTION_EVENT_TYPE` that indicates which type of event this is, and which payload to reference (if any) for additional information.

# Remarks

## QUIC_CONNECTION_EVENT_CONNECTED

This event is delivered when the handshake has completed. This means the peer has been securely authenticated. This happens after one full round trip on the client side. The server side considers the handshake complete once the client responds after this.

### Connected

Additional state can be found in the `CONNECTED` struct/union.

`SessionResumed`

A flag that indicates if a previous TLS session was successfully resumed.

`NegotiatedAlpnLength`

The length of the `NegotiatedAlpn` field.

`NegotiatedAlpn`

The buffer (not null terminated) that holds the ALPN that was negotiated during the handshake.

## QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT

This event is delivered whenever the transport (e.g. QUIC layer) determines the connection has been terminated. This can happen for a number of different reasons. Some are as follows.

- The handshake failed (any number of reasons).
- The connection was idle for long enough.
- The connection disconnected (lost contact with peer; no acknowledgments).
- The connection encountered a protocol violation.

### SHUTDOWN_INITIATED_BY_TRANSPORT

Additional status can be found in the `SHUTDOWN_INITIATED_BY_TRANSPORT` struct/union.

`Status`

The platform status code that indicates the reason for the shutdown.

`ErrorCode`

The wire format error code that indicates the reason for the shutdown.

## QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER

This event is delivered when the peer application has terminated the application, with an application's protocol specific, 62-bit error code.

### SHUTDOWN_INITIATED_BY_PEER

Error code is found in the `SHUTDOWN_INITIATED_BY_PEER` struct/union.

`ErrorCode`

The error code received from the peer for the shutdown.

## QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE

This event is the last one delivered to the application, and indicates the connection may now be safely closed.

### SHUTDOWN_COMPLETE

Various state flags are contained in the `SHUTDOWN_COMPLETE` struct/union.

`HandshakeCompleted`

A flag indicating if the QUIC handshake completed before the connection was shutdown.

`PeerAcknowledgedShutdown`

A flag indicating if the peer explicitly acknowledged the connection shutdown.

`AppCloseInProgress`

A flag indicating that the application called [ConnectionClose](ConnectionClose.md) on this connection.

## QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED

This event is delivered when the local address used for the primary/active path communication has changed.

### LOCAL_ADDRESS_CHANGED

New local address is passed in the `LOCAL_ADDRESS_CHANGED` struct/union.

`Address`

The new local IP address.

## QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED

This event is delivered when the remote address used for the primary/active path communication has changed.

### PEER_ADDRESS_CHANGED

New peer ip address is passed in the `PEER_ADDRESS_CHANGED` struct/union.

`Address`

The new peer IP address.

## QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED

This event is delivered when the peer has created a new stream.

### PEER_STREAM_STARTED

Details of the new stream are passed in the `PEER_STREAM_STARTED` struct/union.

`Stream`

A handle to the newly peer-created stream.

`Flags`

A set of flags indicating describing the newly opened stream:

Value | Meaning
--- | ---
**QUIC_STREAM_OPEN_FLAG_NONE**<br>0 | No special behavior. Defaults to bidirectional stream.
**QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL**<br>1 | A unidirectional stream.
**QUIC_STREAM_OPEN_FLAG_0_RTT**<br>2 | The stream was received in 0-RTT.

If a server wishes to use `QUIC_STREAM_OPEN_FLAG_DELAY_ID_FC_UPDATES` for the newly started stream, it may append this flag to `Flags` before it returns from the callback.

## QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE

This event indicates the number of streams the peer is willing to accept has changed.

### STREAMS_AVAILABLE

New stream counts are passed in the `STREAMS_AVAILABLE` struct/union.

`BidirectionalCount`

The number of bidirectional streams the peer is willing to accept.

`UnidirectionalCount`

The number of unidirectional streams the peer is willing to accept.

## QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS

This event indicates the peer is currently blocked on the number of parallel streams the app has configured it is willing to accept.

## QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED

This event indicates the processor or CPU that MsQuic has determined would be the best for processing the given connection.

### IDEAL_PROCESSOR_CHANGED

The new processor number is passed in the `IDEAL_PROCESSOR_CHANGED` struct/union.

`IdealProcessor`

The processor number that should be ideally used for processing the connection.

## QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED

This event indicates the current state for sending unreliable datagrams has changed.

### DATAGRAM_STATE_CHANGED

New datagram state is passed in the `DATAGRAM_STATE_CHANGED` struct/union.

`SendEnabled`

A flag that indicates datagrams are allowed to be sent.

`MaxSendLength`

When enabled, indicates the maximum length of a single datagram that can fit in a packet.

## QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED

This event indicates a received unreliable datagram from the peer.

### DATAGRAM_RECEIVED

Unreliable datagram buffer and metadata are passed in the `DATAGRAM_RECEIVED` struct/union.

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

### SEND_STATE_CHANGED

Unreliable datagram send state is passed in the `SEND_STATE_CHANGED` struct/union.

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

### RESUMED

Connection resumption state is passed in the `Resumed` struct/union.

`ResumptionStateLength`

The length of the `ResumptionState` buffer.

`ResumptionState`

The resumption ticket data previously sent to the client via [ConnectionSendResumptionTicket](ConnectionSendResumptionTicket.md).

## QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED

This event indicates to the client that a TLS resumption ticket has been received from the server.

### RESUMPTION_TICKET_RECEIVED

Resumption ticket state is passed in the `RESUMPTION_TICKET_RECEIVED` struct/union.

`ResumptionTicketLength`

The length of the `ResumptionTicket` buffer.

`ResumptionTicket`

The resumption ticket data received from the server. For a client to later resume the session in a new connection, it must pass this data to the new connection via the `QUIC_PARAM_CONN_RESUMPTION_TICKET` parameter.

## QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED

This event indicates a certificate has been received from the peer.

### PEER_CERTIFICATE_RECEIVED

The peer certificate and related data is passed in the `PEER_CERTIFICATE_RECEIVED` struct/union.

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

## QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event indicates the result of reliable reset negotiation. This is only indicated if QUIC_SETTINGS.ReliableResetEnabled is TRUE.

### RELIABLE_RESET_NEGOTIATED

Result of reliable reset negotiation is passed in the `RELIABLE_RESET_NEGOTIATED` struct/union.

`IsNegotiated`

If TRUE, reliable reset has been negotiated.

## QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event indicates the result of one way delay negotiation. This is only indicated if QUIC_SETTINGS.OneWayDelayEnabled is TRUE.

### ONE_WAY_DELAY_NEGOTIATED

Details of the one way delay negotiation are passed in the `ONE_WAY_DELAY_NEGOTIATED` struct/union.

`SendNegotiated`

If TRUE, sending one-way delay timestamps has been negotiated.

`ReceiveNegotiated`

If TRUE, receiving one-way delay timestamps has been negotiated.

## QUIC_CONNECTION_EVENT_NETWORK_STATISTICS

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event is only indicated if QUIC_SETTINGS.EnableNetStatsEvent is TRUE. This event indicates the latest network statistics generated during the QUIC protocol handling in the MsQuic library.

### NETWORK_STATISTICS

Detailed networking statistics are passed in the `QUIC_NETWORK_STATISTICS` struct/union.

`BytesInFlight`

Bytes that were sent on the wire, but not yet acked

`PostedBytes`

Total bytes queued, but not yet acked. These may contain sent bytes that may have portentially lost too.

`IdealBytes`

Ideal number of bytes required to be available to avoid limiting throughput.

`SmoothedRTT`

Smoothed RTT value

`CongestionWindow`

Congestion Window

`Bandwidth`

Estimated bandwidth

# QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event indicates the content of an OBSERVED_ADDRESS frame.

## NOTIFY_OBSERVED_ADDRESS
Both Observed address and local address are passed in the `NOTIFY_OBSERVED_ADDRESS` struct/union.

`LocalAddress`

The local IP address.

`ObservedAddress`

The observed IP address.

# QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_ADDED

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event is only indicated if QUIC_SETTINGS.AddAddressMode is MANUAL. This event indicates the content of an ADD_ADDRESS frame.

## NOTIFY_REMOTE_ADDRESS_ADDED
The contents of ADD_ADDRESS frame are passed in the `NOTIFY_REMOTE_ADDRESS_ADDED` struct/union.

`Address`

The new Remote IP address.

`SequenceNumber`

The Sequence Number of the added address.

# QUIC_CONNECTION_EVENT_PATH_VALIDATED

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event is delivered when a path has been validated.

## PATH_VALIDATED
Both the Local IP address and the Remote IP address are  passed in the `PATH_VALIDATED` struct/union.

`LocalAddress`

The Local IP address of a path.

`RemoteAddress`

The Remote IP address of a path.

# QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED

**Preview feature**: This event is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

This event is only indicated if QUIC_SETTINGS.AddAddressMode is MANUAL. This event indicates the content of a REMOVE_ADDRESS frame.

## NOTIFY_REMOTE_ADDRESS_REMOVED
The content of REMOVE_ADDRESS frame is passed in the `NOTIFY_REMOTE_ADDRESS_REMOVED` struct/union.

`SequenceNumber`

The Sequence Number of the removed address.


# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[QUIC_CONNECTION_CALLBACK](QUIC_CONNECTION_CALLBACK.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
[QUIC_CREDENTIAL_CONFIG](QUIC_CREDENTIAL_CONFIG.md)<br>
[Preview Features](../PreviewFeatures.md)<br>
