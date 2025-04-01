QUIC_STREAM_EVENT structure
======

QUIC stream events and the corresponding payload

# Syntax
```C
typedef enum QUIC_STREAM_EVENT_TYPE {
    QUIC_STREAM_EVENT_START_COMPLETE            = 0,
    QUIC_STREAM_EVENT_RECEIVE                   = 1,
    QUIC_STREAM_EVENT_SEND_COMPLETE             = 2,
    QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN        = 3,
    QUIC_STREAM_EVENT_PEER_SEND_ABORTED         = 4,
    QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED      = 5,
    QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE    = 6,
    QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE         = 7,
    QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE    = 8,
    QUIC_STREAM_EVENT_PEER_ACCEPTED             = 9,
    QUIC_STREAM_EVENT_CANCEL_ON_LOSS            = 10,
} QUIC_STREAM_EVENT_TYPE;
```

The payload for QUIC stream events.

```C
typedef struct QUIC_STREAM_EVENT {
    QUIC_STREAM_EVENT_TYPE Type;
    union {
        struct {
            QUIC_STATUS Status;
            QUIC_UINT62 ID;
            BOOLEAN PeerAccepted : 1;
            BOOLEAN RESERVED : 7;
        } START_COMPLETE;
        struct {
            /* in */    uint64_t AbsoluteOffset;
            /* inout */ uint64_t TotalBufferLength;
            _Field_size_(BufferCount)
            /* in */    const QUIC_BUFFER* Buffers;
            _Field_range_(0, UINT32_MAX)
            /* in */    uint32_t BufferCount;
            /* in */    QUIC_RECEIVE_FLAGS Flags;
        } RECEIVE;
        struct {
            BOOLEAN Canceled;
            void* ClientContext;
        } SEND_COMPLETE;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_SEND_ABORTED;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_RECEIVE_ABORTED;
        struct {
            BOOLEAN Graceful;
        } SEND_SHUTDOWN_COMPLETE;
        struct {
            BOOLEAN ConnectionShutdown;
            BOOLEAN AppCloseInProgress       : 1;
            BOOLEAN ConnectionShutdownByApp  : 1;
            BOOLEAN ConnectionClosedRemotely : 1;
            BOOLEAN RESERVED                 : 5;
            QUIC_UINT62 ConnectionErrorCode;
            QUIC_STATUS ConnectionCloseStatus;
        } SHUTDOWN_COMPLETE;
        struct {
            uint64_t ByteCount;
        } IDEAL_SEND_BUFFER_SIZE;
        struct {
            /* out */ QUIC_UINT62 ErrorCode;
        } CANCEL_ON_LOSS;
    };
} QUIC_STREAM_EVENT;
```

# Parameters

`Type`

The `QUIC_STREAM_EVENT_TYPE` that indicates which type of event this is, and which payload to reference (if any) for additional information.

# Remarks

## QUIC_STREAM_EVENT_START_COMPLETE

This event is delivered when the [StreamStart](streamStart.md) operation completes. The accompanying payload contains data to indicate whether the operation succeeded or failed.

### START_COMPLETE

Additional state from the `StreamStart` operation is included in this payload struct/union.

`Status`

QUIC_STATUS value to indicate the operation completion code. Check for success using the QUIC_SUCCEEDED macro.

`ID`

Stream ID if available.

`PeerAccepted`

If TRUE, the peer has accepted the stream.

## QUIC_STREAM_EVENT_RECEIVE

Data received on an open stream is primarily delivered to the application through this event.

### RECEIVE

Received data on the stream is passed in this struct/union.

`AbsoluteOffset`

Absolute offset of the current data payload from the start of the receive operation.

`TotalBufferLength`

MsQuic indicates the total buffer length of the data in this parameter.

See [Receiving Data On Streams](../Streams.md#Receiving) for further details on receiving data on a stream.

Most notably, if the application...
 - processes all the received data synchronously in this call, this parameter must be left unchanged and  `QUIC_STATUS_SUCCESS` must be returned from this call.
 - can processes only part of the received buffer synchronously in this call, it should be indicated to MsQuic by setting this parameter to the byte count processed and returning `QUIC_STATUS_CONTINUE` from this call.
 - desires to process the received data asynchronously, it should return `QUIC_STATUS_PENDING` from this call.

`Buffers`

An array of `QUIC_BUFFER`s containing received data.

`BufferCount`

Count of `QUIC_BUFFER`s in this payload.

`Flags`

A set of flags indicating describing the received data:

Value | Meaning
--- | ---
**QUIC_RECEIVE_FLAG_NONE**<br>0 | No special behavior.
**QUIC_RECEIVE_FLAG_0_RTT**<br>1 | The data was received in 0-RTT.
**QUIC_RECEIVE_FLAG_FIN**<br>2 | FIN was included with this data. Used only for streamed data.

## QUIC_STREAM_EVENT_SEND_COMPLETE

Indicates that MsQuic has completed a [StreamSend](StreamSend.md) operation initated by the application.

This is an important event in the asynchronous process of sending data over a stream.
More info here:
- [Send Buffering](../Streams.md#Send_Buffering)
- [QUIC_BUFFER Handling Note](StreamSend.md#Remarks)

### SEND_COMPLETE

Data for `StreamSend` completion is included in this struct/union.

`Canceled`
Indicates that the StreamSend operation was canceled.

`ClientContext`
Client context to match this event with the original `StreamSend` operation.

## QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN

Indicates that the current send operation from the peer on this stream has been completed/shutdown.

## QUIC_STREAM_EVENT_PEER_SEND_ABORTED

Indicates that the peer has aborted `StreamSend` operation.

### SEND_ABORTED

Additional details of the send abort event are passed in this struct/union.

`ErrorCode`

Application's protocol specific, 62-bit error code.

## QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED

Indicates that the peer has aborted receiving data.

### RECEIVE_ABORTED

Additional details of the receive abort event are passed in this struct/union.

`ErrorCode`

Application's protocol specific, 62-bit error code.

## QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE

This event is raised when a stream send direction has been fully shut down.

### SEND_SHUTDOWN_COMPLETE

Additional details of send shutdown completion are passed in this struct/union.

`Graceful`

TRUE if the send shutdown operation was gracefully shutdown, FALSE otherwise.

## QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE

This event indicates that the stream has been completely shutdown.

### SHUTDOWN_COMPLETE

Additional details for the stream shutdown are passed in this struct/union.

`ConnectionShutdown`

If TRUE, the Connection corresponding to this stream has been closed locally or remotely.

`AppCloseInProgress`

If TRUE, the application is in the process of closing the stream.

`ConnectionShutdownByApp`

If TRUE, the application shutdown the Connection corresponding to this stream.

`ConnectionClosedRemotely`

If TRUE, the Connection corresponding to this stream has been closed remotely.

`ConnectionErrorCode`

62-bit Connection closure error code, if any.

`ConnectionCloseStatus`

QUIC_STATUS value of the connection close operation, if any.

## QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE

MsQuic indicates the ideal send buffer size to the application through this event, so as not to idle the connection.

### IDEAL_SEND_BUFFER_SIZE

Ideal send buffer size is indicated in this struct/union.

`ByteCount`

Ideal send buffer size in bytes for each `StreamSend` operation to avoid idling the connection.

## QUIC_STREAM_EVENT_PEER_ACCEPTED

This event is raised when a peer has provided sufficient flow control to accept a new stream. See [StreamStart](StreamStart.md) for additional information.

## QUIC_STREAM_EVENT_CANCEL_ON_LOSS

This event is raised when a stream is shutdown due to packet loss. See [Cancel on Loss](../Streams.md#Cancel_On_Loss) for further details.

### CANCEL_ON_LOSS

The application can supply an error code in this struct to be sent to the peer.

`ErrorCode`

The application can set this 62 bit error code to communicate to the peer about the stream shutdown, which is received by the peer as a `QUIC_STREAM_EVENT_PEER_SEND_ABORTED` event on its stream object.

# See Also

[Streams](../Streams.md)<br>
[StreamOpen](StreamOpen.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[QUIC_STREAM_CALLBACK](QUIC_STREAM_CALLBACK.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
