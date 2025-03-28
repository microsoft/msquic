QUIC_STREAM_EVENT structure
======

The payload for QUIC connection events.

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

### START_COMPLETE

`Status`

`ID`

`PeerAccepted`

## QUIC_STREAM_EVENT_RECEIVE

### RECEIVE

`AbsoluteOffset`

`TotalBufferLength`

`Buffers`

`BufferCount`

`Flags`


## QUIC_STREAM_EVENT_SEND_COMPLETE

### SEND_COMPLETE

`Canceled`

`ClientContext`

## QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN


## QUIC_STREAM_EVENT_PEER_SEND_ABORTED

### SEND_ABORTED

`ErrorCode`

## QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED

### RECEIVE_ABORTED

`ErrorCode`


## QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE

### SEND_SHUTDOWN_COMPLETE

`Graceful`


## QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE

### SHUTDOWN_COMPLETE

`ConnectionShutdown`

`AppCloseInProgress`

`ConnectionShutdownByApp`

`ConnectionClosedRemotely`

`ConnectionErrorCode`

`ConnectionCloseStatus`

## QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE

### IDEAL_SEND_BUFFER_SIZE

`ByteCount`

## QUIC_STREAM_EVENT_PEER_ACCEPTED


## QUIC_STREAM_EVENT_CANCEL_ON_LOSS

### CANCEL_ON_LOSS
`ErrorCode`


# See Also

[StreamOpen](StreamOpen.md)<br>
[QUIC_STREAM_CALLBACK](QUIC_STREAM_CALLBACK.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
