QUIC_LISTENER_EVENT structure
======

QUIC listener events and the corresponding payload

# Syntax

```C
typedef enum QUIC_LISTENER_EVENT_TYPE {
    QUIC_LISTENER_EVENT_NEW_CONNECTION      = 0,
    QUIC_LISTENER_EVENT_STOP_COMPLETE       = 1,
    QUIC_LISTENER_EVENT_DOS_MODE_CHANGED    = 2,
} QUIC_LISTENER_EVENT_TYPE;
```

The payload for QUIC listener events.

```C
typedef struct QUIC_LISTENER_EVENT {
    QUIC_LISTENER_EVENT_TYPE Type;
    union {
        struct {
            const QUIC_NEW_CONNECTION_INFO* Info;
            HQUIC Connection;
            const uint8_t* NewNegotiatedAlpn;
        } NEW_CONNECTION;
        struct {
            BOOLEAN AppCloseInProgress  : 1;
            BOOLEAN RESERVED            : 7;
        } STOP_COMPLETE;
    };
} QUIC_LISTENER_EVENT;
```

# Parameters

`Type`

The `QUIC_LISTENER_EVENT_TYPE` that indicates which type of event this is, and which payload to reference (if any) for additional information.

# Remarks

## QUIC_LISTENER_EVENT_NEW_CONNECTION

This event is delivered when a new connection is received by the listener.

### NEW_CONNECTION

Details of the new connection are passed in the `NEW_CONNECTION` struct/union.

`Info`

This field indicates the [QUIC_NEW_CONNECTION_INFO](QUIC_NEW_CONNECTION_INFO.md) structure for the new connection.

`Connection`

This field indicates the valid handle to the new incoming connection.

## QUIC_LISTENER_EVENT_STOP_COMPLETE

This event is delivered when server app wants to stop receiving new incoming connections.

### STOP_COMPLETE

Details of the listener stopping are indicated in `STOP_COMPLETE` struct/union.

`AppCloseInProgress`

This flag indicates the server has called [ListenerClose](ListenerClose.md).

`RESERVED`

This field reserved for future use. Do not use.

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerStop](ListenerStop.md)<br>
[QUIC_LISTENER_CALLBACK](QUIC_LISTENER_CALLBACK.md)<br>
[QUIC_NEW_CONNECTION_INFO](QUIC_NEW_CONNECTION_INFO.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
