QUIC_LISTENER_EVENT structure
======

The payload for QUIC listener events.

# Syntax

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

`Info`

This field indicates the [QUIC_NEW_CONNECTION_INFO](QUIC_NEW_CONNECTION_INFO.md) structure for the new connection.

`Connection`

This field indicates the valid handle to the new incoming connection.

`NewNegotiatedAlpn`

This field is optional to set. If you want to set, this field **must** indicate a valid address on the ClientAlpnList.
If you do not set this field, server will use `NegotiatedAlpn` in the `QUIC_NEW_CONNECTION_INFO`.
If you set this field, server will use the ALPN in this field.
If you set this field incorrectly, server will **fail** the connection with `QUIC_STATUS_INTERNAL_ERROR`.

### Example Usage of NewNegotiatedAlpn Field

```C
uint8_t NewAlpn[] = "msquic1";
uint8_t NewAlpnLength = sizeof(NewAlpn)/sizeof(*NewAlpn) - 1;
uint16_t AlpnListLength = Event->NEW_CONNECTION.Info->ClientAlpnListLength;
const uint8_t* AlpnList = Event->NEW_CONNECTION.Info->ClientAlpnList;
while (AlpnListLength != 0) {
    if (AlpnList[0] == NewAlpnLength &&
        memcmp(AlpnList+1, NewAlpn, NewAlpnLength) == 0) {
        Event->NEW_CONNECTION.NewNegotiatedAlpn = AlpnList;
        break;
    }
    AlpnListLength -= AlpnList[0] + 1;
    AlpnList += (size_t)AlpnList[0] + (size_t)1;
}
```

## QUIC_LISTENER_EVENT_STOP_COMPLETE

This event is delivered when server app wants to stop receiving new incoming connections.

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
