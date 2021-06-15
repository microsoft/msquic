ConnectionSetConfiguration function
======

Sets the (server-side) configuration handle for the connection. This must be called on an accepted connection in order to proceed with the QUIC handshake.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_SET_CONFIGURATION_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ _Pre_defensive_ HQUIC Configuration
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

`Configuration`

The valid handle to an open and loaded configuration object.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

`ConnectionSetConfiguration` can be called in the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback, or outside of it if the connection was accepted. It's generally recommended to call `ConnectionSetConfiguration` in the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback unless the server application needs to do asynchronous processing to decide which configuration to use on a connection.

# See Also

[ConnectionOpen](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
