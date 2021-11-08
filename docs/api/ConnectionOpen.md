ConnectionOpen function
======

Creates a new connection.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Connection
    );
```

# Parameters

`Registration`

The valid handle to an open registration object.

`Handler`

A pointer to the app's callback handler to be invoked for all connection events.

`Context`

The app context pointer (possibly null) to be associated with the connection object.

`Connection`

On success, returns a handle to the newly opened connection object.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

`ConnectionOpen` is used to create a connection in the client application. In server applications, [ListenerOpen](ListenerOpen.md) and [ListenerStart](ListenerStart.md) must be called to listen for incoming connection attempts, and the server side Connection is created in the `QUIC_LISTENER_EVENT_NEW_CONNECTION` event.

'ConnectionOpen' only allocates the resources for the connection, it does not start the connection. To start the connect, the application must call [ConnectionStart](ConnectionStart.md).

Once `ConnectionOpen` completes successfully, the application may create streams, and queue data for sending. This is when 0-RTT streams and data **MUST** be created and queued. See [StreamOpen](StreamOpen.md), and [StreamStart](StreamStart.md).

Once the connection has been shutdown, it must be cleaned up with a call to [ConnectionClose](ConnectionClose.md).

# See Also

[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
[QUIC_CONNECTION_CALLBACK](QUIC_CONNECTION_CALLBACK.md)<br>
[QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md)<br>
