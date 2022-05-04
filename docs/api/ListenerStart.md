ListenerStart function
======

Starts listening for incoming connection requests.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_START_FN)(
    _In_ _Pre_defensive_ HQUIC Listener,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ const QUIC_ADDR* LocalAddress
    );
```

# Parameters

`Listener`

A valid handle to an open listener object.

`AlpnBuffers`

An array of `QUIC_BUFFER` structs that each contain a pointer and length to a different [Application Layer Protocol Negotiation](https://tools.ietf.org/html/rfc7301) (ALPN) buffer, in order of preference, to be negotiated by the incoming connections.

`AlpnBufferCount`

The number of `QUIC_BUFFER` structs in `AlpnBuffers`.

`LocalAddress`

Optional pointer to a `QUIC_ADDR` to indicate the address and/or port to listen for connections on. May be `NULL` to let the networking stack choose.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

`ListenerStart` starts listening for incoming connections and callbacks on the listener may begin before the function call returns. Connection attempts that are received are indicated via `QUIC_LISTENER_EVENT_NEW_CONNECTION` event to the server application. The server application indicates acceptance of the connection attempt by calling [SetCallbackHandler](SetCallbackHandler.md) on the connection object, and returning `QUIC_STATUS_SUCCESS` from the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback. The server application must call [ConnectionSetConfiguration](ConnectionSetConfiguration.md) on the connection, either before returning from the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback, or on its own after returning from the callback, otherwise the connection handshake will stall and timeout.

After returning `QUIC_STATUS_SUCCESS` from the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback, the server application owns the connection object and must eventually call [ConnectionClose](ConnectionClose.md) on it, otherwise a memory leak will occur.

The server application **MUST NOT** call [ConnectionClose](ConnectionClose.md) within the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback when returning failure, to reject a connection. This will result in a double-free in release builds, and an assert in debug builds.  It's acceptable to call [ConnectionClose](ConnectionClose.md) within the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback if returning `QUIC_STATUS_SUCCESS`, or `QUIC_STATUS_PENDING`, since the server application owns the connection object then.

ALPNs specified in `AlpnBuffers` must be less than 255 bytes in length.

The server application may set any combination of local address and/or port number in the `QUIC_ADDR` pointed to by `LocalAddress`. If no port number is given, then the networking stack will choose an available port number, which can be queried by [GetParam](GetParam.md) with `QUIC_PARAM_LISTENER_LOCAL_ADDRESS`.

MsQuic listens on dual-mode wildcard sockets for each unique port number, and performs address filtering, if necessary, within the QUIC layer.

Due to the use of per processor sockets for performance reasons, 2 distinct processes listening on the same port will not result in the 2nd instance failing to start. The behavior in this case is undefined, and different per platform, but will result in each app not getting the receives it expects. There is potential for a future workaround for this on Windows, but no currently known solution on Posix-based platforms. This quirk does not apply if a process using UDP without MsQuic is already bound to the port, as long as that process is not using per processor sockets.

On Posix-based platforms, 2 distinct processes using wildcard port numbers can potentially receive the same port number, resulting in the above behavior. This behavior does not exist on Windows.

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerClose](ListenerClose.md)<br>
[ListenerStop](ListenerStop.md)<br>
