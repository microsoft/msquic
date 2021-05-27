ConnectionShutdown function
======

Starts the shutdown process on a connection.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_CONNECTION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

`Flags`

The flags that control the behavior of the shutdown.

Value | Meaning
--- | ---
**QUIC_CONNECTION_SHUTDOWN_FLAG_NONE**<br>0 | The connection is shutdown gracefully and informs the peer.
**QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT**<br>1 | The connection is immediately shutdown without informing the peer.

`ErrorCode`

The 62-bit error code to indicate to the peer as the reason for the shutdown.

# Remarks

A client or server application may call `ConnectionShutdown` on any connections that have successfully called `ConnectionStart` to shut down the connection.

`ConnectionShutdown` implicitly shuts down any streams that have not already shutdown, but it does not send stop_sending or reset_stream frames for them individually, and only sends a connection_close frame. Stream shutdown events are always delivered to the application for the streams which were implicitly shutdown.

`ConnectionShutdown` is guaranteed to work in low-memory scenarios, though it may be unable to inform the peer if it cannot allocate memory for the final packet containing the connection_close frame.

Using the `QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT` flag instructs MsQuic to tear down the local connection state, but because the peer is not informed, packets may still arrive from the peer until connection idle timeout. These packets are ignored locally, however they may still show up in packet captures.

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
