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

**TODO**

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
