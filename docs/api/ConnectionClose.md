ConnectionClose function
======

Closes an existing connection.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_CONNECTION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Connection
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

# Remarks

`ConnectionClose` cleans up and frees all resources allocated for the connection in `ConnectionOpen`.

A caller should shutdown an active connection via [ConnectionShutdown](ConnectionShutdown.md) before calling
`ConnectionClose`. Calling `ConnectionClose` without [ConnectionShutdown](ConnectionShutdown.md) will abortively and
silently shutdown the connection as well as all associated streams through an implicit call to
[ConnectionShutdown](ConnectionShutdown.md) with the `QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT` flag.

A server application **MUST NOT** call `ConnectionClose` within the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback when returning failure, to reject a connection. This will result in a double-free in release builds, and an assert in debug builds.  It's acceptable to call `ConnectionClose` within the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback if returning `QUIC_STATUS_SUCCESS`, or `QUIC_STATUS_PENDING`, since the server application owns the connection object then.

`ConnectionClose` is equivalent to `free` and **MUST** be the final call on a connection handle.
Any API calls using a connection handle after `ConnectionClose` has been called is a use-after-free error!

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
