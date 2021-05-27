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

A caller should shutdown an active connection via [ConnectionShutdown](ConnectionShutdown.md) before calling `ConnectionClose`; calling `ConnectionClose` without [ConnectionShutdown](ConnectionShutdown.md) will implicitly call [ConnectionShutdown](ConnectionShutdown.md) with the `QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT` flag.

A server application **MUST NOT** call `ConnectionClose` within the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback when returning failure, to reject a connection. This will result in a double-free in release builds, and an assert in debug builds.  It's acceptable to call `ConnectionClose` within the `QUIC_LISTENER_EVENT_NEW_CONNECTION` callback if returning `QUIC_STATUS_SUCCESS`, or `QUIC_STATUS_PENDING`, since the server application owns the connection object then.

`ConnectionClose` is the **last** API call to use a connection handle. An application **MUST NOT** use a connection handle after calling `ConnectionClose`! Any calls using a connection handle after calling `ConnectionClose` is a use-after-free.

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
