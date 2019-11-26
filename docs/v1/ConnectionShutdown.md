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

**TODO**

# Remarks

**TODO**

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
