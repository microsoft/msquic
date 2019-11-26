SessionShutdown function
======

Starts the shutdown process for all connections in the session.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_SESSION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );
```

# Parameters

**TODO**

# Remarks

**TODO**

# See Also

[SessionOpen](SessionOpen.md)<br>
[SessionClose](SessionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
