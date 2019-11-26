ConnectionOpen function
======

Creates a new connection.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Connection
    );
```

# Parameters

**TODO**

# Return Value

The function returns a `QUIC_STATUS`. The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
