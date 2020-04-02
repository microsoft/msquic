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

**TODO**

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
