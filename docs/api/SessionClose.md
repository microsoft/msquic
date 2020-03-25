SessionClose function
======

Closes an existing session.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_SESSION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Session
    );
```

# Parameters

`Session`

The valid handle to an open session object.

# Remarks

**TODO**

# See Also

[SessionOpen](SessionOpen.md)<br>
[SessionShutdown](SessionShutdown.md)<br>
