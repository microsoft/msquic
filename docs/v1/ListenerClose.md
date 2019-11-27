ListenerClose function
======

Closes an existing listener.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_LISTENER_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Listener
    );
```

# Parameters

**TODO**

# Remarks

**TODO**

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerStart](ListenerStart.md)<br>
[ListenerStop](ListenerStop.md)<br>
