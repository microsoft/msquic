ListenerStop function
======

Stops listening for incoming connection requests.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_LISTENER_STOP_FN)(
    _In_ _Pre_defensive_ HQUIC Listener
    );
```

# Parameters

**TODO**

# Remarks

**TODO**

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerClose](ListenerClose.md)<br>
[ListenerStart](ListenerStart.md)<br>
