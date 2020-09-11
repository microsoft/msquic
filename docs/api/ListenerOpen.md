ListenerOpen function
======

Creates a new listener.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Listener, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Listener
    );
```

# Parameters

**TODO**

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ListenerClose](ListenerClose.md)<br>
[ListenerStart](ListenerStart.md)<br>
[ListenerStop](ListenerStop.md)<br>
