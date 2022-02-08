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

`Listener`

A valid handle to an open listener object.

# Remarks

`ListenerClose` frees all allocated resources associated with the listener handle. If a listener has not had [ListenerStop](ListenerStop.md) called on it at the time `ListenerClose` is called, [ListenerStop](ListenerStop.md) is invoked internally. A server application **MUST NOT** call `ListenerClose` within any callback except for `QUIC_LISTENER_EVENT_STOP_COMPLETE`, unless it has already received the `QUIC_LISTENER_EVENT_STOP_COMPLETE` event.

`ListenerClose` is equivalent to `free` and **MUST** be the final call on a listener handle. Any API calls using a listener handle after `ListenerClose` has been called is a use-after-free error!

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerStart](ListenerStart.md)<br>
[ListenerStop](ListenerStop.md)<br>
