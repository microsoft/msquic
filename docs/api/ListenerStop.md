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

`Listener`

A valid handle to an open, and started, listener object.

# Remarks

`ListenerStop` is called when the server application wants to stop receiving new incoming connections. It is an asynchronous call. When the stop operation is complete the `QUIC_LISTENER_EVENT_STOP_COMPLETE` event will be delivered to the application. The server may call `ListenerStop` in any callback.

If the server application wishes to resume receiving new connections, it may call [ListenerStart](ListenerStart.md) on the same listener, again.

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerClose](ListenerClose.md)<br>
[ListenerStart](ListenerStart.md)<br>
