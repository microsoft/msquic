QUIC_LISTENER_CALLBACK function pointer
======

Handles listener events.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_LISTENER_CALLBACK)(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    );
```

# Parameters

`Listener`

The valid handle to the listener object this event is for.

`Context`

The application callback context (optionally) supplied in [ListenerOpen](ListenerOpen.md).

`Event`

A pointer to the [QUIC_LISTENER_EVENT](QUIC_LISTENER_EVENT.md) payload.

# Remarks

This function pointer handles callbacks from MsQuic for listener events. Apps are expected to keep any execution time in the callback **to a minimum**.

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[QUIC_LISTENER_EVENT](QUIC_LISTENER_EVENT.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
