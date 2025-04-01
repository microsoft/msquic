QUIC_CONNECTION_CALLBACK function pointer
======

Handles connection events.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_CONNECTION_CALLBACK)(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    );
```

# Parameters

`Connection`

The valid handle to the connection object this event is for.

`Context`

The application callback context (optionally) supplied in [ConnectionOpen](ConnectionOpen.md), [SetCallbackHandler](SetCallbackHandler.md) or [SetContext](SetContext.md).

`Event`

A pointer to the [QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md) payload.

# Remarks

This function pointer handles callbacks from MsQuic for connection events. Apps are expected to keep any execution time in the callback **to a minimum**.

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
