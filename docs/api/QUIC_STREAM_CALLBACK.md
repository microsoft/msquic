QUIC_STREAM_CALLBACK function pointer signature
======

Handles stream events.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_STREAM_CALLBACK)(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    );
```

# Parameters

`Stream`

The valid handle to the stream object this event is for.

`Context`

The application callback context (optionally) supplied in [StreamOpen](StreamOpen.md), [SetCallbackHandler](SetCallbackHandler.md) or [SetContext](SetContext.md).

`Event`

A pointer to the [QUIC_STREAM_EVENT](QUIC_STREAM_EVENT.md) payload.

# Remarks

This is the signature of the function that handles callbacks from MsQuic for stream events. Apps are expected to keep any execution time in the callback **to a minimum**.

# See Also

[StreamOpen](StreamOpen.md)<br>
[QUIC_STREAM_EVENT](QUIC_STREAM_EVENT.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
[SetContext](SetContext.md)<br>
