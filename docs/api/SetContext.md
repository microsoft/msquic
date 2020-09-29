SetContext function
======

Sets the application context for the API object.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_SET_CONTEXT_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ void* Context
    );
```

# Parameters

`Handle`

The valid handle to any API object. This includes handles to registration, configuration, listener, connection and stream objects.

`Context`

A new application context to register with the API object.

# Remarks

This function allows the app to set the application context for the API object. This context can be later retrieved by a call to [GetContext](GetContext.md). It is also passed into all callback handler events for the object.

> **Important** There is no internal synchronization for this context. If the app calls [GetContext](GetContext.md), **SetContext** and/or [SetCallbackHandler](SetCallbackHandler.md) on different threads, it must provide for the necessary synchronization mechanisms.

# See Also

[GetContext](GetContext.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
