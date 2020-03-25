SetCallbackHandler function
======

Sets the application context and callback function pointer for the API object.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_SET_CALLBACK_HANDLER_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ void* Handler,
    _In_opt_ void* Context
    );
```

# Parameters

`Handle`

The valid handle to any API object that uses callback handlers. This includes handles to listener, connection and stream objects.

`Handler`

A new application callback handler to register with the API object.

`Context`

A new application context to register with the API object.

# Remarks

This function allows the app to set the application callback handler and context for the API object. The context can be later retrieved by a call to [GetContext](GetContext.md). It is also passed into all callback handler events for the object.

> **Important** There is no internal synchronization for this callback handler or context. If the app calls [GetContext](GetContext.md), [SetContext](SetContext.md) and/or **SetCallbackHandler** on different threads, it must provide for the necessary synchronization mechanisms.

# See Also

[GetContext](GetContext.md)<br>
[SetContext](SetContext.md)<br>
