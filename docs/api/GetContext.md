GetContext function
======

Gets the application context from the API object.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void*
(QUIC_API * QUIC_GET_CONTEXT_FN)(
    _In_ _Pre_defensive_ HQUIC Handle
    );
```

# Parameters

`Handle`

The valid handle to any API object. This includes handles to registration, configuration, listener, connection and stream objects.

# Return Value

The function returns the previously set application context for the object.

# Remarks

This function allows the app to query the application context it has previously set on the object.

> **Important** There is no internal synchronization for this context. If the app calls **GetContext**, [SetContext](SetContext.md) and/or [SetCallbackHandler](SetCallbackHandler.md) on different threads, it must provide for the necessary synchronization mechanisms.

# See Also

[SetContext](SetContext.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
