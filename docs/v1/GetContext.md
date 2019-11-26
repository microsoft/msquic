GetContext function
======

Gets the application context from the API handle.

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

**TODO**

# Return Value

The function returns the application's context.

# Remarks

**TODO**

# See Also

[SetContext](SetContext.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
