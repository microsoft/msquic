SetContext function
======

Sets the application context for the API handle.

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

**TODO**

# Remarks

**TODO**

# See Also

[GetContext](GetContext.md)<br>
[SetCallbackHandler](SetCallbackHandler.md)<br>
