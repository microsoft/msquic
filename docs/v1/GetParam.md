GetParam function
======

Gets a parameter from an API object.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_GET_PARAM_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );
```

# Parameters

**TODO**

# Return Value

The function returns a `QUIC_STATUS`. The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[SetParam](SetParam.md)<br>
