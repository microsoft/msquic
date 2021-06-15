SetParam function
======

Sets a parameter on an API object.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SET_PARAM_FN)(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );
```

# Parameters

`Handle`

The valid handle to any API object. This includes handles to registration, configuration, listener, connection and stream objects. For `Level` equal to `QUIC_PARAM_LEVEL_GLOBAL`, this parameter must be `NULL`.

`Level`

The level at which the parameter is defined (for example, `QUIC_PARAM_LEVEL_CONNECTION`).

`Param`

The parameter for which the value is to be set (for example, `QUIC_PARAM_CONN_IDLE_TIMEOUT`). The `Param` parameter must be a parameter defined within the specified `Level`, or behavior is undefined.

`BufferLength`

A pointer to the size, in bytes, of the `Buffer` buffer.

`Buffer`

A pointer to the buffer in which the value for the requested option is to be returned.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[Settings](../Settings.md#api-object-parameters)<br>
[GetParam](GetParam.md)<br>
