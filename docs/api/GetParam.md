GetParam function
======

Gets a parameter from an API object.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_GET_PARAM_FN)(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
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

The size, in bytes, of the buffer pointed to by the `Buffer` parameter.

`Buffer`

A pointer to the buffer in which the value for the requested parameter is specified.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

While many parameters are staticly-sized, some are dynamically-sized and will require the application to do a double call to `GetParam`: the first to find out the amount of memory needed to allocate, placed in `BufferLength`, and the second call to actually retrieve the parameter's value.  For example, after setting a `DesiredVersionsList` on a `QUIC_SETTINGS`, retrieving the settings from the same API object will require a double call to allocate storage for the `DesiredVersionsList`.

Sample of double-call:
```C
    uint32_t SettingsSize = 0;
    QUIC_SETTINGS* Settings = NULL;

    if (QUIC_STATUS_BUFFER_TOO_SMALL ==
        MsQuic->GetParam(
            Configuration,
            QUIC_PARAM_LEVEL_CONFIGURATION,
            QUIC_PARAM_CONFIGURATION_SETTINGS,
            &SettingsSize,
            Settings)) {

        Settings = (QUIC_SETTINGS*)malloc(SettingsSize);

        if (QUIC_FAILED(
                MsQuic->GetParam(
                    Configuration,
                    QUIC_PARAM_LEVEL_CONFIGURATION,
                    QUIC_PARAM_CONFIGURATION_SETTINGS,
                    &SettingsSize,
                    Settings))) {
            // Error.
        }
    }
```

# See Also

[Settings](../Settings.md#api-object-parameters)<br>
[SetParam](SetParam.md)<br>
