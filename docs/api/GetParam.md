GetParam function
======

Gets a parameter from an API object.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_GET_PARAM_FN)(
    _When_(QUIC_PARAM_IS_GLOBAL(Param), _Reserved_)
    _When_(!QUIC_PARAM_IS_GLOBAL(Param), _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );
```

# Parameters

`Handle`

The valid handle to any API object. This includes handles to registration, configuration, listener, connection and stream objects. For global parameters, this parameter must be `NULL`.

`Param`

The parameter for which the value is to be set (for example, `QUIC_PARAM_CONN_IDLE_TIMEOUT`).

`BufferLength`

The size, in bytes, of the buffer pointed to by the `Buffer` parameter.

`Buffer`

A pointer to the buffer in which the value for the requested parameter is specified.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

While many parameters are staticly-sized, some are dynamically-sized and will require the application to do a double call to `GetParam`: the first to find out the amount of memory needed to allocate, placed in `BufferLength`, and the second call to actually retrieve the parameter's value.  For example, after setting a `QUIC_VERSION_SETTINGS` on a `QUIC_CONFIGURATION`, retrieving the settings from the same API object will require a double call to allocate enough storage for the `QUIC_VERSION_SETTINGS` lists.

Sample of double-call:
```C
    uint32_t SettingsSize = 0;
    QUIC_VERSION_SETTINGS* Settings = NULL;

    if (QUIC_STATUS_BUFFER_TOO_SMALL ==
        MsQuic->GetParam(
            Configuration,
            QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
            &SettingsSize,
            Settings)) {

        Settings = (QUIC_VERSION_SETTINGS*)malloc(SettingsSize);

        if (QUIC_FAILED(
                MsQuic->GetParam(
                    Configuration,
                    QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS,
                    &SettingsSize,
                    Settings))) {
            // Error.
        }
    }
```

# Special Parameters

## QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES

Returns an array of well-known sizes (in bytes) for each version of the `QUIC_STATISTICS_V2` struct. This allows applications to determine the correct buffer size for statistics queries, even as new versions are added in future MsQuic releases.

> **Note** - Most applications should **not** leverage this and instead directly call to query the `QUIC_STATISTICS_V2`. This API is only necessary for layers on top of MsQuic that need to pass through this information to additional layers on top of them.

- **Type:** `uint32_t[]` (array of struct sizes)
- **Get-only**
- **Variable-length:** The number of sizes returned may change in future versions. The caller should pass a buffer of `uint32_t` and use the double-call pattern to determine the required buffer size.

**Sample usage:**
```c
uint32_t Sizes[8]; // Large enough for future growth
uint32_t BufferLength = sizeof(Sizes);
QUIC_STATUS Status =
    MsQuic->GetParam(
        NULL,
        QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES,
        &BufferLength,
        Sizes);
if (Status == QUIC_STATUS_BUFFER_TOO_SMALL) {
    // BufferLength is set to required size (in bytes)
    // Allocate a larger buffer and call again
}
uint32_t NumSizes = BufferLength / sizeof(uint32_t);
// Sizes[0..NumSizes-1] now contains the struct sizes for each version
```

See also: [Settings.md](../Settings.md#global-parameters)

# See Also

[Settings](../Settings.md#api-object-parameters)<br>
[SetParam](SetParam.md)<br>
