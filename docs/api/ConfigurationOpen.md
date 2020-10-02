ConfigurationOpen function
======

Creates a new configuration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONFIGURATION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_reads_bytes_opt_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _In_ uint32_t SettingsSize,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Configuration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Configuration
    );
```

# Parameters

`Registration`

The valid handle to an open registration object.

**TODO**

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ConfigurationClose](ConfigurationClose.md)<br>
[ConfigurationLoadCredential](ConfigurationLoadCredential.md)<br>
