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

`AlpnBuffers`

An array of `QUIC_BUFFER` structs that each contain a pointer and length to a different [Application Layer Protocol Negotiation](https://www.rfc-editor.org/rfc/rfc7301) (ALPN) buffer.

`AlpnBufferCount`

The number of `QUIC_BUFFER` structs in the `AlpnBuffers` array.

`Settings`

An optional pointer to a [QUIC_SETTINGS](QUIC_SETTINGS.md) struct that defines the initial parameters for this configuration.

`SettingSize`

The size (in bytes) of the `Settings` parameter. 

`Context`

The application context pointer (possibly null) to be associated with the configuration object.

`Configuration`

On success, returns a handle to the newly opened configuration object.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

On success, `ConfigurationOpen` creates a new configuration object. A configuration object abstracts all connection settings and security configuration.

Once the configuration is loaded (via [ConfigurationLoadCredential](ConfigurationLoadCredential.md)) it can be used for a connection; [ConnectionStart](ConnectionStart.md) on client; [ConnectionSetConfiguration](ConnectionSetConfiguration.md) on server.

The configuration must be cleaned up via [ConfigurationClose](ConfigurationClose.md) when the application is done with it.

# See Also

[ConfigurationClose](ConfigurationClose.md)<br>
[ConfigurationLoadCredential](ConfigurationLoadCredential.md)<br>
[ConnectionSetConfiguration](ConnectionSetConfiguration.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
