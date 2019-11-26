MsQuicOpen function
======

Opens a new handle to the MsQuic library.

# Syntax

```C
_IRQL_requires_max_(PASSIVE_LEVEL)
_Pre_defensive_
QUIC_STATUS
QUIC_API
MsQuicOpen(
    _In_ uint32_t ApiVersion,
    _Out_ void** QuicApi
    );
```

# Parameters

`ApiVersion`

The version number of the API handle and function table to open.

Value | Meaning
--- | ---
**QUIC_API_VERSION_1**<br>0x00000001 | Version 1 of the MsQuic API.<br>`QuicApi` returns a pointer to a [QUIC_API_V1](../v1/QUIC_API_V1.md) function table.

`QuicApi`

On success, returns a pointer the new version specific function table. The table above explains the mappings between `ApiVersion` to function table.

# Return Value

The function returns a `QUIC_STATUS`. The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function is the entry point for the MsQuic API.

# Helpers

Version specific helpers of this function are included inline:

### MsQuicOpenV1

```C
inline
QUIC_STATUS
QUIC_API
MsQuicOpenV1(
    _Out_ QUIC_API_V1** QuicApi
    )
{
    return MsQuicOpen(QUIC_API_VERSION_1, (void**)QuicApi);
}
```

# See Also

[MsQuicClose](MsQuicClose.md)<br>
[QUIC_API_V1](../v1/QUIC_API_V1.md)<br>
