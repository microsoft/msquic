MsQuicClose function
======

Closes an existing handle to the MsQuic library, releasing the reference on the library and freeing the function table.

# Syntax

```C
_IRQL_requires_max_(PASSIVE_LEVEL)
_Pre_defensive_
void
QUIC_API
MsQuicClose(
    _In_ const void* QuicApi
    );
```

# Parameters

`QuicApi`

The function table from a previous call to [MsQuicOpen](MsQuicOpen.md).

# Remarks

This function **must** be called when the app is done with the MsQuic library.

# See Also

[MsQuicOpen](MsQuicOpen.md)<br>
