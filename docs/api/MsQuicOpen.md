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
    _Out_ const QUIC_API_TABLE** QuicApi
    );
```

# Parameters

`QuicApi`

On success, returns a pointer to the API function table.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function is the entry point for the MsQuic API. This function may be called multiple times to get multiple new function tables, but this is generally unnecessary. An app should only need call this once.

For every successful call to **MsQuicOpen** the app must call [MsQuicClose](MsQuicClose.md), passing in the function table from *QuicApi* when the app is done with it.

Calls to **MsQuicOpen** and [MsQuicClose](MsQuicClose.md) increment and decrement reference counts on the library. The addition of the first reference count initializes the global state and the removal of the last reference count cleans up the global state. Since both of these operations are not light weight it's **highly recommended** that an app does not open and close very frequently.

**MsQuicOpen** may dynamically load other dependencies, so it **must not** be called from [DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) on Windows.

# See Also

[MsQuicClose](MsQuicClose.md)<br>
[QUIC_API_TABLE](QUIC_API_TABLE.md)<br>
