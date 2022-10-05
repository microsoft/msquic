MsQuicOpenVersion function
======

Opens a new handle to the MsQuic library and returns a version specific API table.

# Syntax

```C
_IRQL_requires_max_(PASSIVE_LEVEL)
_Pre_defensive_
QUIC_STATUS
QUIC_API
MsQuicOpenVersion(
    _In_ uint32_t Version,
    _Out_ const QUIC_API_TABLE** QuicApi
    );
```

# Parameters

`Version`

The API Version to use.

`QuicApi`

On success, returns a pointer to the API function table.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function is the entry point for the MsQuic API. This function may be called multiple times to get multiple new function tables, but this is generally unnecessary. An app should only need call this once. A single `QuicApi` may be shared and safely used by multiple callers on parallel threads.

For every successful call to **MsQuicOpenVersion** the app must call [MsQuicClose](MsQuicClose.md), passing in the function table from *QuicApi* when the app is done with it.

Calls to **MsQuicOpenVersion** and [MsQuicClose](MsQuicClose.md) increment and decrement reference counts on the library. The addition of the first reference count initializes the global state and the removal of the last reference count cleans up the global state. Since both of these operations are not light weight it's **highly recommended** that an app does not open and close very frequently.

**MsQuicOpenVersion** may dynamically load other dependencies, so it **must not** be called from [DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) on Windows.

**MsQuicOpenVersion** takes a version number to indicate which version of the API to use. Newer versions of the library will support older versions of the API for binary compatibility. The **MsQuicOpen2** definition in msquic.h now forwards to **MsQuicOpenVersion**

**MsQuicOpenVersion** and [MsQuicClose](MsQuicClose.md) are not thread-safe if the caller is statically linking MsQuic, and therefore must not be called in parallel.

# See Also

[MsQuicClose](MsQuicClose.md)<br>
[QUIC_API_TABLE](QUIC_API_TABLE.md)<br>
