CloseAsync function
======

Asynchronously closes an existing handle to the MsQuic library, releasing the reference on the library and freeing the function table.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API *QUIC_CLOSE_ASYNC_FN)(
    _In_ QUIC_COMPLETE_HANDLER Handler,
    _In_opt_ void* Context
    );
```

# Parameters

`Handler`

The callback handler to be invoked when the close operation is complete.

`Context`

Optional context pointer to be passed to the Handler when the close operation completes.

# Remarks

This function is an asynchronous alternative to [MsQuicClose](MsQuicClose.md). Unlike [MsQuicClose](MsQuicClose.md), this function will not block and instead, registers a callback to be invoked when the cleanup is complete. This avoids deadlocks in single-threaded execution environments.

This function (or [MsQuicClose](MsQuicClose.md)) **must** be called when the app is done with the MsQuic library.

# See Also

[MsQuicOpenVersion](MsQuicOpenVersion.md)<br>
[MsQuicClose](MsQuicClose.md)<br>
