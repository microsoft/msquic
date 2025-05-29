CloseAsync function
======

Asynchronously closes an existing handle to the MsQuic library, releasing the reference on the library and freeing the function table.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API *QUIC_CLOSE_ASYNC_FN)(
    _In_ _Pre_defensive_ const void* QuicApi,
    _In_ QUIC_CLOSE_COMPLETE_HANDLER Handler,
    _In_opt_ void* Context
    );
```

# Parameters

`QuicApi`

The function table from a previous call to [MsQuicOpenVersion](MsQuicOpenVersion.md).

`Handler`

The callback handler to be invoked when the close operation is complete.

`Context`

Optional context pointer to be passed to the Handler when the close operation completes.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

* **QUIC_STATUS_SUCCESS** - The operation completed synchronously. The callback handler will **not** be called.
* **QUIC_STATUS_PENDING** - The operation will complete asynchronously. The callback handler will be called upon completion.
* Any other status code indicates an error.

# Remarks

This function is an asynchronous alternative to [MsQuicClose](MsQuicClose.md). Unlike [MsQuicClose](MsQuicClose.md), this function will not block and instead, if the operation can't complete immediately, registers a callback to be invoked when the cleanup is complete. This avoids deadlocks in single-threaded execution environments.

If the function returns QUIC_STATUS_SUCCESS, the cleanup completed synchronously and the callback will not be invoked. If it returns QUIC_STATUS_PENDING, the callback will be invoked when the cleanup is complete.

This function **must** be called when the app is done with the MsQuic library.

# See Also

[MsQuicOpenVersion](MsQuicOpenVersion.md)<br>
[MsQuicClose](MsQuicClose.md)<br>
