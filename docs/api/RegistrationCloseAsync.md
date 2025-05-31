RegistrationCloseAsync function
======

Asynchronously closes an existing registration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_REGISTRATION_CLOSE_ASYNC_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Registration,
    _In_ QUIC_COMPLETE_HANDLER Handler,
    _In_opt_ void* Context
    );
```

# Parameters

`Registration`

A registration handle from a previous call to [RegistrationOpen](RegistrationOpen.md).

`Handler`

The callback handler to be invoked when the registration close operation is complete.

`Context`

Optional context pointer to be passed to the Handler when the close operation completes.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

* **QUIC_STATUS_SUCCESS** - The operation completed synchronously. The callback handler will **not** be called.
* **QUIC_STATUS_PENDING** - The operation will complete asynchronously. The callback handler will be called upon completion.
* Any other status code indicates an error.

# Remarks

Unlike [RegistrationClose](RegistrationClose.md), this function will not block waiting for child objects to be cleaned up. Instead, if the operation can't complete immediately, it registers a callback to be invoked when the cleanup is complete. This avoids deadlocks in single-threaded execution environments.

If the function returns QUIC_STATUS_SUCCESS, the cleanup completed synchronously and the callback will not be invoked. If it returns QUIC_STATUS_PENDING, the callback will be invoked when the cleanup is complete.

The application **must** close/delete all child configurations and connection objects before closing the registration. This call will trigger the provided callback when those outstanding objects are cleaned up, only if the function returns QUIC_STATUS_PENDING.

It is safe to call this function from any MsQuic event callback, as it will not deadlock.

# See Also

[RegistrationOpen](RegistrationOpen.md)<br>
[RegistrationClose](RegistrationClose.md)<br>
