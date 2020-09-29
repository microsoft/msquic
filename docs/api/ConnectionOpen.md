ConnectionOpen function
======

Creates a new connection.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ HQUIC Configuration,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Connection
    );
```

# Parameters

`Registration`

The valid handle to an open registration object.

`Configuration`

The valid handle to an open configuration object.

`Handler`

A pointer to the app's callback handler to be invoked for all connection events.

`Context`

The app context pointer (possibly null) to be associated with the connection object.

`Connection`

On success, returns a handle to the newly opened connection object.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
