ListenerOpen function
======

Creates a new listener.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ _Pre_defensive_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Listener, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Listener
    );
```

# Parameters

`Registration`

The valid handle to an open registration object.

`Handler`

A pointer to the app's callback handler to be invoked for all listener events.

`Context`

The app context pointer (possibly null) to be associated with the listener object.

`Listener`

On success, returns a handle to the newly opened listener object.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

`ListenerOpen` is used to allocate resources for a server application to listen for QUIC connections. The server doesn't start listening for connection attempts until [ListenerStart](ListenerStart.md) is successfully called. For a client application, [ConnectionOpen](ConnectionOpen.md) is called to create a new connection, and [ConnectionStart](ConnectionStart.md) to start that new connection.

The application may call [ListenerStart](ListenerStart.md) and [ListenerStop](ListenerStop.md) multiple times over the lifetime of a listener object, if it needs to start and stop listening for connections. Most server applications will call [ListenerStart](ListenerStart.md) once at start up, and then [ListenerStop](ListenerStop.md) at shutdown.

Every listener created with a call to `ListenerOpen` **MUST** be cleaned up with a call to [ListenerClose](ListenerClose.md), otherwise a memory leak will occur. 

# See Also

[ListenerClose](ListenerClose.md)<br>
[ListenerStart](ListenerStart.md)<br>
[ListenerStop](ListenerStop.md)<br>
