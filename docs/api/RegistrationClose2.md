RegistrationClose2 function
======

> **Preview**
> This routine is in preview and is subject to breaking changes.

Closes an existing registration asynchronously.

# Syntax

```C
typedef
_Function_class_(QUIC_REGISTRATION_CLOSE_CALLBACK)
void
(QUIC_API QUIC_REGISTRATION_CLOSE_CALLBACK)(
    _In_opt_ void* Context
    );
typedef QUIC_REGISTRATION_CLOSE_CALLBACK *QUIC_REGISTRATION_CLOSE_CALLBACK_HANDLER;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_REGISTRATION_CLOSE2_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Registration,
    _In_ _Pre_defensive_ QUIC_REGISTRATION_CLOSE_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context
    );
```

# Parameters

`Registration`

A registration handle from a previous call to [RegistrationOpen](RegistrationOpen.md).

`Handler`

A registration close completion handler. It will be invoked exactly once upon completion of the registration close request.

`Context`

The context to provide to the close completion handler.

# Remarks

> **Preview**
> This routine is in preview and is subject to breaking changes.

The application should close/delete all child configurations and connection objects before closing the registration. This request **will not complete** until those outstanding objects are cleaned up.

# See Also

[RegistrationOpen](RegistrationOpen.md)<br>
