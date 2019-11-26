RegistrationOpen function
======

Creates a new registration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_REGISTRATION_OPEN_FN)(
    _In_opt_z_ _Pre_defensive_ const char* AppName,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    );
```

# Parameters

`AppName`

An optional name for the application layer, used purely for debugging purposes.

`Registration`

On success, returns a handle the the newly created registration.

# Return Value

The function returns a `QUIC_STATUS`. The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[RegistrationClose](RegistrationClose.md)<br>
