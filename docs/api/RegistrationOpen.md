RegistrationOpen function
======

Creates a new registration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_REGISTRATION_OPEN_FN)(
    _In_opt_ const QUIC_REGISTRATION_CONFIG* Config,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    );
```

# Parameters

`Config`

An optional configuration for the registration.

`Registration`

On success, returns a handle the the newly created registration.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[RegistrationClose](RegistrationClose.md)<br>
