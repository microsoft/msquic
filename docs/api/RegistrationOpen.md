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

An optional [QUIC_REGISTRATION_CONFIG](QUIC_REGISTRATION_CONFIG.md) to specify how to configure the execution context of the registration.

`Registration`

On success, returns a handle to the newly created registration.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

A registration represents an execution context for the application. This consists of one or more system threads that are used to process the protocol logic for the application's connections. Each execution context is completely independent from another. This allows for different applications in the same process (or kernel space) to execute generally independent.

A caveat to this independence is that until a packet or connection can be determined to belong to a particular registration there is shared processing.

# See Also

[RegistrationClose](RegistrationClose.md)<br>
