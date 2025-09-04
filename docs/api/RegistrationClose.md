RegistrationClose function
======

Closes an existing registration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_REGISTRATION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Registration
    );
```

# Parameters

`Registration`

A registration handle from a previous call to [RegistrationOpen](RegistrationOpen.md).

# Remarks

The application **must** close/delete all child configurations and connection objects before closing the registration. This call **will block** on those outstanding objects being cleaned up. Do not call it on any MsQuic event callback or a thread that would otherwise be running an external execution context, or it will deadlock.

# See Also

[RegistrationOpen](RegistrationOpen.md)<br>
(Preview) [RegistrationClose2](RegistrationClose2.md)<br>
