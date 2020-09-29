RegistrationShutdown function
======

Starts the shutdown process for all connections in the registration.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_REGISTRATION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );
```

# Parameters

`Registration`

The valid handle to an open registration object.

`Flags`

The flags that control the behavior of the shutdown.

Value | Meaning
--- | ---
**QUIC_CONNECTION_SHUTDOWN_FLAG_NONE**<br>0 | The connection is shutdown gracefully and informs the peer.
**QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT**<br>1 | The connection is immediately shutdown without informing the peer.

`ErrorCode`

The 62-bit error code to indicate to the peer as the reason for the shutdown.

# Remarks

**TODO**

# See Also

[RegistrationOpen](RegistrationOpen.md)<br>
[RegistrationClose](RegistrationClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
