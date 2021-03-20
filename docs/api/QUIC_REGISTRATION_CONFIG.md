QUIC_REGISTRATION_CONFIG structure
======

The structure used to configure the execution context of a application registration.

# Syntax

```C
typedef struct QUIC_REGISTRATION_CONFIG {
    const char* AppName;
    QUIC_EXECUTION_PROFILE ExecutionProfile;
} QUIC_REGISTRATION_CONFIG;
```

# Members

`AppName`

An optional (may be `NULL`), null-terminated string describing the application that created the registration. This field is primarily used for debugging purposes.

`ExecutionProfile`

Provides a hint to MsQuic on how to optimize its thread scheduling operations.

**Value** | **Meaning**
------ | ------
**QUIC_EXECUTION_PROFILE_LOW_LATENCY**<br>0 | Indicates that scheduling should be generally optimized for reducing response latency. *The default execution profile.*
**QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT**<br>1 | Indicates that scheduling should be optimized for maximum single connection throughput.
**QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER**<br>2 | Indicates that minimal responsiveness is required by the scheduling logic. For instance, a background transfer or process.
**QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME**<br>3 | Indicates responsiveness is of paramount importance to the scheduler.

# See Also

[RegistrationOpen](RegistrationOpen.md)<br>
