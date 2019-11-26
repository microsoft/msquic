SecConfigCreate function
======

Asynchronously creates a new security configuration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
void
(QUIC_API QUIC_SEC_CONFIG_CREATE_COMPLETE)(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
    );

typedef QUIC_SEC_CONFIG_CREATE_COMPLETE *QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SEC_CONFIG_CREATE_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ _Pre_defensive_
        QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    );
```

# Parameters

**TODO**

# Return Value

The function returns a `QUIC_STATUS`. The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[SecConfigDelete](SecConfigDelete.md)<br>
