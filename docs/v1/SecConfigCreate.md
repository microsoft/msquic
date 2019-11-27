SecConfigCreate function
======

Asynchronously creates a new security configuration.

# Syntax

```C
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

`Registration`

The valid handle to an open registration object.

`Flags`

The flags that control the type of the structure passed into the *Certificate* parameter.

Value | Meaning
--- | ---
**QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH**<br>0x00000001 | The *Certificate* parameter points to a `QUIC_CERTIFICATE_HASH` struct.
**QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE**<br>0x00000002 | The *Certificate* parameter points to a `QUIC_CERTIFICATE_HASH_STORE` struct.
**QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT**<br>0x00000004 | The *Certificate* parameter points to a `PCCERT_CONTEXT` (Windows specific) struct.
**QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE**<br>0x00000008 | The *Certificate* parameter points to a `QUIC_CERTIFICATE_FILE` struct.
**QUIC_SEC_CONFIG_FLAG_ENABLE_OCSP**<br>0x000000010 | This option can be used in conjunction with the above, and enables the Online Certificate Status Protocol (OCSP).

`Certificate`

A pointer to a certificate configuration struct whos type is determined by the *Flags* field.

`Principal`

An optional pointer, to a null-terminated string that specifies the name of the principal whose credentials the security config will reference.

`Context`

The app context pointer to be passed back into the *CompletionHandler*.

`CompletionHandler`

A pointer to the app's callback handler to be executed when the security config creation has completed.

# Return Value

The function returns a [QUIC_STATUS](../v0/QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[SecConfigDelete](SecConfigDelete.md)<br>
