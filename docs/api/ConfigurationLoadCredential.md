ConfigurationLoadCredential function
======

Deletes an existing configuration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN)(
    _In_ _Pre_defensive_ HQUIC Configuration,
    _In_ _Pre_defensive_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    );
```

# Parameters

**TODO**

# Remarks

**TODO**

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[ConfigurationClose](ConfigurationClose.md)<br>
