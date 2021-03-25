ConfigurationClose function
======

Deletes an existing security configuration.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_CONFIGURATION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Configuration
    );
```

# Parameters

`Configuration`

The valid handle to an open configuration object.

# Remarks

This function releases the configuration object.

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[ConfigurationLoadCredential](ConfigurationLoadCredential.md)<br>
