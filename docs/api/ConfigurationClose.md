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

`ConfigurationClose` is equivalent to `free` and **MUST** be the final call on a configuration handle.
Any API calls using a configuration handle after `ConfigurationClose` has been called is a use-after-free error!

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[ConfigurationLoadCredential](ConfigurationLoadCredential.md)<br>
