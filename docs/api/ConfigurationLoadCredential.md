ConfigurationLoadCredential function
======

Loads the specified credential configuration for the configuration object.

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

`Configuration`

The valid handle to an open configuration object.

`CredConfig`

The [QUIC_CREDENTIAL_CONFIG](QUIC_CREDENTIAL_CONFIG.md) that describes the security configuration to load for the configuration.

# Remarks

This function loads the security configuration and credentials for the configuration. Depending on the `Flags` field in the `CredConfig` (and platform support) the load may be synchronous or asynchronous. If asynchronous, completion is indicated via a callback to the `AsyncHandler` set on the `CredConfig`.

Once the configuration has been successfully loaded, it can be used for a connection; [ConnectionStart](ConnectionStart.md) on client; [ConnectionSetConfiguration](ConnectionSetConfiguration.md) on server.

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[ConfigurationClose](ConfigurationClose.md)<br>
