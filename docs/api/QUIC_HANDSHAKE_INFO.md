QUIC_HANDSHAKE_INFO structure
======

Used to return the various algorithms negotiated during the TLS handshake.

# Syntax

```C
typedef struct QUIC_HANDSHAKE_INFO {
    QUIC_TLS_PROTOCOL_VERSION TlsProtocolVersion;
    QUIC_CIPHER_ALGORITHM CipherAlgorithm;
    int32_t CipherStrength;
    QUIC_HASH_ALGORITHM Hash;
    int32_t HashStrength;
    QUIC_KEY_EXCHANGE_ALGORITHM KeyExchangeAlgorithm;
    int32_t KeyExchangeStrength;
    QUIC_CIPHER_SUITE CipherSuite;
    QUIC_TLS_GROUP TlsGroup;            // Added in v2.5
} QUIC_HANDSHAKE_INFO;
```

# Members

#### `TlsProtocolVersion`

Indicates which version of TLS was negotiated.

`QUIC_TLS_PROTOCOL_UNKNOWN`

An unknown or unexpected value was used.

`QUIC_TLS_PROTOCOL_1_3`

Version 1.3 was negotiated. This is currently the only expected value to be returned.

#### `CipherAlgorithm`

The `QUIC_CIPHER_ALGORITHM` negotiated.

#### `CipherStrength`

TODO

#### `Hash`

The `QUIC_HASH_ALGORITHM` negotiated.

#### `HashStrength`

TODO

#### `KeyExchangeAlgorithm`

The `QUIC_KEY_EXCHANGE_ALGORITHM` negotiated.

#### `KeyExchangeStrength`

TODO

#### `CipherSuite`

The `QUIC_CIPHER_SUITE` negotiated.

#### `TlsGroup`

The `QUIC_TLS_GROUP` negotiated.

> **Note** - This field is not supported before MsQuic version v2.5. Calls to older versions of MsQuic will indicate a final output length not including this field. Additionally, older callers that use the old version of the struct will still work, and MsQuic will not try to write this field.

# Remarks

This may be queries for a connection after the handshake has completed via a call to [GetParam](GetParam.md) by using the `QUIC_PARAM_TLS_HANDSHAKE_INFO` parameter.

# See Also

[GetParam](GetParam.md)<br>
