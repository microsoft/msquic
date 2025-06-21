QUIC_STATELESS_RETRY_CONFIG structure
======

The structure used to configure the stateless retry feature.

# Syntax

```C
typedef struct QUIC_STATELESS_RETRY_CONFIG {
    QUIC_AEAD_ALGORITHM_TYPE Algorithm;
    uint32_t RotationMs;
    uint32_t SecretLength;
    _Field_size_bytes_(SecretLength)
        const uint8_t* Secret;
} QUIC_STATELESS_RETRY_CONFIG;
```

# Members

`Algorithm`

The AEAD algorithm used for protecting the retry token. Must be one of the following constants:

Constant |  Key Length
---------|------------
**QUIC_AEAD_ALGORITHM_AES_128_GCM**<br> 0 | 16
**QUIC_AEAD_ALGORITHM_AES_256_GCM**<br>1<br> *The default* | 32
**QUIC_AEAD_ALGORITHM_CHACHA20_POLY1305**<br>2 | 32

`RotationMs`

The interval to rotate the retry key. 30,000ms is the default.

`SecretLength`

The length in bytes pointed to by Secret. Must match the key size of the chosen `Algorithm`.

`Secret`

A non-NULL pointer to a buffer containing `SecretLength` bytes of randomness. Used to generate the keys protecting the retry token.

# See Also

[Settings](../Settings.md)<br>