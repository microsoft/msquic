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

Constant |  Key Length (bytes)
---------|------------
**QUIC_AEAD_ALGORITHM_AES_128_GCM**<br> 0 | 16
**QUIC_AEAD_ALGORITHM_AES_256_GCM**<br>1<br> *The default* | 32

`RotationMs`

The interval to rotate the retry key. 30,000ms is the default. A token is valid for twice this interval. Zero is not allowed.

`SecretLength`

The length in bytes pointed to by Secret. Must match the key length of the chosen `Algorithm`.

`Secret`

A non-NULL pointer to a buffer containing `SecretLength` bytes of randomness. Used to generate the keys protecting the retry token.

# Remarks

`RotationMs` should be kept to a short interval, less than a minute, as retry tokens are returned immediately by clients.
Changing `RotationMs`, `Algorithm`, or `Secret` will invalidate all retry tokens issued prior to the change.
All servers deployed in a cluster and sharing the secret must have their clocks synchronized within `RotationMs` of UTC.
A server whose clock is ahead of UTC may produce a retry token that other servers in that deployment are unable to validate.

## Stateless Retry key Generation Algorithm

The stateless retry key is generated from the above configuration parameters using the [SP800-108 rev. 1 CTR-HMAC KDF](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) algorithm with SHA256.
Where:

*K_in* is the `Secret` provided above.

*Label* is the string "QUIC Stateless Retry Key" without the terminating NULL character.

*Context* is the UNIX epoch timestamp in milliseconds, divided by `RotationMs`, as an 8-byte signed integer in little-endian format.

*L* is the same as the key length for the `Algorithm`.


# See Also

[Settings](../Settings.md)<br>
