QUIC_CREDENTIAL_CONFIG structure
======

The description for the security configuration to load for a configuration object.

# Syntax

```C
typedef struct QUIC_CREDENTIAL_CONFIG {
    QUIC_CREDENTIAL_TYPE Type;
    QUIC_CREDENTIAL_FLAGS Flags;
    union {
        QUIC_CERTIFICATE_HASH* CertificateHash;
        QUIC_CERTIFICATE_HASH_STORE* CertificateHashStore;
        QUIC_CERTIFICATE* CertificateContext;
        QUIC_CERTIFICATE_FILE* CertificateFile;
        QUIC_CERTIFICATE_FILE_PROTECTED* CertificateFileProtected;
    };
    const char* Principal;
    void* Reserved; // Currently unused
    QUIC_CREDENTIAL_LOAD_COMPLETE_HANDLER AsyncHandler; // Optional
} QUIC_CREDENTIAL_CONFIG;
```

# Members

`Type`

TODO

`Flags`

TODO

`CertificateHash`

TODO

`CertificateHashStore`

TODO

`CertificateContext`

TODO

`CertificateFile`

TODO

`CertificateFileProtected`

TODO

`Principal`

TODO

`AsyncHandler`

TODO

# Remarks

TODO

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CREDENTIAL_LOAD_COMPLETE)
void
(QUIC_API QUIC_CREDENTIAL_LOAD_COMPLETE)(
    _In_ HQUIC Configuration,
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status
    );

typedef QUIC_CREDENTIAL_LOAD_COMPLETE *QUIC_CREDENTIAL_LOAD_COMPLETE_HANDLER;

typedef struct QUIC_CERTIFICATE_HASH {
    uint8_t ShaHash[20];
} QUIC_CERTIFICATE_HASH;

typedef struct QUIC_CERTIFICATE_HASH_STORE {
    QUIC_CERTIFICATE_HASH_STORE_FLAGS Flags;
    uint8_t ShaHash[20];
    char StoreName[128];
} QUIC_CERTIFICATE_HASH_STORE;

typedef struct QUIC_CERTIFICATE_FILE {
    const char *PrivateKeyFile;
    const char *CertificateFile;
} QUIC_CERTIFICATE_FILE;

typedef struct QUIC_CERTIFICATE_FILE_PROTECTED {
    const char *PrivateKeyFile;
    const char *CertificateFile;
    const char *PrivateKeyPassword;
} QUIC_CERTIFICATE_FILE_PROTECTED;

typedef void QUIC_CERTIFICATE; // Platform specific certificate context object
```

# See Also

[ConfigurationLoadCredential](ConfigurationLoadCredential.md)<br>
