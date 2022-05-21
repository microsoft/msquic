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
        QUIC_CERTIFICATE_PKCS12* CertificatePkcs12;
    };
    const char* Principal;
    void* Reserved; // Currently unused
    QUIC_CREDENTIAL_LOAD_COMPLETE_HANDLER AsyncHandler; // Optional
    QUIC_ALLOWED_CIPHER_SUITE_FLAGS AllowedCipherSuites;// Optional
} QUIC_CREDENTIAL_CONFIG;
```

# Members

#### `Type`

Indicates which type of credential is represented.

`QUIC_CREDENTIAL_TYPE_NONE`

Only valid for clients. No client authentication is provided.

`QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH`

Search the Windows Current User (Local Machine for kernel mode) My certificate store for the certificate thumbprint pointed to by the `CertificateHash` member.
Only valid on Windows with Schannel.

`QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE`

Search the Windows Current User (Local Machine for kernel mode) certificate store for the provided store name and certificate thumbprint pointed to by the `CertificateHashStore` member.
Only valid on Windows with Schannel.

`QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT`

Provide a Windows CAPI `CERTIFICATE_CONTEXT` with the certificate to use in the `CertificateContext` member.
Only valid on Windows in user mode.

`QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE`

Provide file paths to a private key file in PEM format, and a certificate file in PEM or CER format, pointed to by the `CertificateFile` member.
Only valid for OpenSSL.

`QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED`

Provide file paths to a protected private key file, and a certificate file, and a password to unprotect the private key, pointed to by the `CertificateFileProtected` member.
Only valid for OpenSSL.

`QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12`

Provide an in-memory ASN.1 blob of a PKCS12 (PFX) certificate and private, with optional private key password, pointed to by the `CertificatePkcs12` member.
Not currently supported.

#### `Flags`

Any combination of the following flags which change the credential behavior.

`QUIC_CREDENTIAL_FLAG_NONE`

Used with server in default configuration.

`QUIC_CREDENTIAL_FLAG_CLIENT`

Presence of this flag indicates this is a client. Absence indicates server.

`QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS`

Return `QUIC_STATUS_PENDING` immediately from [ConfigurationLoadCredential](ConfigurationLoadCredential.md) and load the credentials asynchronously. Completion is indicated via the `AsyncHandler` callback.

`QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION`

Indicate to the TLS layer that no server certificate validation is to be performed. **THIS IS DANGEROUS; DO NOT USE IN PRODUCTION**

`QUIC_CREDENTIAL_FLAG_ENABLE_OCSP`

Enable OCSP stapling for this connection. Only valid for Schannel.

`QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED`

Receive `QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED` events when a certificate is received from the peer (client or server).

`QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION`

Request the TLS layer perform validation on the received certificate, and provide results to the application via `QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED` events, and allow the application to override failed validation.
Only supported by Schannel. Requires `QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED` to also be set.

`QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION`

Require clients to provide authentication for the handshake to succeed.
Not supported on client.

`QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION`

Use the built-in TLS library's certificate validation instead of the platform's certificate validation.
This is enabled by default on non-Windows systems, and only has effect on Windows when OpenSSL is used.

`QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT`

Only check the leaf certificate for revocation. Only valid on Windows.

`QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN`

Check every certificate in the chain for revocation. Only valid on Windows.

`QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`

Check every certificate in the chain, except the root, for revocation. Only valid on Windows.

`QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK`

Ignore errors from no revocation check being performed. Only valid on Windows.

`QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE`

Ignore revocation offline failures. Only valid on Windows.

`QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES`

Enables which cipher suites are available for negotiation via the `AllowedCipherSuites` member.

`QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES`

Provide the remote X.509 certificate as a DER (binary) blob and entire certificate chain to the application as a PKCS #7 DER blob in the `QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED` event.
Not supported in kernel mode.

`QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS`

Tells the TLS layer (currently only supported by Schannel) to only use the supplied client certificate and not go looking for one on its own if the server asked for a certificate but the client app didn't supply one. More information can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthn/performing-authentication-using-schannel#authenticating-the-client).

`QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER`

Tells the TLS layer (only supported by Schannel server) to use the system credential mapper to map the client-supplied credentials to a user account on the system.

`QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL`

Only use certificates already cached when doing URL retrieval to build a certificate chain. Only valid on Windows.

`QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY`

Only use cached revocation information when checking a certificate chain. Only valid on Windows.

#### `CertificateHash`

Must **only** use with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH` type.

#### `CertificateHashStore`

Must **only** use with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE` type.

#### `CertificateContext`

Must **only** use with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT` type.

#### `CertificateFile`

Must **only** use with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE` type.

#### `CertificateFileProtected`

Must **only** use with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED` type.

#### `CertificatePkcs12`

Must **only** use with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12` type.

#### `Principal`

Principal name string to select certificate by the principal name. Only supported by Schannel.

#### `AsyncHandler`

Optional callback to receive completion of asynchronous credential load. Only used with `QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS` flag.

#### `AllowedCipherSuites`

A set of flags indicating which cipher suites are available to negotiate. Must be used with `QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES`.

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
