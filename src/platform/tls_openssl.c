/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling OpenSSL.

--*/

#include "platform_internal.h"

#define OPENSSL_SUPPRESS_DEPRECATED 1 // For hmac.h, which was deprecated in 3.0
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#ifdef QUIC_CLOG
#include "tls_openssl.c.clog.h"
#endif

uint16_t CxPlatTlsTPHeaderSize = 0;

//
// The QUIC sec config object. Created once per listener on server side and
// once per connection on client side.
//

typedef struct CXPLAT_SEC_CONFIG {

    //
    // The SSL context associated with the sec config.
    //
    SSL_CTX *SSLCtx;

    //
    // Callbacks for TLS.
    //
    CXPLAT_TLS_CALLBACKS Callbacks;

} CXPLAT_SEC_CONFIG;

//
// A TLS context associated per connection.
//

typedef struct CXPLAT_TLS {

    //
    // The TLS configuration information and credentials.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // Indicates if this context belongs to server side or client side
    // connection.
    //
    BOOLEAN IsServer;

    //
    // The TLS extension type for the QUIC transport parameters.
    //
    uint16_t QuicTpExtType;

    //
    // The ALPN buffer.
    //
    uint16_t AlpnBufferLength;
    const uint8_t* AlpnBuffer;

    //
    // On client side stores a NULL terminated SNI.
    //
    const char* SNI;

    //
    // Ssl - A SSL object associated with the connection.
    //
    SSL *Ssl;

    //
    // State - The TLS state associated with the connection.
    // ResultFlags - Stores the result of the TLS data processing operation.
    //

    CXPLAT_TLS_PROCESS_STATE* State;
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    //
    // Callback context and handler for QUIC TP.
    //
    QUIC_CONNECTION* Connection;

#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    //
    // Optional struct to log TLS traffic secrets.
    // Only non-null when the connection is configured to log these.
    //
    CXPLAT_TLS_SECRETS* TlsSecrets;
#endif

} CXPLAT_TLS;

typedef struct CXPLAT_HP_KEY {
    EVP_CIPHER_CTX* CipherCtx;
    CXPLAT_AEAD_TYPE Aead;
} CXPLAT_HP_KEY;

//
// Default list of Cipher used.
//
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS    "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"

//
// Default list of curves for ECDHE ciphers.
//
#define CXPLAT_TLS_DEFAULT_SSL_CURVES     "P-256:X25519:P-384:P-521"

//
// Default cert verify depth.
//
#define CXPLAT_TLS_DEFAULT_VERIFY_DEPTH  10

//
// Hack to set trusted cert file on client side.
//
char *QuicOpenSslClientTrustedCert = NULL;

QUIC_STATUS
CxPlatTlsLibraryInitialize(
    void
    )
{
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "OPENSSL_init_ssl failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    //
    // OPENSSL_init_ssl() may leave errors in the error queue while returning
    // success.
    //

    ERR_clear_error();

    //
    // LINUX_TODO:Add Check for openssl library QUIC support.
    //

    return QUIC_STATUS_SUCCESS;
}

void
CxPlatTlsLibraryUninitialize(
    void
    )
{
}

static
int
CxPlatTlsAlpnSelectCallback(
    _In_ SSL *Ssl,
    _Out_writes_bytes_(Outlen) const unsigned char **Out,
    _Out_ unsigned char *OutLen,
    _In_reads_bytes_(Inlen) const unsigned char *In,
    _In_ unsigned int InLen,
    _In_ void *Arg
    )
{
    UNREFERENCED_PARAMETER(In);
    UNREFERENCED_PARAMETER(InLen);
    UNREFERENCED_PARAMETER(Arg);

    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    //
    // QUIC already parsed and picked the ALPN to use and set it in the
    // NegotiatedAlpn variable.
    //

    CXPLAT_DBG_ASSERT(TlsContext->State->NegotiatedAlpn != NULL);
    *OutLen = TlsContext->State->NegotiatedAlpn[0];
    *Out = TlsContext->State->NegotiatedAlpn + 1;

    return SSL_TLSEXT_ERR_OK;
}

CXPLAT_STATIC_ASSERT((int)ssl_encryption_initial == (int)QUIC_PACKET_KEY_INITIAL, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)ssl_encryption_early_data == (int)QUIC_PACKET_KEY_0_RTT, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)ssl_encryption_handshake == (int)QUIC_PACKET_KEY_HANDSHAKE, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)ssl_encryption_application == (int)QUIC_PACKET_KEY_1_RTT, "Code assumes exact match!");

void
CxPlatTlsNegotiatedCiphers(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ CXPLAT_AEAD_TYPE *AeadType,
    _Out_ CXPLAT_HASH_TYPE *HashType
    )
{
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(TlsContext->Ssl))) {
    case 0x03001301U: // TLS_AES_128_GCM_SHA256
        *AeadType = CXPLAT_AEAD_AES_128_GCM;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    case 0x03001302U: // TLS_AES_256_GCM_SHA384
        *AeadType = CXPLAT_AEAD_AES_256_GCM;
        *HashType = CXPLAT_HASH_SHA384;
        break;
    case 0x03001303U: // TLS_CHACHA20_POLY1305_SHA256
        *AeadType = CXPLAT_AEAD_CHACHA20_POLY1305;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
    }
}

int
CxPlatTlsSetEncryptionSecretsCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(SecretLen) const uint8_t* ReadSecret,
    _In_reads_(SecretLen) const uint8_t* WriteSecret,
    _In_ size_t SecretLen
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;
    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    QUIC_STATUS Status;

    QuicTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        Level);

    CXPLAT_SECRET Secret;
    CxPlatTlsNegotiatedCiphers(TlsContext, &Secret.Aead, &Secret.Hash);
    CxPlatCopyMemory(Secret.Secret, WriteSecret, SecretLen);

    CXPLAT_DBG_ASSERT(TlsState->WriteKeys[KeyType] == NULL);
    Status =
        QuicPacketKeyDerive(
            KeyType,
            &Secret,
            "write secret",
            TRUE,
            &TlsState->WriteKeys[KeyType]);
    if (QUIC_FAILED(Status)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    TlsState->WriteKey = KeyType;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
    CxPlatCopyMemory(Secret.Secret, ReadSecret, SecretLen);

    CXPLAT_DBG_ASSERT(TlsState->ReadKeys[KeyType] == NULL);
    Status =
        QuicPacketKeyDerive(
            KeyType,
            &Secret,
            "read secret",
            TRUE,
            &TlsState->ReadKeys[KeyType]);
    if (QUIC_FAILED(Status)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_1_RTT) {
        //
        // The 1-RTT read keys aren't actually allowed to be used until the
        // handshake completes.
        //
    } else {
        TlsState->ReadKey = KeyType;
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
    }
#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    if (TlsContext->TlsSecrets != NULL) {
        TlsContext->TlsSecrets->SecretLength = (uint8_t)SecretLen;
        switch (KeyType) {
        case QUIC_PACKET_KEY_HANDSHAKE:
            if (TlsContext->IsServer) {
                memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret, ReadSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret, WriteSecret, SecretLen);
            } else {
                memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret, WriteSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret, ReadSecret, SecretLen);
            }
            TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
            TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
            break;
        case QUIC_PACKET_KEY_1_RTT:
            if (TlsContext->IsServer) {
                memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0, ReadSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0, WriteSecret, SecretLen);
            } else {
                memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0, WriteSecret, SecretLen);
                memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0, ReadSecret, SecretLen);
            }
            TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
            TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
            //
            // We're done with the TlsSecrets.
            //
            TlsContext->TlsSecrets = NULL;
            break;
        case QUIC_PACKET_KEY_0_RTT:
            if (!TlsContext->IsServer) {
                memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret, WriteSecret, SecretLen);
                TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
            }
            break;
        default:
            break;
        }
    }
#endif

    return 1;
}

int
CxPlatTlsAddHandshakeDataCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(Length) const uint8_t *Data,
    _In_ size_t Length
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;

    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    CXPLAT_DBG_ASSERT(KeyType == 0 || TlsState->WriteKeys[KeyType] != NULL);

    QuicTraceLogConnVerbose(
        OpenSslAddHandshakeData,
        TlsContext->Connection,
        "Sending %llu handshake bytes (Level = %u)",
        (uint64_t)Length,
        Level);

    if (Length + TlsState->BufferLength > 0xF000) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Too much handshake data");
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    if (Length + TlsState->BufferLength > (size_t)TlsState->BufferAllocLength) {
        //
        // Double the allocated buffer length until there's enough room for the
        // new data.
        //
        uint16_t NewBufferAllocLength = TlsState->BufferAllocLength;
        while (Length + TlsState->BufferLength > (size_t)NewBufferAllocLength) {
            NewBufferAllocLength <<= 1;
        }

        uint8_t* NewBuffer = CXPLAT_ALLOC_NONPAGED(NewBufferAllocLength, QUIC_POOL_TLS_BUFFER);
        if (NewBuffer == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto buffer",
                NewBufferAllocLength);
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        CxPlatCopyMemory(
            NewBuffer,
            TlsState->Buffer,
            TlsState->BufferLength);
        CXPLAT_FREE(TlsState->Buffer, QUIC_POOL_TLS_BUFFER);
        TlsState->Buffer = NewBuffer;
        TlsState->BufferAllocLength = NewBufferAllocLength;
    }

    switch (KeyType) {
    case QUIC_PACKET_KEY_HANDSHAKE:
        if (TlsState->BufferOffsetHandshake == 0) {
            TlsState->BufferOffsetHandshake = TlsState->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                TlsState->BufferOffsetHandshake);
        }
        break;
    case QUIC_PACKET_KEY_1_RTT:
        if (TlsState->BufferOffset1Rtt == 0) {
            TlsState->BufferOffset1Rtt = TlsState->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                TlsState->BufferOffset1Rtt);
        }
        break;
    default:
        break;
    }

    CxPlatCopyMemory(
        TlsState->Buffer + TlsState->BufferLength,
        Data,
        Length);
    TlsState->BufferLength += (uint16_t)Length;
    TlsState->BufferTotalLength += (uint16_t)Length;

    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_DATA;

    return 1;
}

int
CxPlatTlsFlushFlightCallback(
    _In_ SSL *Ssl
    )
{
    UNREFERENCED_PARAMETER(Ssl);
    return 1;
}

int
CxPlatTlsSendAlertCallback(
    _In_ SSL *Ssl,
    _In_ enum ssl_encryption_level_t Level,
    _In_ uint8_t Alert
    )
{
    UNREFERENCED_PARAMETER(Level);

    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        Level);

    TlsContext->State->AlertCode = Alert;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;

    return 1;
}

int
CxPlatTlsClientHelloCallback(
    _In_ SSL *Ssl,
    _Out_opt_ int *Alert,
    _In_ void *arg
    )
{
    UNREFERENCED_PARAMETER(arg);
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    const uint8_t* TransportParams;
    size_t TransportParamLen;

    if (!SSL_client_hello_get0_ext(
            Ssl,
            TlsContext->QuicTpExtType,
            &TransportParams,
            &TransportParamLen)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        *Alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

SSL_QUIC_METHOD OpenSslQuicCallbacks = {
    CxPlatTlsSetEncryptionSecretsCallback,
    CxPlatTlsAddHandshakeDataCallback,
    CxPlatTlsFlushFlightCallback,
    CxPlatTlsSendAlertCallback
};

QUIC_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_FILE, PrivateKeyFile) == FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED, PrivateKeyFile),
    "Mismatch (private key) in certificate file structs");

QUIC_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_FILE, CertificateFile) == FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED, CertificateFile),
    "Mismatch (certificate file) in certificate file structs");

QUIC_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_HASH, ShaHash) == FIELD_OFFSET(QUIC_CERTIFICATE_HASH_EXPLICIT_PRIVATE_KEY, ShaHash),
    "Mismatch (sha hash) in certificate hash structs");

QUIC_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_HASH_STORE, Flags) == FIELD_OFFSET(QUIC_CERTIFICATE_HASH_STORE_EXPLICIT_PRIVATE_KEY, Flags),
    "Mismatch (flags) in certificate hash store structs");

QUIC_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_HASH_STORE, ShaHash) == FIELD_OFFSET(QUIC_CERTIFICATE_HASH_STORE_EXPLICIT_PRIVATE_KEY, ShaHash),
    "Mismatch (sha hash) in certificate hash store structs");

QUIC_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_HASH_STORE, StoreName) == FIELD_OFFSET(QUIC_CERTIFICATE_HASH_STORE_EXPLICIT_PRIVATE_KEY, StoreName),
    "Mismatch (store name) in certificate hash store structs");

QUIC_STATUS
CxPlatTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ RSA** EvpPrivateKey,
    _Out_ X509** X509Cert);

QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not supported by this TLS implementation
    }

    if (CredConfig->TicketKey != NULL) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not currently supported
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
            return QUIC_STATUS_NOT_SUPPORTED; // Not supported for client (yet)
        }
    } else {
        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_NONE) {
            return QUIC_STATUS_INVALID_PARAMETER; // Required for server
        }

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            if (CredConfig->CertificateFile == NULL ||
                CredConfig->CertificateFile->CertificateFile == NULL ||
                CredConfig->CertificateFile->PrivateKeyFile == NULL) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            if (CredConfig->CertificateFileProtected == NULL ||
                CredConfig->CertificateFileProtected->CertificateFile == NULL ||
                CredConfig->CertificateFileProtected->PrivateKeyFile == NULL ||
                CredConfig->CertificateFileProtected->PrivateKeyPassword == NULL) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_EXPLICIT_PRIVATE_KEY ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE_EXPLICIT_PRIVATE_KEY) {
#ifndef _WIN32
            return QUIC_STATUS_NOT_SUPPORTED; // Only supported on windows.
#endif
            // Windows parameters checked later
        } else {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    CXPLAT_SEC_CONFIG* SecurityConfig = NULL;
    RSA* RsaKey = NULL;
    X509* X509Cert = NULL;

    //
    // Create a security config.
    //

    SecurityConfig = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    SecurityConfig->Callbacks = *TlsCallbacks;

    //
    // Create the a SSL context for the security config.
    //

    SecurityConfig->SSLCtx = SSL_CTX_new(TLS_method());
    if (SecurityConfig->SSLCtx == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    //
    // Configure the SSL context with the defaults.
    //

    Ret = SSL_CTX_set_min_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_min_proto_version failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_max_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_max_proto_version failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set_ciphersuites(
            SecurityConfig->SSLCtx,
            CXPLAT_TLS_DEFAULT_SSL_CIPHERS);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_ciphersuites failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_default_verify_paths failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set1_groups_list(
            SecurityConfig->SSLCtx,
            CXPLAT_TLS_DEFAULT_SSL_CURVES);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set1_groups_list failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_quic_method(SecurityConfig->SSLCtx, &OpenSslQuicCallbacks);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_quic_method failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        BOOLEAN VerifyServerCertificate = TRUE; // !(Flags & QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION);
        if (!VerifyServerCertificate) { // cppcheck-suppress knownConditionTrueFalse
            SSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER, NULL);
        } else {
            SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);

            if (QuicOpenSslClientTrustedCert != NULL) {
                //
                // LINUX_TODO: This is a hack to set a client side trusted cert in order
                //   to verify server cert. Fix this once MsQuic formally supports
                //   passing TLS related config from APP layer to TAL.
                //

                /*Ret =
                    SSL_CTX_load_verify_locations(
                        SecurityConfig->SSLCtx,
                        QuicOpenSslClientTrustedCert,
                        NULL);
                if (Ret != 1) {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        ERR_get_error(),
                        "SSL_CTX_load_verify_locations failed");
                    Status = QUIC_STATUS_TLS_ERROR;
                    goto Exit;
                }*/
            }
        }
    } else {
        SSL_CTX_set_options(
            SecurityConfig->SSLCtx,
            (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_CIPHER_SERVER_PREFERENCE |
            SSL_OP_NO_ANTI_REPLAY);
        SSL_CTX_clear_options(SecurityConfig->SSLCtx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        SSL_CTX_set_mode(SecurityConfig->SSLCtx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx, CxPlatTlsAlpnSelectCallback, NULL);

        //
        // Set the server certs.
        //

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            SSL_CTX_set_default_passwd_cb_userdata(
                SecurityConfig->SSLCtx, (void*)CredConfig->CertificateFileProtected->PrivateKeyPassword);
        }

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            Ret =
                SSL_CTX_use_PrivateKey_file(
                    SecurityConfig->SSLCtx,
                    CredConfig->CertificateFile->PrivateKeyFile,
                    SSL_FILETYPE_PEM);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_use_PrivateKey_file failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            Ret =
                SSL_CTX_use_certificate_chain_file(
                    SecurityConfig->SSLCtx,
                    CredConfig->CertificateFile->CertificateFile);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_use_certificate_chain_file failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            Status =
                CxPlatTlsExtractPrivateKey(
                    CredConfig,
                    &RsaKey,
                    &X509Cert);
            if (QUIC_FAILED(Status)) {
                goto Exit;
            }

            Ret =
                SSL_CTX_use_RSAPrivateKey(
                    SecurityConfig->SSLCtx,
                    RsaKey);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_use_RSAPrivateKey_file failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            Ret =
                SSL_CTX_use_certificate(
                    SecurityConfig->SSLCtx,
                    X509Cert);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_use_certificate failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

        Ret = SSL_CTX_check_private_key(SecurityConfig->SSLCtx);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_check_private_key failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, UINT32_MAX);
        SSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx, CxPlatTlsClientHelloCallback, NULL);
    }

    //
    // Invoke completion inline.
    //

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

Exit:

    if (SecurityConfig != NULL) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    if (X509Cert != NULL) {
        X509_free(X509Cert);
    }

    if (RsaKey != NULL) {
        RSA_free(RsaKey);
    }

    return Status;
}

void
CxPlatTlsSecConfigDelete(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->SSLCtx != NULL) {
        SSL_CTX_free(SecurityConfig->SSLCtx);
        SecurityConfig->SSLCtx = NULL;
    }

    CXPLAT_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}

QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_TLS* TlsContext = NULL;
    uint16_t ServerNameLength = 0;

    TlsContext = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_TLS), QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
#ifdef CXPLAT_TLS_SECRETS_SUPPORT
    TlsContext->TlsSecrets = Config->TlsSecrets;
#endif

    QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

            ServerNameLength = (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI = CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_TLS_SNI);
            if (TlsContext->SNI == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "SNI",
                    ServerNameLength + 1);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }

            memcpy((char*)TlsContext->SNI, Config->ServerName, ServerNameLength + 1);
        }
    }

    //
    // Create a SSL object for the connection.
    //

    TlsContext->Ssl = SSL_new(Config->SecConfig->SSLCtx);
    if (TlsContext->Ssl == NULL) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SSL_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    if (Config->IsServer) {
        SSL_set_accept_state(TlsContext->Ssl);
        //SSL_set_quic_early_data_enabled(TlsContext->Ssl, 1);
    } else {
        SSL_set_connect_state(TlsContext->Ssl);
        SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
        SSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);
    }

    SSL_set_quic_use_legacy_codepoint(
        TlsContext->Ssl,
        TlsContext->QuicTpExtType == TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS_DRAFT);

    if (SSL_set_quic_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SSL_set_quic_transport_params failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
    CXPLAT_FREE(Config->LocalTPBuffer, QUIC_POOL_TLS_TRANSPARAMS);

    State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_UNSUPPORTED; // 0-RTT not currently supported.

    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:

    if (TlsContext != NULL) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = NULL;
    }

    return Status;
}

void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        if (TlsContext->SNI != NULL) {
            CXPLAT_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
            TlsContext->SNI = NULL;
        }

        if (TlsContext->Ssl != NULL) {
            SSL_free(TlsContext->Ssl);
            TlsContext->Ssl = NULL;
        }

        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength) const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    int Ret = 0;
    int Err = 0;

    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        TlsContext->ResultFlags = CXPLAT_TLS_RESULT_ERROR;

        QuicTraceLogConnVerbose(
            OpenSsslIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
        goto Exit;
    }

    if (*BufferLength != 0) {
        QuicTraceLogConnVerbose(
            OpenSslProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
    }

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (SSL_provide_quic_data(
            TlsContext->Ssl,
            (OSSL_ENCRYPTION_LEVEL)TlsContext->State->ReadKey,
            Buffer,
            *BufferLength) != 1) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        goto Exit;
    }

    if (!State->HandshakeComplete) {
        Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret <= 0) {
            Err = SSL_get_error(TlsContext->Ssl, Ret);
            switch (Err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                goto Exit;

            case SSL_ERROR_SSL:
                QuicTraceLogConnError(
                    OpenSslHandshakeErrorStr,
                    TlsContext->Connection,
                    "TLS handshake error: %s",
                    ERR_error_string(ERR_get_error(), NULL));
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;

            default:
                QuicTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        if (!TlsContext->IsServer) {
            const uint8_t* NegotiatedAlpn;
            uint32_t NegotiatedAlpnLength;
            SSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn, &NegotiatedAlpnLength);
            if (NegotiatedAlpnLength == 0) {
                QuicTraceLogConnError(
                    OpenSslAlpnNegotiationFailure,
                    TlsContext->Connection,
                    "Failed to negotiate ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (NegotiatedAlpnLength > UINT8_MAX) {
                QuicTraceLogConnError(
                    OpenSslInvalidAlpnLength,
                    TlsContext->Connection,
                    "Invalid negotiated ALPN length");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            TlsContext->State->NegotiatedAlpn =
                CxPlatTlsAlpnFindInList(
                    TlsContext->AlpnBufferLength,
                    TlsContext->AlpnBuffer,
                    (uint8_t)NegotiatedAlpnLength,
                    NegotiatedAlpn);
            if (TlsContext->State->NegotiatedAlpn == NULL) {
                QuicTraceLogConnError(
                    OpenSslNoMatchingAlpn,
                    TlsContext->Connection,
                    "Failed to find a matching ALPN");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "Handshake complete");
        State->HandshakeComplete = TRUE;
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_COMPLETE;

        if (TlsContext->IsServer) {
            TlsContext->State->ReadKey = QUIC_PACKET_KEY_1_RTT;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
        } else {
            const uint8_t* TransportParams;
            size_t TransportParamLen;
            SSL_get_peer_quic_transport_params(
                    TlsContext->Ssl, &TransportParams, &TransportParamLen);
            if (TransportParams == NULL || TransportParamLen == 0) {
                QuicTraceLogConnError(
                    OpenSslMissingTransportParameters,
                    TlsContext->Connection,
                    "No transport parameters received");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                    TlsContext->Connection,
                    (uint16_t)TransportParamLen,
                    TransportParams)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        }
    }

    Ret = SSL_do_handshake(TlsContext->Ssl);
    if (Ret != 1) {
        Err = SSL_get_error(TlsContext->Ssl, Ret);
        switch (Err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            goto Exit;

        case SSL_ERROR_SSL:
            QuicTraceLogConnError(
                OpenSslHandshakeErrorStr,
                TlsContext->Connection,
                "TLS handshake error: %s",
                ERR_error_string(ERR_get_error(), NULL));
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;

        default:
            QuicTraceLogConnError(
                OpenSslHandshakeError,
                TlsContext->Connection,
                "TLS handshake error: %d",
                Err);
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

Exit:

    if (!(TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR)) {
        if (State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] != NULL &&
            State->BufferOffsetHandshake == 0) {
            State->BufferOffsetHandshake = State->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                State->BufferOffsetHandshake);
        }
        if (State->WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL &&
            State->BufferOffset1Rtt == 0) {
            State->BufferOffset1Rtt = State->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                State->BufferOffset1Rtt);
        }
    }

    return TlsContext->ResultFlags;
}

CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessDataComplete(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ uint32_t * ConsumedBuffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(ConsumedBuffer);
    return CXPLAT_TLS_RESULT_ERROR;
}

QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

//
// Crypto / Key Functionality
//

#ifdef DEBUG
void
CxPlatTlsLogSecret(
    _In_z_ const char* const Prefix,
    _In_reads_(Length)
        const uint8_t* const Secret,
    _In_ uint32_t Length
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    char SecretStr[256 + 1] = {0};
    CXPLAT_DBG_ASSERT(Length * 2 < sizeof(SecretStr));
    for (uint32_t i = 0; i < Length; i++) {
        SecretStr[i*2]     = HEX_TO_CHAR(Secret[i] >> 4);
        SecretStr[i*2 + 1] = HEX_TO_CHAR(Secret[i] & 0xf);
    }
    QuicTraceLogVerbose(
        OpenSslLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
}
#else
#define CxPlatTlsLogSecret(Prefix, Secret, Length) UNREFERENCED_PARAMETER(Prefix);
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t HashLength,
    _Out_writes_all_(5 + CXPLAT_HKDF_PREFIX_LEN + strlen(Label))
        uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    CXPLAT_DBG_ASSERT(strlen(Label) <= UINT8_MAX - CXPLAT_HKDF_PREFIX_LEN);
    uint8_t LabelLength = (uint8_t)strlen(Label);

    Data[0] = HashLength >> 8;
    Data[1] = HashLength & 0xff;
    Data[2] = CXPLAT_HKDF_PREFIX_LEN + LabelLength;
    memcpy(Data + 3, CXPLAT_HKDF_PREFIX, CXPLAT_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + CXPLAT_HKDF_PREFIX_LEN, Label, LabelLength);
    Data[3 + CXPLAT_HKDF_PREFIX_LEN + LabelLength] = 0;
    *DataLength = 3 + CXPLAT_HKDF_PREFIX_LEN + LabelLength + 1;

    Data[*DataLength] = 0x1;
    *DataLength += 1;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHkdfExpandLabel(
    _In_ CXPLAT_HASH* Hash,
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLength,
    _In_ uint32_t OutputLength, // Writes CxPlatHashLength(HashType) bytes.
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    uint8_t LabelBuffer[64];
    uint32_t LabelLength = sizeof(LabelBuffer);

    _Analysis_assume_(strlen(Label) <= 23);
    CxPlatHkdfFormatLabel(Label, KeyLength, LabelBuffer, &LabelLength);

    return
        CxPlatHashCompute(
            Hash,
            LabelBuffer,
            LabelLength,
            OutputLength,
            Output);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatTlsDeriveInitialSecrets(
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _In_ uint8_t CIDLength,
    _Out_ CXPLAT_SECRET *ClientInitial,
    _Out_ CXPLAT_SECRET *ServerInitial
    )
{
    QUIC_STATUS Status;
    CXPLAT_HASH* InitialHash = NULL;
    CXPLAT_HASH* DerivedHash = NULL;
    uint8_t InitialSecret[CXPLAT_HASH_SHA256_SIZE];

    CxPlatTlsLogSecret("init cid", CID, CIDLength);

    Status =
        CxPlatHashCreate(
            CXPLAT_HASH_SHA256,
            Salt,
            CXPLAT_VERSION_SALT_LENGTH,
            &InitialHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Extract secret for client and server secret expansion.
    //
    Status =
        CxPlatHashCompute(
            InitialHash,
            CID,
            CIDLength,
            sizeof(InitialSecret),
            InitialSecret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatTlsLogSecret("init secret", InitialSecret, sizeof(InitialSecret));

    //
    // Create hash for client and server secret expansion.
    //
    Status =
        CxPlatHashCreate(
            CXPLAT_HASH_SHA256,
            InitialSecret,
            sizeof(InitialSecret),
            &DerivedHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand client secret.
    //
    ClientInitial->Hash = CXPLAT_HASH_SHA256;
    ClientInitial->Aead = CXPLAT_AEAD_AES_128_GCM;
    Status =
        CxPlatHkdfExpandLabel(
            DerivedHash,
            "client in",
            sizeof(InitialSecret),
            CXPLAT_HASH_SHA256_SIZE,
            ClientInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand server secret.
    //
    ServerInitial->Hash = CXPLAT_HASH_SHA256;
    ServerInitial->Aead = CXPLAT_AEAD_AES_128_GCM;
    Status =
        CxPlatHkdfExpandLabel(
            DerivedHash,
            "server in",
            sizeof(InitialSecret),
            CXPLAT_HASH_SHA256_SIZE,
            ServerInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    CxPlatHashFree(InitialHash);
    CxPlatHashFree(DerivedHash);

    CxPlatSecureZeroMemory(InitialSecret, sizeof(InitialSecret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const CXPLAT_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    )
{
    const uint16_t SecretLength = CxPlatHashLength(Secret->Hash);
    const uint16_t KeyLength = CxPlatKeyLength(Secret->Aead);

    CXPLAT_DBG_ASSERT(SecretLength >= KeyLength);
    CXPLAT_DBG_ASSERT(SecretLength >= CXPLAT_IV_LENGTH);
    CXPLAT_DBG_ASSERT(SecretLength <= CXPLAT_HASH_MAX_SIZE);

    CxPlatTlsLogSecret(SecretName, Secret->Secret, SecretLength);

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(CXPLAT_SECRET) : 0);
    QUIC_PACKET_KEY *Key = CXPLAT_ALLOC_NONPAGED(PacketKeyLength, QUIC_POOL_TLS_PACKETKEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    CXPLAT_HASH* Hash = NULL;
    uint8_t Temp[CXPLAT_HASH_MAX_SIZE];

    QUIC_STATUS Status =
        CxPlatHashCreate(
            Secret->Hash,
            Secret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic iv",
            CXPLAT_IV_LENGTH,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    memcpy(Key->Iv, Temp, CXPLAT_IV_LENGTH);
    CxPlatTlsLogSecret("static iv", Key->Iv, CXPLAT_IV_LENGTH);

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic key",
            KeyLength,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatTlsLogSecret("key", Temp, KeyLength);

    Status =
        CxPlatKeyCreate(
            Secret->Aead,
            Temp,
            &Key->PacketKey);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            CxPlatHkdfExpandLabel(
                Hash,
                "quic hp",
                KeyLength,
                SecretLength,
                Temp);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        CxPlatTlsLogSecret("hp", Temp, KeyLength);

        Status =
            CxPlatHpKeyCreate(
                Secret->Aead,
                Temp,
                &Key->HeaderKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        CxPlatCopyMemory(Key->TrafficSecret, Secret, sizeof(CXPLAT_SECRET));
    }

    *NewKey = Key;
    Key = NULL;

Error:

    QuicPacketKeyFree(Key);
    CxPlatHashFree(Hash);

    CxPlatSecureZeroMemory(Temp, sizeof(Temp));

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(NewReadKey != NULL, _At_(*NewReadKey, __drv_allocatesMem(Mem)))
_When_(NewWriteKey != NULL, _At_(*NewWriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** NewReadKey,
    _Out_opt_ QUIC_PACKET_KEY** NewWriteKey
    )
{
    QUIC_STATUS Status;
    CXPLAT_SECRET ClientInitial, ServerInitial;
    QUIC_PACKET_KEY* ReadKey = NULL, *WriteKey = NULL;

    Status =
        CxPlatTlsDeriveInitialSecrets(
            Salt,
            CID,
            CIDLength,
            &ClientInitial,
            &ServerInitial);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (NewWriteKey != NULL) {
        Status =
            QuicPacketKeyDerive(
                QUIC_PACKET_KEY_INITIAL,
                IsServer ? &ServerInitial : &ClientInitial,
                IsServer ? "srv secret" : "cli secret",
                TRUE,
                &WriteKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewReadKey != NULL) {
        Status =
            QuicPacketKeyDerive(
                QUIC_PACKET_KEY_INITIAL,
                IsServer ? &ClientInitial : &ServerInitial,
                IsServer ? "cli secret" : "srv secret",
                TRUE,
                &ReadKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewWriteKey != NULL) {
        *NewWriteKey = WriteKey;
        WriteKey = NULL;
    }

    if (NewReadKey != NULL) {
        *NewReadKey = ReadKey;
        ReadKey = NULL;
    }

Error:

    QuicPacketKeyFree(ReadKey);
    QuicPacketKeyFree(WriteKey);

    CxPlatSecureZeroMemory(ClientInitial.Secret, sizeof(ClientInitial.Secret));
    CxPlatSecureZeroMemory(ServerInitial.Secret, sizeof(ServerInitial.Secret));

    return Status;
}

void
QuicPacketKeyFree(
    _In_opt_ QUIC_PACKET_KEY* Key
    )
{
    if (Key != NULL) {
        CxPlatKeyFree(Key->PacketKey);
        CxPlatHpKeyFree(Key->HeaderKey);
        if (Key->Type >= QUIC_PACKET_KEY_1_RTT) {
            CxPlatSecureZeroMemory(Key->TrafficSecret, sizeof(CXPLAT_SECRET));
        }
        CXPLAT_FREE(Key, QUIC_POOL_TLS_PACKETKEY);
    }
}

QUIC_STATUS
QuicPacketKeyUpdate(
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    )
{
    if (OldKey->Type != QUIC_PACKET_KEY_1_RTT) {
        return QUIC_STATUS_INVALID_STATE;
    }

    CXPLAT_HASH* Hash = NULL;
    CXPLAT_SECRET NewTrafficSecret;
    const uint16_t SecretLength = CxPlatHashLength(OldKey->TrafficSecret->Hash);

    QUIC_STATUS Status =
        CxPlatHashCreate(
            OldKey->TrafficSecret->Hash,
            OldKey->TrafficSecret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        CxPlatHkdfExpandLabel(
            Hash,
            "quic ku",
            SecretLength,
            SecretLength,
            NewTrafficSecret.Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    NewTrafficSecret.Hash = OldKey->TrafficSecret->Hash;
    NewTrafficSecret.Aead = OldKey->TrafficSecret->Aead;

    Status =
        QuicPacketKeyDerive(
            QUIC_PACKET_KEY_1_RTT,
            &NewTrafficSecret,
            "update traffic secret",
            FALSE,
            NewKey);

    CxPlatSecureZeroMemory(&NewTrafficSecret, sizeof(CXPLAT_SECRET));
    CxPlatSecureZeroMemory(OldKey->TrafficSecret, sizeof(CXPLAT_SECRET));

Error:

    CxPlatHashFree(Hash);

    return Status;
}

QUIC_STATUS
CxPlatKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_KEY** NewKey
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const EVP_CIPHER *Aead;

    EVP_CIPHER_CTX* CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        Aead = EVP_aes_128_gcm();
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        Aead = EVP_aes_256_gcm();
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        Aead = EVP_chacha20_poly1305();
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (EVP_CipherInit_ex(CipherCtx, Aead, NULL, RawKey, NULL, 1) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CipherInit_ex failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, CXPLAT_IV_LENGTH, NULL) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = (CXPLAT_KEY*)CipherCtx;
    CipherCtx = NULL;

Exit:

    CxPlatKeyFree((CXPLAT_KEY*)CipherCtx);

    return Status;
}

void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    )
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)Key);
}

QUIC_STATUS
CxPlatEncrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > CXPLAT_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= CXPLAT_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t PlainTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;
    uint8_t *Tag = Buffer + PlainTextLength;
    int OutLen;

    EVP_CIPHER_CTX* CipherCtx = (EVP_CIPHER_CTX*)Key;

    if (EVP_EncryptInit_ex(CipherCtx, NULL, NULL, NULL, Iv) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptInit_ex failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (AuthData != NULL &&
        EVP_EncryptUpdate(CipherCtx, NULL, &OutLen, AuthData, (int)AuthDataLength) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate (AD) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (EVP_EncryptUpdate(CipherCtx, Buffer, &OutLen, Buffer, (int)PlainTextLength) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate (Cipher) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (EVP_EncryptFinal_ex(CipherCtx, Tag, &OutLen) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptFinal_ex failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, CXPLAT_ENCRYPTION_OVERHEAD, Tag) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatDecrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t CipherTextLength = BufferLength - CXPLAT_ENCRYPTION_OVERHEAD;
    uint8_t *Tag = Buffer + CipherTextLength;
    int OutLen;

    EVP_CIPHER_CTX* CipherCtx = (EVP_CIPHER_CTX*)Key;

    if (EVP_DecryptInit_ex(CipherCtx, NULL, NULL, NULL, Iv) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptInit_ex failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (AuthData != NULL &&
        EVP_DecryptUpdate(CipherCtx, NULL, &OutLen, AuthData, (int)AuthDataLength) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptUpdate (AD) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (EVP_DecryptUpdate(CipherCtx, Buffer, &OutLen, Buffer, (int)CipherTextLength) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptUpdate (Cipher) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_TAG, CXPLAT_ENCRYPTION_OVERHEAD, Tag) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    if (EVP_DecryptFinal_ex(CipherCtx, Tag, &OutLen) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_DecryptFinal_ex failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatHpKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_HP_KEY** NewKey
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const EVP_CIPHER *Aead;
    CXPLAT_HP_KEY* Key = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_HP_KEY), QUIC_POOL_TLS_HP_KEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_HP_KEY",
            sizeof(CXPLAT_HP_KEY));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Key->Aead = AeadType;

    Key->CipherCtx = EVP_CIPHER_CTX_new();
    if (Key->CipherCtx == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Cipherctx alloc failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        Aead = EVP_aes_128_ecb();
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        Aead = EVP_aes_256_ecb();
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        Aead = EVP_chacha20();
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(Key->CipherCtx, Aead, NULL, RawKey, NULL) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptInit_ex failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = Key;
    Key = NULL;

Exit:

    CxPlatHpKeyFree(Key);

    return Status;
}

void
CxPlatHpKeyFree(
    _In_opt_ CXPLAT_HP_KEY* Key
    )
{
    if (Key != NULL) {
        EVP_CIPHER_CTX_free(Key->CipherCtx);
        CXPLAT_FREE(Key, QUIC_POOL_TLS_HP_KEY);
    }
}

QUIC_STATUS
CxPlatHpComputeMask(
    _In_ CXPLAT_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize) const uint8_t* const Cipher,
    _Out_writes_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize) uint8_t* Mask
    )
{
    int OutLen = 0;
    if (Key->Aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        static const uint8_t Zero[] = { 0, 0, 0, 0, 0 };
        for (uint32_t i = 0, Offset = 0; i < BatchSize; ++i, Offset += CXPLAT_HP_SAMPLE_LENGTH) {
            if (EVP_EncryptInit_ex(Key->CipherCtx, NULL, NULL, NULL, Cipher + Offset) != 1) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "EVP_EncryptInit_ex (hp) failed");
                return QUIC_STATUS_TLS_ERROR;
            }
            if (EVP_EncryptUpdate(Key->CipherCtx, Mask + Offset, &OutLen, Zero, sizeof(Zero)) != 1) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "EVP_EncryptUpdate (hp) failed");
                return QUIC_STATUS_TLS_ERROR;
            }
        }
    } else {
        if (EVP_EncryptUpdate(Key->CipherCtx, Mask, &OutLen, Cipher, CXPLAT_HP_SAMPLE_LENGTH * BatchSize) != 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "EVP_EncryptUpdate failed");
            return QUIC_STATUS_TLS_ERROR;
        }
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Hash abstraction
//

typedef struct CXPLAT_HASH {
    //
    // The message digest.
    //
    const EVP_MD *Md;

    //
    // Context used for hashing.
    //
    HMAC_CTX* HashContext;

} CXPLAT_HASH;

QUIC_STATUS
CxPlatHashCreate(
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(SaltLength) const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ CXPLAT_HASH** NewHash
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const EVP_MD *Md;

    HMAC_CTX* HashContext = HMAC_CTX_new();
    if (HashContext == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_CTX_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (HashType) {
    case CXPLAT_HASH_SHA256:
        Md = EVP_sha256();
        break;
    case CXPLAT_HASH_SHA384:
        Md = EVP_sha384();
        break;
    case CXPLAT_HASH_SHA512:
        Md = EVP_sha512();
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    if (HMAC_Init_ex(HashContext, Salt, SaltLength, Md, NULL) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Init_ex failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewHash = (CXPLAT_HASH*)HashContext;
    HashContext = NULL;

Exit:

    CxPlatHashFree((CXPLAT_HASH*)HashContext);

    return Status;
}

void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    HMAC_CTX_free((HMAC_CTX*)Hash);
}

QUIC_STATUS
CxPlatHashCompute(
    _In_ CXPLAT_HASH* Hash,
    _In_reads_(InputLength) const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength,
    _Out_writes_all_(OutputLength) uint8_t* const Output
    )
{
    HMAC_CTX* HashContext = (HMAC_CTX*)Hash;

    if (!HMAC_Init_ex(HashContext, NULL, 0, NULL, NULL)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Init_ex(NULL) failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    if (!HMAC_Update(HashContext, Input, InputLength)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Update failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    uint32_t ActualOutputSize = OutputLength;
    if (!HMAC_Final(HashContext, Output, &ActualOutputSize)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Final failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    CXPLAT_FRE_ASSERT(ActualOutputSize == OutputLength);
    return QUIC_STATUS_SUCCESS;
}
