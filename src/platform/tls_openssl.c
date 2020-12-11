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

uint16_t QuicTlsTPHeaderSize = 0;

//
// The QUIC sec config object. Created once per listener on server side and
// once per connection on client side.
//

typedef struct QUIC_SEC_CONFIG {

    //
    // The SSL context associated with the sec config.
    //

    SSL_CTX *SSLCtx;

} QUIC_SEC_CONFIG;

//
// A TLS context associated per connection.
//

typedef struct QUIC_TLS {

    //
    // The TLS configuration information and credentials.
    //
    QUIC_SEC_CONFIG* SecConfig;

    //
    // Indicates if this context belongs to server side or client side
    // connection.
    //
    BOOLEAN IsServer;

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

    QUIC_TLS_PROCESS_STATE* State;
    QUIC_TLS_RESULT_FLAGS ResultFlags;

    //
    // Callback context and handler for QUIC TP.
    //
    QUIC_CONNECTION* Connection;
    QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;

#ifdef QUIC_TLS_SECRETS_SUPPORT
    //
    // Optional struct to log TLS traffic secrets.
    // Only non-null when the connection is configured to log these.
    //
    QUIC_TLS_SECRETS* TlsSecrets;
#endif

} QUIC_TLS;

typedef struct QUIC_HP_KEY {
    EVP_CIPHER_CTX* CipherCtx;
    QUIC_AEAD_TYPE Aead;
} QUIC_HP_KEY;

//
// Default list of Cipher used.
//
#define QUIC_TLS_DEFAULT_SSL_CIPHERS    "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"

//
// Default list of curves for ECDHE ciphers.
//
#define QUIC_TLS_DEFAULT_SSL_CURVES     "P-256:X25519:P-384:P-521"

//
// Default cert verify depth.
//
#define QUIC_TLS_DEFAULT_VERIFY_DEPTH  10

//
// Hack to set trusted cert file on client side.
//
char *QuicOpenSslClientTrustedCert = NULL;

QUIC_STATUS
QuicTlsLibraryInitialize(
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
QuicTlsLibraryUninitialize(
    void
    )
{
}

static
int
QuicTlsAlpnSelectCallback(
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

    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);

    //
    // QUIC already parsed and picked the ALPN to use and set it in the
    // NegotiatedAlpn variable.
    //

    QUIC_DBG_ASSERT(TlsContext->State->NegotiatedAlpn != NULL);
    *OutLen = TlsContext->State->NegotiatedAlpn[0];
    *Out = TlsContext->State->NegotiatedAlpn + 1;

    return SSL_TLSEXT_ERR_OK;
}

QUIC_STATIC_ASSERT((int)ssl_encryption_initial == (int)QUIC_PACKET_KEY_INITIAL, "Code assumes exact match!");
QUIC_STATIC_ASSERT((int)ssl_encryption_early_data == (int)QUIC_PACKET_KEY_0_RTT, "Code assumes exact match!");
QUIC_STATIC_ASSERT((int)ssl_encryption_handshake == (int)QUIC_PACKET_KEY_HANDSHAKE, "Code assumes exact match!");
QUIC_STATIC_ASSERT((int)ssl_encryption_application == (int)QUIC_PACKET_KEY_1_RTT, "Code assumes exact match!");

void
QuicTlsNegotiatedCiphers(
    _In_ QUIC_TLS* TlsContext,
    _Out_ QUIC_AEAD_TYPE *AeadType,
    _Out_ QUIC_HASH_TYPE *HashType
    )
{
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(TlsContext->Ssl))) {
    case 0x03001301U: // TLS_AES_128_GCM_SHA256
        *AeadType = QUIC_AEAD_AES_128_GCM;
        *HashType = QUIC_HASH_SHA256;
        break;
    case 0x03001302U: // TLS_AES_256_GCM_SHA384
        *AeadType = QUIC_AEAD_AES_256_GCM;
        *HashType = QUIC_HASH_SHA384;
        break;
    case 0x03001303U: // TLS_CHACHA20_POLY1305_SHA256
        *AeadType = QUIC_AEAD_CHACHA20_POLY1305;
        *HashType = QUIC_HASH_SHA256;
        break;
    default:
        QUIC_FRE_ASSERT(FALSE);
    }
}

int
QuicTlsSetEncryptionSecretsCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(SecretLen) const uint8_t* ReadSecret,
    _In_reads_(SecretLen) const uint8_t* WriteSecret,
    _In_ size_t SecretLen
    )
{
    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);
    QUIC_TLS_PROCESS_STATE* TlsState = TlsContext->State;
    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    QUIC_STATUS Status;

    QuicTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        Level);

    QUIC_SECRET Secret;
    QuicTlsNegotiatedCiphers(TlsContext, &Secret.Aead, &Secret.Hash);
    QuicCopyMemory(Secret.Secret, WriteSecret, SecretLen);

    QUIC_DBG_ASSERT(TlsState->WriteKeys[KeyType] == NULL);
    Status =
        QuicPacketKeyDerive(
            KeyType,
            &Secret,
            "write secret",
            TRUE,
            &TlsState->WriteKeys[KeyType]);
    if (QUIC_FAILED(Status)) {
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
        return -1;
    }

    TlsState->WriteKey = KeyType;
    TlsContext->ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
    QuicCopyMemory(Secret.Secret, ReadSecret, SecretLen);

    QUIC_DBG_ASSERT(TlsState->ReadKeys[KeyType] == NULL);
    Status =
        QuicPacketKeyDerive(
            KeyType,
            &Secret,
            "read secret",
            TRUE,
            &TlsState->ReadKeys[KeyType]);
    if (QUIC_FAILED(Status)) {
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
        return -1;
    }

    if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_1_RTT) {
        //
        // The 1-RTT read keys aren't actually allowed to be used until the
        // handshake completes.
        //
    } else {
        TlsState->ReadKey = KeyType;
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
    }
#ifdef QUIC_TLS_SECRETS_SUPPORT
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
QuicTlsAddHandshakeDataCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(Length) const uint8_t *Data,
    _In_ size_t Length
    )
{
    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);
    QUIC_TLS_PROCESS_STATE* TlsState = TlsContext->State;

    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    QUIC_DBG_ASSERT(KeyType == 0 || TlsState->WriteKeys[KeyType] != NULL);

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
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
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

        uint8_t* NewBuffer = QUIC_ALLOC_NONPAGED(NewBufferAllocLength, QUIC_POOL_TLS_BUFFER);
        if (NewBuffer == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto buffer",
                NewBufferAllocLength);
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
            return -1;
        }

        QuicCopyMemory(
            NewBuffer,
            TlsState->Buffer,
            TlsState->BufferLength);
        QUIC_FREE(TlsState->Buffer, QUIC_POOL_TLS_BUFFER);
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

    QuicCopyMemory(
        TlsState->Buffer + TlsState->BufferLength,
        Data,
        Length);
    TlsState->BufferLength += (uint16_t)Length;
    TlsState->BufferTotalLength += (uint16_t)Length;

    TlsContext->ResultFlags |= QUIC_TLS_RESULT_DATA;

    return 1;
}

int
QuicTlsFlushFlightCallback(
    _In_ SSL *Ssl
    )
{
    UNREFERENCED_PARAMETER(Ssl);
    return 1;
}

int
QuicTlsSendAlertCallback(
    _In_ SSL *Ssl,
    _In_ enum ssl_encryption_level_t Level,
    _In_ uint8_t Alert
    )
{
    UNREFERENCED_PARAMETER(Level);

    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);

    QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        Level);

    TlsContext->State->AlertCode = Alert;
    TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;

    return 1;
}

int
QuicTlsClientHelloCallback(
    _In_ SSL *Ssl,
    _Out_opt_ int *Alert,
    _In_ void *arg
    )
{
    UNREFERENCED_PARAMETER(arg);
    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);

    const uint8_t* TransportParams;
    size_t TransportParamLen;

    if (!SSL_client_hello_get0_ext(
            Ssl,
            TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS,
            &TransportParams,
            &TransportParamLen)) {
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
        *Alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

SSL_QUIC_METHOD OpenSslQuicCallbacks = {
    QuicTlsSetEncryptionSecretsCallback,
    QuicTlsAddHandshakeDataCallback,
    QuicTlsFlushFlightCallback,
    QuicTlsSendAlertCallback
};

QUIC_STATUS
QuicTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ RSA** EvpPrivateKey,
    _Out_ X509** X509Cert);

QUIC_STATUS
QuicTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_opt_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
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
        } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
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
    QUIC_SEC_CONFIG* SecurityConfig = NULL;
    RSA* RsaKey = NULL;
    X509* X509Cert = NULL;

    //
    // Create a security config.
    //

    SecurityConfig = QUIC_ALLOC_NONPAGED(sizeof(QUIC_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_SEC_CONFIG",
            sizeof(QUIC_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

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
            QUIC_TLS_DEFAULT_SSL_CIPHERS);
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
            QUIC_TLS_DEFAULT_SSL_CURVES);
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
            SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, QUIC_TLS_DEFAULT_VERIFY_DEPTH);

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

        SSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx, QuicTlsAlpnSelectCallback, NULL);

        //
        // Set the server certs.
        //

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
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
                QuicTlsExtractPrivateKey(
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
        SSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx, QuicTlsClientHelloCallback, NULL);
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
        QuicTlsSecConfigDelete(SecurityConfig);
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
QuicTlsSecConfigDelete(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->SSLCtx != NULL) {
        SSL_CTX_free(SecurityConfig->SSLCtx);
        SecurityConfig->SSLCtx = NULL;
    }

    QUIC_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}

QUIC_STATUS
QuicTlsInitialize(
    _In_ const QUIC_TLS_CONFIG* Config,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Out_ QUIC_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_TLS* TlsContext = NULL;
    uint16_t ServerNameLength = 0;

    TlsContext = QUIC_ALLOC_NONPAGED(sizeof(QUIC_TLS), QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS",
            sizeof(QUIC_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(TlsContext, sizeof(QUIC_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;
#ifdef QUIC_TLS_SECRETS_SUPPORT
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

            TlsContext->SNI = QUIC_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_TLS_SNI);
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
    QUIC_FREE(Config->LocalTPBuffer, QUIC_POOL_TLS_TRANSPARAMS);

    State->EarlyDataState = QUIC_TLS_EARLY_DATA_UNSUPPORTED; // 0-RTT not currently supported.

    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:

    if (TlsContext != NULL) {
        QuicTlsUninitialize(TlsContext);
        TlsContext = NULL;
    }

    return Status;
}

void
QuicTlsUninitialize(
    _In_opt_ QUIC_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        if (TlsContext->SNI != NULL) {
            QUIC_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
            TlsContext->SNI = NULL;
        }

        if (TlsContext->Ssl != NULL) {
            SSL_free(TlsContext->Ssl);
            TlsContext->Ssl = NULL;
        }

        QUIC_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

void
QuicTlsReset(
    _In_ QUIC_TLS* TlsContext
    )
{
    QuicTraceLogConnInfo(
        OpenSslContextReset,
        TlsContext->Connection,
        "Resetting TLS state");

    QUIC_DBG_ASSERT(TlsContext->IsServer == FALSE);

    //
    // Free the old SSL state.
    //

    if (TlsContext->Ssl != NULL) {
        SSL_free(TlsContext->Ssl);
        TlsContext->Ssl = NULL;
    }

    //
    // Create a new SSL state.
    //

    TlsContext->Ssl = SSL_new(TlsContext->SecConfig->SSLCtx);
    if (TlsContext->Ssl == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SSL_new failed");
        QUIC_DBG_ASSERT(FALSE);
        goto Exit;
    }

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    SSL_set_connect_state(TlsContext->Ssl);
    SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
    SSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);

    QUIC_FRE_ASSERT(FALSE); // Currently unsupported!!
    /* TODO - Figure out if this is necessary.
    if (SSL_set_quic_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SSL_set_quic_transport_params failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }*/

Exit:

    return;
}

QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ QUIC_TLS* TlsContext,
    _In_ QUIC_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength) const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
{
    int Ret = 0;
    int Err = 0;

    QUIC_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    if (DataType == QUIC_TLS_TICKET_DATA) {
        TlsContext->ResultFlags = QUIC_TLS_RESULT_ERROR;

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
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
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
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;

            default:
                QuicTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
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
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (NegotiatedAlpnLength > UINT8_MAX) {
                QuicTraceLogConnError(
                    OpenSslInvalidAlpnLength,
                    TlsContext->Connection,
                    "Invalid negotiated ALPN length");
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;
            }
            TlsContext->State->NegotiatedAlpn =
                QuicTlsAlpnFindInList(
                    TlsContext->AlpnBufferLength,
                    TlsContext->AlpnBuffer,
                    (uint8_t)NegotiatedAlpnLength,
                    NegotiatedAlpn);
            if (TlsContext->State->NegotiatedAlpn == NULL) {
                QuicTraceLogConnError(
                    OpenSslNoMatchingAlpn,
                    TlsContext->Connection,
                    "Failed to find a matching ALPN");
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "Handshake complete");
        State->HandshakeComplete = TRUE;
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_COMPLETE;

        if (TlsContext->IsServer) {
            TlsContext->State->ReadKey = QUIC_PACKET_KEY_1_RTT;
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
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
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;
            }
            if (!TlsContext->ReceiveTPCallback(
                    TlsContext->Connection,
                    (uint16_t)TransportParamLen,
                    TransportParams)) {
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
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
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
            goto Exit;

        default:
            QuicTraceLogConnError(
                OpenSslHandshakeError,
                TlsContext->Connection,
                "TLS handshake error: %d",
                Err);
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

Exit:

    if (!(TlsContext->ResultFlags & QUIC_TLS_RESULT_ERROR)) {
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

QUIC_TLS_RESULT_FLAGS
QuicTlsProcessDataComplete(
    _In_ QUIC_TLS* TlsContext,
    _Out_ uint32_t * ConsumedBuffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(ConsumedBuffer);
    return QUIC_TLS_RESULT_ERROR;
}

QUIC_STATUS
QuicTlsParamSet(
    _In_ QUIC_TLS* TlsContext,
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
QuicTlsParamGet(
    _In_ QUIC_TLS* TlsContext,
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
QuicTlsLogSecret(
    _In_z_ const char* const Prefix,
    _In_reads_(Length)
        const uint8_t* const Secret,
    _In_ uint32_t Length
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    char SecretStr[256 + 1] = {0};
    QUIC_DBG_ASSERT(Length * 2 < sizeof(SecretStr));
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
#define QuicTlsLogSecret(Prefix, Secret, Length) UNREFERENCED_PARAMETER(Prefix);
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t HashLength,
    _Out_writes_all_(5 + QUIC_HKDF_PREFIX_LEN + strlen(Label))
        uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    QUIC_DBG_ASSERT(strlen(Label) <= UINT8_MAX - QUIC_HKDF_PREFIX_LEN);
    uint8_t LabelLength = (uint8_t)strlen(Label);

    Data[0] = HashLength >> 8;
    Data[1] = HashLength & 0xff;
    Data[2] = QUIC_HKDF_PREFIX_LEN + LabelLength;
    memcpy(Data + 3, QUIC_HKDF_PREFIX, QUIC_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + QUIC_HKDF_PREFIX_LEN, Label, LabelLength);
    Data[3 + QUIC_HKDF_PREFIX_LEN + LabelLength] = 0;
    *DataLength = 3 + QUIC_HKDF_PREFIX_LEN + LabelLength + 1;

    Data[*DataLength] = 0x1;
    *DataLength += 1;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHkdfExpandLabel(
    _In_ QUIC_HASH* Hash,
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLength,
    _In_ uint32_t OutputLength, // Writes QuicHashLength(HashType) bytes.
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    uint8_t LabelBuffer[64];
    uint32_t LabelLength = sizeof(LabelBuffer);

    _Analysis_assume_(strlen(Label) <= 23);
    QuicHkdfFormatLabel(Label, KeyLength, LabelBuffer, &LabelLength);

    return
        QuicHashCompute(
            Hash,
            LabelBuffer,
            LabelLength,
            OutputLength,
            Output);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicTlsDeriveInitialSecrets(
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _In_ uint8_t CIDLength,
    _Out_ QUIC_SECRET *ClientInitial,
    _Out_ QUIC_SECRET *ServerInitial
    )
{
    QUIC_STATUS Status;
    QUIC_HASH* InitialHash = NULL;
    QUIC_HASH* DerivedHash = NULL;
    uint8_t InitialSecret[QUIC_HASH_SHA256_SIZE];

    QuicTlsLogSecret("init cid", CID, CIDLength);

    Status =
        QuicHashCreate(
            QUIC_HASH_SHA256,
            Salt,
            QUIC_VERSION_SALT_LENGTH,
            &InitialHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Extract secret for client and server secret expansion.
    //
    Status =
        QuicHashCompute(
            InitialHash,
            CID,
            CIDLength,
            sizeof(InitialSecret),
            InitialSecret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsLogSecret("init secret", InitialSecret, sizeof(InitialSecret));

    //
    // Create hash for client and server secret expansion.
    //
    Status =
        QuicHashCreate(
            QUIC_HASH_SHA256,
            InitialSecret,
            sizeof(InitialSecret),
            &DerivedHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand client secret.
    //
    ClientInitial->Hash = QUIC_HASH_SHA256;
    ClientInitial->Aead = QUIC_AEAD_AES_128_GCM;
    Status =
        QuicHkdfExpandLabel(
            DerivedHash,
            "client in",
            sizeof(InitialSecret),
            QUIC_HASH_SHA256_SIZE,
            ClientInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand server secret.
    //
    ServerInitial->Hash = QUIC_HASH_SHA256;
    ServerInitial->Aead = QUIC_AEAD_AES_128_GCM;
    Status =
        QuicHkdfExpandLabel(
            DerivedHash,
            "server in",
            sizeof(InitialSecret),
            QUIC_HASH_SHA256_SIZE,
            ServerInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    QuicHashFree(InitialHash);
    QuicHashFree(DerivedHash);

    QuicSecureZeroMemory(InitialSecret, sizeof(InitialSecret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    )
{
    const uint16_t SecretLength = QuicHashLength(Secret->Hash);
    const uint16_t KeyLength = QuicKeyLength(Secret->Aead);

    QUIC_DBG_ASSERT(SecretLength >= KeyLength);
    QUIC_DBG_ASSERT(SecretLength >= QUIC_IV_LENGTH);
    QUIC_DBG_ASSERT(SecretLength <= QUIC_HASH_MAX_SIZE);

    QuicTlsLogSecret(SecretName, Secret->Secret, SecretLength);

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0);
    QUIC_PACKET_KEY *Key = QUIC_ALLOC_NONPAGED(PacketKeyLength, QUIC_POOL_TLS_PACKETKEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QuicZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    QUIC_HASH* Hash = NULL;
    uint8_t Temp[QUIC_HASH_MAX_SIZE];

    QUIC_STATUS Status =
        QuicHashCreate(
            Secret->Hash,
            Secret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic iv",
            QUIC_IV_LENGTH,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    memcpy(Key->Iv, Temp, QUIC_IV_LENGTH);
    QuicTlsLogSecret("static iv", Key->Iv, QUIC_IV_LENGTH);

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic key",
            KeyLength,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsLogSecret("key", Temp, KeyLength);

    Status =
        QuicKeyCreate(
            Secret->Aead,
            Temp,
            &Key->PacketKey);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            QuicHkdfExpandLabel(
                Hash,
                "quic hp",
                KeyLength,
                SecretLength,
                Temp);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        QuicTlsLogSecret("hp", Temp, KeyLength);

        Status =
            QuicHpKeyCreate(
                Secret->Aead,
                Temp,
                &Key->HeaderKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        QuicCopyMemory(Key->TrafficSecret, Secret, sizeof(QUIC_SECRET));
    }

    *NewKey = Key;
    Key = NULL;

Error:

    QuicPacketKeyFree(Key);
    QuicHashFree(Hash);

    QuicSecureZeroMemory(Temp, sizeof(Temp));

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(NewReadKey != NULL, _At_(*NewReadKey, __drv_allocatesMem(Mem)))
_When_(NewWriteKey != NULL, _At_(*NewWriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** NewReadKey,
    _Out_opt_ QUIC_PACKET_KEY** NewWriteKey
    )
{
    QUIC_STATUS Status;
    QUIC_SECRET ClientInitial, ServerInitial;
    QUIC_PACKET_KEY* ReadKey = NULL, *WriteKey = NULL;

    Status =
        QuicTlsDeriveInitialSecrets(
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

    QuicSecureZeroMemory(ClientInitial.Secret, sizeof(ClientInitial.Secret));
    QuicSecureZeroMemory(ServerInitial.Secret, sizeof(ServerInitial.Secret));

    return Status;
}

void
QuicPacketKeyFree(
    _In_opt_ QUIC_PACKET_KEY* Key
    )
{
    if (Key != NULL) {
        QuicKeyFree(Key->PacketKey);
        QuicHpKeyFree(Key->HeaderKey);
        if (Key->Type >= QUIC_PACKET_KEY_1_RTT) {
            QuicSecureZeroMemory(Key->TrafficSecret, sizeof(QUIC_SECRET));
        }
        QUIC_FREE(Key, QUIC_POOL_TLS_PACKETKEY);
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

    QUIC_HASH* Hash = NULL;
    QUIC_SECRET NewTrafficSecret;
    const uint16_t SecretLength = QuicHashLength(OldKey->TrafficSecret->Hash);

    QUIC_STATUS Status =
        QuicHashCreate(
            OldKey->TrafficSecret->Hash,
            OldKey->TrafficSecret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicHkdfExpandLabel(
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

    QuicSecureZeroMemory(&NewTrafficSecret, sizeof(QUIC_SECRET));
    QuicSecureZeroMemory(OldKey->TrafficSecret, sizeof(QUIC_SECRET));

Error:

    QuicHashFree(Hash);

    return Status;
}

QUIC_STATUS
QuicKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_KEY** NewKey
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
    case QUIC_AEAD_AES_128_GCM:
        Aead = EVP_aes_128_gcm();
        break;
    case QUIC_AEAD_AES_256_GCM:
        Aead = EVP_aes_256_gcm();
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
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

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, QUIC_IV_LENGTH, NULL) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *NewKey = (QUIC_KEY*)CipherCtx;
    CipherCtx = NULL;

Exit:

    QuicKeyFree((QUIC_KEY*)CipherCtx);

    return Status;
}

void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    )
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)Key);
}

QUIC_STATUS
QuicEncrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > QUIC_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= QUIC_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t PlainTextLength = BufferLength - QUIC_ENCRYPTION_OVERHEAD;
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

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, QUIC_ENCRYPTION_OVERHEAD, Tag) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicDecrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);

    const uint16_t CipherTextLength = BufferLength - QUIC_ENCRYPTION_OVERHEAD;
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

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_TAG, QUIC_ENCRYPTION_OVERHEAD, Tag) != 1) {
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
QuicHpKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_HP_KEY** NewKey
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const EVP_CIPHER *Aead;
    QUIC_HP_KEY* Key = QUIC_ALLOC_NONPAGED(sizeof(QUIC_HP_KEY), QUIC_POOL_TLS_HP_KEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_HP_KEY",
            sizeof(QUIC_HP_KEY));
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
    case QUIC_AEAD_AES_128_GCM:
        Aead = EVP_aes_128_ecb();
        break;
    case QUIC_AEAD_AES_256_GCM:
        Aead = EVP_aes_256_ecb();
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
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

    QuicHpKeyFree(Key);

    return Status;
}

void
QuicHpKeyFree(
    _In_opt_ QUIC_HP_KEY* Key
    )
{
    if (Key != NULL) {
        EVP_CIPHER_CTX_free(Key->CipherCtx);
        QUIC_FREE(Key, QUIC_POOL_TLS_HP_KEY);
    }
}

QUIC_STATUS
QuicHpComputeMask(
    _In_ QUIC_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize) const uint8_t* const Cipher,
    _Out_writes_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize) uint8_t* Mask
    )
{
    int OutLen = 0;
    if (Key->Aead == QUIC_AEAD_CHACHA20_POLY1305) {
        static const uint8_t Zero[] = { 0, 0, 0, 0, 0 };
        for (uint32_t i = 0, Offset = 0; i < BatchSize; ++i, Offset += QUIC_HP_SAMPLE_LENGTH) {
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
        if (EVP_EncryptUpdate(Key->CipherCtx, Mask, &OutLen, Cipher, QUIC_HP_SAMPLE_LENGTH * BatchSize) != 1) {
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

typedef struct QUIC_HASH {
    //
    // The message digest.
    //
    const EVP_MD *Md;

    //
    // Context used for hashing.
    //
    HMAC_CTX* HashContext;

} QUIC_HASH;

QUIC_STATUS
QuicHashCreate(
    _In_ QUIC_HASH_TYPE HashType,
    _In_reads_(SaltLength) const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ QUIC_HASH** NewHash
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
    case QUIC_HASH_SHA256:
        Md = EVP_sha256();
        break;
    case QUIC_HASH_SHA384:
        Md = EVP_sha384();
        break;
    case QUIC_HASH_SHA512:
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

    *NewHash = (QUIC_HASH*)HashContext;
    HashContext = NULL;

Exit:

    QuicHashFree((QUIC_HASH*)HashContext);

    return Status;
}

void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    )
{
    HMAC_CTX_free((HMAC_CTX*)Hash);
}

QUIC_STATUS
QuicHashCompute(
    _In_ QUIC_HASH* Hash,
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

    QUIC_FRE_ASSERT(ActualOutputSize == OutputLength);
    return QUIC_STATUS_SUCCESS;
}
