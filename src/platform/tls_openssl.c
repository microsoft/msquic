/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling OpenSSL.

--*/

#include "platform_internal.h"

#define OPENSSL_SUPPRESS_DEPRECATED 1 // For hmac.h, which was deprecated in 3.0
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#endif
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#ifdef _WIN32
#pragma warning(pop)
#endif
#ifdef QUIC_CLOG
#include "tls_openssl.c.clog.h"
#endif

uint16_t CxPlatTlsTPHeaderSize = 0;

const size_t OpenSslFilePrefixLength = sizeof("..\\..\\..\\..\\..\\..\\submodules");

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
    // Optional ticket key provided by the app.
    //
    QUIC_TICKET_KEY_CONFIG* TicketKey;

    //
    // Callbacks for TLS.
    //
    CXPLAT_TLS_CALLBACKS Callbacks;

    //
    // The application supplied credential flags.
    //
    QUIC_CREDENTIAL_FLAGS Flags;

    //
    // Internal TLS credential flags.
    //
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags;

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

#define CXPLAT_TLS_AES_128_GCM_SHA256       "TLS_AES_128_GCM_SHA256"
#define CXPLAT_TLS_AES_256_GCM_SHA384       "TLS_AES_256_GCM_SHA384"
#define CXPLAT_TLS_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"

//
// Default list of curves for ECDHE ciphers.
//
#define CXPLAT_TLS_DEFAULT_SSL_CURVES     "P-256:X25519:P-384:P-521"

//
// Default cert verify depth.
//
#define CXPLAT_TLS_DEFAULT_VERIFY_DEPTH  10

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
    _Out_writes_bytes_(*OutLen) const unsigned char **Out,
    _Out_ unsigned char *OutLen,
    _In_reads_bytes_(InLen) const unsigned char *In,
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

BOOLEAN
CxPlatTlsVerifyCertificate(
    _In_ X509* X509Cert,
    _In_ const char* SNI
    );

static
int
CxPlatTlsCertificateVerifyCallback(
    int preverify_ok,
    X509_STORE_CTX *x509_ctx
    )
{
    X509* Cert = X509_STORE_CTX_get0_cert(x509_ctx);
    SSL *Ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION)) {
        preverify_ok = CxPlatTlsVerifyCertificate(Cert, TlsContext->SNI);
    }

    if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
        !preverify_ok) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Internal certificate validation failed");
        return FALSE;
    }

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
        !TlsContext->SecConfig->Callbacks.CertificateReceived(
            TlsContext->Connection,
            x509_ctx,
            0,
            0)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Indicate certificate received failed");
        X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REJECTED);
        return FALSE;
    }

    return TRUE;
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
        (uint32_t)Level);

    CXPLAT_SECRET Secret;
    CxPlatTlsNegotiatedCiphers(TlsContext, &Secret.Aead, &Secret.Hash);

    if (WriteSecret) {
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

        if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_0_RTT) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
            TlsContext->State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
        }
    }

    if (ReadSecret) {
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
        (uint32_t)Level);

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
        (uint32_t)Level);

    TlsContext->State->AlertCode = Alert;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;

    return 1;
}

_Success_(return == SSL_CLIENT_HELLO_SUCCESS)
int
CxPlatTlsClientHelloCallback(
    _In_ SSL *Ssl,
    _When_(return == SSL_CLIENT_HELLO_ERROR, _Out_)
        int *Alert,
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

int
CxPlatTlsOnClientSessionTicketReceived(
    _In_ SSL *Ssl,
    _In_ SSL_SESSION *Session
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    BIO* Bio = BIO_new(BIO_s_mem());
    if (Bio) {
        if (PEM_write_bio_SSL_SESSION(Bio, Session) == 1) {
            uint8_t* Data = NULL;
            long Length = BIO_get_mem_data(Bio, &Data);
            if (Length < UINT16_MAX) {
                QuicTraceLogConnInfo(
                    OpenSslOnRecvTicket,
                    TlsContext->Connection,
                    "Received session ticket, %u bytes",
                    (uint32_t)Length);
                TlsContext->SecConfig->Callbacks.ReceiveTicket(
                    TlsContext->Connection,
                    (uint32_t)Length,
                    Data);
            } else {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Session data too big");
            }
        } else {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "PEM_write_bio_SSL_SESSION failed");
        }
        BIO_free(Bio);
    } else {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            ERR_get_error(),
            "BIO_new_mem_buf failed");
    }

    //
    // We always return a "fail" response so that the session gets freed again
    // because we haven't used the reference.
    //
    return 0;
}

_Success_(return > 0)
int
CxPlatTlsOnSessionTicketKeyNeeded(
    _In_ SSL *Ssl,
    _When_(enc, _Out_writes_bytes_(16))
    _When_(!enc, _In_reads_bytes_(16))
        unsigned char key_name[16],
    _When_(enc, _Out_writes_bytes_(EVP_MAX_IV_LENGTH))
    _When_(!enc, _In_reads_bytes_(EVP_MAX_IV_LENGTH))
        unsigned char iv[EVP_MAX_IV_LENGTH],
    _Inout_ EVP_CIPHER_CTX *ctx,
    _Inout_ HMAC_CTX *hctx,
    _In_ int enc // Encryption or decryption
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    QUIC_TICKET_KEY_CONFIG* TicketKey = TlsContext->SecConfig->TicketKey;

    CXPLAT_DBG_ASSERT(TicketKey != NULL);
    if (TicketKey == NULL) {
        return -1;
    }

    CXPLAT_STATIC_ASSERT(
        sizeof(TicketKey->Id) == 16,
        "key_name and TicketKey->Id are the same size");

    if (enc) {
        if (QUIC_FAILED(CxPlatRandom(EVP_MAX_IV_LENGTH, iv))) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Failed to generate ticket IV");
            return -1; // Insufficient random
        }
        CxPlatCopyMemory(key_name, TicketKey->Id, 16);
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, TicketKey->Material, iv);
        HMAC_Init_ex(hctx, TicketKey->Material, 32, EVP_sha256(), NULL);

    } else {
        if (memcmp(key_name, TicketKey->Id, 16) != 0) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Ticket key_name mismatch");
            return 0; // No match
        }
        HMAC_Init_ex(hctx, TicketKey->Material, 32, EVP_sha256(), NULL);
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, TicketKey->Material, iv);
    }

    return 1; // This indicates that the ctx and hctx have been set and the
              // session can continue on those parameters.
}

int
CxPlatTlsOnServerSessionTicketGenerated(
    _In_ SSL *Ssl,
    _In_ void *arg
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(arg);
    return 1;
}

SSL_TICKET_RETURN
CxPlatTlsOnServerSessionTicketDecrypted(
    _In_ SSL *Ssl,
    _In_ SSL_SESSION *ss,
    _In_ const unsigned char *keyname,
    _In_ size_t keyname_length,
    _In_ SSL_TICKET_STATUS status,
    _In_ void *arg
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(ss);
    UNREFERENCED_PARAMETER(keyname);
    UNREFERENCED_PARAMETER(keyname_length);
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(arg);
    if (status == SSL_TICKET_SUCCESS) {
        return SSL_TICKET_RETURN_USE;
    }
    if (status == SSL_TICKET_SUCCESS_RENEW) {
        return SSL_TICKET_RETURN_USE_RENEW;
    }
    return SSL_TICKET_RETURN_IGNORE_RENEW;
}

SSL_QUIC_METHOD OpenSslQuicCallbacks = {
    CxPlatTlsSetEncryptionSecretsCallback,
    CxPlatTlsAddHandshakeDataCallback,
    CxPlatTlsFlushFlightCallback,
    CxPlatTlsSendAlertCallback
};

CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_FILE, PrivateKeyFile) == FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED, PrivateKeyFile),
    "Mismatch (private key) in certificate file structs");

CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_FILE, CertificateFile) == FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED, CertificateFile),
    "Mismatch (certificate file) in certificate file structs");

QUIC_STATUS
CxPlatTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ RSA** EvpPrivateKey,
    _Out_ X509** X509Cert);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP ||
        CredConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not supported by this TLS implementation
    }

    if (CredConfig->Reserved != NULL) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and should be NULL.
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
        } else if(CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
            if (CredConfig->CertificatePkcs12 == NULL ||
                CredConfig->CertificatePkcs12->Asn1Blob == NULL ||
                CredConfig->CertificatePkcs12->Asn1BlobLength == 0) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
        } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) { // NOLINT bugprone-branch-clone
#ifndef _WIN32
            return QUIC_STATUS_NOT_SUPPORTED; // Only supported on windows.
#endif
            // Windows parameters checked later
        } else {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES &&
        ((CredConfig->AllowedCipherSuites &
            (QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 |
            QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 |
            QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)) == 0)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CredConfig->AllowedCipherSuites,
            "No valid cipher suites presented");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    CXPLAT_SEC_CONFIG* SecurityConfig = NULL;
    RSA* RsaKey = NULL;
    X509* X509Cert = NULL;
    EVP_PKEY * PrivateKey = NULL;
    char* CipherSuiteString = NULL;

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

    CxPlatZeroMemory(SecurityConfig, sizeof(CXPLAT_SEC_CONFIG));
    SecurityConfig->Callbacks = *TlsCallbacks;
    SecurityConfig->Flags = CredConfig->Flags;
    SecurityConfig->TlsFlags = TlsCredFlags;

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

    char* CipherSuites = CXPLAT_TLS_DEFAULT_SSL_CIPHERS;
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
        //
        // Calculate allowed cipher suite string length.
        //
        uint8_t CipherSuiteStringLength = 0;
        uint8_t AllowedCipherSuitesCount = 0;
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            CipherSuiteStringLength += (uint8_t)sizeof(CXPLAT_TLS_AES_128_GCM_SHA256);
            AllowedCipherSuitesCount++;
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            CipherSuiteStringLength += (uint8_t)sizeof(CXPLAT_TLS_AES_256_GCM_SHA384);
            AllowedCipherSuitesCount++;
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
            CipherSuiteStringLength += (uint8_t)sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256);
            AllowedCipherSuitesCount++;
        }

        CipherSuiteString = CXPLAT_ALLOC_NONPAGED(CipherSuiteStringLength, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
        if (CipherSuiteString == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CipherSuiteString",
                CipherSuiteStringLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        //
        // Order of if-statements matters here because OpenSSL uses the order
        // of cipher suites to indicate preference. Below, we use the default
        // order of preference for TLS 1.3 cipher suites.
        //
        uint8_t CipherSuiteStringCursor = 0;
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            CxPlatCopyMemory(
                &CipherSuiteString[CipherSuiteStringCursor],
                CXPLAT_TLS_AES_256_GCM_SHA384,
                sizeof(CXPLAT_TLS_AES_256_GCM_SHA384));
            CipherSuiteStringCursor += (uint8_t)sizeof(CXPLAT_TLS_AES_256_GCM_SHA384);
            if (--AllowedCipherSuitesCount > 0) {
                CipherSuiteString[CipherSuiteStringCursor - 1] = ':';
            }
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
            CxPlatCopyMemory(
                &CipherSuiteString[CipherSuiteStringCursor],
                CXPLAT_TLS_CHACHA20_POLY1305_SHA256,
                sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256));
            CipherSuiteStringCursor += (uint8_t)sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256);
            if (--AllowedCipherSuitesCount > 0) {
                CipherSuiteString[CipherSuiteStringCursor - 1] = ':';
            }
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            CxPlatCopyMemory(
                &CipherSuiteString[CipherSuiteStringCursor],
                CXPLAT_TLS_AES_128_GCM_SHA256,
                sizeof(CXPLAT_TLS_AES_128_GCM_SHA256));
            CipherSuiteStringCursor += (uint8_t)sizeof(CXPLAT_TLS_AES_128_GCM_SHA256);
        }
        CXPLAT_DBG_ASSERT(CipherSuiteStringCursor == CipherSuiteStringLength);
        CipherSuites = CipherSuiteString;
    }

    Ret =
        SSL_CTX_set_ciphersuites(
            SecurityConfig->SSLCtx,
            CipherSuites);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_ciphersuites failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

#ifdef CX_PLATFORM_USES_TLS_BUILTIN_CERTIFICATE
    SecurityConfig->Flags |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
#endif

    if (SecurityConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) {
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

    if ((CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) &&
        !(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
        SSL_CTX_set_session_cache_mode(
            SecurityConfig->SSLCtx,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(
            SecurityConfig->SSLCtx,
            CxPlatTlsOnClientSessionTicketReceived);
    }

    if (!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
        if (!(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
            Ret = SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, 0xFFFFFFFF);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_set_max_early_data failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            Ret = SSL_CTX_set_num_tickets(SecurityConfig->SSLCtx, 1);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_set_num_tickets failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

        } else {
            Ret = SSL_CTX_set_num_tickets(SecurityConfig->SSLCtx, 0);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_set_num_tickets failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        SSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER, CxPlatTlsCertificateVerifyCallback);
        SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);

        //
        // TODO - Support additional certificate validation parameters, such as
        // the location of the trusted root CAs (SSL_CTX_load_verify_locations)?
        //

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

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
            CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {

            if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
                SSL_CTX_set_default_passwd_cb_userdata(
                    SecurityConfig->SSLCtx, (void*)CredConfig->CertificateFileProtected->PrivateKeyPassword);
            }

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
        } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
            BIO* Bio = BIO_new(BIO_s_mem());
            PKCS12 *Pkcs12 = NULL;

            if (!Bio) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "BIO_new failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            BIO_set_mem_eof_return(Bio, 0);
            BIO_write(Bio, CredConfig->CertificatePkcs12->Asn1Blob, CredConfig->CertificatePkcs12->Asn1BlobLength);
            Pkcs12 = d2i_PKCS12_bio(Bio, NULL);
            BIO_free(Bio);
            Bio = NULL;

            if (!Pkcs12) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "d2i_PKCS12_bio failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            STACK_OF(X509) *Ca = NULL;
            Ret =
                PKCS12_parse(Pkcs12, CredConfig->CertificatePkcs12->PrivateKeyPassword, &PrivateKey, &X509Cert, &Ca);
            if (Ca) {
                sk_X509_pop_free(Ca, X509_free); // no handling for custom certificate chains yet.
            }
            if (Pkcs12) {
                PKCS12_free(Pkcs12);
            }

            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "PKCS12_parse failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            Ret =
                SSL_CTX_use_PrivateKey(
                    SecurityConfig->SSLCtx,
                    PrivateKey);
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

    if (CipherSuiteString != NULL) {
        CxPlatFree(CipherSuiteString, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
    }

    if (X509Cert != NULL) {
        X509_free(X509Cert);
    }

    if (RsaKey != NULL) {
        RSA_free(RsaKey);
    }

    if (PrivateKey != NULL) {
        EVP_PKEY_free(PrivateKey);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_
        CXPLAT_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->SSLCtx != NULL) {
        SSL_CTX_free(SecurityConfig->SSLCtx);
    }

    if (SecurityConfig->TicketKey != NULL) {
        CXPLAT_FREE(SecurityConfig->TicketKey, QUIC_POOL_TLS_TICKET_KEY);
    }

    CXPLAT_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig,
    _In_reads_(KeyCount) QUIC_TICKET_KEY_CONFIG* KeyConfig,
    _In_ uint8_t KeyCount
    )
{
    CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now
    UNREFERENCED_PARAMETER(KeyCount);

    if (SecurityConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (SecurityConfig->TicketKey == NULL) {
        SecurityConfig->TicketKey =
            CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_TICKET_KEY_CONFIG), QUIC_POOL_TLS_TICKET_KEY);
        if (SecurityConfig->TicketKey == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "QUIC_TICKET_KEY_CONFIG",
                sizeof(QUIC_TICKET_KEY_CONFIG));
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    CxPlatCopyMemory(
        SecurityConfig->TicketKey,
        KeyConfig,
        sizeof(QUIC_TICKET_KEY_CONFIG));

    SSL_CTX_set_tlsext_ticket_key_cb(
        SecurityConfig->SSLCtx,
        CxPlatTlsOnSessionTicketKeyNeeded);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
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
    UNREFERENCED_PARAMETER(State);

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
    } else {
        SSL_set_connect_state(TlsContext->Ssl);
        SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
        SSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);
    }

    if (!(Config->SecConfig->TlsFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {

        if (Config->ResumptionTicketLength != 0) {
            CXPLAT_DBG_ASSERT(Config->ResumptionTicketBuffer != NULL);

            QuicTraceLogConnInfo(
                OpenSslOnSetTicket,
                TlsContext->Connection,
                "Setting session ticket, %u bytes",
                Config->ResumptionTicketLength);
            BIO* Bio =
                BIO_new_mem_buf(
                    Config->ResumptionTicketBuffer,
                    (int)Config->ResumptionTicketLength);
            if (Bio) {
                SSL_SESSION* Session = PEM_read_bio_SSL_SESSION(Bio, NULL, 0, NULL);
                if (Session) {
                    if (!SSL_set_session(TlsContext->Ssl, Session)) {
                        QuicTraceEvent(
                            TlsErrorStatus,
                            "[ tls][%p] ERROR, %u, %s.",
                            TlsContext->Connection,
                            ERR_get_error(),
                            "SSL_set_session failed");
                    }
                    SSL_SESSION_free(Session);
                } else {
                    QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        ERR_get_error(),
                        "PEM_read_bio_SSL_SESSION failed");
                }
                BIO_free(Bio);
            } else {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    ERR_get_error(),
                    "BIO_new_mem_buf failed");
            }
        }

        if (Config->IsServer || (Config->ResumptionTicketLength != 0)) {
            SSL_set_quic_early_data_enabled(TlsContext->Ssl, 1);
        }
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
    if (Config->ResumptionTicketBuffer) {
        CXPLAT_FREE(Config->ResumptionTicketBuffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
    }

    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:

    if (TlsContext != NULL) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = NULL;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
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

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
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

        if (SSL_provide_quic_data(
                TlsContext->Ssl,
                (OSSL_ENCRYPTION_LEVEL)TlsContext->State->ReadKey,
                Buffer,
                *BufferLength) != 1) {
            char buf[256];
            QuicTraceLogConnError(
                OpenSslQuicDataErrorStr,
                TlsContext->Connection,
                "SSL_provide_quic_data failed: %s",
                ERR_error_string(ERR_get_error(), buf));
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

    if (!State->HandshakeComplete) {
        int Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret <= 0) {
            int Err = SSL_get_error(TlsContext->Ssl, Ret);
            switch (Err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                goto Exit;

            case SSL_ERROR_SSL: {
                char buf[256];
                const char* file;
                int line;
                ERR_error_string_n(ERR_get_error_line(&file, &line), buf, sizeof(buf));
                QuicTraceLogConnError(
                    OpenSslHandshakeErrorStr,
                    TlsContext->Connection,
                    "TLS handshake error: %s, file:%s:%d",
                    buf,
                    (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file),
                    line);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }

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
            "TLS Handshake complete");
        State->HandshakeComplete = TRUE;
        if (SSL_session_reused(TlsContext->Ssl)) {
            QuicTraceLogConnInfo(
                OpenSslHandshakeResumed,
                TlsContext->Connection,
                "TLS Handshake resumed");
            State->SessionResumed = TRUE;
        }
        if (!TlsContext->IsServer) {
            int EarlyDataStatus = SSL_get_early_data_status(TlsContext->Ssl);
            if (EarlyDataStatus == SSL_EARLY_DATA_ACCEPTED) {
                State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;

            } else if (EarlyDataStatus == SSL_EARLY_DATA_REJECTED) {
                State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_REJECTED;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_REJECT;
            }
        }
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

    } else {
        if (SSL_process_quic_post_handshake(TlsContext->Ssl) != 1) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "SSL_process_quic_post_handshake failed");
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

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessDataComplete(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ uint32_t * ConsumedBuffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    *ConsumedBuffer = 0;
    return CXPLAT_TLS_RESULT_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
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

static
QUIC_STATUS
CxPlatMapCipherSuite(
    _Inout_ QUIC_HANDSHAKE_INFO* HandshakeInfo
    )
{
    //
    // Mappings taken from the following .NET definitions.
    // https://github.com/dotnet/runtime/blob/69425a7e6198ff78131ad64f1aa3fc28202bfde8/src/libraries/Native/Unix/System.Security.Cryptography.Native/pal_ssl.c
    // https://github.com/dotnet/runtime/blob/1d9e50cb4735df46d3de0cee5791e97295eaf588/src/libraries/System.Net.Security/src/System/Net/Security/TlsCipherSuiteData.Lookup.cs
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    HandshakeInfo->KeyExchangeAlgorithm = QUIC_KEY_EXCHANGE_ALGORITHM_NONE;
    HandshakeInfo->KeyExchangeStrength = 0;
    HandshakeInfo->HashStrength = 0;

    switch (HandshakeInfo->CipherSuite) {
        case QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256:
            HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_AES_128;
            HandshakeInfo->CipherStrength = 128;
            HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_256;
            break;
        case QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384:
            HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_AES_256;
            HandshakeInfo->CipherStrength = 256;
            HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_384;
            break;
        //
        // Not supporting ChaChaPoly for querying currently.
        //
        // case QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256:
        //     HandshakeInfo->CipherAlgorithm = QUIC_ALG_CHACHA20;
        //     HandshakeInfo->CipherStrength = 256;
        //     HandshakeInfo->Hash = QUIC_ALG_SHA_256;
        //     break;
        default:
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
}

static
uint32_t
CxPlatMapVersion(
    _In_z_ const char* Version
    )
{
    if (strcmp(Version, "TLSv1.3") == 0) {
        return QUIC_TLS_PROTOCOL_1_3;
    }
    return QUIC_TLS_PROTOCOL_UNKNOWN;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

        case QUIC_PARAM_TLS_HANDSHAKE_INFO: {
            if (*BufferLength < sizeof(QUIC_HANDSHAKE_INFO)) {
                *BufferLength = sizeof(QUIC_HANDSHAKE_INFO);
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            QUIC_HANDSHAKE_INFO* HandshakeInfo = (QUIC_HANDSHAKE_INFO*)Buffer;
            HandshakeInfo->TlsProtocolVersion =
                CxPlatMapVersion(
                    SSL_get_version(TlsContext->Ssl));

            const SSL_CIPHER* Cipher = SSL_get_current_cipher(TlsContext->Ssl);
            if (Cipher == NULL) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Unable to get cipher suite");
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }
            HandshakeInfo->CipherSuite = SSL_CIPHER_get_protocol_id(Cipher);
            Status = CxPlatMapCipherSuite(HandshakeInfo);
            break;
        }

        case QUIC_PARAM_TLS_NEGOTIATED_ALPN: {

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            const uint8_t* NegotiatedAlpn;
            unsigned int NegotiatedAlpnLen = 0;
            SSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn, &NegotiatedAlpnLen);
            if (NegotiatedAlpnLen <= 0) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Unable to get negotiated alpn");
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }
            if (*BufferLength < NegotiatedAlpnLen) {
                *BufferLength = NegotiatedAlpnLen;
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *BufferLength = NegotiatedAlpnLen;
            CxPlatCopyMemory(Buffer, NegotiatedAlpn, NegotiatedAlpnLen);
            Status = QUIC_STATUS_SUCCESS;
            break;
        }

        default:
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketKeyFree(
    _In_opt_ __drv_freesMem(Mem) QUIC_PACKET_KEY* Key
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

_IRQL_requires_max_(DISPATCH_LEVEL)
_At_(*NewKey, __drv_allocatesMem(Mem))
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    )
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)Key);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatEncrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
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

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatDecrypt(
    _In_ CXPLAT_KEY* Key,
    _In_reads_bytes_(CXPLAT_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength)
        uint8_t* Buffer
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHpComputeMask(
    _In_ CXPLAT_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(CXPLAT_HP_SAMPLE_LENGTH* BatchSize)
        const uint8_t* const Cipher,
    _Out_writes_bytes_(CXPLAT_HP_SAMPLE_LENGTH* BatchSize)
        uint8_t* Mask
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

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHashCreate(
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    HMAC_CTX_free((HMAC_CTX*)Hash);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHashCompute(
    _In_ CXPLAT_HASH* Hash,
    _In_reads_(InputLength)
        const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength, // CxPlatHashLength(HashType)
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
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
