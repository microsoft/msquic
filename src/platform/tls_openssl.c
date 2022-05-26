/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling OpenSSL.

--*/

#include "platform_internal.h"

#include "openssl/opensslv.h"
#if OPENSSL_VERSION_MAJOR >= 3
#define IS_OPENSSL_3
#endif

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#endif
#include "openssl/bio.h"
#ifdef IS_OPENSSL_3
#include "openssl/core_names.h"
#else
#include "openssl/hmac.h"
#endif
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/pkcs7.h"
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

#define PFX_PASSWORD_LENGTH 33
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
    // Labels for deriving key material.
    //
    const QUIC_HKDF_LABELS* HkdfLabels;

    //
    // Indicates if this context belongs to server side or client side
    // connection.
    //
    BOOLEAN IsServer : 1;

    //
    // Indicates if the peer sent a certificate.
    //
    BOOLEAN PeerCertReceived : 1;

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

    //
    // Optional struct to log TLS traffic secrets.
    // Only non-null when the connection is configured to log these.
    //
    QUIC_TLS_SECRETS* TlsSecrets;

} CXPLAT_TLS;

//
// Default list of Cipher used.
//
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

#define CXPLAT_TLS_AES_128_GCM_SHA256       "TLS_AES_128_GCM_SHA256"
#define CXPLAT_TLS_AES_256_GCM_SHA384       "TLS_AES_256_GCM_SHA384"
#define CXPLAT_TLS_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"

//
// Default cert verify depth.
//
#define CXPLAT_TLS_DEFAULT_VERIFY_DEPTH  10

static
QUIC_STATUS
CxPlatTlsMapOpenSSLErrorToQuicStatus(
    _In_ int OpenSSLError
    )
{
    switch (OpenSSLError) {
    case X509_V_ERR_CERT_REJECTED:
        return QUIC_STATUS_BAD_CERTIFICATE;
    case X509_V_ERR_CERT_REVOKED:
        return QUIC_STATUS_REVOKED_CERTIFICATE;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return QUIC_STATUS_CERT_EXPIRED;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        __fallthrough;
    case X509_V_ERR_CERT_UNTRUSTED:
        return QUIC_STATUS_CERT_UNTRUSTED_ROOT;
    default:
        return QUIC_STATUS_TLS_ERROR;
    }
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

static
int
CxPlatTlsCertificateVerifyCallback(
    X509_STORE_CTX *x509_ctx,
    void* param
    )
{
    UNREFERENCED_PARAMETER(param);
    int CertificateVerified = 0;
    int status = TRUE;
    unsigned char* OpenSSLCertBuffer = NULL;
    QUIC_BUFFER PortableCertificate = { 0, 0 };
    QUIC_BUFFER PortableChain = { 0, 0 };
    X509* Cert = X509_STORE_CTX_get0_cert(x509_ctx);
    SSL *Ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    int ValidationResult = X509_V_OK;
    BOOLEAN IsDeferredValidationOrClientAuth =
        (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
        TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION);

    TlsContext->PeerCertReceived = (Cert != NULL);

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT ||
        IsDeferredValidationOrClientAuth) &&
        !(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
        if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION)) {
            if (Cert == NULL) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "No certificate passed");
                X509_STORE_CTX_set_error(x509_ctx, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
                return FALSE;
            }

            int OpenSSLCertLength = i2d_X509(Cert, &OpenSSLCertBuffer);
            if (OpenSSLCertLength <= 0) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "i2d_X509 failed");
                CertificateVerified = FALSE;
            } else {
                CertificateVerified =
                    CxPlatCertVerifyRawCertificate(
                        OpenSSLCertBuffer,
                        OpenSSLCertLength,
                        TlsContext->SNI,
                        TlsContext->SecConfig->Flags,
                        IsDeferredValidationOrClientAuth?
                            (uint32_t*)&ValidationResult :
                            NULL);
            }

            if (OpenSSLCertBuffer != NULL) {
                OPENSSL_free(OpenSSLCertBuffer);
            }

            if (!CertificateVerified) {
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REJECTED);
            }
        } else {
            CertificateVerified = X509_verify_cert(x509_ctx);

            if (IsDeferredValidationOrClientAuth &&
                CertificateVerified <= 0) {
                ValidationResult =
                    (int)CxPlatTlsMapOpenSSLErrorToQuicStatus(X509_STORE_CTX_get_error(x509_ctx));
            }
        }
    } else if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
               (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES)) {
        //
        // We need to get certificates provided by peer if we going to pass them via Callbacks.CertificateReceived.
        // We don't really care about validation status but without calling X509_verify_cert() x509_ctx has 
        // no certificates attached to it and that impacts validation of custom certificate chains.
        //
        // OpenSSL 3 has X509_build_chain() to build just the chain.
        // We may do something similar here for OpenSsl 1.1
        //
        X509_verify_cert(x509_ctx);
    }

    if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
        !(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !CertificateVerified) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Internal certificate validation failed");
        return FALSE;
    }

    if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) {
        if (Cert) {
            PortableCertificate.Length = i2d_X509(Cert, &PortableCertificate.Buffer);
            if (!PortableCertificate.Buffer) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Failed to serialize certificate context");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_OUT_OF_MEM);
                return FALSE;
            }
        }
        if (x509_ctx) {
            int ChainCount;
            STACK_OF(X509)* Chain = X509_STORE_CTX_get0_chain(x509_ctx);
            if ((ChainCount = sk_X509_num(Chain)) > 0) {
                PKCS7* p7 = PKCS7_new();
                if (p7) {
                    PKCS7_set_type(p7, NID_pkcs7_signed);
                    PKCS7_content_new(p7, NID_pkcs7_data);

                    for (int i = 0; i < ChainCount; i++) {
                        PKCS7_add_certificate(p7, sk_X509_value(Chain, i));
                    }
                    PortableChain.Length = i2d_PKCS7(p7, &PortableChain.Buffer);
                    PKCS7_free(p7);
                } else {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "Failed to allocate PKCS7 context");
                }
            }
        }
    }

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
        !TlsContext->SecConfig->Callbacks.CertificateReceived(
            TlsContext->Connection,
            (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) ? (QUIC_CERTIFICATE*)&PortableCertificate : (QUIC_CERTIFICATE*)Cert,
            (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) ? (QUIC_CERTIFICATE_CHAIN*)&PortableChain : (QUIC_CERTIFICATE_CHAIN*)x509_ctx,
            0,
            ValidationResult)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Indicate certificate received failed");
        X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REJECTED);
        status = FALSE;
    }

    if (PortableCertificate.Buffer) {
        OPENSSL_free(PortableCertificate.Buffer);
    }
    if (PortableChain.Buffer) {
        OPENSSL_free(PortableChain.Buffer);
    }

    return status;
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
                TlsContext->HkdfLabels,
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
                TlsContext->HkdfLabels,
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

    if (TlsContext->TlsSecrets != NULL) {
        TlsContext->TlsSecrets->SecretLength = (uint8_t)SecretLen;
        switch (KeyType) {
        case QUIC_PACKET_KEY_HANDSHAKE:
            CXPLAT_FRE_ASSERT(ReadSecret != NULL && WriteSecret != NULL);
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
            CXPLAT_FRE_ASSERT(ReadSecret != NULL && WriteSecret != NULL);
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
                CXPLAT_FRE_ASSERT(WriteSecret != NULL);
                memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret, WriteSecret, SecretLen);
                TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
            }
            break;
        default:
            break;
        }
    }

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
    if (TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR) {
        CXPLAT_DBG_ASSERT(CxPlatIsRandomMemoryFailureEnabled());
        return -1;
    }
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
#ifdef IS_OPENSSL_3
    _Inout_ EVP_MAC_CTX *hctx,
#else
    _Inout_ HMAC_CTX *hctx,
#endif
    _In_ int enc // Encryption or decryption
    )
{
#ifdef IS_OPENSSL_3
    OSSL_PARAM params[3];
#endif
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

#ifdef IS_OPENSSL_3
        params[0] =
            OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_KEY,
                TicketKey->Material,
                32);
        params[1] =
            OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST,
                "sha256",
                0);
        params[2] =
            OSSL_PARAM_construct_end();
         EVP_MAC_CTX_set_params(hctx, params);
#else
        HMAC_Init_ex(hctx, TicketKey->Material, 32, EVP_sha256(), NULL);
#endif
    } else {
        if (memcmp(key_name, TicketKey->Id, 16) != 0) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Ticket key_name mismatch");
            return 0; // No match
        }
#ifdef IS_OPENSSL_3
        params[0] =
            OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_KEY,
                TicketKey->Material,
                32);
        params[1] =
            OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST,
                "sha256",
                0);
        params[2] =
            OSSL_PARAM_construct_end();
         EVP_MAC_CTX_set_params(hctx, params);
#else
        HMAC_Init_ex(hctx, TicketKey->Material, 32, EVP_sha256(), NULL);
#endif
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
    _In_ SSL_SESSION *Session,
    _In_ const unsigned char *keyname,
    _In_ size_t keyname_length,
    _In_ SSL_TICKET_STATUS status,
    _In_ void *arg
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    UNREFERENCED_PARAMETER(keyname);
    UNREFERENCED_PARAMETER(keyname_length);
    UNREFERENCED_PARAMETER(arg);

    QuicTraceLogConnVerbose(
        OpenSslTickedDecrypted,
        TlsContext->Connection,
        "Session ticket decrypted, status %u",
        (uint32_t)status);

    SSL_TICKET_RETURN Result;
    if (status == SSL_TICKET_SUCCESS) {
        Result = SSL_TICKET_RETURN_USE;
    } else if (status == SSL_TICKET_SUCCESS_RENEW) {
        Result = SSL_TICKET_RETURN_USE_RENEW;
    } else {
        Result = SSL_TICKET_RETURN_IGNORE_RENEW;
    }

    uint8_t* Buffer = NULL;
    size_t Length = 0;
    if (Session != NULL &&
        SSL_SESSION_get0_ticket_appdata(Session, (void**)&Buffer, &Length)) {

        QuicTraceLogConnVerbose(
            OpenSslRecvTicketData,
            TlsContext->Connection,
            "Received ticket data, %u bytes",
            (uint32_t)Length);

        if (!TlsContext->SecConfig->Callbacks.ReceiveTicket(
                TlsContext->Connection,
                (uint32_t)Length,
                Buffer)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ReceiveTicket failed");
            if (status == SSL_TICKET_SUCCESS_RENEW) {
                Result = SSL_TICKET_RETURN_IGNORE_RENEW;
            } else {
                Result = SSL_TICKET_RETURN_IGNORE;
            }
        }
    }

    return Result;
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
    QUIC_CREDENTIAL_FLAGS CredConfigFlags = CredConfig->Flags;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not supported by this TLS implementation
    }

#ifdef CX_PLATFORM_USES_TLS_BUILTIN_CERTIFICATE
    CredConfigFlags |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
#endif

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !(CredConfigFlags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED)) {
        return QUIC_STATUS_INVALID_PARAMETER; // Defer validation without indication doesn't make sense.
    }

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) &&
        (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

#ifdef CX_PLATFORM_DARWIN
    if (((CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) == 0) &&
        (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
#endif

    if (CredConfig->Reserved != NULL) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and should be NULL.
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
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_NONE) {
        if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
            return QUIC_STATUS_INVALID_PARAMETER; // Required for server
        }
    } else {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES &&
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
    X509* X509Cert = NULL;
    EVP_PKEY* PrivateKey = NULL;
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
    SecurityConfig->Flags = CredConfigFlags;
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
    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
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

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) &&
        !(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
        SSL_CTX_set_session_cache_mode(
            SecurityConfig->SSLCtx,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(
            SecurityConfig->SSLCtx,
            CxPlatTlsOnClientSessionTicketReceived);
    }

    if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
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

            Ret = SSL_CTX_set_session_ticket_cb(
                SecurityConfig->SSLCtx,
                NULL,
                CxPlatTlsOnServerSessionTicketDecrypted,
                NULL);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_set_session_ticket_cb failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

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

    //
    // Set the certs.
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
    } else if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        BIO* Bio = BIO_new(BIO_s_mem());
        PKCS12 *Pkcs12 = NULL;
        const char* Password = NULL;
        char PasswordBuffer[PFX_PASSWORD_LENGTH];

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

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
            Password = CredConfig->CertificatePkcs12->PrivateKeyPassword;
            Ret =
                BIO_write(
                    Bio,
                    CredConfig->CertificatePkcs12->Asn1Blob,
                    CredConfig->CertificatePkcs12->Asn1BlobLength);
            if (Ret < 0) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "BIO_write failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            uint8_t* PfxBlob = NULL;
            uint32_t PfxSize = 0;
            CxPlatRandom(sizeof(PasswordBuffer), PasswordBuffer);

            //
            // Fixup password to printable characters
            //
            for (uint32_t idx = 0; idx < sizeof(PasswordBuffer); ++idx) {
                PasswordBuffer[idx] = ((uint8_t)PasswordBuffer[idx] % 94) + 32;
            }
            PasswordBuffer[PFX_PASSWORD_LENGTH - 1] = 0;
            Password = PasswordBuffer;

            Status =
                CxPlatCertExtractPrivateKey(
                    CredConfig,
                    PasswordBuffer,
                    &PfxBlob,
                    &PfxSize);
            if (QUIC_FAILED(Status)) {
                goto Exit;
            }

            Ret = BIO_write(Bio, PfxBlob, PfxSize);
            CXPLAT_FREE(PfxBlob, QUIC_POOL_TLS_PFX);
            if (Ret < 0) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "BIO_write failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

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

        STACK_OF(X509) *CaCertificates = NULL;
        Ret =
            PKCS12_parse(Pkcs12, Password, &PrivateKey, &X509Cert, &CaCertificates);
        if (CaCertificates) {
            X509* CaCert;
            while ((CaCert = sk_X509_pop(CaCertificates)) != NULL) {
                //
                // This transfers ownership to SSLCtx and CaCert does not need to be freed.
                //
                SSL_CTX_add_extra_chain_cert(SecurityConfig->SSLCtx, CaCert);
            }
            sk_X509_free(CaCertificates);
        }
        if (Pkcs12) {
            PKCS12_free(Pkcs12);
        }
        if (Password == PasswordBuffer) {
            CxPlatZeroMemory(PasswordBuffer, sizeof(PasswordBuffer));
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
    }

    if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
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
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        SSL_CTX_set_cert_verify_callback(SecurityConfig->SSLCtx, CxPlatTlsCertificateVerifyCallback, NULL);
        SSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER, NULL);
        if (!(CredConfigFlags & (QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION | QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION))) {
            SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);
        }

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

        if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED ||
            CredConfigFlags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            SSL_CTX_set_cert_verify_callback(
                SecurityConfig->SSLCtx,
                CxPlatTlsCertificateVerifyCallback,
                NULL);
        }

        if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            int VerifyMode = SSL_VERIFY_PEER;
            if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
                SSL_CTX_set_verify_depth(
                    SecurityConfig->SSLCtx,
                    CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);
            }
            if (!(CredConfigFlags & (QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION))) {
                VerifyMode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            SSL_CTX_set_verify(
                SecurityConfig->SSLCtx,
                VerifyMode,
                NULL);
        }

        SSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx, CxPlatTlsAlpnSelectCallback, NULL);

        SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, UINT32_MAX);
        SSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx, CxPlatTlsClientHelloCallback, NULL);
    }

    //
    // Invoke completion inline.
    //

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
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

#ifdef IS_OPENSSL_3
    SSL_CTX_set_tlsext_ticket_key_evp_cb(
        SecurityConfig->SSLCtx,
        CxPlatTlsOnSessionTicketKeyNeeded);
#else
    SSL_CTX_set_tlsext_ticket_key_cb(
        SecurityConfig->SSLCtx,
        CxPlatTlsOnSessionTicketKeyNeeded);
#endif

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

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);

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
    TlsContext->HkdfLabels = Config->HkdfLabels;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->TlsSecrets = Config->TlsSecrets;

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
void
CxPlatTlsUpdateHkdfLabels(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ const QUIC_HKDF_LABELS* const Labels
    )
{
    TlsContext->HkdfLabels = Labels;
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
            OpenSslSendTicketData,
            TlsContext->Connection,
            "Sending ticket data, %u bytes",
            *BufferLength);

        SSL_SESSION* Session = SSL_get_session(TlsContext->Ssl);
        if (Session == NULL) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "SSL_get_session failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
        if (!SSL_SESSION_set1_ticket_appdata(Session, Buffer, *BufferLength)) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "SSL_SESSION_set1_ticket_appdata failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        if (!SSL_new_session_ticket(TlsContext->Ssl)) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "SSL_new_session_ticket failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        int Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret != 1) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                SSL_get_error(TlsContext->Ssl, Ret),
                "SSL_do_handshake failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

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
#ifdef IS_OPENSSL_3
                ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), buf, sizeof(buf));
#else
                ERR_error_string_n(ERR_get_error_line(&file, &line), buf, sizeof(buf));
#endif
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
        } else if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
            !TlsContext->PeerCertReceived) {
            QUIC_STATUS ValidationResult =
                (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
                (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
                TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION)) ?
                    QUIC_STATUS_CERT_NO_CERT :
                    QUIC_STATUS_SUCCESS;

            if (!TlsContext->SecConfig->Callbacks.CertificateReceived(
                    TlsContext->Connection,
                    NULL,
                    NULL,
                    0,
                    ValidationResult)) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Indicate null certificate received failed");
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                TlsContext->State->AlertCode = CXPLAT_TLS_ALERT_CODE_REQUIRED_CERTIFICATE;
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
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;

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
QUIC_STATUS
CxPlatSecConfigParamSet(
    _In_ CXPLAT_SEC_CONFIG* TlsContext,
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

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamGet(
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* SecConfig,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(SecConfig);
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
        case QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256:
            HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_CHACHA20;
            HandshakeInfo->CipherStrength = 256; // TODO - Is this correct?
            HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_256;
            break;
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
            if (NegotiatedAlpnLen == 0) {
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
