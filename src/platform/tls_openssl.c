/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling OpenSSL.

--*/

#include "platform_internal.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/pem.h"

#ifdef QUIC_LOGS_WPP
#include "tls_openssl.tmh"
#endif

uint16_t QuicTlsTPHeaderSize = 0;

//
// TLS session object.
//

typedef struct QUIC_TLS_SESSION {

    //
    // AlpnBufferLength - The length of ALPN buffer.
    // AlpnBuffer - Stores the Alpn Length in its first byte followed by the
    // ALPN.
    //

    uint16_t AlpnBufferLength;
    unsigned char AlpnBuffer[0];

} QUIC_TLS_SESSION;

//
// The QUIC sec config object. Created once per listener on server side and
// once per connection on client side.
//

typedef struct QUIC_SEC_CONFIG {
    //
    // The sec config rundown object passed by MsQuic during sec config
    // creation.
    //

    QUIC_RUNDOWN_REF* CleanupRundown;

    //
    // Ref count.
    //

    long RefCount;

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
    // TlsSession - The TLS session object that this context belong to.
    //

    QUIC_TLS_SESSION* TlsSession;

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

} QUIC_TLS;

//
// Represents a packet payload protection key.
//

typedef struct QUIC_KEY {
    //
    // The cipher to use for encryption/decryption.
    //

    const EVP_CIPHER *Aead;

    //
    // Buffer and Buffer length of the key.
    //

    size_t BufferLen;
    uint8_t Buffer[64];

} QUIC_KEY;

//
// Represents a hash.
//

typedef struct QUIC_HASH {
    //
    // The message digest.
    //

    const EVP_MD *Md;

    //
    // Salt and salt length.
    //

    uint32_t SaltLength;
    uint8_t Salt[QUIC_VERSION_SALT_LENGTH];

} QUIC_HASH;

//
// Represents a packet header protection key.
//

typedef struct QUIC_HP_KEY {
    //
    // The cipher to use for encryption/decryption.
    //
    const EVP_CIPHER *Aead;

    //
    // Buffer and BufferLen of the key.
    //
    int BufferLen;
    uint8_t Buffer[64];

} QUIC_HP_KEY;

//
// Default list of Cipher used.
//

#define QUIC_TLS_DEFAULT_SSL_CIPHERS    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

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

static
int
QuicTlsAlpnSelectCallback(
    _In_ SSL *Ssl,
    _Out_writes_bytes_(Outlen) const unsigned char **Out,
    _Out_ unsigned char *OutLen,
    _In_reads_bytes_(Inlen) const unsigned char *In,
    _In_ unsigned int InLen,
    _In_ void *Arg
    );

static
QUIC_STATUS
QuicAllocatePacketKey(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ BOOLEAN AllocHpKey,
    _Outptr_ QUIC_PACKET_KEY** Key
    );

static
QUIC_STATUS
QuicTlsKeyCreate(
    _Inout_ QUIC_TLS* TlsContext,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ QUIC_PACKET_KEY_TYPE QuicKeyType,
    _Out_ QUIC_PACKET_KEY** QuicKey
    );

static
void
QuicTlsKeySetAead(
    _In_ QUIC_AEAD_TYPE AeadType,
    _Out_ QUIC_PACKET_KEY* Key
    );

static
const EVP_MD *
QuicTlsKeyGetMd(
    _In_ QUIC_HASH_TYPE HashType
    );

static
void
QuicTlsNegotiatedCiphers(
    _In_ QUIC_TLS* TlsContext,
    _Out_ QUIC_AEAD_TYPE *AeadType,
    _Out_ QUIC_HASH_TYPE *HashType
    );

static
BOOLEAN
QuicTlsHdkfExpand(
    _Out_writes_bytes_(KeyLen) uint8_t *Key,
    _In_ size_t KeyLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_reads_bytes_(InfoLen) const uint8_t *Info,
    _In_ size_t InfoLen,
    _In_ const EVP_MD *Md
    );

static
BOOLEAN
QuicTlsHkdfExpandLabel(
    _Out_writes_bytes_(KeyLen) uint8_t *Key,
    _In_ size_t KeyLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_z_ const char* const Label,
    _In_ const EVP_MD *Md
    );

static
void
QuicTlsHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLen,
    _Out_writes_all_(4 + QUIC_HKDF_PREFIX_LEN + strlen(Label)) uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    );

static
QUIC_STATUS
QuicTlsDerivePacketProtectionKey(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    );

static
QUIC_STATUS
QuicTlsDerivePacketProtectionIv(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    );

static
QUIC_STATUS
QuicTlsDeriveHeaderProtectionKey(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    );

static
BOOLEAN
QuicTlsDeriveClientInitialSecret(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen
    );

static
BOOLEAN
QuicTlsDeriveServerInitialSecret(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen
    );

static
QUIC_STATUS
QuicTlsUpdateTrafficSecret(
    _Out_writes_bytes_(SecretLen) const uint8_t *NewSecret,
    _In_reads_bytes_(SecretLen) const uint8_t *OldSecret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md
    );

static
BOOLEAN
QuicTlsHkdfExtract(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_reads_(SaltLen) const uint8_t *Salt,
    _In_ size_t SaltLen,
    _In_ const EVP_MD *Md
    );

static
size_t
QuicTlsAeadTagLength(
    _In_ const EVP_CIPHER *Aead
    );

static
int
QuicTlsEncrypt(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(PlainTextLen) const uint8_t *PlainText,
    _In_ size_t PlainTextLen,
    _In_reads_bytes_(KeyLen) const uint8_t *Key,
    _In_ size_t KeyLen,
    _In_reads_bytes_(NonceLen) const uint8_t *Nonce,
    _In_ size_t NonceLen,
    _In_reads_bytes_(AuthDataLen) const uint8_t *Authdata,
    _In_ size_t AuthDataLen,
    _In_ const EVP_CIPHER *Aead
    );

static
int
QuicTlsDecrypt(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(CipherTextLen) const uint8_t *CipherText,
    _In_ size_t CipherTextLen,
    _In_reads_bytes_(KeyLen) const uint8_t *Key,
    _In_ size_t KeyLen,
    _In_reads_bytes_(NonceLen) const uint8_t *Nonce,
    _In_ size_t NonceLen,
    _In_reads_bytes_(AuthDataLen) const uint8_t *AuthData,
    _In_ size_t AuthDataLen,
    _In_ const EVP_CIPHER *Aead
    );

static
BOOLEAN
QuicTlsHeaderMask(
    _Out_writes_bytes_(5) uint8_t *OutputBuffer,
    _In_reads_bytes_(keylen) const uint8_t *Key,
    _In_ size_t keylen,
    _In_reads_bytes_(16) const uint8_t *Sample,
    _In_ const EVP_CIPHER *Aead
    );

static
BOOLEAN
QuicTlsHash(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_reads_bytes_(SaltLen) const uint8_t *Salt,
    _In_ size_t SaltLen,
    _In_ QUIC_HASH *Hash
    );

static
void
QuicTlsSecConfigDelete(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    );

static
char
GetTlsIdentifier(
    _In_ const QUIC_TLS* TlsContext
    )
{
    const char IDs[2] = { 'C', 'S' };
    return IDs[TlsContext->IsServer];
}

QUIC_STATUS
QuicTlsLibraryInitialize(
    void
    )
{
    int Ret = 0;

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        QuicTraceLogError("[ tls] OPENSSL_init_ssl failed.");
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
    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);
    unsigned char *Ptr = NULL;
    unsigned char *End = NULL;

    UNREFERENCED_PARAMETER(Arg);

    for (Ptr = (unsigned char *)In, End = (unsigned char *)In + InLen;
        Ptr + TlsContext->TlsSession->AlpnBufferLength <= End;
        Ptr += *Ptr + 1) {
        if (memcmp(
                Ptr,
                TlsContext->TlsSession->AlpnBuffer,
                TlsContext->TlsSession->AlpnBufferLength) == 0) {
            *Out = Ptr + 1;
            *OutLen = *Ptr;
            return SSL_TLSEXT_ERR_OK;
        }
    }

    QuicTraceLogError("[ tls] Client did not present correct ALPN");

    return SSL_TLSEXT_ERR_NOACK;
}

QUIC_STATIC_ASSERT((int)ssl_encryption_initial == (int)QUIC_PACKET_KEY_INITIAL, "Code assumes exact match!");
QUIC_STATIC_ASSERT((int)ssl_encryption_early_data == (int)QUIC_PACKET_KEY_0_RTT, "Code assumes exact match!");
QUIC_STATIC_ASSERT((int)ssl_encryption_handshake == (int)QUIC_PACKET_KEY_HANDSHAKE, "Code assumes exact match!");
QUIC_STATIC_ASSERT((int)ssl_encryption_application == (int)QUIC_PACKET_KEY_1_RTT, "Code assumes exact match!");

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

    QuicTraceLogVerbose("[ tls][%p][%c] New encryption secrets (Level = %u).",
        TlsContext, GetTlsIdentifier(TlsContext), Level);

    QUIC_DBG_ASSERT(TlsState->WriteKeys[KeyType] == NULL);
    Status =
        QuicTlsKeyCreate(
            TlsContext,
            WriteSecret,
            SecretLen,
            KeyType,
            &TlsState->WriteKeys[KeyType]);
    if (QUIC_FAILED(Status)) {
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
        return -1;
    }

    TlsState->WriteKey = KeyType;
    TlsContext->ResultFlags |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;

    QUIC_DBG_ASSERT(TlsState->ReadKeys[KeyType] == NULL);
    Status =
        QuicTlsKeyCreate(
            TlsContext,
            ReadSecret,
            SecretLen,
            KeyType,
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

    return 1;
}

int
QuicTlsAddHandshakeDataCallback(
    _In_ SSL *Ssl,
    _In_ OSSL_ENCRYPTION_LEVEL Level,
    _In_reads_(len) const uint8_t *Data,
    _In_ size_t Length
    )
{
    QUIC_TLS* TlsContext = SSL_get_app_data(Ssl);
    QUIC_TLS_PROCESS_STATE* TlsState = TlsContext->State;

    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)Level;
    QUIC_DBG_ASSERT(TlsState->WriteKeys[KeyType] != NULL);

    QuicTraceLogVerbose("[ tls][%p][%c] Sending %llu handshake bytes (Level = %u).",
        TlsContext, GetTlsIdentifier(TlsContext), Length, Level);

    if (Length + TlsState->BufferLength > (size_t)TlsState->BufferAllocLength) {
        QuicTraceLogError("[ tls][%p][%c] Buffer overflow for output handshake data.",
            TlsContext, GetTlsIdentifier(TlsContext));
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
        return -1;
    }

    switch (KeyType) {
    case QUIC_PACKET_KEY_HANDSHAKE:
        if (TlsState->BufferOffsetHandshake == 0) {
            TlsState->BufferOffsetHandshake = TlsState->BufferTotalLength;
            QuicTraceLogInfo("[ tls][%p][%c] Writing Handshake data starts at %u.",
                TlsContext, GetTlsIdentifier(TlsContext), TlsState->BufferOffsetHandshake);
        }
        break;
    case QUIC_PACKET_KEY_1_RTT:
        if (TlsState->BufferOffset1Rtt == 0) {
            TlsState->BufferOffset1Rtt = TlsState->BufferTotalLength;
            QuicTraceLogInfo("[ tls][%p][%c] Writing 1-RTT data starts at %u.",
                TlsContext, GetTlsIdentifier(TlsContext), TlsState->BufferOffset1Rtt);
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

    QuicTraceLogError("[ tls][%p][%c] Send alert = %u (Level = %u).",
        TlsContext, GetTlsIdentifier(TlsContext), Alert, Level);

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

    if (!TlsContext->ReceiveTPCallback(
            TlsContext->Connection,
            (uint16_t)TransportParamLen,
            TransportParams)) {
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
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
QuicTlsServerSecConfigCreate(
    _Inout_ QUIC_RUNDOWN_REF* Rundown,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    QUIC_SEC_CONFIG* SecurityConfig = NULL;
    QUIC_CERTIFICATE_FILE* CertFile = Certificate;
    uint32_t SSLOpts = 0;

    //
    // We only allow PEM formatted cert files.
    //

    if (Flags != QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE) {
        QuicTraceLogError("[ tls] Invalid flags: %lu.", Flags);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (CertFile == NULL) {
        QuicTraceLogError("[ tls] CertFile unspecified.");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (!QuicRundownAcquire(Rundown)) {
        QuicTraceLogError("[ tls] Failed to acquire sec config rundown.");
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    //
    // Create a security config.
    //

    SecurityConfig = QuicAlloc(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        QuicTraceLogError("[ tls] Security config allocation failure.");
        QuicRundownRelease(Rundown);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    SecurityConfig->CleanupRundown = Rundown;

    //
    // Initial ref.
    //

    SecurityConfig->RefCount = 1;

    //
    // Create the a SSL context for the security config.
    //

    SecurityConfig->SSLCtx = SSL_CTX_new(TLS_method());
    if (SecurityConfig->SSLCtx == NULL) {
        QuicTraceLogError("[ tls] SSL_CTX_new failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    //
    // Configure the SSL context with the defaults.
    //

    SSLOpts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
               SSL_OP_SINGLE_ECDH_USE |
               SSL_OP_CIPHER_SERVER_PREFERENCE |
               SSL_OP_NO_ANTI_REPLAY;

    SSL_CTX_set_options(SecurityConfig->SSLCtx, SSLOpts);
    SSL_CTX_clear_options(SecurityConfig->SSLCtx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    Ret =
        SSL_CTX_set_ciphersuites(
            SecurityConfig->SSLCtx,
            QUIC_TLS_DEFAULT_SSL_CIPHERS);
    if (Ret != 1) {
        QuicTraceLogError("[ tls] SSL_CTX_set_ciphersuites failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set1_groups_list(
            SecurityConfig->SSLCtx,
            QUIC_TLS_DEFAULT_SSL_CURVES);
    if (Ret != 1) {
        QuicTraceLogError("[ tls] SSL_CTX_set1_groups_list failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    SSL_CTX_set_mode(SecurityConfig->SSLCtx, SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_set_min_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);

    SSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx, QuicTlsAlpnSelectCallback, NULL);

    SSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);

    //
    // Set the server certs.
    //

    Ret =
        SSL_CTX_use_PrivateKey_file(
            SecurityConfig->SSLCtx,
            CertFile->PrivateKeyFile,
            SSL_FILETYPE_PEM);
    if (Ret != 1) {
        QuicTraceLogError("[ tls] SSL_CTX_use_PrivateKey_file failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_use_certificate_chain_file(
            SecurityConfig->SSLCtx,
            CertFile->CertificateFile);
    if (Ret != 1) {
      QuicTraceLogError("[ tls] SSL_CTX_use_certificate_chain_file failed, error: %ld", ERR_get_error());
      Status = QUIC_STATUS_TLS_ERROR;
      goto Exit;
    }

    Ret = SSL_CTX_check_private_key(SecurityConfig->SSLCtx);
    if (Ret != 1) {
      QuicTraceLogError("TLS: SSL_CTX_check_private_key failed, error: %ld", ERR_get_error());
      Status = QUIC_STATUS_TLS_ERROR;
      goto Exit;
    }

    SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, UINT32_MAX);
    SSL_CTX_set_quic_method(SecurityConfig->SSLCtx, &OpenSslQuicCallbacks);
    SSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx, QuicTlsClientHelloCallback, NULL);

    //
    // Invoke completion inline.
    //

    CompletionHandler(Context, Status, SecurityConfig);

    Status = QUIC_STATUS_SUCCESS;
    SecurityConfig = NULL;

Exit:

    if (SecurityConfig != NULL) {
        QuicTlsSecConfigDelete(SecurityConfig);
        SecurityConfig = NULL;
    }

    return Status;
}

static
void
QuicTlsSecConfigDelete(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    QUIC_RUNDOWN_REF* Rundown = SecurityConfig->CleanupRundown;

    if (SecurityConfig->SSLCtx != NULL) {
        SSL_CTX_free(SecurityConfig->SSLCtx);
        SecurityConfig->SSLCtx = NULL;
    }

    QuicFree(SecurityConfig);
    SecurityConfig = NULL;

    if (Rundown != NULL) {
        QuicRundownRelease(Rundown);
        Rundown = NULL;
    }
}

QUIC_STATUS
QuicTlsClientSecConfigCreate(
    _In_ uint32_t Flags,
    _Outptr_ QUIC_SEC_CONFIG** ClientConfig
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    QUIC_SEC_CONFIG* SecurityConfig = NULL;

    //
    // Create a security config.
    //

    SecurityConfig = QuicAlloc(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        QuicTraceLogError("[ tls] SecurityConfig alloc failed.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(SecurityConfig, sizeof(*SecurityConfig));
    SecurityConfig->RefCount = 1;

    //
    // Create a SSL context for the security config.
    // LINUX_TODO: Check if it's better to make this context global and shared
    // across all client connections.
    //

    SecurityConfig->SSLCtx = SSL_CTX_new(TLS_method());
    if (SecurityConfig->SSLCtx == NULL) {
        QuicTraceLogError("[ tls] SSL_CTX_new failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    //
    // Configure the SSL defaults.
    //

    SSL_CTX_set_min_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);

    SSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);

    Ret =
        SSL_CTX_set_ciphersuites(
            SecurityConfig->SSLCtx,
            QUIC_TLS_DEFAULT_SSL_CIPHERS);
    if (Ret != 1) {
        QuicTraceLogError("[ tls] SSL_CTX_set_ciphersuites failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set1_groups_list(
            SecurityConfig->SSLCtx,
            QUIC_TLS_DEFAULT_SSL_CURVES);
    if (Ret != 1) {
        QuicTraceLogError("[ tls] SSL_CTX_set1_groups_list failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    SSL_CTX_set_quic_method(SecurityConfig->SSLCtx, &OpenSslQuicCallbacks);

    //
    // Cert related config.
    //

    BOOLEAN VerifyServerCertificate = TRUE; // !(Flags & QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION);
    if (!VerifyServerCertificate) {
        SSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, QUIC_TLS_DEFAULT_VERIFY_DEPTH);

        if (QuicOpenSslClientTrustedCert == NULL) {
            SSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);
        } else {
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
                QuicTraceLogError("[ tls] SSL_CTX_load_verify_locations failed, error: %ld", ERR_get_error());
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }*/
        }
    }

    *ClientConfig = SecurityConfig;
    SecurityConfig = NULL;

Exit:

    if (SecurityConfig != NULL) {
        QuicTlsSecConfigDelete(SecurityConfig);
        SecurityConfig = NULL;
    }

    return Status;
}

inline
QUIC_SEC_CONFIG*
QuicTlsSecConfigAddRef(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    InterlockedIncrement(&SecurityConfig->RefCount);
    return SecurityConfig;
}

void
QUIC_API
QuicTlsSecConfigRelease(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    if (InterlockedDecrement(&SecurityConfig->RefCount) == 0) {
        QuicTlsSecConfigDelete(SecurityConfig);
        SecurityConfig = NULL;
    }
}

QUIC_STATUS
QuicTlsSessionInitialize(
    _In_z_ const char* ALPN,
    _Out_ QUIC_TLS_SESSION** NewTlsSession
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_TLS_SESSION* TlsSession = NULL;
    size_t ALPNLength = strlen(ALPN);

    if (ALPNLength > QUIC_MAX_ALPN_LENGTH) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    TlsSession = QuicAlloc(sizeof(QUIC_TLS_SESSION) + ALPNLength + 1);
    if (TlsSession == NULL) {
        QuicTraceLogWarning("[ tls] Failed to allocate QUIC_TLS_SESSION.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    //
    // Copy over the ALPN length followed by the ALPN into the ALPN buffer.
    //

    TlsSession->AlpnBuffer[0] = (unsigned char)ALPNLength;
    QuicCopyMemory((char*)&TlsSession->AlpnBuffer[1], ALPN, ALPNLength);
    TlsSession->AlpnBufferLength = (uint16_t)ALPNLength + 1;

    *NewTlsSession = TlsSession;
    TlsSession = NULL;

Exit:

    if (TlsSession != NULL) {
        QUIC_FREE(TlsSession);
        TlsSession = NULL;
    }

    return Status;
}

void
QuicTlsSessionUninitialize(
    _In_opt_ QUIC_TLS_SESSION* TlsSession
    )
{
    if (TlsSession != NULL) {
        QUIC_FREE(TlsSession);
        TlsSession = NULL;
    }
}

QUIC_STATUS
QuicTlsSessionSetTicketKey(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_reads_bytes_(44)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsSession);
    UNREFERENCED_PARAMETER(Buffer);
    //
    // LINUX_TODO.
    //
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicTlsSessionAddTicket(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsSession);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    //
    // LINUX_TODO.
    //
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicTlsInitialize(
    _In_ const QUIC_TLS_CONFIG* Config,
    _Out_ QUIC_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_TLS* TlsContext = NULL;
    uint16_t ServerNameLength = 0;

    TlsContext = QuicAlloc(sizeof(QUIC_TLS));
    if (TlsContext == NULL) {
        QuicTraceLogError("[ tls] Failed to allocate TLS context.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(TlsContext, sizeof(QUIC_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->TlsSession = Config->TlsSession;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = QuicTlsSecConfigAddRef(Config->SecConfig);
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;

    QuicTraceLogVerbose("[ tls][%p][%c] Created.", TlsContext, GetTlsIdentifier(TlsContext));

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

            ServerNameLength = (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);

            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                QuicTraceLogError("[ tls][%p][%c] Invalid / Too long server name!", TlsContext, GetTlsIdentifier(TlsContext));
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI = QuicAlloc(ServerNameLength + 1);

            if (TlsContext->SNI == NULL) {
                QuicTraceLogError("[ tls][%p][%c] Failed to allocate SNI.", TlsContext, GetTlsIdentifier(TlsContext));
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
        QuicTraceLogError("[ tls][%p][%c] Failed to allocate Ssl object.", TlsContext, GetTlsIdentifier(TlsContext));
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
        SSL_set_alpn_protos(
            TlsContext->Ssl,
            Config->TlsSession->AlpnBuffer,
            Config->TlsSession->AlpnBufferLength);
    }

    if (SSL_set_quic_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        QuicTraceLogError("[ tls][%p][%c] Failed to set TP.", TlsContext, GetTlsIdentifier(TlsContext));
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
    QUIC_FREE(Config->LocalTPBuffer);

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
        QuicTraceLogVerbose("[ tls][%p][%c] Cleaning up.", TlsContext, GetTlsIdentifier(TlsContext));

        if (TlsContext->SecConfig != NULL) {
            QuicTlsSecConfigRelease(TlsContext->SecConfig);
            TlsContext->SecConfig = NULL;
        }

        if (TlsContext->SNI != NULL) {
            QUIC_FREE(TlsContext->SNI);
            TlsContext->SNI = NULL;
        }

        if (TlsContext->Ssl != NULL) {
            SSL_free(TlsContext->Ssl);
            TlsContext->Ssl = NULL;
        }

        QUIC_FREE(TlsContext);
        TlsContext = NULL;
    }
}

void
QuicTlsReset(
    _In_ QUIC_TLS* TlsContext
    )
{
    QuicTraceLogInfo("[ tls][%p][%c] Resetting TLS state.", TlsContext, GetTlsIdentifier(TlsContext));

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
        QuicTraceLogError("[ tls][%p][%c] Failed to allocate Ssl object.", TlsContext, GetTlsIdentifier(TlsContext));
        QUIC_DBG_ASSERT(FALSE);
        goto Exit;
    }

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    SSL_set_connect_state(TlsContext->Ssl);
    SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
    SSL_set_alpn_protos(
        TlsContext->Ssl,
        TlsContext->TlsSession->AlpnBuffer,
        TlsContext->TlsSession->AlpnBufferLength);

    /* TODO - Figure out if this is necessary.
    if (SSL_set_quic_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        QuicTraceLogError("[ tls][%p][%c] Failed to set TP.", TlsContext, GetTlsIdentifier(TlsContext));
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }*/

Exit:

    return;
}

QUIC_SEC_CONFIG*
QuicTlsGetSecConfig(
    _In_ QUIC_TLS* TlsContext
    )
{
    return QuicTlsSecConfigAddRef(TlsContext->SecConfig);
}

QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ QUIC_TLS* TlsContext,
    _In_reads_bytes_(*BufferLength) const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
{
    int Ret = 0;
    int Err = 0;

    QUIC_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    if (*BufferLength != 0) {
        QuicTraceLogVerbose("[ tls][%p][%c] Processing %u received bytes.",
            TlsContext, GetTlsIdentifier(TlsContext), *BufferLength);
    }

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (SSL_provide_quic_data(
            TlsContext->Ssl,
            TlsContext->State->ReadKey,
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
                QuicTraceLogError("[ tls][%p][%c] TLS handshake error: %s.",
                    TlsContext, GetTlsIdentifier(TlsContext), ERR_error_string(ERR_get_error(), NULL));
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;

            default:
                QuicTraceLogError("[ tls][%p][%c] TLS handshake error: %d.",
                    TlsContext, GetTlsIdentifier(TlsContext), Err);
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        QuicTraceLogInfo("[ tls][%p][%c] Handshake complete.", TlsContext, GetTlsIdentifier(TlsContext));
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
                QuicTraceLogError("[ tls][%p][%c] No transport parameters received",
                    TlsContext, GetTlsIdentifier(TlsContext));
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
            QuicTraceLogError("[ tls][%p][%c] TLS handshake error: %s.",
                TlsContext, GetTlsIdentifier(TlsContext), ERR_error_string(ERR_get_error(), NULL));
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
            goto Exit;

        default:
            QuicTraceLogError("[ tls][%p][%c] TLS handshake error: %d.",
                TlsContext, GetTlsIdentifier(TlsContext), Err);
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
            goto Exit;
        }
    }

Exit:

    return TlsContext->ResultFlags;
}

QUIC_TLS_RESULT_FLAGS
QuicTlsProcessDataComplete(
    _In_ QUIC_TLS* TlsContext,
    _Out_ uint32_t * BufferConsumed
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferConsumed);
    return QUIC_TLS_RESULT_ERROR;
}

QUIC_STATUS
QuicTlsReadTicket(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_INVALID_STATE;
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

QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(QUIC_VERSION_SALT_LENGTH) const uint8_t* const Salt,
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength) const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** ReadKey,
    _Out_opt_ QUIC_PACKET_KEY** WriteKey
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempReadKey = NULL;
    QUIC_PACKET_KEY *TempWriteKey = NULL;
    uint8_t InitialSecret[QUIC_HASH_SHA256_SIZE] = {0};
    uint8_t Secret[QUIC_HASH_SHA256_SIZE] = {0};

    if (WriteKey != NULL) {
        Status = QuicAllocatePacketKey(QUIC_PACKET_KEY_INITIAL, TRUE, &TempWriteKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] Key alloc failure.");
            goto Exit;
        }

        TempWriteKey->PacketKey->Aead = EVP_aes_128_gcm();
        TempWriteKey->HeaderKey->Aead = EVP_aes_128_ctr();

        if (!QuicTlsHkdfExtract(
                InitialSecret,
                sizeof(InitialSecret),
                CID,
                CIDLength,
                Salt,
                QUIC_VERSION_SALT_LENGTH,
                EVP_sha256())) {
            QuicTraceLogError("[ tls] QuicTlsHkdfExtract failed.");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        if (IsServer) {
            if (!QuicTlsDeriveServerInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                QuicTraceLogError("[ tls] QuicTlsDeriveServerInitialSecret failed.");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            if (!QuicTlsDeriveClientInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                QuicTraceLogError("[ tls] QuicTlsDeriveClientInitialSecret failed.");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

        Status =
            QuicTlsDerivePacketProtectionKey(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempWriteKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionKey failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDerivePacketProtectionIv(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempWriteKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionIv failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDeriveHeaderProtectionKey(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempWriteKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] QuicTlsDeriveHeaderProtectionKey failed. error: %ld", Status);
            goto Exit;
        }
    }

    if (ReadKey != NULL) {
        Status = QuicAllocatePacketKey(QUIC_PACKET_KEY_INITIAL, TRUE, &TempReadKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] Key alloc failure.");
            goto Exit;
        }

        TempReadKey->PacketKey->Aead = EVP_aes_128_gcm();
        TempReadKey->HeaderKey->Aead = EVP_aes_128_ctr();

        if (!QuicTlsHkdfExtract(
                InitialSecret,
                sizeof(InitialSecret),
                CID,
                CIDLength,
                Salt,
                QUIC_VERSION_SALT_LENGTH,
                EVP_sha256())) {
            QuicTraceLogError("[ tls] QuicTlsHkdfExtract failed.");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        if (IsServer) {
            if (!QuicTlsDeriveClientInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                QuicTraceLogError("[ tls] QuicTlsDeriveClientInitialSecret failed.");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            if (!QuicTlsDeriveServerInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                QuicTraceLogError("[ tls] QuicTlsDeriveServerInitialSecret failed.");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

        Status =
            QuicTlsDerivePacketProtectionKey(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempReadKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionKey failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDerivePacketProtectionIv(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempReadKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionIv failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDeriveHeaderProtectionKey(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempReadKey);

        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("[ tls] QuicTlsDeriveHeaderProtectionKey failed. error: %ld", Status);
            goto Exit;
        }
    }

    if (ReadKey != NULL) {
        *ReadKey = TempReadKey;
        TempReadKey = NULL;
    }

    if (WriteKey != NULL) {
        *WriteKey = TempWriteKey;
        TempWriteKey = NULL;
    }

Exit:

    QuicPacketKeyFree(TempReadKey);
    QuicPacketKeyFree(TempWriteKey);

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
        QUIC_FREE(Key);
    }
}

QUIC_STATUS
QuicPacketKeyUpdate(
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempKey = NULL;
    size_t SecretLen = 0;

    QUIC_FRE_ASSERT(OldKey->Type == QUIC_PACKET_KEY_1_RTT);

    Status = QuicAllocatePacketKey(QUIC_PACKET_KEY_1_RTT, FALSE, &TempKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] Key alloc failure");
        goto Exit;
    }

    TempKey->Type = OldKey->Type;
    TempKey->PacketKey->Aead = OldKey->PacketKey->Aead;

    TempKey->TrafficSecret[0].Aead = OldKey->TrafficSecret[0].Aead;
    TempKey->TrafficSecret[0].Hash = OldKey->TrafficSecret[0].Hash;

    SecretLen = QuicHashLength(OldKey->TrafficSecret[0].Hash);

    Status =
        QuicTlsUpdateTrafficSecret(
            TempKey->TrafficSecret[0].Secret,
            OldKey->TrafficSecret[0].Secret,
            SecretLen,
            QuicTlsKeyGetMd(OldKey->TrafficSecret[0].Hash));
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] QuicTlsUpdateTrafficSecret failed. error: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDerivePacketProtectionKey(
            TempKey->TrafficSecret[0].Secret,
            SecretLen,
            QuicTlsKeyGetMd(OldKey->TrafficSecret[0].Hash),
            TempKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionKey failed. error: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDerivePacketProtectionIv(
            TempKey->TrafficSecret[0].Secret,
            SecretLen,
            QuicTlsKeyGetMd(OldKey->TrafficSecret[0].Hash),
            TempKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionIv failed. error: %ld", Status);
        goto Exit;
    }

    *NewKey = TempKey;
    TempKey = NULL;

Exit:

    QuicPacketKeyFree(TempKey);

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
    QUIC_KEY* Key = QuicAlloc(sizeof(QUIC_KEY));

    if (Key == NULL) {
        QuicTraceLogError("[ tls] Failed to allocate key.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        Key->Aead = EVP_aes_128_gcm();
        break;
    case QUIC_AEAD_AES_256_GCM:
        Key->Aead = EVP_aes_256_gcm();
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
        Key->Aead = EVP_chacha20_poly1305();
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    Key->BufferLen = EVP_CIPHER_key_length(Key->Aead);

    memcpy(Key->Buffer, RawKey, Key->BufferLen);

    *NewKey = Key;
    Key = NULL;

Exit:

    QuicKeyFree(Key);

    return Status;
}

void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    )
{
    if (Key != NULL) {
        QuicFree(Key);
        Key = NULL;
    }
}

QUIC_STATUS
QuicEncrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH) const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength) const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);
    int Ret =
        QuicTlsEncrypt(
            Buffer,
            BufferLength,
            Buffer,
            BufferLength - QUIC_ENCRYPTION_OVERHEAD,
            Key->Buffer,
            Key->BufferLen,
            Iv,
            QUIC_IV_LENGTH,
            AuthData,
            AuthDataLength,
            Key->Aead);
    return (Ret < 0) ? QUIC_STATUS_TLS_ERROR : QUIC_STATUS_SUCCESS;
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
    int Ret =
        QuicTlsDecrypt(
            Buffer,
            BufferLength,
            Buffer,
            BufferLength,
            Key->Buffer,
            Key->BufferLen,
            Iv,
            QUIC_IV_LENGTH,
            AuthData,
            AuthDataLength,
            Key->Aead);
    return (Ret < 0) ? QUIC_STATUS_TLS_ERROR : QUIC_STATUS_SUCCESS;
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
    QUIC_HP_KEY* Key = QUIC_ALLOC_NONPAGED(sizeof(QUIC_KEY));

    if (Key == NULL) {
        QuicTraceLogError("[ tls] Failed to allocate key.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        Key->Aead = EVP_aes_128_ctr();
        break;
    case QUIC_AEAD_AES_256_GCM:
        Key->Aead = EVP_aes_256_ctr();
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
        Key->Aead = EVP_chacha20_poly1305();
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    Key->BufferLen = EVP_CIPHER_key_length(Key->Aead);
    QuicCopyMemory(Key->Buffer, RawKey, Key->BufferLen);

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
        QuicFree(Key);
        Key = NULL;
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
    for (uint8_t i = 0; i < BatchSize; i++) {
        if (!QuicTlsHeaderMask(
                Mask + i * QUIC_HP_SAMPLE_LENGTH,
                Key->Buffer,
                Key->BufferLen,
                Cipher + i * QUIC_HP_SAMPLE_LENGTH,
                Key->Aead)) {
            return QUIC_STATUS_TLS_ERROR;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicHashCreate(
    _In_ QUIC_HASH_TYPE HashType,
    _In_reads_(SaltLength) const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ QUIC_HASH** NewHash
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_HASH* Hash = QUIC_ALLOC_NONPAGED(sizeof(QUIC_HASH) + SaltLength);

    if (Hash == NULL) {
        QuicTraceLogError("[ tls] Failed to allocate hash.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (HashType) {
    case QUIC_HASH_SHA256:
        Hash->Md = EVP_sha256();
    case QUIC_HASH_SHA384:
        Hash->Md = EVP_sha384();
    case QUIC_HASH_SHA512:
        Hash->Md = EVP_sha512();
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    QUIC_FRE_ASSERT(SaltLength <= QUIC_VERSION_SALT_LENGTH);
    Hash->SaltLength = SaltLength;
    memcpy(Hash->Salt, Salt, SaltLength);

    *NewHash = Hash;
    Hash = NULL;

Exit:

    QuicHashFree(Hash);

    return Status;
}

void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    )
{
    if (Hash != NULL) {
        QuicFree(Hash);
        Hash = NULL;
    }
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
    return
        QuicTlsHash(
            Output,
            OutputLength,
            Input,
            InputLength,
            Hash->Salt,
            Hash->SaltLength,
            Hash) != 0 ?
        QUIC_STATUS_SUCCESS : QUIC_STATUS_INTERNAL_ERROR;
}

static
void
QuicTlsKeySetAead(
    _In_ QUIC_AEAD_TYPE AeadType,
    _Out_ QUIC_PACKET_KEY* Key
    )
{
    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        Key->PacketKey->Aead = EVP_aes_128_gcm();
        if (Key->HeaderKey != NULL) {
            Key->HeaderKey->Aead = EVP_aes_128_ctr();
        }
        break;
    case QUIC_AEAD_AES_256_GCM:
        Key->PacketKey->Aead = EVP_aes_256_gcm();
        if (Key->HeaderKey != NULL) {
            Key->HeaderKey->Aead = EVP_aes_256_ctr();
        }
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
        Key->PacketKey->Aead = EVP_chacha20_poly1305();
        if (Key->HeaderKey != NULL) {
            Key->HeaderKey->Aead = EVP_chacha20();
        }
        break;
    default:
        QUIC_FRE_ASSERT(FALSE);
    }
}

static
const
EVP_MD *
QuicTlsKeyGetMd(
    _In_ QUIC_HASH_TYPE HashType
    )
{
    switch (HashType) {
    case QUIC_HASH_SHA256:
        return EVP_sha256();
    case QUIC_HASH_SHA384:
        return EVP_sha384();
    default:
        QUIC_FRE_ASSERT(FALSE);
        return NULL;
    }
}

static
void
QuicTlsNegotiatedCiphers(
    _In_ QUIC_TLS* TlsContext,
    _Out_ QUIC_AEAD_TYPE *AeadType,
    _Out_ QUIC_HASH_TYPE *HashType
    )
{
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(TlsContext->Ssl))) {
    case 0x03001301u: // TLS_AES_128_GCM_SHA256
        *AeadType = QUIC_AEAD_AES_128_GCM;
        *HashType = QUIC_HASH_SHA256;
        break;
    case 0x03001302u: // TLS_AES_256_GCM_SHA384
        *AeadType = QUIC_AEAD_AES_256_GCM;
        *HashType = QUIC_HASH_SHA384;
        break;
    case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
        *AeadType = QUIC_AEAD_CHACHA20_POLY1305;
        *HashType = QUIC_HASH_SHA256;
        break;
    default:
        QUIC_FRE_ASSERT(FALSE);
    }
}

static
QUIC_STATUS
QuicTlsKeyCreate(
    _Inout_ QUIC_TLS* TlsContext,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _Out_ QUIC_PACKET_KEY** Key
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempKey = NULL;
    QUIC_SECRET *TrafficSecret = NULL;
    QUIC_HASH_TYPE HashType;
    QUIC_AEAD_TYPE AeadType;

    Status = QuicAllocatePacketKey(KeyType, TRUE, &TempKey);

    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] key alloc failed.");
        goto Exit;
    }

    QuicTlsNegotiatedCiphers(TlsContext, &AeadType, &HashType);
    QuicTlsKeySetAead(AeadType, TempKey);

    Status =
        QuicTlsDerivePacketProtectionKey(
            Secret,
            SecretLen,
            QuicTlsKeyGetMd(HashType),
            TempKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionKey failed. Status: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDeriveHeaderProtectionKey(
            Secret,
            SecretLen,
            QuicTlsKeyGetMd(HashType),
            TempKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] QuicTlsDeriveHeaderProtectionKey failed. Status: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDerivePacketProtectionIv(
            Secret,
            SecretLen,
            QuicTlsKeyGetMd(HashType),
            TempKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[ tls] QuicTlsDerivePacketProtectionIv failed. Status: %ld", Status);
        goto Exit;
    }

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        TrafficSecret = &TempKey->TrafficSecret[0];
        QuicCopyMemory(TrafficSecret->Secret, Secret, SecretLen);
        TrafficSecret->Aead = AeadType;
        TrafficSecret->Hash = HashType;
    }

    *Key = TempKey;
    TempKey = NULL;

Exit:

    QuicPacketKeyFree(TempKey);

    return Status;
}

static
BOOLEAN
QuicTlsHdkfExpand(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_reads_bytes_(InfoLen) const uint8_t *Info,
    _In_ size_t InfoLen,
    _In_ const EVP_MD *Md
    )
{
    BOOLEAN Ret = TRUE;
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (KeyCtx == NULL) {
        QuicTraceLogError("[ tls] Key ctx alloc failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive_init(KeyCtx) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_derive_init failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_hkdf_mode(KeyCtx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_hkdf_mode failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(KeyCtx, Md) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set_hkdf_md failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(KeyCtx, "", 0) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set1_hkdf_salt failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(KeyCtx, Secret, SecretLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set1_hkdf_key failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(KeyCtx, Info, InfoLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_add1_hkdf_info failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive(KeyCtx, OutputBuffer, &OutputBufferLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_derive failed");
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (KeyCtx != NULL) {
        EVP_PKEY_CTX_free(KeyCtx);
        KeyCtx = NULL;
    }

    return Ret;
}

static
BOOLEAN
QuicTlsHkdfExpandLabel(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_z_ const char* const Label,
    _In_ const EVP_MD *Md
    )
{
    uint8_t Info[128] = {0};
    size_t InfoLen = sizeof(Info);

    QuicTlsHkdfFormatLabel(Label, OutputBufferLen, Info, (uint32_t *)&InfoLen);

    return
        QuicTlsHdkfExpand(
            OutputBuffer,
            OutputBufferLen,
            Secret,
            SecretLen,
            Info,
            InfoLen,
            Md);
}

static
void
QuicTlsHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLen,
    _Out_writes_all_(4 + QUIC_HKDF_PREFIX_LEN + strlen(Label)) uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    size_t LabelLen = strlen(Label);

    QUIC_DBG_ASSERT((size_t)*DataLength >= (LabelLen + 10));

    Data[0] = KeyLen / 256;
    Data[1] = KeyLen % 256;
    Data[2] = (uint8_t)(QUIC_HKDF_PREFIX_LEN + LabelLen);
    memcpy(Data + 3, QUIC_HKDF_PREFIX, QUIC_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + QUIC_HKDF_PREFIX_LEN, Label, LabelLen);
    Data[3+QUIC_HKDF_PREFIX_LEN+LabelLen] = 0;
    *DataLength = 3 + QUIC_HKDF_PREFIX_LEN + (uint32_t)LabelLen + 1;
}

static
QUIC_STATUS
QuicAllocatePacketKey(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ BOOLEAN AllocHpKey,
    _Outptr_ QUIC_PACKET_KEY** Key
    )
{
    const size_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0);

    QUIC_PACKET_KEY * TempKey = QuicAlloc(PacketKeyLength);
    if (TempKey == NULL) {
        QuicTraceLogError("[ tls] TempKey alloc failed.");
        goto Error;
    }

    QuicZeroMemory(TempKey, PacketKeyLength);
    TempKey->Type = KeyType;

    if (AllocHpKey) {
        TempKey->HeaderKey = QuicAlloc(sizeof(QUIC_HP_KEY));
        if (TempKey->HeaderKey == NULL) {
            QuicTraceLogError("[ tls] HeaderKey alloc failed.");
            goto Error;
        }
    }

    TempKey->PacketKey = QuicAlloc(sizeof(QUIC_KEY));
    if (TempKey->PacketKey == NULL) {
        QuicTraceLogError("[ tls] PacketKey alloc failed.");
        goto Error;
    }

    *Key = TempKey;
    
    return QUIC_STATUS_SUCCESS;

Error:

    QuicPacketKeyFree(TempKey);

    return QUIC_STATUS_OUT_OF_MEMORY;
}

static
QUIC_STATUS
QuicTlsDerivePacketProtectionKey(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    )
{
    BOOLEAN Ret = 0;
    int KeyLen = EVP_CIPHER_key_length(QuicKey->PacketKey->Aead);

    QUIC_FRE_ASSERT(KeyLen <= 64);

    QuicKey->PacketKey->BufferLen = KeyLen;

    Ret =
        QuicTlsHkdfExpandLabel(
            QuicKey->PacketKey->Buffer,
            KeyLen,
            Secret,
            SecretLen,
            "quic key",
            Md);

    if (!Ret) {
        QuicTraceLogError("[ tls] QuicTlsHkdfExpandLabel failed, error: %d", Ret);
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

static
QUIC_STATUS
QuicTlsDerivePacketProtectionIv(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    )
{
    BOOLEAN Ret = 0;
    int IvLen = max(8, EVP_CIPHER_iv_length(QuicKey->PacketKey->Aead));

    QUIC_FRE_ASSERT(IvLen <= QUIC_IV_LENGTH);

    Ret =
        QuicTlsHkdfExpandLabel(
            QuicKey->Iv,
            IvLen,
            Secret,
            SecretLen,
            "quic iv",
            Md);

    if (!Ret) {
        QuicTraceLogError("[ tls] QuicTlsHkdfExpandLabel failed, error: %d", Ret);
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

static
QUIC_STATUS
QuicTlsDeriveHeaderProtectionKey(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    )
{
    BOOLEAN Ret = 0;
    int KeyLen = EVP_CIPHER_key_length(QuicKey->HeaderKey->Aead);

    QUIC_FRE_ASSERT(KeyLen <= 64);
    QuicKey->HeaderKey->BufferLen = KeyLen;

    Ret =
        QuicTlsHkdfExpandLabel(
            QuicKey->HeaderKey->Buffer,
            KeyLen,
            Secret,
            SecretLen,
            "quic hp",
            Md);

    if (!Ret) {
        QuicTraceLogError("[ tls] QuicTlsHkdfExpandLabel failed, error: %d", Ret);
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
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

    QUIC_PACKET_KEY *Key;
    QUIC_STATUS Status = QuicAllocatePacketKey(KeyType, CreateHpKey, &Key);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsKeySetAead(Secret->Aead, Key);

     Status =
        QuicTlsDerivePacketProtectionIv(
            Secret->Secret,
            SecretLength,
            QuicTlsKeyGetMd(Secret->Hash),
            Key);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicTlsDerivePacketProtectionKey(
            Secret->Secret,
            SecretLength,
            QuicTlsKeyGetMd(Secret->Hash),
            Key);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            QuicTlsDeriveHeaderProtectionKey(
                Secret->Secret,
                SecretLength,
                QuicTlsKeyGetMd(Secret->Hash),
                Key);
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

    return Status;
}

static
QUIC_STATUS
QuicTlsUpdateTrafficSecret(
    _Out_writes_bytes_(SecretLen) const uint8_t *NewSecret,
    _In_reads_bytes_(SecretLen) const uint8_t *OldSecret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md
    )
{
    BOOLEAN Ret = 0;

    Ret =
        QuicTlsHkdfExpandLabel(
            (uint8_t *)NewSecret,
            SecretLen,
            (uint8_t *)OldSecret,
            SecretLen,
            "quic ku",
            Md);

    if (!Ret) {
        QuicTraceLogError("[ tls] QuicTlsHkdfExpandLabel failed, error: %d", Ret);
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

static
BOOLEAN
QuicTlsDeriveClientInitialSecret(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen
    )
{
    return
        QuicTlsHkdfExpandLabel(
            OutputBuffer,
            OutputBufferLen,
            Secret,
            SecretLen,
            "client in",
            EVP_sha256());
}

static
BOOLEAN
QuicTlsDeriveServerInitialSecret(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen
    )
{
    return
        QuicTlsHkdfExpandLabel(
            OutputBuffer,
            OutputBufferLen,
            Secret,
            SecretLen,
            "server in",
            EVP_sha256());
}

static
BOOLEAN
QuicTlsHkdfExtract(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_reads_(SaltLen) const uint8_t *Salt,
    _In_ size_t SaltLen,
    _In_ const EVP_MD *Md
    )
{
    int Ret = TRUE;
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (KeyCtx == NULL) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_new_id failed.");
        return FALSE;
    }

    if (EVP_PKEY_derive_init(KeyCtx) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_derive_init failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_hkdf_mode(KeyCtx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_hkdf_mode failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(KeyCtx, Md) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set_hkdf_md failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(KeyCtx, Salt, SaltLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set1_hkdf_salt failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(KeyCtx, Secret, SecretLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set1_hkdf_key failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive(KeyCtx, OutputBuffer, &OutputBufferLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_derive failed.");
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (KeyCtx != NULL) {
        EVP_PKEY_CTX_free(KeyCtx);
        KeyCtx = NULL;
    }

    return Ret;
}

static
size_t
QuicTlsAeadTagLength(
    _In_ const EVP_CIPHER *Aead
    )
{
    if (Aead == EVP_aes_128_gcm() || Aead == EVP_aes_256_gcm()) {
        return EVP_GCM_TLS_TAG_LEN;
    }

    if (Aead == EVP_chacha20_poly1305()) {
        return EVP_CHACHAPOLY_TLS_TAG_LEN;
    }

    QUIC_FRE_ASSERT(FALSE);
    return 0;
}

static
int
QuicTlsEncrypt(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(PlainTextLen) const uint8_t *PlainText,
    _In_ size_t PlainTextLen,
    _In_reads_bytes_(KeyLen) const uint8_t *Key,
    _In_ size_t KeyLen,
    _In_reads_bytes_(NonceLen) const uint8_t *Nonce,
    _In_ size_t NonceLen,
    _In_reads_bytes_(AuthDataLen) const uint8_t *Authdata,
    _In_ size_t AuthDataLen,
    _In_ const EVP_CIPHER *Aead
    )
{
    int Ret = 0;
    size_t TagLen = QuicTlsAeadTagLength(Aead);
    EVP_CIPHER_CTX *CipherCtx = NULL;
    size_t OutLen = 0;
    int Len = 0;

    QUIC_FRE_ASSERT(TagLen == QUIC_ENCRYPTION_OVERHEAD);

    if (OutputBufferLen < PlainTextLen + TagLen) {
        QuicTraceLogError("[ tls] Incorrect output buffer length :%ld.", OutputBufferLen);
        Ret = -1;
        goto Exit;
    }

    CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        QuicTraceLogError("[ tls] CipherCtx alloc failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, Aead, NULL, NULL, NULL) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptInit_ex failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, NonceLen, NULL) != 1) {
        QuicTraceLogError("[ tls] EVP_CIPHER_CTX_ctrl failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, NULL, NULL, Key, Nonce) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptInit_ex failed.");
        Ret = -1;
        goto Exit;
    }

    if (Authdata != NULL) {
        if (EVP_EncryptUpdate(CipherCtx, NULL, &Len, Authdata, AuthDataLen) != 1) {
            QuicTraceLogError("[ tls] EVP_EncryptUpdate failed.");
            Ret = -1;
            goto Exit;
        }
    }

    if (EVP_EncryptUpdate(CipherCtx, OutputBuffer, &Len, PlainText, PlainTextLen) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptUpdate failed.");
        Ret = -1;
        goto Exit;
    }

    OutLen = Len;

    if (EVP_EncryptFinal_ex(CipherCtx, OutputBuffer + OutLen, &Len) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptFinal_ex failed.");
        Ret = -1;
        goto Exit;
    }

    OutLen += Len;

    QUIC_FRE_ASSERT(OutLen + TagLen <= OutputBufferLen);

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, TagLen, OutputBuffer + OutLen) != 1) {
        Ret = -1;
        goto Exit;
    }

    OutLen += TagLen;
    Ret = OutLen;

Exit:

    if (CipherCtx != NULL) {
        EVP_CIPHER_CTX_free(CipherCtx);
        CipherCtx = NULL;
    }

    return Ret;
}

static
int
QuicTlsDecrypt(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(CipherTextLen) const uint8_t *CipherText,
    _In_ size_t CipherTextLen,
    _In_reads_bytes_(KeyLen) const uint8_t *Key,
    _In_ size_t KeyLen,
    _In_reads_bytes_(NonceLen) const uint8_t *Nonce,
    _In_ size_t NonceLen,
    _In_reads_bytes_(AuthDataLen) const uint8_t *AuthData,
    _In_ size_t AuthDataLen,
    _In_ const EVP_CIPHER *Aead
    )
{
    size_t TagLen = QuicTlsAeadTagLength(Aead);
    int Ret = -1;
    EVP_CIPHER_CTX *CipherCtx = NULL;

    QUIC_FRE_ASSERT(TagLen == QUIC_ENCRYPTION_OVERHEAD);

    if (TagLen > CipherTextLen || OutputBufferLen + TagLen < CipherTextLen) {
        QuicTraceLogError("[ tls] Incorrect buffer length.");
        goto Exit;
    }

    CipherTextLen -= TagLen;
    uint8_t *Tag = (uint8_t *)CipherText + CipherTextLen;

    CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        QuicTraceLogError("[ tls] EVP_CIPHER_CTX_new failed.");
        goto Exit;
    }

    if (EVP_DecryptInit_ex(CipherCtx, Aead, NULL, NULL, NULL) != 1) {
        QuicTraceLogError("[ tls] EVP_DecryptInit_ex failed, 0x%x.", ERR_get_error());
        goto Exit;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, NonceLen, NULL) != 1) {
        QuicTraceLogError("[ tls] EVP_CIPHER_CTX_ctrl failed, 0x%x.", ERR_get_error());
        goto Exit;
    }

    if (EVP_DecryptInit_ex(CipherCtx, NULL, NULL, Key, Nonce) != 1) {
        QuicTraceLogError("[ tls] EVP_DecryptInit_ex failed, 0x%x.", ERR_get_error());
        goto Exit;
    }

    size_t OutLen;
    int Len;

    if (AuthData != NULL) {
        if (EVP_DecryptUpdate(CipherCtx, NULL, &Len, AuthData, AuthDataLen) != 1) {
            QuicTraceLogError("[ tls] EVP_DecryptUpdate (AD) failed, 0x%x.", ERR_get_error());
            goto Exit;
        }
    }

    if (EVP_DecryptUpdate(CipherCtx, OutputBuffer, &Len, CipherText, CipherTextLen) != 1) {
        QuicTraceLogError("[ tls] EVP_DecryptUpdate (Cipher) failed, 0x%x.", ERR_get_error());
        goto Exit;
    }

    OutLen = Len;

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_TAG, TagLen, Tag) != 1) {
        QuicTraceLogError("[ tls] EVP_CIPHER_CTX_ctrl failed, 0x%x.", ERR_get_error());
        goto Exit;
    }

    if (EVP_DecryptFinal_ex(CipherCtx, OutputBuffer + OutLen, &Len) != 1) {
        QuicTraceLogError("[ tls] EVP_DecryptFinal_ex failed, 0x%x.", ERR_get_error());
        goto Exit;
    }

    OutLen += Len;
    Ret = OutLen;

Exit:

    if (CipherCtx != NULL) {
        EVP_CIPHER_CTX_free(CipherCtx);
        CipherCtx = NULL;
    }

    return Ret;
}

static
BOOLEAN
QuicTlsHeaderMask(
    _Out_writes_bytes_(5) uint8_t *OutputBuffer,
    _In_reads_bytes_(keylen) const uint8_t *Key,
    _In_ size_t keylen,
    _In_reads_bytes_(16) const uint8_t *Cipher,
    _In_ const EVP_CIPHER *Aead
    )
{
    BOOLEAN Ret = FALSE;
    uint8_t Temp[16] = {0};
    int OutputLen = 0;
    int Len = 0;
    uint8_t Zero[5] = {0};
    uint32_t Ctr = 0;
    uint8_t Iv[16] = {0};
    static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

    EVP_CIPHER_CTX *CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        QuicTraceLogError("[ tls] Cipherctx alloc failed.");
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, Aead, NULL, Key, Cipher) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptInit_ex failed.");
        goto Exit;
    }

    if (EVP_EncryptUpdate(CipherCtx, Temp, &Len, PLAINTEXT, sizeof(PLAINTEXT) - 1) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptUpdate failed.");
        goto Exit;
    }

    QUIC_FRE_ASSERT(Len == 5);
    OutputLen += Len;

    if (EVP_EncryptFinal_ex(CipherCtx, Temp + OutputLen, &Len) != 1) {
        QuicTraceLogError("[ tls] EVP_EncryptFinal_ex failed.");
        goto Exit;
    }

    QUIC_FRE_ASSERT(Len == 0);
    QuicCopyMemory(OutputBuffer, Temp, OutputLen);
    Ret = TRUE;

Exit:

    if (CipherCtx != NULL) {
        EVP_CIPHER_CTX_free(CipherCtx);
        CipherCtx = NULL;
    }

    return Ret;
}

static
BOOLEAN
QuicTlsHash(
    _Out_writes_bytes_(OutputBufferLen) uint8_t *OutputBuffer,
    _In_ size_t OutputBufferLen,
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_reads_bytes_(SaltLen) const uint8_t *Salt,
    _In_ size_t SaltLen,
    _In_ QUIC_HASH *Hash
    )
{
    BOOLEAN Ret = TRUE;
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (KeyCtx == NULL) {
        QuicTraceLogError("[ tls] KeyCtx alloc failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive_init(KeyCtx) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_derive_init failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_hkdf_mode(KeyCtx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_hkdf_mode failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(KeyCtx, Hash->Md) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set_hkdf_md failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(KeyCtx, Salt, SaltLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set1_hkdf_salt failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(KeyCtx, Secret, SecretLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_CTX_set1_hkdf_key failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive(KeyCtx, OutputBuffer, &OutputBufferLen) != 1) {
        QuicTraceLogError("[ tls] EVP_PKEY_derive failed.");
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (KeyCtx != NULL) {
        EVP_PKEY_CTX_free(KeyCtx);
        KeyCtx = NULL;
    }

    return Ret;
}
