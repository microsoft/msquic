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

typedef struct _QUIC_TLS_SESSION {

    //
    // AlpnBufferLength - The length of ALPN buffer.
    // AlpnBuffer - Stores the Alpn Length in its first byte followed by the
    // ALPN.
    //

    uint16_t AlpnBufferLength;
    unsigned char AlpnBuffer[0];

} QUIC_TLS_SESSION, *PQUIC_TLS_SESSION;

//
// The QUIC sec config object. Created once per listener on server side and
// once per connection on client side.
//

typedef struct _QUIC_SEC_CONFIG {
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

typedef struct _QUIC_TLS {

    //
    // TlsSession - The TLS session object that this context belong to.
    //

    PQUIC_TLS_SESSION TlsSession;

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

    PQUIC_CONNECTION Connection;
    QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;

} QUIC_TLS, *PQUIC_TLS;

//
// Represents a packet payload protection key.
//

typedef struct _QUIC_KEY {
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

typedef struct _QUIC_HASH {
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

typedef struct _QUIC_HP_KEY {
    //
    // The cipher to use for encryption/decryption.
    //

    const EVP_CIPHER *Aead;

    //
    // Buffer and BufferLen of the key.
    //

    size_t BufferLen;
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
size_t
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
size_t
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
/*++

Routine Description:

    Gets the identifier identifying if the Tls context belongs to client or
    server.

Arguments:

    TlsContext - The TLS context.

Return Value:

    char - Identifier.

--*/
{
    const char IDs[2] = { 'C', 'S' };
    return IDs[TlsContext->IsServer];
}

QUIC_STATUS
QuicTlsLibraryInitialize(
    void
    )
/*++

Routine Description:

    Initializes the TAL and TLS library.

Arguments:

    None.

Return Value:

    QUIC_STATUS.

--*/
{
    int Ret = 0;

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        LogError("[ tls] OPENSSL_init_ssl() failed.");
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
/*++

Routine Description:

    Uninitializes the TAL and TLS library.

Arguments:

    None.

Return Value:

    none.

--*/
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
/*++

Routine Description:

    Callback invoked by OpenSSL for ALPN selection on server side.

Arguments:

    Ssl - The SSL object.

    Out - The output buffer pointer to return the selected ALPN.

    OutLen - The output buffer length.

    In - The input buffer containing the client supplied ALPN.

    InLen - The inout buffer length.

    Arg - Unused.

Return Value:

    SSL_TLSEXT_ERR_OK on success, SSL_TLSEXT_ERR_NOACK on fails.

--*/
{
    PQUIC_TLS TlsContext = SSL_get_app_data(Ssl);
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

    LogError("[ tls] Client did not present correct ALPN");

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

    LogVerbose("[ tls][%p][%c] New encryption secrets (Level = %u).",
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

    LogVerbose("[ tls][%p][%c] Sending %llu handshake bytes (Level = %u).",
        TlsContext, GetTlsIdentifier(TlsContext), Length, Level);

    if (Length + TlsState->BufferLength > (size_t)TlsState->BufferAllocLength) {
        LogError("[ tls][%p][%c] Buffer overflow for output handshake data.",
            TlsContext, GetTlsIdentifier(TlsContext));
        TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
        return -1;
    }

    switch (KeyType) {
    case QUIC_PACKET_KEY_HANDSHAKE:
        if (TlsState->BufferOffsetHandshake == 0) {
            TlsState->BufferOffsetHandshake = TlsState->BufferTotalLength;
            LogInfo("[ tls][%p][%c] Writing Handshake data starts at %u.",
                TlsContext, GetTlsIdentifier(TlsContext), TlsState->BufferOffsetHandshake);
        }
        break;
    case QUIC_PACKET_KEY_1_RTT:
        if (TlsState->BufferOffset1Rtt == 0) {
            TlsState->BufferOffset1Rtt = TlsState->BufferTotalLength;
            LogInfo("[ tls][%p][%c] Writing 1-RTT data starts at %u.",
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

    LogError("[ tls][%p][%c] Send alert = %u (Level = %u).",
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
/*++

Routine Description:

    Creates server security config.

Arguments:

    Rundown - A secconfig rundown object passed by MsQuic. A ref is hold on
        this rundown until the secconfig object is freed.

    Flags - CERT related flags.

    Certificate - The certificate object.

    Principle - Unused.

    Context - A context to be pass in sec config completion handler.

    CompletionHandler - The sec config completion handler.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    QUIC_SEC_CONFIG* SecurityConfig = NULL;
    QUIC_CERTIFICATE_FILE* CertFile = Certificate;
    LONG SSLOpts = 0;

    //
    // We only allow PEM formatted cert files.
    //

    if (Flags != QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE) {
        LogError("[ tls] Invalid flags: %lu.", Flags);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (CertFile == NULL) {
        LogError("[ tls] CertFile unspecified.");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (!QuicRundownAcquire(Rundown)) {
        LogError("[ tls] Failed to acquire sec config rundown.");
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    //
    // Create a security config.
    //

    SecurityConfig = QuicAlloc(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        LogError("[ tls] Security config allocation failure.");
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
        LogError("[ tls] SSL_CTX_new() failed, error: %ld", ERR_get_error());
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
        LogError("[ tls] SSL_CTX_set_ciphersuites() failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set1_groups_list(
            SecurityConfig->SSLCtx,
            QUIC_TLS_DEFAULT_SSL_CURVES);
    if (Ret != 1) {
        LogError("[ tls] SSL_CTX_set1_groups_list() failed, error: %ld", ERR_get_error());
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
        LogError("[ tls] SSL_CTX_use_PrivateKey_file() failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_use_certificate_chain_file(
            SecurityConfig->SSLCtx,
            CertFile->CertificateFile);
    if (Ret != 1) {
      LogError("[ tls] SSL_CTX_use_certificate_chain_file() failed, error: %ld", ERR_get_error());
      Status = QUIC_STATUS_TLS_ERROR;
      goto Exit;
    }

    Ret = SSL_CTX_check_private_key(SecurityConfig->SSLCtx);
    if (Ret != 1) {
      LogError("TLS: SSL_CTX_check_private_key() failed, error: %ld", ERR_get_error());
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
/*++

Routine Description:

    Delets a security config.

Arguments:

    SecurityConfig - The security config to delete.

Return Value:

    None.

--*/
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
/*++

Routine Description:

    Creates client security config.

Arguments:

    Flags - CERT related flags.

    ClientConfig - A pointer to return client config.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    QUIC_SEC_CONFIG* SecurityConfig = NULL;

    //
    // Create a security config.
    //

    SecurityConfig = QuicAlloc(sizeof(QUIC_SEC_CONFIG));
    if (SecurityConfig == NULL) {
        LogError("[ tls] SecurityConfig alloc failed.");
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
        LogError("[ tls] SSL_CTX_new() failed, error: %ld", ERR_get_error());
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
        LogError("[ tls] SSL_CTX_set_ciphersuites() failed, error: %ld", ERR_get_error());
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        SSL_CTX_set1_groups_list(
            SecurityConfig->SSLCtx,
            QUIC_TLS_DEFAULT_SSL_CURVES);
    if (Ret != 1) {
        LogError("[ tls] SSL_CTX_set1_groups_list() failed, error: %ld", ERR_get_error());
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

            Ret =
                SSL_CTX_load_verify_locations(
                    SecurityConfig->SSLCtx,
                    QuicOpenSslClientTrustedCert,
                    NULL);
            if (Ret != 1) {
                LogError("[ tls] SSL_CTX_load_verify_locations() failed, error: %ld", ERR_get_error());
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
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
/*++

Routine Description:

    Adds a ref on a sec config object.

Arguments:

    SecurityConfig - The security config to ref.

Return Value:

    Returns the sec config object.

--*/
{
    InterlockedIncrement(&SecurityConfig->RefCount);
    return SecurityConfig;
}

void
QUIC_API
QuicTlsSecConfigRelease(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
/*++

Routine Description:

    Releases a ref on a sec config object.

Arguments:

    SecurityConfig - The security config to release ref.

Return Value:

    None.

--*/
{
    if (InterlockedDecrement(&SecurityConfig->RefCount) == 0) {
        QuicTlsSecConfigDelete(SecurityConfig);
        SecurityConfig = NULL;
    }
}

QUIC_STATUS
QuicTlsSessionInitialize(
    _In_z_ const char* ALPN,
    _Out_ PQUIC_TLS_SESSION* NewTlsSession
    )
/*++

Routine Description:

    Creates a TLS session object.

Arguments:

    ALPN - A null terminated ALPN string.

    NewTlsSession - A pointer to return the TLS session object.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PQUIC_TLS_SESSION TlsSession = NULL;
    size_t ALPNLength = strlen(ALPN);

    if (ALPNLength > QUIC_MAX_ALPN_LENGTH) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    TlsSession = QuicAlloc(sizeof(QUIC_TLS_SESSION) + ALPNLength + 1);
    if (TlsSession == NULL) {
        LogWarning("[ tls] Failed to allocate QUIC_TLS_SESSION.");
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
    _In_opt_ PQUIC_TLS_SESSION TlsSession
    )
/*++

Routine Description:

    Destroys a TLS session object.

Arguments:

    TlsSession - The TLS session object to destroy.

Return Value:

    None.

--*/
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
    _In_ PQUIC_TLS_SESSION TlsSession,
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
    _Out_ PQUIC_TLS* NewTlsContext
    )
/*++

Routine Description:

    Initializes TLS context for a connection.

Arguments:

    Config - The TLS config associated with the connection.

    NewTlsContext - A pointer to return the new TLS context.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PQUIC_TLS TlsContext = NULL;
    uint16_t ServerNameLength = 0;

    TlsContext = QuicAlloc(sizeof(QUIC_TLS));
    if (TlsContext == NULL) {
        LogError("[ tls] Failed to allocate TLS context.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(TlsContext, sizeof(QUIC_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->TlsSession = Config->TlsSession;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = QuicTlsSecConfigAddRef(Config->SecConfig);
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;

    LogVerbose("[ tls][%p][%c] Created.", TlsContext, GetTlsIdentifier(TlsContext));

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

            ServerNameLength = (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);

            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                LogError("[ tls][%p][%c] Invalid / Too long server name!", TlsContext, GetTlsIdentifier(TlsContext));
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI = QuicAlloc(ServerNameLength + 1);

            if (TlsContext->SNI == NULL) {
                LogError("[ tls][%p][%c] Failed to allocate SNI.", TlsContext, GetTlsIdentifier(TlsContext));
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
        LogError("[ tls][%p][%c] Failed to allocate Ssl object.", TlsContext, GetTlsIdentifier(TlsContext));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    if (Config->IsServer) {
        SSL_set_accept_state(TlsContext->Ssl);
        SSL_set_quic_early_data_enabled(TlsContext->Ssl, 1);
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
        LogError("[ tls][%p][%c] Failed to set TP.", TlsContext, GetTlsIdentifier(TlsContext));
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

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
    _In_opt_ PQUIC_TLS TlsContext
    )
/*++

Routine Description:

    Uninitializes a TLS context.

Arguments:

    TlsContext - TLS context to uninitialize.

Return Value:

    QUIC_STATUS.

--*/
{
    if (TlsContext != NULL) {
        LogVerbose("[ tls][%p][%c] Cleaning up.", TlsContext, GetTlsIdentifier(TlsContext));

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
    _In_ PQUIC_TLS TlsContext
    )
/*++

Routine Description:

    Reset SSL state.

Arguments:

    TlsContext - TLS context.

Return Value:

    None.

--*/
{
    LogInfo("[ tls][%p][%c] Resetting TLS state.", TlsContext, GetTlsIdentifier(TlsContext));

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
        LogError("[ tls][%p][%c] Failed to allocate Ssl object.", TlsContext, GetTlsIdentifier(TlsContext));
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
        LogError("[ tls][%p][%c] Failed to set TP.", TlsContext, GetTlsIdentifier(TlsContext));
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }*/

Exit:

    return;
}

QUIC_SEC_CONFIG*
QuicTlsGetSecConfig(
    _In_ PQUIC_TLS TlsContext
    )
/*++

Routine Description:

    Gets the refed sec config object associated with a TLS context. The caller
    is responsible for derefing the sec config object once its done.

Arguments:

    TlsContext - TLS context.

Return Value:

    QUIC_SEC_CONFIG - A ref counter sec config object.

--*/
{
    return QuicTlsSecConfigAddRef(TlsContext->SecConfig);
}

QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ PQUIC_TLS TlsContext,
    _In_reads_bytes_(*BufferLength) const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
/*++

Routine Description:

    Called by MsQuic to process TLS data.

Arguments:

    TlsContext - TLS context.

    Buffer - The TLS data.

    BufferLength - The TLS data buffer length.

    State - The state of TLS data processing.

Return Value:

    QUIC_TLS_RESULT_FLAGS - Result flags.

--*/
{
    int Ret = 0;
    int Err = 0;

    QUIC_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    if (*BufferLength != 0) {
        LogVerbose("[ tls][%p][%c] Processing %u received bytes.",
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
                LogError("[ tls][%p][%c] TLS handshake error: %s.",
                    TlsContext, GetTlsIdentifier(TlsContext), ERR_error_string(ERR_get_error(), NULL));
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;

            default:
                LogError("[ tls][%p][%c] TLS handshake error: %d.",
                    TlsContext, GetTlsIdentifier(TlsContext), Err);
                TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
                goto Exit;
            }
        }

        LogInfo("[ tls][%p][%c] Handshake complete.", TlsContext, GetTlsIdentifier(TlsContext));
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
                LogError("[ tls][%p][%c] No transport parameters received",
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
            LogError("[ tls][%p][%c] TLS handshake error: %s.",
                TlsContext, GetTlsIdentifier(TlsContext), ERR_error_string(ERR_get_error(), NULL));
            TlsContext->ResultFlags |= QUIC_TLS_RESULT_ERROR;
            goto Exit;

        default:
            LogError("[ tls][%p][%c] TLS handshake error: %d.",
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
    _In_ PQUIC_TLS TlsContext,
    _Out_ uint32_t * BufferConsumed
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferConsumed);
    return QUIC_TLS_RESULT_ERROR;
}

QUIC_STATUS
QuicTlsReadTicket(
    _In_ PQUIC_TLS TlsContext,
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
    _In_ PQUIC_TLS TlsContext,
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
    _In_ PQUIC_TLS TlsContext,
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
/*++

Routine Description:

    Creates initial packet keys.

Arguments:

    IsServer - TRUE if server side.

    Salt - A version specific Salt.

    CIDLength - The connection ID length.

    CID - The connection ID.

    ReadKey - A pointer to read key to return.

    WriteKey - A pointer to read key to return.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempReadKey = NULL;
    QUIC_PACKET_KEY *TempWriteKey = NULL;
    uint8_t InitialSecret[QUIC_HASH_SHA256_SIZE] = {0};
    uint8_t Secret[QUIC_HASH_SHA256_SIZE] = {0};

    if (WriteKey != NULL) {
        Status = QuicAllocatePacketKey(QUIC_PACKET_KEY_INITIAL, &TempWriteKey);

        if (QUIC_FAILED(Status)) {
            LogError("[ tls] Key alloc failure.");
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
            LogError("[ tls] QuicTlsHkdfExtract() failed.");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        if (IsServer) {
            if (!QuicTlsDeriveServerInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                LogError("[ tls] QuicTlsDeriveServerInitialSecret() failed.");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            if (!QuicTlsDeriveClientInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                LogError("[ tls] QuicTlsDeriveClientInitialSecret() failed.");
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
            LogError("[ tls] QuicTlsDerivePacketProtectionKey() failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDerivePacketProtectionIv(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempWriteKey);

        if (QUIC_FAILED(Status)) {
            LogError("[ tls] QuicTlsDerivePacketProtectionIv() failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDeriveHeaderProtectionKey(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempWriteKey);

        if (QUIC_FAILED(Status)) {
            LogError("[ tls] QuicTlsDeriveHeaderProtectionKey() failed. error: %ld", Status);
            goto Exit;
        }
    }

    if (ReadKey != NULL) {
        Status = QuicAllocatePacketKey(QUIC_PACKET_KEY_INITIAL, &TempReadKey);

        if (QUIC_FAILED(Status)) {
            LogError("[ tls] Key alloc failure.");
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
            LogError("[ tls] QuicTlsHkdfExtract() failed.");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        if (IsServer) {
            if (!QuicTlsDeriveClientInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                LogError("[ tls] QuicTlsDeriveClientInitialSecret() failed.");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            if (!QuicTlsDeriveServerInitialSecret(
                    Secret,
                    sizeof(Secret),
                    InitialSecret,
                    sizeof(InitialSecret))) {
                LogError("[ tls] QuicTlsDeriveServerInitialSecret() failed.");
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
            LogError("[ tls] QuicTlsDerivePacketProtectionKey() failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDerivePacketProtectionIv(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempReadKey);

        if (QUIC_FAILED(Status)) {
            LogError("[ tls] QuicTlsDerivePacketProtectionIv() failed. error: %ld", Status);
            goto Exit;
        }

        Status =
            QuicTlsDeriveHeaderProtectionKey(
                Secret,
                sizeof(Secret),
                EVP_sha256(),
                TempReadKey);

        if (QUIC_FAILED(Status)) {
            LogError("[ tls] QuicTlsDeriveHeaderProtectionKey() failed. error: %ld", Status);
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

    if (TempReadKey != NULL) {
        QuicFree(TempReadKey);
        TempReadKey = NULL;
    }

    if (TempWriteKey != NULL) {
        QuicFree(TempWriteKey);
        TempWriteKey = NULL;
    }

    return Status;
}

void
QuicPacketKeyFree(
    _In_opt_ QUIC_PACKET_KEY* Key
    )
/*++

Routine Description:

    Frees packet key.

Arguments:

    Key - Packet key to free.

Return Value:

    None.

--*/
{
    if (Key != NULL) {
        QUIC_FREE(Key);
        Key = NULL;
    }
}

QUIC_STATUS
QuicPacketKeyUpdate(
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    )
/*++

Routine Description:

    Updates 1-RTT keys.

Arguments:

    OldKey - Old key.

    NewKey - Returns the new key.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempKey = NULL;
    size_t SecretLen = 0;

    QUIC_FRE_ASSERT(OldKey->Type == QUIC_PACKET_KEY_1_RTT);

    Status = QuicAllocatePacketKey(QUIC_PACKET_KEY_1_RTT, &TempKey);

    if (QUIC_FAILED(Status)) {
        LogError("[ tls] Key alloc failure");
        goto Exit;
    }

    TempKey->Type = OldKey->Type;
    TempKey->PacketKey->Aead = OldKey->PacketKey->Aead;
    TempKey->HeaderKey->Aead = OldKey->HeaderKey->Aead;

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
        LogError("[ tls] QuicTlsUpdateTrafficSecret() failed. error: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDerivePacketProtectionKey(
            TempKey->TrafficSecret[0].Secret,
            SecretLen,
            QuicTlsKeyGetMd(OldKey->TrafficSecret[0].Hash),
            TempKey);

    if (QUIC_FAILED(Status)) {
        LogError("[ tls] QuicTlsDerivePacketProtectionKey() failed. error: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDerivePacketProtectionIv(
            TempKey->TrafficSecret[0].Secret,
            SecretLen,
            QuicTlsKeyGetMd(OldKey->TrafficSecret[0].Hash),
            TempKey);

    if (QUIC_FAILED(Status)) {
        LogError("[ tls] QuicTlsDerivePacketProtectionIv() failed. error: %ld", Status);
        goto Exit;
    }

    *NewKey = TempKey;
    TempKey = NULL;

Exit:

    if (TempKey != NULL) {
        QuicFree(TempKey);
        TempKey = NULL;
    }

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
/*++

Routine Description:

    Creates a quic key.

Arguments:

    AeadType - The Aead type.

    RawKey - The raw key.

    NewKey - Return the new QUIC key.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_KEY* Key = QuicAlloc(sizeof(QUIC_KEY));

    if (Key == NULL) {
        LogError("[ tls] Failed to allocate key.");
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

    if (Key != NULL) {
        QuicFree(Key);
        Key = NULL;
    }

    return Status;
}

void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    )
/*++

Routine Description:

    Frees a quic key.

Arguments:

    Key - The key to free.

Return Value:

    None.

--*/
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
/*++

Routine Description:

    Encrypts a buffer using a supplied key.

Arguments:

    Key - The key to use for encryption.

    Iv - The IV to use for encryption.

    AuthDataLength - The auth data length.

    AuthData - The AuthData to use for encryption.

    BufferLength - The length of bufffer.

    Buffer - Buffer containing data to be encrypted plus some addition space for
        encryption overhead. On return this buffer contains the encrypted data.

Return Value:

    QUIC_STATUS.

--*/
{
    int Ret = 0;

    Ret =
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

    if (Ret < 0) {
        LogError("[ tls] QuicTlsEncrypt() failed. Ret: %ld", Ret);
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
/*++

Routine Description:

    Decrypts a buffer using a supplied key.

Arguments:

    Key - The key to use for decryption.

    Iv - The IV to use for decryption.

    AuthDataLength - The auth data length.

    AuthData - The AuthData to use for decryption.

    BufferLength - The length of bufffer.

    Buffer - Buffer containing data to be decryption. On return this buffer
        contains the decrypted data.

Return Value:

    QUIC_STATUS.

--*/
{
    size_t Ret = 0;

    Ret =
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

    if (Ret < 0) {
        LogError("[ tls] QuicTlsDecrypt() failed. Ret: %ld", Ret);
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
/*++

Routine Description:

    Creates a header protection key.

Arguments:

    AeadType - The Aead type.

    RawKey - The raw key.

    NewKey - Returns the new key.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_HP_KEY* Key = QUIC_ALLOC_NONPAGED(sizeof(QUIC_KEY));

    if (Key == NULL) {
        LogError("[ tls] Failed to allocate key.");
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

    if (Key != NULL) {
        QuicFree(Key);
        Key = NULL;
    }

    return Status;
}

void
QuicHpKeyFree(
    _In_opt_ QUIC_HP_KEY* Key
    )
/*++

Routine Description:

    Frees a header protection key.

Arguments:

    Key - Key to free.

Return Value:

    None.

--*/
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
/*++

Routine Description:

    Computes the header protection mask.

Arguments:

    Key - The key to use.

    BatchSize - The number of masks to be computed.

    Cipher - The Ciphers to use for mask computation.

    Mask - Returns an array of masks.

Return Value:

    QUIC_STATUS.

--*/
{
    int Ret = 0;
    uint8_t i = 0;
    QuicZeroMemory(Mask, sizeof(QUIC_HP_SAMPLE_LENGTH * BatchSize));

    for (i = 0; i < BatchSize; i++) {
        Ret =
            QuicTlsHeaderMask(
                Mask + i * QUIC_HP_SAMPLE_LENGTH,
                Key->Buffer,
                Key->BufferLen,
                Cipher + i * QUIC_HP_SAMPLE_LENGTH,
                Key->Aead);

        if (Ret < 0) {
            LogError("[ tls] QuicTlsHeaderMask() failed. Ret: %ld", Ret);
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
/*++

Routine Description:

    Creates a hash.

Arguments:

    HashType - The hash type.

    Salt - The salt.

    SaltLength - The salt length.

    NewHash - Returns the new hash.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_HASH* Hash = QUIC_ALLOC_NONPAGED(sizeof(QUIC_HASH) + SaltLength);

    if (Hash == NULL) {
        LogError("[ tls] Failed to allocate hash.");
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

    if (Hash != NULL) {
        QuicFree(Hash);
        Hash = NULL;
    }

    return Status;
}

void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    )
/*++

Routine Description:

    Frees a hash.

Arguments:

    Hash - The hash to be freed.

Return Value:

    QUIC_STATUS.

--*/
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
/*++

Routine Description:

    Computes a hash.

Arguments:

    Hash - The quic hash object.

    Input - The input to hash.

    InputLength - The input length.

    OutputLength - The output length.

    Output - Returns the computed hash.

Return Value:

    QUIC_STATUS.

--*/
{
    return
        QuicTlsHash(
            Output,
            OutputLength,
            Input,
            InputLength,
            Hash->Salt,
            Hash->SaltLength,
            Hash);
}

static
void
QuicTlsKeySetAead(
    _In_ QUIC_AEAD_TYPE AeadType,
    _Out_ QUIC_PACKET_KEY* Key
    )
/*++

Routine Description:

    Sets the AEAD on the key.

Arguments:

    AeadType - The AEAD type.

    Key - The key.

Return Value:

    None.

--*/
{
    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        Key->PacketKey->Aead = EVP_aes_128_gcm();
        Key->HeaderKey->Aead = EVP_aes_128_ctr();
        break;
    case QUIC_AEAD_AES_256_GCM:
        Key->PacketKey->Aead = EVP_aes_256_gcm();
        Key->HeaderKey->Aead = EVP_aes_256_ctr();
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
        Key->PacketKey->Aead = EVP_chacha20_poly1305();
        Key->HeaderKey->Aead = EVP_chacha20();
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
/*++

Routine Description:

    Sets the message digest corresponding to the hash type.

Arguments:

    HashType - The Hash type.

Return Value:

    The message digest.

--*/
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
/*++

Routine Description:

    Gets the negotiated Aead and hash.

Arguments:

    TlsContext - The TLS context.

    AeadType - The Aead type.

    HashType - The Hash type.

Return Value:

    None.

--*/
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
/*++

Routine Description:

    Creates a packet key based on the secret.

Arguments:

    TlsContext - The TLS context.

    Secret - The secret.

    SecretLen - The secret length.

    KeyType - The key type.

    Key - Returns the created key.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempKey = NULL;
    QUIC_SECRET *TrafficSecret = NULL;
    QUIC_HASH_TYPE HashType;
    QUIC_AEAD_TYPE AeadType;

    Status = QuicAllocatePacketKey(KeyType, &TempKey);

    if (QUIC_FAILED(Status)) {
        LogError("[ tls] key alloc failed.");
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
        LogError("[ tls] QuicTlsDerivePacketProtectionKey() failed. Status: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDeriveHeaderProtectionKey(
            Secret,
            SecretLen,
            QuicTlsKeyGetMd(HashType),
            TempKey);

    if (QUIC_FAILED(Status)) {
        LogError("[ tls] QuicTlsDeriveHeaderProtectionKey() failed. Status: %ld", Status);
        goto Exit;
    }

    Status =
        QuicTlsDerivePacketProtectionIv(
            Secret,
            SecretLen,
            QuicTlsKeyGetMd(HashType),
            TempKey);

    if (QUIC_FAILED(Status)) {
        LogError("[ tls] QuicTlsDerivePacketProtectionIv() failed. Status: %ld", Status);
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

    if (TempKey != NULL) {
        QuicFree(TempKey);
        TempKey = NULL;
    }

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
/*++

Routine Description:

    Expands the secret into a key using low level OpenSSL APIs.

Arguments:

    OutputBuffer - The output buffer for derived key.

    OutputBufferLen - The output buffer length.

    Secret - The secret.

    SecretLen - The secret length.

    Info - The info.

    InfoLen - The info length.

    Md - The message digest to use.

Return Value:

    TRUE on success, FALSE on failure.

--*/
{
    BOOLEAN Ret = TRUE;
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (KeyCtx == NULL) {
        LogError("[ tls] Key ctx alloc failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive_init(KeyCtx) != 1) {
        LogError("[ tls] EVP_PKEY_derive_init() failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_hkdf_mode(KeyCtx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_hkdf_mode() failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(KeyCtx, Md) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set_hkdf_md() failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(KeyCtx, "", 0) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set1_hkdf_salt() failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(KeyCtx, Secret, SecretLen) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set1_hkdf_key() failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(KeyCtx, Info, InfoLen) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_add1_hkdf_info() failed");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive(KeyCtx, OutputBuffer, &OutputBufferLen) != 1) {
        LogError("[ tls] EVP_PKEY_derive() failed");
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
/*++

Routine Description:

    Derives a key based on the secret and label.

Arguments:

    OutputBuffer - The output buffer for derived key.

    OutputBufferLen - The output buffer length.

    Secret - The secret.

    SecretLen - The secret length.

    Label - The label.

    Md - The message digest to use.

Return Value:

    TRUE on success, FALSE on failure.

--*/
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
/*++

Routine Description:

    Formats a label for key derivation.

Arguments:

    Label - The label.

    KeyLen - The key length.

    Data - Returns the formatted label.

    DataLength - The length of the data.

Return Value:

    None.

--*/
{
    size_t LabelLen = strlen(Label);

    QUIC_DBG_ASSERT((size_t)*DataLength >= (LabelLen + 10));

    Data[0] = KeyLen / 256;
    Data[1] = KeyLen % 256;
    Data[2] = (uint8_t)(QUIC_HKDF_PREFIX_LEN + LabelLen);
    memcpy(Data + 3, QUIC_HKDF_PREFIX, QUIC_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + QUIC_HKDF_PREFIX_LEN, Label, LabelLen);
    Data[3+QUIC_HKDF_PREFIX_LEN+LabelLen] = 0;
    *DataLength = 3 + QUIC_HKDF_PREFIX_LEN + (ULONG)LabelLen + 1;
}

static
QUIC_STATUS
QuicAllocatePacketKey(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _Outptr_ QUIC_PACKET_KEY** Key
    )
/*++

Routine Description:

    Allocates space for a packet key.

Arguments:

    KeyType - The key type.

    Key - Returns the allocated key.

Return Value:

    QUIC_STATUS.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PACKET_KEY *TempKey = NULL;
    size_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0) +
        sizeof(QUIC_HP_KEY) +
        sizeof(QUIC_KEY);

    TempKey = QuicAlloc(PacketKeyLength);

    if (TempKey == NULL) {
        LogError("[ tls] key alloc failed.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(TempKey, PacketKeyLength);

    TempKey->HeaderKey =
            (QUIC_HP_KEY *)
                ((uint8_t *)TempKey +
                sizeof(QUIC_PACKET_KEY) +
                (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0));
    TempKey->PacketKey = (QUIC_KEY *)(TempKey->HeaderKey + 1);

    TempKey->Type = KeyType;

    *Key = TempKey;
    TempKey = NULL;

Exit:

    if (TempKey != NULL) {
        QuicFree(TempKey);
        TempKey = NULL;
    }

    return Status;
}

static
QUIC_STATUS
QuicTlsDerivePacketProtectionKey(
    _In_reads_bytes_(SecretLen) const uint8_t *Secret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md,
    _Out_ QUIC_PACKET_KEY *QuicKey
    )
/*++

Routine Description:

    Derives a packet payload protection key based on a secret.

Arguments:

    Secret - The secret.

    SecretLen - The secret len.

    Md - The message digest to use.

    QuicKey - Returns the derived key.

Return Value:

    QUIC_STATUS.

--*/
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
        LogError("[ tls] QuicTlsHkdfExpandLabel() failed, error: %d", Ret);
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
/*++

Routine Description:

    Derives a packet protection IV based on a secret.

Arguments:

    Secret - The secret.

    SecretLen - The secret len.

    Md - The message digest to use.

    QuicKey - Returns the derived IV.

Return Value:

    QUIC_STATUS.

--*/
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
        LogError("[ tls] QuicTlsHkdfExpandLabel() failed, error: %d", Ret);
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
/*++

Routine Description:

    Derives a packet header protection key based on a secret.

Arguments:

    Secret - The secret.

    SecretLen - The secret len.

    Md - The message digest to use.

    QuicKey - Returns the derived key.

Return Value:

    QUIC_STATUS.

--*/
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
        LogError("[ tls] QuicTlsHkdfExpandLabel() failed, error: %d", Ret);
        return QUIC_STATUS_TLS_ERROR;
    }

    return QUIC_STATUS_SUCCESS;
}

static
QUIC_STATUS
QuicTlsUpdateTrafficSecret(
    _Out_writes_bytes_(SecretLen) const uint8_t *NewSecret,
    _In_reads_bytes_(SecretLen) const uint8_t *OldSecret,
    _In_ size_t SecretLen,
    _In_ const EVP_MD *Md
    )
/*++

Routine Description:

    Derives a new secret based on old secret.

Arguments:

    NewSecret - Returns the secret.

    OldSecret - The old secret.

    SecretLen - The secret len.

    Md - The message digest to use.

Return Value:

    QUIC_STATUS.

--*/
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
        LogError("[ tls] QuicTlsHkdfExpandLabel() failed, error: %d", Ret);
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
/*++

Routine Description:

    Derives the client initial secret based on a secret.

Arguments:

    OutputBuffer - Buffer to return the initial secret.

    OutputBufferLen - The output buffer length.

    Secret - The secret.

    SecretLen - The secret len.

Return Value:

    QUIC_STATUS.

--*/
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
/*++

Routine Description:

    Derives the server initial secret based on a secret.

Arguments:

    OutputBuffer - Buffer to return the initial secret.

    OutputBufferLen - The output buffer length.

    Secret - The secret.

    SecretLen - The secret len.

Return Value:

    QUIC_STATUS.

--*/
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
/*++

Routine Description:

    Extracts a key from a secret and salt using low level OpenSSL APIs.

Arguments:

    OutputBuffer - Buffer to return the initial secret.

    OutputBufferLen - The output buffer length.

    Secret - The secret.

    SecretLen - The secret len.

    Salt - The salt to use.

    SaltLen - The salt len.

    Md - The message digest to use.

Return Value:

    QUIC_STATUS.

--*/
{
    int Ret = TRUE;
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (KeyCtx == NULL) {
        LogError("[ tls] EVP_PKEY_CTX_new_id() failed.");
        return FALSE;
    }

    if (EVP_PKEY_derive_init(KeyCtx) != 1) {
        LogError("[ tls] EVP_PKEY_derive_init() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_hkdf_mode(KeyCtx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_hkdf_mode() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(KeyCtx, Md) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set_hkdf_md() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(KeyCtx, Salt, SaltLen) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set1_hkdf_salt() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(KeyCtx, Secret, SecretLen) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set1_hkdf_key() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive(KeyCtx, OutputBuffer, &OutputBufferLen) != 1) {
        LogError("[ tls] EVP_PKEY_derive() failed.");
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
/*++

Routine Description:

    Gets the Aead tag length.

Arguments:

    Aead - Aead object.

Return Value:

    Tag length.

--*/
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
size_t
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
/*++

Routine Description:

    Encrypts a plain text data using low level OpenSSL APIs.

Arguments:

    OutputBuffer - A buffer to return encrypted data.

    OutputBufferLen - The output buffer length.

    PlainText - The plain text buffer.

    PlainTextLen - The plain text length.

    Key - The key to use for encryption.

    KeyLen - The key length.

    Nonce - The nonce.

    NonceLen - The nonce length.

    Authdata - The auth data.

    AuthDataLen - The auth data length.

    Aead - The aead cipher to use for encryption.

Return Value:

    The total encrypted bytes.

--*/
{
    size_t Ret = 0;
    size_t TagLen = QuicTlsAeadTagLength(Aead);
    EVP_CIPHER_CTX *CipherCtx = NULL;
    size_t OutLen = 0;
    int Len = 0;

    QUIC_FRE_ASSERT(TagLen == QUIC_ENCRYPTION_OVERHEAD);

    if (OutputBufferLen < PlainTextLen + TagLen) {
        LogError("[ tls] Incorrect output buffer length :%ld.", OutputBufferLen);
        Ret = -1;
        goto Exit;
    }

    CipherCtx = EVP_CIPHER_CTX_new();

    if (CipherCtx == NULL) {
        LogError("[ tls] CipherCtx alloc failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, Aead, NULL, NULL, NULL) != 1) {
        LogError("[ tls] EVP_EncryptInit_ex() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, NonceLen, NULL) != 1) {
        LogError("[ tls] EVP_CIPHER_CTX_ctrl() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, NULL, NULL, Key, Nonce) != 1) {
        LogError("[ tls] EVP_EncryptInit_ex() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_EncryptUpdate(CipherCtx, NULL, &Len, Authdata, AuthDataLen) != 1) {
        LogError("[ tls] EVP_EncryptUpdate() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_EncryptUpdate(CipherCtx, OutputBuffer, &Len, PlainText, PlainTextLen) != 1) {
        LogError("[ tls] EVP_EncryptUpdate() failed.");
        Ret = -1;
        goto Exit;
    }

    OutLen = Len;

    if (EVP_EncryptFinal_ex(CipherCtx, OutputBuffer + OutLen, &Len) != 1) {
        LogError("[ tls] EVP_EncryptFinal_ex() failed.");
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
size_t
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
/*++

Routine Description:

    Decrypts a plain text data using low level OpenSSL APIs.

Arguments:

    OutputBuffer - A buffer to return decrypted data.

    OutputBufferLen - The output buffer length.

    CipherText - The cipher text buffer.

    CipherTextLen - The cipher text length.

    Key - The key to use for encryption.

    KeyLen - The key length.

    Nonce - The nonce.

    NonceLen - The nonce length.

    Authdata - The auth data.

    AuthDataLen - The auth data length.

    Aead - The aead cipher to use for decryption.

Return Value:

    The total decrypted bytes.

--*/
{
    size_t TagLen = QuicTlsAeadTagLength(Aead);
    size_t Ret = 0;
    EVP_CIPHER_CTX *CipherCtx = NULL;

    QUIC_FRE_ASSERT(TagLen == QUIC_ENCRYPTION_OVERHEAD);

    if (TagLen > CipherTextLen || OutputBufferLen + TagLen < CipherTextLen) {
        LogError("[ tls] Incorrect buffer length.");
        Ret = -1;
        goto Exit;
    }

    CipherTextLen -= TagLen;
    uint8_t *Tag = (uint8_t *)CipherText + CipherTextLen;

    CipherCtx = EVP_CIPHER_CTX_new();

    if (CipherCtx == NULL) {
        LogError("[ tls] CipherCtx alloc failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_DecryptInit_ex(CipherCtx, Aead, NULL, NULL, NULL) != 1) {
        LogError("[ tls] EVP_DecryptInit_ex() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_IVLEN, NonceLen, NULL) != 1) {
        LogError("[ tls] EVP_CIPHER_CTX_ctrl() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_DecryptInit_ex(CipherCtx, NULL, NULL, Key, Nonce) != 1) {
        LogError("[ tls] EVP_DecryptInit_ex() failed.");
        Ret = -1;
        goto Exit;
    }

    size_t OutLen;
    int Len;

    if (EVP_DecryptUpdate(CipherCtx, NULL, &Len, AuthData, AuthDataLen) != 1) {
        LogError("[ tls] EVP_DecryptUpdate() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_DecryptUpdate(CipherCtx, OutputBuffer, &Len, CipherText, CipherTextLen) != 1) {
        LogError("[ tls] EVP_DecryptUpdate() failed.");
        Ret = -1;
        goto Exit;
    }

    OutLen = Len;

    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_TAG, TagLen, Tag) != 1) {
        LogError("[ tls] EVP_CIPHER_CTX_ctrl() failed.");
        Ret = -1;
        goto Exit;
    }

    if (EVP_DecryptFinal_ex(CipherCtx, OutputBuffer + OutLen, &Len) != 1) {
        LogError("[ tls] EVP_DecryptFinal_ex() failed.");
        Ret = -1;
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
/*++

Routine Description:

    Computes a header mask using low level OpenSSL APIs.

Arguments:

    OutputBuffer - A buffer to return mask.

    OutputBufferLen - The output buffer length.

    Key - The key to use for encryption.

    KeyLen - The key length.

    Cipher - The cipher data to use for header mask.

    Aead - The Aead cipher to use.

Return Value:

    TRUE on success, FALSE on failure.

--*/
{
    BOOLEAN Ret = TRUE;
    uint8_t Temp[16] = {0};
    int OutputLen = 0;
    int Len = 0;
    uint8_t Zero[5] = {0};
    uint32_t Ctr = 0;
    uint8_t Iv[16] = {0};
    static const uint8_t PLAINTEXT[] = "\x00\x00\x00\x00\x00";

    EVP_CIPHER_CTX *CipherCtx = EVP_CIPHER_CTX_new();

    if (CipherCtx == NULL) {
        LogError("[ tls] Cipherctx alloc failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_EncryptInit_ex(CipherCtx, Aead, NULL, Key, Cipher) != 1) {
        LogError("[ tls] EVP_EncryptInit_ex() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_EncryptUpdate(CipherCtx, Temp, &Len, PLAINTEXT, sizeof(PLAINTEXT) - 1) != 1) {
        LogError("[ tls] EVP_EncryptUpdate() failed.");
        Ret = FALSE;
        goto Exit;
    }

    QUIC_FRE_ASSERT(Len == 5);
    OutputLen += Len;

    if (EVP_EncryptFinal_ex(CipherCtx, Temp + OutputLen, &Len) != 1) {
        LogError("[ tls] EVP_EncryptFinal_ex() failed.");
        Ret = FALSE;
        goto Exit;
    }

    QUIC_FRE_ASSERT(Len == 0);

    QuicCopyMemory(OutputBuffer, Temp, OutputLen);

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
/*++

Routine Description:

    Computes a hash using low level OpenSSL APIs.

Arguments:

    OutputBuffer - A buffer to return hash.

    OutputBufferLen - The output buffer length.

    Secret - The secret.

    SecretLen - The secret length.

    Salt - The salt.

    SaltLen - The salt length.

    Hash - The quic hash object.

Return Value:

    TRUE on success, FALSE on failure.

--*/
{
    BOOLEAN Ret = TRUE;
    EVP_PKEY_CTX *KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (KeyCtx == NULL) {
        LogError("[ tls] KeyCtx alloc failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive_init(KeyCtx) != 1) {
        LogError("[ tls] EVP_PKEY_derive_init() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_hkdf_mode(KeyCtx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_hkdf_mode() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(KeyCtx, Hash->Md) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set_hkdf_md() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(KeyCtx, Salt, SaltLen) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set1_hkdf_salt() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(KeyCtx, Secret, SecretLen) != 1) {
        LogError("[ tls] EVP_PKEY_CTX_set1_hkdf_key() failed.");
        Ret = FALSE;
        goto Exit;
    }

    if (EVP_PKEY_derive(KeyCtx, OutputBuffer, &OutputBufferLen) != 1) {
        LogError("[ tls] EVP_PKEY_derive() failed.");
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
