/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the cryptographic functions by calling OpenSSL.

--*/

#include "platform_internal.h"

#include "openssl/opensslv.h"
#if OPENSSL_VERSION_MAJOR >= 3
#define IS_OPENSSL_3
#endif

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#else
#include <dlfcn.h>
#endif
#include "openssl/bio.h"
#ifdef IS_OPENSSL_3
#include "openssl/core_names.h"
#else
#include "openssl/hmac.h"
#endif
#include "openssl/err.h"
#include "openssl/evp.h"
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
#include "crypt_openssl.c.clog.h"
#endif

EVP_CIPHER *CXPLAT_AES_128_GCM_ALG_HANDLE;
EVP_CIPHER *CXPLAT_AES_256_GCM_ALG_HANDLE;
EVP_CIPHER *CXPLAT_AES_256_CBC_ALG_HANDLE;
EVP_CIPHER *CXPLAT_AES_128_ECB_ALG_HANDLE;
EVP_CIPHER *CXPLAT_AES_256_ECB_ALG_HANDLE;
EVP_CIPHER *CXPLAT_CHACHA20_ALG_HANDLE;
EVP_CIPHER *CXPLAT_CHACHA20_POLY1305_ALG_HANDLE;
#ifdef IS_OPENSSL_3
EVP_MAC_CTX *CXPLAT_HMAC_SHA256_CTX_HANDLE;
EVP_MAC_CTX *CXPLAT_HMAC_SHA384_CTX_HANDLE;
EVP_MAC_CTX *CXPLAT_HMAC_SHA512_CTX_HANDLE;

_Success_(return != 0)
int
CxPlatLoadCipher(
    _In_ char *cipher_name,
    _Outptr_ EVP_CIPHER **cipher
    )
{
    *cipher = EVP_CIPHER_fetch(NULL, cipher_name, "");
    if (*cipher == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            cipher_name);
        return 0;
    }
    return 1;
}

_Success_(return != 0)
int
CxPlatLoadMAC(
    _In_ char *name,
    _Outptr_ EVP_MAC **mac
    )
{
    *mac = EVP_MAC_fetch(NULL, name, "");
    if (*mac == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_MAC_fetch failed");
        return 0;
    }
    return 1;
}

_Success_(return != 0)
int
CxPlatLoadHMACCTX(
    _In_ EVP_MAC *mac,
    _In_ char *digest,
    _Outptr_ EVP_MAC_CTX **ctx
    )
{
    EVP_MAC_CTX *c;
    OSSL_PARAM AlgParam[2];

    c = EVP_MAC_CTX_new(mac);
    if (c == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "EVP_MAC_CTX_new",
            0);
        return 0;
    }
    AlgParam[0] = OSSL_PARAM_construct_utf8_string("digest", digest, 0);
    AlgParam[1] = OSSL_PARAM_construct_end();
    if (!EVP_MAC_CTX_set_params(c, AlgParam)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_CTX_set_params failed");
        EVP_MAC_CTX_free(c);
        return 0;
    }
    *ctx = c;
    return 1;
}
#endif

typedef struct CXPLAT_HP_KEY {
    EVP_CIPHER_CTX* CipherCtx;
    CXPLAT_AEAD_TYPE Aead;
} CXPLAT_HP_KEY;

#if defined CXPLAT_SYSTEM_CRYPTO && !defined IS_OPENSSL_3 && !defined _WIN32
// This is to fulfill link dependency in ssl_init.
// If system OpenSSL has chacha support, we will redirect it to loaded handle.
//
const EVP_CIPHER *EVP_chacha20_poly1305(void)
{
    return CXPLAT_CHACHA20_POLY1305_ALG_HANDLE;
}
#endif

QUIC_STATUS
CxPlatCryptInitialize(
    void
    )
{
#ifdef IS_OPENSSL_3
    EVP_MAC *mac = NULL;
#endif

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "OPENSSL_init_ssl failed");
        return QUIC_STATUS_TLS_ERROR;
    }

#ifdef IS_OPENSSL_3
    //
    // Preload ciphers
    //
    if (!CxPlatLoadCipher("AES-128-GCM", &CXPLAT_AES_128_GCM_ALG_HANDLE) ||
        !CxPlatLoadCipher("AES-256-GCM", &CXPLAT_AES_256_GCM_ALG_HANDLE) ||
        !CxPlatLoadCipher("AES-256-CBC", &CXPLAT_AES_256_CBC_ALG_HANDLE) ||
        !CxPlatLoadCipher("AES-128-ECB", &CXPLAT_AES_128_ECB_ALG_HANDLE) ||
        !CxPlatLoadCipher("AES-256-ECB", &CXPLAT_AES_256_ECB_ALG_HANDLE)) {
        goto Error;
    }

    //
    // Load ChaCha20 ciphers if they exist.
    //
    CxPlatLoadCipher("ChaCha20", &CXPLAT_CHACHA20_ALG_HANDLE);
    CxPlatLoadCipher("ChaCha20-Poly1305", &CXPLAT_CHACHA20_POLY1305_ALG_HANDLE);

    //
    // Preload HMAC
    //
    if (!CxPlatLoadMAC("HMAC", &mac)) {
        goto Error;
    }

    //
    // Preload HMACs with digest
    //
    if (!CxPlatLoadHMACCTX(mac, "sha256", &CXPLAT_HMAC_SHA256_CTX_HANDLE) ||
        !CxPlatLoadHMACCTX(mac, "sha384", &CXPLAT_HMAC_SHA384_CTX_HANDLE) ||
        !CxPlatLoadHMACCTX(mac, "sha512", &CXPLAT_HMAC_SHA512_CTX_HANDLE)) {
        goto Error;
    }
    EVP_MAC_free(mac);

    return QUIC_STATUS_SUCCESS;

Error:
    EVP_MAC_free(mac);
    CxPlatCryptUninitialize();
    return QUIC_STATUS_OUT_OF_MEMORY;
#else // ! IS_OPENSSL_3
    CXPLAT_AES_128_GCM_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_128_gcm();
    CXPLAT_AES_256_GCM_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_256_gcm();
    CXPLAT_AES_256_CBC_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_256_cbc();
    CXPLAT_AES_128_ECB_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_128_ecb();
    CXPLAT_AES_256_ECB_ALG_HANDLE = (EVP_CIPHER *)EVP_aes_256_ecb();
#if defined _WIN32 || !defined CXPLAT_SYSTEM_CRYPTO
    CXPLAT_CHACHA20_ALG_HANDLE = (EVP_CIPHER *)EVP_chacha20();
    CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = (EVP_CIPHER *)EVP_chacha20_poly1305();
#else
    CXPLAT_CHACHA20_ALG_HANDLE = NULL;
    CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = NULL;

    //
    // Try to load ChaCha20 ciphers dynamically. They may or may not exist when using system crypto.
    //
    void* handle = dlopen("libcrypto.so.1.1", RTLD_LAZY | RTLD_GLOBAL);
    EVP_CIPHER* (*func)(void) = NULL;
    if (handle != NULL) {
        func = dlsym(handle, "EVP_chacha20");
        if (func != NULL) {
            CXPLAT_CHACHA20_ALG_HANDLE = (*func)();

            func = dlsym(handle, "EVP_chacha20_poly1305");
            if (func != NULL) {
                CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = (*func)();
                EVP_add_cipher(CXPLAT_CHACHA20_POLY1305_ALG_HANDLE);
            }
        } else {
            dlclose(handle);
        }
    }
#endif
    return QUIC_STATUS_SUCCESS;
#endif
}

BOOLEAN
CxPlatCryptSupports(
    CXPLAT_AEAD_TYPE AeadType
    )
{
    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        return CXPLAT_AES_128_GCM_ALG_HANDLE != NULL;
    case CXPLAT_AEAD_AES_256_GCM:
        return CXPLAT_AES_256_GCM_ALG_HANDLE != NULL;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        return CXPLAT_CHACHA20_ALG_HANDLE != NULL;
    default:
        return FALSE;
    }
}

void
CxPlatCryptUninitialize(
    void
    )
{
#ifdef IS_OPENSSL_3
    EVP_CIPHER_free(CXPLAT_AES_128_GCM_ALG_HANDLE);
    CXPLAT_AES_128_GCM_ALG_HANDLE = NULL;
    EVP_CIPHER_free(CXPLAT_AES_256_CBC_ALG_HANDLE);
    CXPLAT_AES_256_CBC_ALG_HANDLE = NULL;
    EVP_CIPHER_free(CXPLAT_AES_128_ECB_ALG_HANDLE);
    CXPLAT_AES_128_ECB_ALG_HANDLE = NULL;
    EVP_CIPHER_free(CXPLAT_AES_256_ECB_ALG_HANDLE);
    CXPLAT_AES_256_ECB_ALG_HANDLE = NULL;
    if (CXPLAT_CHACHA20_ALG_HANDLE != NULL) {
        EVP_CIPHER_free(CXPLAT_CHACHA20_ALG_HANDLE);
        CXPLAT_CHACHA20_ALG_HANDLE = NULL;
    }
    if (CXPLAT_CHACHA20_POLY1305_ALG_HANDLE != NULL) {
        EVP_CIPHER_free(CXPLAT_CHACHA20_POLY1305_ALG_HANDLE);
        CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = NULL;
    }

    EVP_MAC_CTX_free(CXPLAT_HMAC_SHA256_CTX_HANDLE);
    CXPLAT_HMAC_SHA256_CTX_HANDLE = NULL;
    EVP_MAC_CTX_free(CXPLAT_HMAC_SHA384_CTX_HANDLE);
    CXPLAT_HMAC_SHA384_CTX_HANDLE = NULL;
    EVP_MAC_CTX_free(CXPLAT_HMAC_SHA512_CTX_HANDLE);
    CXPLAT_HMAC_SHA512_CTX_HANDLE = NULL;
#endif
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
#ifdef IS_OPENSSL_3
    OSSL_PARAM AlgParam[2];
    size_t TagLength;
#endif

    EVP_CIPHER_CTX* CipherCtx = EVP_CIPHER_CTX_new();
    if (CipherCtx == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "EVP_CIPHER_CTX_new",
            0);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        Aead = CXPLAT_AES_128_GCM_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        Aead = CXPLAT_AES_256_GCM_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        if (CXPLAT_CHACHA20_POLY1305_ALG_HANDLE == NULL) {
            Status = QUIC_STATUS_NOT_SUPPORTED;
            goto Exit;
        }
        Aead = CXPLAT_CHACHA20_POLY1305_ALG_HANDLE;
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

#ifdef IS_OPENSSL_3
    TagLength = CXPLAT_IV_LENGTH;
    AlgParam[0] = OSSL_PARAM_construct_size_t("ivlen", &TagLength);
    AlgParam[1] = OSSL_PARAM_construct_end();

    if (EVP_CipherInit_ex2(CipherCtx, Aead, RawKey, NULL, 1, AlgParam) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CipherInit_ex2 failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
#else
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
#endif

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
#ifdef IS_OPENSSL_3
    OSSL_PARAM AlgParam[2];
#endif

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

#ifdef IS_OPENSSL_3
    AlgParam[0] = OSSL_PARAM_construct_octet_string("tag", Tag, CXPLAT_ENCRYPTION_OVERHEAD);
    AlgParam[1] = OSSL_PARAM_construct_end();

    if (EVP_CIPHER_CTX_get_params(CipherCtx, AlgParam) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_get_params (GET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }
#else
    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_GET_TAG, CXPLAT_ENCRYPTION_OVERHEAD, Tag) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }
#endif

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
#ifdef IS_OPENSSL_3
    OSSL_PARAM AlgParam[2];
#endif

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

#ifdef IS_OPENSSL_3
    AlgParam[0] = OSSL_PARAM_construct_octet_string("tag", Tag, CXPLAT_ENCRYPTION_OVERHEAD);
    AlgParam[1] = OSSL_PARAM_construct_end();

    if (EVP_CIPHER_CTX_set_params(CipherCtx, AlgParam) != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_set_params (SET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }
#else
    if (EVP_CIPHER_CTX_ctrl(CipherCtx, EVP_CTRL_AEAD_SET_TAG, CXPLAT_ENCRYPTION_OVERHEAD, Tag) != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
        return QUIC_STATUS_TLS_ERROR;
    }
#endif

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
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "EVP_CIPHER_CTX_new",
            0);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        Aead = CXPLAT_AES_128_ECB_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        Aead = CXPLAT_AES_256_ECB_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        if (CXPLAT_CHACHA20_ALG_HANDLE == NULL) {
            Status = QUIC_STATUS_NOT_SUPPORTED;
            goto Exit;
        }
        Aead = CXPLAT_CHACHA20_ALG_HANDLE;
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

#ifdef IS_OPENSSL_3
//
// OpenSSL 3.0 Hash implementation
//
typedef struct CXPLAT_HASH {
    EVP_MAC_CTX* Ctx;
    uint32_t SaltLength;
    uint8_t Salt[0];
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
    CXPLAT_HASH* Hash;
    EVP_MAC_CTX *hctx = NULL;

    Hash = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_HASH) + SaltLength, QUIC_POOL_TLS_HASH);
    if (Hash == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Crypt Hash Context",
            sizeof(CXPLAT_HASH) + SaltLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CxPlatZeroMemory(Hash, sizeof(CXPLAT_HASH) + SaltLength);

    Hash->SaltLength = SaltLength;
    CxPlatCopyMemory(Hash->Salt, Salt, SaltLength);

    switch (HashType) {
    case CXPLAT_HASH_SHA256:
        hctx = CXPLAT_HMAC_SHA256_CTX_HANDLE;
        break;
    case CXPLAT_HASH_SHA384:
        hctx = CXPLAT_HMAC_SHA384_CTX_HANDLE;
        break;
    case CXPLAT_HASH_SHA512:
        hctx = CXPLAT_HMAC_SHA512_CTX_HANDLE;
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    Hash->Ctx = EVP_MAC_CTX_dup(hctx);
    if (Hash->Ctx == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "EVP_MAC_CTX_dup",
            0);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    *NewHash = Hash;
    Hash = NULL;

Exit:

    CxPlatHashFree(Hash);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    if (Hash) {
        EVP_MAC_CTX_free(Hash->Ctx);
        CXPLAT_FREE(Hash, QUIC_POOL_TLS_HASH);
    }
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
    if (!EVP_MAC_init(Hash->Ctx, Hash->Salt, Hash->SaltLength, NULL)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_init failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    if (!EVP_MAC_update(Hash->Ctx, Input, InputLength)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_update failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    size_t ActualOutputSize = OutputLength;
    if (!EVP_MAC_final(Hash->Ctx, Output, &ActualOutputSize, OutputLength)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_final failed");
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    CXPLAT_FRE_ASSERT(ActualOutputSize == OutputLength);
    return QUIC_STATUS_SUCCESS;
}
#else
//
// OpenSSL 1.1 Hash implementation
//
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
#endif
