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
#include "crypt_openssl.c.clog.h"
#endif

typedef struct CXPLAT_HP_KEY {
    EVP_CIPHER_CTX* CipherCtx;
    CXPLAT_AEAD_TYPE Aead;
} CXPLAT_HP_KEY;

QUIC_STATUS
CxPlatCryptInitialize(
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
CxPlatCryptUninitialize(
    void
    )
{
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

#ifdef IS_OPENSSL_3
//
// OpenSSL 3.0 Hash implementation
//
typedef struct CXPLAT_HASH {
    EVP_MAC* Mac;
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
    const char* HashString;
    OSSL_PARAM AlgParam[2];

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

    Hash->Mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (Hash->Mac == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_fetch failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Hash->Ctx = EVP_MAC_CTX_new(Hash->Mac);
    if (Hash->Ctx == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_CTX_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    switch (HashType) {
    case CXPLAT_HASH_SHA256:
        HashString = "sha256";
        break;
    case CXPLAT_HASH_SHA384:
        HashString = "sha384";
        break;
    case CXPLAT_HASH_SHA512:
        HashString = "sha512";
        break;
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    AlgParam[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)HashString, 0);
    AlgParam[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_CTX_set_params(Hash->Ctx, AlgParam)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_MAC_CTX_set_params failed");
        Status = QUIC_STATUS_TLS_ERROR;
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
        if (Hash->Ctx) {
            EVP_MAC_CTX_free(Hash->Ctx);
        }
        if (Hash->Mac) {
            EVP_MAC_free(Hash->Mac);
        }
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
