/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    BCrypt cryptographic implementation for QUIC

Environment:

    Windows user mode or kernel mode

--*/

#include "platform_internal.h"
#include <security.h>
#ifdef QUIC_CLOG
#include "crypt_bcrypt.c.clog.h"
#endif

typedef struct CXPLAT_HP_KEY {
    BCRYPT_KEY_HANDLE Key;
    CXPLAT_AEAD_TYPE Aead;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info[0];
} CXPLAT_HP_KEY;

#define SecStatusToQuicStatus(x) (QUIC_STATUS)(x)

#ifdef QUIC_RESTRICTED_BUILD
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

_When_(Status < 0, _Out_range_(>, 0))
_When_(Status >= 0, _Out_range_(==, 0))
ULONG
NTAPI
RtlNtStatusToDosError (
   NTSTATUS Status
   );
#endif

#ifdef _KERNEL_MODE
#define NtStatusToQuicStatus(x) (x)
#else
#define NtStatusToQuicStatus(x) HRESULT_FROM_WIN32(RtlNtStatusToDosError(x))
#endif

//
// Defines until BCrypt.h updates
//
#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif

#ifdef _KERNEL_MODE
BCRYPT_ALG_HANDLE CXPLAT_HMAC_SHA256_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_HMAC_SHA384_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_HMAC_SHA512_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_AES_ECB_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_AES_GCM_ALG_HANDLE;
#else
BCRYPT_ALG_HANDLE CXPLAT_HMAC_SHA256_ALG_HANDLE = BCRYPT_HMAC_SHA256_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_HMAC_SHA384_ALG_HANDLE = BCRYPT_HMAC_SHA384_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_HMAC_SHA512_ALG_HANDLE = BCRYPT_HMAC_SHA512_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_AES_ECB_ALG_HANDLE = BCRYPT_AES_ECB_ALG_HANDLE;
BCRYPT_ALG_HANDLE CXPLAT_AES_GCM_ALG_HANDLE = BCRYPT_AES_GCM_ALG_HANDLE;
#endif
BCRYPT_ALG_HANDLE CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = NULL;

QUIC_STATUS
CxPlatCryptInitialize(
    void
    )
{
#ifdef _KERNEL_MODE
    ULONG Flags = BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_PROV_DISPATCH;
    NTSTATUS Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_HMAC_SHA256_ALG_HANDLE,
            BCRYPT_SHA256_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            Flags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA256 algorithm");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_HMAC_SHA384_ALG_HANDLE,
            BCRYPT_SHA384_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            Flags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA384 algorithm");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_HMAC_SHA512_ALG_HANDLE,
            BCRYPT_SHA512_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            Flags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA512 algorithm");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_AES_ECB_ALG_HANDLE,
            BCRYPT_AES_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open AES algorithm");
        goto Error;
    }

    Status =
        BCryptSetProperty(
            CXPLAT_AES_ECB_ALG_HANDLE,
            BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_ECB,
            sizeof(BCRYPT_CHAIN_MODE_ECB),
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Set ECB chaining mode");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_AES_GCM_ALG_HANDLE,
            BCRYPT_AES_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open AES algorithm");
        goto Error;
    }

    Status =
        BCryptSetProperty(
            CXPLAT_AES_GCM_ALG_HANDLE,
            BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_GCM,
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Set GCM chaining mode");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_CHACHA20_POLY1305_ALG_HANDLE,
            BCRYPT_CHACHA20_POLY1305_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open ChaCha20-Poly1305 algorithm");
        //
        // ChaCha20-Poly1305 may not be supported on older OSes, so don't treat
        // this failure as fatal.
        //
        Status = QUIC_STATUS_SUCCESS;
    } else {
        Status =
            BCryptSetProperty(
                CXPLAT_CHACHA20_POLY1305_ALG_HANDLE,
                BCRYPT_CHAINING_MODE,
                (PBYTE)BCRYPT_CHAIN_MODE_NA,
                sizeof(BCRYPT_CHAIN_MODE_NA),
                0);
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Set ChaCha20-Poly1305 chaining mode");
            goto Error;
        }
    }

Error:

    if (!NT_SUCCESS(Status)) {
        if (CXPLAT_HMAC_SHA256_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_HMAC_SHA256_ALG_HANDLE, 0);
            CXPLAT_HMAC_SHA256_ALG_HANDLE = NULL;
        }
        if (CXPLAT_HMAC_SHA384_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_HMAC_SHA384_ALG_HANDLE, 0);
            CXPLAT_HMAC_SHA384_ALG_HANDLE = NULL;
        }
        if (CXPLAT_HMAC_SHA512_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_HMAC_SHA512_ALG_HANDLE, 0);
            CXPLAT_HMAC_SHA512_ALG_HANDLE = NULL;
        }
        if (CXPLAT_AES_ECB_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_AES_ECB_ALG_HANDLE, 0);
            CXPLAT_AES_ECB_ALG_HANDLE = NULL;
        }
        if (CXPLAT_AES_GCM_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_AES_GCM_ALG_HANDLE, 0);
            CXPLAT_AES_GCM_ALG_HANDLE = NULL;
        }
        if (CXPLAT_CHACHA20_POLY1305_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_CHACHA20_POLY1305_ALG_HANDLE, 0);
            CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = NULL;
        }
    }

    return NtStatusToQuicStatus(Status);
#else
    NTSTATUS Status =
        BCryptOpenAlgorithmProvider(
            &CXPLAT_CHACHA20_POLY1305_ALG_HANDLE,
            BCRYPT_CHACHA20_POLY1305_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open ChaCha20-Poly1305 algorithm");
        //
        // ChaCha20-Poly1305 may not be supported on older OSes, so don't treat
        // this failure as fatal.
        //
        Status = QUIC_STATUS_SUCCESS;
    } else {
        Status =
            BCryptSetProperty(
                CXPLAT_CHACHA20_POLY1305_ALG_HANDLE,
                BCRYPT_CHAINING_MODE,
                (PBYTE)BCRYPT_CHAIN_MODE_NA,
                sizeof(BCRYPT_CHAIN_MODE_NA),
                0);
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Set ChaCha20-Poly1305 chaining mode");
            goto Error;
        }
    }

Error:
    if (!NT_SUCCESS(Status)) {
        if (CXPLAT_CHACHA20_POLY1305_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(CXPLAT_CHACHA20_POLY1305_ALG_HANDLE, 0);
            CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = NULL;
        }
    }
    return NtStatusToQuicStatus(Status);
#endif
}

void
CxPlatCryptUninitialize(
    void
    )
{
#ifdef _KERNEL_MODE
    BCryptCloseAlgorithmProvider(CXPLAT_HMAC_SHA256_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(CXPLAT_HMAC_SHA384_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(CXPLAT_HMAC_SHA512_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(CXPLAT_AES_ECB_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(CXPLAT_AES_GCM_ALG_HANDLE, 0);
    CXPLAT_HMAC_SHA256_ALG_HANDLE = NULL;
    CXPLAT_HMAC_SHA384_ALG_HANDLE = NULL;
    CXPLAT_HMAC_SHA512_ALG_HANDLE = NULL;
    CXPLAT_AES_ECB_ALG_HANDLE = NULL;
    CXPLAT_AES_GCM_ALG_HANDLE = NULL;
#endif
    if (CXPLAT_CHACHA20_POLY1305_ALG_HANDLE != NULL) {
        BCryptCloseAlgorithmProvider(CXPLAT_CHACHA20_POLY1305_ALG_HANDLE, 0);
        CXPLAT_CHACHA20_POLY1305_ALG_HANDLE = NULL;
    }
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
    uint8_t KeyLength;
    BCRYPT_ALG_HANDLE KeyAlgHandle;

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        KeyLength = 16;
        KeyAlgHandle = CXPLAT_AES_GCM_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        KeyLength = 32;
        KeyAlgHandle = CXPLAT_AES_GCM_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        KeyLength = 32;
        KeyAlgHandle = CXPLAT_CHACHA20_POLY1305_ALG_HANDLE;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status =
        BCryptGenerateSymmetricKey(
            KeyAlgHandle,
            (BCRYPT_KEY_HANDLE*)NewKey,
            NULL, // Let BCrypt manage the memory for this key.
            0,
            (uint8_t*)RawKey,
            KeyLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptGenerateSymmetricKey");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    )
{
    if (Key) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)Key);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatEncrypt(
    _In_ CXPLAT_KEY* _Key,
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
    NTSTATUS Status;
    ULONG CipherTextSize;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
    BCRYPT_KEY_HANDLE Key = (BCRYPT_KEY_HANDLE)_Key;

    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

#ifdef QUIC_FUZZER
    if (MsQuicFuzzerContext.EncryptCallback) {
#pragma prefast(suppress: __WARNING_26000, "Auth Data and Buffer are always contiguous")
        MsQuicFuzzerContext.EncryptCallback(
            MsQuicFuzzerContext.CallbackContext,
            (uint8_t*)AuthData,
            AuthDataLength + BufferLength
        );
    }
#endif

    BCRYPT_INIT_AUTH_MODE_INFO(Info);
    Info.pbAuthData = (uint8_t*)AuthData;
    Info.cbAuthData = AuthDataLength;
    Info.pbTag = Buffer + (BufferLength - CXPLAT_ENCRYPTION_OVERHEAD);
    Info.cbTag = CXPLAT_ENCRYPTION_OVERHEAD;
    Info.pbNonce = (uint8_t*)Iv;
    Info.cbNonce = CXPLAT_IV_LENGTH;

    Status =
        BCryptEncrypt(
            Key,
            Buffer,
            BufferLength - CXPLAT_ENCRYPTION_OVERHEAD,
            &Info,
            NULL,
            0,
            Buffer,
            BufferLength,
            &CipherTextSize,
            0);

    CXPLAT_DBG_ASSERT(CipherTextSize == (ULONG)(BufferLength - CXPLAT_ENCRYPTION_OVERHEAD));

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatDecrypt(
    _In_ CXPLAT_KEY* _Key,
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
    NTSTATUS Status;
    ULONG PlainTextSize;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
    BCRYPT_KEY_HANDLE Key = (BCRYPT_KEY_HANDLE)_Key;

    CXPLAT_DBG_ASSERT(CXPLAT_ENCRYPTION_OVERHEAD <= BufferLength);

    BCRYPT_INIT_AUTH_MODE_INFO(Info);
    Info.pbAuthData = (uint8_t*)AuthData;
    Info.cbAuthData = AuthDataLength;
    Info.pbTag = Buffer + (BufferLength - CXPLAT_ENCRYPTION_OVERHEAD);
    Info.cbTag = CXPLAT_ENCRYPTION_OVERHEAD;
    Info.pbNonce = (uint8_t*)Iv;
    Info.cbNonce = CXPLAT_IV_LENGTH;

    Status =
        BCryptDecrypt(
            Key,
            Buffer,
            BufferLength - CXPLAT_ENCRYPTION_OVERHEAD,
            &Info,
            NULL,
            0,
            Buffer,
            BufferLength - CXPLAT_ENCRYPTION_OVERHEAD,
            &PlainTextSize,
            0);

    CXPLAT_DBG_ASSERT(PlainTextSize == (ULONG)(BufferLength - CXPLAT_ENCRYPTION_OVERHEAD));

    return NtStatusToQuicStatus(Status);
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
    BCRYPT_ALG_HANDLE AlgHandle;
    CXPLAT_HP_KEY* Key = NULL;
    uint32_t AllocLength;
    uint8_t KeyLength;

    switch (AeadType) {
    case CXPLAT_AEAD_AES_128_GCM:
        KeyLength = 16;
        AllocLength = sizeof(CXPLAT_HP_KEY);
        AlgHandle = CXPLAT_AES_ECB_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_AES_256_GCM:
        KeyLength = 32;
        AllocLength = sizeof(CXPLAT_HP_KEY);
        AlgHandle = CXPLAT_AES_ECB_ALG_HANDLE;
        break;
    case CXPLAT_AEAD_CHACHA20_POLY1305:
        KeyLength = 32;
        AllocLength =
            sizeof(CXPLAT_HP_KEY) +
            sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO) +
            CXPLAT_ENCRYPTION_OVERHEAD;
        AlgHandle = CXPLAT_CHACHA20_POLY1305_ALG_HANDLE;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    Key = CXPLAT_ALLOC_NONPAGED(AllocLength, QUIC_POOL_TLS_HP_KEY);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_HP_KEY",
            AllocLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Key->Aead = AeadType;

    NTSTATUS Status =
        BCryptGenerateSymmetricKey(
            AlgHandle,
            &Key->Key,
            NULL, // Let BCrypt manage the memory for this key.
            0,
            (uint8_t*)RawKey,
            KeyLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            (AeadType == CXPLAT_AEAD_CHACHA20_POLY1305) ?
                "BCryptGenerateSymmetricKey (ChaCha)" :
                "BCryptGenerateSymmetricKey (ECB)");
        goto Error;
    }

    if (AeadType == CXPLAT_AEAD_CHACHA20_POLY1305) {
        BCRYPT_INIT_AUTH_MODE_INFO(*Key->Info);
        Key->Info->pbTag = (uint8_t*)(Key->Info + 1);
        Key->Info->cbTag = CXPLAT_ENCRYPTION_OVERHEAD;
        Key->Info->pbAuthData = NULL;
        Key->Info->cbAuthData = 0;
    }

    *NewKey = Key;
    Key = NULL;

Error:

    if (Key) {
        CXPLAT_FREE(Key, QUIC_POOL_TLS_HP_KEY);
        Key = NULL;
    }

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHpKeyFree(
    _In_opt_ CXPLAT_HP_KEY* Key
    )
{
    if (Key) {
        BCryptDestroyKey(Key->Key);
        if (Key->Aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
            CxPlatSecureZeroMemory(Key->Info, sizeof(*Key->Info) + CXPLAT_ENCRYPTION_OVERHEAD);
        }
        CXPLAT_FREE(Key, QUIC_POOL_TLS_HP_KEY);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHpComputeMask(
    _In_ CXPLAT_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const Cipher,
    _Out_writes_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    )
{
    ULONG TempSize = 0;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (Key->Aead == CXPLAT_AEAD_CHACHA20_POLY1305) {
        //
        // This doesn't work because it needs to set the counter value
        // and BCrypt doesn't support that.
        //
        uint8_t Zero[5] = { 0, 0, 0, 0, 0 };
        Key->Info->cbNonce = CXPLAT_HP_SAMPLE_LENGTH;
        for (uint32_t i = 0, Offset = 0; i < BatchSize; ++i, Offset += CXPLAT_HP_SAMPLE_LENGTH) {
            Key->Info->pbNonce = (uint8_t*)(Cipher + Offset);
            Status =
                NtStatusToQuicStatus(
                BCryptEncrypt(
                    Key->Key,
                    Zero,
                    sizeof(Zero),
                    Key->Info,
                    NULL,
                    0,
                    Mask + Offset,
                    CXPLAT_HP_SAMPLE_LENGTH, // This will fail because the Tag won't fit
                    &TempSize,
                    0));
            if (QUIC_FAILED(Status)) {
                break;
            }
        }
    } else {
        Status =
            NtStatusToQuicStatus(
            BCryptEncrypt(
                Key->Key,
                (uint8_t*)Cipher,
                CXPLAT_HP_SAMPLE_LENGTH * BatchSize,
                NULL,
                NULL,
                0,
                Mask,
                CXPLAT_HP_SAMPLE_LENGTH * BatchSize,
                &TempSize,
                0));
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHashCreate(
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ CXPLAT_HASH** Hash
    )
{
    BCRYPT_ALG_HANDLE HashAlgHandle;

    switch (HashType) {
    case CXPLAT_HASH_SHA256:
        HashAlgHandle = CXPLAT_HMAC_SHA256_ALG_HANDLE;
        break;
    case CXPLAT_HASH_SHA384:
        HashAlgHandle = CXPLAT_HMAC_SHA384_ALG_HANDLE;
        break;
    case CXPLAT_HASH_SHA512:
        HashAlgHandle = CXPLAT_HMAC_SHA512_ALG_HANDLE;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status =
        BCryptCreateHash(
            HashAlgHandle,
            (BCRYPT_HASH_HANDLE*)Hash,
            NULL, // Let BCrypt manage the memory for this hash object.
            0,
            (uint8_t*)Salt,
            (ULONG)SaltLength,
            BCRYPT_HASH_REUSABLE_FLAG);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptCreateHash");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    if (Hash) {
        BCryptDestroyHash((BCRYPT_HASH_HANDLE)Hash);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHashCompute(
    _In_ CXPLAT_HASH* Hash,
    _In_reads_(InputLength)
        const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength,
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    BCRYPT_HASH_HANDLE HashHandle = (BCRYPT_HASH_HANDLE)Hash;

    NTSTATUS Status =
        BCryptHashData(
            HashHandle,
            (uint8_t*)Input,
            InputLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptHashData");
        goto Error;
    }

    Status =
        BCryptFinishHash(
            HashHandle,
            Output,
            OutputLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptFinishHash");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}
