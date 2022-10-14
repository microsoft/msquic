/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Symcrypt cryptographic implementation for QUIC

Environment:

    Windows user mode or kernel mode

--*/

#include "platform_internal.h"
#include <symcrypt.h>
#ifdef QUIC_CLOG
#include "crypt_symcrypt.c.clog.h"
#endif

typedef struct CXPLAT_HP_KEY {
    VOID* Key;
    CXPLAT_AEAD_TYPE Aead;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthenticatedInfo[0];
} CXPLAT_HP_KEY;

QUIC_STATUS
CxPlatCryptInitialize(
    void
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(AeadType);
    UNREFERENCED_PARAMETER(RawKey);
    UNREFERENCED_PARAMETER(NewKey);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    )
{
    UNREFERENCED_PARAMETER(Key);
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
    UNREFERENCED_PARAMETER(_Key);
    UNREFERENCED_PARAMETER(Iv);
    UNREFERENCED_PARAMETER(AuthDataLength);
    UNREFERENCED_PARAMETER(AuthData);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    return QUIC_STATUS_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(_Key);
    UNREFERENCED_PARAMETER(Iv);
    UNREFERENCED_PARAMETER(AuthDataLength);
    UNREFERENCED_PARAMETER(AuthData);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    return QUIC_STATUS_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(AeadType);
    UNREFERENCED_PARAMETER(RawKey);
    UNREFERENCED_PARAMETER(NewKey);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHpKeyFree(
    _In_opt_ CXPLAT_HP_KEY* Key
    )
{
    UNREFERENCED_PARAMETER(Key);
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
    UNREFERENCED_PARAMETER(Key);
    UNREFERENCED_PARAMETER(BatchSize);
    UNREFERENCED_PARAMETER(Cipher);
    UNREFERENCED_PARAMETER(Mask);
    return QUIC_STATUS_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(HashType);
    UNREFERENCED_PARAMETER(SaltLength);
    UNREFERENCED_PARAMETER(Salt);
    UNREFERENCED_PARAMETER(Hash);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    )
{
    UNREFERENCED_PARAMETER(Hash);
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
    UNREFERENCED_PARAMETER(Input);
    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(Output);
    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Hash);
    return QUIC_STATUS_NOT_SUPPORTED;
}

BOOLEAN
CxPlatCryptIsChaCha20Poly1305Supported(
    )
{
    return TRUE;
}