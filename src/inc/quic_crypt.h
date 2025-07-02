/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for the cryptographic functions.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4214)  // nonstandard extension used: bit field types other than int

typedef struct CXPLAT_KEY CXPLAT_KEY;
typedef struct CXPLAT_HP_KEY CXPLAT_HP_KEY;
typedef struct CXPLAT_HASH CXPLAT_HASH;
typedef struct CXPLAT_QEO_CONNECTION CXPLAT_QEO_CONNECTION;

#define CXPLAT_HKDF_PREFIX        "tls13 "
#define CXPLAT_HKDF_PREFIX_LEN    (sizeof(CXPLAT_HKDF_PREFIX) - 1)

//
// Length of the salt for version specific initial keys.
//
#define CXPLAT_VERSION_SALT_LENGTH 20

//
// The overhead in a packet from encryption.
//
#define CXPLAT_ENCRYPTION_OVERHEAD 16

//
// The length of the IV used in QUIC.
//
#define CXPLAT_IV_LENGTH 12

//
// The maximum buffer length of the IV need by the platform layer.
//
#ifdef _WIN32
#define CXPLAT_MAX_IV_LENGTH 48 // BCrypt requires block size
#else
#define CXPLAT_MAX_IV_LENGTH CXPLAT_IV_LENGTH
#endif

//
// The length of buffer used for header protection sampling.
//
#define CXPLAT_HP_SAMPLE_LENGTH 16

//
// Different AEAD algorithms supported for QUIC.
//
typedef enum CXPLAT_AEAD_TYPE {

    CXPLAT_AEAD_AES_128_GCM       = 0,    // 16 byte key
    CXPLAT_AEAD_AES_256_GCM       = 1,    // 32 byte key
    CXPLAT_AEAD_CHACHA20_POLY1305 = 2     // 32 byte key

} CXPLAT_AEAD_TYPE;

CXPLAT_STATIC_ASSERT(
    (uint32_t)CXPLAT_AEAD_AES_128_GCM == (uint32_t)QUIC_AEAD_ALGORITHM_AES_128_GCM &&
    (uint32_t)CXPLAT_AEAD_AES_256_GCM == (uint32_t)QUIC_AEAD_ALGORITHM_AES_256_GCM,
    "CXPLAT AEAD algorithm enum values must match the QUIC API enum values.");

typedef enum CXPLAT_AEAD_TYPE_SIZE {

    CXPLAT_AEAD_AES_128_GCM_SIZE       = 16,
    CXPLAT_AEAD_AES_256_GCM_SIZE       = 32,
    CXPLAT_AEAD_CHACHA20_POLY1305_SIZE = 32,

    CXPLAT_AEAD_MAX_SIZE               = 32 // This should be the max of the above values.

} CXPLAT_AEAD_TYPE_SIZE;

QUIC_INLINE
uint16_t
CxPlatKeyLength(
    CXPLAT_AEAD_TYPE Type
    )
{
    switch (Type) {
    case CXPLAT_AEAD_AES_128_GCM: return 16;
    case CXPLAT_AEAD_AES_256_GCM:
    case CXPLAT_AEAD_CHACHA20_POLY1305: return 32;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
        return 0;
    }
}

//
// Different hash algorithms supported for QUIC.
//
typedef enum CXPLAT_HASH_TYPE {

    CXPLAT_HASH_SHA256  = 0,    // 32 bytes
    CXPLAT_HASH_SHA384  = 1,    // 48 bytes
    CXPLAT_HASH_SHA512  = 2     // 64 bytes

} CXPLAT_HASH_TYPE;

typedef enum CXPLAT_HASH_TYPE_SIZE {

    CXPLAT_HASH_SHA256_SIZE = 32,
    CXPLAT_HASH_SHA384_SIZE = 48,
    CXPLAT_HASH_SHA512_SIZE = 64,

    CXPLAT_HASH_MAX_SIZE = 64

} CXPLAT_HASH_TYPE_SIZE;

QUIC_INLINE
uint16_t
CxPlatHashLength(
    CXPLAT_HASH_TYPE Type
    )
{
    switch (Type) {
    case CXPLAT_HASH_SHA256: return 32;
    case CXPLAT_HASH_SHA384: return 48;
    case CXPLAT_HASH_SHA512: return 64;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
        return 0;
    }
}

typedef struct CXPLAT_SECRET {
    CXPLAT_HASH_TYPE Hash;
    CXPLAT_AEAD_TYPE Aead;
    uint8_t Secret[CXPLAT_HASH_MAX_SIZE];
} CXPLAT_SECRET;

//
// Different possible packet key types.
//
typedef enum QUIC_PACKET_KEY_TYPE {

    QUIC_PACKET_KEY_INITIAL,
    QUIC_PACKET_KEY_0_RTT,
    QUIC_PACKET_KEY_HANDSHAKE,
    QUIC_PACKET_KEY_1_RTT,
    QUIC_PACKET_KEY_1_RTT_OLD,
    QUIC_PACKET_KEY_1_RTT_NEW,

    QUIC_PACKET_KEY_COUNT

} QUIC_PACKET_KEY_TYPE;

#pragma warning(disable:4200)  // nonstandard extension used: zero-length array in struct/union

typedef struct QUIC_PACKET_KEY {

    QUIC_PACKET_KEY_TYPE Type;
    CXPLAT_KEY* PacketKey;
    CXPLAT_HP_KEY* HeaderKey;
    uint8_t Iv[CXPLAT_IV_LENGTH];
    CXPLAT_SECRET TrafficSecret[0]; // Only preset for Type == QUIC_PACKET_KEY_1_RTT

} QUIC_PACKET_KEY;

typedef struct QUIC_HKDF_LABELS {

    _Field_z_ const char* KeyLabel;
    _Field_z_ const char* IvLabel;
    _Field_z_ const char* HpLabel;  // Header protection
    _Field_z_ const char* KuLabel;  // Key update

} QUIC_HKDF_LABELS;

//
// Creates a packet key from the static version specific salt.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(ReadKey != NULL, _At_(*ReadKey, __drv_allocatesMem(Mem)))
_When_(WriteKey != NULL, _At_(*WriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_ const QUIC_HKDF_LABELS* HkdfLabels,
    _In_reads_(CXPLAT_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** ReadKey,
    _Out_opt_ QUIC_PACKET_KEY** WriteKey
    );

//
// Frees the packet key.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketKeyFree(
    _In_opt_ __drv_freesMem(Mem) QUIC_PACKET_KEY* Key
    );

//
// Calculates the updated packet key from the current packet key.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_At_(*NewKey, __drv_allocatesMem(Mem))
QUIC_STATUS
QuicPacketKeyUpdate(
    _In_ const QUIC_HKDF_LABELS* HkdfLabels,
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_KEY** Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_HKDF_LABELS* HkdfLabels,
    _In_ const CXPLAT_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPacketKeyDeriveOffload(
    _In_ const QUIC_HKDF_LABELS* HkdfLabels,
    _In_ const QUIC_PACKET_KEY* const PacketKey,
    _In_z_ const char* const SecretName,
    _Inout_ CXPLAT_QEO_CONNECTION* Offload
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatKeyFree(
    _In_opt_ CXPLAT_KEY* Key
    );

CXPLAT_STATIC_ASSERT(
    sizeof(uint64_t) < CXPLAT_IV_LENGTH,
    "Packet Number Length is less than IV Length");

QUIC_INLINE
void
QuicCryptoCombineIvAndPacketNumber(
    _In_reads_bytes_(CXPLAT_IV_LENGTH)
        const uint8_t* const IvIn,
    _In_reads_bytes_(sizeof(uint64_t))
        const uint8_t* const PacketNumber,
    _Out_writes_bytes_(CXPLAT_IV_LENGTH)
        uint8_t* IvOut
    )
{
    //
    // XOR the packet number with the IV.
    // Because PacketNumber is in host-order (little-endian), and the protocol
    // expects it to be XORed in network-order, count down from the "end" of
    // PacketNumber while counting up to the end of IV when doing the XOR.
    //
    IvOut[0]  = IvIn[0];
    IvOut[1]  = IvIn[1];
    IvOut[2]  = IvIn[2];
    IvOut[3]  = IvIn[3];
    IvOut[4]  = IvIn[4]  ^ PacketNumber[7];
    IvOut[5]  = IvIn[5]  ^ PacketNumber[6];
    IvOut[6]  = IvIn[6]  ^ PacketNumber[5];
    IvOut[7]  = IvIn[7]  ^ PacketNumber[4];
    IvOut[8]  = IvIn[8]  ^ PacketNumber[3];
    IvOut[9]  = IvIn[9]  ^ PacketNumber[2];
    IvOut[10] = IvIn[10] ^ PacketNumber[1];
    IvOut[11] = IvIn[11] ^ PacketNumber[0];
}

//
// Encrypts buffer with the given key. 'BufferLength' includes the extra space
// that should be preallocated for the overhead, as indicated by
// CXPLAT_ENCRYPTION_OVERHEAD.
// i.e. BufferLength = PayloadLength + CXPLAT_ENCRYPTION_OVERHEAD
//
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
    );

//
// Decrypts buffer with the given key. 'BufferLength' is the full encrypted
// payload length on input. On output, the length shrinks by
// CXPLAT_ENCRYPTION_OVERHEAD.
//
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
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHpKeyCreate(
    _In_ CXPLAT_AEAD_TYPE AeadType,
    _When_(AeadType == CXPLAT_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == CXPLAT_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == CXPLAT_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ CXPLAT_HP_KEY** Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHpKeyFree(
    _In_opt_ CXPLAT_HP_KEY* Key
    );

//
// Calculates the header protection mask, to be XOR'ed with the QUIC packet
// header.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHpComputeMask(
    _In_ CXPLAT_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const Cipher,
    _Out_writes_bytes_(CXPLAT_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatHashCreate(
    _In_ CXPLAT_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ CXPLAT_HASH** Hash
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatHashFree(
    _In_opt_ CXPLAT_HASH* Hash
    );

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
    );

BOOLEAN
CxPlatCryptSupports(
    CXPLAT_AEAD_TYPE AeadType
    );

#if defined(__cplusplus)
}
#endif
