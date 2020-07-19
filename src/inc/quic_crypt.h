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

typedef struct QUIC_KEY QUIC_KEY;
typedef struct QUIC_HP_KEY QUIC_HP_KEY;
typedef struct QUIC_HASH QUIC_HASH;

#define QUIC_HKDF_PREFIX        "tls13 "
#define QUIC_HKDF_PREFIX_LEN    (sizeof(QUIC_HKDF_PREFIX) - 1)

//
// Length of the salt for version specific initial keys.
//
#define QUIC_VERSION_SALT_LENGTH 20

//
// The overhead in a packet from encryption.
//
#define QUIC_ENCRYPTION_OVERHEAD 16

//
// The length of the IV used in QUIC.
//
#define QUIC_IV_LENGTH 12

//
// The length of buffer used for header protection sampling.
//
#define QUIC_HP_SAMPLE_LENGTH 16

//
// Different AEAD algorithms supported for QUIC.
//
typedef enum QUIC_AEAD_TYPE {

    QUIC_AEAD_AES_128_GCM       = 0,    // 16 byte key
    QUIC_AEAD_AES_256_GCM       = 1,    // 32 byte key
    QUIC_AEAD_CHACHA20_POLY1305 = 2     // 32 byte key

} QUIC_AEAD_TYPE;

typedef enum QUIC_AEAD_TYPE_SIZE {

    QUIC_AEAD_AES_128_GCM_SIZE       = 16,
    QUIC_AEAD_AES_256_GCM_SIZE       = 32,
    QUIC_AEAD_CHACHA20_POLY1305_SIZE = 32

} QUIC_AEAD_TYPE_SIZE;

inline
uint16_t
QuicKeyLength(
    QUIC_AEAD_TYPE Type
    )
{
    switch (Type) {
    case QUIC_AEAD_AES_128_GCM: return 16;
    case QUIC_AEAD_AES_256_GCM:
    case QUIC_AEAD_CHACHA20_POLY1305: return 32;
    default:
        QUIC_FRE_ASSERT(FALSE);
        return 0;
    }
}

//
// Different hash algorithms supported for QUIC.
//
typedef enum QUIC_HASH_TYPE {

    QUIC_HASH_SHA256  = 0,    // 32 bytes
    QUIC_HASH_SHA384  = 1,    // 48 bytes
    QUIC_HASH_SHA512  = 2     // 64 bytes

} QUIC_HASH_TYPE;

typedef enum QUIC_HASH_TYPE_SIZE {

    QUIC_HASH_SHA256_SIZE = 32,
    QUIC_HASH_SHA384_SIZE = 48,
    QUIC_HASH_SHA512_SIZE = 64,

    QUIC_HASH_MAX_SIZE = 64

} QUIC_HASH_TYPE_SIZE;

inline
uint16_t
QuicHashLength(
    QUIC_HASH_TYPE Type
    )
{
    switch (Type) {
    case QUIC_HASH_SHA256: return 32;
    case QUIC_HASH_SHA384: return 48;
    case QUIC_HASH_SHA512: return 64;
    default:
        QUIC_FRE_ASSERT(FALSE);
        return 0;
    }
}

typedef struct QUIC_SECRET {
    QUIC_HASH_TYPE Hash;
    QUIC_AEAD_TYPE Aead;
    uint8_t Secret[QUIC_HASH_MAX_SIZE];
} QUIC_SECRET;

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
    QUIC_KEY* PacketKey;
    QUIC_HP_KEY* HeaderKey;
    uint8_t Iv[QUIC_IV_LENGTH];
    QUIC_SECRET TrafficSecret[0]; // Only preset for Type == QUIC_PACKET_KEY_1_RTT

} QUIC_PACKET_KEY;

//
// Creates a packet key from the static version specific salt.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_When_(ReadKey != NULL, _At_(*ReadKey, __drv_allocatesMem(Mem)))
_When_(WriteKey != NULL, _At_(*WriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
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
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_KEY** Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    );

static_assert(
    sizeof(uint64_t) < QUIC_IV_LENGTH,
    "Packet Number Length is less than IV Length");

inline
void
QuicCryptoCombineIvAndPacketNumber(
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const IvIn,
    _In_reads_bytes_(sizeof(uint64_t))
        const uint8_t* const PacketNumber,
    _Out_writes_bytes_(QUIC_IV_LENGTH)
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
// QUIC_ENCRYPTION_OVERHEAD.
// i.e. BufferLength = PayloadLength + QUIC_ENCRYPTION_OVERHEAD
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicEncrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > QUIC_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= QUIC_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    );

//
// Decrypts buffer with the given key. 'BufferLength' is the full encrypted
// payload length on input. On output, the length shrinks by
// QUIC_ENCRYPTION_OVERHEAD.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDecrypt(
    _In_ QUIC_KEY* Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
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
QuicHpKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_HP_KEY** Key
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHpKeyFree(
    _In_opt_ QUIC_HP_KEY* Key
    );

//
// Calculates the header protection mask, to be XOR'ed with the QUIC packet
// header.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHpComputeMask(
    _In_ QUIC_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const Cipher,
    _Out_writes_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHashCreate(
    _In_ QUIC_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ QUIC_HASH** Hash
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHashCompute(
    _In_ QUIC_HASH* Hash,
    _In_reads_(InputLength)
        const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength, // QuicHashLength(HashType)
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    );

#if defined(__cplusplus)
}
#endif
