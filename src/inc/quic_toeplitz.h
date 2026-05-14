/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#define NIBBLES_PER_BYTE    2
#define BITS_PER_NIBBLE     4

//
// The size (in bytes) of the input.
//
typedef enum CXPLAT_TOEPLITZ_INPUT_SIZE {
    //
    // This includes space for 16 bytes for source IPv6 address, 16 bytes for
    // destination IPv6 address, 2 bytes for source port, and 2 bytes for
    // destination port.
    //
    CXPLAT_TOEPLITZ_INPUT_SIZE_IP =             36,

    //
    // This includes space for a 20 bytes for CID, 16 bytes for IPv6 address
    // and 2 bytes for UDP port.
    //
    CXPLAT_TOEPLITZ_INPUT_SIZE_QUIC =           38,

    CXPLAT_TOEPLITZ_INPUT_SIZE_MAX =            38,
} CXPLAT_TOEPLITZ_INPUT_SIZE;

//
// The size (in bytes) of the output hash.

//
#define CXPLAT_TOEPLITZ_OUPUT_SIZE            sizeof(uint32_t)

//
// The max size (in bytes) of the key is equal to the size of the input and output.
//
#define CXPLAT_TOEPLITZ_KEY_SIZE_MAX              (CXPLAT_TOEPLITZ_INPUT_SIZE_MAX + CXPLAT_TOEPLITZ_OUPUT_SIZE)

//
// The min size (in bytes) of the key is equal to the size of the input and output.
//
#define CXPLAT_TOEPLITZ_KEY_SIZE_MIN              (CXPLAT_TOEPLITZ_INPUT_SIZE_IP + CXPLAT_TOEPLITZ_OUPUT_SIZE)

//
// Fixed lookup table size.
//
#define CXPLAT_TOEPLITZ_LOOKUP_TABLE_SIZE     16

//
// Fixed number of lookup tables. Use the maximum of two possible values.
//
#define CXPLAT_TOEPLITZ_LOOKUP_TABLE_COUNT_MAX    (CXPLAT_TOEPLITZ_INPUT_SIZE_MAX * NIBBLES_PER_BYTE)

typedef struct CXPLAT_TOEPLITZ_LOOKUP_TABLE {
    uint32_t Table[CXPLAT_TOEPLITZ_LOOKUP_TABLE_SIZE];
} CXPLAT_TOEPLITZ_LOOKUP_TABLE;

typedef struct CXPLAT_TOEPLITZ_HASH {
    CXPLAT_TOEPLITZ_LOOKUP_TABLE LookupTableArray[CXPLAT_TOEPLITZ_LOOKUP_TABLE_COUNT_MAX];
    uint8_t HashKey[CXPLAT_TOEPLITZ_KEY_SIZE_MAX];
    CXPLAT_TOEPLITZ_INPUT_SIZE InputSize;
} CXPLAT_TOEPLITZ_HASH;

//
// Initializes the Toeplitz hash structure. Toeplitz->HashKey must be set first.
//
void
CxPlatToeplitzHashInitialize(
    _Inout_ CXPLAT_TOEPLITZ_HASH* Toeplitz
    );

//
// Computes a Toeplitz hash.
// TODO - Update SAL to ensure:
//   HashInputLength + HashInputOffset <= CXPLAT_TOEPLITZ_INPUT_SIZE
//
uint32_t
CxPlatToeplitzHashCompute(
    _In_ const CXPLAT_TOEPLITZ_HASH* Toeplitz,
    _In_reads_(HashInputLength)
        const uint8_t* HashInput,
    _In_ uint32_t HashInputLength,
    _In_ uint32_t HashInputOffset
    );

//
// Computes the Toeplitz hash of a QUIC address.
//
QUIC_INLINE
void
CxPlatToeplitzHashComputeAddr(
    _In_ const CXPLAT_TOEPLITZ_HASH* Toeplitz,
    _In_ const QUIC_ADDR* Addr,
    _Inout_ uint32_t* Key,
    _Out_ uint32_t* Offset
    )
{
    if (QuicAddrGetFamily(Addr) == QUIC_ADDRESS_FAMILY_INET) {
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)Addr) + QUIC_ADDR_V4_PORT_OFFSET,
                2, 0);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)Addr) + QUIC_ADDR_V4_IP_OFFSET,
                4, 2);
        *Offset = 2 + 4;
    } else {
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)Addr) + QUIC_ADDR_V6_PORT_OFFSET,
                2, 0);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)Addr) + QUIC_ADDR_V6_IP_OFFSET,
                16, 2);
        *Offset = 2 + 16;
    }
}

//
// Computes the Toeplitz hash of two QUIC addresses as RSS would.
//
QUIC_INLINE
void
CxPlatToeplitzHashComputeRss(
    _In_ const CXPLAT_TOEPLITZ_HASH* Toeplitz,
    _In_ const QUIC_ADDR* SrcAddr,
    _In_ const QUIC_ADDR* DestAddr,
    _Inout_ uint32_t* Key,
    _Out_ uint32_t* Offset
    )
{
    CXPLAT_FRE_ASSERT(QuicAddrGetFamily(SrcAddr) == QuicAddrGetFamily(DestAddr));

    if (QuicAddrGetFamily(SrcAddr) == QUIC_ADDRESS_FAMILY_INET) {
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)SrcAddr) + QUIC_ADDR_V4_IP_OFFSET,
                4, 0);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)DestAddr) + QUIC_ADDR_V4_IP_OFFSET,
                4, 4);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)SrcAddr) + QUIC_ADDR_V4_PORT_OFFSET,
                2, 8);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)DestAddr) + QUIC_ADDR_V4_PORT_OFFSET,
                2, 10);
        *Offset = 4 + 4 + 2 + 2;
    } else {
        CXPLAT_DBG_ASSERT(QuicAddrGetFamily(SrcAddr) == QUIC_ADDRESS_FAMILY_INET6);

        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)SrcAddr) + QUIC_ADDR_V6_IP_OFFSET,
                16, 0);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)DestAddr) + QUIC_ADDR_V6_IP_OFFSET,
                16, 16);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)SrcAddr) + QUIC_ADDR_V6_PORT_OFFSET,
                2, 32);
        *Key ^=
            CxPlatToeplitzHashCompute(
                Toeplitz,
                ((uint8_t*)DestAddr) + QUIC_ADDR_V6_PORT_OFFSET,
                2, 34);
        *Offset = 16 + 16 + 2 + 2;
    }
}

#if defined(__cplusplus)
}
#endif
