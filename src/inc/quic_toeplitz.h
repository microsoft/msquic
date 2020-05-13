/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define NIBBLES_PER_BYTE    2
#define BITS_PER_NIBBLE     4

//
// The size (in bytes) of the input.

// This includes space for a 20 bytes for CID, 16 bytes for IPv6 address
// and 2 bytes for UDP port.
//
#define QUIC_TOEPLITZ_INPUT_SIZE            38

//
// The size (in bytes) of the output hash.

//
#define QUIC_TOEPLITZ_OUPUT_SIZE            sizeof(uint32_t)

//
// The size (in bytes) of the key is equal to the size of the input and output.
//
#define QUIC_TOEPLITZ_KEY_SIZE              (QUIC_TOEPLITZ_INPUT_SIZE + QUIC_TOEPLITZ_OUPUT_SIZE)

//
// Fixed lookup table size.
//
#define QUIC_TOEPLITZ_LOOKUP_TABLE_SIZE     16

//
// Fixed number of lookup tables.
//
#define QUIC_TOEPLITZ_LOOKUP_TABLE_COUNT    (QUIC_TOEPLITZ_INPUT_SIZE * NIBBLES_PER_BYTE)

typedef struct QUIC_TOEPLITZ_LOOKUP_TABLE {
    uint32_t Table[QUIC_TOEPLITZ_LOOKUP_TABLE_SIZE];
} QUIC_TOEPLITZ_LOOKUP_TABLE;

typedef struct QUIC_TOEPLITZ_HASH {
    QUIC_TOEPLITZ_LOOKUP_TABLE LookupTableArray[QUIC_TOEPLITZ_LOOKUP_TABLE_COUNT];
    uint8_t HashKey[QUIC_TOEPLITZ_KEY_SIZE];
} QUIC_TOEPLITZ_HASH;

//
// Initializes the Toeplitz hash structure. Toeplitz->HashKey must be set first.
//
void
QuicToeplitzHashInitialize(
    _Inout_ QUIC_TOEPLITZ_HASH* Toeplitz
    );

//
// Computes a Toeplitz hash.
//
uint32_t
QuicToeplitzHashCompute(
    _In_ const QUIC_TOEPLITZ_HASH* Toeplitz,
    _In_reads_(HashInputLength)
        const uint8_t* HashInput,
    _In_ uint32_t HashInputLength,
    _In_ uint32_t HashInputOffset
    );
