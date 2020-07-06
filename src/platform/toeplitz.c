/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    An implementation of the Toeplitz Hash Algorithm (adapted from Windows
    RTL toeplitz hash implementation).

Notes:

    The hash requires a key K that has (i + o - 1) bits, where i is the number
    of bits in the input and o is the number of bits in the output. In case,
    the input length is variable, i represents the number of bits in the
    longest possible hash input. We simplify the algorithm by stipulating that
    K must be (i + o) bits long. Since we also mandate that output length is
    always 32 bits, the length of the key K is (i + 32) bits.

    The hash input is processed from left to right -- where left represents the
    first bit, or if the input is a array of bytes, then the MSB of the 0th
    element is the leftmost bit. Same nomenclature goes for the Key, K.

    The hash computation starts off with a 32-bit result R, initialized to 0.
    Each bit of the input is scanned, and if bit number x in the hash input is
    set to 1, the the key K is shifted LEFT x bits, and the leftmost 32 bits of
    the shifted key are XORed into the result.

    The hash has the nice property that the hash input bit stream can be cut up
    into parts, and the hash output of each part can be computed separately.
    The XOR of these hash outputs will yield the hash output of the complete
    hash input bit-stream.

    The typical implementation requires the hash input to be processed one bit
    at a time, which is too slow for a software implementation.

    We have speeded the implementation by processing the hash input four bits
    at a time. This requires us to maintain a lookup table of 16 32-bit entries
    for each nibble of the hash input.

    This implementation assumes that the output of the hash is always 32-bit.
    It also assumes that the caller will pass in a array of bytes to hash, and
    the number of bits in the hash input will always be a multiple of 8 -- that
    is, no byte need be processed partially in the array passed in by the
    caller.

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "toeplitz.c.clog.h"
#endif

//
// Initializes the state required for a Toeplitz hash computation. We
// maintain per-nibble lookup tables, and we initialize them here.
//
void
QuicToeplitzHashInitialize(
    _Inout_ QUIC_TOEPLITZ_HASH* Toeplitz
    )
{
    uint32_t BaseShift, StartByteOfKey;
    uint32_t Word1, Word2;
    uint32_t Signature1, Signature2, Signature3, Signature4;

    //
    // Our table based strategy works as follows. For each nibble of the
    // hash input, there is a table of 16 32-bit values. This table can
    // directly be looked up to find out what value needs to be XORed
    // into the result based on the value of the nibble. Therefore, a
    // 4 byte hash input will have 8 nibbles, and each of the nibbles
    // has a separate lookup table. This lookup table is looked up
    // based on the nibble value, the contents are XORed into the result
    // and we then move to the next nibble of the input, and the next
    // table.
    //

    //
    // Initialize the Toeplitz->LookupTables.
    //
    for (uint32_t i = 0; i < QUIC_TOEPLITZ_LOOKUP_TABLE_COUNT; i++) {
        //
        // First construct the 32-bit word that is obtained after
        // shifting the key left by i*4 bits. That goes into Word1
        //
        StartByteOfKey = i / NIBBLES_PER_BYTE;

        Word1 = (Toeplitz->HashKey[StartByteOfKey] << 24) +
                (Toeplitz->HashKey[StartByteOfKey + 1] << 16) +
                (Toeplitz->HashKey[StartByteOfKey + 2] << 8) +
                 Toeplitz->HashKey[StartByteOfKey + 3];

        //
        // However, we'll need the byte that succeeds Word1, because as we
        // shift Word1 left, we need to bring in bits from the successor byte.
        // The successor byte goes in Word2.
        //
        Word2 = Toeplitz->HashKey[StartByteOfKey + 4];

        BaseShift = (i % NIBBLES_PER_BYTE) * BITS_PER_NIBBLE;

        //
        // Signature1 represents the value that needs to be XORed into
        // the result if the LSB of the nibble is 1. Similarly, for
        // the other Signature values.
        //
        Signature1 = (Word1 << BaseShift) | (Word2 >> (8 * sizeof(uint8_t) - BaseShift));
        BaseShift ++;
        Signature2 = (Word1 << BaseShift) | (Word2 >> (8 * sizeof(uint8_t) - BaseShift));
        BaseShift ++;
        Signature3 = (Word1 << BaseShift) | (Word2 >> (8 * sizeof(uint8_t) - BaseShift));
        BaseShift ++;
        Signature4 = (Word1 << BaseShift) | (Word2 >> (8 * sizeof(uint8_t) - BaseShift));

        for (uint32_t j = 0; j < QUIC_TOEPLITZ_LOOKUP_TABLE_SIZE; j++) {

            Toeplitz->LookupTableArray[i].Table[j] = 0;
            if (j & 0x1) {
                Toeplitz->LookupTableArray[i].Table[j] ^= Signature4;
            }

            if (j & 0x2) {
                Toeplitz->LookupTableArray[i].Table[j] ^= Signature3;
            }

            if (j & 0x4) {
                Toeplitz->LookupTableArray[i].Table[j] ^= Signature2;
            }

            if (j & 0x8) {
                Toeplitz->LookupTableArray[i].Table[j] ^= Signature1;
            }
        }
    }
}

//
// Computes the hash by processing the input four-bits at a time. It is assumed
// that the hash input is a whole number of bytes (no partial byte-processing
// needs to be done at the end).
//
uint32_t
QuicToeplitzHashCompute(
    _In_ const QUIC_TOEPLITZ_HASH* Toeplitz,
    _In_reads_(HashInputLength)
        const uint8_t* HashInput,
    _In_ uint32_t HashInputLength,
    _In_ uint32_t HashInputOffset
    )
{
    //
    // BaseOffset is the first lookup table to be accessed.
    //
    uint32_t BaseOffset = HashInputOffset * NIBBLES_PER_BYTE;
    uint32_t Result = 0;

    QUIC_DBG_ASSERT(
        (BaseOffset + HashInputLength * NIBBLES_PER_BYTE) <= QUIC_TOEPLITZ_LOOKUP_TABLE_COUNT);

    for (uint32_t i = 0; i < HashInputLength; i++) {
        Result ^= Toeplitz->LookupTableArray[BaseOffset].Table[(HashInput[i] >> 4) & 0xf];
        BaseOffset++;
        Result ^= Toeplitz->LookupTableArray[BaseOffset].Table[HashInput[i] & 0xf];
        BaseOffset++;
    }

    return Result;
}
