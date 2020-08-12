/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for QUIC variable length encoding.

--*/

#pragma once

//
// Variable Length Integer Encoding
//
// The QUIC RFC defines a custom variable length integer encoding with the
// following format. The high bits of the first byte indicate the length of the
// encoded value:
//
//      00      1 byte
//      01      2 bytes
//      10      4 bytes
//      11      8 bytes
//

//
// The maximum value that can be encoded in a QUIC variable-length integer.
//
#define QUIC_VAR_INT_MAX ((1ULL << 62) - 1)

//
// Represents a variable-length integer.
//
typedef _In_range_(0, QUIC_VAR_INT_MAX) uint64_t QUIC_VAR_INT;

//
// Helper to determine the number of bytes required to encode the value
// in a variable-length encoding.
//
#define QuicVarIntSize(Value) \
    ((QUIC_VAR_INT)Value < 0x40 ? sizeof(uint8_t) : ((QUIC_VAR_INT)Value < 0x4000 ? sizeof(uint16_t) : ((QUIC_VAR_INT)Value < 0x40000000 ? sizeof(uint32_t) : sizeof(uint64_t))))

//
// Helper to encode a variable-length integer.
//
inline
_When_(Value < 0x40, _Post_equal_to_(Buffer + sizeof(uint8_t)))
_When_(Value >= 0x40 && Value < 0x4000, _Post_equal_to_(Buffer + sizeof(uint16_t)))
_When_(Value >= 0x4000 && Value < 0x40000000, _Post_equal_to_(Buffer + sizeof(uint32_t)))
_When_(Value >= 0x40000000, _Post_equal_to_(Buffer + sizeof(uint64_t)))
uint8_t*
QuicVarIntEncode(
    _In_ QUIC_VAR_INT Value,
    _When_(Value < 0x40, _Out_writes_bytes_(sizeof(uint8_t)))
    _When_(Value >= 0x40 && Value < 0x4000, _Out_writes_bytes_(sizeof(uint16_t)))
    _When_(Value >= 0x4000 && Value < 0x40000000, _Out_writes_bytes_(sizeof(uint32_t)))
    _When_(Value >= 0x40000000, _Out_writes_bytes_(sizeof(uint64_t)))
        uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(Value <= QUIC_VAR_INT_MAX);

    if (Value < 0x40) {
        Buffer[0] = (uint8_t)Value;
        return Buffer + sizeof(uint8_t);
    } else if (Value < 0x4000) {
        const uint16_t tmp = QuicByteSwapUint16((0x40 << 8) | (uint16_t)Value);
        memcpy(Buffer, &tmp, sizeof(tmp));
        return Buffer + sizeof(uint16_t);
    } else if (Value < 0x40000000) {
        const uint32_t tmp = QuicByteSwapUint32((0x80UL << 24) | (uint32_t)Value);
        memcpy(Buffer, &tmp, sizeof(tmp));
        return Buffer + sizeof(uint32_t);
    } else {
        const uint64_t tmp = QuicByteSwapUint64((0xc0ULL << 56) | Value);
        memcpy(Buffer, &tmp, sizeof(tmp));
        return Buffer + sizeof(uint64_t);
    }
}

//
// Writes a variable length integer into 2 bytes. Assumes the value will fit.
//
inline
_Post_equal_to_(Buffer + sizeof(uint16_t))
uint8_t*
QuicVarIntEncode2Bytes(
    _In_range_(0, 0x3FFF) QUIC_VAR_INT Value,
    _Out_writes_bytes_(sizeof(uint16_t))
        uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(Value < 0x4000);

    const uint16_t tmp = QuicByteSwapUint16((0x40 << 8) | (uint16_t)Value);
    memcpy(Buffer, &tmp, sizeof(tmp));
    return Buffer + sizeof(uint16_t);
}

//
// Helper to decode a variable-length integer.
//
inline
_Success_(return != FALSE)
BOOLEAN
QuicVarIntDecode(
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_
    _Deref_in_range_(0, BufferLength)
    _Deref_out_range_(0, BufferLength)
        uint16_t* Offset,
    _Out_ QUIC_VAR_INT* Value
    )
{
    if (BufferLength < sizeof(uint8_t) + *Offset) {
        return FALSE;
    }
    if (Buffer[*Offset] < 0x40) {
        *Value = Buffer[*Offset];
        QUIC_ANALYSIS_ASSERT(*Value < 0x100ULL);
        *Offset += sizeof(uint8_t);
    } else if (Buffer[*Offset] < 0x80) {
        if (BufferLength < sizeof(uint16_t) + *Offset) {
            return FALSE;
        }
        *Value = ((uint64_t)(Buffer[*Offset] & 0x3fUL)) << 8;
        *Value |= Buffer[*Offset + 1];
        QUIC_ANALYSIS_ASSERT(*Value < 0x10000ULL);
        *Offset += sizeof(uint16_t);
    } else if (Buffer[*Offset] < 0xc0) {
        if (BufferLength < sizeof(uint32_t) + *Offset) {
            return FALSE;
        }
        uint32_t v;
        memcpy(&v, Buffer + *Offset, sizeof(uint32_t));
        *Value = QuicByteSwapUint32(v) & 0x3fffffffUL;
        QUIC_ANALYSIS_ASSERT(*Value < 0x100000000ULL);
        *Offset += sizeof(uint32_t);
    } else {
        if (BufferLength < sizeof(uint64_t) + *Offset) {
            return FALSE;
        }
        uint64_t v;
        memcpy(&v, Buffer + *Offset, sizeof(uint64_t));
        *Value = QuicByteSwapUint64(v) & 0x3fffffffffffffffULL;
        *Offset += sizeof(uint64_t);
    }
    return TRUE;
}
