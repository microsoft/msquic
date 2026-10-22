/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "range_subrange.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_RANGE_TIERED QUIC_RANGE_TIERED;

// log2(256) = 8, used to divide a logical index by the block capacity.
#define QUIC_RANGE_TIERED_BLOCK_SHIFT 8
// Each fixed-size block stores 256 subranges.
#define QUIC_RANGE_TIERED_BLOCK_CAPACITY \
    (1u << QUIC_RANGE_TIERED_BLOCK_SHIFT)
// Mask 255 extracts or wraps a block-local slot without modulo.
#define QUIC_RANGE_TIERED_BLOCK_MASK \
    (QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1)
// One complete 256-subrange block occupies 4,096 bytes.
#define QUIC_RANGE_TIERED_BLOCK_BYTES \
    (QUIC_RANGE_TIERED_BLOCK_CAPACITY * sizeof(QUIC_SUBRANGE))
// The 256 directory slots address at most 65,536 logical subranges.
#define QUIC_RANGE_TIERED_DIRECTORY_CAPACITY \
    (1u << (16 - QUIC_RANGE_TIERED_BLOCK_SHIFT))
// Promote when the array contains one full block of 256 subranges.
#define QUIC_RANGE_TIERED_PROMOTE_LENGTH \
    QUIC_RANGE_TIERED_BLOCK_CAPACITY

//
// Returns TRUE when the byte budget can hold the tiered directory and the
// first two data blocks required for promotion.
//
BOOLEAN
QuicRangeTieredCanPromote(
    _In_ uint32_t MaxAllocSize
    );

//
// Converts a full heap-backed array by adopting InitialBlock as tiered block
// zero and inserting one new subrange. Failure leaves InitialBlock unchanged
// and caller-owned. Success transfers ownership to NewTiered.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredConvertAndInsert(
    _Inout_updates_(InitialLength) QUIC_SUBRANGE* InitialBlock,
    _In_ uint32_t InitialLength,
    _In_ uint32_t MaxAllocSize,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count,
    _Out_ QUIC_RANGE_TIERED** NewTiered
    );

//
// Inserts one subrange into tiered storage. Required block allocation completes
// before records move. At capacity, a range whose budget differs from
// QUIC_MAX_RANGE_ALLOC_SIZE may age out its lowest record. Returns NULL on
// allocation or capacity failure.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredInsert(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t MaxAllocSize,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    );

//
// Removes Count consecutive tiered records. Removal may move records and
// reclaim blocks, so previously returned record pointers are invalidated.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredRemove(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    );

//
// Returns the number of subranges stored by a tiered range.
//
uint32_t
QuicRangeTieredSize(
    _In_ const QUIC_RANGE_TIERED* Tiered
    );

//
// Frees the directory and every allocated tiered block.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredUninitialize(
    _In_ QUIC_RANGE_TIERED* Tiered
    );

//
// Returns the subrange at logical Index in tiered storage.
//
QUIC_SUBRANGE*
QuicRangeTieredGet(
    _In_ const QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t Index
    );

//
// Returns current directory and data-block bytes.
//
uint32_t
QuicRangeTieredGetAllocatedBytes(
    _In_ const QUIC_RANGE_TIERED* Tiered
    );

//
// Returns the maximum logical subrange capacity.
//
uint32_t
QuicRangeTieredGetCapacity(
    _In_ const QUIC_RANGE_TIERED* Tiered
    );

#if defined(__cplusplus)
}
#endif
