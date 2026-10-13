/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#if QUIC_RANGE_USE_TIERED

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
// Promotes a full array by transferring its allocation into tiered block zero.
// Range must contain exactly 256 sorted subranges in a heap-backed array.
// Index is in [0, UsedLength]; Low and Count define the new subrange.
// The directory and second block are allocated before source records move.
// Failure returns NULL and leaves Range array-backed and unchanged. Success
// returns the inserted subrange and invalidates previously returned pointers.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredConvertAndInsert(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    );

//
// Inserts one subrange into an existing tiered range at logical Index.
// Index is in [0, UsedLength]; Low and Count define the new subrange.
// Required block allocation completes before records move. Returns NULL on
// allocation or capacity failure. Success may invalidate all record pointers.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredInsert(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    );

//
// Removes Count consecutive subranges starting at logical Index.
// The span must be nonempty and fully contained in Range. Removal may move
// records, reclaim blocks, or demote to inline array storage, so it always
// returns TRUE to report that previously returned pointers may be invalid.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeTieredRemove(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    );

//
// Clears a tiered range, frees its directory and every allocated block, and
// restores empty inline array storage. MaxAllocSize is preserved.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredReset(
    _Inout_ QUIC_RANGE* Range
    );

//
// Frees the directory and every block during final destruction.
// Unlike Reset, this does not restore array mode; it clears Range->Tiered.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredUninitialize(
    _Inout_ QUIC_RANGE* Range
    );

//
// Returns the subrange at logical Index in a tiered range.
// Index must be less than UsedLength. The pointer remains valid only until a
// later range mutation, reset, or uninitialization.
//
QUIC_SUBRANGE*
QuicRangeTieredGet(
    _In_ const QUIC_RANGE* Range,
    _In_ uint32_t Index
    );

//
// Returns current directory and data-block bytes for a tiered range.
// The value includes active blocks and retained spare blocks.
//
uint32_t
QuicRangeTieredGetAllocatedBytes(
    _In_ const QUIC_RANGE* Range
    );

//
// Returns the maximum logical subrange capacity allowed by the directory and
// the range's configured allocation budget.
//
uint32_t
QuicRangeTieredGetCapacity(
    _In_ const QUIC_RANGE* Range
    );

#endif

#if defined(__cplusplus)
}
#endif
