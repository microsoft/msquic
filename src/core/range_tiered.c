/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tiered vector storage for large QUIC_RANGE instances.

--*/

#include "precomp.h"
#include "range_tiered.h"

struct QUIC_RANGE_TIERED {

    // Each non-NULL entry owns one fixed-capacity subrange block.
    QUIC_SUBRANGE* Blocks[QUIC_RANGE_TIERED_DIRECTORY_CAPACITY];
    // Each entry maps logical slot zero to a physical circular slot.
    uint16_t Starts[QUIC_RANGE_TIERED_DIRECTORY_CAPACITY];
    // Active blocks contain live records; allocated blocks may include a spare.
    uint16_t ActiveBlockCount;
    uint16_t AllocatedBlockCount;
    // Maximum blocks allowed by both the byte budget and directory capacity.
    uint16_t MaxBlockCount;

};

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_RANGE_TIERED) < QUIC_RANGE_TIERED_BLOCK_BYTES,
    "Tiered range directory must fit in less than one range block");

//
// Returns the number of blocks required for the given subrange count.
// SubRangeCount is the total logical subrange count to represent.
//
static uint16_t
QuicRangeTieredGetRequiredBlockCount(
    _In_ uint32_t SubRangeCount
    )
{
    // An empty range requires no active blocks.
    if (SubRangeCount == 0) {
        return 0;
    }

    // ceil(SubRangeCount/QUIC_RANGE_TIERED_BLOCK_CAPACITY)
    return
        (uint16_t)(
            (SubRangeCount + QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1) >>
                QUIC_RANGE_TIERED_BLOCK_SHIFT);
}

//
// Returns the current live record count for an active block.
// BlockIndex identifies a block in Range's current active layout.
// The final active block may be empty while insertion is reserving capacity.
//
static uint16_t
QuicRangeTieredGetBlockSubRangeCount(
    _In_ const QUIC_RANGE* Range,
    _In_ uint16_t BlockIndex
    )
{
    const QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    CXPLAT_DBG_ASSERT(BlockIndex < Tiered->ActiveBlockCount);
    // Invariant: Every current non-final active block is full.
    if (BlockIndex + 1 < Tiered->ActiveBlockCount) {
        return QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    }
    // The current final active block contains the remaining subranges.
    const uint32_t BlockStart =
        (uint32_t)BlockIndex << QUIC_RANGE_TIERED_BLOCK_SHIFT;
    CXPLAT_DBG_ASSERT(Range->UsedLength >= BlockStart);
    const uint32_t BlockSubRangeCount =
        Range->UsedLength - BlockStart;
    CXPLAT_DBG_ASSERT(
        BlockSubRangeCount <= QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    return (uint16_t)BlockSubRangeCount;
}

//
// Maps a logical slot in a circular block to its physical record.
// Slot is relative to the block's logical start, not physical array slot zero.
//
static QUIC_SUBRANGE*
QuicRangeTieredGetBlockSlot(
    _In_ const QUIC_RANGE_TIERED* Tiered,
    _In_ uint16_t BlockIndex,
    _In_ uint16_t Slot
    )
{
    // Block capacity is a power of two, so masking wraps without division.
    const uint16_t PhysicalSlot =
        (uint16_t)(
            (Tiered->Starts[BlockIndex] + Slot) &
                QUIC_RANGE_TIERED_BLOCK_MASK);
    return &Tiered->Blocks[BlockIndex][PhysicalSlot];
}

//
// Frees the final allocated block and updates allocation accounting.
// The caller must ensure this trailing block is no longer active.
//
static void
QuicRangeTieredFreeLastBlock(
    _Inout_ QUIC_RANGE_TIERED* Tiered
    )
{
    CXPLAT_DBG_ASSERT(Tiered->AllocatedBlockCount != 0);
    // Invariant: Allocated blocks occupy a contiguous directory prefix.
    const uint16_t BlockIndex =
        --Tiered->AllocatedBlockCount;
    QUIC_SUBRANGE* Block = Tiered->Blocks[BlockIndex];
    Tiered->Blocks[BlockIndex] = NULL;
    Tiered->Starts[BlockIndex] = 0;
    CXPLAT_FREE(Block, QUIC_POOL_RANGE);
}

//
// Releases trailing spare blocks after utilization falls below one quarter.
// The active prefix is preserved and at most one spare block is retained.
//
static void
QuicRangeTieredReleaseExcessBlocks(
    _Inout_ QUIC_RANGE* Range
    )
{
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    // Retain the current allocation until active use falls below one quarter.
    if (Tiered->AllocatedBlockCount <= 1 ||
        (uint32_t)Tiered->ActiveBlockCount * 4 >=
            Tiered->AllocatedBlockCount) {
        return;
    }

    // Keep one spare block so limited regrowth does not immediately allocate.
    const uint16_t RetainedBlockCount =
        (uint16_t)CXPLAT_MAX(
            1,
            (uint32_t)Tiered->ActiveBlockCount + 1);
    while (Tiered->AllocatedBlockCount >
           RetainedBlockCount) {
        QuicRangeTieredFreeLastBlock(Tiered);
    }
}

//
// Frees every data block and the tiered directory.
// Tiered is invalid after this function returns.
//
static void
QuicRangeTieredFreeStorage(
    QUIC_RANGE_TIERED* Tiered
    )
{
    while (Tiered->AllocatedBlockCount != 0) {
        QuicRangeTieredFreeLastBlock(Tiered);
    }
    CXPLAT_FREE(Tiered, QUIC_POOL_RANGE);
}

//
// Moves a small tiered range back into the inline array.
// Range->UsedLength must fit within QUIC_RANGE_INITIAL_SUB_COUNT.
//
static void
QuicRangeTieredDemote(
    _Inout_ QUIC_RANGE* Range
    )
{
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_TIERED);
    CXPLAT_DBG_ASSERT(
        Range->UsedLength <=
            QUIC_RANGE_INITIAL_SUB_COUNT);

    // Save the directory before changing the backing-storage union member.
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    // Copy in logical order because each physical block may be circularly wrapped.
    for (uint32_t i = 0; i < Range->UsedLength; ++i) {
        Range->PreAllocSubRanges[i] =
            *QuicRangeTieredGet(Range, i);
    }

    // Inline storage is embedded in QUIC_RANGE, so demotion cannot fail.
    QuicRangeTieredFreeStorage(Tiered);
    Range->SubRanges = Range->PreAllocSubRanges;
    Range->AllocLength = QUIC_RANGE_INITIAL_SUB_COUNT;
    Range->Mode = QUIC_RANGE_MODE_ARRAY;
}

//
// Reduces storage after removal by demoting or releasing excess blocks.
//
static void
QuicRangeTieredCompact(
    _Inout_ QUIC_RANGE* Range
    )
{
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_TIERED);
    if (Range->UsedLength <=
        QUIC_RANGE_INITIAL_SUB_COUNT) {
        QuicRangeTieredDemote(Range);
    } else {
        QuicRangeTieredReleaseExcessBlocks(Range);
    }
}

QUIC_SUBRANGE*
QuicRangeTieredGet(
    _In_ const QUIC_RANGE* Range,
    _In_ uint32_t Index
    )
{
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_TIERED);
    CXPLAT_DBG_ASSERT(Index < Range->UsedLength);
    return
        QuicRangeTieredGetBlockSlot(
            Range->Tiered,
            (uint16_t)(Index >> QUIC_RANGE_TIERED_BLOCK_SHIFT),
            (uint16_t)(Index & QUIC_RANGE_TIERED_BLOCK_MASK));
}

//
// Allocates and activates all blocks required before a mutation begins.
// RequiredBlockCount is the desired post-mutation active block count.
// Failure rolls back only allocations made by this call.
//
static BOOLEAN
QuicRangeTieredEnsureActiveBlocks(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint16_t RequiredBlockCount
    )
{
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    // MaxBlockCount already charges the directory and every permitted block.
    if (RequiredBlockCount > Tiered->MaxBlockCount) {
        return FALSE;
    }

    // This count is the rollback boundary for allocations made by this call.
    const uint16_t OriginalAllocated = Tiered->AllocatedBlockCount;
    while (Tiered->AllocatedBlockCount < RequiredBlockCount) {
        // Blocks are independent allocations so growth never relocates old blocks.
        QUIC_SUBRANGE* Block =
            CXPLAT_ALLOC_NONPAGED(
                QUIC_RANGE_TIERED_BLOCK_BYTES,
                QUIC_POOL_RANGE);
        if (Block == NULL) {
            goto Error;
        }

        const uint16_t BlockIndex = Tiered->AllocatedBlockCount++;
        Tiered->Blocks[BlockIndex] = Block;
        Tiered->Starts[BlockIndex] = 0;
    }

    // Publish active blocks only after every required allocation succeeds.
    while (Tiered->ActiveBlockCount < RequiredBlockCount) {
        Tiered->Starts[Tiered->ActiveBlockCount] = 0;
        Tiered->ActiveBlockCount++;
    }
    return TRUE;

Error:

    // Roll back only blocks allocated by this call; live records were not moved.
    while (Tiered->AllocatedBlockCount > OriginalAllocated) {
        QuicRangeTieredFreeLastBlock(Tiered);
    }
    return FALSE;
}

//
// Inserts Value into a circular block with one available logical slot.
// For a full block, the caller first saves the final record and passes Count
// as QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1.
// Tiered owns the block directory, and BlockIndex selects the target block.
// Count is the target block's live subrange count.
// Index is the logical insertion slot in the range [0, Count].
// Value points to the subrange copied into the opened slot.
//
static void
QuicRangeTieredInsertLocal(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint16_t BlockIndex,
    _In_ uint16_t Count,
    _In_ uint16_t Index,
    _In_ const QUIC_SUBRANGE* Value
    )
{
    CXPLAT_DBG_ASSERT(Count < QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    CXPLAT_DBG_ASSERT(Index <= Count);

    const uint16_t SuffixCount = (uint16_t)(Count - Index);
    // Move the shorter side; ties move the suffix and preserve the start slot.
    if (Index < SuffixCount) {
        const uint16_t OriginalStart = Tiered->Starts[BlockIndex];
        // Move the circular start back one slot and wrap at zero.
        const uint16_t NewStart =
            (uint16_t)(
                (OriginalStart - 1) &
                    QUIC_RANGE_TIERED_BLOCK_MASK);
        for (uint16_t i = 0; i < Index; ++i) {
            const uint16_t Destination =
                (uint16_t)(
                    (NewStart + i) &
                        QUIC_RANGE_TIERED_BLOCK_MASK);
            Tiered->Blocks[BlockIndex][Destination] =
                *QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    i);
        }
        Tiered->Starts[BlockIndex] = NewStart;
    } else {
        // Copy backward because the source and destination ranges overlap.
        for (uint16_t i = Count; i > Index; --i) {
            QUIC_SUBRANGE* Destination =
                QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    i);
            *Destination =
                *QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    (uint16_t)(i - 1));
        }
    }

    // Store the new value in the logical insertion slot.
    *QuicRangeTieredGetBlockSlot(Tiered, BlockIndex, Index) = *Value;
}

//
// Removes one record from a circular block.
// Count is the block's live subrange count and Index is a logical block slot.
//
static void
QuicRangeTieredRemoveLocal(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint16_t BlockIndex,
    _In_ uint16_t Count,
    _In_ uint16_t Index
    )
{
    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(Index < Count);

    const uint16_t PrefixCount = Index;
    const uint16_t SuffixCount = (uint16_t)(Count - Index - 1);
    // Move the shorter side; ties move the suffix and preserve the start slot.
    if (PrefixCount < SuffixCount) {
        for (uint16_t i = Index; i > 0; --i) {
            QUIC_SUBRANGE* Destination =
                QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    i);
            *Destination =
                *QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    (uint16_t)(i - 1));
        }
        Tiered->Starts[BlockIndex] =
            (uint16_t)(
                (Tiered->Starts[BlockIndex] + 1) &
                    QUIC_RANGE_TIERED_BLOCK_MASK);
    } else {
        // Copy forward because every source is above its destination.
        for (uint16_t i = Index; i + 1 < Count; ++i) {
            QUIC_SUBRANGE* Destination =
                QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    i);
            *Destination =
                *QuicRangeTieredGetBlockSlot(
                    Tiered,
                    BlockIndex,
                    (uint16_t)(i + 1));
        }
    }
}

//
// Removes one logical record and carries later records backward by block.
// Index is a logical index across the complete range.
//
static void
QuicRangeTieredRemoveOne(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index
    )
{
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    CXPLAT_DBG_ASSERT(Index < Range->UsedLength);

    // Preserve the pre-remove block count because the old final block may empty.
    const uint16_t OldBlockCount = Tiered->ActiveBlockCount;
    const uint16_t BlockIndex =
        (uint16_t)(Index >> QUIC_RANGE_TIERED_BLOCK_SHIFT);
    const uint16_t LocalIndex =
        (uint16_t)(Index & QUIC_RANGE_TIERED_BLOCK_MASK);
    QuicRangeTieredRemoveLocal(
        Tiered,
        BlockIndex,
        QuicRangeTieredGetBlockSubRangeCount(Range, BlockIndex),
        LocalIndex);

    // Carry each later block's first record backward to keep prior blocks full.
    for (uint16_t i = (uint16_t)(BlockIndex + 1);
         i < OldBlockCount;
         ++i) {
        const QUIC_SUBRANGE Carry =
            *QuicRangeTieredGetBlockSlot(Tiered, i, 0);
        Tiered->Starts[i] =
            (uint16_t)(
                (Tiered->Starts[i] + 1) &
                    QUIC_RANGE_TIERED_BLOCK_MASK);
        *QuicRangeTieredGetBlockSlot(
            Tiered,
            (uint16_t)(i - 1),
            QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1) = Carry;
    }

    // Publish the new logical size after every backward carry completes.
    Range->UsedLength--;
    Tiered->ActiveBlockCount =
        QuicRangeTieredGetRequiredBlockCount(Range->UsedLength);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredInsert(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    )
{
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_TIERED);
    CXPLAT_DBG_ASSERT(Index <= Range->UsedLength);

    if (Range->UsedLength == QuicRangeTieredGetCapacity(Range)) {
        // Maximum-budget ranges never discard data, and index zero cannot age out.
        if (Range->MaxAllocSize == QUIC_MAX_RANGE_ALLOC_SIZE ||
            Index == 0) {
            return NULL;
        }
        // Age out the first subrange and adjust for the resulting index shift.
        QuicRangeTieredRemoveOne(Range, 0);
        Index--;
    }

    const uint16_t RequiredBlockCount =
        QuicRangeTieredGetRequiredBlockCount(
            Range->UsedLength + 1);
    // Invariant: All required allocation succeeds before any record moves.
    if (!QuicRangeTieredEnsureActiveBlocks(
            Range,
            RequiredBlockCount)) {
        return NULL;
    }

    uint16_t BlockIndex =
        (uint16_t)(Index >> QUIC_RANGE_TIERED_BLOCK_SHIFT);
    uint16_t LocalIndex =
        (uint16_t)(Index & QUIC_RANGE_TIERED_BLOCK_MASK);
    QUIC_SUBRANGE Carry = {Low, Count};

    // Carry displaced records forward until a block has an available slot.
    for (;;) {
        const uint16_t BlockSubRangeCount =
            QuicRangeTieredGetBlockSubRangeCount(
                Range,
                BlockIndex);
        // The first block with spare capacity terminates the carry chain.
        if (BlockSubRangeCount <
            QUIC_RANGE_TIERED_BLOCK_CAPACITY) {
            QuicRangeTieredInsertLocal(
                Tiered,
                BlockIndex,
                BlockSubRangeCount,
                LocalIndex,
                &Carry);
            break;
        }

        // Save the full block's final record before local insertion overwrites it.
        const QUIC_SUBRANGE NextCarry =
            *QuicRangeTieredGetBlockSlot(
                Tiered,
                BlockIndex,
                QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1);
        QuicRangeTieredInsertLocal(
            Tiered,
            BlockIndex,
            QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1,
            LocalIndex,
            &Carry);
        Carry = NextCarry;
        BlockIndex++;
        LocalIndex = 0;
    }

    // Publish the new logical size only after the carry is fully stored.
    Range->UsedLength++;
    return QuicRangeTieredGet(Range, Index);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeTieredRemove(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    )
{
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_TIERED);
    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(Index + Count <= Range->UsedLength);

    // The common single-record path uses bounded local movement and carries.
    if (Count == 1) {
        QuicRangeTieredRemoveOne(Range, Index);
        QuicRangeTieredCompact(Range);
        return TRUE;
    }

    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    const uint32_t TailCount =
        Range->UsedLength - Index - Count;
    const uint64_t SingleRemoveEstimate =
        (uint64_t)Count *
            (QUIC_RANGE_TIERED_BLOCK_CAPACITY / 2 +
             Tiered->ActiveBlockCount);
    // Repeat local removal only when its estimate is cheaper than copying the tail.
    if (SingleRemoveEstimate < TailCount) {
        // The next record in the removed span shifts into the same logical index.
        for (uint32_t i = 0; i < Count; ++i) {
            QuicRangeTieredRemoveOne(Range, Index);
        }
        QuicRangeTieredCompact(Range);
        return TRUE;
    }

    // Sources are always above destinations, so forward tail copying is overlap-safe.
    for (uint32_t i = 0; i < TailCount; ++i) {
        *QuicRangeTieredGet(Range, Index + i) =
            *QuicRangeTieredGet(Range, Index + Count + i);
    }
    Range->UsedLength -= Count;
    Tiered->ActiveBlockCount =
        QuicRangeTieredGetRequiredBlockCount(Range->UsedLength);
    QuicRangeTieredCompact(Range);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredConvertAndInsert(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    )
{
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_ARRAY);
    CXPLAT_DBG_ASSERT(Index <= Range->UsedLength);
    CXPLAT_DBG_ASSERT(
        Range->UsedLength ==
            QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    CXPLAT_DBG_ASSERT(
        Range->AllocLength ==
            QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    CXPLAT_DBG_ASSERT(
        Range->SubRanges !=
            Range->PreAllocSubRanges);

    const uint16_t RequiredBlockCount =
        QuicRangeTieredGetRequiredBlockCount(
            Range->UsedLength + 1);
    CXPLAT_DBG_ASSERT(RequiredBlockCount == 2);

    // The final representation contains the adopted array and one new block.
    if (Range->MaxAllocSize <
        sizeof(QUIC_RANGE_TIERED) +
            (uint32_t)RequiredBlockCount *
                QUIC_RANGE_TIERED_BLOCK_BYTES) {
        return NULL;
    }

    // The directory is separate so blocks can grow without relocating old records.
    QUIC_RANGE_TIERED* Tiered =
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_RANGE_TIERED),
            QUIC_POOL_RANGE);
    if (Tiered == NULL) {
        return NULL;
    }
    CxPlatZeroMemory(Tiered, sizeof(*Tiered));
    // Limit capacity by both the remaining byte budget and directory slots.
    Tiered->MaxBlockCount =
        (uint16_t)CXPLAT_MIN(
            (Range->MaxAllocSize - (uint32_t)sizeof(*Tiered)) /
                QUIC_RANGE_TIERED_BLOCK_BYTES,
            QUIC_RANGE_TIERED_DIRECTORY_CAPACITY);
    if (Tiered->MaxBlockCount < RequiredBlockCount) {
        CXPLAT_FREE(Tiered, QUIC_POOL_RANGE);
        return NULL;
    }

    // Range retains ownership while the directory temporarily borrows block zero.
    Tiered->Blocks[0] = Range->SubRanges;
    Tiered->ActiveBlockCount = 1;
    Tiered->AllocatedBlockCount = 1;

    // Use tiered helpers without publishing the representation to Range yet.
    QUIC_RANGE Temporary = *Range;
    Temporary.Tiered = Tiered;
    Temporary.AllocLength = 0;
    Temporary.Mode = QUIC_RANGE_MODE_TIERED;

    // Allocate the second block before the borrowed array can be modified.
    if (!QuicRangeTieredEnsureActiveBlocks(
            &Temporary,
            RequiredBlockCount)) {
        // Block zero is still owned by Range, so free only the new directory.
        CXPLAT_FREE(Tiered, QUIC_POOL_RANGE);
        return NULL;
    }

    // With both blocks ready, insertion cannot fail and transfers ownership.
    QUIC_SUBRANGE* const Inserted =
        QuicRangeTieredInsert(
            &Temporary,
            Index,
            Low,
            Count);
    CXPLAT_FRE_ASSERT(Inserted != NULL);

    // Publish the directory, which now owns the former array as block zero.
    Range->Tiered = Tiered;
    Range->UsedLength = Temporary.UsedLength;
    Range->AllocLength = 0;
    Range->Mode = QUIC_RANGE_MODE_TIERED;
    return Inserted;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredReset(
    _Inout_ QUIC_RANGE* Range
    )
{
    Range->UsedLength = 0;
    QuicRangeTieredDemote(Range);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredUninitialize(
    _Inout_ QUIC_RANGE* Range
    )
{
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    QuicRangeTieredFreeStorage(Tiered);
    Range->Tiered = NULL;
}

uint32_t
QuicRangeTieredGetAllocatedBytes(
    _In_ const QUIC_RANGE* Range
    )
{
    return
        (uint32_t)sizeof(*Range->Tiered) +
        (uint32_t)Range->Tiered->AllocatedBlockCount *
            (uint32_t)QUIC_RANGE_TIERED_BLOCK_BYTES;
}

uint32_t
QuicRangeTieredGetCapacity(
    _In_ const QUIC_RANGE* Range
    )
{
    return
        (uint32_t)Range->Tiered->MaxBlockCount *
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;
}
