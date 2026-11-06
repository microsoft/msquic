/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tiered vector storage for large QUIC_RANGE instances.

--*/

#include "precomp.h"
#include "range_tiered.h"
#ifdef QUIC_CLOG
#include "range_tiered.c.clog.h"
#endif

struct QUIC_RANGE_TIERED {

    // Each non-NULL entry owns one fixed-capacity subrange block.
    QUIC_SUBRANGE* Blocks[QUIC_RANGE_TIERED_DIRECTORY_CAPACITY];
    // Each entry maps logical slot zero to a physical circular slot.
    uint16_t Starts[QUIC_RANGE_TIERED_DIRECTORY_CAPACITY];
    // Total logical subranges stored across every active block.
    uint32_t UsedLength;
    // Active blocks contain live records; inactive allocations remain reusable.
    uint16_t ActiveBlockCount;
    uint16_t AllocatedBlockCount;
    // Maximum blocks allowed by both the byte budget and directory capacity.
    uint16_t MaxBlockCount;

};

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_RANGE_TIERED) < QUIC_RANGE_TIERED_BLOCK_BYTES,
    "Tiered range directory must fit in less than one range block");

BOOLEAN
QuicRangeTieredCanPromote(
    _In_ uint32_t MaxAllocSize
    )
{
    // The final representation contains the adopted block and one new block.
    return
        MaxAllocSize >=
            (uint32_t)sizeof(QUIC_RANGE_TIERED) +
                2U * QUIC_RANGE_TIERED_BLOCK_BYTES;
}

//
// Returns the number of blocks required for the given subrange count.
// SubRangeCount is the total logical subrange count to represent.
//
static uint32_t
QuicRangeTieredGetRequiredBlockCount(
    _In_ uint32_t SubRangeCount
    )
{
    CXPLAT_DBG_ASSERT(
        SubRangeCount <=
            QUIC_RANGE_TIERED_DIRECTORY_CAPACITY *
                QUIC_RANGE_TIERED_BLOCK_CAPACITY);

    // An empty range requires no active blocks.
    if (SubRangeCount == 0) {
        return 0;
    }

    // ceil(SubRangeCount/QUIC_RANGE_TIERED_BLOCK_CAPACITY)
    return
        (SubRangeCount + QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1) /
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;
}

//
// Returns the current live record count for an active block.
// BlockIndex identifies a block in Tiered's current active layout.
// The final active block may be empty while insertion is reserving capacity.
//
static uint32_t
QuicRangeTieredGetBlockSubRangeCount(
    _In_ const QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t BlockIndex
    )
{
    CXPLAT_DBG_ASSERT(BlockIndex < Tiered->ActiveBlockCount);
    // Invariant: Every current non-final active block is full.
    if (BlockIndex + 1 < Tiered->ActiveBlockCount) {
        return QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    }
    // The current final active block contains the remaining subranges.
    const uint32_t BlockStart =
        (uint32_t)BlockIndex * QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    CXPLAT_DBG_ASSERT(Tiered->UsedLength >= BlockStart);
    const uint32_t BlockSubRangeCount =
        Tiered->UsedLength - BlockStart;
    CXPLAT_DBG_ASSERT(
        BlockSubRangeCount <= QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    return BlockSubRangeCount;
}

//
// Maps a block-local logical index to its physical circular-array index.
//
static uint32_t
QuicRangeTieredGetPhysicalSlotIndex(
    _In_ const QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t BlockIndex,
    _In_ uint32_t LogicalIndex
    )
{
    return
        (Tiered->Starts[BlockIndex] + LogicalIndex) %
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;
}

//
// Maps a logical slot in a circular block to its physical record.
// Slot is relative to the block's logical start, not physical array slot zero.
//
static QUIC_SUBRANGE*
QuicRangeTieredGetBlockSlot(
    _In_ const QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t BlockIndex,
    _In_ uint32_t Slot
    )
{
    const uint32_t PhysicalSlot =
        QuicRangeTieredGetPhysicalSlotIndex(
            Tiered,
            BlockIndex,
            Slot);
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
    const uint32_t BlockIndex =
        --Tiered->AllocatedBlockCount;
    QUIC_SUBRANGE* Block = Tiered->Blocks[BlockIndex];
    Tiered->Blocks[BlockIndex] = NULL;
    Tiered->Starts[BlockIndex] = 0;
    CXPLAT_FREE(Block, QUIC_POOL_RANGE);
}

//
// Releases trailing inactive blocks after utilization falls below one quarter.
// The active prefix is preserved while retaining capacity for regrowth.
//
static void
QuicRangeTieredReleaseExcessBlocks(
    _Inout_ QUIC_RANGE_TIERED* Tiered
    )
{
    // Retain the current allocation until active use falls below one quarter.
    if (Tiered->AllocatedBlockCount <= 1 ||
        (uint32_t)Tiered->ActiveBlockCount * 4 >=
            Tiered->AllocatedBlockCount) {
        return;
    }

    // Retain headroom so limited regrowth does not immediately allocate.
    const uint32_t RetainedBlockCount =
        CXPLAT_MAX(
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

QUIC_SUBRANGE*
QuicRangeTieredGet(
    _In_ const QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t Index
    )
{
    CXPLAT_DBG_ASSERT(Index < Tiered->UsedLength);
    return
        QuicRangeTieredGetBlockSlot(
            Tiered,
            Index / QUIC_RANGE_TIERED_BLOCK_CAPACITY,
            Index % QUIC_RANGE_TIERED_BLOCK_CAPACITY);
}

uint32_t
QuicRangeTieredSize(
    _In_ const QUIC_RANGE_TIERED* Tiered
    )
{
    return Tiered->UsedLength;
}

//
// Allocates and activates all blocks required before a mutation begins.
// RequiredBlockCount is the desired post-mutation active block count.
// Failure rolls back only allocations made by this call.
//
static BOOLEAN
QuicRangeTieredEnsureActiveBlocks(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t RequiredBlockCount
    )
{
    // MaxBlockCount already charges the directory and every permitted block.
    if (RequiredBlockCount > Tiered->MaxBlockCount) {
        return FALSE;
    }

    // This count is the rollback boundary for allocations made by this call.
    const uint32_t OriginalAllocated = Tiered->AllocatedBlockCount;
    while (Tiered->AllocatedBlockCount < RequiredBlockCount) {
        // Blocks are independent allocations so growth never relocates old blocks.
        QUIC_SUBRANGE* Block =
            CXPLAT_ALLOC_NONPAGED(
                QUIC_RANGE_TIERED_BLOCK_BYTES,
                QUIC_POOL_RANGE);
        if (Block == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "tiered range block",
                (unsigned long long)QUIC_RANGE_TIERED_BLOCK_BYTES);
            goto Error;
        }

        const uint32_t BlockIndex = Tiered->AllocatedBlockCount++;
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
// Selects the shorter physically contiguous side of a block-local mutation.
// If the shorter side wraps, the other side is selected.
//
static BOOLEAN
QuicRangeTieredShouldMovePrefix(
    _In_ uint32_t PrefixCount,
    _In_ uint32_t SuffixCount,
    _In_ BOOLEAN PrefixIsContiguous,
    _In_ BOOLEAN SuffixIsContiguous
    )
{
    CXPLAT_DBG_ASSERT(PrefixIsContiguous || SuffixIsContiguous);
    return
        PrefixIsContiguous &&
        (!SuffixIsContiguous || PrefixCount < SuffixCount);
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
    _In_ uint32_t BlockIndex,
    _In_ uint32_t Count,
    _In_ uint32_t Index,
    _In_ const QUIC_SUBRANGE* Value
    )
{
    CXPLAT_DBG_ASSERT(Count < QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    CXPLAT_DBG_ASSERT(Index <= Count);

    const uint32_t PrefixCount = Index;
    const uint32_t SuffixCount = Count - Index;
    const uint32_t OriginalStart = Tiered->Starts[BlockIndex];
    const uint32_t PhysicalIndex =
        QuicRangeTieredGetPhysicalSlotIndex(
            Tiered,
            BlockIndex,
            Index);
    const BOOLEAN PrefixIsContiguous =
        PrefixCount == 0 ||
        (OriginalStart != 0 &&
         (uint32_t)OriginalStart + PrefixCount <=
            QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    const BOOLEAN SuffixIsContiguous =
        SuffixCount == 0 ||
        (uint32_t)PhysicalIndex + SuffixCount <
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;

    if (QuicRangeTieredShouldMovePrefix(
            PrefixCount,
            SuffixCount,
            PrefixIsContiguous,
            SuffixIsContiguous)) {
        // Move the circular start back one slot and wrap at zero.
        if (PrefixCount != 0) {
            memmove(
                Tiered->Blocks[BlockIndex] + OriginalStart - 1,
                Tiered->Blocks[BlockIndex] + OriginalStart,
                PrefixCount * sizeof(QUIC_SUBRANGE));
        }
        Tiered->Starts[BlockIndex] =
            (uint16_t)(
                (OriginalStart + QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1) %
                    QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    } else {
        if (SuffixCount != 0) {
            memmove(
                Tiered->Blocks[BlockIndex] + PhysicalIndex + 1,
                Tiered->Blocks[BlockIndex] + PhysicalIndex,
                SuffixCount * sizeof(QUIC_SUBRANGE));
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
    _In_ uint32_t BlockIndex,
    _In_ uint32_t Count,
    _In_ uint32_t Index
    )
{
    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(Index < Count);

    const uint32_t PrefixCount = Index;
    const uint32_t SuffixCount = Count - Index - 1;
    const uint32_t OriginalStart = Tiered->Starts[BlockIndex];
    const uint32_t PhysicalIndex =
        QuicRangeTieredGetPhysicalSlotIndex(
            Tiered,
            BlockIndex,
            Index);
    const BOOLEAN PrefixIsContiguous =
        PrefixCount == 0 ||
        (uint32_t)OriginalStart + PrefixCount <
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    const BOOLEAN SuffixIsContiguous =
        SuffixCount == 0 ||
        (uint32_t)PhysicalIndex + SuffixCount <
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;

    if (QuicRangeTieredShouldMovePrefix(
            PrefixCount,
            SuffixCount,
            PrefixIsContiguous,
            SuffixIsContiguous)) {
        if (PrefixCount != 0) {
            memmove(
                Tiered->Blocks[BlockIndex] + OriginalStart + 1,
                Tiered->Blocks[BlockIndex] + OriginalStart,
                PrefixCount * sizeof(QUIC_SUBRANGE));
        }
        Tiered->Starts[BlockIndex] =
            (uint16_t)(
                (OriginalStart + 1) %
                    QUIC_RANGE_TIERED_BLOCK_CAPACITY);
        return;
    }

    if (SuffixCount != 0) {
        memmove(
            Tiered->Blocks[BlockIndex] + PhysicalIndex,
            Tiered->Blocks[BlockIndex] + PhysicalIndex + 1,
            SuffixCount * sizeof(QUIC_SUBRANGE));
    }
}

//
// Removes one logical record and carries later records backward by block.
// Index is a logical index across the complete range.
//
static void
QuicRangeTieredRemoveOne(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t Index
    )
{
    CXPLAT_DBG_ASSERT(Index < Tiered->UsedLength);

    // Preserve the pre-remove block count because the old final block may empty.
    const uint32_t OldBlockCount = Tiered->ActiveBlockCount;
    const uint32_t BlockIndex =
        Index / QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    const uint32_t LocalIndex =
        Index % QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    QuicRangeTieredRemoveLocal(
        Tiered,
        BlockIndex,
        QuicRangeTieredGetBlockSubRangeCount(Tiered, BlockIndex),
        LocalIndex);

    // Carry each later block's first record backward to keep prior blocks full.
    for (uint32_t i = BlockIndex + 1;
         i < OldBlockCount;
         ++i) {
        const QUIC_SUBRANGE Carry =
            *QuicRangeTieredGetBlockSlot(Tiered, i, 0);
        Tiered->Starts[i] =
            (uint16_t)(
                (Tiered->Starts[i] + 1) %
                    QUIC_RANGE_TIERED_BLOCK_CAPACITY);
        *QuicRangeTieredGetBlockSlot(
            Tiered,
            i - 1,
            QUIC_RANGE_TIERED_BLOCK_CAPACITY - 1) = Carry;
    }

    // Publish the new logical size after every backward carry completes.
    Tiered->UsedLength--;
    Tiered->ActiveBlockCount =
        (uint16_t)QuicRangeTieredGetRequiredBlockCount(
            Tiered->UsedLength);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeTieredInsert(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t MaxAllocSize,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    )
{
    CXPLAT_DBG_ASSERT(Index <= Tiered->UsedLength);

    if (Tiered->UsedLength == QuicRangeTieredGetCapacity(Tiered)) {
        // Maximum-budget ranges never discard data, and index zero cannot age out.
        if (MaxAllocSize == QUIC_MAX_RANGE_ALLOC_SIZE ||
            Index == 0) {
            return NULL;
        }
        // Age out the first subrange and adjust for the resulting index shift.
        QuicRangeTieredRemoveOne(Tiered, 0);
        Index--;
    }

    const uint32_t RequiredBlockCount =
        QuicRangeTieredGetRequiredBlockCount(
            Tiered->UsedLength + 1);
    // Invariant: All required allocation succeeds before any record moves.
    if (!QuicRangeTieredEnsureActiveBlocks(
            Tiered,
            RequiredBlockCount)) {
        return NULL;
    }

    uint32_t BlockIndex =
        Index / QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    uint32_t LocalIndex =
        Index % QUIC_RANGE_TIERED_BLOCK_CAPACITY;
    QUIC_SUBRANGE Carry = {Low, Count};

    // Carry displaced records forward until a block has an available slot.
    for (;;) {
        const uint32_t BlockSubRangeCount =
            QuicRangeTieredGetBlockSubRangeCount(
                Tiered,
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
    Tiered->UsedLength++;
    return QuicRangeTieredGet(Tiered, Index);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredRemove(
    _Inout_ QUIC_RANGE_TIERED* Tiered,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    )
{
    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(Index + Count <= Tiered->UsedLength);

    // The common single-record path uses bounded local movement and carries.
    if (Count == 1) {
        QuicRangeTieredRemoveOne(Tiered, Index);
        QuicRangeTieredReleaseExcessBlocks(Tiered);
        return;
    }

    const uint32_t TailCount =
        Tiered->UsedLength - Index - Count;
    const uint64_t SingleRemoveEstimate =
        (uint64_t)Count *
            (QUIC_RANGE_TIERED_BLOCK_CAPACITY / 2 +
             Tiered->ActiveBlockCount);
    // Repeat local removal only when its estimate is cheaper than copying the tail.
    if (SingleRemoveEstimate < TailCount) {
        // The next record in the removed span shifts into the same logical index.
        for (uint32_t i = 0; i < Count; ++i) {
            QuicRangeTieredRemoveOne(Tiered, Index);
        }
        QuicRangeTieredReleaseExcessBlocks(Tiered);
        return;
    }

    // Sources are always above destinations, so forward tail copying is overlap-safe.
    for (uint32_t i = 0; i < TailCount; ++i) {
        *QuicRangeTieredGet(Tiered, Index + i) =
            *QuicRangeTieredGet(Tiered, Index + Count + i);
    }
    Tiered->UsedLength -= Count;
    Tiered->ActiveBlockCount =
        (uint16_t)QuicRangeTieredGetRequiredBlockCount(
            Tiered->UsedLength);
    QuicRangeTieredReleaseExcessBlocks(Tiered);
}

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
    )
{
    *NewTiered = NULL;
    CXPLAT_DBG_ASSERT(Index <= InitialLength);
    CXPLAT_DBG_ASSERT(
        InitialLength ==
            QUIC_RANGE_TIERED_BLOCK_CAPACITY);
    CXPLAT_DBG_ASSERT(InitialBlock != NULL);

    const uint32_t RequiredBlockCount =
        QuicRangeTieredGetRequiredBlockCount(
            InitialLength + 1);
    CXPLAT_DBG_ASSERT(RequiredBlockCount == 2);

    CXPLAT_DBG_ASSERT(
        QuicRangeTieredCanPromote(MaxAllocSize));

    // The directory is separate so blocks can grow without relocating old records.
    QUIC_RANGE_TIERED* Tiered =
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_RANGE_TIERED),
            QUIC_POOL_RANGE);
    if (Tiered == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "tiered range directory",
            (unsigned long long)sizeof(QUIC_RANGE_TIERED));
        return NULL;
    }
    CxPlatZeroMemory(Tiered, sizeof(*Tiered));
    // Limit capacity by both the remaining byte budget and directory slots.
    Tiered->MaxBlockCount =
        (uint16_t)CXPLAT_MIN(
            (MaxAllocSize - (uint32_t)sizeof(*Tiered)) /
                QUIC_RANGE_TIERED_BLOCK_BYTES,
            QUIC_RANGE_TIERED_DIRECTORY_CAPACITY);
    if (Tiered->MaxBlockCount < RequiredBlockCount) {
        CXPLAT_FREE(Tiered, QUIC_POOL_RANGE);
        return NULL;
    }

    // The caller retains ownership while the directory borrows block zero.
    Tiered->Blocks[0] = InitialBlock;
    Tiered->UsedLength = InitialLength;
    Tiered->ActiveBlockCount = 1;
    Tiered->AllocatedBlockCount = 1;

    // Allocate the second block before the borrowed array can be modified.
    if (!QuicRangeTieredEnsureActiveBlocks(
            Tiered,
            RequiredBlockCount)) {
        // Block zero is still caller-owned, so free only the new directory.
        CXPLAT_FREE(Tiered, QUIC_POOL_RANGE);
        return NULL;
    }

    // With both blocks ready, insertion cannot fail and transfers ownership.
    QUIC_SUBRANGE* const Inserted =
        QuicRangeTieredInsert(
            Tiered,
            MaxAllocSize,
            Index,
            Low,
            Count);
    CXPLAT_FRE_ASSERT(Inserted != NULL);

    // The caller publishes the directory, which now owns the initial block.
    *NewTiered = Tiered;
    return Inserted;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeTieredUninitialize(
    _In_ QUIC_RANGE_TIERED* Tiered
    )
{
    QuicRangeTieredFreeStorage(Tiered);
}

uint32_t
QuicRangeTieredGetAllocatedBytes(
    _In_ const QUIC_RANGE_TIERED* Tiered
    )
{
    return
        (uint32_t)sizeof(*Tiered) +
        (uint32_t)Tiered->AllocatedBlockCount *
            (uint32_t)QUIC_RANGE_TIERED_BLOCK_BYTES;
}

uint32_t
QuicRangeTieredGetCapacity(
    _In_ const QUIC_RANGE_TIERED* Tiered
    )
{
    return
        (uint32_t)Tiered->MaxBlockCount *
            QUIC_RANGE_TIERED_BLOCK_CAPACITY;
}
