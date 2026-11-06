/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A set of unique 64-bit values, stored as ordered subranges.

--*/

#include "precomp.h"

//
// Copies a small tiered range back into embedded array storage.
//
static
void
QuicRangeDemote(
    _Inout_ QUIC_RANGE* Range
    )
{
    CXPLAT_DBG_ASSERT(Range->Mode == QUIC_RANGE_MODE_TIERED);
    CXPLAT_DBG_ASSERT(
        (Range->AllowedModes & QUIC_RANGE_MODE_ARRAY) != 0);
    QUIC_RANGE_TIERED* Tiered = Range->Tiered;
    const uint32_t UsedLength = QuicRangeTieredSize(Tiered);
    CXPLAT_DBG_ASSERT(
        UsedLength <=
            QUIC_RANGE_INITIAL_SUB_COUNT);

    //
    // Copy in logical order before replacing the active union member.
    //
    for (uint32_t i = 0; i < UsedLength; ++i) {
        Range->Array.PreAllocSubRanges[i] =
            *QuicRangeTieredGet(Tiered, i);
    }

    QuicRangeTieredUninitialize(Tiered);
    QuicRangeArrayInitialize(&Range->Array);
    Range->Array.UsedLength = UsedLength;
    Range->Mode = QUIC_RANGE_MODE_ARRAY;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeInitialize(
    _In_ uint32_t MaxAllocSize,
    _In_ QUIC_RANGE_MODE_MASK AllowedModes,
    _Out_ QUIC_RANGE* Range
    )
{
    CXPLAT_DBG_ASSERT(
        AllowedModes == QUIC_RANGE_MODE_ARRAY ||
        AllowedModes ==
            (QUIC_RANGE_MODE_ARRAY | QUIC_RANGE_MODE_TIERED));
    QuicRangeArrayInitialize(&Range->Array);
    Range->MaxAllocSize = MaxAllocSize;
    CXPLAT_FRE_ASSERT(sizeof(QUIC_SUBRANGE) * QUIC_RANGE_INITIAL_SUB_COUNT < MaxAllocSize);
    Range->Mode = QUIC_RANGE_MODE_ARRAY;
    Range->AllowedModes = AllowedModes;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeUninitialize(
    _In_ QUIC_RANGE* Range
    )
{
    // Dispatch before interpreting the backing-storage union as an array pointer.
    if (Range->Mode == QUIC_RANGE_MODE_TIERED) {
        QuicRangeTieredUninitialize(Range->Tiered);
        return;
    }
    QuicRangeArrayUninitialize(&Range->Array);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeReset(
    _Inout_ QUIC_RANGE* Range
    )
{
    if (Range->Mode == QUIC_RANGE_MODE_TIERED) {
        QuicRangeTieredUninitialize(Range->Tiered);
        QuicRangeArrayInitialize(&Range->Array);
        Range->Mode = QUIC_RANGE_MODE_ARRAY;
        return;
    }
    QuicRangeArrayReset(&Range->Array);
}

//
// Returns TRUE when the next array growth should instead promote to tiered
// storage. The range must opt in and have enough budget for the initial tiered
// directory and two data blocks.
//
static BOOLEAN
QuicRangeShouldPromote(
    _In_ const QUIC_RANGE* Range
    )
{
    if (Range->Mode != QUIC_RANGE_MODE_ARRAY ||
        (Range->AllowedModes & QUIC_RANGE_MODE_TIERED) == 0) {
        return FALSE;
    }

    if (Range->Array.UsedLength != QUIC_RANGE_TIERED_PROMOTE_LENGTH ||
        Range->Array.AllocLength != QUIC_RANGE_TIERED_PROMOTE_LENGTH) {
        return FALSE;
    }

    return QuicRangeTieredCanPromote(Range->MaxAllocSize);
}

//
// Dispatches insertion to the active storage backend and promotes an eligible
// full array before publishing the tiered representation.
//
static
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeInsertSubrange(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    )
{
    if (Range->Mode == QUIC_RANGE_MODE_TIERED) {
        return
            QuicRangeTieredInsert(
                Range->Tiered,
                Range->MaxAllocSize,
                Index,
                Low,
                Count);
    }

    if (!QuicRangeShouldPromote(Range)) {
        return
            QuicRangeArrayInsert(
                &Range->Array,
                Range->MaxAllocSize,
                Index,
                Low,
                Count);
    }

    CXPLAT_DBG_ASSERT(
        Range->Array.SubRanges !=
            Range->Array.PreAllocSubRanges);
    QUIC_RANGE_TIERED* Tiered;
    QUIC_SUBRANGE* Sub =
        QuicRangeTieredConvertAndInsert(
            Range->Array.SubRanges,
            Range->Array.UsedLength,
            Range->MaxAllocSize,
            Index,
            Low,
            Count,
            &Tiered);
    if (Sub != NULL) {
        CXPLAT_DBG_ASSERT(
            (Range->AllowedModes & QUIC_RANGE_MODE_TIERED) != 0);
        Range->Tiered = Tiered;
        Range->Mode = QUIC_RANGE_MODE_TIERED;
    }
    return Sub;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeRemoveSubranges(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    )
{
    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(Index + Count <= QuicRangeSize(Range));

    if (Range->Mode == QUIC_RANGE_MODE_TIERED) {
        //
        // Tiered removal reports pointer invalidation because records may move
        // physically even when no allocation is released.
        //
        QuicRangeTieredRemove(Range->Tiered, Index, Count);
        if (QuicRangeTieredSize(Range->Tiered) <=
            QUIC_RANGE_INITIAL_SUB_COUNT) {
            QuicRangeDemote(Range);
        }
        return TRUE;
    }

    return
        QuicRangeArrayRemoveSubranges(
            &Range->Array,
            Index,
            Count);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetRange(
    _In_ QUIC_RANGE* Range,
    _In_ uint64_t Low,
    _Out_ uint64_t* Count,
    _Out_ BOOLEAN* IsLastRange
    )
{
    QUIC_RANGE_SEARCH_KEY Key = { Low, Low };
    int i = QuicRangeSearch(Range, &Key);
    if (IS_INSERT_INDEX(i)) {
        return FALSE;
    }

    QUIC_SUBRANGE* Sub = QuicRangeGet(Range, i);
    *Count = Sub->Count - (Low - Sub->Low);
    *IsLastRange = (uint32_t)(i + 1) == QuicRangeSize(Range);
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeAddRange(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t Low,
    _In_ uint64_t Count,
    _Out_ BOOLEAN* RangeUpdated
    )
{
    uint32_t i;
    QUIC_SUBRANGE* Sub;
    QUIC_RANGE_SEARCH_KEY Key = { Low, Low + Count - 1 };

    *RangeUpdated = FALSE;

#if QUIC_RANGE_USE_BINARY_SEARCH
    if ((Sub = QuicRangeGetSafe(Range, QuicRangeSize(Range) - 1)) != NULL &&
        Sub->Low + Sub->Count > Low) {
#endif
        //
        // The new range is somewhere before the end of the of the last subrange
        // so we must search for the first overlapping or adjacent subrange.
        //
        int result = QuicRangeSearch(Range, &Key);
        if (IS_FIND_INDEX(result)) {
            //
            // We found 'an' overlapping subrange. We need to ensure this is the
            // first overlapping range.
            //
            i = (uint32_t)result;
            while ((Sub = QuicRangeGetSafe(Range, i - 1)) != NULL &&
                    QuicRangeCompare(&Key, Sub) == 0) {
                --i;
            }
        } else {
            //
            // No overlapping range was found, so the index of the insert was
            // returned.
            i = INSERT_INDEX_TO_FIND_INDEX(result);
        }
        //
        // Make sure the previous subrange isn't 1 less than the current Low.
        // If so, start with that subrange.
        //
        if ((Sub = QuicRangeGetSafe(Range, i - 1)) != NULL &&
            Sub->Low + Sub->Count == Low) {
            i--;
        } else {
            Sub = QuicRangeGetSafe(Range, i);
        }
#if QUIC_RANGE_USE_BINARY_SEARCH
    } else if (Sub == NULL) {
        //
        // There are no subranges.
        //
        i = 0;
    } else if (Sub->Low + Sub->Count == Low) {
        //
        // New value is adjacent to the current last subrange.
        //
        i = QuicRangeSize(Range) - 1;
    } else {
        //
        // New value is after the current last subrange.
        //
        i = QuicRangeSize(Range);
        Sub = NULL;
    }
#endif

    if (Sub == NULL || Sub->Low > Low + Count) {
        //
        // Insert before the current subrange (or at the beginning).
        //
        Sub =
            QuicRangeInsertSubrange(
                Range,
                i,
                Low,
                Count);
        if (Sub == NULL) {
            return NULL;
        }

        *RangeUpdated = TRUE;

    } else {
        //
        // Found an overlapping or adjacent subrange.
        // Expand this subrange to cover the inserted range.
        //
        if (Sub->Low > Low) {
            *RangeUpdated = TRUE;
            Sub->Count += Sub->Low - Low;
            Sub->Low = Low;
        }
        if (Sub->Low + Sub->Count < Low + Count) {
            *RangeUpdated = TRUE;
            Sub->Count = Low + Count - Sub->Low;
        }

        //
        // Subsume subranges overlapping/adjacent to the expanded subrange.
        //
        uint32_t j = i + 1;
        QUIC_SUBRANGE* Next;
        while ((Next = QuicRangeGetSafe(Range, j)) != NULL &&
                Next->Low <= Low + Count) {
            if (Next->Low + Next->Count > Sub->Low + Sub->Count) {
                //
                // Don't bother updating "Count" (the loop will terminate).
                //
                Sub->Count = Next->Low + Next->Count - Sub->Low;
            }
            j++;
        }

        uint32_t RemoveCount = j - (i + 1);
        if (RemoveCount != 0) {
            if (QuicRangeRemoveSubranges(Range, i + 1, RemoveCount)) {
                //
                // Removal invalidated record pointers, so reacquire Sub.
                //
                Sub = QuicRangeGet(Range, i);
            }
        }
    }

    return Sub;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeAddValue(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t Value
    )
{
    BOOLEAN DontCare;
    return QuicRangeAddRange(Range, Value, 1, &DontCare) != NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeSetMin(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t Low
    )
{
    //
    // Drop all values less than "low".
    //
    uint32_t i = 0;
    QUIC_SUBRANGE* Sub = NULL;
    while (i < QuicRangeSize(Range)) {
        Sub = QuicRangeGet(Range, i);
        if (Sub->Low >= Low) {
            break;
        }

        if (QuicRangeGetHigh(Sub) >= Low) {
            Sub->Count -= Low - Sub->Low;
            Sub->Low = Low;
            break;
        }
        i++;
    }
    if (i > 0) {
        QuicRangeRemoveSubranges(Range, 0, i);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRangeGetMin(
    _In_ QUIC_RANGE* Range
    )
{
    return QuicRangeGet(Range, 0)->Low;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetMinSafe(
    _In_ QUIC_RANGE* Range,
    _Out_ uint64_t* Value
    )
{
    if (QuicRangeSize(Range) > 0) {
        *Value = QuicRangeGetMin(Range);
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRangeGetMax(
    _In_ QUIC_RANGE* Range
    )
{
    return
        QuicRangeGetHigh(
            QuicRangeGet(
                Range,
                QuicRangeSize(Range) - 1));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetMaxSafe(
    _In_ QUIC_RANGE* Range,
    _Out_ uint64_t* Value
    )
{
    if (QuicRangeSize(Range) > 0) {
        *Value = QuicRangeGetMax(Range);
        return TRUE;
    }
    return FALSE;
}
