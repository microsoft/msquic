/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A set of unique 64-bit values, stored as an array of subranges ordered from
    smallest to largest.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "range.c.clog.h"
#endif

#define INITIAL_SUBRANGE_COUNT 8

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRangeInitialize(
    _In_ uint32_t MaxAllocSize,
    _Out_ QUIC_RANGE* Range
    )
{
    Range->UsedLength = 0;
    Range->AllocLength = INITIAL_SUBRANGE_COUNT;
    Range->MaxAllocSize = MaxAllocSize;
    QUIC_FRE_ASSERT(sizeof(QUIC_SUBRANGE) * INITIAL_SUBRANGE_COUNT < MaxAllocSize);
    Range->SubRanges = QUIC_ALLOC_NONPAGED(sizeof(QUIC_SUBRANGE) * INITIAL_SUBRANGE_COUNT);
    if (Range->SubRanges == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "range",
            sizeof(QUIC_SUBRANGE) * INITIAL_SUBRANGE_COUNT);
    }
    return (Range->SubRanges == NULL) ? QUIC_STATUS_OUT_OF_MEMORY : QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeUninitialize(
    _In_ QUIC_RANGE* Range
    )
{
    QUIC_FREE(Range->SubRanges);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeReset(
    _Inout_ QUIC_RANGE* Range
    )
{
    Range->UsedLength = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGrow(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t NextIndex   // The next index to write to after the grow.
    )
{
    if (Range->AllocLength == QUIC_MAX_RANGE_ALLOC_SIZE) {
        return FALSE; // Can't grow any more.
    }

    uint32_t NewAllocLength = Range->AllocLength << 1; // Grow by a factor of 2.
    uint32_t NewAllocSize = NewAllocLength * sizeof(QUIC_SUBRANGE);
    QUIC_FRE_ASSERTMSG(NewAllocSize > sizeof(QUIC_SUBRANGE), "Range alloc arithmetic underflow.");
    if (NewAllocSize > Range->MaxAllocSize) {
        //
        // Don't log anything as this will be the common case after we hit the
        // cap. For instance, after receiving lots of packets.
        //
        return FALSE;
    }

    QUIC_SUBRANGE* NewSubRanges = QUIC_ALLOC_NONPAGED(NewAllocSize);
    if (NewSubRanges == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "range (realloc)",
            NewAllocLength);
        return FALSE;
    }

    //
    // Move the items to the new array and make room for the next index to write.
    //

    if (NextIndex == 0) {
        memcpy(
            NewSubRanges + 1,
            Range->SubRanges,
            Range->UsedLength * sizeof(QUIC_SUBRANGE));
    } else if (NextIndex == Range->UsedLength) {
        memcpy(
            NewSubRanges,
            Range->SubRanges,
            Range->UsedLength * sizeof(QUIC_SUBRANGE));
    } else {
        memcpy(
            NewSubRanges,
            Range->SubRanges,
            NextIndex * sizeof(QUIC_SUBRANGE));
        memcpy(
            NewSubRanges + NextIndex + 1,
            Range->SubRanges + NextIndex,
            (Range->UsedLength - NextIndex) * sizeof(QUIC_SUBRANGE));
    }

    QUIC_FREE(Range->SubRanges);
    Range->SubRanges = NewSubRanges;
    Range->AllocLength = NewAllocLength;
    Range->UsedLength++; // For the next write index.

    return TRUE;
}

//
// Reads the array for inserting a new subrange at the given index.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeMakeSpace(
    _Inout_ QUIC_RANGE* Range,
    _Inout_ uint32_t* Index
    )
{
    QUIC_DBG_ASSERT(*Index <= Range->UsedLength);

    if (Range->UsedLength == Range->AllocLength) {
        if (!QuicRangeGrow(Range, *Index)) {
            //
            // We either can't or aren't allowed to grow any more. If we weren't
            // trying to append to the front, age out the smallest values to
            // make room for a new larger one.
            //
            if (Range->MaxAllocSize == QUIC_MAX_RANGE_ALLOC_SIZE ||
                *Index == 0) {
                return NULL;
            } else if (*Index > 1) {
                memmove(
                    Range->SubRanges,
                    Range->SubRanges + 1,
                    (*Index - 1) * sizeof(QUIC_SUBRANGE));
            }
            (*Index)--; // Actually going to be inserting 1 before where requested.
        }
    } else {
        if (*Index == 0) {
            memmove(
                Range->SubRanges + 1,
                Range->SubRanges,
                Range->UsedLength * sizeof(QUIC_SUBRANGE));
        } else if (*Index == Range->UsedLength) {
            //
            // No need to copy. Appending to the end.
            //
        } else {
            memmove(
                Range->SubRanges + *Index + 1,
                Range->SubRanges + *Index,
                (Range->UsedLength - *Index) * sizeof(QUIC_SUBRANGE));
        }
        Range->UsedLength++; // For the new write.
    }

    return Range->SubRanges + *Index;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeRemoveSubranges(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    )
{
    QUIC_DBG_ASSERT(Count > 0);
    QUIC_DBG_ASSERT(Index + Count <= Range->UsedLength);

    if (Index + Count < Range->UsedLength) {
        memmove(
            Range->SubRanges + Index,
            Range->SubRanges + Index + Count,
            (Range->UsedLength - Index - Count) * sizeof(QUIC_SUBRANGE));
    }

    Range->UsedLength -= Count;

    BOOLEAN Reallocated = FALSE;
    if (Range->AllocLength >= INITIAL_SUBRANGE_COUNT * 2 &&
        Range->UsedLength < Range->AllocLength / 4) {
        //
        // Shrink
        //
        uint32_t NewAllocLength = Range->AllocLength / 2;
        QUIC_SUBRANGE* NewSubRanges =
            QUIC_ALLOC_NONPAGED(sizeof(QUIC_SUBRANGE) * NewAllocLength);
        if (NewSubRanges != NULL) {
            memcpy(
                NewSubRanges,
                Range->SubRanges,
                Range->UsedLength * sizeof(QUIC_SUBRANGE));
            QUIC_FREE(Range->SubRanges);
            Range->SubRanges = NewSubRanges;
            Range->AllocLength = NewAllocLength;
            Reallocated = TRUE;
        }
    }

    return Reallocated;
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
    *IsLastRange = (uint32_t)(i + 1) == Range->UsedLength;
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
    int result;
    uint32_t i;
    QUIC_SUBRANGE* Sub;
    QUIC_RANGE_SEARCH_KEY Key = { Low, Low + Count - 1 };

    *RangeUpdated = FALSE;

#if QUIC_RANGE_USE_BINARY_SEARCH
    if ((Sub = QuicRangeGetSafe(Range, Range->UsedLength - 1)) != NULL &&
        Sub->Low + Sub->Count > Low) {
#endif
        //
        // The new range is somewhere before the end of the of the last subrange
        // so we must search for the first overlapping or adjacent subrange.
        //
        result = QuicRangeSearch(Range, &Key);
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
            Sub = QuicRangeGet(Range, i);
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
        i = Range->UsedLength - 1;
    } else {
        //
        // New value is after the current last subrange.
        //
        i = Range->UsedLength;
        Sub = NULL;
    }
#endif

    if (Sub == NULL || Sub->Low > Low + Count) {
        //
        // Insert before the current subrange (or at the beginning).
        //
        Sub = QuicRangeMakeSpace(Range, &i);
        if (Sub == NULL) {
            return NULL;
        }

        Sub->Low = Low;
        Sub->Count = Count;
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
                // The subranges were reallocated, so update our Sub pointer.
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
_Success_(return != FALSE)
BOOLEAN
QuicRangeRemoveRange(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    )
{
    //
    // Returns FALSE only if there is an allocation failure
    // (if the input range is already removed, does nothing
    // and returns TRUE).
    //

    uint32_t i;
    QUIC_SUBRANGE* Sub = NULL;
    QUIC_SUBRANGE* Test;

    //
    // Find the leftmost overlapping subrange.
    //
    for (i = 0; (Test = QuicRangeGetSafe(Range, i)) != NULL; i++) {
        if (Test->Low < Low + Count &&
            Test->Low + Test->Count > Low) {
            Sub = Test;
            break;
        }
    }
    if (Sub == NULL) {
        return TRUE;
    }

    if (Sub->Low + Sub->Count > Low + Count &&
        Sub->Low < Low) {
        //
        // Middle overlaps. Duplicate the subrange. The first part
        // will be handled by the "right edge overlaps" case,
        // and the second part will be handled by the "left edge
        // overlaps" case.
        //
        QUIC_SUBRANGE* NewSub = QuicRangeMakeSpace(Range, &i);
        if (NewSub == NULL) {
            return FALSE;
        }
        *NewSub = *Sub;
        Sub = NewSub;
    }

    if (Sub->Low < Low) {
        //
        // Right edge overlaps.
        //
        Sub->Count = Low - Sub->Low;
        Sub = QuicRangeGetSafe(Range, ++i);
    }

    uint32_t prev = i;
    while (Sub &&
        Sub->Low >= Low &&
        Sub->Low + Sub->Count <= Low + Count) {
        //
        // Full overlap.
        //
        Sub = QuicRangeGetSafe(Range, ++i);
    }
    if (i > prev) {
        QuicRangeRemoveSubranges(Range, prev, i - prev);
        Sub = QuicRangeGetSafe(Range, prev);
    }

    if (Sub &&
        Sub->Low < Low + Count &&
        Sub->Low + Sub->Count > Low + Count) {
        //
        // Left edge overlaps.
        //
        Sub->Count -= (Low + Count - Sub->Low);
        Sub->Low = Low + Count;
    }

    return TRUE;
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
        } else if (QuicRangeGetHigh(Sub) >= Low) {
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
    if (Range->UsedLength > 0) {
        *Value = QuicRangeGetMin(Range);
        return TRUE;
    } else {
        return FALSE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRangeGetMax(
    _In_ QUIC_RANGE* Range
    )
{
    return QuicRangeGetHigh(QuicRangeGet(Range, Range->UsedLength - 1));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetMaxSafe(
    _In_ QUIC_RANGE* Range,
    _Out_ uint64_t* Value
    )
{
    if (Range->UsedLength > 0) {
        *Value = QuicRangeGetMax(Range);
        return TRUE;
    } else {
        return FALSE;
    }
}
