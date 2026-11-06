/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Array-backed storage for QUIC_RANGE.

--*/

#include "precomp.h"
#include "range_array.h"
#ifdef QUIC_CLOG
#include "range_array.c.clog.h"
#endif

//
// Activates the embedded initial allocation and resets the logical length.
// Any previously owned heap allocation must already be released or transferred.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeArrayInitialize(
    _Out_ QUIC_RANGE_ARRAY* Array
    )
{
    Array->UsedLength = 0;
    Array->AllocLength = QUIC_RANGE_INITIAL_SUB_COUNT;
    Array->SubRanges = Array->PreAllocSubRanges;
}

//
// Releases heap-backed storage. The embedded initial allocation is part of the
// array descriptor and must never be freed.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeArrayUninitialize(
    _In_ QUIC_RANGE_ARRAY* Array
    )
{
    if (Array->SubRanges != Array->PreAllocSubRanges) {
        CXPLAT_FREE(Array->SubRanges, QUIC_POOL_RANGE);
    }
}

//
// Removes every logical record while retaining the current allocation for
// subsequent insertions.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeArrayReset(
    _Inout_ QUIC_RANGE_ARRAY* Array
    )
{
    Array->UsedLength = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeArrayRemoveSubranges(
    _Inout_ QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    )
{
    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(Index + Count <= Array->UsedLength);

    if (Index + Count < Array->UsedLength) {
        memmove(
            Array->SubRanges + Index,
            Array->SubRanges + Index + Count,
            (Array->UsedLength - Index - Count) * sizeof(QUIC_SUBRANGE));
    }

    Array->UsedLength -= Count;

    if (Array->AllocLength >= QUIC_RANGE_INITIAL_SUB_COUNT * 2 &&
        Array->UsedLength < Array->AllocLength / 4) {
        //
        // Shrink
        //
        uint32_t NewAllocLength = Array->AllocLength / 2;
        QUIC_SUBRANGE* NewSubRanges;
        if (NewAllocLength == QUIC_RANGE_INITIAL_SUB_COUNT) {
            NewSubRanges = Array->PreAllocSubRanges;
        } else {
            NewSubRanges =
                CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_SUBRANGE) * NewAllocLength, QUIC_POOL_RANGE);
            if (NewSubRanges == NULL) {
                return FALSE;
            }
        }
        memcpy(
            NewSubRanges,
            Array->SubRanges,
            Array->UsedLength * sizeof(QUIC_SUBRANGE));
        CXPLAT_FREE(Array->SubRanges, QUIC_POOL_RANGE);
        Array->SubRanges = NewSubRanges;
        Array->AllocLength = NewAllocLength;
        return TRUE;
    }

    return FALSE;
}

//
// Doubles the allocation and leaves a new logical slot at NextIndex while
// copying the existing records around that slot.
//
static
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeArrayGrow(
    _Inout_ QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t MaxAllocSize,
    _In_ uint32_t NextIndex
    )
{
    if (Array->AllocLength == QUIC_MAX_RANGE_ALLOC_SIZE) {
        return FALSE; // Can't grow any more.
    }

    uint32_t NewAllocLength = Array->AllocLength << 1; // Grow by a factor of 2.
    uint32_t NewAllocSize = NewAllocLength * sizeof(QUIC_SUBRANGE);
    CXPLAT_FRE_ASSERTMSG(NewAllocSize > sizeof(QUIC_SUBRANGE), "Range alloc arithmetic underflow.");
    if (NewAllocSize > MaxAllocSize) {
        //
        // Don't log anything as this will be the common case after we hit the
        // cap. For instance, after receiving lots of packets.
        //
        return FALSE;
    }

    QUIC_SUBRANGE* NewSubRanges = CXPLAT_ALLOC_NONPAGED(NewAllocSize, QUIC_POOL_RANGE);
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

    CXPLAT_DBG_ASSERT(Array->SubRanges != 0);
    if (NextIndex == 0) {
        memcpy(
            NewSubRanges + 1,
            Array->SubRanges,
            Array->UsedLength * sizeof(QUIC_SUBRANGE));
    } else if (NextIndex == Array->UsedLength) {
        memcpy(
            NewSubRanges,
            Array->SubRanges,
            Array->UsedLength * sizeof(QUIC_SUBRANGE));
    } else {
        memcpy(
            NewSubRanges,
            Array->SubRanges,
            NextIndex * sizeof(QUIC_SUBRANGE));
        memcpy(
            NewSubRanges + NextIndex + 1,
            Array->SubRanges + NextIndex,
            (Array->UsedLength - NextIndex) * sizeof(QUIC_SUBRANGE));
    }

    if (Array->SubRanges != Array->PreAllocSubRanges) {
        CXPLAT_FREE(Array->SubRanges, QUIC_POOL_RANGE);
    }
    Array->SubRanges = NewSubRanges;
    Array->AllocLength = NewAllocLength;
    Array->UsedLength++; // For the next write index.

    return TRUE;
}

//
// Reserves one array record at Index. Capped arrays retain their existing
// behavior of aging out the lowest record when growth is unavailable.
//
static
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeArrayMakeSpace(
    _Inout_ QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t MaxAllocSize,
    _Inout_ uint32_t* Index
    )
{
    CXPLAT_DBG_ASSERT(*Index <= Array->UsedLength);

    if (Array->UsedLength == Array->AllocLength) {
        if (!QuicRangeArrayGrow(Array, MaxAllocSize, *Index)) {
            //
            // We either can't or aren't allowed to grow any more. If we weren't
            // trying to append to the front, age out the smallest values to
            // make room for a new larger one.
            //
            if (MaxAllocSize == QUIC_MAX_RANGE_ALLOC_SIZE ||
                *Index == 0) {
                return NULL;
            }

            if (*Index > 1) {
                memmove(
                    Array->SubRanges,
                    Array->SubRanges + 1,
                    (*Index - 1) * sizeof(QUIC_SUBRANGE));
            }
            (*Index)--; // Actually going to be inserting 1 before where requested.
        }
    } else {
        CXPLAT_DBG_ASSERT(Array->SubRanges != 0);
        if (*Index == 0) {
            memmove(
                Array->SubRanges + 1,
                Array->SubRanges,
                Array->UsedLength * sizeof(QUIC_SUBRANGE));
        } else if (*Index == Array->UsedLength) {
            //
            // No need to copy. Appending to the end.
            //
        } else {
            memmove(
                Array->SubRanges + *Index + 1,
                Array->SubRanges + *Index,
                (Array->UsedLength - *Index) * sizeof(QUIC_SUBRANGE));
        }
        Array->UsedLength++; // For the new write.
    }

    return Array->SubRanges + *Index;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeArrayInsert(
    _Inout_ QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t MaxAllocSize,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    )
{
    QUIC_SUBRANGE* Sub =
        QuicRangeArrayMakeSpace(
            Array,
            MaxAllocSize,
            &Index);
    if (Sub != NULL) {
        Sub->Low = Low;
        Sub->Count = Count;
    }
    return Sub;
}
