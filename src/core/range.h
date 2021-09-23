/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

#define QUIC_RANGE_NO_MAX_ALLOC_SIZE    UINT32_MAX
#define QUIC_RANGE_USE_BINARY_SEARCH    1

#define QUIC_RANGE_INITIAL_SUB_COUNT    8

typedef struct QUIC_SUBRANGE {

    uint64_t Low;
    uint64_t Count;

} QUIC_SUBRANGE;

CXPLAT_STATIC_ASSERT(IS_POWER_OF_TWO(sizeof(QUIC_SUBRANGE)), L"Must be power of two");

typedef struct QUIC_RANGE_SEARCH_KEY {

    uint64_t Low;
    uint64_t High;

} QUIC_RANGE_SEARCH_KEY;

//
// Returns the largest value in a subrange.
//
inline
uint64_t
QuicRangeGetHigh(
    _In_ const QUIC_SUBRANGE* const Sub
    )
{
    return Sub->Low + Sub->Count - 1;
}

typedef struct QUIC_RANGE {

    //
    // Array of subranges that represent the set of intervals.
    //
    _Field_size_(AllocLength)
    QUIC_SUBRANGE* SubRanges;

    //
    // The number of currently used subranges in the 'SubRanges' array.
    //
    uint32_t UsedLength;

    //
    // The number of allocated subranges in the 'SubRanges' array.
    //
    _Field_range_(1, QUIC_MAX_RANGE_ALLOC_SIZE)
    uint32_t AllocLength;

    //
    // The maximum allocation byte count for the 'SubRanges' array.
    //
    _Field_range_(sizeof(QUIC_SUBRANGE), sizeof(QUIC_SUBRANGE) * QUIC_MAX_RANGE_ALLOC_SIZE)
    uint32_t MaxAllocSize;

    //
    // Allocates a number of subranges along with the parent object.
    //
    QUIC_SUBRANGE PreAllocSubRanges[QUIC_RANGE_INITIAL_SUB_COUNT];

} QUIC_RANGE;

//
// Returns the number of subranges in the range.
//
inline
uint32_t
QuicRangeSize(
    _In_ const QUIC_RANGE * const Range
    )
{
    return Range->UsedLength;
}

//
// Accessor function for a subrange at a given index.
//
inline
QUIC_SUBRANGE*
QuicRangeGet(
    _In_ const QUIC_RANGE * const Range,
    _In_ uint32_t Index
    )
{
    return &Range->SubRanges[Index];
}

//
// Accessor function for a subrange at a given index. Validates 'Index' is in
// the valid range, otherwise returns NULL.
//
inline
QUIC_SUBRANGE*
QuicRangeGetSafe(
    _In_ const QUIC_RANGE * const Range,
    _In_ uint32_t Index
    )
{
    return Index < QuicRangeSize(Range) ? &Range->SubRanges[Index] : NULL;
}

//
// Returns 0 if the Key overlaps the subrange.
// Returns -1 if the Key is less than the subrange.
// Returns 1 if the Key is greater than the subrange.
//
inline
int
QuicRangeCompare(
    const QUIC_RANGE_SEARCH_KEY* Key,
    const QUIC_SUBRANGE* Sub
    )
{
    if (Key->High < Sub->Low) {
        return -1;
    }
    if (QuicRangeGetHigh(Sub) < Key->Low) {
        return 1;
    }
    return 0;
}

//
// The design for the search functions is that when a negative number is
// returned it indicates the range wasn't found. Additionally, the number can
// be used to determine where the value would be inserted if wanted. Positive
// values then indicates the index of the subrange that matches the search.
//

#define IS_FIND_INDEX(i)                (i >= 0)
#define IS_INSERT_INDEX(i)              (i < 0)
#define FIND_INDEX_TO_INSERT_INDEX(i)   (-((int)(i)) - 1)
#define INSERT_INDEX_TO_FIND_INDEX(i)   (uint32_t)(-((i) + 1))

#if QUIC_RANGE_USE_BINARY_SEARCH

//
// O(log(n))
// Does a binary search to find *a* subrange that overlaps the search key passed
// into the function. There is no guarentee which subrange is returned if
// multiple overlap the search.
//
inline
int
QuicRangeSearch(
    _In_ const QUIC_RANGE* Range,
    _In_ const QUIC_RANGE_SEARCH_KEY* Key
    )
{
    uint32_t Num = Range->UsedLength;
    uint32_t Lo = 0;
    uint32_t Hi = Range->UsedLength - 1;
    uint32_t Mid = 0;
    int Result = 0;

    while (Lo <= Hi) {
        uint32_t Half;
        if ((Half = Num / 2) != 0) {
            Mid = Lo + ((Num & 1) ? Half : (Half - 1));
            if ((Result = QuicRangeCompare(Key, QuicRangeGet(Range, Mid))) == 0) {
                return (int)Mid;
            } else if (Result < 0) {
                Hi = Mid - 1;
                Num = (Num & 1) ? Half : Half-1;
            } else {
                Lo = Mid + 1;
                Num = Half;
            }
        } else if (Num) {
            if ((Result = QuicRangeCompare(Key, QuicRangeGet(Range, Lo))) == 0) {
                return (int)Lo;
            } else if (Result < 0) {
                return FIND_INDEX_TO_INSERT_INDEX(Lo);
            } else {
                return FIND_INDEX_TO_INSERT_INDEX(Lo + 1);
            }
        } else {
            break;
        }
    }

    return
        Result > 0 ?
            FIND_INDEX_TO_INSERT_INDEX(Mid + 1) :
            FIND_INDEX_TO_INSERT_INDEX(Mid);
}

#else

//
// O(n)
// Does a reverse linear search to find the largest subrange that overlaps the
// search key passed into the function.
//
inline
int
QuicRangeSearch(
    _In_ const QUIC_RANGE* Range,
    _In_ const QUIC_RANGE_SEARCH_KEY* Key
    )
{
    int Result;
    uint32_t i;
    for (i = QuicRangeSize(Range); i > 0; i--) {
        QUIC_SUBRANGE* Sub = QuicRangeGet(Range, i - 1);
        if ((Result = QuicRangeCompare(Key, Sub)) == 0) {
            return (int)(i - 1);
        } else if (Result > 0) {
            break;
        }
    }
    return FIND_INDEX_TO_INSERT_INDEX(i);
}

#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeInitialize(
    _In_ uint32_t MaxAllocSize,
    _Out_ QUIC_RANGE* Range
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeUninitialize(
    _In_ QUIC_RANGE* Range
    );

//
// Removes all values and resets the range back to initial state.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeReset(
    _Inout_ QUIC_RANGE* Range
    );

//
// O(n)      when QUIC_RANGE_USE_BINARY_SEARCH == 0
// O(log(n)) when QUIC_RANGE_USE_BINARY_SEARCH == 1
// Returns FALSE if "low" is not inserted. Otherwise, returns TRUE and the
// count of contiguous inserted values starting with "low," and sets
// IsLastRange to TRUE if this contiguous subrange has the largest inserted
// element.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetRange(
    _In_ QUIC_RANGE* Range,
    _In_ uint64_t Low,
    _Out_ uint64_t* Count,
    _Out_ BOOLEAN* IsLastRange
    );

//
// O(n)      when QUIC_RANGE_USE_BINARY_SEARCH == 0
// O(log(n)) when QUIC_RANGE_USE_BINARY_SEARCH == 1
// Inserts a single value. Returns TRUE if successful or FALSE on an
// allocation failure.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeAddValue(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t Value
    );

//
// O(n)      when QUIC_RANGE_USE_BINARY_SEARCH == 0
// O(log(n)) when QUIC_RANGE_USE_BINARY_SEARCH == 1
// Adds a range of contiguous values. Returns the updated subrange if
// successful or NULL on an allocation failure.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeAddRange(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t LowValue,
    _In_ uint64_t Count,
    _Out_ BOOLEAN* RangeUpdated
    );

//
// Removes a number of subranges from the range. Returns TRUE if the list was
// shrunk (reallocated) because of the removal operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeRemoveSubranges(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    );

//
// O(n) Removes a range of values from the range object. Returns TRUE if
// successful or FALSE on an allocation failure.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeRemoveRange(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t LowValue,
    _In_ uint64_t Count
    );

//
// Drops all values in the range below the input value.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeSetMin(
    _Inout_ QUIC_RANGE* Range,
    _In_ uint64_t Low
    );

//
// O(1) Returns the minimum value in the range. Function assumes there are
// values in the range. Function is unsafe to call if the caller isn't positive
// there are values in the range.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRangeGetMin(
    _In_ QUIC_RANGE* Range
    );

//
// O(1) Returns the minimum value in the range. Returns FALSE if the range
// doesn't contain any values.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetMinSafe(
    _In_ QUIC_RANGE* Range,
    _Out_ uint64_t* Value
    );

//
// O(1) Returns the maximum value in the range. Function assumes there are
// values in the range. Function is unsafe to call if the caller isn't positive
// there are values in the range.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRangeGetMax(
    _In_ QUIC_RANGE* Range
    );

//
// O(1) Returns the maximum value in the range. Returns FALSE if the range
// doesn't contain any values.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRangeGetMaxSafe(
    _In_ QUIC_RANGE* Range,
    _Out_ uint64_t* Value
    );

#if defined(__cplusplus)
}
#endif
