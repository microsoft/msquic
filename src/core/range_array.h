/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "range_subrange.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define QUIC_RANGE_INITIAL_SUB_COUNT 8

typedef struct QUIC_RANGE_ARRAY {

    //
    // Array-backed subrange storage.
    //
    _Field_size_(AllocLength)
    QUIC_SUBRANGE* SubRanges;

    //
    // The number of currently used subranges.
    //
    uint32_t UsedLength;

    //
    // The number of allocated subranges.
    //
    _Field_range_(1, QUIC_MAX_RANGE_ALLOC_SIZE)
    uint32_t AllocLength;

    //
    // Allocates the initial subranges along with the array descriptor.
    //
    QUIC_SUBRANGE PreAllocSubRanges[QUIC_RANGE_INITIAL_SUB_COUNT];

} QUIC_RANGE_ARRAY;

QUIC_INLINE
uint32_t
QuicRangeArraySize(
    _In_ const QUIC_RANGE_ARRAY* Array
    )
{
    return Array->UsedLength;
}

QUIC_INLINE
QUIC_SUBRANGE*
QuicRangeArrayGet(
    _In_ const QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t Index
    )
{
    CXPLAT_DBG_ASSERT(Index < Array->UsedLength);
    return &Array->SubRanges[Index];
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeArrayInitialize(
    _Out_ QUIC_RANGE_ARRAY* Array
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeArrayUninitialize(
    _In_ QUIC_RANGE_ARRAY* Array
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRangeArrayReset(
    _Inout_ QUIC_RANGE_ARRAY* Array
    );

//
// Removes Count records beginning at Index and shrinks underused allocations.
// Returns TRUE when retained records move to a different backing allocation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRangeArrayRemoveSubranges(
    _Inout_ QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t Index,
    _In_ uint32_t Count
    );

//
// Inserts one initialized subrange into array storage.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SUBRANGE*
QuicRangeArrayInsert(
    _Inout_ QUIC_RANGE_ARRAY* Array,
    _In_ uint32_t MaxAllocSize,
    _In_ uint32_t Index,
    _In_ uint64_t Low,
    _In_ uint64_t Count
    );

#if defined(__cplusplus)
}
#endif
