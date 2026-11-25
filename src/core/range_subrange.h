/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_SUBRANGE {

    uint64_t Low;
    uint64_t Count;

} QUIC_SUBRANGE;

CXPLAT_STATIC_ASSERT(IS_POWER_OF_TWO(sizeof(QUIC_SUBRANGE)), "Must be power of two");

//
// Returns the largest value in a subrange.
//
QUIC_INLINE
uint64_t
QuicRangeGetHigh(
    _In_ const QUIC_SUBRANGE* const Sub
    )
{
    return Sub->Low + Sub->Count - 1;
}

#if defined(__cplusplus)
}
#endif
