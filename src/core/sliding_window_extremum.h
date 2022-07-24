/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
    
--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY {

    uint64_t Value;

    uint64_t Time;

} QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY;


typedef struct QUIC_SLIDING_WINDOW_EXTREMUM {

    //
    // Lifetime of each entry
    //
    uint64_t EntryLifetime;

    //
    // Capcity of sliding window
    //
    uint32_t WindowCapacity;

    //
    // Current size of sliding window
    //
    uint32_t WindowSize;
    
    //
    // Head of the monotone queue
    //
    uint32_t WindowHead;

    //
    // Rotated monotone deque maintains the extremum of sliding window
    //
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY* Extremums;

} QUIC_SLIDING_WINDOW_EXTREMUM;

//
// Initializes the sliding window's internal structure
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_SLIDING_WINDOW_EXTREMUM
QuicSlidingWindowExtremumInitialize(
    _In_ uint64_t EntryLifetime,
    _In_ uint32_t WindowCapacity,
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY* Entries
    );

//
// Resets the sliding window's internal structure
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSlidingWindowExtremumReset(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window
    );

//
// Gets the extremum element from sliding window
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSlidingWindowExtremumGet(
    _In_ const QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _Inout_ QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY* Entry
    );

//
// Updates a new value to the sliding window and maintains the **minima** of the window  
//
// Do not mix QuicSlidingWindowExtremumUpdateMin and QuicSlidingWindowExtremumUpdateMax
// function with same SlidingWindowExtremum instance.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSlidingWindowExtremumUpdateMin(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    );

//
// Updates a new value to the sliding window and maintains the **maxima** of the window  
//
// Do not mix QuicSlidingWindowExtremumUpdateMin and QuicSlidingWindowExtremumUpdateMax
// functions with same SlidingWindowExtremum instance.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSlidingWindowExtremumUpdateMax(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    );

#if defined(__cplusplus)
}
#endif
