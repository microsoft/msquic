/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
    
--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct SLIDING_WINDOW_EXTREMUM_ENTRY {

    uint64_t Value;

    uint64_t Time;

} SLIDING_WINDOW_EXTREMUM_ENTRY;


typedef struct SLIDING_WINDOW_EXTREMUM {

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
    SLIDING_WINDOW_EXTREMUM_ENTRY* Window;

} SLIDING_WINDOW_EXTREMUM;

//
// Initializes the sliding window's internal structure
//
_IRQL_requires_max_(DISPATCH_LEVEL)
SLIDING_WINDOW_EXTREMUM
SlidingWindowExtremumInitialize(
    _In_ uint64_t EntryLifetime,
    _In_ uint32_t WindowCapacity,
    _In_ SLIDING_WINDOW_EXTREMUM_ENTRY* Window
    );

//
// Resets the sliding windows' internal structure
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumReset(
    _In_ SLIDING_WINDOW_EXTREMUM* w
    );

//
// Gets the extremum element from sliding window
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
SlidingWindowExtremumGet(
    _In_ const SLIDING_WINDOW_EXTREMUM* w,
    _Inout_ SLIDING_WINDOW_EXTREMUM_ENTRY* Entry
    );

//
// Updates a new value to the sliding window and maintains the **minima** of the window  
//
// Do not mix SlidingWindowExtremumUpdateMin and SlidingWindowExtremumUpdateMax
// function with same SlidingWindowExtremum instance.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumUpdateMin(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    );

//
// Updates a new value to the sliding window and maintains the **maxima** of the window  
//
// Do not mix SlidingWindowExtremumUpdateMin and SlidingWindowExtremumUpdateMax
// functions with same SlidingWindowExtremum instance.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumUpdateMax(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    );

#if defined(__cplusplus)
}
#endif
