/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.
    
--*/

#pragma once

// TODO[wizmann]: add some test for the data structure

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

    SLIDING_WINDOW_EXTREMUM_ENTRY* Window;

} SLIDING_WINDOW_EXTREMUM;

_IRQL_requires_max_(DISPATCH_LEVEL)
SLIDING_WINDOW_EXTREMUM
SlidingWindowExtremumInitialize(
    _In_ uint64_t EntryLifetime,
    _In_ uint32_t WindowCapacity,
    _In_ SLIDING_WINDOW_EXTREMUM_ENTRY* Window
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
SlidingWindowExtremumGet(
    _In_ const SLIDING_WINDOW_EXTREMUM* w,
    _Inout_ SLIDING_WINDOW_EXTREMUM_ENTRY* Entry
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumReset(
    _In_ SLIDING_WINDOW_EXTREMUM* w
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumUpdateMin(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumUpdateMax(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    );