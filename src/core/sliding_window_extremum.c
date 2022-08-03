/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The following functions implement a sliding window extremum (either maxima
    or minima) algorithm for MsQuic. The design is based on a well-known data
    structure called "monotone queue".

    Since the queue is monotonic, we can easily access the extremum element by
    looking at the first element. Adding new element will sweep out
    older elements which value is greater/less than equal to the new element,
    along with the elements which is expired.
    
    If there are more elements comparing to the capacity of queue, the
    algorithm will still work but the accuracy will be compromised.

--*/


#include "precomp.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_SLIDING_WINDOW_EXTREMUM
QuicSlidingWindowExtremumInitialize(
    _In_ uint64_t EntryLifetime,
    _In_ uint32_t WindowCapacity,
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY* Entries
    )
{
    QUIC_SLIDING_WINDOW_EXTREMUM Window;
    
    CXPLAT_DBG_ASSERT(WindowCapacity > 0);
    CXPLAT_DBG_ASSERT(EntryLifetime > 0);

    Window.EntryLifetime = EntryLifetime;
    Window.WindowCapacity = WindowCapacity;

    Window.WindowSize = 0;
    Window.WindowHead = 0;
    Window.Extremums = Entries;

    return Window;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSlidingWindowExtremumGet(
    _In_ const QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _Inout_ QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY* Entry
    )
{
    if (Window->WindowSize != 0) {
        *Entry = Window->Extremums[Window->WindowHead];
        return QUIC_STATUS_SUCCESS;
    }
    
    return QUIC_STATUS_NOT_FOUND;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSlidingWindowExtremumReset(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window
    )
{
    Window->WindowSize = 0;
    Window->WindowHead = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumExpire(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _In_ uint64_t NewTime
    )
{
    while (Window->WindowSize > 0) {
        CXPLAT_DBG_ASSERT(NewTime >= Window->Extremums[Window->WindowHead].Time);

        if (NewTime - Window->Extremums[Window->WindowHead].Time > Window->EntryLifetime) {
            Window->WindowHead = (Window->WindowHead + 1) % Window->WindowCapacity;
            Window->WindowSize--;
        } else {
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSlidingWindowExtremumUpdateMin(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    )
{
    if (Window->WindowSize > 0) {
        uint32_t WindowRear = (Window->WindowHead + Window->WindowSize - 1) % Window->WindowCapacity;
        if (NewTime < Window->Extremums[WindowRear].Time) {
            return;
        }

        SlidingWindowExtremumExpire(Window, NewTime);
    }

    while (Window->WindowSize > 0) {
        uint32_t WindowRear = (Window->WindowHead + Window->WindowSize - 1) % Window->WindowCapacity;

        CXPLAT_DBG_ASSERT(NewTime >= Window->Extremums[WindowRear].Time);

        if (NewTime - Window->Extremums[WindowRear].Time > Window->EntryLifetime ||
            NewValue <= Window->Extremums[WindowRear].Value) {
            Window->WindowSize--;
        } else {
            break;
        }
    }

    if (Window->WindowSize < Window->WindowCapacity) {
        uint32_t NewRear = (Window->WindowHead + Window->WindowSize) % Window->WindowCapacity;

        Window->Extremums[NewRear].Value = NewValue;
        Window->Extremums[NewRear].Time = NewTime;

        Window->WindowSize++;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSlidingWindowExtremumUpdateMax(
    _In_ QUIC_SLIDING_WINDOW_EXTREMUM* Window,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    )
{
    if (Window->WindowSize > 0) {
        uint32_t WindowRear = (Window->WindowHead + Window->WindowSize - 1) % Window->WindowCapacity;
        if (NewTime < Window->Extremums[WindowRear].Time) {
            return;
        }

        SlidingWindowExtremumExpire(Window, NewTime);
    }

    while (Window->WindowSize > 0) {
        uint32_t WindowRear = (Window->WindowHead + Window->WindowSize - 1) % Window->WindowCapacity;

        CXPLAT_DBG_ASSERT(NewTime >= Window->Extremums[WindowRear].Time);

        if (NewTime - Window->Extremums[WindowRear].Time > Window->EntryLifetime ||
            NewValue >= Window->Extremums[WindowRear].Value) {
            Window->WindowSize--;
        } else {
            break;
        }
    }

    if (Window->WindowSize < Window->WindowCapacity) {
        uint32_t NewRear = (Window->WindowHead + Window->WindowSize) % Window->WindowCapacity;

        Window->Extremums[NewRear].Value = NewValue;
        Window->Extremums[NewRear].Time = NewTime;

        Window->WindowSize++;
    }
}
