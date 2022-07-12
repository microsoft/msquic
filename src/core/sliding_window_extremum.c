/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
SLIDING_WINDOW_EXTREMUM
SlidingWindowExtremumInitialize(
    _In_ uint64_t EntryLifetime,
    _In_ uint32_t WindowCapacity,
    _In_ SLIDING_WINDOW_EXTREMUM_ENTRY* Window
    )
{
    SLIDING_WINDOW_EXTREMUM w;
    
    CXPLAT_DBG_ASSERT(WindowCapacity > 0);
    CXPLAT_DBG_ASSERT(EntryLifetime > 0);

    w.EntryLifetime = EntryLifetime;
    w.WindowCapacity = WindowCapacity;

    w.WindowSize = 0;
    w.WindowHead = 0;
    w.Window = Window;

    return w;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
SlidingWindowExtremumGet(
    _In_ const SLIDING_WINDOW_EXTREMUM* w,
    _Inout_ SLIDING_WINDOW_EXTREMUM_ENTRY* Entry
    )
{
    if (w->WindowSize != 0) {
        *Entry = w->Window[w->WindowHead];
        return QUIC_STATUS_SUCCESS;
    }
    
    return QUIC_STATUS_NOT_FOUND;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumReset(
    _In_ SLIDING_WINDOW_EXTREMUM* w
    )
{
    w->WindowSize = 0;
    w->WindowHead = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumExpire(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewTime
    )
{
    while (w->WindowSize > 0) {
        CXPLAT_DBG_ASSERT(NewTime >= w->Window[w->WindowHead].Time);

        if (NewTime - w->Window[w->WindowHead].Time > w->EntryLifetime) {
            w->WindowHead = (w->WindowHead + 1) % w->WindowCapacity;
            w->WindowSize--;
        } else {
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumUpdateMin(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    )
{
    SlidingWindowExtremumExpire(w, NewTime);

    while (w->WindowSize > 0) {
        uint32_t WindowRear = (w->WindowHead + w->WindowSize - 1) % w->WindowCapacity;

        CXPLAT_DBG_ASSERT(NewTime >= w->Window[WindowRear].Time);

        if (NewTime - w->Window[WindowRear].Time > w->EntryLifetime ||
            NewValue <= w->Window[WindowRear].Value) {
            w->WindowSize--;
        } else {
            break;
        }
    }

    if (w->WindowSize < w->WindowCapacity) {
        uint32_t WindowRear = (w->WindowHead + w->WindowSize - 1) % w->WindowCapacity;

        w->Window[WindowRear].Value = NewValue;
        w->Window[WindowRear].Time = NewTime;

        w->WindowSize++;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SlidingWindowExtremumUpdateMax(
    _In_ SLIDING_WINDOW_EXTREMUM* w,
    _In_ uint64_t NewValue,
    _In_ uint64_t NewTime
    )
{
    SlidingWindowExtremumExpire(w, NewTime);

    while (w->WindowSize > 0) {
        uint32_t WindowRear = (w->WindowHead + w->WindowSize - 1) % w->WindowCapacity;

        CXPLAT_DBG_ASSERT(NewTime >= w->Window[WindowRear].Time);

        if (NewTime - w->Window[WindowRear].Time > w->EntryLifetime ||
            NewValue >= w->Window[WindowRear].Value) {
            w->WindowSize--;
        } else {
            break;
        }
    }

    if (w->WindowSize < w->WindowCapacity) {
        uint32_t WindowRear = (w->WindowHead + w->WindowSize - 1) % w->WindowCapacity;

        w->Window[WindowRear].Value = NewValue;
        w->Window[WindowRear].Time = NewTime;

        w->WindowSize++;
    }
}