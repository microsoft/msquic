/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Platform definitions.

Supported Environments:

    Windows user mode
    Windows kernel mode
    Linux user mode

--*/

#pragma once

#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

//
// Time unit conversion.
//
#define NS_TO_US(x)     ((x) / 1000)
#define US_TO_NS(x)     ((x) * 1000)
#define NS100_TO_US(x)  ((x) / 10)
#define US_TO_NS100(x)  ((x) * 10)
#define MS_TO_NS100(x)  ((x)*10000)
#define NS100_TO_MS(x)  ((x)/10000)
#define US_TO_MS(x)     ((x) / 1000)
#define MS_TO_US(x)     ((x) * 1000)
#define US_TO_S(x)      ((x) / (1000 * 1000))
#define S_TO_US(x)      ((x) * 1000 * 1000)
#define S_TO_NS(x)      ((x) * 1000 * 1000 * 1000)
#define MS_TO_S(x)      ((x) / 1000)
#define S_TO_MS(x)      ((x) * 1000)

#define QUIC_CONTAINING_RECORD(address, type, field) \
    ((type *)((uint8_t*)(address) - offsetof(type, field)))

typedef struct QUIC_LIST_ENTRY {
    struct QUIC_LIST_ENTRY* Flink;
    struct QUIC_LIST_ENTRY* Blink;
} QUIC_LIST_ENTRY;

typedef struct QUIC_SINGLE_LIST_ENTRY {
    struct QUIC_SINGLE_LIST_ENTRY* Next;
} QUIC_SINGLE_LIST_ENTRY;

#ifndef FORCEINLINE
#if (_MSC_VER >= 1200)
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE __inline
#endif
#endif

//
// Different pool tags used for marking allocations.
//

#define QUIC_POOL_GENERIC   'CIUQ'  // QUIC - Generic QUIC
#define QUIC_POOL_CONN      'noCQ'  // QCon - QUIC connection
#define QUIC_POOL_TP        'PTCQ'  // QCTP - QUIC connection transport parameters
#define QUIC_POOL_STREAM    'mtSQ'  // QStm - QUIC stream
#define QUIC_POOL_SBUF      'fBSQ'  // QSBf - QUIC stream buffer
#define QUIC_POOL_META      'MFSQ'  // QSFM - QUIC sent frame metedata
#define QUIC_POOL_DATA      'atDQ'  // QDta - QUIC datagram buffer
#define QUIC_POOL_TEST      'tsTQ'  // QTst - QUIC test code
#define QUIC_POOL_PERF      'frPQ'  // QPrf - QUIC perf code
#define QUIC_POOL_TOOL      'loTQ'  // QTol - QUIC tool code

typedef enum QUIC_THREAD_FLAGS {
    QUIC_THREAD_FLAG_NONE               = 0x0000,
    QUIC_THREAD_FLAG_SET_IDEAL_PROC     = 0x0001,
    QUIC_THREAD_FLAG_SET_AFFINITIZE     = 0x0002,
    QUIC_THREAD_FLAG_HIGH_PRIORITY      = 0x0004
} QUIC_THREAD_FLAGS;

#ifdef DEFINE_ENUM_FLAG_OPERATORS
DEFINE_ENUM_FLAG_OPERATORS(QUIC_THREAD_FLAGS);
#endif

#ifdef _KERNEL_MODE
#define QUIC_PLATFORM_TYPE 1
#include <quic_platform_winkernel.h>
#elif _WIN32
#define QUIC_PLATFORM_TYPE 2
#include <quic_platform_winuser.h>
#elif QUIC_PLATFORM_LINUX
#define QUIC_PLATFORM_TYPE 3
#include <quic_platform_linux.h>
#else
#define QUIC_PLATFORM_TYPE 0xFF
#error "Unsupported Platform"
#endif

#define QuicListEntryValidate(Entry) \
    QUIC_DBG_ASSERT( \
        (((Entry->Flink)->Blink) == Entry) && \
        (((Entry->Blink)->Flink) == Entry))

FORCEINLINE
void
QuicListInitializeHead(
    _Out_ QUIC_LIST_ENTRY* ListHead
    )
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

_Must_inspect_result_
FORCEINLINE
BOOLEAN
QuicListIsEmpty(
    _In_ const QUIC_LIST_ENTRY* ListHead
    )
{
    return (BOOLEAN)(ListHead->Flink == ListHead);
}

FORCEINLINE
void
QuicListInsertHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Out_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    QUIC_LIST_ENTRY* Flink = ListHead->Flink;
    Entry->Flink = Flink;
    Entry->Blink = ListHead;
    Flink->Blink = Entry;
    ListHead->Flink = Entry;
}

FORCEINLINE
void
QuicListInsertTail(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(ListHead);
    QUIC_LIST_ENTRY* Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

FORCEINLINE
QUIC_LIST_ENTRY*
QuicListRemoveHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead
    )
{
    QuicListEntryValidate(ListHead);
    QUIC_LIST_ENTRY* Entry = ListHead->Flink;
    QUIC_LIST_ENTRY* Flink = Entry->Flink;
    ListHead->Flink = Flink;
    Flink->Blink = ListHead;
    return Entry;
}

FORCEINLINE
BOOLEAN
QuicListEntryRemove(
    _In_ QUIC_LIST_ENTRY* Entry
    )
{
    QuicListEntryValidate(Entry);
    QUIC_LIST_ENTRY* Flink = Entry->Flink;
    QUIC_LIST_ENTRY* Blink = Entry->Blink;
    Blink->Flink = Flink;
    Flink->Blink = Blink;
    return (BOOLEAN)(Flink == Blink);
}

inline
void
QuicListMoveItems(
    _Inout_ QUIC_LIST_ENTRY* Source,
    _Inout_ QUIC_LIST_ENTRY* Destination
    )
{
    //
    // If there are items, copy them.
    //
    if (!QuicListIsEmpty(Source)) {

        if (QuicListIsEmpty(Destination)) {

            //
            // Copy the links of the Source.
            //
            Destination->Flink = Source->Flink;
            Destination->Blink = Source->Blink;

            //
            // Fix the item's links to point to new head.
            //
            Destination->Flink->Blink = Destination;
            Destination->Blink->Flink = Destination;

        } else {

            //
            // Fix Destination's current last item to point
            // to the first of Source.
            //
            Source->Flink->Blink = Destination->Blink;
            Destination->Blink->Flink = Source->Flink;

            //
            // Fix Destination's new last item to be the of Source's last item.
            //
            Source->Blink->Flink = Destination;
            Destination->Blink = Source->Blink;
        }

        //
        // Reset the Source to empty list.
        //
        QuicListInitializeHead(Source);
    }
}

FORCEINLINE
void
QuicListPushEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_SINGLE_LIST_ENTRY* Entry
    )
{
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

FORCEINLINE
QUIC_SINGLE_LIST_ENTRY*
QuicListPopEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead
    )
{
    QUIC_SINGLE_LIST_ENTRY* FirstEntry = ListHead->Next;
    if (FirstEntry != NULL) {
        ListHead->Next = FirstEntry->Next;
    }
    return FirstEntry;
}

#include "quic_hashtable.h"
#include "quic_toeplitz.h"
