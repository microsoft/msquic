/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The following functions along with the QuicConnTimer* ones in connection.c
    implement a custom timer wheel algorithm for MsQuic. The design takes
    advantage of the fact that each connection is 'owned' by a single worker
    at a time, and that worker already drives the execution, serially, for all
    those connections. Using this interface, the worker can also drive the
    expiration of all the timers that belong to those connections, removing the
    need for the platform to provide any timer implementation, and providing a
    more efficient total timer solution.

    The timer wheel consists of a few main parts:

        Connections - Each connection maintains its own internal array of all
        its timers. It only reports the soonest/next time to the timer wheel.
        The timer wheel itself doesn't care about anything other than that value
        from the connection.

        Slots - This is a very simple hash table of time slots. Each slot holds
        all connections with a next expiration time modulo the total slot count.

        Slot Entry - Each slot is made up of a sorted, doubly-linked list of
        connections.

        Next Expiration - Along with all the connections in the timer wheel, the
        timer wheel also explicitly keeps track of the next expiration time and
        connection for quick next delay calculations.

    With these parts, the timer wheel is able to support insertion, update and
    removal of any number of timers (and their associated connection).

    Insertion or update consists of getting the next expiration time from the
    connection, calculating the correct slot and then doing an insert into the
    slot's sorted list of connections. Additionally, the next expiration is
    updated if the new timer is the soonest to expire.

    Removal consists of removing the connection from the doubly-linked list and
    updating the timer wheel's next expiration if this connection was currently
    next to expire.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "timer_wheel.c.clog.h"
#endif

//
// The initial count of slots in the timer wheel.
//
#define QUIC_TIMER_WHEEL_INITIAL_SLOT_COUNT     32

//
// On average, the max number of connections per slot.
//
#define QUIC_TIMER_WHEEL_MAX_LOAD_FACTOR    32

//
// Helper to get the slot index for a given time.
//
#define TIME_TO_SLOT_INDEX(TimerWheel, TimeUs) \
    ((US_TO_MS(TimeUs) / 1000) % TimerWheel->SlotCount)

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTimerWheelInitialize(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel
    )
{
    TimerWheel->NextExpirationTime = UINT64_MAX;
    TimerWheel->ConnectionCount = 0;
    TimerWheel->NextConnection = NULL;
    TimerWheel->SlotCount = QUIC_TIMER_WHEEL_INITIAL_SLOT_COUNT;
    TimerWheel->Slots =
        QUIC_ALLOC_NONPAGED(QUIC_TIMER_WHEEL_INITIAL_SLOT_COUNT * sizeof(QUIC_LIST_ENTRY));
    if (TimerWheel->Slots == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "timerwheel slots",
            QUIC_TIMER_WHEEL_INITIAL_SLOT_COUNT * sizeof(QUIC_LIST_ENTRY));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    for (uint32_t i = 0; i < TimerWheel->SlotCount; ++i) {
        QuicListInitializeHead(&TimerWheel->Slots[i]);
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelUninitialize(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel
    )
{
    for (uint32_t i = 0; i < TimerWheel->SlotCount; ++i) {
        QUIC_LIST_ENTRY* ListHead = &TimerWheel->Slots[i];
        QUIC_LIST_ENTRY* Entry = ListHead->Flink;
        while (Entry != ListHead) {
            QUIC_CONNECTION* Connection =
                QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, TimerLink);
            QuicTraceLogConnWarning(
                StillInTimerWheel,
                Connection,
                "Still in timer wheel! Connection was likely leaked!");
            Entry = Entry->Blink;
        }
        QUIC_TEL_ASSERT(QuicListIsEmpty(&TimerWheel->Slots[i]));
    }
    QUIC_TEL_ASSERT(TimerWheel->ConnectionCount == 0);
    QUIC_TEL_ASSERT(TimerWheel->NextConnection == NULL);
    QUIC_TEL_ASSERT(TimerWheel->NextExpirationTime == UINT64_MAX);

    QUIC_FREE(TimerWheel->Slots);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelResize(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel
    )
{
    uint32_t NewSlotCount = TimerWheel->SlotCount * 2;
    if (NewSlotCount <= TimerWheel->SlotCount) {
        //
        // Max size has been reached.
        //
        return;
    }

    QUIC_LIST_ENTRY* NewSlots =
        QUIC_ALLOC_NONPAGED(NewSlotCount * sizeof(QUIC_LIST_ENTRY));
    if (NewSlots == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "timerwheel slots (realloc)",
            NewSlotCount * sizeof(QUIC_LIST_ENTRY));
        return;
    }

    QuicTraceLogVerbose(
        TimerWheelResize,
        "[time][%p] Resizing timer wheel (new slot count = %u).",
        TimerWheel,
        NewSlotCount);

    for (uint32_t i = 0; i < NewSlotCount; ++i) {
        QuicListInitializeHead(&NewSlots[i]);
    }

    uint32_t OldSlotCount = TimerWheel->SlotCount;
    QUIC_LIST_ENTRY* OldSlots = TimerWheel->Slots;

    TimerWheel->SlotCount = NewSlotCount;
    TimerWheel->Slots = NewSlots;

    for (uint32_t i = 0; i < OldSlotCount; ++i) {
        //
        // Iterate through each old slot, remove all connections and add them
        // to the new slots.
        //
        while (!QuicListIsEmpty(&OldSlots[i])) {
            QUIC_CONNECTION* Connection =
                QUIC_CONTAINING_RECORD(
                    QuicListRemoveHead(&OldSlots[i]),
                    QUIC_CONNECTION,
                    TimerLink);
            uint64_t ExpirationTime = QuicConnGetNextExpirationTime(Connection);
            uint32_t SlotIndex = TIME_TO_SLOT_INDEX(TimerWheel, ExpirationTime);

            //
            // Insert the connection into the slot, in the correct order. We search
            // the slot's list in reverse order, with the assumption that most new
            // timers will on average be later than existing ones.
            //
            QUIC_LIST_ENTRY* ListHead = &TimerWheel->Slots[SlotIndex];
            QUIC_LIST_ENTRY* Entry = ListHead->Blink;

            while (Entry != ListHead) {
                QUIC_CONNECTION* ConnectionEntry =
                    QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, TimerLink);
                uint64_t EntryExpirationTime = QuicConnGetNextExpirationTime(ConnectionEntry);

                if (ExpirationTime > EntryExpirationTime) {
                    break;
                }

                Entry = Entry->Blink;
            }

            //
            // Insert after the current entry.
            //
            QuicListInsertHead(Entry, &Connection->TimerLink);
        }
    }
}

//
// Called to update NextConnection and NextExpirationTime when the
// current NextConnection is updated.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelUpdate(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel
    )
{
    TimerWheel->NextExpirationTime = UINT64_MAX;
    TimerWheel->NextConnection = NULL;

    //
    // Loop over the slots to find the connection with the earliest
    // expiration time.
    //
    for (uint32_t i = 0; i < TimerWheel->SlotCount; ++i) {
        if (!QuicListIsEmpty(&TimerWheel->Slots[i])) {
            QUIC_CONNECTION* ConnectionEntry =
                QUIC_CONTAINING_RECORD(
                    TimerWheel->Slots[i].Flink,
                    QUIC_CONNECTION,
                    TimerLink);
            uint64_t EntryExpirationTime = QuicConnGetNextExpirationTime(ConnectionEntry);
            if (EntryExpirationTime < TimerWheel->NextExpirationTime) {
                TimerWheel->NextExpirationTime = EntryExpirationTime;
                TimerWheel->NextConnection = ConnectionEntry;
            }
        }
    }

    if (TimerWheel->NextConnection == NULL) {
        QuicTraceLogVerbose(
            TimerWheelNextExpirationNull,
            "[time][%p] Next Expiration = {NULL}.",
            TimerWheel);
    } else {
        QuicTraceLogVerbose(
            TimerWheelNextExpiration,
            "[time][%p] Next Expiration = {%llu, %p}.",
            TimerWheel,
            TimerWheel->NextExpirationTime,
            TimerWheel->NextConnection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelRemoveConnection(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel,
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->TimerLink.Flink != NULL) {
        //
        // If the connection was in the timer wheel, remove its entry in the
        // doubly-link list.
        //
        QuicTraceLogVerbose(
            TimerWheelRemoveConnection,
            "[time][%p] Removing Connection %p.",
            TimerWheel,
            Connection);
        QuicListEntryRemove(&Connection->TimerLink);
        Connection->TimerLink.Flink = NULL;
        TimerWheel->ConnectionCount--;

        if (Connection == TimerWheel->NextConnection) {
            QuicTimerWheelUpdate(TimerWheel);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelUpdateConnection(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel,
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    uint64_t ExpirationTime = QuicConnGetNextExpirationTime(Connection);

    if (Connection->TimerLink.Flink != NULL) {
        //
        // Connection is already in the timer wheel, so remove it first.
        //
        QuicListEntryRemove(&Connection->TimerLink);

        if (ExpirationTime == UINT64_MAX) {
            TimerWheel->ConnectionCount--;
        }

    } else {

        //
        // It wasn't in the wheel already, so we must be adding it to the
        // wheel.
        //
        if (ExpirationTime != UINT64_MAX) {
            TimerWheel->ConnectionCount++;
        }
    }

    if (ExpirationTime == UINT64_MAX) {
        //
        // No more timers left, go ahead and invalidate its link.
        //
        Connection->TimerLink.Flink = NULL;
        QuicTraceLogVerbose(
            TimerWheelRemoveConnection,
            "[time][%p] Removing Connection %p.",
            TimerWheel,
            Connection);

        if (Connection == TimerWheel->NextConnection) {
            QuicTimerWheelUpdate(TimerWheel);
        }

    } else {

        uint32_t SlotIndex = TIME_TO_SLOT_INDEX(TimerWheel, ExpirationTime);

        //
        // Insert the connection into the slot, in the correct order. We search
        // the slot's list in reverse order, with the assumption that most new
        // timers will on average be later than existing ones.
        //
        QUIC_LIST_ENTRY* ListHead = &TimerWheel->Slots[SlotIndex];
        QUIC_LIST_ENTRY* Entry = ListHead->Blink;

        while (Entry != ListHead) {
            QUIC_CONNECTION* ConnectionEntry =
                QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, TimerLink);
            uint64_t EntryExpirationTime = QuicConnGetNextExpirationTime(ConnectionEntry);

            if (ExpirationTime > EntryExpirationTime) {
                break;
            }

            Entry = Entry->Blink;
        }

        //
        // Insert after the current entry.
        //
        QuicListInsertHead(Entry, &Connection->TimerLink);

        QuicTraceLogVerbose(
            TimerWheelUpdateConnection,
            "[time][%p] Updating Connection %p.",
            TimerWheel,
            Connection);

        //
        // Make sure the next expiration time/connection is still correct.
        //
        if (ExpirationTime < TimerWheel->NextExpirationTime) {
            TimerWheel->NextExpirationTime = ExpirationTime;
            TimerWheel->NextConnection = Connection;
            QuicTraceLogVerbose(
                TimerWheelNextExpiration,
                "[time][%p] Next Expiration = {%llu, %p}.",
                TimerWheel,
                ExpirationTime,
                Connection);
        } else if (Connection == TimerWheel->NextConnection) {
            QuicTimerWheelUpdate(TimerWheel);
        }

        //
        // Resize the timer wheel if we have too many connections for the
        // current size.
        //
        if (TimerWheel->ConnectionCount >
            TimerWheel->SlotCount * QUIC_TIMER_WHEEL_MAX_LOAD_FACTOR) {
            QuicTimerWheelResize(TimerWheel);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
uint64_t
QuicTimerWheelGetWaitTime(
    _In_ QUIC_TIMER_WHEEL* TimerWheel
    )
{
    uint64_t Delay;
    if (TimerWheel->NextExpirationTime != UINT64_MAX) {
        uint64_t TimeNow = QuicTimeUs64();
        if (TimerWheel->NextExpirationTime <= TimeNow) {
            //
            // The next timer is already in the past. It needs to be processed
            // immediately.
            //
            Delay = 0;
        } else {
            //
            // Convert the absolute expiration time to a relative delay. Add one
            // to the delay to ensure we don't end up expiring our wait too
            // early.
            //
            Delay = US_TO_MS(TimerWheel->NextExpirationTime - TimeNow) + 1;
        }
    } else {
        //
        // No timers in the timer wheel currently.
        //
        Delay = UINT64_MAX;
    }
    return Delay;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelGetExpired(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel,
    _In_ uint64_t TimeNow,
    _Inout_ QUIC_LIST_ENTRY* OutputListHead
    )
{
    //
    // Iterate through every slot to find all the connections that now have
    // expired timers.
    //
    for (uint32_t i = 0; i < TimerWheel->SlotCount; ++i) {
        QUIC_LIST_ENTRY* ListHead = &TimerWheel->Slots[i];
        QUIC_LIST_ENTRY* Entry = ListHead->Flink;
        while (Entry != ListHead) {
            QUIC_CONNECTION* ConnectionEntry =
                QUIC_CONTAINING_RECORD(Entry, QUIC_CONNECTION, TimerLink);
            uint64_t EntryExpirationTime = QuicConnGetNextExpirationTime(ConnectionEntry);
            if (EntryExpirationTime > TimeNow) {
                break;
            }
            Entry = Entry->Flink;
            QuicListEntryRemove(&ConnectionEntry->TimerLink);
            QuicListInsertTail(OutputListHead, &ConnectionEntry->TimerLink);
            TimerWheel->ConnectionCount--;
        }
    }
}
