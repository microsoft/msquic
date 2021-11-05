/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_CONNECTION QUIC_CONNECTION;

typedef struct QUIC_TIMER_WHEEL {

    //
    // The expiration time (in us) for the next timer in the timer wheel.
    //
    uint64_t NextExpirationTime;

    //
    // Total number of connections in the timer wheel.
    //
    uint64_t ConnectionCount;

    //
    // The connection with the timer that expires next.
    //
    QUIC_CONNECTION* NextConnection;

    //
    // The number of slots in the Slots array.
    //
    uint32_t SlotCount;

    //
    // An array of slots in the timer wheel.
    //
    CXPLAT_LIST_ENTRY* Slots;

} QUIC_TIMER_WHEEL;

//
// Initializes the timer wheel's internal structure.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTimerWheelInitialize(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel
    );

//
// Cleans up the timer wheel.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelUninitialize(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel
    );

//
// Removes the connection from the timer wheel.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelRemoveConnection(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel,
    _Inout_ QUIC_CONNECTION* Connection
    );

//
// Inserts, removes, or moves the connection in the timer wheel. Called
// when the connection's timer state changes.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelUpdateConnection(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel,
    _Inout_ QUIC_CONNECTION* Connection
    );

//
// Gets the next connection with an expired timer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTimerWheelGetExpired(
    _Inout_ QUIC_TIMER_WHEEL* TimerWheel,
    _In_ uint64_t TimeNow,
    _Inout_ CXPLAT_LIST_ENTRY* ListHead
    );
