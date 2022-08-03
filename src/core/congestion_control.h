/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "cubic.h"

typedef struct QUIC_ACK_EVENT {

    uint64_t TimeNow; // microsecond

    uint64_t LargestPacketNumberAcked;

    uint32_t NumRetransmittableBytes;

    uint32_t SmoothedRtt;

} QUIC_ACK_EVENT;

typedef struct QUIC_LOSS_EVENT {

    uint64_t LargestPacketNumberLost;

    uint64_t LargestPacketNumberSent;

    uint32_t NumRetransmittableBytes;

    BOOLEAN PersistentCongestion : 1;

} QUIC_LOSS_EVENT;

typedef struct QUIC_CONGESTION_CONTROL {

    //
    // Name of congestion control algorithm
    //
    const char* Name;

    BOOLEAN (*QuicCongestionControlCanSend)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
        );

    void (*QuicCongestionControlSetExemption)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint8_t NumPackets
        );

    void (*QuicCongestionControlReset)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ BOOLEAN FullReset
        );

    uint32_t (*QuicCongestionControlGetSendAllowance)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint64_t TimeSinceLastSend,
        _In_ BOOLEAN TimeSinceLastSendValid
        );

    void (*QuicCongestionControlOnDataSent)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint32_t NumRetransmittableBytes
        );

    BOOLEAN (*QuicCongestionControlOnDataInvalidated)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint32_t NumRetransmittableBytes
        );

    BOOLEAN (*QuicCongestionControlOnDataAcknowledged)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ const QUIC_ACK_EVENT* AckEvent
        );

    void (*QuicCongestionControlOnDataLost)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ const QUIC_LOSS_EVENT* LossEvent
        );

    BOOLEAN (*QuicCongestionControlOnSpuriousCongestionEvent)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
        );

    void (*QuicCongestionControlLogOutFlowStatus)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    uint8_t (*QuicCongestionControlGetExemptions)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    uint32_t (*QuicCongestionControlGetBytesInFlightMax)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    uint32_t (*QuicCongestionControlGetCongestionWindow)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    //
    // Algorithm specific state.
    //
    union {
        QUIC_CONGESTION_CONTROL_CUBIC Cubic;
    };

} QUIC_CONGESTION_CONTROL;

//
// Initializes the algorithm specific congestion control algorithm.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );

//
// Returns TRUE if more bytes can be sent on the network.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlCanSend(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->QuicCongestionControlSetExemption(Cc, NumPackets);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    Cc->QuicCongestionControlReset(Cc, FullReset);
}

//
// Returns the number of bytes that can be sent immediately.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    return Cc->QuicCongestionControlGetSendAllowance(Cc, TimeSinceLastSend, TimeSinceLastSendValid);
}

//
// Called when any retransmittable data is sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    Cc->QuicCongestionControlOnDataSent(Cc, NumRetransmittableBytes);
}

//
// Called when any data needs to be removed from inflight but cannot be
// considered lost or acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    return Cc->QuicCongestionControlOnDataInvalidated(Cc, NumRetransmittableBytes);
}

//
// Called when any data is acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    return Cc->QuicCongestionControlOnDataAcknowledged(Cc, AckEvent);
}

//
// Called when data is determined lost.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    Cc->QuicCongestionControlOnDataLost(Cc, LossEvent);
}

//
// Called when all recently considered lost data was actually acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlOnSpuriousCongestionEvent(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint8_t
QuicCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetExemptions(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->QuicCongestionControlLogOutFlowStatus(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicCongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetBytesInFlightMax(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicCongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetCongestionWindow(Cc);
}
