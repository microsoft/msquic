/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
typedef struct QUIC_CONGESTION_CONTROL {
    // Name of congestion control algorithm
    const char* Name;
    
    BOOLEAN (*QuicCongestionControlCanSend)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
        );

    void (*QuicCongestionControlSetExemption)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint8_t NumPackets
        );

    void (*QuicCongestionControlInitialize)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ const QUIC_SETTINGS* Settings
        );

    void (*QuicCongestionControlReset)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
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
        _In_ uint64_t TimeNow, // microsecond
        _In_ uint64_t LargestPacketNumberAcked,
        _In_ uint32_t NumRetransmittableBytes,
        _In_ uint32_t SmoothedRtt
        );

    void (*QuicCongestionControlOnDataLost)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint64_t LargestPacketNumberLost,
        _In_ uint64_t LargestPacketNumberSent,
        _In_ uint32_t NumRetransmittableBytes,
        _In_ BOOLEAN PersistentCongestion
        );

    void (*QuicCongestionControlOnSpuriousCongestionEvent)(
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

    uint64_t Ctx[104 / sizeof(uint64_t)];
} QUIC_CONGESTION_CONTROL;

#define QUIC_CONGESTION_CONTROL_CONTEXT_SIZE (RTL_FIELD_SIZE(QUIC_CONGESTION_CONTROL, Ctx))

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
void
QuicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    );

//
// Returns the number of bytes that can be sent immediately.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    );

//
// Called when any retransmittable data is sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    );

//
// Called when any data needs to be removed from inflight but cannot be
// considered lost or acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    );

//
// Called when any data is acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeNow, // microsecond
    _In_ uint64_t LargestPacketNumberAcked,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ uint32_t SmoothedRtt
    );

//
// Called when data is determined lost.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberLost,
    _In_ uint64_t LargestPacketNumberSent,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ BOOLEAN PersistentCongestion
    );

//
// Called when all recently considered lost data was actually acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
QuicCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

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
    _In_ const struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetBytesInFlightMax(Cc);
}
