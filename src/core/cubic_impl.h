/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
CubicCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;
    return Ctx->BytesInFlight < Ctx->CongestionWindow || Ctx->Exemptions > 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
CubicCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;
    Ctx->Exemptions = NumPackets;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS* Settings
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CubicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CubicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CubicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CubicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeNow, // microsecond
    _In_ uint64_t LargestPacketNumberAcked,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ uint32_t SmoothedRtt
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberLost,
    _In_ uint64_t LargestPacketNumberSent,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ BOOLEAN PersistentCongestion
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
CubicCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

void
CubicCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

uint32_t
CubicCongestionControlGetBytesInFlightMax(
    _In_ const struct QUIC_CONGESTION_CONTROL* Cc
    );
