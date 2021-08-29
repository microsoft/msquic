/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
typedef struct QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT {

    //
    // TRUE if we have had at least one congestion event.
    // If TRUE, RecoverySentPacketNumber is valid.
    //
    BOOLEAN HasHadCongestionEvent : 1;

    //
    // This flag indicates a congestion event occurred and CC is attempting
    // to recover from it.
    //
    BOOLEAN IsInRecovery : 1;

    //
    // This flag indicates a persistent congestion event occurred and CC is
    // attempting to recover from it.
    //
    BOOLEAN IsInPersistentCongestion : 1;

    //
    // TRUE if there has been at least one ACK.
    //
    BOOLEAN TimeOfLastAckValid : 1;

    //
    // The size of the initial congestion window, in packets.
    //
    uint32_t InitialWindowPackets;

    //
    // Minimum time without any sends before the congestion window is reset.
    //
    uint32_t SendIdleTimeoutMs;

    uint32_t CongestionWindow; // bytes
    uint32_t PrevCongestionWindow; // bytes
    uint32_t SlowStartThreshold; // bytes
    uint32_t PrevSlowStartThreshold; // bytes

    //
    // The number of bytes considered to be still in the network.
    //
    // The client of this module should send packets until BytesInFlight becomes
    // larger than CongestionWindow (see QuicCongestionControlCanSend). This
    // means BytesInFlight can become larger than CongestionWindow by up to one
    // packet's worth of bytes, plus exemptions (see Exemptions variable).
    //
    uint32_t BytesInFlight;
    uint32_t BytesInFlightMax;

    //
    // A count of packets which can be sent ignoring CongestionWindow.
    // The count is decremented as the packets are sent. BytesInFlight is still
    // incremented for these packets. This is used to send probe packets for
    // loss recovery.
    //
    uint8_t Exemptions;

    uint64_t TimeOfLastAck; // millisec
    uint64_t TimeOfCongAvoidStart; // millisec
    uint32_t KCubic; // millisec
    uint32_t PrevKCubic; // millisec
    uint32_t WindowMax; // bytes
    uint32_t PrevWindowMax; // bytes
    uint32_t WindowLastMax; // bytes
    uint32_t PrevWindowLastMax; // bytes

    //
    // This variable tracks the largest packet that was outstanding at the time
    // the last congestion event occurred. An ACK for any packet number greater
    // than this indicates recovery is over.
    //
    uint64_t RecoverySentPacketNumber;

} QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT;

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT) <= QUIC_CONGESTION_CONTROL_CONTEXT_SIZE,
    "Context size for Cubic exceeds the expected size");

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
CubicCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT*)Cc->Ctx;
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
    QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC_CONTEXT*)Cc->Ctx;
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
CubicCongestionControlFinalize(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc
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

static const QUIC_CONGESTION_CONTROL QuicCongestionControlCubic = {
    .Name = "Cubic",
    .QuicCongestionControlCanSend = CubicCongestionControlCanSend,
    .QuicCongestionControlSetExemption = CubicCongestionControlSetExemption,
    .QuicCongestionControlInitialize = CubicCongestionControlInitialize,
    .QuicCongestionControlReset = CubicCongestionControlReset,
    .QuicCongestionControlGetSendAllowance = CubicCongestionControlGetSendAllowance,
    .QuicCongestionControlOnDataSent = CubicCongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = CubicCongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = CubicCongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = CubicCongestionControlOnDataLost,
    .QuicCongestionControlOnSpuriousCongestionEvent = CubicCongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = CubicCongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = CubicCongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = CubicCongestionControlGetBytesInFlightMax,
};