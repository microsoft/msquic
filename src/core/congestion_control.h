/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_CONGESTION_CONTROL {

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
    uint32_t SlowStartThreshold; // bytes

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
    uint32_t WindowMax; // bytes
    uint32_t WindowLastMax; // bytes

    //
    // This variable tracks the largest packet that was outstanding at the time
    // the last congestion event occurred. An ACK for any packet number greater
    // than this indicates recovery is over.
    //
    uint64_t RecoverySentPacketNumber;

} QUIC_CONGESTION_CONTROL;

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
    return Cc->BytesInFlight < Cc->CongestionWindow || Cc->Exemptions > 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->Exemptions = NumPackets;
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
    _In_ uint64_t TimeNow, // millisec
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