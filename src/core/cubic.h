/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

typedef struct QUIC_CONGESTION_CONTROL_CUBIC {

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
    uint32_t AimdWindow; // bytes
    uint32_t PrevAimdWindow; // bytes
    uint32_t AimdAccumulator; // bytes

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
    // The leftover send allowance from a previous send. Only used when pacing.
    //
    uint32_t LastSendAllowance; // bytes

    //
    // A count of packets which can be sent ignoring CongestionWindow.
    // The count is decremented as the packets are sent. BytesInFlight is still
    // incremented for these packets. This is used to send probe packets for
    // loss recovery.
    //
    uint8_t Exemptions;

    uint64_t TimeOfLastAck; // microseconds
    uint64_t TimeOfCongAvoidStart; // microseconds
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

} QUIC_CONGESTION_CONTROL_CUBIC;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );
