/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

typedef struct BBR_RTT_SAMPLER {

    BOOLEAN RttSampleExpired: 1;

    BOOLEAN MinRttTimestampValid: 1;

    uint64_t Expiration;

    uint32_t MinRtt;

    uint64_t MinRttTimestamp;

} BBR_RTT_SAMPLER;

typedef struct WINDOWED_FILTER {

    //
    // Time length of window.
    //
    uint64_t WindowLength;

    //
    // Uninitialized value of Sample
    //
    uint64_t ZeroValue;

    //
    // Best estimate is element 0.
    //
    struct
    {

        uint64_t Sample;

        uint64_t Time;

    } Estimates[3];

} WINDOWED_FILTER;

typedef struct BBR_BANDWIDTH_SAMPLER {

    BOOLEAN AppLimited : 1;

    WINDOWED_FILTER WindowedFilter;

    uint64_t AppLimitedExitTarget;

} BBR_BANDWIDTH_SAMPLER;

typedef struct QUIC_CONGESTION_CONTROL_BBR {

    BOOLEAN BtlbwFound : 1;

    BOOLEAN AppLimitedSinceProbeRtt : 1;

    BOOLEAN ExitingQuiescene : 1;

    BOOLEAN EndOfRecoveryValid : 1;

    BOOLEAN AckAggregationStartTimeValid : 1;

    BOOLEAN ProbeRttRoundValid : 1;

    BOOLEAN EarliestTimeToExitProbeRttValid : 1;

    //
    // The size of the initial congestion window, in packets.
    //
    uint32_t InitialCongestionWindowPackets;

    uint32_t CongestionWindow; // bytes

    uint32_t InitialCongestionWindow; // bytes

    uint32_t RecoveryWindow; // bytes

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

    //
    // This variable tracks the largest packet that was outstanding at the time
    // the last congestion event occurred. An ACK for any packet number greater
    // than this indicates recovery is over.
    //
    uint64_t RoundTripCounter;

    uint32_t CwndGain;

    uint32_t PacingGain;

    uint64_t SendQuantum;

    uint8_t SlowStartupRoundCounter;

    uint32_t PacingCycleIndex;

    uint64_t AggregatedAckBytes;

    uint32_t RecoveryState;

    uint32_t BbrState;

    uint64_t CycleStart;

    uint64_t EndOfRoundTrip;

    uint64_t EndOfRecovery;

    uint64_t PreviousStartupBandwidth;

    uint64_t AckAggregationStartTime;

    uint64_t ProbeRttRound;

    uint64_t EarliestTimeToExitProbeRtt;

    WINDOWED_FILTER MaxAckHeightFilter;

    BBR_RTT_SAMPLER MinRttSampler;

    BBR_BANDWIDTH_SAMPLER BandwidthSampler;

} QUIC_CONGESTION_CONTROL_BBR;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS* Settings
    );
