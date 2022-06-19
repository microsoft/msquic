/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

typedef struct BBR_RTT_STATS {

    //
    // TRUE if current RTT sample is expired
    //
    BOOLEAN RttSampleExpired: 1;

    //
    // TRUE if there has been at least one MinRtt
    //
    BOOLEAN MinRttTimestampValid: 1;

    //
    // The expire duration of last MinRtt
    //
    uint64_t Expiration; // microseconds

    uint32_t MinRtt; // microseconds

    uint64_t MinRttTimestamp; // microseconds

} BBR_RTT_STATS;

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

typedef struct BBR_BANDWIDTH_FILTER {

    //
    // TRUE if bandwidth is limited by the application
    //
    BOOLEAN AppLimited : 1;

    //
    // Target packet number to quit the AppLimited state
    //
    uint64_t AppLimitedExitTarget;

    //
    // Max filter for bottleneck bandwidth
    //
    WINDOWED_FILTER WindowedFilter;

} BBR_BANDWIDTH_FILTER;

typedef struct QUIC_CONGESTION_CONTROL_BBR {

    //
    // Whether the bottleneck bandwidth has been detected
    //
    BOOLEAN BtlbwFound : 1;

    //
    // TRUE when exiting quiescence
    //
    BOOLEAN ExitingQuiescene : 1;

    //
    // If TRUE, EndOfRecovery is valid
    //
    BOOLEAN EndOfRecoveryValid : 1;

    //
    // If TRUE, EndOfRoundTrip is valid
    //
    BOOLEAN EndOfRoundTripValid : 1;

    //
    // If TRUE, AckAggregationStartTime is valid
    //
    BOOLEAN AckAggregationStartTimeValid : 1;

    //
    // If TRUE, ProbeRttRound is valid
    //
    BOOLEAN ProbeRttRoundValid : 1;

    //
    // If TRUE, EarliestTimeToExitProbeRtt is valid
    //
    BOOLEAN EarliestTimeToExitProbeRttValid : 1;
    
    //
    // The size of the initial congestion window in packets
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
    // Count of packet-timed round trips
    //
    uint64_t RoundTripCounter;

    //
    // The dynamic gain factor used to scale the estimated BDP to produce a
    // congestion window (cwnd)
    //
    uint32_t CwndGain;

    //
    // The dynamic gain factor used to scale bottleneck bandwidth to produce the
    // pacing rate
    //
    uint32_t PacingGain;

    //
    // The dynamic send quantum specifies the maximum size of these transmission
    // aggregates
    //
    uint64_t SendQuantum;

    //
    // Counter of continuous round trips in STARTUP
    //
    uint8_t SlowStartupRoundCounter;

    //
    // Current cycle index in kPacingGain
    //
    uint32_t PacingCycleIndex;

    //
    // Starting time of ack aggregation
    //
    uint64_t AckAggregationStartTime;

    //
    // Number of bytes acked during this aggregation
    //
    uint64_t AggregatedAckBytes;

    //
    // Current state of recovery
    //
    uint32_t RecoveryState;

    //
    // Current state of BBR state machine
    //
    uint32_t BbrState;

    //
    // The time at which the last pacing gain cycle was started
    //
    uint64_t CycleStart;

    //
    // Receiving acknowledgement of a packet after EndoOfRoundTrip will
    // indicate the current round trip is ended
    //
    uint64_t EndOfRoundTrip;

    //
    // Receiving acknowledgement of a packet after EndoOfRecovery will cause
    // BBR to exit the recovery mode
    //
    uint64_t EndOfRecovery;

    //
    // The bandwidth of last during STARTUP state
    //
    uint64_t LastEstimatedStartupBandwidth;

    //
    // Indicates whether to exit ProbeRtt if there're at least one RTT round with the
    // minimum cwnd
    //
    uint64_t ProbeRttRound;

    //
    // Indicates the eariest time to exit ProbeRTT state
    //
    uint64_t EarliestTimeToExitProbeRtt;

    //
    // Tracks the maximum number of bytes acked faster than the sending rate
    //
    WINDOWED_FILTER MaxAckHeightFilter;

    //
    // BBR estimates minimum RTT by the minimum recent RTT
    //
    BBR_RTT_STATS MinRttStats;

    //
    // BBR estimates maximum bandwidth by the maximum recent bandwidth
    //
    BBR_BANDWIDTH_FILTER BandwidthFilter;

} QUIC_CONGESTION_CONTROL_BBR;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );
