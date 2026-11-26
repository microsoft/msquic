/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include "sliding_window_extremum.h"

#define kBbrDefaultFilterCapacity 3

#if defined(__cplusplus)
extern "C" {
#endif

struct QUIC_ACK_EVENT;

typedef enum BBR_STATE {
    BBR_STATE_STARTUP,

    BBR_STATE_DRAIN,

    BBR_STATE_PROBE_BW,

    BBR_STATE_PROBE_RTT
} BBR_STATE;

typedef enum RECOVERY_STATE {
    RECOVERY_STATE_NOT_RECOVERY = 0,

    RECOVERY_STATE_CONSERVATIVE = 1,

    RECOVERY_STATE_GROWTH = 2,
} RECOVERY_STATE;

//
// Bandwidth is measured as BW_UNIT * bytes per second.
//
#define BW_UNIT 8 // 1 << 3

//
// Gain is measured as (1 / GAIN_UNIT)
//
#define GAIN_UNIT 256 // 1 << 8

extern const uint32_t kMinCwndInMss;

//
// Cwnd gain during ProbeBw
//
extern const uint32_t kCwndGain;

//
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kStartupGrowthTarget
//
extern const uint8_t kStartupSlowGrowRoundLimit;

//
// During ProbeRtt, we need to stay in low inflight condition for at least kProbeRttTimeInUs
//
extern const uint32_t kProbeRttTimeInUs;

//
// Time until a MinRtt measurement is expired.
//
extern const uint32_t kBbrMinRttExpirationInMicroSecs;

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
    // Max filter for tracking the maximum recent delivery_rate sample, for estimating max bandwidth
    //
    QUIC_SLIDING_WINDOW_EXTREMUM WindowedMaxFilter;

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY WindowedMaxFilterEntries[kBbrDefaultFilterCapacity];
} BBR_BANDWIDTH_FILTER;

typedef struct BBR_COMMON {
    //
    // Whether the bottleneck bandwidth has been detected
    //
    BOOLEAN BtlbwFound : 1;

    //
    // TRUE when exiting quiescence
    //
    BOOLEAN ExitingQuiescence : 1;

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
    // If TRUE, ProbeRttEndTime is valid
    //
    BOOLEAN ProbeRttEndTimeValid : 1;

    //
    // If TRUE, current RTT sample is expired
    //
    BOOLEAN RttSampleExpired: 1;

    //
    // If TRUE, there has been at least one MinRtt sample
    //
    BOOLEAN MinRttTimestampValid: 1;

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
    // Receiving acknowledgment of a packet after EndoOfRoundTrip will
    // indicate the current round trip is ended
    //
    uint64_t EndOfRoundTrip;

    //
    // Receiving acknowledgment of a packet after EndoOfRecovery will cause
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
    uint64_t ProbeRttEndTime;

    //
    // The max filter tracking the recent maximum degree of aggregation in the path
    //
    QUIC_SLIDING_WINDOW_EXTREMUM MaxAckHeightFilter;
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY MaxAckHeightFilterEntries[kBbrDefaultFilterCapacity];

    uint64_t MinRtt; // microseconds

    //
    // Time when MinRtt was sampled. Only valid if MinRttTimestampValid is set.
    //
    uint64_t MinRttTimestamp; // microseconds

    //
    // BBR estimates maximum bandwidth by the maximum recent bandwidth
    //
    BBR_BANDWIDTH_FILTER BandwidthFilter;
} BBR_COMMON;

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrBandwidthFilterOnPacketAcked(
    _In_ BBR_BANDWIDTH_FILTER* b,
    _In_ const struct QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t RttCounter,
    _In_ uint64_t MinValidPacketNumber
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrGetBandwidth(
    _In_ const BBR_COMMON* Bbr
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrGetBdp(
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrUpdateBottleneckBandwidth(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrUpdateRecoveryWindow(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint16_t DatagramPayloadLength,
    _In_ uint32_t BytesAcked
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrUpdateAckAggregation(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ const struct QUIC_ACK_EVENT* AckEvent
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrGetTargetCwnd(
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ uint32_t Gain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrGetSendAllowance(
    _In_ const BBR_COMMON* Bbr,
    _In_ const QUIC_CONNECTION* Connection,
    _In_ uint64_t Bandwidth,
    _In_ uint32_t CongestionWindow,
    _In_ uint64_t TimeSinceLastSend,
    _In_ BOOLEAN TimeSinceLastSendValid
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrSetSendQuantum(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ uint16_t DatagramPayloadLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrUpdateCongestionWindow(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ uint16_t DatagramPayloadLength,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrReset(
    _Inout_ BBR_COMMON* Bbr,
    _In_ BOOLEAN FullReset,
    _In_ uint16_t DatagramPayloadLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrInitialize(
    _Inout_ BBR_COMMON* Bbr,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings,
    _In_ uint32_t BandwidthFilterLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrOnDataSent(
    _Inout_ BBR_COMMON* Bbr,
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t NumRetransmittableBytes
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogState(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogOutFlowStatus(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const BBR_COMMON* Bbr
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrGetNetworkStatistics(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _Out_ struct QUIC_NETWORK_STATISTICS* NetworkStatistics
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrIndicateConnectionEvent(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogRecoveryExit(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogCongestion(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogPersistentCongestion(
    _In_ QUIC_CONNECTION* Connection
    );

#if defined(__cplusplus)
}
#endif
