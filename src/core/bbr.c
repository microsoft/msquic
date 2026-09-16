/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Bottleneck Bandwidth and RTT (BBR) congestion control.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "bbr.c.clog.h"
#endif

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

//
// The length of the gain cycle
//
#define GAIN_CYCLE_LENGTH 8

const uint64_t kQuantaFactor = 3;

const uint32_t kMinCwndInMss = 4;

const uint32_t kDefaultRecoveryCwndInMss = 2000;

const uint64_t kMicroSecsInSec = 1000000;

const uint64_t kMilliSecsInSec = 1000;

const uint64_t kLowPacingRateThresholdBytesPerSecond = 1200ULL * 1000;

const uint64_t kHighPacingRateThresholdBytesPerSecond = 24ULL * 1000 * 1000;

const uint32_t kHighGain = GAIN_UNIT * 2885 / 1000 + 1; // 2/ln(2)

const uint32_t kDrainGain = GAIN_UNIT * 1000 / 2885; // 1/kHighGain

//
// Cwnd gain during ProbeBw
//
const uint32_t kCwndGain = GAIN_UNIT * 2;

//
// The expected of bandwidth growth in each round trip time during STARTUP
//
const uint32_t kStartupGrowthTarget = GAIN_UNIT * 5 / 4;

//
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kStartupGrowthTarget
//
const uint8_t kStartupSlowGrowRoundLimit = 3;

//
// The cycle of gains used during the PROBE_BW stage
//
const uint32_t kPacingGain[GAIN_CYCLE_LENGTH] = {
    GAIN_UNIT * 5 / 4,
    GAIN_UNIT * 3 / 4,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT
};

//
// During ProbeRtt, we need to stay in low inflight condition for at least kProbeRttTimeInUs
//
const uint32_t kProbeRttTimeInUs = 200 * 1000;

//
// Time until a MinRtt measurement is expired.
//
const uint32_t kBbrMinRttExpirationInMicroSecs = S_TO_US(10);

const uint32_t kBbrMaxBandwidthFilterLen = 10;

const uint32_t kBbrMaxAckHeightFilterLen = 10;

static
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrBandwidthFilterOnPacketAcked(
    _In_ BBR_BANDWIDTH_FILTER* b,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t RttCounter,
    _In_ uint64_t MinValidPacketNumber
    )
{
    uint64_t MaxDeliveryRate = 0;
    if (b->AppLimited && b->AppLimitedExitTarget < AckEvent->LargestAck) {
        b->AppLimited = FALSE;
    }

    uint64_t TimeNow = AckEvent->TimeNow;

    QUIC_SENT_PACKET_METADATA* AckedPacketsIterator = AckEvent->AckedPackets;
    while (AckedPacketsIterator != NULL) {
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckedPacketsIterator;
        AckedPacketsIterator = AckedPacketsIterator->Next;

        if (AckedPacket->PacketLength == 0 || AckedPacket->PacketNumber < MinValidPacketNumber) {
            continue;
        }

        uint64_t SendRate = UINT64_MAX;
        uint64_t AckRate = UINT64_MAX;

        if (AckedPacket->Flags.HasLastAckedPacketInfo) {
            CXPLAT_DBG_ASSERT(AckedPacket->TotalBytesSent >= AckedPacket->LastAckedPacketInfo.TotalBytesSent);
            CXPLAT_DBG_ASSERT(CxPlatTimeAtOrBefore64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime));

            uint64_t AckElapsed = 0;
            uint64_t SendElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime);

            if (SendElapsed) {
                SendRate = (kMicroSecsInSec * BW_UNIT *
                    (AckedPacket->TotalBytesSent - AckedPacket->LastAckedPacketInfo.TotalBytesSent) /
                    SendElapsed);
            }

            if (!CxPlatTimeAtOrBefore64(AckEvent->AdjustedAckTime, AckedPacket->LastAckedPacketInfo.AdjustedAckTime)) {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckElapsed = CxPlatTimeDiff64(AckedPacket->LastAckedPacketInfo.AckTime, TimeNow);
            }

            CXPLAT_DBG_ASSERT(AckEvent->NumTotalAckedRetransmittableBytes >= AckedPacket->LastAckedPacketInfo.TotalBytesAcked);
            if (AckElapsed) {
                AckRate = (kMicroSecsInSec * BW_UNIT *
                           (AckEvent->NumTotalAckedRetransmittableBytes - AckedPacket->LastAckedPacketInfo.TotalBytesAcked) /
                           AckElapsed);
            }
        } else if (!CxPlatTimeAtOrBefore64(TimeNow, AckedPacket->SentTime)) {
            CXPLAT_DBG_ASSERT(CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow) != 0);
            SendRate = (kMicroSecsInSec * BW_UNIT *
                        AckEvent->NumTotalAckedRetransmittableBytes /
                        CxPlatTimeDiff64(AckedPacket->SentTime, TimeNow));
        }

        if (SendRate == UINT64_MAX && AckRate == UINT64_MAX) {
            continue;
        }

        uint64_t DeliveryRate = CXPLAT_MIN(SendRate, AckRate);
        MaxDeliveryRate = CXPLAT_MAX(MaxDeliveryRate, DeliveryRate);

        QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
        QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&b->WindowedMaxFilter, &Entry);

        uint64_t PreviousMaxDeliveryRate = 0;
        if (QUIC_SUCCEEDED(Status)) {
            PreviousMaxDeliveryRate = Entry.Value;
        }

        if (DeliveryRate >= PreviousMaxDeliveryRate || !AckedPacket->Flags.IsAppLimited) {
            QuicSlidingWindowExtremumUpdateMax(&b->WindowedMaxFilter, DeliveryRate, RttCounter);
        }
    }
    return MaxDeliveryRate;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Cc->Bbr.BandwidthFilter.WindowedMaxFilter, &Entry);
    if (QUIC_SUCCEEDED(Status)) {
        return Cc->Bbr.BbrVersion3 ? CXPLAT_MIN(Entry.Value, Cc->Bbr.V3.BandwidthLow) : Entry.Value;
    }
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlInRecovery(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
)
{
    return Cc->Bbr.RecoveryState != RECOVERY_STATE_NOT_RECOVERY;
}

static
uint32_t
BbrCongestionControlGetBdp(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    uint64_t BytesPerSecond = BbrCongestionControlGetBandwidth(Cc) / BW_UNIT;
    uint64_t Rtt = Cc->Bbr.MinRtt;
    uint64_t Whole = BytesPerSecond / kMicroSecsInSec;
    uint64_t Remainder = BytesPerSecond % kMicroSecsInSec;
    if ((Whole && Rtt > UINT32_MAX / Whole) ||
        (Remainder && Rtt > UINT64_MAX / Remainder)) {
        return UINT32_MAX;
    }
    return (uint32_t)CXPLAT_MIN(Whole * Rtt + Remainder * Rtt / kMicroSecsInSec, UINT32_MAX);
}

static
uint32_t
BbrV3InflightWithHeadroom(
    _In_ const QUIC_CONGESTION_CONTROL_BBR* Bbr
    )
{
    return Bbr->V3.InflightHigh == UINT32_MAX ? UINT32_MAX :
        (uint32_t)((uint64_t)Bbr->V3.InflightHigh * 85 / 100);
}

static
void
BbrV3StartPhase(
    _In_ QUIC_CONGESTION_CONTROL_BBR* Bbr,
    _In_ BBR_V3_PHASE Phase,
    _In_ uint64_t TimeNow,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    Bbr->V3.Phase = Phase;
    Bbr->V3.ProbeRound = Bbr->RoundTripCounter;
    Bbr->PacingGain = GAIN_UNIT;
    if (Phase == BBR_V3_PHASE_DOWN) {
        uint32_t RandomValue = 0;
        CxPlatRandom(sizeof(RandomValue), &RandomValue);
        Bbr->V3.ProbeWait = S_TO_US(2) + RandomValue % S_TO_US(1);
        Bbr->CycleStart = TimeNow;
        Bbr->V3.ProbeEndPacketNumber = LargestSentPacketNumber;
        Bbr->V3.AwaitingProbeFeedback = TRUE;
        Bbr->PacingGain = GAIN_UNIT * 9 / 10;
        Bbr->V3.LossInRound = FALSE;
    } else if (Phase == BBR_V3_PHASE_REFILL) {
        Bbr->V3.InflightLow = UINT32_MAX;
        Bbr->V3.BandwidthLow = UINT64_MAX;
        Bbr->V3.LossInRound = FALSE;
        Bbr->V3.BandwidthLatest = 0;
        Bbr->V3.InflightLatest = 0;
        Bbr->V3.ProbeUpAcked = 0;
        Bbr->V3.ProbeUpCount = CXPLAT_MAX(Bbr->CongestionWindow, 1);
        Bbr->V3.ProbeSamples = FALSE;
        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LargestSentPacketNumber;
    } else if (Phase == BBR_V3_PHASE_UP) {
        Bbr->PacingGain = GAIN_UNIT * 5 / 4;
        Bbr->V3.ProbeSamples = TRUE;
        Bbr->V3.ProbeStartPacketNumber = LargestSentPacketNumber + 1;
        Bbr->V3.AwaitingProbeFeedback = FALSE;
        Bbr->LastEstimatedStartupBandwidth = 0;
        Bbr->SlowStartupRoundCounter = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): False positive: embedded Cc is valid.
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;
    uint32_t CongestionWindow = Bbr->CongestionWindow;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        if (!Bbr->BbrVersion3 || !Bbr->MinRttTimestampValid) {
            return MinCongestionWindow;
        }
        uint32_t ProbeWindow = BbrCongestionControlGetBdp(Cc) / 2;
        CongestionWindow = (uint32_t)CXPLAT_MAX(MinCongestionWindow, CXPLAT_MIN(CongestionWindow, ProbeWindow));
    }

    if (Bbr->BbrVersion3) {
        uint32_t InflightHigh = Bbr->V3.InflightHigh;
        if (Bbr->BbrState == BBR_STATE_PROBE_RTT ||
            (Bbr->BbrState == BBR_STATE_PROBE_BW && Bbr->V3.Phase == BBR_V3_PHASE_CRUISE)) {
            InflightHigh = BbrV3InflightWithHeadroom(Bbr);
        }
        CongestionWindow = CXPLAT_MAX(MinCongestionWindow,
            CXPLAT_MIN(CongestionWindow, CXPLAT_MIN(InflightHigh, Bbr->V3.InflightLow)));
    }
    if (BbrCongestionControlInRecovery(Cc)) {
        return CXPLAT_MIN(CongestionWindow, Bbr->RecoveryWindow);
    }

    return CongestionWindow;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeBw(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t CongestionEventTime
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_PROBE_BW;
    Bbr->CwndGain = kCwndGain;

    if (Bbr->BbrVersion3) {
        BbrV3StartPhase(Bbr, BBR_V3_PHASE_DOWN, CongestionEventTime,
            QuicCongestionControlGetConnection(Cc)->LossDetection.LargestSentPacketNumber);
    } else {
        uint32_t RandomValue = 0;
        CxPlatRandom(sizeof(uint32_t), &RandomValue);
        Bbr->PacingCycleIndex = (RandomValue % (GAIN_CYCLE_LENGTH - 1) + 2) % GAIN_CYCLE_LENGTH;
        CXPLAT_DBG_ASSERT(Bbr->PacingCycleIndex != 1);
        Bbr->PacingGain = kPacingGain[Bbr->PacingCycleIndex];
    }

    Bbr->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.BbrState = BBR_STATE_STARTUP;
    Cc->Bbr.PacingGain = Cc->Bbr.BbrVersion3 ? GAIN_UNIT * 277 / 100 : kHighGain;
    Cc->Bbr.CwndGain = Cc->Bbr.BbrVersion3 ? kCwndGain : kHighGain;
    Cc->Bbr.V3.ProbeSamples = Cc->Bbr.BbrVersion3;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BandwidthFilter.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnLogBbr(
    _In_ QUIC_CONNECTION* const Connection
    )
{
    QUIC_CONGESTION_CONTROL* Cc = &Connection->CongestionControl;
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QuicTraceEvent(
        ConnBbr,
        "[conn][%p] BBR: State=%u RState=%u CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%u",
        Connection,
        Bbr->BbrState,
        Bbr->RecoveryState,
        BbrCongestionControlGetCongestionWindow(Cc),
        Bbr->BytesInFlight,
        Bbr->BytesInFlightMax,
        Bbr->MinRtt,
        BbrCongestionControlGetBandwidth(Cc) / BW_UNIT,
        BbrCongestionControlIsAppLimited(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlGetNetworkStatistics(
    _In_ const QUIC_CONNECTION* const Connection,
    _In_ const QUIC_CONGESTION_CONTROL* const Cc,
    _Out_ QUIC_NETWORK_STATISTICS* NetworkStatistics
    )
{
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    const QUIC_PATH* Path = &Connection->Paths[0];

    NetworkStatistics->BytesInFlight = Bbr->BytesInFlight;
    NetworkStatistics->PostedBytes = Connection->SendBuffer.PostedBytes;
    NetworkStatistics->IdealBytes = Connection->SendBuffer.IdealBytes;
    NetworkStatistics->SmoothedRTT = Path->SmoothedRtt;
    NetworkStatistics->CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    NetworkStatistics->Bandwidth = BbrCongestionControlGetBandwidth(Cc) / BW_UNIT;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlIndicateConnectionEvent(
    _In_ QUIC_CONNECTION* const Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_NETWORK_STATISTICS;

    BbrCongestionControlGetNetworkStatistics(Connection, Cc, &Event.NETWORK_STATISTICS);

    QuicTraceLogConnVerbose(
        IndicateDataAcked,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]",
        Event.NETWORK_STATISTICS.BytesInFlight,
        Event.NETWORK_STATISTICS.PostedBytes,
        Event.NETWORK_STATISTICS.IdealBytes,
        Event.NETWORK_STATISTICS.SmoothedRTT,
        Event.NETWORK_STATISTICS.CongestionWindow,
        Event.NETWORK_STATISTICS.Bandwidth);
    QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    return Cc->Bbr.BytesInFlight < CongestionWindow || Cc->Bbr.Exemptions > 0;
}

void
BbrCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    const QUIC_PATH* Path = &Connection->Paths[0];
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QuicTraceEvent(
        ConnOutFlowStatsV2,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Bbr->BytesInFlight,
        Bbr->CongestionWindow,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0,
        Path->OneWayDelay);
}

//
// Returns TRUE if we became unblocked.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicConnLogOutFlowStats(Connection);

    if (PreviousCanSendState != BbrCongestionControlCanSend(Cc)) {
        if (PreviousCanSendState) {
            QuicConnAddOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_CONGESTION_CONTROL);
        } else {
            QuicConnRemoveOutFlowBlockedReason(
                Connection, QUIC_FLOW_BLOCKED_CONGESTION_CONTROL);
            Connection->Send.LastFlushTime = CxPlatTimeUs64(); // Reset last flush time
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BytesInFlightMax;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
BbrCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.Exemptions;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->Bbr.Exemptions = NumPackets;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    if (!Bbr->BytesInFlight && BbrCongestionControlIsAppLimited(Cc)) {
        Bbr->ExitingQuiescence = TRUE;
        if (Bbr->BbrVersion3) {
            Bbr->AckAggregationStartTimeValid = FALSE;
            Bbr->AggregatedAckBytes = 0;
        }
    }

    Bbr->BytesInFlight += NumRetransmittableBytes;
    if (Bbr->BytesInFlightMax < Bbr->BytesInFlight) {
        Bbr->BytesInFlightMax = Bbr->BytesInFlight;
        QuicSendBufferConnectionAdjust(QuicCongestionControlGetConnection(Cc));
    }

    if (Bbr->Exemptions > 0) {
        --Bbr->Exemptions;
    }

    BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnPacketSent(
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _Inout_ QUIC_SENT_PACKET_METADATA* Packet
    )
{
    Packet->Flags.IsBbrProbe = FALSE;
    Packet->InflightAtSend = 0;
    Packet->TotalBytesLost = 0;
    // Settings can be changed while the active controller stays the same.
    if (Cc->QuicCongestionControlOnDataSent == BbrCongestionControlOnDataSent && Cc->Bbr.BbrVersion3) {
        Packet->InflightAtSend = Cc->Bbr.BytesInFlight;
        Packet->TotalBytesLost = Cc->Bbr.V3.TotalBytesLost;
        Packet->Flags.IsBbrProbe = Cc->Bbr.BbrState == BBR_STATE_STARTUP ||
            (Cc->Bbr.BbrState == BBR_STATE_PROBE_BW && Cc->Bbr.V3.Phase == BBR_V3_PHASE_UP);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= NumRetransmittableBytes);
    Bbr->BytesInFlight -= NumRetransmittableBytes;

    return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlUpdateRecoveryWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t BytesAcked
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    CXPLAT_DBG_ASSERT(Bbr->RecoveryState != RECOVERY_STATE_NOT_RECOVERY);

    if (Bbr->RecoveryState == RECOVERY_STATE_GROWTH) {
        Bbr->RecoveryWindow = (uint32_t)CXPLAT_MIN((uint64_t)Bbr->RecoveryWindow + BytesAcked, UINT32_MAX);
    }

    uint32_t RecoveryWindow = CXPLAT_MAX(
        Bbr->RecoveryWindow, (uint32_t)CXPLAT_MIN((uint64_t)Bbr->BytesInFlight + BytesAcked, UINT32_MAX));

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    Bbr->RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlHandleAckInProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t LargestSentPacketNumber,
    _In_ uint64_t AckTime
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (!Bbr->ProbeRttEndTimeValid &&
        Bbr->BytesInFlight < BbrCongestionControlGetCongestionWindow(Cc) + DatagramPayloadLength) {

        Bbr->ProbeRttEndTime = AckTime + kProbeRttTimeInUs;
        Bbr->ProbeRttEndTimeValid = TRUE;

        Bbr->ProbeRttRoundValid = FALSE;
        if (Bbr->BbrVersion3) {
            Bbr->ProbeRttRoundValid = TRUE;
            Bbr->ProbeRttRound = Bbr->RoundTripCounter;
            Bbr->EndOfRoundTripValid = TRUE;
            Bbr->EndOfRoundTrip = LargestSentPacketNumber;
        }

        return;
    }

    if (Bbr->ProbeRttEndTimeValid) {

        if (!Bbr->ProbeRttRoundValid && NewRoundTrip) {
            Bbr->ProbeRttRoundValid = TRUE;
            Bbr->ProbeRttRound = Bbr->RoundTripCounter;
        }

        if (Bbr->ProbeRttRoundValid &&
            (!Bbr->BbrVersion3 || Bbr->RoundTripCounter > Bbr->ProbeRttRound) &&
            CxPlatTimeAtOrBefore64(Bbr->ProbeRttEndTime, AckTime)) {
            Bbr->MinRttTimestamp = AckTime;
            Bbr->MinRttTimestampValid = TRUE;
            if (Bbr->BbrVersion3) {
                Bbr->V3.ProbeRttMinTimestamp = AckTime;
                Bbr->CongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Bbr->V3.PriorCongestionWindow);
            }

            if (Bbr->BtlbwFound) {
                BbrCongestionControlTransitToProbeBw(Cc, AckTime);
            } else {
                BbrCongestionControlTransitToStartup(Cc);
            }
        }

    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlUpdateAckAggregation(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    if (!Bbr->AckAggregationStartTimeValid) {
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr->AckAggregationStartTimeValid = TRUE;
        return 0;
    }

    uint64_t ExpectedAckBytes = BbrCongestionControlGetBandwidth(Cc) *
                                CxPlatTimeDiff64(Bbr->AckAggregationStartTime, AckEvent->TimeNow) /
                                kMicroSecsInSec /
                                BW_UNIT;

    //
    // Reset current ack aggregation status when we witness ack arrival rate being less or equal than
    // estimated bandwidth
    //
    if (Bbr->AggregatedAckBytes <= ExpectedAckBytes) {
        Bbr->AggregatedAckBytes = AckEvent->NumRetransmittableBytes;
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr->AckAggregationStartTimeValid = TRUE;

        return 0;
    }

    Bbr->AggregatedAckBytes += AckEvent->NumRetransmittableBytes;

    QuicSlidingWindowExtremumUpdateMax(&Bbr->MaxAckHeightFilter,
        Bbr->AggregatedAckBytes - ExpectedAckBytes, Bbr->RoundTripCounter);

    return Bbr->AggregatedAckBytes - ExpectedAckBytes;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetTargetCwnd(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t Gain
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    uint64_t BandwidthEst = BbrCongestionControlGetBandwidth(Cc);

    if (!BandwidthEst || !Bbr->MinRttTimestampValid) {
        return (uint32_t)CXPLAT_MIN((uint64_t)Gain * Bbr->InitialCongestionWindow / GAIN_UNIT, UINT32_MAX);
    }

    uint64_t Bdp = BbrCongestionControlGetBdp(Cc);
    uint64_t TargetCwnd = (Bdp * Gain / GAIN_UNIT) + (kQuantaFactor * Bbr->SendQuantum);
    return (uint32_t)CXPLAT_MIN(TargetCwnd, UINT32_MAX);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    uint64_t BandwidthEst = BbrCongestionControlGetBandwidth(Cc);
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);

    uint32_t SendAllowance = 0;

    if (Bbr->BytesInFlight >= CongestionWindow) {
        //
        // We are CC blocked, so we can't send anything.
        //
        SendAllowance = 0;

    } else if (
        !TimeSinceLastSendValid ||
        !Connection->Settings.PacingEnabled ||
        !Bbr->MinRttTimestampValid ||
        Bbr->MinRtt < QUIC_SEND_PACING_INTERVAL) {
        //
        // We're not in the necessary state to pace.
        //
        SendAllowance = CongestionWindow - Bbr->BytesInFlight;

    } else {
        //
        // We are pacing, so split the congestion window into chunks which are
        // spread out over the RTT. Calculate the current send allowance (chunk
        // size) as the time since the last send times the pacing rate (CWND / RTT).
        //
        // Convert the bandwidth sample (BW_UNIT * bytes/second) to bytes.
        // Bound the elapsed interval before multiplying: idle time cannot grant
        // more than a window, and should not overflow the pacing calculation.
        uint64_t PacingRate = BandwidthEst / BW_UNIT * Bbr->PacingGain / GAIN_UNIT;
        if (!PacingRate) {
            PacingRate = (uint64_t)Bbr->InitialCongestionWindow * kMicroSecsInSec /
                Bbr->MinRtt * Bbr->PacingGain / GAIN_UNIT;
        }
        uint64_t Elapsed = CXPLAT_MIN(TimeSinceLastSend, kMicroSecsInSec);
        uint64_t Allowance = PacingRate > UINT64_MAX / kMicroSecsInSec ? UINT64_MAX :
            PacingRate * Elapsed / kMicroSecsInSec;
        SendAllowance = (uint32_t)CXPLAT_MIN(Allowance, UINT32_MAX);

        if (SendAllowance > CongestionWindow - Bbr->BytesInFlight) {
            SendAllowance = CongestionWindow - Bbr->BytesInFlight;
        }

        if (SendAllowance > (CongestionWindow >> 2)) {
            SendAllowance = CongestionWindow >> 2; // Don't send more than a quarter of the current window.
        }
    }
    return SendAllowance;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_PROBE_RTT;
    if (Bbr->BbrVersion3) {
        Bbr->V3.PriorCongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Bbr->V3.PriorCongestionWindow);
        Bbr->V3.ProbeSamples = FALSE;
    }
    Bbr->PacingGain = GAIN_UNIT;
    Bbr->ProbeRttEndTimeValid = FALSE;
    Bbr->ProbeRttRoundValid = FALSE;

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.BbrState = BBR_STATE_DRAIN;
    Cc->Bbr.PacingGain = Cc->Bbr.BbrVersion3 ? GAIN_UNIT / 2 : kDrainGain;
    Cc->Bbr.CwndGain = Cc->Bbr.BbrVersion3 ? kCwndGain : kHighGain;
    Cc->Bbr.V3.ProbeRound = Cc->Bbr.RoundTripCounter;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetSendQuantum(
    _In_ QUIC_CONGESTION_CONTROL* Cc
)
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    uint64_t Bandwidth = BbrCongestionControlGetBandwidth(Cc);

    uint64_t PacingRate = Bandwidth * Bbr->PacingGain / GAIN_UNIT;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (PacingRate < kLowPacingRateThresholdBytesPerSecond * BW_UNIT) {
        Bbr->SendQuantum = (uint64_t)DatagramPayloadLength;
    } else if (PacingRate < kHighPacingRateThresholdBytesPerSecond * BW_UNIT) {
        Bbr->SendQuantum = (uint64_t)DatagramPayloadLength * 2;
    } else {
        Bbr->SendQuantum = CXPLAT_MIN(PacingRate / kMilliSecsInSec / BW_UNIT, 64 * 1024 /* 64k */);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlUpdateCongestionWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return;
    }

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    BbrCongestionControlSetSendQuantum(Cc);

    uint64_t TargetCwnd = BbrCongestionControlGetTargetCwnd(Cc, Bbr->CwndGain);
    if (Bbr->BtlbwFound) {
        QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
        QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Bbr->MaxAckHeightFilter, &Entry);
        if (QUIC_SUCCEEDED(Status)) {
            TargetCwnd += Entry.Value;
        }
    }

    uint32_t CongestionWindow = Bbr->CongestionWindow;
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (Bbr->BtlbwFound) {
        CongestionWindow = (uint32_t)CXPLAT_MIN(CXPLAT_MIN(TargetCwnd, CongestionWindow + AckedBytes), UINT32_MAX);
    } else if (CongestionWindow < TargetCwnd || TotalBytesAcked < Bbr->InitialCongestionWindow) {
        CongestionWindow = (uint32_t)CXPLAT_MIN((uint64_t)CongestionWindow + AckedBytes, UINT32_MAX);
    }

    Bbr->CongestionWindow = CXPLAT_MAX(CongestionWindow, MinCongestionWindow);
    if (Bbr->BbrVersion3) {
        // Apply the model after ACK aggregation and startup growth, including
        // when no bandwidth/RTT sample is available yet.
        Bbr->CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    }

    QuicConnLogBbr(QuicCongestionControlGetConnection(Cc));
}

//
// BBRv3 keeps loss adaptation on packet rounds, independently of ACK batching.
// ProbeBW's long-term model is refreshed by probes, not by every isolated loss.
//
static
void
BbrV3UpdateModel(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t DeliveryRate
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    BBR_V3_MODEL* Model = &Bbr->V3;
    uint32_t Delivered = 0;
    for (const QUIC_SENT_PACKET_METADATA* Packet = AckEvent->AckedPackets; Packet; Packet = Packet->Next) {
        if (Packet->PacketNumber >= Model->MinValidPacketNumber && Packet->Flags.HasLastAckedPacketInfo) {
            Delivered = CXPLAT_MAX(Delivered, (uint32_t)CXPLAT_MIN(
                AckEvent->NumTotalAckedRetransmittableBytes - Packet->LastAckedPacketInfo.TotalBytesAcked,
                UINT32_MAX));
        }
    }
    Model->BandwidthLatest = CXPLAT_MAX(Model->BandwidthLatest, DeliveryRate);
    Model->InflightLatest = CXPLAT_MAX(Model->InflightLatest, Delivered);

    if (NewRoundTrip) {
        if (Bbr->BbrState == BBR_STATE_STARTUP && Model->ExcessiveLossInRound && Model->StartupLossEvents >= 6) {
            Bbr->BtlbwFound = TRUE;
            Model->InflightHigh = CXPLAT_MAX(Model->InflightLatest,
                BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT));
        }
        BOOLEAN Probing = Bbr->BbrState == BBR_STATE_STARTUP ||
            (Bbr->BbrState == BBR_STATE_PROBE_BW &&
                (Model->Phase == BBR_V3_PHASE_REFILL || Model->Phase == BBR_V3_PHASE_UP));
        if (Model->LossInRound && !Probing) {
            if (Model->BandwidthLow == UINT64_MAX) {
                Model->BandwidthLow = BbrCongestionControlGetBandwidth(Cc);
            }
            if (Model->InflightLow == UINT32_MAX) {
                Model->InflightLow = Bbr->CongestionWindow;
            }
            Model->BandwidthLow = CXPLAT_MAX(1, CXPLAT_MAX(Model->BandwidthLatest, Model->BandwidthLow / 10 * 7));
            Model->InflightLow = CXPLAT_MAX(Model->InflightLatest, (uint32_t)((uint64_t)Model->InflightLow * 7 / 10));
        }
        Model->LossInRound = FALSE;
        Model->ExcessiveLossInRound = FALSE;
        Model->StartupLossEvents = 0;
        Model->BandwidthLatest = DeliveryRate;
        Model->InflightLatest = Delivered;
    }

    if (Model->AwaitingProbeFeedback && AckEvent->LargestAck > Model->ProbeEndPacketNumber) {
        Model->AwaitingProbeFeedback = FALSE;
        Model->ProbeSamples = FALSE;
        if (!AckEvent->IsLargestAckedPacketAppLimited) {
            ++Model->CycleCount;
        }
    }
}

static
void
BbrV3UpdateProbeBw(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ BOOLEAN NewRoundTrip
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    BBR_V3_MODEL* Model = &Bbr->V3;
    const uint32_t Mss = QuicPathGetDatagramPayloadSize(&QuicCongestionControlGetConnection(Cc)->Paths[0]);

    if (Model->Phase == BBR_V3_PHASE_DOWN || Model->Phase == BBR_V3_PHASE_CRUISE) {
        uint64_t ProbeRounds = CXPLAT_MIN(63, CXPLAT_MAX(1, BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT) / Mss));
        if (CxPlatTimeDiff64(Bbr->CycleStart, AckEvent->TimeNow) >= Model->ProbeWait ||
            Bbr->RoundTripCounter - Model->ProbeRound >= ProbeRounds) {
            BbrV3StartPhase(Bbr, BBR_V3_PHASE_REFILL, AckEvent->TimeNow, AckEvent->LargestSentPacketNumber);
        } else if (Model->Phase == BBR_V3_PHASE_DOWN &&
            Bbr->BytesInFlight <= BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT) &&
            Bbr->BytesInFlight <= CXPLAT_MAX(4 * Mss, BbrV3InflightWithHeadroom(Bbr))) {
            // CRUISE shares DOWN's probe timer and round count.
            Model->Phase = BBR_V3_PHASE_CRUISE;
            Bbr->PacingGain = GAIN_UNIT;
        }
    } else if (Model->Phase == BBR_V3_PHASE_REFILL) {
        if (NewRoundTrip && Bbr->RoundTripCounter > Model->ProbeRound) {
            BbrV3StartPhase(Bbr, BBR_V3_PHASE_UP, AckEvent->TimeNow, AckEvent->LargestSentPacketNumber);
        }
    } else {
        if (NewRoundTrip) {
            Model->ProbeUpCount = CXPLAT_MAX(Mss, Model->ProbeUpCount / 2);
        }
        if (!AckEvent->IsLargestAckedPacketAppLimited && !BbrCongestionControlInRecovery(Cc) &&
            Model->InflightHigh != UINT32_MAX) {
            BOOLEAN AtLimit = FALSE;
            for (const QUIC_SENT_PACKET_METADATA* Packet = AckEvent->AckedPackets; Packet; Packet = Packet->Next) {
                AtLimit |= Packet->PacketNumber >= Model->ProbeStartPacketNumber &&
                    Packet->Flags.IsBbrProbe && !Packet->Flags.IsAppLimited && Packet->InflightAtSend >= Model->InflightHigh;
            }
            if (AtLimit) {
                if (Model->InflightHigh < BbrCongestionControlGetTargetCwnd(Cc, Bbr->CwndGain)) {
                    // A probe constrained by its learned window has not yet
                    // tested the path's available bandwidth.
                    Bbr->SlowStartupRoundCounter = 0;
                }
                Model->ProbeUpAcked += AckEvent->NumRetransmittableBytes;
                uint64_t Increase = Model->ProbeUpAcked / CXPLAT_MAX(Model->ProbeUpCount, 1) * Mss;
                Model->ProbeUpAcked %= CXPLAT_MAX(Model->ProbeUpCount, 1);
                Model->InflightHigh = (uint32_t)CXPLAT_MIN((uint64_t)Model->InflightHigh + Increase, UINT32_MAX);
            }
        }
        if (Bbr->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
            BbrV3StartPhase(Bbr, BBR_V3_PHASE_DOWN, AckEvent->TimeNow, AckEvent->LargestSentPacketNumber);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (AckEvent->IsImplicit) {
        if (Bbr->BbrVersion3) {
            CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
            Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;
        }
        BbrCongestionControlUpdateCongestionWindow(
            Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

        if (Connection->Settings.NetStatsEventEnabled) {
            BbrCongestionControlIndicateConnectionEvent(Connection, Cc);
        }
        return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    }

    uint32_t PrevInflightBytes = Bbr->BytesInFlight;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    QUIC_ACK_EVENT CurrentPathAck;
    if (Bbr->BbrVersion3 && Bbr->V3.MinValidPacketNumber && AckEvent->AckedPackets != NULL) {
        CurrentPathAck = *AckEvent;
        CurrentPathAck.MinRtt = UINT64_MAX;
        CurrentPathAck.MinRttValid = FALSE;
        CurrentPathAck.LargestAck = 0;
        BOOLEAN HasCurrentPathPacket = FALSE;
        for (const QUIC_SENT_PACKET_METADATA* Packet = AckEvent->AckedPackets; Packet; Packet = Packet->Next) {
            if (Packet->PacketNumber < Bbr->V3.MinValidPacketNumber) {
                continue;
            }
            HasCurrentPathPacket = TRUE;
            if (Packet->PacketNumber >= CurrentPathAck.LargestAck) {
                CurrentPathAck.LargestAck = Packet->PacketNumber;
                CurrentPathAck.IsLargestAckedPacketAppLimited = Packet->Flags.IsAppLimited;
            }
            if (AckEvent->MinRttValid) {
                uint64_t Rtt = CxPlatTimeDiff64(Packet->SentTime, AckEvent->TimeNow);
                uint64_t AckDelay = CxPlatTimeDiff64(AckEvent->AdjustedAckTime, AckEvent->TimeNow);
                if (Rtt >= AckDelay) {
                    Rtt -= AckDelay;
                }
                CurrentPathAck.MinRtt = CXPLAT_MIN(CurrentPathAck.MinRtt, Rtt);
                CurrentPathAck.MinRttValid = TRUE;
            }
        }
        if (!HasCurrentPathPacket) {
            return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
        }
        AckEvent = &CurrentPathAck;
    }
    if (Bbr->BbrVersion3 && AckEvent->LargestAck < Bbr->V3.MinValidPacketNumber) {
        return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    }

    if (AckEvent->MinRttValid) {
        Bbr->RttSampleExpired = Bbr->MinRttTimestampValid ?
           CxPlatTimeAtOrBefore64(Bbr->MinRttTimestamp + kBbrMinRttExpirationInMicroSecs, AckEvent->TimeNow) :
           FALSE;
        if (Bbr->RttSampleExpired || Bbr->MinRtt > AckEvent->MinRtt) {
            Bbr->MinRtt = AckEvent->MinRtt;
            Bbr->MinRttTimestamp = AckEvent->TimeNow;
            Bbr->MinRttTimestampValid = TRUE;
        }
        if (Bbr->BbrVersion3) {
            BOOLEAN ProbeExpired = CxPlatTimeAtOrBefore64(
                Bbr->V3.ProbeRttMinTimestamp + S_TO_US(5), AckEvent->TimeNow);
            if (AckEvent->MinRtt <= Bbr->V3.ProbeRttMin || ProbeExpired) {
                Bbr->V3.ProbeRttMin = AckEvent->MinRtt;
                Bbr->V3.ProbeRttMinTimestamp = AckEvent->TimeNow;
            }
            Bbr->RttSampleExpired = ProbeExpired;
        }
    }

    BOOLEAN NewRoundTrip = FALSE;
    if (!Bbr->EndOfRoundTripValid || Bbr->EndOfRoundTrip < AckEvent->LargestAck) {
        Bbr->RoundTripCounter++;
        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = AckEvent->LargestSentPacketNumber;
        NewRoundTrip = TRUE;
    }

    BOOLEAN LastAckedPacketAppLimited =
        AckEvent->AckedPackets == NULL ? FALSE : AckEvent->IsLargestAckedPacketAppLimited;

    uint64_t DeliveryRate = BbrBandwidthFilterOnPacketAcked(&Bbr->BandwidthFilter, AckEvent,
        Bbr->BbrVersion3 ? Bbr->V3.CycleCount : Bbr->RoundTripCounter,
        Bbr->BbrVersion3 ? Bbr->V3.MinValidPacketNumber : 0);
    if (Bbr->BbrVersion3) {
        BbrV3UpdateModel(Cc, AckEvent, NewRoundTrip, DeliveryRate);
    }

    if (BbrCongestionControlInRecovery(Cc)) {
        CXPLAT_DBG_ASSERT(Bbr->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (!AckEvent->HasLoss && Bbr->EndOfRecovery < AckEvent->LargestAck) {
            Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
            if (Bbr->BbrVersion3) {
                Bbr->CongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Bbr->V3.PriorCongestionWindow);
            }
            QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
        } else {
            BbrCongestionControlUpdateRecoveryWindow(Cc, AckEvent->NumRetransmittableBytes);
        }
    }

    BbrCongestionControlUpdateAckAggregation(Cc, AckEvent);

    if (Bbr->BbrState == BBR_STATE_PROBE_BW && !Bbr->BbrVersion3) {
        BOOLEAN ShouldAdvancePacingGainCycle = CxPlatTimeDiff64(Bbr->CycleStart, AckEvent->TimeNow) > Bbr->MinRtt;

        if (Bbr->PacingGain > GAIN_UNIT && !AckEvent->HasLoss &&
            PrevInflightBytes < BbrCongestionControlGetTargetCwnd(Cc, Bbr->PacingGain)) {
            ShouldAdvancePacingGainCycle = FALSE;
        }

        if (Bbr->PacingGain < GAIN_UNIT) {
            uint64_t TargetCwnd = BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT);
            if (Bbr->BytesInFlight <= TargetCwnd) {
                ShouldAdvancePacingGainCycle = TRUE;
            }
        }

        if (ShouldAdvancePacingGainCycle) {
            Bbr->PacingCycleIndex = (Bbr->PacingCycleIndex + 1) % GAIN_CYCLE_LENGTH;
            Bbr->CycleStart = AckEvent->TimeNow;
            Bbr->PacingGain = kPacingGain[Bbr->PacingCycleIndex];
        }
    }

    if ((!Bbr->BtlbwFound || (Bbr->BbrVersion3 && Bbr->BbrState == BBR_STATE_PROBE_BW &&
            Bbr->V3.Phase == BBR_V3_PHASE_UP)) && NewRoundTrip && !LastAckedPacketAppLimited &&
            (!Bbr->BbrVersion3 || DeliveryRate != 0)) {
        uint64_t BandwidthTarget = (uint64_t)(Bbr->LastEstimatedStartupBandwidth * kStartupGrowthTarget / GAIN_UNIT);
        uint64_t CurrentBandwidth = BbrCongestionControlGetBandwidth(Cc);

        if (CurrentBandwidth >= BandwidthTarget) {
            Bbr->LastEstimatedStartupBandwidth = CurrentBandwidth;
            Bbr->SlowStartupRoundCounter = 0;
        } else if (++Bbr->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
            Bbr->BtlbwFound = TRUE;
        }
    }

    if (Bbr->BbrVersion3 && Bbr->BbrState == BBR_STATE_PROBE_BW) {
        BbrV3UpdateProbeBw(Cc, AckEvent, NewRoundTrip);
    }

    if (Bbr->BbrState == BBR_STATE_STARTUP && Bbr->BtlbwFound) {
        BbrCongestionControlTransitToDrain(Cc);
    }

    if (Bbr->BbrState == BBR_STATE_DRAIN &&
        (Bbr->BytesInFlight <= BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT) ||
            (Bbr->BbrVersion3 && Bbr->RoundTripCounter - Bbr->V3.ProbeRound >= 3))) {
        BbrCongestionControlTransitToProbeBw(Cc, AckEvent->TimeNow);
    }

    if (Bbr->BbrState != BBR_STATE_PROBE_RTT &&
        !Bbr->ExitingQuiescence &&
        Bbr->MinRttTimestampValid &&
        Bbr->RttSampleExpired) {
        BbrCongestionControlTransitToProbeRtt(Cc, AckEvent->LargestSentPacketNumber);
    }

    Bbr->ExitingQuiescence = FALSE;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        BbrCongestionControlHandleAckInProbeRtt(
            Cc, NewRoundTrip, AckEvent->LargestSentPacketNumber, AckEvent->TimeNow);
    }

    BbrCongestionControlUpdateCongestionWindow(
        Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

    if (Connection->Settings.NetStatsEventEnabled) {
        BbrCongestionControlIndicateConnectionEvent(Connection, Cc);
    }

    return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

static
void
BbrV3HandleLoss(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent,
    _In_ uint32_t PreviousCongestionWindow
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    BBR_V3_MODEL* Model = &Bbr->V3;
    uint64_t AccountedBytes = 0;
    BOOLEAN EndProbe = FALSE;
    for (const QUIC_SENT_PACKET_METADATA* Packet = LossEvent->LostPackets; Packet; Packet = Packet->Next) {
        if (!Packet->Flags.IsAckEliciting) {
            continue;
        }
        AccountedBytes += Packet->PacketLength;
        if (Packet->PacketNumber < Model->MinValidPacketNumber) {
            continue;
        }
        Model->TotalBytesLost += Packet->PacketLength;
        Model->LossInRound = TRUE;
        if (!Model->StartupLossEvents || Packet->PacketNumber != Model->LastLostPacketNumber + 1) {
            ++Model->StartupLossEvents;
        }
        Model->LastLostPacketNumber = Packet->PacketNumber;
        uint64_t LostSinceSent = Model->TotalBytesLost - Packet->TotalBytesLost;
        if (!Packet->InflightAtSend || LostSinceSent <= Packet->InflightAtSend / 50) {
            continue;
        }
        Model->ExcessiveLossInRound = TRUE;
        if (!Packet->Flags.IsBbrProbe || !Model->ProbeSamples ||
            Packet->PacketNumber < Model->ProbeStartPacketNumber) {
            continue;
        }
        if (Bbr->BbrState == BBR_STATE_STARTUP) {
            // Startup needs losses from multiple discontiguous ranges over a
            // complete packet round; a single tail drop is not a plateau.
            continue;
        }
        Model->ProbeSamples = FALSE;
        if (!Packet->Flags.IsAppLimited) {
            // Interpolate the prefix of this packet at which loss crossed 2%.
            uint32_t SafeInflight = Packet->InflightAtSend - CXPLAT_MIN(Packet->InflightAtSend, Packet->PacketLength);
            uint64_t PreviousLoss = LostSinceSent - Packet->PacketLength;
            if (PreviousLoss <= SafeInflight / 50) {
                SafeInflight += (uint32_t)((SafeInflight - PreviousLoss * 50) / 49);
            }
            uint32_t Target = CXPLAT_MIN(PreviousCongestionWindow,
                BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT));
            Model->InflightHigh = CXPLAT_MAX(SafeInflight, (uint32_t)((uint64_t)Target * 7 / 10));
        }
        if (Bbr->BbrState == BBR_STATE_PROBE_BW && Model->Phase == BBR_V3_PHASE_UP) {
            EndProbe = TRUE;
        }
    }
    // Unit callers may supply only aggregate loss; it still contributes to
    // the short-term model, but cannot fabricate a sent-time probe sample.
    CXPLAT_DBG_ASSERT(AccountedBytes <= LossEvent->NumRetransmittableBytes);
    Model->TotalBytesLost += LossEvent->NumRetransmittableBytes - AccountedBytes;
    if (AccountedBytes < LossEvent->NumRetransmittableBytes) {
        Model->LossInRound = TRUE;
    }
    if (EndProbe) {
        // Finish the batch before resetting round signals: subsequent losses
        // in the same probe must not also reduce the short-term bounds.
        BbrV3StartPhase(Bbr, BBR_V3_PHASE_DOWN, LossEvent->TimeNow, LossEvent->LargestSentPacketNumber);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    QuicTraceEvent(
        ConnCongestionV2,
        "[conn][%p] Congestion event: IsEcn=%hu",
        Connection,
        FALSE);
    Connection->Stats.Send.CongestionCount++;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(LossEvent->NumRetransmittableBytes > 0);
    uint32_t PreviousCongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);

    Bbr->EndOfRecoveryValid = TRUE;
    Bbr->EndOfRecovery = LossEvent->LargestSentPacketNumber;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    uint32_t RecoveryWindow = Bbr->RecoveryWindow;
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (!BbrCongestionControlInRecovery(Cc)) {
        if (Bbr->BbrVersion3) {
            Bbr->V3.UndoValid = TRUE;
            Bbr->V3.PriorCongestionWindow = Bbr->CongestionWindow;
            Bbr->V3.UndoInflightHigh = Bbr->V3.InflightHigh;
            Bbr->V3.UndoInflightLow = Bbr->V3.InflightLow;
            Bbr->V3.UndoBandwidthLow = Bbr->V3.BandwidthLow;
            Bbr->V3.UndoState = Bbr->BbrState;
            Bbr->V3.UndoPhase = Bbr->V3.Phase;
            Bbr->V3.UndoBtlbwFound = Bbr->BtlbwFound;
        }
        Bbr->RecoveryState = RECOVERY_STATE_CONSERVATIVE;
        RecoveryWindow = Bbr->BytesInFlight;

        RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);

        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LossEvent->LargestSentPacketNumber;
    }

    if (Bbr->BbrVersion3) {
        BbrV3HandleLoss(Cc, LossEvent, PreviousCongestionWindow);
    }

    if (LossEvent->PersistentCongestion) {
        Bbr->RecoveryWindow = MinCongestionWindow;

        QuicTraceEvent(
            ConnPersistentCongestion,
            "[conn][%p] Persistent congestion event",
            Connection);
        Connection->Stats.Send.PersistentCongestionCount++;
        if (Bbr->BbrVersion3) {
            Bbr->V3.InflightLow = MinCongestionWindow;
        }
    } else if (Bbr->BbrVersion3) {
        Bbr->RecoveryWindow = CXPLAT_MAX(Bbr->BytesInFlight, MinCongestionWindow);
    } else {
        Bbr->RecoveryWindow =
            RecoveryWindow > LossEvent->NumRetransmittableBytes + MinCongestionWindow
            ? RecoveryWindow - LossEvent->NumRetransmittableBytes
            : MinCongestionWindow;
    }

    BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    QuicConnLogBbr(QuicCongestionControlGetConnection(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    if (!Bbr->BbrVersion3 || !Bbr->V3.UndoValid) {
        return FALSE;
    }
    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);
    Bbr->V3.InflightHigh = CXPLAT_MAX(Bbr->V3.InflightHigh, Bbr->V3.UndoInflightHigh);
    Bbr->V3.InflightLow = CXPLAT_MAX(Bbr->V3.InflightLow, Bbr->V3.UndoInflightLow);
    Bbr->V3.BandwidthLow = CXPLAT_MAX(Bbr->V3.BandwidthLow, Bbr->V3.UndoBandwidthLow);
    Bbr->CongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Bbr->V3.PriorCongestionWindow);
    Bbr->BtlbwFound = Bbr->V3.UndoBtlbwFound;
    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->V3.LossInRound = FALSE;
    Bbr->V3.ExcessiveLossInRound = FALSE;
    Bbr->V3.StartupLossEvents = 0;
    Bbr->LastEstimatedStartupBandwidth = 0;
    Bbr->SlowStartupRoundCounter = 0;
    if (Bbr->BbrState != BBR_STATE_PROBE_RTT) {
        if (Bbr->V3.UndoState == BBR_STATE_STARTUP) {
            BbrCongestionControlTransitToStartup(Cc);
        } else if (Bbr->V3.UndoState == BBR_STATE_PROBE_BW && Bbr->V3.UndoPhase == BBR_V3_PHASE_UP) {
            Bbr->BbrState = BBR_STATE_PROBE_BW;
            BbrV3StartPhase(Bbr, BBR_V3_PHASE_UP, CxPlatTimeUs64(),
                QuicCongestionControlGetConnection(Cc)->LossDetection.LargestSentPacketNumber);
        }
    }
    Bbr->V3.UndoValid = FALSE;
    return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    uint64_t LargestSentPacketNumber = Connection->LossDetection.LargestSentPacketNumber;

    if (Bbr->BytesInFlight > BbrCongestionControlGetCongestionWindow(Cc)) {
        return;
    }

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr->CongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->InitialCongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->RecoveryWindow = kDefaultRecoveryCwndInMss * DatagramPayloadLength;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;

    if (FullReset) {
        Bbr->BytesInFlight = 0;
    }
    Bbr->Exemptions = 0;

    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->RoundTripCounter = 0;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->ExitingQuiescence = FALSE;
    Bbr->LastEstimatedStartupBandwidth = 0;
    uint64_t TotalBytesLost = Bbr->V3.TotalBytesLost;
    Bbr->V3 = (BBR_V3_MODEL) {
        .BandwidthLow = UINT64_MAX,
        .InflightHigh = UINT32_MAX,
        .InflightLow = UINT32_MAX,
        .ProbeRttMin = UINT64_MAX,
        .ProbeRttMinTimestamp = CxPlatTimeUs64(),
        .ProbeWait = S_TO_US(2),
        .ProbeUpCount = UINT32_MAX,
        .TotalBytesLost = TotalBytesLost,
        .MinValidPacketNumber = Connection->Send.NextPacketNumber,
    };
    BbrCongestionControlTransitToStartup(Cc);

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = CxPlatTimeUs64();
    Bbr->CycleStart = 0;

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EndOfRoundTripValid = FALSE;
    Bbr->EndOfRoundTrip = 0;

    Bbr->ProbeRttEndTimeValid = FALSE;
    Bbr->ProbeRttEndTime = CxPlatTimeUs64();

    Bbr->RttSampleExpired = TRUE;
    Bbr->MinRttTimestampValid = FALSE;
    Bbr->MinRtt = UINT64_MAX;
    Bbr->MinRttTimestamp = 0;

    QuicSlidingWindowExtremumReset(&Bbr->MaxAckHeightFilter);

    QuicSlidingWindowExtremumReset(&Bbr->BandwidthFilter.WindowedMaxFilter);
    Bbr->BandwidthFilter.AppLimited = FALSE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = 0;

    BbrCongestionControlLogOutFlowStatus(Cc);
    QuicConnLogBbr(Connection);
}


static const QUIC_CONGESTION_CONTROL QuicCongestionControlBbr = {
    .Name = "BBR",
    .QuicCongestionControlCanSend = BbrCongestionControlCanSend,
    .QuicCongestionControlSetExemption = BbrCongestionControlSetExemption,
    .QuicCongestionControlReset = BbrCongestionControlReset,
    .QuicCongestionControlGetSendAllowance = BbrCongestionControlGetSendAllowance,
    .QuicCongestionControlGetCongestionWindow = BbrCongestionControlGetCongestionWindow,
    .QuicCongestionControlOnDataSent = BbrCongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = BbrCongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = BbrCongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = BbrCongestionControlOnDataLost,
    .QuicCongestionControlOnEcn = NULL,
    .QuicCongestionControlOnSpuriousCongestionEvent = BbrCongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = BbrCongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = BbrCongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = BbrCongestionControlGetBytesInFlightMax,
    .QuicCongestionControlIsAppLimited = BbrCongestionControlIsAppLimited,
    .QuicCongestionControlSetAppLimited = BbrCongestionControlSetAppLimited,
    .QuicCongestionControlGetNetworkStatistics = BbrCongestionControlGetNetworkStatistics
};

static
_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitializeInternal(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings,
    _In_ BOOLEAN UseBbrV3
    )
{
    *Cc = QuicCongestionControlBbr;
    Cc->Name = UseBbrV3 ? "BBRv3" : "BBR";
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    Bbr->InitialCongestionWindowPackets = Settings->InitialWindowPackets;
    Bbr->BbrVersion3 = UseBbrV3;
    Bbr->MaxAckHeightFilter = QuicSlidingWindowExtremumInitialize(
        kBbrMaxAckHeightFilterLen, kBbrDefaultFilterCapacity, Bbr->MaxAckHeightFilterEntries);
    Bbr->BandwidthFilter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(
        UseBbrV3 ? 1 : kBbrMaxBandwidthFilterLen,
        kBbrDefaultFilterCapacity, Bbr->BandwidthFilter.WindowedMaxFilterEntries);
    BbrCongestionControlReset(Cc, TRUE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    BbrCongestionControlInitializeInternal(Cc, Settings, FALSE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitializeV3(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    BbrCongestionControlInitializeInternal(Cc, Settings, TRUE);
}
