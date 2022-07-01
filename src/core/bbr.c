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
// Bandwidth is measured as (bytes / BW_UNIT) per second
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
// Bandwidth WindowFilter length, in unit of RTT
//
const uint32_t kBandwidthFilterLength = 10;

//
// RTT Stats default expiration
//
const uint32_t kRttStatsExpirationInSecond = 10;

_IRQL_requires_max_(DISPATCH_LEVEL)
WINDOWED_FILTER
NewWindowedFilter(
    _In_ uint32_t WindowLength,
    _In_ uint64_t ZeroValue,
    _In_ uint64_t ZeroTime
    )
{
    WINDOWED_FILTER w;
    w.WindowLength = WindowLength;
    w.ZeroValue = ZeroValue;

    w.Estimates[0].Sample = ZeroValue;
    w.Estimates[0].Time = ZeroTime;

    w.Estimates[1].Sample = ZeroValue;
    w.Estimates[1].Time = ZeroTime;

    w.Estimates[2].Sample = ZeroValue;
    w.Estimates[2].Time = ZeroTime;
    return w;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
WindowedFilterGetBest(
    _In_ const WINDOWED_FILTER* w
    )
{
    return w->Estimates[0].Sample;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
WindowedFilterReset(
    _In_ WINDOWED_FILTER* w,
    _In_ uint64_t NewSample,
    _In_ uint64_t NewTime
    )
{
    w->Estimates[0].Sample = w->Estimates[1].Sample = w->Estimates[2].Sample = NewSample;
    w->Estimates[0].Time = w->Estimates[1].Time = w->Estimates[2].Time = NewTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
WindowedFilterUpdate(
    _In_ WINDOWED_FILTER* w,
    _In_ uint64_t NewSample,
    _In_ uint64_t NewTime
    )
{
    if (w->Estimates[0].Sample == w->ZeroValue ||
        NewSample >= w->Estimates[0].Sample ||
        NewTime - w->Estimates[2].Time > w->WindowLength) {

        WindowedFilterReset(w, NewSample, NewTime);
        return;
    }

    if (NewSample >= w->Estimates[1].Sample) {
        w->Estimates[1].Sample = NewSample;
        w->Estimates[1].Time = NewTime;
        w->Estimates[2] = w->Estimates[1];
    } else if (NewSample >= w->Estimates[2].Sample) {
        w->Estimates[2].Sample = NewSample;
        w->Estimates[2].Time = NewTime;
    }

    if (NewTime - w->Estimates[0].Time > w->WindowLength) {
        w->Estimates[0] = w->Estimates[1];
        w->Estimates[1] = w->Estimates[2];
        w->Estimates[2].Sample = NewSample;
        w->Estimates[2].Time = NewTime;

        if (NewTime - w->Estimates[0].Time > w->WindowLength) {
            w->Estimates[0] = w->Estimates[1];
            w->Estimates[1] = w->Estimates[2];
        }
        return;
    }

    if (w->Estimates[1].Sample == w->Estimates[0].Sample &&
        NewTime - w->Estimates[1].Time > (w->WindowLength >> 2)) {

        w->Estimates[2].Sample = NewSample;
        w->Estimates[2].Time = NewTime;

        w->Estimates[1].Sample = NewSample;
        w->Estimates[1].Time = NewTime;
        return;

    }

    if (w->Estimates[2].Sample == w->Estimates[1].Sample &&
        NewTime - w->Estimates[2].Time > (w->WindowLength >> 1)) {

        w->Estimates[2].Sample = NewSample;
        w->Estimates[2].Time = NewTime;

    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BBR_RTT_STATS
NewBbrRttStats(
    _In_ uint64_t Expiration
    )
{
    BBR_RTT_STATS stats = {
        .RttSampleExpired = TRUE,
        .MinRttTimestampValid = FALSE,
        .Expiration = Expiration,
        .MinRtt = UINT32_MAX,
        .MinRttTimestamp = 0
    };

    return stats;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrRttStatsUpdate(
    _In_ BBR_RTT_STATS* Stats,
    _In_ uint32_t RttSample,
    _In_ uint64_t SampledTime
    )
{
    Stats->RttSampleExpired = Stats->MinRttTimestampValid ?
       CxPlatTimeAtOrBefore64(Stats->MinRttTimestamp + Stats->Expiration, SampledTime) :
       FALSE;

    if (Stats->RttSampleExpired || Stats->MinRtt > RttSample) {
        Stats->MinRtt = RttSample;
        Stats->MinRttTimestamp = SampledTime;
        Stats->MinRttTimestampValid = TRUE;
        return TRUE;
    }

    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrBandwidthFilterOnAppLimited(
    _In_ BBR_BANDWIDTH_FILTER* b,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    b->AppLimited = TRUE;
    b->AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrBandwidthFilterOnPacketAcked(
    _In_ BBR_BANDWIDTH_FILTER* b,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t RttCounter
    )
{
    if (b->AppLimited && b->AppLimitedExitTarget < AckEvent->LargestPacketNumberAcked) {
        b->AppLimited = FALSE;
    }

    uint64_t TimeNow = AckEvent->TimeNow;

    QUIC_SENT_PACKET_METADATA* AckedPacketsIterator = AckEvent->AckedPackets;
    while (AckedPacketsIterator != NULL) {
        QUIC_SENT_PACKET_METADATA* AckedPacket = AckedPacketsIterator;
        AckedPacketsIterator = AckedPacketsIterator->Next;

        if (AckedPacket->PacketLength == 0) {
            continue;
        }

        uint64_t SendRate = UINT64_MAX;
        uint64_t AckRate = UINT64_MAX;
        uint32_t AckElapsed = 0;
        uint32_t SendElapsed = 0;

        if (AckedPacket->Flags.HasLastAckedPacketInfo) {
            CXPLAT_DBG_ASSERT(AckedPacket->TotalBytesSent >= AckedPacket->LastAckedPacketInfo.TotalBytesSent);
            CXPLAT_DBG_ASSERT(CxPlatTimeAtOrBefore32(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime));
            
            SendElapsed = CxPlatTimeDiff32(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime);

            if (SendElapsed) {
                SendRate = (kMicroSecsInSec * BW_UNIT *
                    (AckedPacket->TotalBytesSent - AckedPacket->LastAckedPacketInfo.TotalBytesSent) /
                    SendElapsed);
            }

            if (!CxPlatTimeAtOrBefore32(AckEvent->AdjustedAckTime, AckedPacket->LastAckedPacketInfo.AdjustedAckTime)) {
                AckElapsed = CxPlatTimeDiff32(AckedPacket->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckElapsed = CxPlatTimeDiff32(AckedPacket->LastAckedPacketInfo.AckTime, (uint32_t)TimeNow);
            }

            CXPLAT_DBG_ASSERT(AckEvent->NumTotalAckedRetransmittableBytes >= AckedPacket->LastAckedPacketInfo.TotalBytesAcked);
            if (AckElapsed) {
                AckRate = (kMicroSecsInSec * BW_UNIT *
                           (AckEvent->NumTotalAckedRetransmittableBytes - AckedPacket->LastAckedPacketInfo.TotalBytesAcked) /
                           AckElapsed);
            }
        } else if (CxPlatTimeAtOrBefore32(AckedPacket->SentTime, (uint32_t)TimeNow)) {
            SendRate = (kMicroSecsInSec * BW_UNIT *
                        AckEvent->NumTotalAckedRetransmittableBytes /
                        CxPlatTimeDiff32(AckedPacket->SentTime, (uint32_t)TimeNow));
        }
        
        if (SendRate == UINT64_MAX && AckRate == UINT64_MAX) {
            continue;
        }

        uint64_t DeliveryRate = CXPLAT_MIN(SendRate, AckRate);

        if (DeliveryRate >= WindowedFilterGetBest(&b->WindowedFilter) ||
                !AckedPacket->Flags.IsAppLimited) {
            WindowedFilterUpdate(&b->WindowedFilter, DeliveryRate, RttCounter);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetMinRtt(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.MinRttStats.MinRtt;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return WindowedFilterGetBest(&Cc->Bbr.BandwidthFilter.WindowedFilter);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlInRecovery(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
)
{
    return Cc->Bbr.RecoveryState != RECOVERY_STATE_NOT_RECOVERY;
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
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return kMinCwndInMss * DatagramPayloadLength;
    }

    if (BbrCongestionControlInRecovery(Cc)) {
        return CXPLAT_MIN(Bbr->CongestionWindow, Bbr->RecoveryWindow);
    }

    return Bbr->CongestionWindow;
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

    uint32_t RandomValue = 0;
    CxPlatRandom(sizeof(uint32_t), &RandomValue);
    Bbr->PacingCycleIndex = (RandomValue % (GAIN_CYCLE_LENGTH - 1) + 2) % GAIN_CYCLE_LENGTH;
    CXPLAT_DBG_ASSERT(Bbr->PacingCycleIndex != 1);
    Bbr->PacingGain = kPacingGain[Bbr->PacingCycleIndex];

    Bbr->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.BbrState = BBR_STATE_STARTUP;
    Cc->Bbr.PacingGain = kHighGain;
    Cc->Bbr.CwndGain = kHighGain;
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
            BbrCongestionControlGetMinRtt(Cc),
            BbrCongestionControlGetBandwidth(Cc) / BW_UNIT,
            BbrCongestionControlIsAppLimited(Cc));
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
            ConnOutFlowStats,
            "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u",
            Connection,
            Connection->Stats.Send.TotalBytes,
            Bbr->BytesInFlight,
            Bbr->BytesInFlightMax,
            Bbr->CongestionWindow,
            0,
            Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
            Connection->SendBuffer.IdealBytes,
            Connection->SendBuffer.PostedBytes,
            Path->GotFirstRttSample ? Path->SmoothedRtt : 0);
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
uint32_t
BbrCongestionControlBoundedCongestionWindow(
    _In_ uint32_t CwndBytes,
    _In_ uint32_t PacketLength,
    _In_ uint32_t MinCwndInMss
    )
{
    return CXPLAT_MAX(CwndBytes, MinCwndInMss * PacketLength);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlUpdateRoundTripCounter(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberAcked,
    _In_ uint64_t LargestPacketNumberSent
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    if (!Bbr->EndOfRoundTripValid || Bbr->EndOfRoundTrip < LargestPacketNumberAcked) {
        Bbr->RoundTripCounter++;
        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LargestPacketNumberSent;
        return TRUE;
    }
    return FALSE;
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
        Bbr->RecoveryWindow += BytesAcked;
    }
    
    uint32_t RecoveryWindow = Bbr->RecoveryWindow;

    RecoveryWindow = CXPLAT_MAX(
        RecoveryWindow, Bbr->BytesInFlight + BytesAcked);


    Bbr->RecoveryWindow = BbrCongestionControlBoundedCongestionWindow(
        RecoveryWindow,
        DatagramPayloadLength,
        kMinCwndInMss);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlHandleAckInProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t LargestSentPacketNumber,
    _In_ uint64_t AckTime)
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    BbrBandwidthFilterOnAppLimited(&Bbr->BandwidthFilter, LargestSentPacketNumber);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (!Bbr->EarliestTimeToExitProbeRttValid &&
        Bbr->BytesInFlight < BbrCongestionControlGetCongestionWindow(Cc) + DatagramPayloadLength) {

        Bbr->EarliestTimeToExitProbeRtt = AckTime + kProbeRttTimeInUs;
        Bbr->EarliestTimeToExitProbeRttValid = TRUE;

        Bbr->ProbeRttRoundValid = FALSE;

        return;
    }

    if (Bbr->EarliestTimeToExitProbeRttValid) {

        if (!Bbr->ProbeRttRoundValid && NewRoundTrip) {
            Bbr->ProbeRttRoundValid = TRUE;
            Bbr->ProbeRttRound = Bbr->RoundTripCounter;
        }

        if (Bbr->ProbeRttRoundValid && CxPlatTimeAtOrBefore64(Bbr->EarliestTimeToExitProbeRtt, AckTime)) {
            Bbr->MinRttStats.MinRttTimestamp = AckTime;
            Bbr->MinRttStats.MinRttTimestampValid = TRUE;

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
    // Reset current ack aggregation status when we witness ack arrival rate being less or equal than estimated bandwidth
    //
    if (Bbr->AggregatedAckBytes <= ExpectedAckBytes) {
        Bbr->AggregatedAckBytes = AckEvent->NumRetransmittableBytes;
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr->AckAggregationStartTimeValid = TRUE;

        return 0;
    }

    Bbr->AggregatedAckBytes += AckEvent->NumRetransmittableBytes;

    WindowedFilterUpdate(&Bbr->MaxAckHeightFilter,
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
    uint64_t MinRttEst = BbrCongestionControlGetMinRtt(Cc);

    if (!BandwidthEst || MinRttEst == UINT32_MAX) {
        return (uint64_t)(Gain) * Bbr->InitialCongestionWindow / GAIN_UNIT;
    }

    uint64_t Bdp = BandwidthEst * MinRttEst / kMicroSecsInSec / BW_UNIT;
    uint64_t TargetCwnd = (Bdp * Gain / GAIN_UNIT) + (kQuantaFactor * Bbr->SendQuantum);
    return (uint32_t)TargetCwnd;
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
    uint64_t MinRttEst = BbrCongestionControlGetMinRtt(Cc);
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
        MinRttEst == UINT32_MAX ||
        MinRttEst < MS_TO_US(QUIC_SEND_PACING_INTERVAL)) {
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
        if (Bbr->BbrState == BBR_STATE_STARTUP) {
            SendAllowance = (uint32_t)CXPLAT_MAX(
                BandwidthEst * Bbr->PacingGain * TimeSinceLastSend / GAIN_UNIT,
                CongestionWindow * Bbr->PacingGain / GAIN_UNIT - Bbr->BytesInFlight);
        } else {
            SendAllowance = (uint32_t)(BandwidthEst * Bbr->PacingGain * TimeSinceLastSend / GAIN_UNIT);
        }

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
BbrCongestionControlHandleAckInProbeBw(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t AckTime,
    _In_ uint64_t PrevInflightBytes,
    _In_ BOOLEAN HasLoss
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    BOOLEAN ShouldAdvancePacingGainCycle =
        CxPlatTimeDiff64(AckTime, Bbr->CycleStart) > BbrCongestionControlGetMinRtt(Cc);

    if (Bbr->PacingGain > GAIN_UNIT && !HasLoss &&
        PrevInflightBytes < BbrCongestionControlGetTargetCwnd(Cc, Bbr->PacingGain)) {
        //
        // pacingGain > GAIN_UNIT means BBR is probeing bandwidth. So we should let inflight bytes reach the target.
        //
        ShouldAdvancePacingGainCycle = FALSE;
    }

    if (Bbr->PacingGain < GAIN_UNIT) {
        uint64_t TargetCwnd = BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT);
        if (Bbr->BytesInFlight <= TargetCwnd) {
            //
            // pacingGain < GAIN_UNIT means BBR is draining the network queue. If inflight bytes is below
            // the target, then it's done.
            //
            ShouldAdvancePacingGainCycle = TRUE;
        }
    }

    if (ShouldAdvancePacingGainCycle) {
        Bbr->PacingCycleIndex = (Bbr->PacingCycleIndex + 1) % GAIN_CYCLE_LENGTH;
        Bbr->CycleStart = AckTime;
        Bbr->PacingGain = kPacingGain[Bbr->PacingCycleIndex];
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberSent
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_PROBE_RTT;
    Bbr->PacingGain = GAIN_UNIT;
    Bbr->EarliestTimeToExitProbeRttValid = FALSE;
    Bbr->ProbeRttRoundValid = FALSE;

    BbrBandwidthFilterOnAppLimited(&Bbr->BandwidthFilter, LargestPacketNumberSent);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.BbrState = BBR_STATE_DRAIN;
    Cc->Bbr.PacingGain = kDrainGain;
    Cc->Bbr.CwndGain = kHighGain;
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
        Bbr->SendQuantum = CXPLAT_MIN(PacingRate * kMilliSecsInSec / BW_UNIT, 64 * 1024 /* 64k */);
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
        TargetCwnd += WindowedFilterGetBest(&Bbr->MaxAckHeightFilter);
    }
    
    uint32_t CongestionWindow = Bbr->CongestionWindow;

    if (Bbr->BtlbwFound) {
        CongestionWindow = (uint32_t)CXPLAT_MIN(TargetCwnd, CongestionWindow + AckedBytes);
    } else if (CongestionWindow < TargetCwnd || TotalBytesAcked < Bbr->InitialCongestionWindow) {
        CongestionWindow += (uint32_t)AckedBytes;
    }

    Bbr->CongestionWindow = BbrCongestionControlBoundedCongestionWindow(
        CongestionWindow,
        DatagramPayloadLength,
        kMinCwndInMss);

    QuicConnLogBbr(QuicCongestionControlGetConnection(Cc));
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
        BbrCongestionControlUpdateCongestionWindow(
            Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

        return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    }

    uint32_t PrevInflightBytes = Bbr->BytesInFlight;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    if (AckEvent->MinRttSampleValid) {
        BbrRttStatsUpdate(&Bbr->MinRttStats, AckEvent->MinRttSample, AckEvent->TimeNow);
    }

    BOOLEAN NewRoundTrip = BbrCongestionControlUpdateRoundTripCounter(
        Cc, AckEvent->LargestPacketNumberAcked, AckEvent->LargestPacketNumberSent);

    BOOLEAN LastAckedPacketAppLimited =
        AckEvent->AckedPackets == NULL ? FALSE : AckEvent->IsLargestAckedPacketAppLimited;

    BbrBandwidthFilterOnPacketAcked(&Bbr->BandwidthFilter, AckEvent, Bbr->RoundTripCounter);

    if (BbrCongestionControlInRecovery(Cc)) {
        CXPLAT_DBG_ASSERT(Bbr->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (!AckEvent->HasLoss && Bbr->EndOfRecovery < AckEvent->LargestPacketNumberAcked) {
            Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
            QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
        } else {
            BbrCongestionControlUpdateRecoveryWindow(Cc, AckEvent->NumRetransmittableBytes);
        }
    }

    BbrCongestionControlUpdateAckAggregation(Cc, AckEvent);

    if (Bbr->BbrState == BBR_STATE_PROBE_BW) {
        BbrCongestionControlHandleAckInProbeBw(Cc, AckEvent->TimeNow, PrevInflightBytes, AckEvent->HasLoss);
    }

    if (!Bbr->BtlbwFound && NewRoundTrip && !LastAckedPacketAppLimited) {
        uint64_t BandwidthTarget = (uint64_t)(Bbr->LastEstimatedStartupBandwidth * kStartupGrowthTarget / GAIN_UNIT);
        uint64_t RealBandwidth = BbrCongestionControlGetBandwidth(Cc);

        if (RealBandwidth >= BandwidthTarget) {
            Bbr->LastEstimatedStartupBandwidth = RealBandwidth;
            Bbr->SlowStartupRoundCounter = 0;
        } else if (++Bbr->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
            Bbr->BtlbwFound = TRUE;
        }
    }

    //
    // Should exit STARTUP state
    //
    if (Bbr->BbrState == BBR_STATE_STARTUP && Bbr->BtlbwFound) {
        BbrCongestionControlTransitToDrain(Cc);
    }

    //
    // Should exit DRAIN state
    //
    if (Bbr->BbrState == BBR_STATE_DRAIN &&
           Bbr->BytesInFlight <= BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT)) {
        BbrCongestionControlTransitToProbeBw(Cc, AckEvent->TimeNow);
    }

    if (Bbr->BbrState != BBR_STATE_PROBE_RTT &&
        !Bbr->ExitingQuiescence &&
        Bbr->MinRttStats.RttSampleExpired) {
        BbrCongestionControlTransitToProbeRtt(Cc, AckEvent->LargestPacketNumberSent);
    }

    Bbr->ExitingQuiescence = FALSE;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        BbrCongestionControlHandleAckInProbeRtt(
            Cc, NewRoundTrip, AckEvent->LargestPacketNumberSent, AckEvent->TimeNow);
    }

    BbrCongestionControlUpdateCongestionWindow(
        Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

    return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
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
        ConnCongestion,
        "[conn][%p] Congestion event",
        Connection);
    Connection->Stats.Send.CongestionCount++;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);
    
    CXPLAT_DBG_ASSERT(LossEvent->NumRetransmittableBytes > 0);

    Bbr->EndOfRecoveryValid = TRUE;
    Bbr->EndOfRecovery = LossEvent->LargestPacketNumberSent;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;
    
    uint32_t RecoveryWindow = Bbr->RecoveryWindow;

    if (!BbrCongestionControlInRecovery(Cc)) {
        Bbr->RecoveryState = RECOVERY_STATE_CONSERVATIVE;
        RecoveryWindow = Bbr->BytesInFlight;
        RecoveryWindow = BbrCongestionControlBoundedCongestionWindow(
            RecoveryWindow,
            DatagramPayloadLength,
            kMinCwndInMss);

        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LossEvent->LargestPacketNumberSent;
    }

    if (LossEvent->PersistentCongestion) {
        Bbr->RecoveryWindow = kMinCwndInMss * DatagramPayloadLength;

        QuicTraceEvent(
            ConnPersistentCongestion,
            "[conn][%p] Persistent congestion event",
            Connection);
        Connection->Stats.Send.PersistentCongestionCount++;
    } else {
        Bbr->RecoveryWindow =
            RecoveryWindow > LossEvent->NumRetransmittableBytes + kMinCwndInMss * DatagramPayloadLength
            ? RecoveryWindow - LossEvent->NumRetransmittableBytes
            : kMinCwndInMss * DatagramPayloadLength;
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
    UNREFERENCED_PARAMETER(Cc);
    return FALSE;
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

    BbrBandwidthFilterOnAppLimited(&Bbr->BandwidthFilter, LargestSentPacketNumber);
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
    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->RoundTripCounter = 0;
    Bbr->CwndGain = kHighGain;
    Bbr->PacingGain = kHighGain;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->ExitingQuiescence = FALSE;
    Bbr->LastEstimatedStartupBandwidth = 0;

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = CxPlatTimeUs64();
    Bbr->CycleStart = 0;

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EndOfRoundTripValid = FALSE;
    Bbr->EndOfRoundTrip = 0;

    Bbr->EarliestTimeToExitProbeRttValid = FALSE;
    Bbr->EarliestTimeToExitProbeRtt = CxPlatTimeUs64();

    Bbr->MinRttStats = NewBbrRttStats(kRttStatsExpirationInSecond * kMicroSecsInSec);

    Bbr->MaxAckHeightFilter = NewWindowedFilter(kBandwidthFilterLength, 0, 0);

    Bbr->BandwidthFilter = (BBR_BANDWIDTH_FILTER) {
        .WindowedFilter = NewWindowedFilter(kBandwidthFilterLength, 0, 0),
        .AppLimited = FALSE,
        .AppLimitedExitTarget = 0,
    };

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
    .QuicCongestionControlOnSpuriousCongestionEvent = BbrCongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = BbrCongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = BbrCongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = BbrCongestionControlGetBytesInFlightMax,
    .QuicCongestionControlIsAppLimited = BbrCongestionControlIsAppLimited,
    .QuicCongestionControlSetAppLimited = BbrCongestionControlSetAppLimited,
};

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    *Cc = QuicCongestionControlBbr;

    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    Bbr->InitialCongestionWindowPackets = Settings->InitialWindowPackets;

    Bbr->CongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->InitialCongestionWindow = Bbr->InitialCongestionWindowPackets * DatagramPayloadLength;
    Bbr->RecoveryWindow = kDefaultRecoveryCwndInMss * DatagramPayloadLength;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;

    Bbr->BytesInFlight = 0;
    Bbr->Exemptions = 0;

    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->RoundTripCounter = 0;
    Bbr->CwndGain = kHighGain;
    Bbr->PacingGain = kHighGain;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->ExitingQuiescence = FALSE;
    Bbr->LastEstimatedStartupBandwidth = 0;
    Bbr->CycleStart = 0;

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = CxPlatTimeUs64();

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;
    
    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EndOfRoundTripValid = FALSE;
    Bbr->EndOfRoundTrip = 0;

    Bbr->EarliestTimeToExitProbeRttValid = FALSE;
    Bbr->EarliestTimeToExitProbeRtt = 0;

    Bbr->MinRttStats = NewBbrRttStats(kRttStatsExpirationInSecond * kMicroSecsInSec);

    Bbr->MaxAckHeightFilter = NewWindowedFilter(kBandwidthFilterLength, 0, 0);

    Bbr->BandwidthFilter = (BBR_BANDWIDTH_FILTER) {
        .WindowedFilter = NewWindowedFilter(kBandwidthFilterLength, 0, 0),
        .AppLimited = FALSE,
        .AppLimitedExitTarget = 0,
    };

    QuicConnLogOutFlowStats(Connection);
    QuicConnLogBbr(Connection);
}
