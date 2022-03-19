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

    BBR_STATE_PROBE_RTT,

    BBR_STATE_COUNT

} BBR_STATE;

typedef enum RECOVERY_STATE {

    RECOVERY_STATE_NOT_RECOVERY = 0,

    RECOVERY_STATE_CONSERVATIVE = 1,

    RECOVERY_STATE_GROWTH = 2,

} RECOVERY_STATE;

const uint64_t kLowPacingRateForSendQuantumBytesPerSecond = 1200ULL * 1000;

const uint64_t kHighPacingRateForSendQuantumBytesPerSecond = 24ULL * 1000 * 1000;

const uint64_t kQuantaFactor = 3;

const uint32_t kMinCwndInMssForBbr = 4;

const uint32_t kDefaultRecoveryCwndInMssForBbr = 2000;

const uint64_t kMicroSecsInSec = 1000000;

const uint64_t kMilliSecsInSec = 1000;

//
// Bandwidth is measured as (bytes/BW_UNIT) per second
//
#define BW_UNIT 8 // 1 << 3

#define BBR_UNIT 256 // 1 << 8

//
// Cwnd and pacing gain during STARSTUP
//
const uint32_t kStartupGain = BBR_UNIT * 2885 / 1000 + 1; // 2/ln(2)

const uint32_t kDrainGain = BBR_UNIT * 1000 / 2885; // 1/kStartupGain

//
// Cwnd gain during ProbeBw
//
const uint32_t kProbeBwGain = BBR_UNIT * 2;

//
// The expected of bandwidth growth in each round trip time during STARTUP
//
const uint32_t kExpectedStartupGrowth = BBR_UNIT * 5 / 4;

//
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kExpectedStartupGrowth
//
const uint8_t kStartupSlowGrowRoundLimit = 3;

//
// Number of pacing cycles
//
#define kNumOfCycles 8

//
// Pacing cycles
//
const uint32_t kPacingGainCycles[kNumOfCycles] = {
    BBR_UNIT * 5 / 4,
    BBR_UNIT * 3 / 4,
    BBR_UNIT, BBR_UNIT, BBR_UNIT,
    BBR_UNIT, BBR_UNIT, BBR_UNIT
};

//
// During ProbeRtt, we need to stay in low inflight condition for at least kProbeRttDuration.
//
const uint32_t kProbeRttDuration = 200 * 1000;

//
// Bandwidth WindowFilter length, in unit of RTT.
//
const uint32_t kBandwidthWindowLength = kNumOfCycles + 2;

//
// RTT Sampler default expiration
//
const uint32_t kDefaultRttSamplerExpirationInSecond = 10;

//
// 64K, used in sendQuantum calculation:
//
const uint64_t k64K = 64 * 1024;

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
BBR_RTT_SAMPLER
NewBbrRttSampler(
    _In_ uint64_t Expiration
    )
{
    BBR_RTT_SAMPLER sampler = {
        .RttSampleExpired = TRUE,
        .MinRttTimestampValid = FALSE,
        .Expiration = Expiration,
        .MinRtt = UINT32_MAX,
        .MinRttTimestamp = 0
    };

    return sampler;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrRttSamplerNewRttSample(
    _In_ BBR_RTT_SAMPLER* Sampler,
    _In_ uint32_t RttSample,
    _In_ uint64_t SampledTime
    )
{
    Sampler->RttSampleExpired = Sampler->MinRttTimestampValid ?
       CxPlatTimeAtOrBefore64(Sampler->MinRttTimestamp + Sampler->Expiration, SampledTime) :
       FALSE;

    if (Sampler->RttSampleExpired || Sampler->MinRtt > RttSample) {
        Sampler->MinRtt = RttSample;
        Sampler->MinRttTimestamp = SampledTime;
        Sampler->MinRttTimestampValid = TRUE;
        return TRUE;
    }

    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrBandwidthSamplerOnAppLimited(
    _In_ BBR_BANDWIDTH_SAMPLER* b
    )
{
    b->AppLimited = TRUE;
    b->AppLimitedExitTarget = CxPlatTimeUs64();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrBandwidthSamplerOnPacketAcked(
    _In_ BBR_BANDWIDTH_SAMPLER* b,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ uint64_t RttCounter
    )
{
    if (b->AppLimited &&
            CxPlatTimeAtOrBefore32((uint32_t)b->AppLimitedExitTarget, AckEvent->LargestAckedPacketSentTime)) {
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

        uint64_t SendRate = 0;
        uint64_t AckRate = 0;
        uint32_t AckDuration = 0;

        if (AckedPacket->Flags.HasLastAckedPacketInfo) {
            CXPLAT_DBG_ASSERT(AckedPacket->TotalBytesSentThen >= AckedPacket->LastAckedPacketInfo.TotalBytesSent);
            CXPLAT_DBG_ASSERT(CxPlatTimeAtOrBefore32(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime));

            SendRate = (kMicroSecsInSec * BW_UNIT *
                (AckedPacket->TotalBytesSentThen - AckedPacket->LastAckedPacketInfo.TotalBytesSent) /
                CxPlatTimeDiff32(AckedPacket->LastAckedPacketInfo.SentTime, AckedPacket->SentTime));

            if (!CxPlatTimeAtOrBefore32(
                    AckEvent->AdjustedAckTime,
                    AckedPacket->LastAckedPacketInfo.AdjustedAckTime)) {
                AckDuration = CxPlatTimeDiff32(AckedPacket->LastAckedPacketInfo.AdjustedAckTime, AckEvent->AdjustedAckTime);
            } else {
                AckDuration = CxPlatTimeDiff32(AckedPacket->LastAckedPacketInfo.AckTime, (uint32_t)TimeNow);
            }

            CXPLAT_DBG_ASSERT(AckEvent->TotalBytesAcked >= AckedPacket->LastAckedPacketInfo.TotalBytesAcked);
            AckRate = (kMicroSecsInSec * BW_UNIT *
                       (AckEvent->TotalBytesAcked - AckedPacket->LastAckedPacketInfo.TotalBytesAcked) /
                       AckDuration);
        } else if (CxPlatTimeAtOrBefore32(AckedPacket->SentTime, (uint32_t)TimeNow)) {
            SendRate = (kMicroSecsInSec * BW_UNIT *
                        AckEvent->TotalBytesAcked /
                        CxPlatTimeDiff32(AckedPacket->SentTime, (uint32_t)TimeNow));
        }

        uint64_t MeasuredBw = CXPLAT_MIN(SendRate, AckRate);

        if (MeasuredBw >= WindowedFilterGetBest(&b->WindowedFilter) ||
                !AckedPacket->Flags.IsAppLimited) {
            WindowedFilterUpdate(&b->WindowedFilter, MeasuredBw, RttCounter);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetMinRtt(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.MinRttSampler.MinRtt;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return WindowedFilterGetBest(&Cc->Bbr.BandwidthSampler.WindowedFilter);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetCongestionWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return Connection->Paths[0].Mtu * kMinCwndInMssForBbr;
    }

    if (Bbr->RecoveryState != RECOVERY_STATE_NOT_RECOVERY) {
        return CXPLAT_MIN(Bbr->CongestionWindow, Bbr->RecoveryWindow);
    }

    return Bbr->CongestionWindow;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t PickRandomCycle(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    uint32_t RandomValue = 0;
    CxPlatRandom(sizeof(uint32_t), &RandomValue);

    Bbr->PacingCycleIndex = (RandomValue % (kNumOfCycles - 1) + 2) % kNumOfCycles;
    CXPLAT_DBG_ASSERT(Bbr->PacingCycleIndex != 1);

    return Bbr->PacingCycleIndex;
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
    Bbr->CwndGain = kProbeBwGain;

    Bbr->PacingGain = kPacingGainCycles[PickRandomCycle(Cc)];
    Bbr->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->PacingGain = kStartupGain;
    Bbr->CwndGain = kStartupGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BandwidthSampler.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnLogBbr(
    _In_ QUIC_CONNECTION* const Connection
    )
{
    QUIC_CONGESTION_CONTROL* Cc = &Connection->CongestionControl;
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    UNREFERENCED_PARAMETER(Cc);
    UNREFERENCED_PARAMETER(Bbr);

    // TODO: make it `QuicTraceEvent`
    /*
    printf(
        "[conn][%p] BBR: CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%d\n",
        Connection,
        BbrCongestionControlGetCongestionWindow(Cc),
        Bbr->BytesInFlight,
        Bbr->BytesInFlightMax,
        BbrCongestionControlGetMinRtt(Cc),
        BbrCongestionControlGetBandwidth(Cc) / BW_UNIT,
        BbrCongestionControlIsAppLimited(Cc));
    fflush(stdout);
    */
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    return Bbr->BytesInFlight < CongestionWindow || Bbr->Exemptions > 0;
}

void
BbrCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    const QUIC_PATH* Path = &Connection->Paths[0];
    const QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    UNREFERENCED_PARAMETER(Connection);
    UNREFERENCED_PARAMETER(Path);
    UNREFERENCED_PARAMETER(Bbr);

    // TODO
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
    BbrCongestionControlLogOutFlowStatus(Cc);

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
        Bbr->ExitingQuiescene = TRUE;
    }

    Bbr->BytesInFlight += NumRetransmittableBytes;
    if (Bbr->BytesInFlightMax < Bbr->BytesInFlight) {
        Bbr->BytesInFlightMax = Bbr->BytesInFlight;
        QuicSendBufferConnectionAdjust(QuicCongestionControlGetConnection(Cc));
    }

    if (!Bbr->AckAggregationStartTimeValid) {
        Bbr->AckAggregationStartTime = CxPlatTimeUs64();
        Bbr->AckAggregationStartTimeValid = TRUE;
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
    _In_ uint32_t LargestAckedSentTime,
    _In_ uint64_t TimeNow
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    if (CxPlatTimeAtOrBefore32((uint32_t)Bbr->EndOfRoundTrip, LargestAckedSentTime)) {
        Bbr->RoundTripCounter++;
        Bbr->EndOfRoundTrip = TimeNow;
        return TRUE;
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlUpdateRecoveryWindowWithAck(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t BytesAcked
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    CXPLAT_DBG_ASSERT(Bbr->RecoveryState != RECOVERY_STATE_NOT_RECOVERY);

    if (Bbr->RecoveryState == RECOVERY_STATE_GROWTH) {
        Bbr->RecoveryWindow += BytesAcked;
    }

    Bbr->RecoveryWindow = CXPLAT_MAX(
        Bbr->RecoveryWindow, Bbr->BytesInFlight + BytesAcked);

    Bbr->RecoveryWindow = BbrCongestionControlBoundedCongestionWindow(
        Bbr->RecoveryWindow,
        Connection->Paths[0].Mtu,
        kMinCwndInMssForBbr);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlHandleAckInProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t AckTime)
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    BbrBandwidthSamplerOnAppLimited(&Bbr->BandwidthSampler);

    if (!Bbr->EarliestTimeToExitProbeRttValid &&
        Bbr->BytesInFlight < BbrCongestionControlGetCongestionWindow(Cc) + Connection->Paths[0].Mtu) {

        Bbr->EarliestTimeToExitProbeRtt = AckTime + kProbeRttDuration;
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
            Bbr->MinRttSampler.MinRttTimestamp = AckTime;
            Bbr->MinRttSampler.MinRttTimestampValid = TRUE;

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
        return 0;
    }

    uint64_t ExpectedAckBytes = BbrCongestionControlGetBandwidth(Cc) *
                                CxPlatTimeDiff64(Bbr->AckAggregationStartTime, AckEvent->TimeNow) /
                                kMicroSecsInSec /
                                BW_UNIT;

    //
    // Ack aggregation starts when we witness ack arrival rate being less than estimated bandwidth
    //
    if (Bbr->AggregatedAckBytes <= ExpectedAckBytes) {
        Bbr->AggregatedAckBytes = AckEvent->NumRetransmittableBytes;
        Bbr->AckAggregationStartTimeValid = TRUE;
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;

        return 0;
    }

    Bbr->AggregatedAckBytes += AckEvent->NumRetransmittableBytes;

    WindowedFilterUpdate(&Bbr->MaxAckHeightFilter,
        Bbr->AggregatedAckBytes - ExpectedAckBytes, Bbr->RoundTripCounter);

    return Bbr->AggregatedAckBytes - ExpectedAckBytes;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlCalculateTargetCwnd(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t Gain
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    uint64_t BandwidthEst = BbrCongestionControlGetBandwidth(Cc);
    uint64_t MinRttEst = BbrCongestionControlGetMinRtt(Cc);

    if (!BandwidthEst || MinRttEst == UINT32_MAX) {
        return (uint64_t)(Gain) * Bbr->InitialCongestionWindow / BBR_UNIT;
    }

    uint64_t Bdp = BandwidthEst * MinRttEst / kMicroSecsInSec / BW_UNIT;
    uint64_t TargetCwnd = (Bdp * Gain / BBR_UNIT) + (kQuantaFactor * Bbr->SendQuantum);
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
                BandwidthEst * Bbr->PacingGain * TimeSinceLastSend / BBR_UNIT,
                CongestionWindow * Bbr->PacingGain / BBR_UNIT - Bbr->BytesInFlight);
        } else {
            SendAllowance = (uint32_t)(BandwidthEst * Bbr->PacingGain * TimeSinceLastSend / BBR_UNIT);
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

    if (Bbr->PacingGain > BBR_UNIT && !HasLoss &&
        PrevInflightBytes < BbrCongestionControlCalculateTargetCwnd(Cc, Bbr->PacingGain)) {
        //
        // pacingGain_ > BBR_UNIT means BBR is probeing bandwidth. So we should let inflight bytes reach the target.
        //
        ShouldAdvancePacingGainCycle = FALSE;
    }

    if (Bbr->PacingGain < BBR_UNIT) {
        uint64_t TargetCwnd = BbrCongestionControlCalculateTargetCwnd(Cc, BBR_UNIT);
        if (Bbr->BytesInFlight <= TargetCwnd) {
            //
            // pacingGain_ < BBR_UNIT means BBR is draining the network queue. If inflight bytes is below
            // the target, then it's done.
            //
            ShouldAdvancePacingGainCycle = TRUE;
        }
    }

    if (ShouldAdvancePacingGainCycle) {
        Bbr->PacingCycleIndex = (Bbr->PacingCycleIndex + 1) % kNumOfCycles;
        Bbr->CycleStart = AckTime;
        Bbr->PacingGain = kPacingGainCycles[Bbr->PacingCycleIndex];
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlDetectShouldExitStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BbrState == BBR_STATE_STARTUP && Cc->Bbr.BtlbwFound;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlDetectBottleneckBandwidth(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN IsAppLimited
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    if (Bbr->BtlbwFound) {
        return;
    }

    if (IsAppLimited) {
        return;
    }

    uint64_t BandwidthTarget = (uint64_t)(Bbr->PreviousStartupBandwidth * kExpectedStartupGrowth / BBR_UNIT);
    uint64_t RealBandwidth = BbrCongestionControlGetBandwidth(Cc);

    if (RealBandwidth >= BandwidthTarget) {
        Bbr->PreviousStartupBandwidth = RealBandwidth;
        Bbr->SlowStartupRoundCounter = 0;
        return;
    }

    if (++Bbr->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
        Bbr->BtlbwFound = TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_PROBE_RTT;
    Bbr->PacingGain = BBR_UNIT;
    Bbr->EarliestTimeToExitProbeRttValid = FALSE;
    Bbr->ProbeRttRoundValid = FALSE;

    BbrBandwidthSamplerOnAppLimited(&Bbr->BandwidthSampler);

    Bbr->AppLimitedSinceProbeRtt = FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR* Bbr = &Cc->Bbr;

    Bbr->BbrState = BBR_STATE_DRAIN;
    Bbr->PacingGain = kDrainGain;
    Bbr->CwndGain = kStartupGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlShouldExitDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.BbrState == BBR_STATE_DRAIN &&
           Cc->Bbr.BytesInFlight <= BbrCongestionControlCalculateTargetCwnd(Cc, BBR_UNIT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlShouldProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_BBR *Bbr = &Cc->Bbr;
    if (Bbr->BbrState != BBR_STATE_PROBE_RTT
        && !Bbr->ExitingQuiescene
        && Bbr->MinRttSampler.RttSampleExpired) {

        return TRUE;

    }
    return FALSE;
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

    uint64_t Bandwidth = BbrCongestionControlGetBandwidth(Cc);

    uint64_t PacingRate = Bandwidth * Bbr->PacingGain / BBR_UNIT;

    if (PacingRate < kLowPacingRateForSendQuantumBytesPerSecond * BW_UNIT) {
        Bbr->SendQuantum = Connection->Paths[0].Mtu;
    } else if (PacingRate < kHighPacingRateForSendQuantumBytesPerSecond * BW_UNIT) {
        Bbr->SendQuantum = Connection->Paths[0].Mtu * 2;
    } else {
        Bbr->SendQuantum = CXPLAT_MIN(PacingRate * kMilliSecsInSec / BW_UNIT, k64K);
    }

    uint64_t TargetCwnd = BbrCongestionControlCalculateTargetCwnd(Cc, Bbr->CwndGain);
    if (Bbr->BtlbwFound) {
        TargetCwnd += WindowedFilterGetBest(&Bbr->MaxAckHeightFilter);
    }

    if (Bbr->BtlbwFound) {
        Bbr->CongestionWindow = (uint32_t)CXPLAT_MIN(TargetCwnd, Bbr->CongestionWindow + AckedBytes);
    } else if (Bbr->CongestionWindow < TargetCwnd || TotalBytesAcked < Bbr->InitialCongestionWindow) {
        Bbr->CongestionWindow += (uint32_t)AckedBytes;
    }

    Bbr->CongestionWindow = BbrCongestionControlBoundedCongestionWindow(
        Bbr->CongestionWindow,
        Connection->Paths[0].Mtu,
        kMinCwndInMssForBbr);

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

    if (AckEvent->IsImplicit) {
        BbrCongestionControlUpdateCongestionWindow(
            Cc, AckEvent->TotalBytesAcked, AckEvent->NumRetransmittableBytes);

        return BbrCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    }

    uint32_t PrevInflightBytes = Bbr->BytesInFlight;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    if (AckEvent->MinRttSampleValid) {
        BOOLEAN Updated = BbrRttSamplerNewRttSample(&Bbr->MinRttSampler, AckEvent->MinRttSample, AckEvent->TimeNow);
        if (Updated) {
            Bbr->AppLimitedSinceProbeRtt = FALSE;
        }
    }

    BOOLEAN NewRoundTrip = BbrCongestionControlUpdateRoundTripCounter(
        Cc, AckEvent->LargestAckedPacketSentTime, AckEvent->TimeNow);

    BOOLEAN LastAckedPacketAppLimited = AckEvent->AckedPackets == NULL ? FALSE : AckEvent->IsLargestAckedPacketAppLimited;

    BbrBandwidthSamplerOnPacketAcked(&Bbr->BandwidthSampler, AckEvent, Bbr->RoundTripCounter);

    if (Bbr->RecoveryState != RECOVERY_STATE_NOT_RECOVERY) {
        CXPLAT_DBG_ASSERT(Bbr->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (CxPlatTimeAtOrBefore32((uint32_t)Bbr->EndOfRecovery, AckEvent->LargestAckedPacketSentTime)) {
            Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
        } else {
            BbrCongestionControlUpdateRecoveryWindowWithAck(Cc, AckEvent->NumRetransmittableBytes);
        }
    }

    BbrCongestionControlUpdateAckAggregation(Cc, AckEvent);

    if (Bbr->BbrState == BBR_STATE_PROBE_BW) {
        BbrCongestionControlHandleAckInProbeBw(Cc, AckEvent->TimeNow, PrevInflightBytes, AckEvent->HasLoss);
    }

    if (NewRoundTrip && !LastAckedPacketAppLimited) {
        BbrCongestionControlDetectBottleneckBandwidth(Cc, LastAckedPacketAppLimited);
    }

    if (BbrCongestionControlDetectShouldExitStartup(Cc)) {
        BbrCongestionControlTransitToDrain(Cc);
    }

    if (BbrCongestionControlShouldExitDrain(Cc)) {
        BbrCongestionControlTransitToProbeBw(Cc, AckEvent->TimeNow);
    }

    if (BbrCongestionControlShouldProbeRtt(Cc)) {
        BbrCongestionControlTransitToProbeRtt(Cc);
    }

    Bbr->ExitingQuiescene = FALSE;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        BbrCongestionControlHandleAckInProbeRtt(Cc, NewRoundTrip, AckEvent->TimeNow);
    }

    BbrCongestionControlUpdateCongestionWindow(
        Cc, AckEvent->TotalBytesAcked, AckEvent->NumRetransmittableBytes);

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

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    Bbr->EndOfRecoveryValid = TRUE;
    Bbr->EndOfRecovery = CxPlatTimeUs64();

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    if (Bbr->RecoveryState != RECOVERY_STATE_NOT_RECOVERY) {
        Bbr->RecoveryState = RECOVERY_STATE_CONSERVATIVE;
        Bbr->RecoveryWindow = Bbr->BytesInFlight;
        Bbr->RecoveryWindow = BbrCongestionControlBoundedCongestionWindow(
            Bbr->RecoveryWindow,
            Connection->Paths[0].Mtu,
            kMinCwndInMssForBbr);

        Bbr->EndOfRoundTrip = CxPlatTimeUs64();
    }

    Bbr->RecoveryWindow =
        Bbr->RecoveryWindow > LossEvent->NumRetransmittableBytes + Connection->Paths[0].Mtu * kMinCwndInMssForBbr
        ? Bbr->RecoveryWindow - LossEvent->NumRetransmittableBytes
        : Connection->Paths[0].Mtu * kMinCwndInMssForBbr;

    if (LossEvent->PersistentCongestion) {
        Bbr->RecoveryWindow = Connection->Paths[0].Mtu * kMinCwndInMssForBbr;
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

    if (Bbr->BytesInFlight > BbrCongestionControlGetCongestionWindow(Cc)) {
        return;
    }

    Bbr->AppLimitedSinceProbeRtt = TRUE;
    BbrBandwidthSamplerOnAppLimited(&Bbr->BandwidthSampler);
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

    Bbr->CongestionWindow = Connection->Paths[0].Mtu * Bbr->InitialCongestionWindowPackets;
    Bbr->InitialCongestionWindow = Connection->Paths[0].Mtu * Bbr->InitialCongestionWindowPackets;
    Bbr->RecoveryWindow = Connection->Paths[0].Mtu * kDefaultRecoveryCwndInMssForBbr;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;

    if (FullReset) {
        Bbr->BytesInFlight = 0;
    }
    Bbr->Exemptions = 0;

    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->RoundTripCounter = 0;
    Bbr->CwndGain = kStartupGain;
    Bbr->PacingGain = kStartupGain;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->AppLimitedSinceProbeRtt = FALSE;
    Bbr->ExitingQuiescene = FALSE;
    Bbr->EndOfRoundTrip = 0;
    Bbr->PreviousStartupBandwidth = 0;

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = 0;
    Bbr->CycleStart = 0;

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EarliestTimeToExitProbeRttValid = FALSE;
    Bbr->EarliestTimeToExitProbeRtt = 0;

    Bbr->MinRttSampler = NewBbrRttSampler(kDefaultRttSamplerExpirationInSecond * kMicroSecsInSec);

    Bbr->MaxAckHeightFilter = NewWindowedFilter(kBandwidthWindowLength, 0, 0);

    Bbr->BandwidthSampler = (BBR_BANDWIDTH_SAMPLER) {
        .WindowedFilter = NewWindowedFilter(kBandwidthWindowLength, 0, 0),
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

    Bbr->InitialCongestionWindowPackets = Settings->InitialWindowPackets;

    Bbr->CongestionWindow = Connection->Paths[0].Mtu * Bbr->InitialCongestionWindowPackets;
    Bbr->InitialCongestionWindow = Connection->Paths[0].Mtu * Bbr->InitialCongestionWindowPackets;
    Bbr->RecoveryWindow = Connection->Paths[0].Mtu * kDefaultRecoveryCwndInMssForBbr;
    Bbr->BytesInFlightMax = Bbr->CongestionWindow / 2;

    Bbr->BytesInFlight = 0;
    Bbr->Exemptions = 0;

    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Bbr->BbrState = BBR_STATE_STARTUP;
    Bbr->RoundTripCounter = 0;
    Bbr->CwndGain = kStartupGain;
    Bbr->PacingGain = kStartupGain;
    Bbr->BtlbwFound = FALSE;
    Bbr->SendQuantum = 0;
    Bbr->SlowStartupRoundCounter = 0 ;

    Bbr->PacingCycleIndex = 0;
    Bbr->AggregatedAckBytes = 0;
    Bbr->AppLimitedSinceProbeRtt = FALSE;
    Bbr->ExitingQuiescene = FALSE;
    Bbr->EndOfRoundTrip = 0;
    Bbr->PreviousStartupBandwidth = 0;
    Bbr->CycleStart = 0;

    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = 0;

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

    Bbr->ProbeRttRoundValid = FALSE;
    Bbr->ProbeRttRound = 0;

    Bbr->EarliestTimeToExitProbeRttValid = FALSE;
    Bbr->EarliestTimeToExitProbeRtt = 0;

    Bbr->MinRttSampler = NewBbrRttSampler(kDefaultRttSamplerExpirationInSecond * kMicroSecsInSec);

    Bbr->MaxAckHeightFilter = NewWindowedFilter(kBandwidthWindowLength, 0, 0);

    Bbr->BandwidthSampler = (BBR_BANDWIDTH_SAMPLER) {
        .WindowedFilter = NewWindowedFilter(kBandwidthWindowLength, 0, 0),
        .AppLimited = FALSE,
        .AppLimitedExitTarget = 0,
    };

    BbrCongestionControlLogOutFlowStatus(Cc);
    QuicConnLogBbr(Connection);
}
