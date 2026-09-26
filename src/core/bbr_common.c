/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "bbr_common.c.clog.h"
#endif

static const uint64_t kQuantaFactor = 3;

const uint32_t kMinCwndInMss = 4;

static const uint32_t kDefaultRecoveryCwndInMss = 2000;

static const uint64_t kMicroSecsInSec = 1000000;

static const uint64_t kMilliSecsInSec = 1000;

static const uint64_t kLowPacingRateThresholdBytesPerSecond = 1200ULL * 1000;

static const uint64_t kHighPacingRateThresholdBytesPerSecond = 24ULL * 1000 * 1000;

//
// Cwnd gain during ProbeBw
//
const uint32_t kCwndGain = GAIN_UNIT * 2;

//
// The expected of bandwidth growth in each round trip time during STARTUP
//
static const uint32_t kStartupGrowthTarget = GAIN_UNIT * 5 / 4;

//
// How many rounds of rtt to stay in STARTUP when the bandwidth isn't growing as
// fast as kStartupGrowthTarget
//
const uint8_t kStartupSlowGrowRoundLimit = 3;

//
// During ProbeRtt, we need to stay in low inflight condition for at least kProbeRttTimeInUs
//
const uint32_t kProbeRttTimeInUs = 200 * 1000;

//
// Time until a MinRtt measurement is expired.
//
const uint32_t kBbrMinRttExpirationInMicroSecs = S_TO_US(10);

static const uint32_t kBbrMaxAckHeightFilterLen = 10;

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
BbrGetBandwidth(
    _In_ const BBR_COMMON* Bbr
    )
{
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = (QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY) { .Value = 0, .Time = 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Bbr->BandwidthFilter.WindowedMaxFilter, &Entry);
    if (QUIC_SUCCEEDED(Status)) {
        return Entry.Value;
    }
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrGetBdp(
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth
    )
{
    uint64_t BytesPerSecond = Bandwidth / BW_UNIT;
    uint64_t Rtt = Bbr->MinRtt;
    uint64_t Whole = BytesPerSecond / kMicroSecsInSec;
    uint64_t Remainder = BytesPerSecond % kMicroSecsInSec;
    if ((Whole && Rtt > UINT32_MAX / Whole) ||
        (Remainder && Rtt > UINT64_MAX / Remainder)) {
        return UINT32_MAX;
    }
    return (uint32_t)CXPLAT_MIN(Whole * Rtt + Remainder * Rtt / kMicroSecsInSec, UINT32_MAX);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrUpdateBottleneckBandwidth(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth
    )
{
    uint64_t BandwidthTarget = Bbr->LastEstimatedStartupBandwidth * kStartupGrowthTarget / GAIN_UNIT;
    if (Bandwidth >= BandwidthTarget) {
        Bbr->LastEstimatedStartupBandwidth = Bandwidth;
        Bbr->SlowStartupRoundCounter = 0;
    } else if (++Bbr->SlowStartupRoundCounter >= kStartupSlowGrowRoundLimit) {
        Bbr->BtlbwFound = TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrUpdateRecoveryWindow(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint16_t DatagramPayloadLength,
    _In_ uint32_t BytesAcked
    )
{
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
uint64_t
BbrUpdateAckAggregation(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ const struct QUIC_ACK_EVENT* AckEvent
    )
{
    if (!Bbr->AckAggregationStartTimeValid) {
        Bbr->AckAggregationStartTime = AckEvent->TimeNow;
        Bbr->AckAggregationStartTimeValid = TRUE;
        return 0;
    }

    uint64_t ExpectedAckBytes = Bandwidth *
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
BbrGetTargetCwnd(
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ uint32_t Gain
    )
{
    if (!Bandwidth || !Bbr->MinRttTimestampValid) {
        return (uint32_t)CXPLAT_MIN((uint64_t)Gain * Bbr->InitialCongestionWindow / GAIN_UNIT, UINT32_MAX);
    }

    uint64_t Bdp = BbrGetBdp(Bbr, Bandwidth);
    uint64_t TargetCwnd = (Bdp * Gain / GAIN_UNIT) + (kQuantaFactor * Bbr->SendQuantum);
    return (uint32_t)CXPLAT_MIN(TargetCwnd, UINT32_MAX);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrGetSendAllowance(
    _In_ const BBR_COMMON* Bbr,
    _In_ const QUIC_CONNECTION* Connection,
    _In_ uint64_t Bandwidth,
    _In_ uint32_t CongestionWindow,
    _In_ uint64_t TimeSinceLastSend,
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
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
        uint64_t PacingRate = Bandwidth / BW_UNIT * Bbr->PacingGain / GAIN_UNIT;
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
BbrSetSendQuantum(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ uint16_t DatagramPayloadLength
    )
{
    uint64_t PacingRate = Bandwidth * Bbr->PacingGain / GAIN_UNIT;

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
BbrUpdateCongestionWindow(
    _Inout_ BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _In_ uint16_t DatagramPayloadLength,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    )
{
    BbrSetSendQuantum(Bbr, Bandwidth, DatagramPayloadLength);

    uint64_t TargetCwnd = BbrGetTargetCwnd(Bbr, Bandwidth, Bbr->CwndGain);
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
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrReset(
    _Inout_ BBR_COMMON* Bbr,
    _In_ BOOLEAN FullReset,
    _In_ uint16_t DatagramPayloadLength
    )
{
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

    Bbr->AggregatedAckBytes = 0;
    Bbr->ExitingQuiescence = FALSE;
    Bbr->LastEstimatedStartupBandwidth = 0;
    Bbr->AckAggregationStartTimeValid = FALSE;
    Bbr->AckAggregationStartTime = CxPlatTimeUs64();
    Bbr->CycleStart = 0;

    Bbr->EndOfRecoveryValid = FALSE;
    Bbr->EndOfRecovery = 0;

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
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrInitialize(
    _Inout_ BBR_COMMON* Bbr,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings,
    _In_ uint32_t BandwidthFilterLength
    )
{
    Bbr->InitialCongestionWindowPackets = Settings->InitialWindowPackets;
    Bbr->MaxAckHeightFilter = QuicSlidingWindowExtremumInitialize(
        kBbrMaxAckHeightFilterLen, kBbrDefaultFilterCapacity, Bbr->MaxAckHeightFilterEntries);
    Bbr->BandwidthFilter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(
        BandwidthFilterLength, kBbrDefaultFilterCapacity, Bbr->BandwidthFilter.WindowedMaxFilterEntries);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicConnLogOutFlowStats(Connection);

    if (PreviousCanSendState != QuicCongestionControlCanSend(Cc)) {
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
void
BbrOnDataSent(
    _Inout_ BBR_COMMON* Bbr,
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    Bbr->BytesInFlight += NumRetransmittableBytes;
    if (Bbr->BytesInFlightMax < Bbr->BytesInFlight) {
        Bbr->BytesInFlightMax = Bbr->BytesInFlight;
        QuicSendBufferConnectionAdjust(Connection);
    }

    if (Bbr->Exemptions > 0) {
        --Bbr->Exemptions;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogState(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth
    )
{
    QuicTraceEvent(
        ConnBbr,
        "[conn][%p] BBR: State=%u RState=%u CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%u",
        Connection,
        Bbr->BbrState,
        Bbr->RecoveryState,
        QuicCongestionControlGetCongestionWindow(&Connection->CongestionControl),
        Bbr->BytesInFlight,
        Bbr->BytesInFlightMax,
        Bbr->MinRtt,
        Bandwidth / BW_UNIT,
        Bbr->BandwidthFilter.AppLimited);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogOutFlowStatus(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const BBR_COMMON* Bbr
    )
{
    const QUIC_PATH* Path = &Connection->Paths[0];

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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrGetNetworkStatistics(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const BBR_COMMON* Bbr,
    _In_ uint64_t Bandwidth,
    _Out_ struct QUIC_NETWORK_STATISTICS* NetworkStatistics
    )
{
    const QUIC_PATH* Path = &Connection->Paths[0];

    NetworkStatistics->BytesInFlight = Bbr->BytesInFlight;
    NetworkStatistics->PostedBytes = Connection->SendBuffer.PostedBytes;
    NetworkStatistics->IdealBytes = Connection->SendBuffer.IdealBytes;
    NetworkStatistics->SmoothedRTT = Path->SmoothedRtt;
    NetworkStatistics->CongestionWindow = QuicCongestionControlGetCongestionWindow(&Connection->CongestionControl);
    NetworkStatistics->Bandwidth = Bandwidth / BW_UNIT;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrIndicateConnectionEvent(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_NETWORK_STATISTICS;

    Cc->QuicCongestionControlGetNetworkStatistics(Connection, Cc, &Event.NETWORK_STATISTICS);

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
void
BbrLogRecoveryExit(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnRecoveryExit,
        "[conn][%p] Recovery complete",
        Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogCongestion(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnCongestionV2,
        "[conn][%p] Congestion event: IsEcn=%hu",
        Connection,
        FALSE);
    Connection->Stats.Send.CongestionCount++;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrLogPersistentCongestion(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnPersistentCongestion,
        "[conn][%p] Persistent congestion event",
        Connection);
    Connection->Stats.Send.PersistentCongestionCount++;
}
