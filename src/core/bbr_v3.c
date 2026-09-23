/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrV3CongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return CXPLAT_MIN(BbrGetBandwidth(&Cc->BbrV3.Common), Cc->BbrV3.Model.BandwidthLow);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrV3CongestionControlInRecovery(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
)
{
    return Cc->BbrV3.Common.RecoveryState != RECOVERY_STATE_NOT_RECOVERY;
}

static
uint32_t
BbrV3InflightWithHeadroom(
    _In_ const QUIC_CONGESTION_CONTROL_BBR_V3* BbrV3
    )
{
    return BbrV3->Model.InflightHigh == UINT32_MAX ? UINT32_MAX :
        (uint32_t)((uint64_t)BbrV3->Model.InflightHigh * 85 / 100);
}

static
void
BbrV3StartPhase(
    _In_ QUIC_CONGESTION_CONTROL_BBR_V3* BbrV3,
    _In_ BBR_V3_PHASE Phase,
    _In_ uint64_t TimeNow,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    BBR_COMMON* Bbr = &BbrV3->Common;
    BbrV3->Model.Phase = Phase;
    BbrV3->Model.ProbeRound = Bbr->RoundTripCounter;
    Bbr->PacingGain = GAIN_UNIT;
    if (Phase == BBR_V3_PHASE_DOWN) {
        uint32_t RandomValue = 0;
        CxPlatRandom(sizeof(RandomValue), &RandomValue);
        BbrV3->Model.ProbeWait = S_TO_US(2) + RandomValue % S_TO_US(1);
        Bbr->CycleStart = TimeNow;
        BbrV3->Model.ProbeEndPacketNumber = LargestSentPacketNumber;
        BbrV3->Model.AwaitingProbeFeedback = TRUE;
        Bbr->PacingGain = GAIN_UNIT * 9 / 10;
        BbrV3->Model.LossInRound = FALSE;
    } else if (Phase == BBR_V3_PHASE_REFILL) {
        BbrV3->Model.InflightLow = UINT32_MAX;
        BbrV3->Model.BandwidthLow = UINT64_MAX;
        BbrV3->Model.LossInRound = FALSE;
        BbrV3->Model.BandwidthLatest = 0;
        BbrV3->Model.InflightLatest = 0;
        BbrV3->Model.ProbeUpAcked = 0;
        BbrV3->Model.ProbeUpCount = CXPLAT_MAX(Bbr->CongestionWindow, 1);
        BbrV3->Model.ProbeSamples = FALSE;
        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LargestSentPacketNumber;
    } else if (Phase == BBR_V3_PHASE_UP) {
        Bbr->PacingGain = GAIN_UNIT * 5 / 4;
        BbrV3->Model.ProbeSamples = TRUE;
        BbrV3->Model.ProbeStartPacketNumber = LargestSentPacketNumber + 1;
        BbrV3->Model.AwaitingProbeFeedback = FALSE;
        Bbr->LastEstimatedStartupBandwidth = 0;
        Bbr->SlowStartupRoundCounter = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrV3CongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): False positive: embedded Cc is valid.
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;
    uint32_t CongestionWindow = Bbr->CongestionWindow;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        if (!Bbr->MinRttTimestampValid) {
            return MinCongestionWindow;
        }
        uint32_t ProbeWindow = BbrGetBdp(Bbr, BbrV3CongestionControlGetBandwidth(Cc)) / 2;
        CongestionWindow = (uint32_t)CXPLAT_MAX(MinCongestionWindow, CXPLAT_MIN(CongestionWindow, ProbeWindow));
    }

    uint32_t InflightHigh = Cc->BbrV3.Model.InflightHigh;
    if (Bbr->BbrState == BBR_STATE_PROBE_RTT ||
        (Bbr->BbrState == BBR_STATE_PROBE_BW && Cc->BbrV3.Model.Phase == BBR_V3_PHASE_CRUISE)) {
        InflightHigh = BbrV3InflightWithHeadroom(&Cc->BbrV3);
    }
    CongestionWindow = CXPLAT_MAX(MinCongestionWindow,
        CXPLAT_MIN(CongestionWindow, CXPLAT_MIN(InflightHigh, Cc->BbrV3.Model.InflightLow)));
    if (BbrV3CongestionControlInRecovery(Cc)) {
        return CXPLAT_MIN(CongestionWindow, Bbr->RecoveryWindow);
    }

    return CongestionWindow;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlTransitToProbeBw(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t CongestionEventTime
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    Bbr->BbrState = BBR_STATE_PROBE_BW;
    Bbr->CwndGain = kCwndGain;

    BbrV3StartPhase(&Cc->BbrV3, BBR_V3_PHASE_DOWN, CongestionEventTime,
        QuicCongestionControlGetConnection(Cc)->LossDetection.LargestSentPacketNumber);

    Bbr->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->BbrV3.Common.BbrState = BBR_STATE_STARTUP;
    Cc->BbrV3.Common.PacingGain = GAIN_UNIT * 277 / 100;
    Cc->BbrV3.Common.CwndGain = kCwndGain;
    Cc->BbrV3.Model.ProbeSamples = TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrV3CongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->BbrV3.Common.BandwidthFilter.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlGetNetworkStatistics(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _Out_ QUIC_NETWORK_STATISTICS* NetworkStatistics
    )
{
    BbrGetNetworkStatistics(Connection, &Cc->BbrV3.Common, BbrV3CongestionControlGetBandwidth(Cc), NetworkStatistics);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrV3CongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    uint32_t CongestionWindow = BbrV3CongestionControlGetCongestionWindow(Cc);
    return Cc->BbrV3.Common.BytesInFlight < CongestionWindow || Cc->BbrV3.Common.Exemptions > 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    BbrLogOutFlowStatus(QuicCongestionControlGetConnection(Cc), &Cc->BbrV3.Common);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrV3CongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->BbrV3.Common.BytesInFlightMax;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
BbrV3CongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->BbrV3.Common.Exemptions;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->BbrV3.Common.Exemptions = NumPackets;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    BOOLEAN PreviousCanSendState = BbrV3CongestionControlCanSend(Cc);

    if (!Bbr->BytesInFlight && BbrV3CongestionControlIsAppLimited(Cc)) {
        Bbr->ExitingQuiescence = TRUE;
        Bbr->AckAggregationStartTimeValid = FALSE;
        Bbr->AggregatedAckBytes = 0;
    }

    BbrOnDataSent(Bbr, QuicCongestionControlGetConnection(Cc), NumRetransmittableBytes);

    BbrUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlOnPacketSent(
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _Inout_ QUIC_SENT_PACKET_METADATA* Packet
    )
{
    Packet->Flags.IsBbrProbe = FALSE;
    Packet->InflightAtSend = 0;
    Packet->TotalBytesLost = 0;
    // Settings can be changed while the active controller stays the same.
    if (Cc->QuicCongestionControlOnDataSent == BbrV3CongestionControlOnDataSent) {
        Packet->InflightAtSend = Cc->BbrV3.Common.BytesInFlight;
        Packet->TotalBytesLost = Cc->BbrV3.Model.TotalBytesLost;
        Packet->Flags.IsBbrProbe = Cc->BbrV3.Common.BbrState == BBR_STATE_STARTUP ||
            (Cc->BbrV3.Common.BbrState == BBR_STATE_PROBE_BW && Cc->BbrV3.Model.Phase == BBR_V3_PHASE_UP);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrV3CongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    BOOLEAN PreviousCanSendState = BbrV3CongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= NumRetransmittableBytes);
    Bbr->BytesInFlight -= NumRetransmittableBytes;

    return BbrUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlHandleAckInProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestSentPacketNumber,
    _In_ uint64_t AckTime
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (!Bbr->ProbeRttEndTimeValid &&
        Bbr->BytesInFlight < BbrV3CongestionControlGetCongestionWindow(Cc) + DatagramPayloadLength) {
        Bbr->ProbeRttEndTime = AckTime + kProbeRttTimeInUs;
        Bbr->ProbeRttEndTimeValid = TRUE;

        Bbr->ProbeRttRound = Bbr->RoundTripCounter;
        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LargestSentPacketNumber;

        return;
    }

    if (Bbr->ProbeRttEndTimeValid) {
        if (Bbr->RoundTripCounter > Bbr->ProbeRttRound &&
            CxPlatTimeAtOrBefore64(Bbr->ProbeRttEndTime, AckTime)) {
            Bbr->MinRttTimestamp = AckTime;
            Bbr->MinRttTimestampValid = TRUE;
            Cc->BbrV3.Model.ProbeRttMinTimestamp = AckTime;
            Bbr->CongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Cc->BbrV3.Model.PriorCongestionWindow);

            if (Bbr->BtlbwFound) {
                BbrV3CongestionControlTransitToProbeBw(Cc, AckTime);
            } else {
                BbrV3CongestionControlTransitToStartup(Cc);
            }
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrV3CongestionControlGetTargetCwnd(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t Gain
    )
{
    return BbrGetTargetCwnd(&Cc->BbrV3.Common, BbrV3CongestionControlGetBandwidth(Cc), Gain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrV3CongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend,
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    return BbrGetSendAllowance(&Cc->BbrV3.Common, QuicCongestionControlGetConnection(Cc),
        BbrV3CongestionControlGetBandwidth(Cc), BbrV3CongestionControlGetCongestionWindow(Cc),
        TimeSinceLastSend, TimeSinceLastSendValid);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    Bbr->BbrState = BBR_STATE_PROBE_RTT;
    Cc->BbrV3.Model.PriorCongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Cc->BbrV3.Model.PriorCongestionWindow);
    Cc->BbrV3.Model.ProbeSamples = FALSE;
    Bbr->PacingGain = GAIN_UNIT;
    Bbr->ProbeRttEndTimeValid = FALSE;

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->BbrV3.Common.BbrState = BBR_STATE_DRAIN;
    Cc->BbrV3.Common.PacingGain = GAIN_UNIT / 2;
    Cc->BbrV3.Common.CwndGain = kCwndGain;
    Cc->BbrV3.Model.ProbeRound = Cc->BbrV3.Common.RoundTripCounter;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlUpdateCongestionWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return;
    }
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    BbrUpdateCongestionWindow(Bbr, BbrV3CongestionControlGetBandwidth(Cc),
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]), TotalBytesAcked, AckedBytes);
    // Apply the model after ACK aggregation and startup growth, including
    // when no bandwidth/RTT sample is available yet.
    Bbr->CongestionWindow = BbrV3CongestionControlGetCongestionWindow(Cc);
    BbrLogState(Connection, Bbr, BbrV3CongestionControlGetBandwidth(Cc));
}

static
void
BbrV3UpdateModel(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent,
    _In_ BOOLEAN NewRoundTrip,
    _In_ uint64_t DeliveryRate
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    BBR_V3_MODEL* Model = &Cc->BbrV3.Model;
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
                BbrV3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT));
        }
        BOOLEAN Probing = Bbr->BbrState == BBR_STATE_STARTUP ||
            (Bbr->BbrState == BBR_STATE_PROBE_BW &&
                (Model->Phase == BBR_V3_PHASE_REFILL || Model->Phase == BBR_V3_PHASE_UP));
        if (Model->LossInRound && !Probing) {
            if (Model->BandwidthLow == UINT64_MAX) {
                Model->BandwidthLow = BbrV3CongestionControlGetBandwidth(Cc);
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
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    BBR_V3_MODEL* Model = &Cc->BbrV3.Model;
    const uint32_t Mss = QuicPathGetDatagramPayloadSize(&QuicCongestionControlGetConnection(Cc)->Paths[0]);

    if (Model->Phase == BBR_V3_PHASE_DOWN || Model->Phase == BBR_V3_PHASE_CRUISE) {
        uint64_t ProbeRounds = CXPLAT_MIN(63, CXPLAT_MAX(1, BbrV3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT) / Mss));
        if (CxPlatTimeDiff64(Bbr->CycleStart, AckEvent->TimeNow) >= Model->ProbeWait ||
            Bbr->RoundTripCounter - Model->ProbeRound >= ProbeRounds) {
            BbrV3StartPhase(&Cc->BbrV3, BBR_V3_PHASE_REFILL, AckEvent->TimeNow, AckEvent->LargestSentPacketNumber);
        } else if (Model->Phase == BBR_V3_PHASE_DOWN &&
            Bbr->BytesInFlight <= BbrV3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT) &&
            Bbr->BytesInFlight <= CXPLAT_MAX(4 * Mss, BbrV3InflightWithHeadroom(&Cc->BbrV3))) {
            // CRUISE shares DOWN's probe timer and round count.
            Model->Phase = BBR_V3_PHASE_CRUISE;
            Bbr->PacingGain = GAIN_UNIT;
        }
    } else if (Model->Phase == BBR_V3_PHASE_REFILL) {
        if (NewRoundTrip && Bbr->RoundTripCounter > Model->ProbeRound) {
            BbrV3StartPhase(&Cc->BbrV3, BBR_V3_PHASE_UP, AckEvent->TimeNow, AckEvent->LargestSentPacketNumber);
        }
    } else {
        if (NewRoundTrip) {
            Model->ProbeUpCount = CXPLAT_MAX(Mss, Model->ProbeUpCount / 2);
        }
        if (!AckEvent->IsLargestAckedPacketAppLimited && !BbrV3CongestionControlInRecovery(Cc) &&
            Model->InflightHigh != UINT32_MAX) {
            BOOLEAN AtLimit = FALSE;
            for (const QUIC_SENT_PACKET_METADATA* Packet = AckEvent->AckedPackets; Packet; Packet = Packet->Next) {
                AtLimit |= Packet->PacketNumber >= Model->ProbeStartPacketNumber &&
                    Packet->Flags.IsBbrProbe && !Packet->Flags.IsAppLimited && Packet->InflightAtSend >= Model->InflightHigh;
            }
            if (AtLimit) {
                if (Model->InflightHigh < BbrV3CongestionControlGetTargetCwnd(Cc, Bbr->CwndGain)) {
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
            BbrV3StartPhase(&Cc->BbrV3, BBR_V3_PHASE_DOWN, AckEvent->TimeNow, AckEvent->LargestSentPacketNumber);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrV3CongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    BOOLEAN PreviousCanSendState = BbrV3CongestionControlCanSend(Cc);
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (AckEvent->IsImplicit) {
        CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
        Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;
        BbrV3CongestionControlUpdateCongestionWindow(
            Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

        if (Connection->Settings.NetStatsEventEnabled) {
            BbrIndicateConnectionEvent(Connection, Cc);
        }
        return BbrUpdateBlockedState(Cc, PreviousCanSendState);
    }

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    QUIC_ACK_EVENT CurrentPathAck;
    if (Cc->BbrV3.Model.MinValidPacketNumber && AckEvent->AckedPackets != NULL) {
        CurrentPathAck = *AckEvent;
        CurrentPathAck.MinRtt = UINT64_MAX;
        CurrentPathAck.MinRttValid = FALSE;
        CurrentPathAck.LargestAck = 0;
        BOOLEAN HasCurrentPathPacket = FALSE;
        for (const QUIC_SENT_PACKET_METADATA* Packet = AckEvent->AckedPackets; Packet; Packet = Packet->Next) {
            if (Packet->PacketNumber < Cc->BbrV3.Model.MinValidPacketNumber) {
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
            return BbrUpdateBlockedState(Cc, PreviousCanSendState);
        }
        AckEvent = &CurrentPathAck;
    }
    if (AckEvent->LargestAck < Cc->BbrV3.Model.MinValidPacketNumber) {
        return BbrUpdateBlockedState(Cc, PreviousCanSendState);
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
        BOOLEAN ProbeExpired = CxPlatTimeAtOrBefore64(
            Cc->BbrV3.Model.ProbeRttMinTimestamp + S_TO_US(5), AckEvent->TimeNow);
        if (AckEvent->MinRtt <= Cc->BbrV3.Model.ProbeRttMin || ProbeExpired) {
            Cc->BbrV3.Model.ProbeRttMin = AckEvent->MinRtt;
            Cc->BbrV3.Model.ProbeRttMinTimestamp = AckEvent->TimeNow;
        }
        Bbr->RttSampleExpired = ProbeExpired;
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
        Cc->BbrV3.Model.CycleCount,
        Cc->BbrV3.Model.MinValidPacketNumber);
    BbrV3UpdateModel(Cc, AckEvent, NewRoundTrip, DeliveryRate);

    if (BbrV3CongestionControlInRecovery(Cc)) {
        CXPLAT_DBG_ASSERT(Bbr->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (!AckEvent->HasLoss && Bbr->EndOfRecovery < AckEvent->LargestAck) {
            Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
            Bbr->CongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Cc->BbrV3.Model.PriorCongestionWindow);
            BbrLogRecoveryExit(Connection);
        } else {
            BbrUpdateRecoveryWindow(Bbr, QuicPathGetDatagramPayloadSize(&Connection->Paths[0]), AckEvent->NumRetransmittableBytes);
        }
    }

    BbrUpdateAckAggregation(Bbr, BbrV3CongestionControlGetBandwidth(Cc), AckEvent);

    if ((!Bbr->BtlbwFound || (Bbr->BbrState == BBR_STATE_PROBE_BW &&
            Cc->BbrV3.Model.Phase == BBR_V3_PHASE_UP)) && NewRoundTrip && !LastAckedPacketAppLimited &&
            DeliveryRate != 0) {
        BbrUpdateBottleneckBandwidth(Bbr, BbrV3CongestionControlGetBandwidth(Cc));
    }

    if (Bbr->BbrState == BBR_STATE_PROBE_BW) {
        BbrV3UpdateProbeBw(Cc, AckEvent, NewRoundTrip);
    }

    if (Bbr->BbrState == BBR_STATE_STARTUP && Bbr->BtlbwFound) {
        BbrV3CongestionControlTransitToDrain(Cc);
    }

    if (Bbr->BbrState == BBR_STATE_DRAIN &&
        (Bbr->BytesInFlight <= BbrV3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT) ||
            Bbr->RoundTripCounter - Cc->BbrV3.Model.ProbeRound >= 3)) {
        BbrV3CongestionControlTransitToProbeBw(Cc, AckEvent->TimeNow);
    }

    if (Bbr->BbrState != BBR_STATE_PROBE_RTT &&
        !Bbr->ExitingQuiescence &&
        Bbr->MinRttTimestampValid &&
        Bbr->RttSampleExpired) {
        BbrV3CongestionControlTransitToProbeRtt(Cc, AckEvent->LargestSentPacketNumber);
    }

    Bbr->ExitingQuiescence = FALSE;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        BbrV3CongestionControlHandleAckInProbeRtt(
            Cc, AckEvent->LargestSentPacketNumber, AckEvent->TimeNow);
    }

    BbrV3CongestionControlUpdateCongestionWindow(
        Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

    if (Connection->Settings.NetStatsEventEnabled) {
        BbrIndicateConnectionEvent(Connection, Cc);
    }

    return BbrUpdateBlockedState(Cc, PreviousCanSendState);
}

static
void
BbrV3HandleLoss(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent,
    _In_ uint32_t PreviousCongestionWindow
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    BBR_V3_MODEL* Model = &Cc->BbrV3.Model;
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
                BbrV3CongestionControlGetTargetCwnd(Cc, GAIN_UNIT));
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
        BbrV3StartPhase(&Cc->BbrV3, BBR_V3_PHASE_DOWN, LossEvent->TimeNow, LossEvent->LargestSentPacketNumber);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    BbrLogCongestion(Connection);

    BOOLEAN PreviousCanSendState = BbrV3CongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(LossEvent->NumRetransmittableBytes > 0);
    uint32_t PreviousCongestionWindow = BbrV3CongestionControlGetCongestionWindow(Cc);

    Bbr->EndOfRecoveryValid = TRUE;
    Bbr->EndOfRecovery = LossEvent->LargestSentPacketNumber;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (!BbrV3CongestionControlInRecovery(Cc)) {
        Cc->BbrV3.Model.UndoValid = TRUE;
        Cc->BbrV3.Model.PriorCongestionWindow = Bbr->CongestionWindow;
        Cc->BbrV3.Model.UndoInflightHigh = Cc->BbrV3.Model.InflightHigh;
        Cc->BbrV3.Model.UndoInflightLow = Cc->BbrV3.Model.InflightLow;
        Cc->BbrV3.Model.UndoBandwidthLow = Cc->BbrV3.Model.BandwidthLow;
        Cc->BbrV3.Model.UndoState = Bbr->BbrState;
        Cc->BbrV3.Model.UndoPhase = Cc->BbrV3.Model.Phase;
        Cc->BbrV3.Model.UndoBtlbwFound = Bbr->BtlbwFound;
        Bbr->RecoveryState = RECOVERY_STATE_CONSERVATIVE;

        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LossEvent->LargestSentPacketNumber;
    }

    BbrV3HandleLoss(Cc, LossEvent, PreviousCongestionWindow);

    if (LossEvent->PersistentCongestion) {
        Bbr->RecoveryWindow = MinCongestionWindow;

        BbrLogPersistentCongestion(Connection);
        Cc->BbrV3.Model.InflightLow = MinCongestionWindow;
    } else {
        Bbr->RecoveryWindow = CXPLAT_MAX(Bbr->BytesInFlight, MinCongestionWindow);
    }

    BbrUpdateBlockedState(Cc, PreviousCanSendState);
    BbrLogState(QuicCongestionControlGetConnection(Cc), Bbr, BbrV3CongestionControlGetBandwidth(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrV3CongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;
    if (!Cc->BbrV3.Model.UndoValid) {
        return FALSE;
    }
    BOOLEAN PreviousCanSendState = BbrV3CongestionControlCanSend(Cc);
    Cc->BbrV3.Model.InflightHigh = CXPLAT_MAX(Cc->BbrV3.Model.InflightHigh, Cc->BbrV3.Model.UndoInflightHigh);
    Cc->BbrV3.Model.InflightLow = CXPLAT_MAX(Cc->BbrV3.Model.InflightLow, Cc->BbrV3.Model.UndoInflightLow);
    Cc->BbrV3.Model.BandwidthLow = CXPLAT_MAX(Cc->BbrV3.Model.BandwidthLow, Cc->BbrV3.Model.UndoBandwidthLow);
    Bbr->CongestionWindow = CXPLAT_MAX(Bbr->CongestionWindow, Cc->BbrV3.Model.PriorCongestionWindow);
    Bbr->BtlbwFound = Cc->BbrV3.Model.UndoBtlbwFound;
    Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
    Cc->BbrV3.Model.LossInRound = FALSE;
    Cc->BbrV3.Model.ExcessiveLossInRound = FALSE;
    Cc->BbrV3.Model.StartupLossEvents = 0;
    Bbr->LastEstimatedStartupBandwidth = 0;
    Bbr->SlowStartupRoundCounter = 0;
    if (Bbr->BbrState != BBR_STATE_PROBE_RTT) {
        if (Cc->BbrV3.Model.UndoState == BBR_STATE_STARTUP) {
            BbrV3CongestionControlTransitToStartup(Cc);
        } else if (Cc->BbrV3.Model.UndoState == BBR_STATE_PROBE_BW && Cc->BbrV3.Model.UndoPhase == BBR_V3_PHASE_UP) {
            Bbr->BbrState = BBR_STATE_PROBE_BW;
            BbrV3StartPhase(&Cc->BbrV3, BBR_V3_PHASE_UP, CxPlatTimeUs64(),
                QuicCongestionControlGetConnection(Cc)->LossDetection.LargestSentPacketNumber);
        }
    }
    Cc->BbrV3.Model.UndoValid = FALSE;
    return BbrUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlSetAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    uint64_t LargestSentPacketNumber = Connection->LossDetection.LargestSentPacketNumber;

    if (Bbr->BytesInFlight > BbrV3CongestionControlGetCongestionWindow(Cc)) {
        return;
    }

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    BBR_COMMON* Bbr = &Cc->BbrV3.Common;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    BbrReset(Bbr, FullReset, DatagramPayloadLength);
    uint64_t TotalBytesLost = Cc->BbrV3.Model.TotalBytesLost;
    Cc->BbrV3.Model = (BBR_V3_MODEL) {
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
    BbrV3CongestionControlTransitToStartup(Cc);

    BbrV3CongestionControlLogOutFlowStatus(Cc);
    BbrLogState(Connection, Bbr, BbrV3CongestionControlGetBandwidth(Cc));
}

static const QUIC_CONGESTION_CONTROL QuicCongestionControlBbrV3 = {
    .Name = "BBRv3",
    .QuicCongestionControlCanSend = BbrV3CongestionControlCanSend,
    .QuicCongestionControlSetExemption = BbrV3CongestionControlSetExemption,
    .QuicCongestionControlReset = BbrV3CongestionControlReset,
    .QuicCongestionControlGetSendAllowance = BbrV3CongestionControlGetSendAllowance,
    .QuicCongestionControlGetCongestionWindow = BbrV3CongestionControlGetCongestionWindow,
    .QuicCongestionControlOnDataSent = BbrV3CongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = BbrV3CongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = BbrV3CongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = BbrV3CongestionControlOnDataLost,
    .QuicCongestionControlOnEcn = NULL,
    .QuicCongestionControlOnSpuriousCongestionEvent = BbrV3CongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = BbrV3CongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = BbrV3CongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = BbrV3CongestionControlGetBytesInFlightMax,
    .QuicCongestionControlIsAppLimited = BbrV3CongestionControlIsAppLimited,
    .QuicCongestionControlSetAppLimited = BbrV3CongestionControlSetAppLimited,
    .QuicCongestionControlGetNetworkStatistics = BbrV3CongestionControlGetNetworkStatistics
};

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrV3CongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    *Cc = QuicCongestionControlBbrV3;
    BbrInitialize(&Cc->BbrV3.Common, Settings, 1);
    BbrV3CongestionControlReset(Cc, TRUE);
}
