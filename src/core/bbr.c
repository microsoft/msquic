/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

//
// The length of the gain cycle
//
#define GAIN_CYCLE_LENGTH 8

static const uint32_t kHighGain = GAIN_UNIT * 2885 / 1000 + 1; // 2/ln(2)

static const uint32_t kDrainGain = GAIN_UNIT * 1000 / 2885; // 1/kHighGain

//
// The cycle of gains used during the PROBE_BW stage
//
static const uint32_t kPacingGain[GAIN_CYCLE_LENGTH] = {
    GAIN_UNIT * 5 / 4,
    GAIN_UNIT * 3 / 4,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT,
    GAIN_UNIT, GAIN_UNIT, GAIN_UNIT
};

static const uint32_t kBbrMaxBandwidthFilterLen = 10;

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
BbrCongestionControlGetBandwidth(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return BbrGetBandwidth(&Cc->Bbr.Common);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlInRecovery(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
)
{
    return Cc->Bbr.Common.RecoveryState != RECOVERY_STATE_NOT_RECOVERY;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    const BBR_COMMON* Bbr = &Cc->Bbr.Common;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): False positive: embedded Cc is valid.
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;
    uint32_t CongestionWindow = Bbr->CongestionWindow;

    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return MinCongestionWindow;
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
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

    Bbr->BbrState = BBR_STATE_PROBE_BW;
    Bbr->CwndGain = kCwndGain;

    uint32_t RandomValue = 0;
    CxPlatRandom(sizeof(uint32_t), &RandomValue);
    Cc->Bbr.PacingCycleIndex = (RandomValue % (GAIN_CYCLE_LENGTH - 1) + 2) % GAIN_CYCLE_LENGTH;
    CXPLAT_DBG_ASSERT(Cc->Bbr.PacingCycleIndex != 1);
    Bbr->PacingGain = kPacingGain[Cc->Bbr.PacingCycleIndex];

    Bbr->CycleStart = CongestionEventTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToStartup(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.Common.BbrState = BBR_STATE_STARTUP;
    Cc->Bbr.Common.PacingGain = kHighGain;
    Cc->Bbr.Common.CwndGain = kHighGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlIsAppLimited(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.Common.BandwidthFilter.AppLimited;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlGetNetworkStatistics(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_CONGESTION_CONTROL* Cc,
    _Out_ QUIC_NETWORK_STATISTICS* NetworkStatistics
    )
{
    BbrGetNetworkStatistics(Connection, &Cc->Bbr.Common, BbrCongestionControlGetBandwidth(Cc), NetworkStatistics);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    uint32_t CongestionWindow = BbrCongestionControlGetCongestionWindow(Cc);
    return Cc->Bbr.Common.BytesInFlight < CongestionWindow || Cc->Bbr.Common.Exemptions > 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    BbrLogOutFlowStatus(QuicCongestionControlGetConnection(Cc), &Cc->Bbr.Common);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.Common.BytesInFlightMax;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
BbrCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->Bbr.Common.Exemptions;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->Bbr.Common.Exemptions = NumPackets;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    if (!Bbr->BytesInFlight && BbrCongestionControlIsAppLimited(Cc)) {
        Bbr->ExitingQuiescence = TRUE;
    }

    BbrOnDataSent(Bbr, QuicCongestionControlGetConnection(Cc), NumRetransmittableBytes);

    BbrUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= NumRetransmittableBytes);
    Bbr->BytesInFlight -= NumRetransmittableBytes;

    return BbrUpdateBlockedState(Cc, PreviousCanSendState);
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
    BBR_COMMON* Bbr = &Cc->Bbr.Common;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    if (!Bbr->ProbeRttEndTimeValid &&
        Bbr->BytesInFlight < BbrCongestionControlGetCongestionWindow(Cc) + DatagramPayloadLength) {
        Bbr->ProbeRttEndTime = AckTime + kProbeRttTimeInUs;
        Bbr->ProbeRttEndTimeValid = TRUE;

        Cc->Bbr.ProbeRttRoundValid = FALSE;

        return;
    }

    if (Bbr->ProbeRttEndTimeValid) {
        if (!Cc->Bbr.ProbeRttRoundValid && NewRoundTrip) {
            Cc->Bbr.ProbeRttRoundValid = TRUE;
            Bbr->ProbeRttRound = Bbr->RoundTripCounter;
        }

        if (Cc->Bbr.ProbeRttRoundValid &&
            CxPlatTimeAtOrBefore64(Bbr->ProbeRttEndTime, AckTime)) {
            Bbr->MinRttTimestamp = AckTime;
            Bbr->MinRttTimestampValid = TRUE;

            if (Bbr->BtlbwFound) {
                BbrCongestionControlTransitToProbeBw(Cc, AckTime);
            } else {
                BbrCongestionControlTransitToStartup(Cc);
            }
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetTargetCwnd(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t Gain
    )
{
    return BbrGetTargetCwnd(&Cc->Bbr.Common, BbrCongestionControlGetBandwidth(Cc), Gain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
BbrCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend,
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    return BbrGetSendAllowance(&Cc->Bbr.Common, QuicCongestionControlGetConnection(Cc),
        BbrCongestionControlGetBandwidth(Cc), BbrCongestionControlGetCongestionWindow(Cc),
        TimeSinceLastSend, TimeSinceLastSendValid);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToProbeRtt(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestSentPacketNumber
    )
{
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

    Bbr->BbrState = BBR_STATE_PROBE_RTT;
    Bbr->PacingGain = GAIN_UNIT;
    Bbr->ProbeRttEndTimeValid = FALSE;
    Cc->Bbr.ProbeRttRoundValid = FALSE;

    Bbr->BandwidthFilter.AppLimited = TRUE;
    Bbr->BandwidthFilter.AppLimitedExitTarget = LargestSentPacketNumber;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlTransitToDrain(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->Bbr.Common.BbrState = BBR_STATE_DRAIN;
    Cc->Bbr.Common.PacingGain = kDrainGain;
    Cc->Bbr.Common.CwndGain = kHighGain;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlUpdateCongestionWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TotalBytesAcked,
    _In_ uint64_t AckedBytes
    )
{
    BBR_COMMON* Bbr = &Cc->Bbr.Common;
    if (Bbr->BbrState == BBR_STATE_PROBE_RTT) {
        return;
    }
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    BbrUpdateCongestionWindow(Bbr, BbrCongestionControlGetBandwidth(Cc),
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]), TotalBytesAcked, AckedBytes);
    BbrLogState(Connection, Bbr, BbrCongestionControlGetBandwidth(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
BbrCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    if (AckEvent->IsImplicit) {
        BbrCongestionControlUpdateCongestionWindow(
            Cc, AckEvent->NumTotalAckedRetransmittableBytes, AckEvent->NumRetransmittableBytes);

        if (Connection->Settings.NetStatsEventEnabled) {
            BbrIndicateConnectionEvent(Connection, Cc);
        }
        return BbrUpdateBlockedState(Cc, PreviousCanSendState);
    }

    uint32_t PrevInflightBytes = Bbr->BytesInFlight;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= AckEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= AckEvent->NumRetransmittableBytes;

    if (AckEvent->MinRttValid) {
        Bbr->RttSampleExpired = Bbr->MinRttTimestampValid ?
           CxPlatTimeAtOrBefore64(Bbr->MinRttTimestamp + kBbrMinRttExpirationInMicroSecs, AckEvent->TimeNow) :
           FALSE;
        if (Bbr->RttSampleExpired || Bbr->MinRtt > AckEvent->MinRtt) {
            Bbr->MinRtt = AckEvent->MinRtt;
            Bbr->MinRttTimestamp = AckEvent->TimeNow;
            Bbr->MinRttTimestampValid = TRUE;
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

    BbrBandwidthFilterOnPacketAcked(&Bbr->BandwidthFilter, AckEvent,
        Bbr->RoundTripCounter,
        0);

    if (BbrCongestionControlInRecovery(Cc)) {
        CXPLAT_DBG_ASSERT(Bbr->EndOfRecoveryValid);
        if (NewRoundTrip && Bbr->RecoveryState != RECOVERY_STATE_GROWTH) {
            Bbr->RecoveryState = RECOVERY_STATE_GROWTH;
        }
        if (!AckEvent->HasLoss && Bbr->EndOfRecovery < AckEvent->LargestAck) {
            Bbr->RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
            BbrLogRecoveryExit(Connection);
        } else {
            BbrUpdateRecoveryWindow(Bbr, QuicPathGetDatagramPayloadSize(&Connection->Paths[0]), AckEvent->NumRetransmittableBytes);
        }
    }

    BbrUpdateAckAggregation(Bbr, BbrCongestionControlGetBandwidth(Cc), AckEvent);

    if (Bbr->BbrState == BBR_STATE_PROBE_BW) {
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
            Cc->Bbr.PacingCycleIndex = (Cc->Bbr.PacingCycleIndex + 1) % GAIN_CYCLE_LENGTH;
            Bbr->CycleStart = AckEvent->TimeNow;
            Bbr->PacingGain = kPacingGain[Cc->Bbr.PacingCycleIndex];
        }
    }

    if (!Bbr->BtlbwFound && NewRoundTrip && !LastAckedPacketAppLimited) {
        BbrUpdateBottleneckBandwidth(Bbr, BbrCongestionControlGetBandwidth(Cc));
    }

    if (Bbr->BbrState == BBR_STATE_STARTUP && Bbr->BtlbwFound) {
        BbrCongestionControlTransitToDrain(Cc);
    }

    if (Bbr->BbrState == BBR_STATE_DRAIN &&
        Bbr->BytesInFlight <= BbrCongestionControlGetTargetCwnd(Cc, GAIN_UNIT)) {
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
        BbrIndicateConnectionEvent(Connection, Cc);
    }

    return BbrUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    BBR_COMMON* Bbr = &Cc->Bbr.Common;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    BbrLogCongestion(Connection);

    BOOLEAN PreviousCanSendState = BbrCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(LossEvent->NumRetransmittableBytes > 0);

    Bbr->EndOfRecoveryValid = TRUE;
    Bbr->EndOfRecovery = LossEvent->LargestSentPacketNumber;

    CXPLAT_DBG_ASSERT(Bbr->BytesInFlight >= LossEvent->NumRetransmittableBytes);
    Bbr->BytesInFlight -= LossEvent->NumRetransmittableBytes;

    uint32_t RecoveryWindow = Bbr->RecoveryWindow;
    uint32_t MinCongestionWindow = kMinCwndInMss * DatagramPayloadLength;

    if (!BbrCongestionControlInRecovery(Cc)) {
        Bbr->RecoveryState = RECOVERY_STATE_CONSERVATIVE;
        RecoveryWindow = Bbr->BytesInFlight;

        RecoveryWindow = CXPLAT_MAX(RecoveryWindow, MinCongestionWindow);

        Bbr->EndOfRoundTripValid = TRUE;
        Bbr->EndOfRoundTrip = LossEvent->LargestSentPacketNumber;
    }

    if (LossEvent->PersistentCongestion) {
        Bbr->RecoveryWindow = MinCongestionWindow;

        BbrLogPersistentCongestion(Connection);
    } else {
        Bbr->RecoveryWindow =
            RecoveryWindow > LossEvent->NumRetransmittableBytes + MinCongestionWindow
            ? RecoveryWindow - LossEvent->NumRetransmittableBytes
            : MinCongestionWindow;
    }

    BbrUpdateBlockedState(Cc, PreviousCanSendState);
    BbrLogState(QuicCongestionControlGetConnection(Cc), Bbr, BbrCongestionControlGetBandwidth(Cc));
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
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

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
    BBR_COMMON* Bbr = &Cc->Bbr.Common;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);

    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    BbrReset(Bbr, FullReset, DatagramPayloadLength);
    Cc->Bbr.ProbeRttRoundValid = FALSE;
    Cc->Bbr.PacingCycleIndex = 0;
    BbrCongestionControlTransitToStartup(Cc);

    BbrCongestionControlLogOutFlowStatus(Cc);
    BbrLogState(Connection, Bbr, BbrCongestionControlGetBandwidth(Cc));
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
BbrCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    *Cc = QuicCongestionControlBbr;
    BbrInitialize(&Cc->Bbr.Common, Settings, kBbrMaxBandwidthFilterLen);
    BbrCongestionControlReset(Cc, TRUE);
}
