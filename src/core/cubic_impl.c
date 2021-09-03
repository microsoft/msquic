/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The algorithm used for adjusting CongestionWindow is CUBIC (RFC8312).

Future work:

    -Early slowstart exit via HyStart or similar.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "cubic.c.clog.h"
#endif

#include "cubic.h"
#include "cubic_impl.h"

//
// BETA and C from RFC8312. 10x multiples for integer arithmetic.
//
#define TEN_TIMES_BETA_CUBIC 7
#define TEN_TIMES_C_CUBIC 4

static const QUIC_CONGESTION_CONTROL QuicCongestionControlCubic = {
    .Name = "Cubic",
    .QuicCongestionControlCanSend = CubicCongestionControlCanSend,
    .QuicCongestionControlSetExemption = CubicCongestionControlSetExemption,
    .QuicCongestionControlInitialize = CubicCongestionControlInitialize,
    .QuicCongestionControlReset = CubicCongestionControlReset,
    .QuicCongestionControlGetSendAllowance = CubicCongestionControlGetSendAllowance,
    .QuicCongestionControlOnDataSent = CubicCongestionControlOnDataSent,
    .QuicCongestionControlOnDataInvalidated = CubicCongestionControlOnDataInvalidated,
    .QuicCongestionControlOnDataAcknowledged = CubicCongestionControlOnDataAcknowledged,
    .QuicCongestionControlOnDataLost = CubicCongestionControlOnDataLost,
    .QuicCongestionControlOnSpuriousCongestionEvent = CubicCongestionControlOnSpuriousCongestionEvent,
    .QuicCongestionControlLogOutFlowStatus = CubicCongestionControlLogOutFlowStatus,
    .QuicCongestionControlGetExemptions = CubicCongestionControlGetExemptions,
    .QuicCongestionControlGetBytesInFlightMax = CubicCongestionControlGetBytesInFlightMax,
};

//
// Shifting nth root algorithm.
//
// This works sort of like long division: we look at the radicand in aligned
// chunks of 3 bits to compute each bit of the root. This is somewhat
// intuitive, since 2^3 = 8, i.e. one bit is needed to encode the cube root
// of a 3-bit number.
//
// At each step, we have a root value computed "so far" (i.e. the most
// significant bits of the root) and we need to find the correct value of
// the LSB of the (shifted) root so that it satisfies the two conditions:
// y^3 <= x
// (y+1)^3 > x
// ...where y represents the shifted value of the root "computed so far"
// and x represents the bits of the radicand "shifted in so far."
//
// The initial shift of 30 bits gives us 3-bit-aligned chunks.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CubeRoot(
    uint32_t Radicand
    )
{
    int i;
    uint32_t x = 0;
    uint32_t y = 0;

    for (i = 30; i >= 0; i -= 3) {
        x = x * 8 + ((Radicand >> i) & 7);
        if ((y * 2 + 1) * (y * 2 + 1) * (y * 2 + 1) <= x) {
            y = y * 2 + 1;
        } else {
            y = y * 2;
        }
    }
    return y;
}

void
QuicConnLogCubic(
    _In_ const QUIC_CONNECTION* const Connection
    )
{
    UNREFERENCED_PARAMETER(Connection);

    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)(&Connection->CongestionControl.Ctx);

    QuicTraceEvent(
        ConnCubic,
        "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Connection,
        Ctx->SlowStartThreshold,
        Ctx->KCubic,
        Ctx->WindowMax,
        Ctx->WindowLastMax);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS* Settings
    )
{
    *Cc = QuicCongestionControlCubic;

    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    Ctx->SlowStartThreshold = UINT32_MAX;
    Ctx->SendIdleTimeoutMs = Settings->SendIdleTimeoutMs;
    Ctx->InitialWindowPackets = Settings->InitialWindowPackets;
    Ctx->CongestionWindow = Connection->Paths[0].Mtu * Ctx->InitialWindowPackets;
    Ctx->BytesInFlightMax = Ctx->CongestionWindow / 2;
    QuicConnLogOutFlowStats(Connection);
    QuicConnLogCubic(Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    Ctx->SlowStartThreshold = UINT32_MAX;
    Ctx->IsInRecovery = FALSE;
    Ctx->HasHadCongestionEvent = FALSE;
    Ctx->CongestionWindow = Connection->Paths[0].Mtu * Ctx->InitialWindowPackets;
    Ctx->BytesInFlightMax = Ctx->CongestionWindow / 2;
    Ctx->BytesInFlight = 0;
    QuicConnLogOutFlowStats(Connection);
    QuicConnLogCubic(Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CubicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    uint32_t SendAllowance;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    if (Ctx->BytesInFlight >= Ctx->CongestionWindow) {
        //
        // We are CC blocked, so we can't send anything.
        //
        SendAllowance = 0;

    } else if (
        !TimeSinceLastSendValid ||
        !Connection->Settings.PacingEnabled ||
        !Connection->Paths[0].GotFirstRttSample ||
        Connection->Paths[0].SmoothedRtt < MS_TO_US(QUIC_SEND_PACING_INTERVAL)) {
        //
        // We're not in the necessary state to pace.
        //
        SendAllowance = Ctx->CongestionWindow - Ctx->BytesInFlight;

    } else {

        //
        // We are pacing, so split the congestion window into chunks which are
        // spread out over the RTT. Calculate the current send allowance (chunk
        // size) as the time since the last send times the pacing rate (CWND / RTT).
        //

        //
        // Since the window grows via ACK feedback and since we defer packets
        // when pacing, using the current window to calculate the pacing
        // interval can slow the growth of the window. So instead, use the
        // predicted window of the next round trip. In slowstart, this is double
        // the current window. In congestion avoidance the growth function is
        // more complicated, and we use a simple estimate of 25% growth.
        //
        uint64_t EstimatedWnd;
        if (Ctx->CongestionWindow < Ctx->SlowStartThreshold) {
            EstimatedWnd = (uint64_t)Ctx->CongestionWindow << 1;
            if (EstimatedWnd > Ctx->SlowStartThreshold) {
                EstimatedWnd = Ctx->SlowStartThreshold;
            }
        } else {
            EstimatedWnd = Ctx->CongestionWindow + (Ctx->CongestionWindow >> 2); // CongestionWindow * 1.25
        }

        SendAllowance =
            (uint32_t)((EstimatedWnd * TimeSinceLastSend) / Connection->Paths[0].SmoothedRtt);
        if (SendAllowance > (Ctx->CongestionWindow - Ctx->BytesInFlight)) {
            SendAllowance = Ctx->CongestionWindow - Ctx->BytesInFlight;
        }
        if (SendAllowance > (Ctx->CongestionWindow >> 2)) {
            SendAllowance = Ctx->CongestionWindow >> 2; // Don't send more than a quarter of the current window.
        }
    }
    return SendAllowance;
}

//
// Returns TRUE if we became unblocked.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CubicCongestionControlUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicConnLogOutFlowStats(Connection);
    if (PreviousCanSendState != CubicCongestionControlCanSend(Cc)) {
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
CubicCongestionControlOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicTraceEvent(
        ConnCongestion,
        "[conn][%p] Congestion event",
        Connection);
    Connection->Stats.Send.CongestionCount++;

    Ctx->IsInRecovery = TRUE;
    Ctx->HasHadCongestionEvent = TRUE;

    //
    // Save previous state, just in case this ends up being spurious.
    //
    Ctx->PrevWindowMax = Ctx->WindowMax;
    Ctx->PrevWindowLastMax = Ctx->WindowLastMax;
    Ctx->PrevKCubic = Ctx->KCubic;
    Ctx->PrevSlowStartThreshold = Ctx->SlowStartThreshold;
    Ctx->PrevCongestionWindow = Ctx->CongestionWindow;

    Ctx->WindowMax = Ctx->CongestionWindow;
    if (Ctx->WindowLastMax > Ctx->WindowMax) {
        //
        // Fast convergence.
        //
        Ctx->WindowLastMax = Ctx->WindowMax;
        Ctx->WindowMax = Ctx->WindowMax * (10 + TEN_TIMES_BETA_CUBIC) / 20;
    } else {
        Ctx->WindowLastMax = Ctx->WindowMax;
    }

    //
    // K = (WindowMax * (1 - BETA) / C) ^ (1/3)
    // BETA := multiplicative window decrease factor.
    //
    // Here we reduce rounding error by left-shifting the CubeRoot argument
    // by 9 before the division and then right-shifting the result by 3
    // (since 2^9 = 2^3^3).
    //
    Ctx->KCubic =
        CubeRoot(
            (Ctx->WindowMax / Connection->Paths[0].Mtu * (10 - TEN_TIMES_BETA_CUBIC) << 9) /
            TEN_TIMES_C_CUBIC);
    Ctx->KCubic = S_TO_MS(Ctx->KCubic);
    Ctx->KCubic >>= 3;

    Ctx->SlowStartThreshold =
    Ctx->CongestionWindow =
        CXPLAT_MAX(
            (uint32_t)Connection->Paths[0].Mtu * QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS,
            Ctx->CongestionWindow * TEN_TIMES_BETA_CUBIC / 10);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlOnPersistentCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicTraceEvent(
        ConnPersistentCongestion,
        "[conn][%p] Persistent congestion event",
        Connection);
    Connection->Stats.Send.PersistentCongestionCount++;

    Ctx->IsInPersistentCongestion = TRUE;
    Ctx->WindowMax =
        Ctx->WindowLastMax =
        Ctx->SlowStartThreshold =
            Ctx->CongestionWindow * TEN_TIMES_BETA_CUBIC / 10;
    Ctx->CongestionWindow =
        Connection->Paths[0].Mtu * QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS;
    Ctx->KCubic = 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CubicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    BOOLEAN PreviousCanSendState = QuicCongestionControlCanSend(Cc);

    Ctx->BytesInFlight += NumRetransmittableBytes;
    if (Ctx->BytesInFlightMax < Ctx->BytesInFlight) {
        Ctx->BytesInFlightMax = Ctx->BytesInFlight;
        QuicSendBufferConnectionAdjust(QuicCongestionControlGetConnection(Cc));
    }

    if (Ctx->Exemptions > 0) {
        --Ctx->Exemptions;
    }

    CubicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CubicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    BOOLEAN PreviousCanSendState = CubicCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Ctx->BytesInFlight >= NumRetransmittableBytes);
    Ctx->BytesInFlight -= NumRetransmittableBytes;

    return CubicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CubicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeNow, // microsecond
    _In_ uint64_t LargestPacketNumberAcked,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ uint32_t SmoothedRtt
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    TimeNow = US_TO_MS(TimeNow);
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    BOOLEAN PreviousCanSendState = CubicCongestionControlCanSend(Cc);

    CXPLAT_DBG_ASSERT(Ctx->BytesInFlight >= NumRetransmittableBytes);
    Ctx->BytesInFlight -= NumRetransmittableBytes;

    if (Ctx->IsInRecovery) {
        if (LargestPacketNumberAcked > Ctx->RecoverySentPacketNumber) {
            //
            // Done recovering. Note that completion of recovery is defined a
            // bit differently here than in TCP: we simply require an ACK for a
            // packet sent after recovery started.
            //
            QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
            Ctx->IsInRecovery = FALSE;
            Ctx->IsInPersistentCongestion = FALSE;
            Ctx->TimeOfCongAvoidStart = CxPlatTimeMs64();
        }
        goto Exit;
    } else if (NumRetransmittableBytes == 0) {
        goto Exit;
    }

    if (Ctx->CongestionWindow < Ctx->SlowStartThreshold) {

        //
        // Slow Start
        //

        Ctx->CongestionWindow += NumRetransmittableBytes;
        if (Ctx->CongestionWindow >= Ctx->SlowStartThreshold) {
            Ctx->TimeOfCongAvoidStart = CxPlatTimeMs64();
        }

    } else {

        //
        // Congestion Avoidance
        //

        //
        // We require steady ACK feedback to justify window growth. If there is
        // a long time gap between ACKs, add the gap to TimeOfCongAvoidStart to
        // reduce the value of TimeInCongAvoid, which effectively freezes window
        // growth during the gap.
        //
        if (Ctx->TimeOfLastAckValid) {
            uint64_t TimeSinceLastAck = CxPlatTimeDiff64(Ctx->TimeOfLastAck, TimeNow);
            if (TimeSinceLastAck > Ctx->SendIdleTimeoutMs &&
                TimeSinceLastAck > US_TO_MS(Connection->Paths[0].SmoothedRtt + 4 * Connection->Paths[0].RttVariance)) {
                Ctx->TimeOfCongAvoidStart += TimeSinceLastAck;
                if (CxPlatTimeAtOrBefore64(TimeNow, Ctx->TimeOfCongAvoidStart)) {
                    Ctx->TimeOfCongAvoidStart = TimeNow;
                }
            }
        }

        uint64_t TimeInCongAvoid =
            CxPlatTimeDiff64(Ctx->TimeOfCongAvoidStart, CxPlatTimeMs64());
        if (TimeInCongAvoid > UINT32_MAX) {
            TimeInCongAvoid = UINT32_MAX;
        }

        //
        // Compute the cubic window:
        // W_cubic(t) = C*(t-K)^3 + WindowMax.
        // (t in seconds; window sizes in MSS)
        //
        // NB: The RFC uses W_cubic(t+RTT) rather than W_cubic(t), so we
        // add RTT to DeltaT.
        //
        // Here we have 30 bits' worth of right shift. This is to convert
        // millisec^3 to sec^3. Each ten bit's worth of shift approximates
        // a division by 1000. The order of operations is chosen to strike
        // a balance between rounding error and overflow protection.
        // With C = 0.4 and MTU=0xffff, we are safe from overflow for
        // DeltaT < ~2.5M (about 30min).
        //

        int64_t DeltaT =
            (int64_t)TimeInCongAvoid -
            (int64_t)Ctx->KCubic +
            (int64_t)US_TO_MS(SmoothedRtt);

        int64_t CubicWindow =
            ((((DeltaT * DeltaT) >> 10) * DeltaT *
             (int64_t)(Connection->Paths[0].Mtu * TEN_TIMES_C_CUBIC / 10)) >> 20) +
            (int64_t)Ctx->WindowMax;

        if (CubicWindow < 0) {
            //
            // The window came out so large it overflowed. We want to limit the
            // huge window below anyway, so just set it to the limiting value.
            //
            CubicWindow = 2 * Ctx->BytesInFlightMax;
        }

        //
        // Compute the AIMD window (called W_est in the RFC):
        // W_est(t) = WindowMax*BETA + [3*(1-BETA)/(1+BETA)] * (t/RTT).
        // (again, window sizes in MSS)
        //
        // This is a window with linear growth which is designed
        // to have the same average window size as an AIMD window
        // with BETA=0.5 and a slope of 1MSS/RTT. Since our
        // BETA is 0.7, we need a smaller slope than 1MSS/RTT to
        // have this property.
        //
        // Also, for our value of BETA we have [3*(1-BETA)/(1+BETA)] ~= 0.5,
        // so we simplify the calculation as:
        // W_est(t) ~= WindowMax*BETA + (t/(2*RTT)).
        //
        // Using max(RTT, 1) prevents division by zero.
        //

        CXPLAT_STATIC_ASSERT(TEN_TIMES_BETA_CUBIC == 7, "TEN_TIMES_BETA_CUBIC must be 7 for simplified calculation.");

        int64_t AimdWindow =
            Ctx->WindowMax * TEN_TIMES_BETA_CUBIC / 10 +
            TimeInCongAvoid * Connection->Paths[0].Mtu / (2 * CXPLAT_MAX(1, US_TO_MS(SmoothedRtt)));

        //
        // Use the cubic or AIMD window, whichever is larger.
        //
        if (AimdWindow > CubicWindow) {
            Ctx->CongestionWindow = (uint32_t)CXPLAT_MAX(AimdWindow, Ctx->CongestionWindow + 1);
        } else {
            //
            // Here we increment by a fraction of the difference, per the spec,
            // rather than setting the window equal to CubicWindow. This helps
            // prevent a burst when transitioning into congestion avoidance, since
            // the cubic window may be significantly different from SlowStartThreshold.
            //
            Ctx->CongestionWindow +=
                (uint32_t)CXPLAT_MAX(
                    ((CubicWindow - Ctx->CongestionWindow) * Connection->Paths[0].Mtu) / Ctx->CongestionWindow,
                    1);
        }
    }

    //
    // Limit the growth of the window based on the number of bytes we
    // actually manage to put on the wire, which may be limited by flow
    // control or by the app posting a limited number of bytes. This must
    // be done to prevent the window from growing without loss feedback from
    // the network.
    //
    // Using 2 * BytesInFlightMax for the limit allows for exponential growth
    // in the window when not otherwise limited.
    //
    if (Ctx->CongestionWindow > 2 * Ctx->BytesInFlightMax) {
        Ctx->CongestionWindow = 2 * Ctx->BytesInFlightMax;
    }

Exit:

    Ctx->TimeOfLastAck = TimeNow;
    Ctx->TimeOfLastAckValid = TRUE;
    return CubicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberLost,
    _In_ uint64_t LargestPacketNumberSent,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ BOOLEAN PersistentCongestion
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    BOOLEAN PreviousCanSendState = CubicCongestionControlCanSend(Cc);

    //
    // If data is lost after the most recent congestion event (or if there
    // hasn't been a congestion event yet) then treat this loss as a new
    // congestion event.
    //
    if (!Ctx->HasHadCongestionEvent ||
        LargestPacketNumberLost > Ctx->RecoverySentPacketNumber) {

        Ctx->RecoverySentPacketNumber = LargestPacketNumberSent;
        CubicCongestionControlOnCongestionEvent(Cc);

        if (PersistentCongestion && !Ctx->IsInPersistentCongestion) {
            CubicCongestionControlOnPersistentCongestionEvent(Cc);
        }
    }

    CXPLAT_DBG_ASSERT(Ctx->BytesInFlight >= NumRetransmittableBytes);
    Ctx->BytesInFlight -= NumRetransmittableBytes;

    CubicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    QuicConnLogCubic(QuicCongestionControlGetConnection(Cc));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    if (!Ctx->IsInRecovery) {
        return;
    }

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    BOOLEAN PreviousCanSendState = QuicCongestionControlCanSend(Cc);

    QuicTraceEvent(
        ConnSpuriousCongestion,
        "[conn][%p] Spurious congestion event",
        Connection);

    //
    // Revert to previous state.
    //
    Ctx->WindowMax = Ctx->PrevWindowMax;
    Ctx->WindowLastMax = Ctx->PrevWindowLastMax;
    Ctx->KCubic = Ctx->PrevKCubic;
    Ctx->SlowStartThreshold = Ctx->PrevSlowStartThreshold;
    Ctx->CongestionWindow = Ctx->PrevCongestionWindow;

    Ctx->IsInRecovery = FALSE;
    Ctx->HasHadCongestionEvent = FALSE;

    CubicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    QuicConnLogCubic(Connection);
}

void
CubicCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;

    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    
    const QUIC_PATH* Path = &Connection->Paths[0];
    UNREFERENCED_PARAMETER(Path);

    QuicTraceEvent(
        ConnOutFlowStats,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Ctx->BytesInFlight,
        Ctx->BytesInFlightMax,
        Ctx->CongestionWindow,
        Ctx->SlowStartThreshold,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0);
}

uint32_t
CubicCongestionControlGetBytesInFlightMax(
    _In_ const struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;
    return Ctx->BytesInFlightMax;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint8_t
CubicCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONGESTION_CONTROL_CUBIC* Ctx = (QUIC_CONGESTION_CONTROL_CUBIC*)&Cc->Ctx;
    return Ctx->Exemptions;
}
