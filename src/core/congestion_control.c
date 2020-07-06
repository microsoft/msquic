/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Algorithm for using (but not exceeding) available network bandwidth.

    The send rate is limited to the available bandwidth by
    limiting the number of bytes in flight to CongestionWindow.

    The algorithm used for adjusting CongestionWindow is CUBIC (RFC8312).

Future work:

    -Early slowstart exit via HyStart or similar.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "congestion_control.c.clog.h"
#endif

//
// BETA and C from RFC8312. 10x multiples for integer arithmetic.
//
#define TEN_TIMES_BETA_CUBIC 7
#define TEN_TIMES_C_CUBIC 4

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
    QuicTraceEvent(
        ConnCubic,
        "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Connection,
        Connection->CongestionControl.SlowStartThreshold,
        Connection->CongestionControl.KCubic,
        Connection->CongestionControl.WindowMax,
        Connection->CongestionControl.WindowLastMax);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS* Settings
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    Cc->SlowStartThreshold = UINT32_MAX;
    Cc->SendIdleTimeoutMs = Settings->SendIdleTimeoutMs;
    Cc->InitialWindowPackets = Settings->InitialWindowPackets;
    Cc->CongestionWindow = Connection->Paths[0].Mtu * Cc->InitialWindowPackets;
    Cc->BytesInFlightMax = Cc->CongestionWindow / 2;
    QuicConnLogOutFlowStats(Connection);
    QuicConnLogCubic(Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    Cc->SlowStartThreshold = UINT32_MAX;
    Cc->IsInRecovery = FALSE;
    Cc->HasHadCongestionEvent = FALSE;
    Cc->CongestionWindow = Connection->Paths[0].Mtu * Cc->InitialWindowPackets;
    Cc->BytesInFlightMax = Cc->CongestionWindow / 2;
    Cc->BytesInFlight = 0;
    QuicConnLogOutFlowStats(Connection);
    QuicConnLogCubic(Connection);
}

//
// Attempts to predict what the congestion window will be one RTT from now.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCongestionControlPredictNextWindow(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    //
    // TODO - Replace NewReno prediction logic.
    //
    uint32_t Wnd;
    if (Cc->CongestionWindow < Cc->SlowStartThreshold) {
        Wnd = Cc->CongestionWindow << 1;
        if (Wnd > Cc->SlowStartThreshold) {
            Wnd = Cc->SlowStartThreshold;
        }
    } else {
        Wnd =
            Cc->CongestionWindow +
            QuicCongestionControlGetConnection(Cc)->Paths[0].Mtu;
    }
    return Wnd;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    uint32_t SendAllowance;
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    if (Cc->BytesInFlight >= Cc->CongestionWindow) {
        //
        // We are CC blocked, so we can't send anything.
        //
        SendAllowance = 0;

    } else if (!Connection->State.UsePacing || !Connection->Paths[0].GotFirstRttSample) {
        //
        // Pacing is disabled or we don't have an RTT sample yet, so just send
        // everything we can.
        //
        SendAllowance = Cc->CongestionWindow - Cc->BytesInFlight;

    } else {
        //
        // Try to pace: if the window and RTT are large enough, the window can
        // be split into chunks which are spread out over the RTT.
        // SendAllowance will be set to the size of the next chunk.
        //
        uint32_t MinChunkSize = QUIC_SEND_PACING_MIN_CHUNK * Connection->Paths[0].Mtu;
        if (Connection->Paths[0].SmoothedRtt < MS_TO_US(QUIC_SEND_PACING_INTERVAL) ||
            Cc->CongestionWindow < MinChunkSize ||
            !TimeSinceLastSendValid) {
            //
            // Either the RTT is too small (i.e. it cannot be split into
            // multiple intervals based on the timer granularity) or the window
            // is too small (i.e. it cannot be split into chunks larger than
            // MinChunkSize) for us to use pacing, or this is the first send,
            // in which case the pacing formula (which uses the time since the
            // last send) is invalid.
            //
            SendAllowance = Cc->CongestionWindow - Cc->BytesInFlight;

        } else {

            //
            // We are pacing, so calculate the current chunk size based on how
            // long it's been since we sent the previous chunk.
            //

            //
            // Since the window grows via ACK feedback and since we defer
            // packets when pacing, using the current window to calculate the
            // pacing interval is not quite as aggressive as we'd like. Instead,
            // use the predicted window of the next RTT.
            //
            uint64_t EstimatedWnd = QuicCongestionControlPredictNextWindow(Cc);

            SendAllowance =
                (uint32_t)((EstimatedWnd * TimeSinceLastSend) / Connection->Paths[0].SmoothedRtt);
            if (SendAllowance < MinChunkSize) {
                SendAllowance = MinChunkSize;
            }
            if (SendAllowance > (Cc->CongestionWindow - Cc->BytesInFlight)) {
                SendAllowance = Cc->CongestionWindow - Cc->BytesInFlight;
            }
            if (SendAllowance > (Cc->CongestionWindow >> 1)) {
                SendAllowance = Cc->CongestionWindow >> 1; // Don't send more than half the current window.
            }
        }
    }
    return SendAllowance;
}

//
// Returns TRUE if we became unblocked.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlUpdateBlockedState(
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
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicTraceEvent(
        ConnCongestion,
        "[conn][%p] Congestion event",
        Connection);
    Connection->Stats.Send.CongestionCount++;

    Cc->IsInRecovery = TRUE;
    Cc->HasHadCongestionEvent = TRUE;

    Cc->WindowMax = Cc->CongestionWindow;
    if (Cc->WindowLastMax > Cc->WindowMax) {
        //
        // Fast convergence.
        //
        Cc->WindowLastMax = Cc->WindowMax;
        Cc->WindowMax = Cc->WindowMax * (10 + TEN_TIMES_BETA_CUBIC) / 20;
    } else {
        Cc->WindowLastMax = Cc->WindowMax;
    }

    //
    // K = (WindowMax * (1 - BETA) / C) ^ (1/3)
    // BETA := multiplicative window decrease factor.
    //
    // Here we reduce rounding error by left-shifting the CubeRoot argument
    // by 9 before the division and then right-shifting the result by 3
    // (since 2^9 = 2^3^3).
    //
    Cc->KCubic =
        CubeRoot(
            (Cc->WindowMax / Connection->Paths[0].Mtu * (10 - TEN_TIMES_BETA_CUBIC) << 9) /
            TEN_TIMES_C_CUBIC);
    Cc->KCubic = S_TO_MS(Cc->KCubic);
    Cc->KCubic >>= 3;

    Cc->SlowStartThreshold =
    Cc->CongestionWindow =
        max(
            (uint32_t)Connection->Paths[0].Mtu * Cc->InitialWindowPackets,
            Cc->CongestionWindow * TEN_TIMES_BETA_CUBIC / 10);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnPersistentCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    QuicTraceEvent(
        ConnPersistentCongestion,
        "[conn][%p] Persistent congestion event",
        Connection);
    Connection->Stats.Send.PersistentCongestionCount++;

    Cc->IsInPersistentCongestion = TRUE;
    Cc->WindowMax =
        Cc->WindowLastMax =
        Cc->SlowStartThreshold =
            Cc->CongestionWindow * TEN_TIMES_BETA_CUBIC / 10;
    Cc->CongestionWindow =
        Connection->Paths[0].Mtu * QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS;
    Cc->KCubic = 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    BOOLEAN PreviousCanSendState = QuicCongestionControlCanSend(Cc);

    Cc->BytesInFlight += NumRetransmittableBytes;
    if (Cc->BytesInFlightMax < Cc->BytesInFlight) {
        Cc->BytesInFlightMax = Cc->BytesInFlight;
        QuicSendBufferConnectionAdjust(QuicCongestionControlGetConnection(Cc));
    }

    if (Cc->Exemptions > 0) {
        --Cc->Exemptions;
    }

    QuicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    BOOLEAN PreviousCanSendState = QuicCongestionControlCanSend(Cc);

    QUIC_DBG_ASSERT(Cc->BytesInFlight >= NumRetransmittableBytes);
    Cc->BytesInFlight -= NumRetransmittableBytes;

    return QuicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeNow, // millisec
    _In_ uint64_t LargestPacketNumberAcked,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ uint32_t SmoothedRtt
    )
{
    QUIC_CONNECTION* Connection = QuicCongestionControlGetConnection(Cc);
    BOOLEAN PreviousCanSendState = QuicCongestionControlCanSend(Cc);

    QUIC_DBG_ASSERT(Cc->BytesInFlight >= NumRetransmittableBytes);
    Cc->BytesInFlight -= NumRetransmittableBytes;

    if (Cc->IsInRecovery) {
        if (LargestPacketNumberAcked > Cc->RecoverySentPacketNumber) {
            //
            // Done recovering. Note that completion of recovery is defined a
            // bit differently here than in TCP: we simply require an ACK for a
            // packet sent after recovery started.
            //
            QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
            Cc->IsInRecovery = FALSE;
            Cc->IsInPersistentCongestion = FALSE;
            Cc->TimeOfCongAvoidStart = QuicTimeMs64();
        }
        goto Exit;
    } else if (NumRetransmittableBytes == 0) {
        goto Exit;
    }

    if (Cc->CongestionWindow < Cc->SlowStartThreshold) {

        //
        // Slow Start
        //

        Cc->CongestionWindow += NumRetransmittableBytes;
        if (Cc->CongestionWindow >= Cc->SlowStartThreshold) {
            Cc->TimeOfCongAvoidStart = QuicTimeMs64();
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
        if (Cc->TimeOfLastAckValid) {
            uint64_t TimeSinceLastAck = QuicTimeDiff64(Cc->TimeOfLastAck, TimeNow);
            if (TimeSinceLastAck > Cc->SendIdleTimeoutMs &&
                TimeSinceLastAck > US_TO_MS(Connection->Paths[0].SmoothedRtt + 4 * Connection->Paths[0].RttVariance)) {
                Cc->TimeOfCongAvoidStart += TimeSinceLastAck;
                if (QuicTimeAtOrBefore64(TimeNow, Cc->TimeOfCongAvoidStart)) {
                    Cc->TimeOfCongAvoidStart = TimeNow;
                }
            }
        }

        uint64_t TimeInCongAvoid =
            QuicTimeDiff64(Cc->TimeOfCongAvoidStart, QuicTimeMs64());
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

        int64_t DeltaT = TimeInCongAvoid - Cc->KCubic + US_TO_MS(SmoothedRtt);

        int64_t CubicWindow =
            ((((DeltaT * DeltaT) >> 10) * DeltaT *
              (int64_t)(Connection->Paths[0].Mtu * TEN_TIMES_C_CUBIC / 10)) >> 20) +
            (int64_t)Cc->WindowMax;

        if (CubicWindow < 0) {
            //
            // The window came out so large it overflowed. We want to limit the
            // huge window below anyway, so just set it to the limiting value.
            //
            CubicWindow = 2 * Cc->BytesInFlightMax;
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

        QUIC_STATIC_ASSERT(TEN_TIMES_BETA_CUBIC == 7, "TEN_TIMES_BETA_CUBIC must be 7 for simplified calculation.");

        int64_t AimdWindow =
            Cc->WindowMax * TEN_TIMES_BETA_CUBIC / 10 +
            TimeInCongAvoid * Connection->Paths[0].Mtu / (2 * max(1, US_TO_MS(SmoothedRtt)));

        //
        // Use the cubic or AIMD window, whichever is larger.
        //
        if (AimdWindow > CubicWindow) {
            Cc->CongestionWindow = (uint32_t)max(AimdWindow, Cc->CongestionWindow + 1);
        } else {
            //
            // Here we increment by a fraction of the difference, per the spec,
            // rather than setting the window equal to CubicWindow. This helps
            // prevent a burst when transitioning into congestion avoidance, since
            // the cubic window may be significantly different from SlowStartThreshold.
            //
            Cc->CongestionWindow +=
                (uint32_t)max(
                    ((CubicWindow - Cc->CongestionWindow) * Connection->Paths[0].Mtu) / Cc->CongestionWindow,
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
    if (Cc->CongestionWindow > 2 * Cc->BytesInFlightMax) {
        Cc->CongestionWindow = 2 * Cc->BytesInFlightMax;
    }

Exit:

    Cc->TimeOfLastAck = TimeNow;
    Cc->TimeOfLastAckValid = TRUE;
    return QuicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t LargestPacketNumberLost,
    _In_ uint64_t LargestPacketNumberSent,
    _In_ uint32_t NumRetransmittableBytes,
    _In_ BOOLEAN PersistentCongestion
    )
{
    BOOLEAN PreviousCanSendState = QuicCongestionControlCanSend(Cc);

    //
    // If data is lost after the most recent congestion event (or if there
    // hasn't been a congestion event yet) then treat this loss as a new
    // congestion event.
    //
    if (!Cc->HasHadCongestionEvent ||
        LargestPacketNumberLost > Cc->RecoverySentPacketNumber) {

        Cc->RecoverySentPacketNumber = LargestPacketNumberSent;
        QuicCongestionControlOnCongestionEvent(Cc);

        if (PersistentCongestion && !Cc->IsInPersistentCongestion) {
            QuicCongestionControlOnPersistentCongestionEvent(Cc);
        }
    }

    QUIC_DBG_ASSERT(Cc->BytesInFlight >= NumRetransmittableBytes);
    Cc->BytesInFlight -= NumRetransmittableBytes;

    QuicCongestionControlUpdateBlockedState(Cc, PreviousCanSendState);
    QuicConnLogCubic(QuicCongestionControlGetConnection(Cc));
}
