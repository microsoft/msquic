/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for CUBIC congestion control.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CubicTest.cpp.clog.h"
#endif

extern "C" uint32_t CubeRoot(uint32_t Radicand);

//
// Helper to create a minimal valid connection for testing CUBIC initialization.
// Uses a real QUIC_CONNECTION structure to ensure proper memory layout when
// QuicCongestionControlGetConnection() does CXPLAT_CONTAINING_RECORD pointer arithmetic.
//
static void InitializeMockConnection(
    QUIC_CONNECTION& Connection,
    uint16_t Mtu)
{
    Connection.Paths[0].Mtu = Mtu;
    Connection.Paths[0].IsActive = TRUE;
    Connection.Send.NextPacketNumber = 0;
    Connection.Settings.PacingEnabled = FALSE;
    Connection.Settings.HyStartEnabled = FALSE;
    Connection.Paths[0].GotFirstRttSample = FALSE;
    Connection.Paths[0].SmoothedRtt = 0;
}

//
// Helper to construct a QUIC_ACK_EVENT with common defaults.
// Fields not specified here (IsImplicit, HasLoss, IsLargestAckedPacketAppLimited,
// AckedPackets) default to 0/FALSE/NULL via {} initialization.
//
static QUIC_ACK_EVENT MakeAckEvent(
    uint64_t TimeNow,
    uint64_t LargestAck,
    uint64_t LargestSentPacketNumber,
    uint32_t BytesAcked,
    uint64_t SmoothedRtt = 50000,
    uint64_t MinRtt = 45000,
    BOOLEAN MinRttValid = TRUE)
{
    QUIC_ACK_EVENT Ack{};
    Ack.TimeNow = TimeNow;
    Ack.LargestAck = LargestAck;
    Ack.LargestSentPacketNumber = LargestSentPacketNumber;
    Ack.NumRetransmittableBytes = BytesAcked;
    Ack.NumTotalAckedRetransmittableBytes = BytesAcked;
    Ack.SmoothedRtt = SmoothedRtt;
    Ack.MinRtt = MinRtt;
    Ack.MinRttValid = MinRttValid;
    Ack.AdjustedAckTime = TimeNow;
    return Ack;
}

//
// Helper to construct a QUIC_LOSS_EVENT with common defaults.
//
static QUIC_LOSS_EVENT MakeLossEvent(
    uint32_t LostBytes,
    uint64_t LargestPacketNumberLost,
    uint64_t LargestSentPacketNumber,
    BOOLEAN PersistentCongestion = FALSE)
{
    QUIC_LOSS_EVENT Loss{};
    Loss.NumRetransmittableBytes = LostBytes;
    Loss.LargestPacketNumberLost = LargestPacketNumberLost;
    Loss.LargestSentPacketNumber = LargestSentPacketNumber;
    Loss.PersistentCongestion = PersistentCongestion;
    return Loss;
}

//
// GoogleTest fixture for CUBIC congestion control tests.
// Provides Connection, Settings, and Cubic members with a parameterized
// InitializeWithDefaults() helper that covers the common setup variations.
//
class CubicTest : public ::testing::Test {
protected:
    static constexpr uint16_t kIPv6UdpOverhead = 48; // IPv6 (40) + UDP (8) header bytes
    QUIC_CONNECTION Connection{};
    QUIC_SETTINGS_INTERNAL Settings{};
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic;
    QUIC_CONGESTION_CONTROL* CC;

    //
    // Common setup: initializes mock connection, configures settings, and
    // calls CubicCongestionControlInitialize. Covers all recurring variations.
    //
    void InitializeWithDefaults(
        uint32_t WindowPackets = 10,
        bool HyStart = false,
        uint16_t Mtu = 1280,
        uint32_t IdleTimeoutMs = 1000,
        bool GotRttSample = false,
        uint64_t SmoothedRtt = 50000,
        bool SetMinRtt = false,
        uint64_t MinRtt = 40000,
        uint64_t RttVariance = 5000
    )
    {
        Settings.InitialWindowPackets = WindowPackets;
        Settings.SendIdleTimeoutMs = IdleTimeoutMs;
        Settings.HyStartEnabled = HyStart ? TRUE : FALSE;

        InitializeMockConnection(Connection, Mtu);
        Connection.Settings.HyStartEnabled = HyStart ? TRUE : FALSE;
        if (GotRttSample) {
            Connection.Paths[0].GotFirstRttSample = TRUE;
            Connection.Paths[0].SmoothedRtt = SmoothedRtt;
        }
        if (SetMinRtt) {
            Connection.Paths[0].MinRtt = MinRtt;
            Connection.Paths[0].RttVariance = RttVariance;
        }
        CC = &Connection.CongestionControl;
        CubicCongestionControlInitialize(CC, &Settings);
        Cubic = &CC->Cubic;
    }

    void InitializeDefaultWithRtt(uint32_t WindowPackets = 10, bool HyStart = true) {
        InitializeWithDefaults(/*WindowPackets=*/WindowPackets, /*HyStart=*/HyStart, /*Mtu=*/1280, /*IdleTimeoutMs=*/1000, /*GotRttSample=*/true, /*SmoothedRtt=*/50000);
    }

    //
    // Helper to enter congestion avoidance from slow start.
    // Sends full window, triggers loss, sends additional data, then exits
    // recovery via an ACK. After this call:
    //   - IsInRecovery = FALSE, HasHadCongestionEvent = TRUE
    //   - CongestionWindow = SlowStartThreshold = pre-loss window * 7/10
    //   - TimeOfCongAvoidStart = 1050000
    //   - Connection.Send.NextPacketNumber = 15
    // Returns the post-loss CongestionWindow.
    //
    uint32_t EnterCongestionAvoidance(uint32_t LostBytes = 2400) {
        CC->QuicCongestionControlOnDataSent(CC, Cubic->CongestionWindow);
        Connection.Send.NextPacketNumber = 10;

        QUIC_LOSS_EVENT LossEvent = MakeLossEvent(LostBytes, 5, 10);
        CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

        Connection.Send.NextPacketNumber = 15;
        CC->QuicCongestionControlOnDataSent(CC, 5000);

        QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &ExitAck);

        return Cubic->CongestionWindow;
    }
};

//
// Test: CanSend scenarios
// Scenario: Comprehensive test of CanSend logic covering: available window (can send),
// congestion blocked (cannot send), and exemptions (bypass blocking). Tests the core
// congestion control decision logic.
//
TEST_F(CubicTest, CanSendScenarios)
{
    InitializeWithDefaults();
    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Scenario 1: Available window - can send
    // Simulate sending half the window
    CC->QuicCongestionControlOnDataSent(CC, CongestionWindow / 2);
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));

    // Scenario 2: Congestion blocked - cannot send
    // Simulate sending the rest to fill the window
    CC->QuicCongestionControlOnDataSent(CC, CongestionWindow / 2);
    ASSERT_FALSE(CC->QuicCongestionControlCanSend(CC));

    // Scenario 3: Exceeding window - still blocked
    // OnDataSent is unconditional (doesn't gate on CanSend), so BytesInFlight can exceed CongestionWindow
    CC->QuicCongestionControlOnDataSent(CC, 100);
    ASSERT_FALSE(CC->QuicCongestionControlCanSend(CC));

    // Scenario 4: With exemptions - can send even when blocked
    CC->QuicCongestionControlSetExemption(CC, 2);
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));
}

//
// Test: GetSendAllowance scenarios
// Scenario: Tests GetSendAllowance under different conditions: congestion blocked (returns 0),
// available window without pacing (returns full window), and invalid time (skips pacing).
// Covers the main decision paths in send allowance calculation.
//
TEST_F(CubicTest, GetSendAllowanceScenarios)
{
    InitializeWithDefaults();
    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Scenario 1: Congestion blocked - should return 0
    // Fill the window completely
    CC->QuicCongestionControlOnDataSent(CC, CongestionWindow);
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 1000, TRUE);
    ASSERT_EQ(Allowance, 0u);

    // Scenario 2: Available window without pacing - should return full window
    // Reset by acknowledging half the data
    Connection.Settings.PacingEnabled = FALSE;
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 5, 10, CongestionWindow / 2);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    uint32_t ExpectedAllowance = Cubic->CongestionWindow - Cubic->BytesInFlight;
    Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 1000, TRUE);
    ASSERT_EQ(Allowance, ExpectedAllowance);

    // Scenario 3: Invalid time - should skip pacing and return full window
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Allowance = CC->QuicCongestionControlGetSendAllowance(
        CC, 1000, FALSE); // FALSE = invalid time
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test: GetSendAllowance with active pacing
// Scenario: Tests the pacing logic that limits send rate based on RTT and congestion window.
// When pacing is enabled with valid RTT samples, the function calculates a pacing rate to
// smooth out packet transmission. This prevents burst sending and improves performance over
// certain network paths. The pacing calculation is: (EstimatedWnd * TimeSinceLastSend) / RTT,
// where EstimatedWnd = min(2*CW, SSThresh) in slow start.
// This test verifies that with pacing enabled, the allowance is rate-limited based on elapsed
// time, resulting in a smaller allowance than the full available congestion window.
//
TEST_F(CubicTest, GetSendAllowanceWithActivePacing)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    Connection.Settings.PacingEnabled = TRUE;
    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Set BytesInFlight to half the window to have available capacity
    CC->QuicCongestionControlOnDataSent(CC, CongestionWindow / 2);

    // Simulate 10ms elapsed since last send
    // In slow start, EstimatedWnd = 2*CW, so pacing = (2*CW * 10ms) / 50ms = CW * 2/5
    uint32_t TimeSinceLastSend = 10000; // 10ms in microseconds

    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, TimeSinceLastSend, TRUE);

    // Pacing formula: (EstimatedWnd * TimeSinceLastSend) / SmoothedRtt
    // In slow start (SSThresh == UINT32_MAX): EstimatedWnd = min(2*CW, SSThresh) = 2*12320 = 24640
    // Allowance = (24640 * 10000) / 50000 = 4928
    uint32_t EstimatedWnd = 2 * CongestionWindow; // slow start doubles
    uint32_t ExpectedPacedAllowance =
        (uint32_t)(((uint64_t)EstimatedWnd * TimeSinceLastSend) / Connection.Paths[0].SmoothedRtt);
    ASSERT_EQ(Allowance, ExpectedPacedAllowance);
}

//
// Test: Congestion window calculation
// Scenario: Tests that the initial congestion window is calculated correctly based on MTU and
// InitialWindowPackets. The expected congestion window is (MTU - 48) * InitialWindowPackets,
// where 48 bytes are reserved for IPv6 and UDP headers. This verifies that the initial
// congestion window is set according to the standard formula.
//
TEST_F(CubicTest, CongestionWindowCalculation)
{
    InitializeWithDefaults(/*WindowPackets=*/10, /*HyStart=*/false, /*Mtu=*/1280);
    uint32_t CongestionWindow = CC->QuicCongestionControlGetCongestionWindow(CC);
    // CongestionWindow = (MTU - 48) * InitialWindowPackets = (1280 - 48) * 10 = 12320
    uint32_t ExpectedCongestionWindow = (1280 - kIPv6UdpOverhead) * 10;
    ASSERT_EQ(CongestionWindow, ExpectedCongestionWindow);
}

//
// Test: Reset scenarios
// Scenario: Tests Reset function with both FullReset=FALSE (preserves BytesInFlight) and
// FullReset=TRUE (zeros BytesInFlight). Verifies that reset properly reinitializes CUBIC
// state: CongestionWindow, BytesInFlightMax, SlowStartThreshold, recovery flags,
// and HyStart state (via CubicCongestionHyStartResetPerRttRound + state change).
//
TEST_F(CubicTest, ResetScenarios)
{
    InitializeWithDefaults();
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t ExpectedWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Scenario 1: Partial reset (FullReset=FALSE) - preserves BytesInFlight
    // First, send some data and trigger a congestion event to set internal flags
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    // Trigger congestion event via loss
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 5, 10);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    uint32_t BytesInFlightBefore = Cubic->BytesInFlight;

    CC->QuicCongestionControlReset(CC, FALSE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightBefore); // Preserved

    // Window-related state re-initialized
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
    ASSERT_EQ(CC->QuicCongestionControlGetBytesInFlightMax(CC), ExpectedWindow / 2);

    // HyStart state reset
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    // After CubicCongestionHyStartResetPerRttRound: MinRttInCurrentRound = UINT64_MAX
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    // NOTE: MinRttInLastRound = UINT32_MAX (copied from MinRttInCurrentRound before
    // the round reset). MinRttInCurrentRound is set to UINT32_MAX instead of
    // UINT64_MAX (as used in Init at line 932). This is a production code bug — the
    // sentinel mismatch could trigger spurious HyStart delay detection after Reset.
    ASSERT_EQ(Cubic->MinRttInLastRound, (uint64_t)UINT32_MAX);

    // Scenario 2: Full reset (FullReset=TRUE) - zeros BytesInFlight
    // Reinitialize and send data again
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    // Trigger another congestion event
    LossEvent.NumRetransmittableBytes = 1200;
    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    CC->QuicCongestionControlReset(CC, TRUE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->BytesInFlight, 0u); // Zeroed with full reset

    // Same window/HyStart reset for full reset
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
    ASSERT_EQ(CC->QuicCongestionControlGetBytesInFlightMax(CC), ExpectedWindow / 2);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInLastRound, (uint64_t)UINT32_MAX); // Same sentinel bug as Scenario 1
}

//
// Test: CubicCongestionControlOnDataSent - BytesInFlight increases and exemptions decrement
// Scenario: Tests that OnDataSent correctly increments BytesInFlight when data is sent
// and decrements exemptions when probe packets are sent. This tracks outstanding data
// in the network and consumes exemptions. Verifies BytesInFlightMax is updated when
// BytesInFlight reaches a new maximum.
//
TEST_F(CubicTest, OnDataSent_IncrementsBytesInFlight)
{
    InitializeWithDefaults();

    // Scenario 1: Send less than BytesInFlightMax — max unchanged
    uint32_t InitialBytesInFlightMax = CC->QuicCongestionControlGetBytesInFlightMax(CC); // CW/2 = 6160
    uint32_t SmallSend = 1500;

    CC->QuicCongestionControlOnDataSent(CC, SmallSend);

    ASSERT_EQ(Cubic->BytesInFlight, SmallSend);
    ASSERT_EQ(CC->QuicCongestionControlGetBytesInFlightMax(CC), InitialBytesInFlightMax); // Unchanged: 1500 < 6160

    // Scenario 2: Send enough to exceed BytesInFlightMax — max updated
    uint32_t LargeSend = InitialBytesInFlightMax; // 6160, total BIF = 7660 > 6160
    CC->QuicCongestionControlOnDataSent(CC, LargeSend);

    ASSERT_EQ(Cubic->BytesInFlight, SmallSend + LargeSend);
    ASSERT_EQ(CC->QuicCongestionControlGetBytesInFlightMax(CC), SmallSend + LargeSend); // Updated: 7660 > 6160

    // Test exemption decrement
    CC->QuicCongestionControlSetExemption(CC, 5); // Set 5 exemptions
    CC->QuicCongestionControlOnDataSent(CC, 1500);
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 4u);

    // Test LastSendAllowance decrement
    // When NumRetransmittableBytes <= LastSendAllowance, allowance is reduced
    Cubic->LastSendAllowance = 2000; // Set initial allowance
    uint32_t TinySend = 500; // Send less than allowance
    CC->QuicCongestionControlOnDataSent(CC, TinySend);
    ASSERT_EQ(Cubic->LastSendAllowance, 2000u - TinySend); // Should be reduced

    // When NumRetransmittableBytes > LastSendAllowance, allowance is zeroed
    Cubic->LastSendAllowance = 1000;
    CC->QuicCongestionControlOnDataSent(CC, 3000); // 3000 > 1000
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
}

//
// Test: CubicCongestionControlOnDataInvalidated - BytesInFlight decreases
// Scenario: Tests OnDataInvalidated when sent packets are discarded (e.g., due to key
// phase change). BytesInFlight should decrease by the invalidated bytes since they're
// no longer considered in-flight. Critical for accurate congestion window management.
//
TEST_F(CubicTest, OnDataInvalidated_DecrementsBytesInFlight)
{
    InitializeWithDefaults();

    // Send data via OnDataSent to properly track BytesInFlightMax
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    uint32_t BytesToInvalidate = 2000;

    CC->QuicCongestionControlOnDataInvalidated(CC, BytesToInvalidate);

    ASSERT_EQ(Cubic->BytesInFlight, 3000u);
}

//
// Test: OnDataAcknowledged - Basic ACK Processing in Slow Start
// Scenario: Tests CubicCongestionControlOnDataAcknowledged for basic slow-start
// window growth. Sends data via OnDataSent (properly tracking BytesInFlightMax),
// then acknowledges a portion. The window should grow by BytesAcked since we are
// in slow start (CongestionWindow < SlowStartThreshold) with HyStart disabled
// (CWndSlowStartGrowthDivisor = 1).
//
TEST_F(CubicTest, OnDataAcknowledged_BasicAck)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);

    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send data via OnDataSent to properly track BytesInFlightMax.
    // Must send enough that BytesInFlightMax > (InitialWindow + BytesAcked) / 2
    // to avoid the 2*BytesInFlightMax clamping guard.
    uint32_t BytesSent = 10000;
    CC->QuicCongestionControlOnDataSent(CC, BytesSent);

    uint32_t BytesAcked = 5000;
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1050000, 5, 10, BytesAcked);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // Slow start growth: window increases by BytesAcked (divisor=1, HyStart disabled)
    // NewWindow = 12320 + 5000 = 17320, clamped by 2*BytesInFlightMax = 2*10000 = 20000 (no clamp)
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow + BytesAcked);
    ASSERT_EQ(Cubic->BytesInFlight, BytesSent - BytesAcked);
}

//
// Test: OnDataLost - Packet Loss Handling and Window Reduction
// Scenario: Tests CUBIC's response to packet loss. When packets are declared lost,
// the congestion window should be reduced by beta (0.7) and the connection enters
// recovery. Verifies window reduction, threshold update, and recovery state flags.
//
TEST_F(CubicTest, OnDataLost_WindowReduction)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20, /*HyStart = */ true);
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send data via OnDataSent to properly track BytesInFlightMax
    CC->QuicCongestionControlOnDataSent(CC, 10000);

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(3600, 10, 15);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // Verify window was reduced (CUBIC multiplicative decrease)
    // New window = InitialWindow * 0.7 = InitialWindow * 7 / 10
    // InitialWindow = (1280 - 48) * 20 = 24640 (IPv6 formula: MTU - 40 - 8)
    // Expected = 24640 * 7 / 10 = 17248
    uint32_t ExpectedWindow = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, ExpectedWindow);

    // Verify recovery state transitions
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
}

//
// Test: OnEcn - ECN Marking Handling
// Scenario: Tests Explicit Congestion Notification (ECN) handling. When ECN-marked packets
// are received, CUBIC should treat it as a congestion signal and reduce the window.
// Unlike loss, ECN does NOT save previous state (`if (!Ecn)` guard),
// so spurious congestion rollback cannot undo an ECN event.
//
TEST_F(CubicTest, OnEcn_CongestionSignal)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20, /*HyStart = */ true);
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send data via OnDataSent to properly track BytesInFlightMax
    CC->QuicCongestionControlOnDataSent(CC, 10000);

    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    CC->QuicCongestionControlOnEcn(CC, &EcnEvent);

    // Verify window was reduced due to ECN congestion signal (same as loss: 0.7x)
    // InitialWindow = (1280 - 48) * 20 = 24640 (IPv6 formula: MTU - 40 - 8)
    // Expected = 24640 * 7 / 10 = 17248
    uint32_t ExpectedWindow = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);

    // Verify recovery state transitions
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
}

//
// Test: GetNetworkStatistics - Statistics Retrieval
// Scenario: Tests retrieval of network statistics including congestion window, RTT estimates,
// and throughput metrics. Used for monitoring and diagnostics.
//
TEST_F(CubicTest, GetNetworkStatistics_RetrieveStats)
{
    InitializeWithDefaults(
        /*WindowPackets=*/10,
        /*HyStart=*/true,
        /*Mtu=*/1280,
        /*IdleTimeoutMs=*/1000,
        /*GotRttSample=*/true,
        /*SmoothedRtt=*/5000,
        /*SetMinRtt=*/true,
        /*MinRtt=*/4000,
        /*RttVariance=*/500
    );

    // Send data via OnDataSent to properly track BytesInFlightMax
    CC->QuicCongestionControlOnDataSent(CC, 8000);

    // Prepare network statistics structure (not QUIC_STATISTICS_V2)
    QUIC_NETWORK_STATISTICS NetworkStats;
    CxPlatZeroMemory(&NetworkStats, sizeof(NetworkStats));

    // Call through function pointer - note it takes Connection as first param
    CC->QuicCongestionControlGetNetworkStatistics(&Connection,CC,&NetworkStats);

    // Verify all 6 statistics fields were populated
    ASSERT_EQ(NetworkStats.CongestionWindow, Cubic->CongestionWindow);
    ASSERT_EQ(NetworkStats.BytesInFlight, Cubic->BytesInFlight);
    ASSERT_EQ(NetworkStats.SmoothedRTT, 5000u);
    // Bandwidth = CongestionWindow / SmoothedRtt = 12320 / 5000 = 2
    uint64_t ExpectedBandwidth = Cubic->CongestionWindow / Connection.Paths[0].SmoothedRtt;
    ASSERT_EQ(NetworkStats.Bandwidth, ExpectedBandwidth);
    // PostedBytes and IdealBytes come from SendBuffer, which is zero-initialized
    ASSERT_EQ(NetworkStats.PostedBytes, 0u);
    ASSERT_EQ(NetworkStats.IdealBytes, 0u);
}

//
// Test: Spurious Congestion Event - No-Op When Not In Recovery
// Scenario: Verifies OnSpuriousCongestionEvent returns FALSE with no state change
// when not in recovery (IsInRecovery=FALSE). The full rollback path is tested
// by SpuriousCongestion_StateRollback.
//
TEST_F(CubicTest, CongestionControlOnSpuriousCongestionEvent)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);
    CC->QuicCongestionControlOnDataSent(CC, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;
    // Not currently in recovery mode, so spurious congestion event should have no effect.
    ASSERT_FALSE(CC->QuicCongestionControlOnSpuriousCongestionEvent(CC));
}

//
// Test: Fast Convergence - Window Reduction Path
// Scenario: Tests CUBIC's fast convergence algorithm. When a new congestion event occurs
// before reaching the previous WindowMax, CUBIC applies an additional reduction factor
// to converge faster with other flows. This tests the WindowLastMax > WindowMax path.
//
TEST_F(CubicTest, FastConvergence_AdditionalReduction)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 30, /*HyStart = */ true);

    // Simulate first congestion event to establish WindowMax
    // Send data to fill the window
    uint32_t InitialWindow = Cubic->CongestionWindow;
    CC->QuicCongestionControlOnDataSent(CC, InitialWindow);

    // Trigger first loss event
    QUIC_LOSS_EVENT FirstLoss = MakeLossEvent(3000, 5, 10);

    CC->QuicCongestionControlOnDataLost(CC, &FirstLoss);

    // ACK while still in recovery (LargestAck == RecoverySentPacketNumber, so
    // recovery doesn't exit). Window stays at post-loss value.
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 10, 15, 5000);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // Send more data
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    // Trigger second loss event (before reaching previous WindowMax)
    // Must use LargestPacketNumberLost > RecoverySentPacketNumber (which is 10 from first loss)
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(3000, 15, 20);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // Fast convergence fires on the second loss because WindowLastMax (36960, set
    // during first loss) > WindowMax (25872, the current CW at second loss entry).
    // The code sets WindowLastMax = WindowMax = 25872, then applies:
    //   WindowMax = WindowMax * (10 + BETA) / 20 = 25872 * 17 / 20 = 21991
    uint32_t WindowAfterFirstLoss = InitialWindow * 7 / 10;  // 25872
    uint32_t ExpectedWindowMax = WindowAfterFirstLoss * 17 / 20;  // 21991
    ASSERT_EQ(Cubic->WindowMax, ExpectedWindowMax);
}

//
// Test: Recovery Exit Path
// Scenario: Tests exiting from recovery state when an ACK is received for a packet
// sent after recovery started (LargestAck > RecoverySentPacketNumber). Uses a
// non-persistent loss to enter recovery cleanly.
//
TEST_F(CubicTest, Recovery_ExitOnNewAck)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);

    // Enter recovery via non-persistent loss
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 8, 10);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // Now in recovery state
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);

    // Send new packet after recovery started
    Connection.Send.NextPacketNumber = 15;

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 15, 20, 1200);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // Should exit recovery
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
}

//
// Test: Zero Bytes Acknowledged - Early Exit
// Scenario: Tests the early exit path when BytesAcked is zero.
// This can occur with ACKs that don't contain retransmittable data.
//
TEST_F(CubicTest, ZeroBytesAcked_EarlyExit)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send some data to have bytes in flight
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 5, 10, 0);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // Window should not change with zero bytes acked
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);
}

//
// Test: Pacing with Slow Start Window Estimation
// Scenario: Tests pacing calculation during slow start phase. When in slow start,
// the estimated window is 2x current window (exponential growth). This covers
// the EstimatedWnd calculation branch in GetSendAllowance.
//
TEST_F(CubicTest, Pacing_SlowStartWindowEstimation)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    Connection.Settings.PacingEnabled = TRUE;

    // Ensure in slow start (SlowStartThreshold is UINT32_MAX by default after init)
    // Send data to have bytes in flight
    CC->QuicCongestionControlOnDataSent(CC, Cubic->CongestionWindow / 2);

    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 10000, TRUE);

    // Pacing formula: (EstimatedWnd * TimeSinceLastSend) / SmoothedRtt
    // In slow start: EstimatedWnd = min(2 * CongestionWindow, SlowStartThreshold) = 24640
    // CongestionWindow = (1280 - 48) * 10 = 12320
    uint32_t CongestionWindow = Cubic->CongestionWindow;
    uint64_t SmoothedRtt = Connection.Paths[0].SmoothedRtt;
    uint32_t TimeSinceLastSend = 10000;
    uint32_t EstimatedWnd = 2 * CongestionWindow; // SSThresh == UINT32_MAX, so min(2*CW, SST) = 2*CW
    uint32_t ExpectedAllowance = (uint32_t)(((uint64_t)EstimatedWnd * TimeSinceLastSend) / SmoothedRtt);
    ASSERT_EQ(Allowance, ExpectedAllowance);

    // Now test the case where estimated window (2x current) exceeds threshold
    // Set threshold to be between current window and 2x current window
    uint32_t CurrentWindow = Cubic->CongestionWindow;
    Cubic->SlowStartThreshold = CurrentWindow + (CurrentWindow / 2); // 1.5x current window = 18480

    // Call GetSendAllowance again
    // EstimatedWnd = min(2 * 12320, 18480) = 18480
    // Allowance = LastSendAllowance + (18480 * 10000) / 50000 = 4928 + 3696 = 8624
    // BUT capped at available window = CongestionWindow - BytesInFlight = 12320 - 6160 = 6160
    uint32_t Allowance2 = CC->QuicCongestionControlGetSendAllowance(CC, 10000, TRUE);

    // Verify exact calculated value (capped at available window)
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;
    uint32_t ExpectedAllowance2 = AvailableWindow;  // 6160 (capped)
    ASSERT_EQ(Allowance2, ExpectedAllowance2);
}

//
// Test: Pacing with Congestion Avoidance Window Estimation
// Scenario: Tests pacing calculation during congestion avoidance phase.
// When past slow start, estimated window is 1.25x current window (linear growth).
//
TEST_F(CubicTest, Pacing_CongestionAvoidanceEstimation)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    Connection.Settings.PacingEnabled = TRUE;

    // Enter congestion avoidance: loss reduces CW to 8624, SSThresh = 8624.
    // Use custom setup (not EnterCongestionAvoidance) because we need specific
    // BytesInFlight for the pacing derivation.
    uint32_t InitialWindow = Cubic->CongestionWindow;
    CC->QuicCongestionControlOnDataSent(CC, InitialWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    uint32_t WindowAfterLoss = InitialWindow * 7 / 10;
    uint32_t BytesInFlightAfterLoss = InitialWindow - LossEvent.NumRetransmittableBytes;

    // Exit recovery with ACK that also reduces BytesInFlight to a known value
    Connection.Send.NextPacketNumber = 15;
    uint32_t BytesAcked = WindowAfterLoss / 2;
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 15, 20, BytesAcked);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    uint32_t BytesInFlightAfterAck = BytesInFlightAfterLoss - BytesAcked;

    // Now in congestion avoidance and out of recovery
    // GetSendAllowance with TimeSinceLastSend=10000us, pacing enabled:
    // - CongestionWindow >= SlowStartThreshold, so EstimatedWnd = CongestionWindow * 1.25
    // - EstimatedWnd = 8624 + 8624/4 = 8624 + 2156 = 10780
    // - SendAllowance = LastSendAllowance + (EstimatedWnd * TimeSinceLastSend) / SmoothedRtt
    // - LastSendAllowance = 0 (first call after ACK)
    // - SendAllowance = 0 + (10780 * 10000) / 50000 = 107800000 / 50000 = 2156
    // - AvailableWindow = CongestionWindow - BytesInFlight = 8624 - 6808 = 1816
    // - SendAllowance (2156) > AvailableWindow (1816), so capped to 1816
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 10000, TRUE);

    uint64_t EstimatedWnd = WindowAfterLoss + (WindowAfterLoss >> 2);
    uint32_t AvailableWindow = WindowAfterLoss - BytesInFlightAfterAck;
    uint32_t CalculatedAllowance = (uint32_t)((EstimatedWnd * 10000) / 50000);
    uint32_t ExpectedAllowance = (CalculatedAllowance > AvailableWindow) ? AvailableWindow : CalculatedAllowance;

    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test: Pacing SendAllowance Capped at Available Window
// Scenario: When the pacing formula produces an allowance larger than the available
// congestion window (CW − BytesInFlight), it is capped to the available window.
// A large TimeSinceLastSend (1 second >> SmoothedRtt of 50ms) causes the pacing
// calculation to exceed the available space, exercising the cap.
//
TEST_F(CubicTest, Pacing_CappedAtAvailableWindow)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    Connection.Settings.PacingEnabled = TRUE;

    // Send data
    CC->QuicCongestionControlOnDataSent(CC, 1000);

    // Large time delta: pacing formula produces (24640 * 1000000) / 50000 = 492800,
    // which far exceeds available window (12320 - 1000 = 11320), triggering the cap.
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 1000000, TRUE);

    // Capped at available window
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;
    ASSERT_EQ(Allowance, AvailableWindow);
}

//
// Test: Congestion Avoidance AIMD vs CUBIC Window Selection
// Scenario: After loss triggers recovery and an ACK exits recovery, a subsequent
// ACK in congestion avoidance exercises the CUBIC formula and AIMD accumulator.
// The max(CUBIC, AIMD) selection determines the new window.
//
TEST_F(CubicTest, CongestionAvoidance_AIMDvsCubicSelection)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    uint32_t WindowAfterLoss = EnterCongestionAvoidance();

    // ACK in congestion avoidance: CUBIC/AIMD selection runs
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1100000, 15, 25, 1200);

    uint32_t WindowBeforeCongAvoid = Cubic->CongestionWindow;

    CC->QuicCongestionControlOnDataAcknowledged(CC, &CongAvoidAck);

    // Congestion avoidance ran: CW >= SSThresh so slow start is skipped,
    // CUBIC formula and AIMD both execute, max() selects the winner.
    ASSERT_FALSE(Cubic->IsInRecovery);

    // Derivation of expected CW:
    // KCubic = CubeRoot((24640/1232 * 3 << 9) / 4) = CubeRoot(7680) = 19
    // KCubic = S_TO_MS(19) = 19000; KCubic >>= 3 = 2375
    // TimeInCongAvoid = 1100000 - 1050000 = 50000 µs
    // DeltaT = US_TO_MS(50000 - 2375000 + 50000) = -2275
    // CubicWindow ≈ ((-2275²>>10) * -2275 * 492 >> 20) + 24640 ≈ 19245
    // AimdWindow(17248) < CubicWindow(19245) → CUBIC path selected
    // TargetWindow = max(17248, min(19245, 17248+8624)) = 19245
    // Growth = (19245 - 17248) * 1232 / 17248 = 142
    // Expected CW = 17248 + 142 = 17390
    ASSERT_GT(Cubic->CongestionWindow, WindowBeforeCongAvoid);
    ASSERT_LE(Cubic->CongestionWindow, WindowBeforeCongAvoid + (WindowBeforeCongAvoid >> 1));
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterLoss + (uint32_t)(((uint64_t)(19245 - WindowAfterLoss) * DatagramPayloadLength) / WindowAfterLoss));
}

//
// Test: AIMD Accumulator - Below WindowPrior (half-rate growth)
// Scenario: In congestion avoidance with AimdWindow < WindowPrior, the AIMD
// accumulator grows at half rate (BytesAcked / 2). This tests the Reno-friendly
// region where CUBIC is still catching up to the previous maximum window.
//
TEST_F(CubicTest, AIMD_AccumulatorBelowWindowPrior)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);

    // After loss: AimdWindow = CW * 7/10, WindowPrior = original CW
    // So AimdWindow < WindowPrior → half-rate accumulator path
    EnterCongestionAvoidance();

    // ACK in congestion avoidance: AIMD accumulator exercised
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    uint32_t BytesAcked = 600; // Half MTU
    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1100000, 16, 25, BytesAcked);

    ASSERT_EQ(Cubic->AimdAccumulator, 0u);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &CongAvoidAck);

    // AimdWindow < WindowPrior, so accumulator += BytesAcked / 2 = 300
    ASSERT_EQ(Cubic->AimdAccumulator, BytesAcked / 2);
}

//
// Test: AIMD Accumulator - Above WindowPrior (full-rate growth)
// Scenario: In congestion avoidance with AimdWindow >= WindowPrior, the AIMD
// accumulator grows at full rate (BytesAcked). This tests the path where CUBIC
// has surpassed its previous maximum and enters the convex region.
//
TEST_F(CubicTest, AIMD_AccumulatorAboveWindowPrior)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);

    EnterCongestionAvoidance();

    // Force AimdWindow >= WindowPrior so the full-rate accumulator path runs.
    // After loss, WindowPrior = original CW and AimdWindow = CW * 7/10.
    // Set AimdWindow = WindowPrior to enter the above-WindowPrior path.
    Cubic->AimdWindow = Cubic->WindowPrior;
    ASSERT_EQ(Cubic->AimdAccumulator, 0u);

    // ACK in congestion avoidance with full-rate accumulation
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    uint32_t BytesAcked = 1200;
    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1100000, 16, 25, BytesAcked);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &CongAvoidAck);

    // AimdWindow >= WindowPrior, so accumulator += BytesAcked (full rate, not halved)
    ASSERT_EQ(Cubic->AimdAccumulator, BytesAcked);
}

//
// Test: AIMD Accumulator - Triggers Window Growth
// Scenario: When AimdAccumulator exceeds AimdWindow, AimdWindow grows by one
// DatagramPayloadLength (1 MSS). We set AimdWindow
// to a small value so a single ACK of sufficient size triggers the growth, and
// BytesAcked exceeds AimdWindow + DatagramPayloadLength to avoid unsigned
// underflow in the subtraction (AimdAccumulator -= AimdWindow).
//
TEST_F(CubicTest, AIMD_AccumulatorTriggersWindowGrowth)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    EnterCongestionAvoidance();

    // Set AimdWindow small enough that a single ACK triggers growth.
    // Use full-rate path: AimdWindow >= WindowPrior.
    // BytesAcked must exceed AimdWindow + DatagramPayloadLength to avoid
    // unsigned underflow in the subtraction (AimdAccumulator -= AimdWindow).
    uint32_t SmallAimdWindow = 100;
    Cubic->AimdWindow = SmallAimdWindow;
    Cubic->WindowPrior = SmallAimdWindow; // AimdWindow >= WindowPrior → full-rate
    Cubic->AimdAccumulator = 0;

    CC->QuicCongestionControlOnDataSent(CC, 3000);

    uint32_t BytesAcked = SmallAimdWindow + DatagramPayloadLength + 100; // 1432: comfortably exceeds threshold
    QUIC_ACK_EVENT GrowthAck = MakeAckEvent(1100000, 16, 25, BytesAcked);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &GrowthAck);

    // Full-rate: AimdAccumulator += BytesAcked = 1432. 1432 > 100 → trigger growth.
    // AimdWindow = 100 + DatagramPayloadLength = 1332
    // AimdAccumulator = 1432 - 1332 = 100
    ASSERT_EQ(Cubic->AimdWindow, SmallAimdWindow + DatagramPayloadLength);
    ASSERT_EQ(Cubic->AimdAccumulator, BytesAcked - (SmallAimdWindow + DatagramPayloadLength));
}

//
// Test: AIMD Sequential Linear Convergence
// Scenario: Verifies that multiple sequential ACKs produce linear AIMD window
// growth across several rounds. After entering congestion avoidance with
// AimdWindow >= WindowPrior (full-rate accumulation), each ACK of BytesAcked
// bytes adds BytesAcked to AimdAccumulator. When AimdAccumulator exceeds
// AimdWindow, the window grows by 1 DatagramPayloadLength and the accumulator
// wraps by subtracting the new AimdWindow. Over N ACKs, AimdWindow should
// grow by exactly floor(totalBytesAcked / averageAimdWindow) * DPL,
// demonstrating the linear AIMD convergence required by RFC 8312 §4.3.
//
TEST_F(CubicTest, AIMD_SequentialLinearConvergence)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    EnterCongestionAvoidance();

    // Set up for full-rate AIMD (AimdWindow >= WindowPrior).
    // Use a small AimdWindow so each ACK triggers exactly one growth.
    // BytesAcked per ACK = AimdWindow + DPL + 100 ensures:
    //   1. Accumulator exceeds AimdWindow → triggers growth
    //   2. Remainder is small → no double-growth in a single ACK
    uint32_t InitialAimdWindow = 1000;
    Cubic->AimdWindow = InitialAimdWindow;
    Cubic->WindowPrior = InitialAimdWindow; // full-rate path
    Cubic->AimdAccumulator = 0;

    // Send data to cover upcoming ACKs
    CC->QuicCongestionControlOnDataSent(CC, 20000);

    // Track expected state manually across multiple ACKs
    uint32_t ExpectedAimdWindow = InitialAimdWindow;
    uint32_t ExpectedAccumulator = 0;
    uint64_t TimeUs = 1100000;
    uint32_t PacketNum = 21;

    const int NumAcks = 5;
    for (int i = 0; i < NumAcks; i++) {
        uint32_t BytesAcked = ExpectedAimdWindow + DatagramPayloadLength + 100;

        QUIC_ACK_EVENT Ack = MakeAckEvent(TimeUs, PacketNum, PacketNum + 1, BytesAcked);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

        // Full-rate: accumulator += BytesAcked
        ExpectedAccumulator += BytesAcked;
        // Accumulator exceeds AimdWindow → grow by 1 DPL
        ExpectedAimdWindow += DatagramPayloadLength;
        ExpectedAccumulator -= ExpectedAimdWindow;

        ASSERT_EQ(Cubic->AimdWindow, ExpectedAimdWindow)
            << "AimdWindow mismatch after ACK " << (i + 1);
        ASSERT_EQ(Cubic->AimdAccumulator, ExpectedAccumulator)
            << "AimdAccumulator mismatch after ACK " << (i + 1);

        TimeUs += 50000; // advance 50ms per ACK
        PacketNum += 2;
    }

    // After 5 ACKs, AimdWindow should have grown by exactly 5 * DPL
    ASSERT_EQ(Cubic->AimdWindow, InitialAimdWindow + NumAcks * DatagramPayloadLength);
}

//
// Test: CubicWindow Overflow to BytesInFlightMax
// Scenario: Tests that when the CUBIC window formula overflows (producing a negative
// int64 result), the window is capped at 2*BytesInFlightMax. After exiting recovery,
// we manipulate TimeOfCongAvoidStart so the CUBIC formula's DeltaT produces a large
// negative value (KCubic >> TimeInCongAvoid), causing the cubic term to overflow.
//
TEST_F(CubicTest, CubicWindow_OverflowToBytesInFlightMax)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    uint32_t WindowAfterLoss = EnterCongestionAvoidance();

    // Force extreme conditions to trigger CUBIC overflow.
    // Set a huge WindowMax so KCubic is very large, making DeltaT deeply negative
    // when TimeInCongAvoid is small. The cubic term DeltaT^3 overflows negative.
    Cubic->WindowMax = UINT32_MAX;
    // Recalculate KCubic for the extreme WindowMax (mirrors the loss handler logic)
    Cubic->KCubic =
        CubeRoot(
            (Cubic->WindowMax / DatagramPayloadLength * (10 - 7) << 9) / 4);
    Cubic->KCubic = Cubic->KCubic * 1000; // S_TO_MS
    Cubic->KCubic >>= 3;

    // Skip time gap adjustment by invalidating the last ACK time
    Cubic->TimeOfLastAckValid = FALSE;

    // Second ACK: CUBIC formula runs with extreme KCubic, producing overflow
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    QUIC_ACK_EVENT OverflowAck = MakeAckEvent(1100000, 16, 25, 1200);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &OverflowAck);

    // CUBIC formula overflow: CubicWindow < 0, capped to 2*BytesInFlightMax.
    // The final CW is determined by max(CubicWindow, AimdWindow) and then the
    // BytesInFlightMax clamp. Verify the window is reasonable (not overflowed).
    ASSERT_FALSE(Cubic->IsInRecovery);
    // CUBIC formula overflow: CubicWindow < 0, capped to 2*BytesInFlightMax (58080).
    // But bounded growth limits TargetWindow to 1.5*CW = 1.5*17248 = 25872.
    // Growth = (25872 - 17248) * 1232 / 17248 = 616. New CW = 17248 + 616 = 17864.
    ASSERT_EQ(
        Cubic->CongestionWindow,
        WindowAfterLoss + (uint32_t)((uint64_t)(WindowAfterLoss * 3 / 2 - WindowAfterLoss) * DatagramPayloadLength / WindowAfterLoss)
    );
}

//
// Test: UpdateBlockedState - Unblock Flow
// Scenario: Tests the flow control unblocking path. When congestion window opens up
// (CanSend transitions from FALSE to TRUE), the function should return TRUE and
// remove the congestion control blocked reason.
//
TEST_F(CubicTest, AckFreesWindow_AllowsNewSends)
{
    InitializeWithDefaults();
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    // MTU=1280, payload = 1280 - 48 = 1232
    // InitialWindow = 10 * 1232 = 12320
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);

    // Start with blocked state by filling the window
    CC->QuicCongestionControlOnDataSent(CC, Cubic->CongestionWindow);
    // BytesInFlight = 12320

    // Now free up space by acknowledging half the data
    uint32_t BytesAcked = InitialWindow / 2;  // 6160
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 5, 10, BytesAcked);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // After ACK in slow start:
    // - BytesInFlight = 12320 - 6160 = 6160
    // - Window grows by BytesAcked = 6160 (slow start)
    // - NewWindow = 12320 + 6160 = 18480
    uint32_t NewWindow = InitialWindow + BytesAcked;
    uint32_t BytesInFlightAfterAck = InitialWindow - BytesAcked;
    ASSERT_EQ(Cubic->CongestionWindow, NewWindow);
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightAfterAck);

    // Note: CubicCongestionControlUpdateBlockedState is internal, but we can
    // test the logic through GetSendAllowance behavior changes
    // Pacing is NOT enabled, so Allowance = CongestionWindow - BytesInFlight
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 1000, TRUE);

    uint32_t ExpectedAllowance = NewWindow - BytesInFlightAfterAck;
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test: Spurious Congestion Event Rollback
// Scenario: Tests the spurious congestion event handling. When a congestion event
// is determined to be spurious (false positive), CUBIC should restore the previous
// state before the congestion event occurred.
//
TEST_F(CubicTest, SpuriousCongestion_StateRollback)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Trigger a congestion event first
    CC->QuicCongestionControlOnDataSent(CC, 10000);
    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeLoss, InitialWindow);
    Connection.Send.NextPacketNumber = 15;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 10, 15);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // After loss: Window = InitialWindow * 7 / 10
    uint32_t ExpectedWindowAfterLoss = WindowBeforeLoss * 7 / 10;
    uint32_t WindowAfterLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowAfterLoss, ExpectedWindowAfterLoss);

    // Now declare it spurious — returns TRUE if blocked state changed
    BOOLEAN SpuriousResult = CC->QuicCongestionControlOnSpuriousCongestionEvent(CC);

    // State should be restored
    ASSERT_EQ(Cubic->CongestionWindow, WindowBeforeLoss);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    // Before rollback: CanSend = TRUE (BIF=7600 < CW=17248).
    // After rollback: CanSend = TRUE (BIF=7600 < CW=24640). No state change → FALSE.
    ASSERT_FALSE(SpuriousResult);
}

//
// Test: App Limited API Coverage
// Scenario: Tests the IsAppLimited and SetAppLimited API functions. In the current
// CUBIC implementation, these are stub functions that don't track app-limited state.
// This test verifies the API is callable and doesn't crash.
//
TEST_F(CubicTest, AppLimited_APICoverage)
{
    InitializeWithDefaults(/*WindowPackets=*/20);

    // IsAppLimited currently always returns FALSE (stub implementation)
    BOOLEAN IsAppLimited = CC->QuicCongestionControlIsAppLimited(CC);
    ASSERT_FALSE(IsAppLimited);

    // SetAppLimited is a no-op in current implementation but should not crash
    CC->QuicCongestionControlSetAppLimited(CC);

    // Still returns FALSE after SetAppLimited (stub behavior)
    IsAppLimited = CC->QuicCongestionControlIsAppLimited(CC);
    ASSERT_FALSE(IsAppLimited);
}

//
// Test: Time Gap in ACKs - Idle Period Handling
// Scenario: Tests the idle-period time gap clamping logic.
// After exiting recovery, a large gap between ACKs (exceeding SendIdleTimeoutMs
// and RTT+4*RttVariance) should advance TimeOfCongAvoidStart to prevent the
// CUBIC formula from producing unrealistic window growth.
//
TEST_F(CubicTest, TimeGap_IdlePeriodHandling)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);
    Connection.Paths[0].RttVariance = 5000;

    // Trigger loss → recovery
    CC->QuicCongestionControlOnDataSent(CC, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 5, 10);

    CC->QuicCongestionControlOnDataLost(
        CC, &LossEvent);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // First ACK: exit recovery. This sets TimeOfCongAvoidStart and TimeOfLastAck.
    Connection.Send.NextPacketNumber = 15;
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &ExitAck);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->TimeOfLastAckValid);

    uint64_t TimeOfCongAvoidBefore = Cubic->TimeOfCongAvoidStart;

    // Second ACK: small gap (50ms), well within idle timeout. No time gap adjustment.
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    QUIC_ACK_EVENT NormalAck = MakeAckEvent(1100000, 14, 22, 1200);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &NormalAck);

    // Small gap: TimeOfCongAvoidStart unchanged
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, TimeOfCongAvoidBefore);

    TimeOfCongAvoidBefore = Cubic->TimeOfCongAvoidStart;

    // Third ACK: 5-second idle gap (exceeds SendIdleTimeoutMs=1000ms and
    // RTT+4*RttVar=50000+20000=70000µs). Time gap clamping should fire.
    CC->QuicCongestionControlOnDataSent(CC, 3000);

    QUIC_ACK_EVENT IdleAck = MakeAckEvent(6100000, 18, 25, 1200);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &IdleAck);

    // Time gap clamping fired: TimeOfCongAvoidStart advanced by the 5s idle gap.
    // TimeSinceLastAck = 6100000 - 1100000 = 5000000 µs.
    // New TimeOfCongAvoidStart = 1050000 + 5000000 = 6050000.
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, TimeOfCongAvoidBefore + 5000000);
}

//
// =========================================================================================
// HyStart++ State Transition Tests
// State Transition Table
// | From State          | To State            | Trigger | Condition                       |
// |---------------------|---------------------|---------|---------------------------------|
// | HYSTART_NOT_STARTED | HYSTART_ACTIVE      | T1      | RTT increase detected           |
// | HYSTART_NOT_STARTED | HYSTART_DONE        | T5      | Loss/ECN/Persistent congestion  |
// | HYSTART_ACTIVE      | HYSTART_DONE        | T2      | Conservative rounds completed   |
// | HYSTART_ACTIVE      | HYSTART_DONE        | T3      | Loss/ECN/Persistent congestion  |
// | HYSTART_ACTIVE      | HYSTART_NOT_STARTED | T6      | RTT decrease detected           |
// | HYSTART_DONE        | (no transitions)    | -       | Terminal state                  |
// =========================================================================================
//

//
// Test: HyStart++ Initialization State Verification
// Transition: Initial state check
// Scenario: Verifies that when HyStartEnabled=TRUE, the system initializes
// to HYSTART_NOT_STARTED with all supporting variables correctly set.
// This establishes the precondition for all other HyStart++ transitions.
//
TEST_F(CubicTest, HyStart_InitialStateVerification)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Verify initial state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInLastRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->HyStartRoundEnd, 0u);
    // At initialization, SlowStartThreshold = UINT32_MAX (slow start mode)
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
}

//
// Test: HyStart++ T5 - Direct Transition NOT_STARTED → DONE via Loss
// Transition: T5 in state model
// Scenario: Tests direct transition from NOT_STARTED to DONE when packet loss
// occurs before HyStart++ detection logic activates. This is the most common
// path when network conditions cause loss during initial slow start.
//
TEST_F(CubicTest, HyStart_T5_NotStartedToDone_ViaLoss)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Verify in NOT_STARTED state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeLoss, InitialWindow);

    // Send data to have bytes in flight
    CC->QuicCongestionControlOnDataSent(CC, 8000);
    Connection.Send.NextPacketNumber = 10;

    // Trigger loss event while still in NOT_STARTED
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // Postcondition: Should transition directly to DONE
    // After loss: Window = InitialWindow * 7 / 10, SSThresh = Window
    uint32_t ExpectedWindow = WindowBeforeLoss * 7 / 10;
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u); // Reset to normal
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, ExpectedWindow);
}

//
// Test: HyStart++ T5 - Direct Transition NOT_STARTED → DONE via ECN
// Transition: T5 in state model
// Scenario: Tests direct transition from NOT_STARTED to DONE when ECN marking
// is received, indicating congestion before HyStart++ activates.
//
TEST_F(CubicTest, HyStart_T5_NotStartedToDone_ViaECN)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);
    Settings.EcnEnabled = TRUE;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Verify in NOT_STARTED state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    uint32_t WindowBeforeECN = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeECN, InitialWindow);

    // Send data
    CC->QuicCongestionControlOnDataSent(CC, 8000);
    Connection.Send.NextPacketNumber = 15;

    // Trigger ECN event
    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    CC->QuicCongestionControlOnEcn(CC, &EcnEvent);

    // Postcondition: Should transition directly to DONE
    // After ECN: Window = InitialWindow * 7 / 10 (β = 0.7)
    uint32_t ExpectedWindow = WindowBeforeECN * 7 / 10;
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
}

//
// Test: HyStart++ T4 - Transition to DONE via Persistent Congestion
// Transition: T4 in state model
// Scenario: Tests transition from any state to DONE when persistent congestion
// is detected. This is the most severe congestion signal, causing drastic
// window reduction to minimum (2 packets).
//
TEST_F(CubicTest, HyStart_T4_AnyToDone_ViaPersistentCongestion)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 30, /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Can be in any state (we'll test from NOT_STARTED)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);

    uint32_t WindowBeforePersistent = Cubic->CongestionWindow;
    // Verify window is large (InitialWindow = 30 * 1232 = 36960)
    ASSERT_EQ(WindowBeforePersistent, InitialWindow);

    // Send data
    CC->QuicCongestionControlOnDataSent(CC, 15000);
    Connection.Send.NextPacketNumber = 20;

    // Trigger persistent congestion
    QUIC_LOSS_EVENT PersistentLoss = MakeLossEvent(8000, 15, 20, TRUE);

    CC->QuicCongestionControlOnDataLost(CC, &PersistentLoss);

    // Postcondition: Drastic reduction to minimum window
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Window should be reduced to minimum (2 packets)
    uint32_t ExpectedMinWindow = DatagramPayloadLength * QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedMinWindow);
}

//
// Test: HyStart++ Terminal State - DONE is Absorbing
// Transition: Verification that DONE has no outgoing transitions
// Scenario: Tests the mathematical proof that HYSTART_DONE is an absorbing state.
// Once in DONE, no further state transitions can occur (all HyStart++ logic is
// bypassed). This verifies the guard.
//
TEST_F(CubicTest, HyStart_TerminalState_DoneIsAbsorbing)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);

    // Transition to DONE state via loss
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // Verify in DONE state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Exit recovery to enable further ACK processing
    Connection.Send.NextPacketNumber = 20;

    // First, ACK the packet that exits recovery (sent after RecoverySentPacketNumber)
    QUIC_ACK_EVENT RecoveryExitAck = MakeAckEvent(1500000, 20, 25, 0, 50000, 48000);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &RecoveryExitAck);

    ASSERT_FALSE(Cubic->IsInRecovery);  // Should have exited recovery

    // Attempt to trigger state changes with various ACK patterns
    // None of these should change the state from DONE

    // Pattern 1: ACKs with varying RTT (would trigger T1 if not in DONE)
    for (int i = 0; i < 2 * QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            2000000 + (i * 10000), 20 + i, 25 + i, BytesToSend,
            50000, 45000 + (i * 1000));

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

        // State should remain DONE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    }

    // Pattern 2: Cross round boundaries (would trigger T2 if in ACTIVE)
    for (int round = 0; round < 2; round++) {
        Connection.Send.NextPacketNumber = 100 + (round * 20);

        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT BoundaryAck = MakeAckEvent(
            3000000 + (round * 60000),
            Connection.Send.NextPacketNumber,
            Connection.Send.NextPacketNumber + 5,
            BytesToSend, 50000, 48000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &BoundaryAck);

        // State should remain DONE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    }

    // Pattern 3: Decreasing RTT (would trigger T6 if in ACTIVE)
    uint32_t BytesToSend = 1200;
    CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

    QUIC_ACK_EVENT DecreaseAck = MakeAckEvent(4000000, 150, 160, BytesToSend, 50000, 30000);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &DecreaseAck);

    // Final verification: State is still DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
}

//
// Test: HyStart++ Disabled - State Unchanged on Congestion Events
// Transition: Verification of early-exit guard
// Scenario: When HyStartEnabled=FALSE (on Connection.Settings), the loss handler's
// HyStart state transition logic is guarded by the enabled flag. The state remains
// NOT_STARTED because the code path `Cubic->HyStartState = HYSTART_DONE` is only
// executed when HyStartEnabled=TRUE. Recovery still occurs normally.
//
TEST_F(CubicTest, HyStart_Disabled_NoTransitions)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20, /*HyStart = */ false);

    // Initial state should be NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);

    // Attempt various operations that would trigger transitions if enabled

    // 1. Send ACKs with increasing RTT (would trigger T1 if enabled).
    // Two iterations suffice — the guard is checked on every ACK.
    for (int i = 0; i < 2; i++) {
        CC->QuicCongestionControlOnDataSent(CC, 1200);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), i, i + 5, 1200,
            50000, 50000 + (i * 2000));

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

        // State should remain NOT_STARTED
        ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    }

    // 2. Trigger loss (would trigger T5)
    Connection.Send.NextPacketNumber = 20;

    // First send more data to have BytesInFlight for the loss
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 15, 20);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // HyStart state unchanged: When HyStartEnabled=FALSE, loss handler skips
    // the `Cubic->HyStartState = HYSTART_DONE` assignment. Recovery still occurs.
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_TRUE(Cubic->IsInRecovery); // Recovery happens independent of HyStart
}

//
// Test: HyStart++ State Invariant - Growth Divisor Consistency
// Transition: Verification of Growth Divisor Invariant from state model
// Scenario: Verifies CWndSlowStartGrowthDivisor is consistent across all
// three states by transitioning NOT_STARTED → ACTIVE → DONE:
// - NOT_STARTED → divisor = 1
// - ACTIVE → divisor = 4 (triggered via delay increase detection)
// - DONE → divisor = 1 (triggered via loss)
//
TEST_F(CubicTest, HyStart_StateInvariant_GrowthDivisor)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20,  /*HyStart = */ true);

    // Invariant 1: NOT_STARTED → divisor = 1
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Transition NOT_STARTED → ACTIVE via delay increase detection.
    // Set up high HyStartRoundEnd to avoid round boundary crossing.
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;
    Cubic->MinRttInLastRound = 40000; // 40ms baseline from "previous round"

    // Send N_SAMPLING (8) ACKs with elevated MinRtt to complete sampling.
    // Eta = MinRttInLastRound / 8 = 5000, threshold = 40000 + 5000 = 45000.
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        CC->QuicCongestionControlOnDataSent(    CC, 1200);
        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, 1200,
            50000, 46000);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);
    }
    ASSERT_EQ(Cubic->HyStartAckCount, 8u);

    // 9th ACK triggers delay increase detection → ACTIVE
    CC->QuicCongestionControlOnDataSent(CC, 1200);
    QUIC_ACK_EVENT TriggerAck = MakeAckEvent(1100000, 20, 25, 1200, 50000, 47000);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &TriggerAck);

    // Invariant 2: ACTIVE → divisor = 4
    ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 4u);

    // Transition ACTIVE → DONE via loss.
    // Send enough data to cover the loss bytes.
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    Connection.Send.NextPacketNumber = 30;
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 25, 30);
    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    // Invariant 3: DONE → divisor = 1
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test: HyStart++ Multiple Congestion Events - State Stability
// Transition: Multiple T5/T4 transitions
// Scenario: Tests that multiple congestion events keep the state in DONE and
// don't cause state corruption. Each event should trigger recovery logic but
// state should remain DONE.
//
TEST_F(CubicTest, HyStart_MultipleCongestionEvents_StateStability)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 30, /*HyStart = */ true);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // First congestion event: NOT_STARTED → DONE
    CC->QuicCongestionControlOnDataSent(CC, 8000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT FirstLoss = MakeLossEvent(2400, 5, 10);

    CC->QuicCongestionControlOnDataLost(CC, &FirstLoss);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    // After first loss: Window = InitialWindow * 7 / 10
    uint32_t WindowAfterFirst = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterFirst);

    // Exit recovery
    Connection.Send.NextPacketNumber = 20;
    QUIC_ACK_EVENT RecoveryExitAck = MakeAckEvent(1100000, 20, 25, 1200, 50000, 48000);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &RecoveryExitAck);

    // Second congestion event: DONE → DONE (should remain)
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    Connection.Send.NextPacketNumber = 30;

    QUIC_LOSS_EVENT SecondLoss = MakeLossEvent(1800, 28, 30);

    CC->QuicCongestionControlOnDataLost(CC, &SecondLoss);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
    // After second loss: Window = WindowAfterFirst * 7 / 10
    uint32_t WindowAfterSecond = WindowAfterFirst * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterSecond);

    // Third congestion event via ECN: DONE → DONE
    Connection.Send.NextPacketNumber = 40;
    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 35;
    EcnEvent.LargestSentPacketNumber = 40;

    CC->QuicCongestionControlOnEcn(CC, &EcnEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
}

//
// Test: HyStart++ Recovery Exit with State Persistence
// Transition: Verification that recovery exit doesn't affect HyStart state
// Scenario: When exiting recovery (IsInRecovery: TRUE → FALSE), the HyStart
// state should remain unchanged. Recovery is orthogonal to HyStart++ state.
//
TEST_F(CubicTest, HyStart_RecoveryExit_StatePersistence)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 20, /*HyStart = */ true);

    // Transition to DONE and enter recovery
    CC->QuicCongestionControlOnDataSent(CC, 8000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // Exit recovery by ACKing packet sent after recovery started
    Connection.Send.NextPacketNumber = 20;

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1100000, 20, 25, 1200, 50000, 48000);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &ExitAck);

    // Recovery should be exited but HyStart state unchanged
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
}

//
// Test: HyStart++ Spurious Congestion with State Verification
// Transition: State behavior during spurious congestion recovery
// Scenario: When a congestion event is declared spurious, window state is rolled
// back but HyStart state is NOT rolled back (it remains DONE). This is because
// HyStart++ state transitions are one-way and not part of the spurious recovery.
//
TEST_F(CubicTest, HyStart_SpuriousCongestion_StateNotRolledBack)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 25, /*HyStart = */ true);

    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Start in NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeLoss, InitialWindow);

    // Trigger congestion event (NOT_STARTED → DONE)
    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 15;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(3600, 10, 15);

    CC->QuicCongestionControlOnDataLost(CC, &LossEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    // After loss: Window = InitialWindow * 7 / 10
    uint32_t ExpectedWindowAfterLoss = WindowBeforeLoss * 7 / 10;
    uint32_t WindowAfterLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowAfterLoss, ExpectedWindowAfterLoss);

    // Declare congestion event spurious
    CC->QuicCongestionControlOnSpuriousCongestionEvent(CC);

    // Window state should be rolled back
    ASSERT_EQ(Cubic->CongestionWindow, WindowBeforeLoss);
    ASSERT_FALSE(Cubic->IsInRecovery);

    // BUT HyStart state should remain DONE (not rolled back)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Verify HyStart logic is still bypassed after spurious recovery
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1200000, 20, 25, 1200, 50000, 55000);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // State still DONE (HyStart++ logic bypassed)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
}

//
// Test: HyStart++ Delay Increase Detection - Eta Calculation and Condition Check
// Scenario: Covers the case of  triggering the delay increase
// detection logic after sampling phase completes. Tests the Eta calculation and
// the condition that checks if RTT has increased beyond the threshold.
//
TEST_F(CubicTest, HyStart_DelayIncreaseDetection_EtaCalculationAndCondition)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);

    // Verify initial state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);

    // Set Connection.Send.NextPacketNumber to a high value so HyStartRoundEnd is high
    // This ensures our ACKs with LargestAck < 100 won't trigger round boundary crossing
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;  // Manually set to match

    // Set up initial MinRttInLastRound to enable delay increase detection
    Cubic->MinRttInLastRound = 40000; // 40ms baseline RTT

    // Phase 1: Send N_SAMPLING (8) ACKs to complete sampling phase
    // This fills up the HyStartAckCount and sets MinRttInCurrentRound
    // Use LargestAck values < HyStartRoundEnd (100) to stay in the same round
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 42000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);
    }

    // After 8 ACKs, we should have completed sampling
    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED); // Still in NOT_STARTED
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 42000u);

    // Phase 2: Send one more ACK with MinRtt below the increase threshold
    // This triggers HyStartAckCount >= 8 and state is NOT_STARTED
    {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        // MinRtt = 43000, which is less than MinRttInLastRound (40000) + Eta (40000/8 = 5000)
        // 43000 < 45000
        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 43000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

        // Should still be in NOT_STARTED since delay increase wasn't significant
        ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
        ASSERT_EQ(Cubic->HyStartAckCount, 8u); // Should still be 8, not reset
    }
}

//
// Test: HyStart++ Delay Increase Detection - Trigger ACTIVE Transition
// Scenario: Triggers the delay increase detection logic with
// a significant RTT increase that causes transition from NOT_STARTED to ACTIVE state.
//
TEST_F(CubicTest, HyStart_DelayIncreaseDetection_TriggerActiveTransition)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);

    // Verify initial state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Set Connection.Send.NextPacketNumber high to avoid round boundary crossing
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;

    // Set up initial MinRttInLastRound to enable delay increase detection
    // Using 40000 us (40ms) as baseline from previous round
    Cubic->MinRttInLastRound = 40000;

    // Phase 1: Send N_SAMPLING (8) ACKs with HIGHER RTT values
    // MinRttInCurrentRound will be set to the minimum of these samples
    // We want MinRttInCurrentRound to end up >= 45000 us
    // Eta = MinRttInLastRound / 8 = 40000 / 8 = 5000 us
    // Threshold = MinRttInLastRound + Eta = 40000 + 5000 = 45000 us
    // So we use MinRtt = 46000 during sampling to get MinRttInCurrentRound = 46000
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 46000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);
    }

    // After 8 ACKs, sampling phase is complete
    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 46000u); // Min of all 46000 samples

    // Phase 2: Send one more ACK to trigger the delay increase detection
    // Now HyStartAckCount >= 8 and HyStartState == NOT_STARTED
    // - MinRttInLastRound (40000) != UINT64_MAX: TRUE
    // - MinRttInCurrentRound (46000) != UINT64_MAX: TRUE
    // - MinRttInCurrentRound (46000) >= MinRttInLastRound (40000) + Eta (5000): TRUE
    {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 47000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

        // Should transition to HYSTART_ACTIVE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);

        // Verify state changes
        ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 4u); // QUIC_CONSERVATIVE_SLOW_START_DEFAULT_GROWTH_DIVISOR
        ASSERT_EQ(Cubic->ConservativeSlowStartRounds, 5u); // QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS
        ASSERT_EQ(Cubic->CssBaselineMinRtt, 46000u); // Set to MinRttInCurrentRound
    }
}

//
// Test: HyStart++ RTT Decrease Detection - Return to NOT_STARTED
// Scenario: Covers the RTT decrease detection logic.
// When in HYSTART_ACTIVE state, if RTT decreases below the baseline, the algorithm
// assumes the previous slow start exit was spurious and returns to NOT_STARTED state.
//
TEST_F(CubicTest, HyStart_RttDecreaseDetection_ReturnToNotStarted)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);

    // Set Connection.Send.NextPacketNumber high to avoid round boundary crossing
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;

    // Set up initial MinRttInLastRound
    Cubic->MinRttInLastRound = 40000;

    // Phase 1: Collect 8 samples with high RTT to complete sampling
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 46000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);
    }

    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 46000u);

    // Phase 2: Trigger transition to HYSTART_ACTIVE with high RTT
    {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 47000);

        CC->QuicCongestionControlOnDataAcknowledged(
            CC,
            &AckEvent);

        ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
        ASSERT_EQ(Cubic->CssBaselineMinRtt, 46000u);
    }

    // Phase 3: Cross a round boundary to reset HyStartAckCount
    // This will move MinRttInCurrentRound (46000) to MinRttInLastRound
    // and reset MinRttInCurrentRound to UINT64_MAX for new sampling
    {
        // Update NextPacketNumber so HyStartRoundEnd will be set to a high value
        Connection.Send.NextPacketNumber = 200;

        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1200000, 100, 105, BytesToSend, 50000, 46000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

        // Still in HYSTART_ACTIVE, but round has been reset
        // HyStartRoundEnd should now be 200
        ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
        ASSERT_EQ(Cubic->HyStartAckCount, 0u); // Reset by round boundary crossing
        ASSERT_EQ(Cubic->MinRttInLastRound, 46000u); // Moved from current round
        ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX); // Reset for new round
        ASSERT_EQ(Cubic->HyStartRoundEnd, 200u); // Set to NextPacketNumber
    }

    // Phase 4: Collect samples in new round with LOWER RTT values
    // This will set MinRttInCurrentRound to a lower value (38000)
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1300000 + (i * 10000), 110 + i, 115 + i, BytesToSend,
            50000, 38000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);
    }

    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 38000u);

    // Phase 5: Send one more ACK to trigger the else branch RTT decrease detection
    // Now HyStartAckCount >= 8 and HyStartState == HYSTART_ACTIVE
    // MinRttInCurrentRound (38000) < CssBaselineMinRtt (46000), so should transition
    {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1400000, 120, 125, BytesToSend, 50000, 39000);

        CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

        // Should transition back to NOT_STARTED due to RTT decrease
        ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
        ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u); // Reset to normal slow start
    }
}

//
// Test: HyStart++ Conservative Slow Start Rounds - Transition to DONE
// Scenario: Covers the round boundary crossing logic
// when in HYSTART_ACTIVE state. After completing the configured number of
// conservative slow start rounds, the algorithm transitions to HYSTART_DONE.
//
TEST_F(CubicTest, HyStart_ConservativeSlowStartRounds_TransitionToDone)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ true);

    // Set Connection.Send.NextPacketNumber to control round boundaries
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;

    Cubic->MinRttInLastRound = 40000;

    // Phase 1: Collect 8 samples with high RTT
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 46000);

        CC->QuicCongestionControlOnDataAcknowledged(
            CC,
            &AckEvent);
    }

    // Phase 2: Transition to HYSTART_ACTIVE
    {
        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 47000);

        CC->QuicCongestionControlOnDataAcknowledged(
            CC,
            &AckEvent);

        ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
        ASSERT_EQ(Cubic->ConservativeSlowStartRounds, QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS); // Default = 5
    }

    // Phase 3: Cross QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS + 1 round boundaries to
    // decrement ConservativeSlowStartRounds
    // Each round boundary crossing when LargestAck >= HyStartRoundEnd will decrement the counter
    for (uint32_t round = 0; round < QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS + 1; round++) {
        // Set NextPacketNumber to a higher value for the next round
        Connection.Send.NextPacketNumber = 100 + (round + 1) * 100;

        uint32_t BytesToSend = 1200;
        CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

        // Use LargestAck >= current HyStartRoundEnd to trigger round boundary
        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1200000 + (round * 100000),
            Cubic->HyStartRoundEnd,
            Connection.Send.NextPacketNumber + 10,
            BytesToSend, 50000, 46000);

        CC->QuicCongestionControlOnDataAcknowledged(
            CC,
            &AckEvent);

        if (round < QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS - 1) {
            // Still in HYSTART_ACTIVE for first n-1 rounds
            ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
            ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX); // Still at init value during ACTIVE rounds
            ASSERT_EQ(Cubic->ConservativeSlowStartRounds, QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS - 1 - round);
        } else {
            // for the rest of the rounds, state should transition
            // to HYSTART_DONE and stay there
            ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
            ASSERT_EQ(Cubic->ConservativeSlowStartRounds, 0u);
            // SlowStartThreshold is set to current congestion window when transitioning to DONE
            ASSERT_EQ(Cubic->SlowStartThreshold, Cubic->CongestionWindow);
        }
    }
}

//
// Test: Congestion Avoidance Time Gap - Overflow Protection
// Scenario: Covers the overflow protection logic when a large time gap causes
// TimeOfCongAvoidStart adjustment to overflow. Tests the boundary condition
// where TimeOfCongAvoidStart might exceed TimeNowUs after adjustment.
//
TEST_F(CubicTest, CongestionAvoidance_TimeGapOverflowProtection)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    Connection.Paths[0].RttVariance = 10000;

    // Force into congestion avoidance by setting window >= threshold
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 20000;

    // Set TimeOfCongAvoidStart to a value where adding a gap would overflow
    uint64_t TimeNowUs = 5000000; // 5 seconds
    Cubic->TimeOfCongAvoidStart = UINT64_MAX - 2000000; // Very close to max
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->TimeOfLastAck = TimeNowUs - 2000000; // 2 seconds ago

    // TimeSinceLastAck = 5000000 - 3000000 = 2000000 us (2 seconds)
    // This is > SendIdleTimeoutMs (1000ms = 1000000us)
    // This is > SmoothedRtt + 4*RttVariance = 50000 + 40000 = 90000us
    // So the gap adjustment will be triggered

    // TimeOfCongAvoidStart + TimeSinceLastAck would overflow:
    // (UINT64_MAX - 2000000) + 2000000 = UINT64_MAX + 0, wrapping around
    // After adding, TimeOfCongAvoidStart would be > TimeNowUs
    // Line 585 checks CxPlatTimeAtOrBefore64(TimeNowUs, TimeOfCongAvoidStart)
    // If true (TimeNowUs <= TimeOfCongAvoidStart), clamp to TimeNowUs

    // Send data
    uint32_t BytesToSend = 1200;
    CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(TimeNowUs, 10, 15, BytesToSend, 50000, 45000, FALSE);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // TimeOfCongAvoidStart should be clamped to TimeNowUs to prevent issues
    // in TimeInCongAvoid calculation
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, TimeNowUs);
}

//
// Test: Congestion Avoidance - Bounded Growth Clamp
// Scenario: When the CUBIC formula produces a window far exceeding the current
// CongestionWindow (e.g., due to large DeltaT with KCubic=0), the bounded
// growth clamp constrains TargetWindow to at most 1.5×CW.
// This prevents unrealistic single-ACK window jumps. The growth per ACK is
// then (TargetWindow - CW) * DatagramPayloadLength / CW.
//
TEST_F(CubicTest, CongestionAvoidance_BoundedGrowthClamp)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    // Force into congestion avoidance
    uint32_t CW = 20000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = CW;

    // Set WindowMax to maximum value. With KCubic=0 and long TimeInCongAvoid,
    // DeltaT is capped to 2.5M, producing a huge positive
    // CubicWindow. The bounded growth clamp limits TargetWindow to 1.5*CW.
    Cubic->WindowMax = UINT32_MAX;
    Cubic->BytesInFlightMax = 50000;

    uint64_t TimeNowUs = 30000000000ULL; // 30000 seconds
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->KCubic = 0;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->TimeOfLastAck = TimeNowUs - 100000;

    uint32_t BytesToSend = 1200;
    CC->QuicCongestionControlOnDataSent(CC, BytesToSend);

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(TimeNowUs, 10, 15, BytesToSend, 50000, 45000, FALSE);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckEvent);

    // CubicWindow is huge positive (DeltaT³ term dominates), exceeding 1.5*CW.
    // Bounded growth clamp: TargetWindow = max(CW, min(CubicWindow, CW + CW/2))
    //                     = max(20000, min(huge, 30000)) = 30000
    // Growth = (TargetWindow - CW) * DatagramPayloadLength / CW
    //        = (30000 - 20000) * 1232 / 20000 = 616
    // NewCW = 20000 + 616 = 20616
    uint32_t TargetWindow = CW + CW / 2;
    uint32_t ExpectedGrowth = (uint32_t)(((uint64_t)(TargetWindow - CW) * DatagramPayloadLength) / CW);
    ASSERT_EQ(Cubic->CongestionWindow, CW + ExpectedGrowth);
}

//
// Test: Slow Start Window Overflow After Persistent Congestion
// Scenario: After persistent congestion, window is reset to 2*MTU while threshold
// remains at a higher value, creating window < threshold condition. A large ACK
// can then trigger the overflow logic where window grows beyond threshold.
//
TEST_F(CubicTest, SlowStart_WindowOverflowAfterPersistentCongestion)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);

    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);

    // Trigger PERSISTENT congestion directly (window will be reduced to 2*MTU)
    CC->QuicCongestionControlOnDataSent(CC, 1200);
    Connection.Send.NextPacketNumber = 25;

    QUIC_LOSS_EVENT PersistentLoss = MakeLossEvent(1200, 20, 25, TRUE);

    CC->QuicCongestionControlOnDataLost(CC, &PersistentLoss);

    // After persistent congestion:
    // - Window is reset to 2 * DatagramPayloadLength (minimum window)
    // - Threshold is set to old_window * 0.7
    uint32_t ExpectedWindowAfterPC = DatagramPayloadLength * QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS;
    uint32_t ExpectedThresholdAfterPC = InitialWindow * 7 / 10;
    uint32_t WindowAfterPC = Cubic->CongestionWindow;
    uint32_t ThresholdAfterPC = Cubic->SlowStartThreshold;

    ASSERT_EQ(WindowAfterPC, ExpectedWindowAfterPC);
    ASSERT_EQ(ThresholdAfterPC, ExpectedThresholdAfterPC);
    // Persistent congestion sets AimdWindow = CW * 7/10
    ASSERT_EQ(Cubic->AimdWindow, ExpectedThresholdAfterPC);

    // We're in recovery after persistent congestion. Need to exit recovery first.
    // Exit recovery by ACKing a packet sent after the recovery started
    Connection.Send.NextPacketNumber = 30;
    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT RecoveryExitAck = MakeAckEvent(1100000, 30, 31, 1200, 50000, 45000, FALSE);

    CC->QuicCongestionControlOnDataAcknowledged(CC, &RecoveryExitAck);

    // Recovery exits but window doesn't grow on the same ACK (code goes to Exit)
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterPC); // Window unchanged on recovery exit

    // Now send and ACK enough bytes to exceed threshold
    // In slow start, window grows by BytesAcked
    uint32_t BytesToExceedThreshold = ThresholdAfterPC - WindowAfterPC + 1000;

    CC->QuicCongestionControlOnDataSent(CC, BytesToExceedThreshold);

    QUIC_ACK_EVENT LargeAck = MakeAckEvent(1200000, 30, 35, BytesToExceedThreshold, 50000, 45000, FALSE);

    // Before ACK: verify we're in slow start
    // Window after recovery exit + BytesInFlight may be < threshold

    CC->QuicCongestionControlOnDataAcknowledged(CC, &LargeAck);

    // After ACK: verify overflow logic executed
    // 1. TimeOfCongAvoidStart should be set
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, LargeAck.TimeNow);

    // 2. Window should be clamped to threshold
    ASSERT_EQ(Cubic->CongestionWindow, ThresholdAfterPC);
}

//
// Test: Reno-Friendly Region (CW = AimdWindow path)
// Scenario: After a loss with a small initial window (3 packets), a large ACK
// in congestion avoidance grows AimdWindow past CubicWindow via the AIMD
// accumulator. Since AimdWindow > CubicWindow, the Reno-friendly region
// CW is set to AimdWindow directly, instead of using the
// bounded growth formula from the concave/convex region.
//
TEST_F(CubicTest, CongestionAvoidance_RenoFriendlyRegion)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 3, /*HyStart = */ false);
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    uint32_t WindowAfterLoss = EnterCongestionAvoidance(/*LostBytes=*/1200);

    // Large ACK in congestion avoidance.
    // BytesAcked=10000 grows AimdAccumulator by 5000 (half-rate: AimdWindow < WindowPrior).
    // 5000 > AimdWindow(2587) → AimdWindow += 1232 = 3819, accumulator = 5000 - 3819 = 1181.
    //
    // KCubic = CubeRoot((3696/1232 * 3 << 9) / 4) = CubeRoot(1152) = 10
    // KCubic = S_TO_MS(10) = 10000; >>3 = 1250
    // TimeInCongAvoid = 1051000 - 1050000 = 1000 µs
    // DeltaT = US_TO_MS(1000 - 1250000 + 50000) = -1199
    // CubicWindow = ((-1199²>>10) * -1199 * 492 >> 20) + 3696 = -790 + 3696 = 2906
    //
    // AimdWindow(3819) > CubicWindow(2906) → Reno-friendly region: CW = AimdWindow
    CC->QuicCongestionControlOnDataSent(CC, 10000);

    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1051000, 21, 25, 10000);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &CongAvoidAck);

    // Verify CW was set from AimdWindow (Reno-friendly), not bounded growth.
    uint32_t ExpectedAimdWindow = WindowAfterLoss + DatagramPayloadLength; // 2587 + 1232 = 3819
    ASSERT_EQ(Cubic->AimdWindow, ExpectedAimdWindow);
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedAimdWindow);
}

//
// Test: ECN Spurious Rollback Restores Stale State
// Scenario: When ECN triggers a congestion event, the `if (!Ecn)` guard
// skips saving previous state (PrevCongestionWindow, etc.).
// If OnSpuriousCongestionEvent is called afterward, it enters the rollback path
// (IsInRecovery is TRUE) but restores the stale/zero Prev* values—NOT the
// pre-ECN state. This confirms the asymmetry between loss-based and ECN-based
// congestion events: loss saves rollback state, ECN does not.
//
TEST_F(CubicTest, ECN_SpuriousRollbackRestoresStaleState)
{
    InitializeDefaultWithRtt(/*WindowPackets = */ 10, /*HyStart = */ false);
    uint32_t PreEcnWindow = Cubic->CongestionWindow; // 12320

    // Send some data so BytesInFlight > 0 (required for realistic state)
    CC->QuicCongestionControlOnDataSent(CC, 1200);
    Connection.Send.NextPacketNumber = 10;

    // Verify Prev* fields are zero (no prior loss-based congestion event)
    ASSERT_EQ(Cubic->PrevCongestionWindow, 0u);
    ASSERT_EQ(Cubic->PrevAimdWindow, 0u);
    ASSERT_EQ(Cubic->PrevSlowStartThreshold, 0u);

    // Trigger ECN congestion event — first congestion event in this connection
    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 5;
    EcnEvent.LargestSentPacketNumber = 10;

    CC->QuicCongestionControlOnEcn(CC, &EcnEvent);

    // After ECN: window reduced to 0.7x, recovery entered
    uint32_t PostEcnWindow = PreEcnWindow * 7 / 10; // 8624
    ASSERT_EQ(Cubic->CongestionWindow, PostEcnWindow);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);

    // ECN does NOT save Prev* (`if (!Ecn)` guard)
    ASSERT_EQ(Cubic->PrevCongestionWindow, 0u);
    ASSERT_EQ(Cubic->PrevAimdWindow, 0u);

    // Call spurious rollback — enters rollback (IsInRecovery=TRUE) but
    // restores stale zero Prev* values, NOT the pre-ECN state
    CC->QuicCongestionControlOnSpuriousCongestionEvent(CC);

    // State flags cleared
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);

    // CW restored to PrevCongestionWindow = 0, NOT to PreEcnWindow (12320)
    // or PostEcnWindow (8624). This documents the ECN rollback asymmetry.
    ASSERT_NE(Cubic->CongestionWindow, PreEcnWindow);
    ASSERT_NE(Cubic->CongestionWindow, PostEcnWindow);
    ASSERT_EQ(Cubic->CongestionWindow, 0u);
    ASSERT_EQ(Cubic->AimdWindow, 0u);
    ASSERT_EQ(Cubic->SlowStartThreshold, 0u);
}
