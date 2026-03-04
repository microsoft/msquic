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
    CxPlatZeroMemory(&Connection, sizeof(Connection));
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
// Initialize() helper that covers the common setup variations.
//
class CubicFixturedTest : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic;

    //
    // Common setup: initializes mock connection, configures settings, and
    // calls CubicCongestionControlInitialize. Covers all recurring variations.
    //
    void Initialize(
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
        CxPlatZeroMemory(&Settings, sizeof(Settings));
        Settings.InitialWindowPackets = WindowPackets;
        Settings.SendIdleTimeoutMs = IdleTimeoutMs;
        if (HyStart) {
            Settings.HyStartEnabled = TRUE;
        }

        InitializeMockConnection(Connection, Mtu);
        if (HyStart) {
            Connection.Settings.HyStartEnabled = TRUE;
        }
        if (GotRttSample) {
            Connection.Paths[0].GotFirstRttSample = TRUE;
            Connection.Paths[0].SmoothedRtt = SmoothedRtt;
        }
        if (SetMinRtt) {
            Connection.Paths[0].MinRtt = MinRtt;
            Connection.Paths[0].RttVariance = RttVariance;
        }

        CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
        Cubic = &Connection.CongestionControl.Cubic;
    }
};


//
// Test 1: Comprehensive initialization verification
// Scenario: Verifies CubicCongestionControlInitialize correctly sets up all CUBIC state
// including settings, function pointers, state flags, HyStart fields, and zero-initialized fields.
// This consolidates basic initialization, function pointer, state flags, HyStart, and zero-field checks.
//
TEST_F(CubicFixturedTest, InitializeComprehensive)
{
    Initialize(); // With default parameters

    Cubic->BytesInFlight = 12345;
    Cubic->Exemptions = 5;


    // Verify settings stored correctly
    ASSERT_EQ(Cubic->InitialWindowPackets, 10u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 1000u);
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);

    // Verify congestion window initialized
    // PayloadLength = 1280 - 48 = 1232, CongestionWindow = 1232 * 10 = 12320
    uint16_t ExpectedPayloadLength = 1280 - 48;
    uint32_t ExpectedCongestionWindow = ExpectedPayloadLength * 10;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedCongestionWindow);
    ASSERT_EQ(Cubic->BytesInFlightMax, Cubic->CongestionWindow / 2);

    // Verify all 17 function pointers are set
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlCanSend, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlSetExemption, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlReset, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetSendAllowance, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataSent, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataInvalidated, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnDataLost, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnEcn, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlLogOutFlowStatus, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetExemptions, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetBytesInFlightMax, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlIsAppLimited, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlSetAppLimited, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetCongestionWindow, nullptr);
    ASSERT_NE(Connection.CongestionControl.QuicCongestionControlGetNetworkStatistics, nullptr);

    // Verify boolean state flags
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
    ASSERT_FALSE(Cubic->TimeOfLastAckValid);

    // Verify HyStart fields
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartRoundEnd, 0u);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInLastRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 2: Initialization with boundary parameter values
// Scenario: Tests initialization with extreme boundary values for MTU, InitialWindowPackets,
// and SendIdleTimeoutMs to ensure robustness across all valid configurations.
//
TEST_F(CubicFixturedTest, InitializeBoundaries)
{
    // Test minimum MTU with minimum window
    Initialize(/*WindowPackets=*/ 1, /*HyStart=*/ false, /*Mtu=*/ QUIC_DPLPMTUD_MIN_MTU, /*IdleTimeoutMs=*/ 0);
    uint32_t ExpectedMinWindow = (QUIC_DPLPMTUD_MIN_MTU - 48) * 1;  // 1232
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedMinWindow);
    ASSERT_EQ(Cubic->InitialWindowPackets, 1u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 0u);

    // Test maximum MTU with maximum window and timeout
    Initialize(/*WindowPackets=*/1000, /*HyStart=*/false, /*Mtu=*/65535, /*IdleTimeoutMs=*/UINT32_MAX);
    uint32_t ExpectedMaxWindow = (65535 - 48) * 1000;  // 65487000
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedMaxWindow);
    ASSERT_EQ(Cubic->InitialWindowPackets, 1000u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, UINT32_MAX);

    // Test very small MTU (below minimum)
    Initialize(/*WindowPackets=*/10, /*HyStart=*/false, /*Mtu=*/500);
    uint32_t ExpectedSmallWindow = (500 - 48) * 10;  // 4520
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedSmallWindow);
}

//
// Test 3: Re-initialization behavior
// Scenario: Tests that CUBIC can be re-initialized with different settings and correctly
// updates its state. Verifies that calling CubicCongestionControlInitialize() multiple times
// properly resets state and applies new settings (e.g., doubling InitialWindowPackets should
// double the CongestionWindow). Important for connection migration or settings updates.
//
TEST_F(CubicFixturedTest, MultipleSequentialInitializations)
{
    Initialize(); // Initial initialization with default parameters

    uint32_t FirstCongestionWindow = Connection.CongestionControl.Cubic.CongestionWindow;

    // Re-initialize with different settings
    Settings.InitialWindowPackets = 20;
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // Should reflect new settings with doubled window
    ASSERT_EQ(Cubic->InitialWindowPackets, 20u);
    ASSERT_EQ(Cubic->CongestionWindow, FirstCongestionWindow * 2);
}

//
// Test 4: CanSend scenarios (via function pointer)
// Scenario: Comprehensive test of CanSend logic covering: available window (can send),
// congestion blocked (cannot send), and exemptions (bypass blocking). Tests the core
// congestion control decision logic.
//
TEST_F(CubicFixturedTest, CanSendScenarios)
{
    Initialize();

    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Scenario 1: Available window - can send
    // Simulate sending half the window
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, CongestionWindow / 2);
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 2: Congestion blocked - cannot send
    // Simulate sending the rest to fill the window
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, CongestionWindow / 2);
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 3: Exceeding window - still blocked
    // Simulate sending more (allowed due to exemption below minimum)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 100);
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 4: With exemptions - can send even when blocked
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 2);
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
}

//
// Test 5: SetExemption (via function pointer)
// Scenario: Tests SetExemption to verify it correctly sets the number of packets that
// can bypass congestion control. Used for probe packets and other special cases.
//
TEST_F(CubicFixturedTest, SetExemption)
{
    Initialize();
    // Initially should be 0
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Set exemptions via function pointer
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 5);
    ASSERT_EQ(Cubic->Exemptions, 5u);

    // Set to zero
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 0);
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Set to max
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 255);
    ASSERT_EQ(Cubic->Exemptions, 255u);
}

//
// Test 6: GetSendAllowance scenarios (via function pointer)
// Scenario: Tests GetSendAllowance under different conditions: congestion blocked (returns 0),
// available window without pacing (returns full window), and invalid time (skips pacing).
// Covers the main decision paths in send allowance calculation.
//
TEST_F(CubicFixturedTest, GetSendAllowanceScenarios)
{
    Initialize(); // With default parameters
    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Scenario 1: Congestion blocked - should return 0
    // Fill the window completely
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, CongestionWindow);
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, 0u);

    // Scenario 2: Available window without pacing - should return full window
    // Reset by acknowledging half the data
    Connection.Settings.PacingEnabled = FALSE;
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 5, 10, CongestionWindow / 2);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    uint32_t ExpectedAllowance = Cubic->CongestionWindow - Cubic->BytesInFlight;
    Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, ExpectedAllowance);

    // Scenario 3: Invalid time - should skip pacing and return full window
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, FALSE); // FALSE = invalid time
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 7: GetSendAllowance with active pacing (via function pointer)
// Scenario: Tests the pacing logic that limits send rate based on RTT and congestion window.
// When pacing is enabled with valid RTT samples, the function calculates a pacing rate to
// smooth out packet transmission. This prevents burst sending and improves performance over
// certain network paths. The pacing calculation is: (CongestionWindow * TimeSinceLastSend) / RTT.
// This test verifies that with pacing enabled, the allowance is rate-limited based on elapsed
// time, resulting in a smaller allowance than the full available congestion window.
//
TEST_F(CubicFixturedTest, GetSendAllowanceWithActivePacing)
{
    Initialize(/*WindowPackets=*/10, /*HyStart=*/false, /*Mtu=*/1280, /*IdleTimeoutMs=*/1000, /*GotRttSample=*/true, /*SmoothedRtt=*/50000);
    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Set BytesInFlight to half the window to have available capacity
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, CongestionWindow / 2);

    // Simulate 10ms elapsed since last send
    // Expected pacing calculation: (CongestionWindow * 10ms) / 50ms = CongestionWindow / 5
    uint32_t TimeSinceLastSend = 10000; // 10ms in microseconds

    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Exact value is calculated considering the current implementation is right and this test is meant to
    // prevent future regressions
    uint32_t ExpectedPacedAllowance = 6160; // Pre-calculated expected value
    ASSERT_EQ(Allowance, ExpectedPacedAllowance);
}

//
// Test 8: Getter functions (via function pointers)
// Scenario: Tests all simple getter functions that return internal state values.
// Verifies GetExemptions, GetBytesInFlightMax, and GetCongestionWindow all return
// correct values matching the internal CUBIC state.
//
TEST_F(CubicFixturedTest, GetterFunctions)
{
    Initialize(); // With default parameters

    // Test GetExemptions
    uint8_t Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(&Connection.CongestionControl);
    ASSERT_EQ(Exemptions, 0u);
    Cubic->Exemptions = 3;
    Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(&Connection.CongestionControl);
    ASSERT_EQ(Exemptions, 3u);

    // Test GetBytesInFlightMax
    uint32_t MaxBytes = Connection.CongestionControl.QuicCongestionControlGetBytesInFlightMax(&Connection.CongestionControl);
    ASSERT_EQ(MaxBytes, Cubic->BytesInFlightMax);
    ASSERT_EQ(MaxBytes, Cubic->CongestionWindow / 2);

    // Test GetCongestionWindow
    uint32_t CongestionWindow = Connection.CongestionControl.QuicCongestionControlGetCongestionWindow(&Connection.CongestionControl);
    ASSERT_EQ(CongestionWindow, Cubic->CongestionWindow);
    // CongestionWindow = (MTU - 48) * InitialWindowPackets = (1280 - 48) * 10 = 12320
    uint32_t ExpectedCongestionWindow = (1280 - 48) * 10;
    ASSERT_EQ(CongestionWindow, ExpectedCongestionWindow);
}

//
// Test 9: Reset scenarios (via function pointer)
// Scenario: Tests Reset function with both FullReset=FALSE (preserves BytesInFlight) and
// FullReset=TRUE (zeros BytesInFlight). Verifies that reset properly reinitializes CUBIC
// state while respecting the FullReset parameter for connection recovery scenarios.
//
TEST_F(CubicFixturedTest, ResetScenarios)
{
    Initialize(); // With default parameters

    // Scenario 1: Partial reset (FullReset=FALSE) - preserves BytesInFlight
    // First, send some data and trigger a congestion event to set internal flags
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    // Trigger congestion event via loss
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    uint32_t BytesInFlightBefore = Cubic->BytesInFlight;

    Connection.CongestionControl.QuicCongestionControlReset(&Connection.CongestionControl, FALSE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightBefore); // Preserved

    // Scenario 2: Full reset (FullReset=TRUE) - zeros BytesInFlight
    // Reinitialize and send data again
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    // Trigger another congestion event
    LossEvent.NumRetransmittableBytes = 1200;
    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    Connection.CongestionControl.QuicCongestionControlReset(&Connection.CongestionControl, TRUE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->BytesInFlight, 0u); // Zeroed with full reset
}

//
// Test 10: CubicCongestionControlOnDataSent - BytesInFlight increases and exemptions decrement
// Scenario: Tests that OnDataSent correctly increments BytesInFlight when data is sent
// and decrements exemptions when probe packets are sent. This tracks outstanding data
// in the network and consumes exemptions. Verifies BytesInFlightMax is updated when
// BytesInFlight reaches a new maximum.
//
TEST_F(CubicFixturedTest, OnDataSent_IncrementsBytesInFlight)
{
    Initialize(); // With default parameters

    uint32_t InitialBytesInFlight = Cubic->BytesInFlight;
    uint32_t InitialBytesInFlightMax = Cubic->BytesInFlightMax;
    uint32_t BytesToSend = 1500;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, BytesToSend);

    ASSERT_EQ(Cubic->BytesInFlight, InitialBytesInFlight + BytesToSend);
    // BytesInFlightMax should update if new BytesInFlight exceeds previous max
    if (InitialBytesInFlight + BytesToSend > InitialBytesInFlightMax) {
        ASSERT_EQ(Cubic->BytesInFlightMax, InitialBytesInFlight + BytesToSend);
    } else {
        ASSERT_EQ(Cubic->BytesInFlightMax, InitialBytesInFlightMax);
    }

    // Test exemption decrement
    Cubic->Exemptions = 5;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 1500);
    ASSERT_EQ(Cubic->Exemptions, 4u);

    // Test LastSendAllowance decrement
    // When NumRetransmittableBytes <= LastSendAllowance, allowance is reduced
    Cubic->LastSendAllowance = 2000; // Set initial allowance
    uint32_t SmallSend = 500; // Send less than allowance
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, SmallSend);
    ASSERT_EQ(Cubic->LastSendAllowance, 2000u - SmallSend); // Should be reduced
}

//
// Test 11: CubicCongestionControlOnDataInvalidated - BytesInFlight decreases
// Scenario: Tests OnDataInvalidated when sent packets are discarded (e.g., due to key
// phase change). BytesInFlight should decrease by the invalidated bytes since they're
// no longer considered in-flight. Critical for accurate congestion window management.
//
TEST_F(CubicFixturedTest, OnDataInvalidated_DecrementsBytesInFlight)
{
    Initialize(); // With default parameters

    // Send some data first
    Cubic->BytesInFlight = 5000;
    uint32_t BytesToInvalidate = 2000;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataInvalidated(
        &Connection.CongestionControl, BytesToInvalidate);

    ASSERT_EQ(Cubic->BytesInFlight, 3000u);
}

//
// Test 12: OnDataAcknowledged - Basic ACK Processing in Slow Start
// Scenario: Tests CubicCongestionControlOnDataAcknowledged for basic slow-start
// window growth. Sends data via OnDataSent (properly tracking BytesInFlightMax),
// then acknowledges a portion. The window should grow by BytesAcked since we are
// in slow start (CongestionWindow < SlowStartThreshold) with HyStart disabled
// (CWndSlowStartGrowthDivisor = 1).
//
TEST_F(CubicFixturedTest, OnDataAcknowledged_BasicAck)
{
    Initialize(/*WindowPackets=*/10, /*HyStart=*/false, /*Mtu=*/1280, /*IdleTimeoutMs=*/1000, /*GotRttSample=*/true, /*SmoothedRtt=*/50000);

    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send data via OnDataSent to properly track BytesInFlightMax.
    // Must send enough that BytesInFlightMax > (InitialWindow + BytesAcked) / 2
    // to avoid the 2*BytesInFlightMax clamping guard.
    uint32_t BytesSent = 10000;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, BytesSent);

    uint32_t BytesAcked = 5000;
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1050000, 5, 10, BytesAcked);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Slow start growth: window increases by BytesAcked (divisor=1, HyStart disabled)
    // NewWindow = 12320 + 5000 = 17320, clamped by 2*BytesInFlightMax = 2*10000 = 20000 (no clamp)
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow + BytesAcked);
    ASSERT_EQ(Cubic->BytesInFlight, BytesSent - BytesAcked);
}

//
// Test 13: OnDataLost - Packet Loss Handling and Window Reduction
// Scenario: Tests CUBIC's response to packet loss. When packets are declared lost,
// the congestion window should be reduced according to CUBIC algorithm (multiplicative decrease).
// Verifies proper loss recovery state transitions.
//
TEST_F(CubicFixturedTest, OnDataLost_WindowReduction)
{
    // QUIC_CONNECTION Connection;
    // QUIC_SETTINGS_INTERNAL Settings{};
    // Settings.InitialWindowPackets = 20;
    // Settings.SendIdleTimeoutMs = 1000;

    // InitializeMockConnection(Connection, 1280);
    // Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    // Connection.Paths[0].GotFirstRttSample = TRUE;
    // Connection.Paths[0].SmoothedRtt = 50000;

    // CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    Initialize(/*WindowPackets=*/20, /*HyStart=*/true, /*Mtu=*/1280, /*IdleTimeoutMs=*/1000, /*GotRttSample=*/true, /*SmoothedRtt=*/50000);
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data in flight
    Cubic->BytesInFlight = 10000;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(3600, 10, 15);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // Verify window was reduced (CUBIC multiplicative decrease)
    // New window = InitialWindow * 0.7 = InitialWindow * 7 / 10
    // InitialWindow = (1280 - 48) * 20 = 24640 (IPv6 formula: MTU - 40 - 8)
    // Expected = 24640 * 7 / 10 = 17248
    uint32_t ExpectedWindow = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, ExpectedWindow);
}

//
// Test 14: OnEcn - ECN Marking Handling
// Scenario: Tests Explicit Congestion Notification (ECN) handling. When ECN-marked packets
// are received, CUBIC should treat it as a congestion signal and reduce the window appropriately.
//
TEST_F(CubicFixturedTest, OnEcn_CongestionSignal)
{
    // QUIC_CONNECTION Connection;
    // QUIC_SETTINGS_INTERNAL Settings{};
    // Settings.InitialWindowPackets = 20;
    // Settings.SendIdleTimeoutMs = 1000;
    // Settings.EcnEnabled = TRUE;

    // InitializeMockConnection(Connection, 1280);
    // Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    // Connection.Paths[0].GotFirstRttSample = TRUE;
    // Connection.Paths[0].SmoothedRtt = 50000;

    // CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    Initialize(/*WindowPackets=*/20, /*HyStart=*/true, /*Mtu=*/1280, /*IdleTimeoutMs=*/1000, /*GotRttSample=*/true, /*SmoothedRtt=*/50000);
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data in flight
    Cubic->BytesInFlight = 10000;

    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnEcn(
        &Connection.CongestionControl,
        &EcnEvent);

    // Verify window was reduced due to ECN congestion signal (same as loss: 0.7x)
    // InitialWindow = (1280 - 48) * 20 = 24640 (IPv6 formula: MTU - 40 - 8)
    // Expected = 24640 * 7 / 10 = 17248
    uint32_t ExpectedWindow = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedWindow);
}

//
// Test 15: GetNetworkStatistics - Statistics Retrieval
// Scenario: Tests retrieval of network statistics including congestion window, RTT estimates,
// and throughput metrics. Used for monitoring and diagnostics.
//
TEST_F(CubicFixturedTest, GetNetworkStatistics_RetrieveStats)
{
    // QUIC_CONNECTION Connection;
    // QUIC_SETTINGS_INTERNAL Settings{};
    // Settings.InitialWindowPackets = 10;
    // Settings.SendIdleTimeoutMs = 1000;

    // InitializeMockConnection(Connection, 1280);
    // Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    // Connection.Paths[0].GotFirstRttSample = TRUE;
    // Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    // Connection.Paths[0].MinRtt = 40000; // 40ms
    // Connection.Paths[0].RttVariance = 5000;

    // CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    Initialize(
        /*WindowPackets=*/10,
        /*HyStart=*/true,
        /*Mtu=*/1280,
        /*IdleTimeoutMs=*/1000,
        /*GotRttSample=*/true,
        /*SmoothedRtt=*/50000,
        /*SetMinRtt=*/true,
        /*MinRtt=*/40000,
        /*RttVariance=*/5000
    );
    Cubic->BytesInFlight = 8000;

    // Prepare network statistics structure (not QUIC_STATISTICS_V2)
    QUIC_NETWORK_STATISTICS NetworkStats;
    CxPlatZeroMemory(&NetworkStats, sizeof(NetworkStats));

    // Call through function pointer - note it takes Connection as first param
    Connection.CongestionControl.QuicCongestionControlGetNetworkStatistics(
        &Connection,
        &Connection.CongestionControl,
        &NetworkStats);

    // Verify statistics were populated
    ASSERT_EQ(NetworkStats.CongestionWindow, Cubic->CongestionWindow);
    ASSERT_EQ(NetworkStats.BytesInFlight, Cubic->BytesInFlight);
    ASSERT_EQ(NetworkStats.SmoothedRTT, 50000u);  // Exact RTT value set
}

//
// Test 16: Miscellaneous Small Functions - Complete API Coverage
// Scenario: Tests remaining small functions to achieve comprehensive API coverage:
// SetExemption, GetExemptions, OnDataInvalidated, GetCongestionWindow, LogOutFlowStatus, OnSpuriousCongestionEvent.
//
TEST_F(CubicFixturedTest, MiscFunctions_APICompleteness)
{
    // QUIC_CONNECTION Connection;
    // QUIC_SETTINGS_INTERNAL Settings{};
    // Settings.InitialWindowPackets = 10;
    // Settings.SendIdleTimeoutMs = 1000;

    // InitializeMockConnection(Connection, 1280);
    // CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    Initialize();

    // Test SetExemption
    Connection.CongestionControl.QuicCongestionControlSetExemption(
        &Connection.CongestionControl,
        1); // Set exemption count

    // Test GetExemptions
    uint8_t Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(
        &Connection.CongestionControl);
    ASSERT_EQ(Exemptions, 1u);

    // Test OnDataInvalidated
    Cubic->BytesInFlight = 5000;
    Connection.CongestionControl.QuicCongestionControlOnDataInvalidated(
        &Connection.CongestionControl,
        2000); // Invalidate 2000 bytes
    ASSERT_EQ(Cubic->BytesInFlight, 3000u);

    // Test GetCongestionWindow
    uint32_t CongestionWindow = Connection.CongestionControl.QuicCongestionControlGetCongestionWindow(
        &Connection.CongestionControl);
    ASSERT_EQ(CongestionWindow, Cubic->CongestionWindow);

    // Test LogOutFlowStatus
    Connection.CongestionControl.QuicCongestionControlLogOutFlowStatus(
        &Connection.CongestionControl);
    // No assertion needed - just ensure it doesn't crash

    // Test OnSpuriousCongestionEvent
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(
        &Connection.CongestionControl);
    // No assertion needed - just ensure it doesn't crash
}

//
// Test 17: Fast Convergence - Window Reduction Path
// Scenario: Tests CUBIC's fast convergence algorithm. When a new congestion event occurs
// before reaching the previous WindowMax, CUBIC applies an additional reduction factor
// to converge faster with other flows. This tests the WindowLastMax > WindowMax path.
//
TEST(CubicTest, FastConvergence_AdditionalReduction)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 30;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Simulate first congestion event to establish WindowMax
    // Send data to fill the window
    uint32_t InitialWindow = Cubic->CongestionWindow;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, InitialWindow);

    // Trigger first loss event
    QUIC_LOSS_EVENT FirstLoss = MakeLossEvent(3000, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &FirstLoss);

    // Grow the window by acknowledging data and sending more (simulate recovery and growth)
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 10, 15, 5000);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);

    // Send more data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 3000);

    // Trigger second loss event (before reaching previous WindowMax)
    // Must use LargestPacketNumberLost > RecoverySentPacketNumber (which is 10 from first loss)
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(3000, 15, 20);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // Fast convergence should apply: WindowMax is reduced
    // After first loss, CongestionWindow = InitialWindow * 0.7 = 36960 * 0.7 = 25872
    // WindowMax after first loss = InitialWindow = 36960
    // After second loss with fast convergence, WindowMax = WindowMax * (1+beta)/2 = 36960 * 0.85 = 31416
    // But if window < WindowLastMax (which is 0 initially), fast convergence doesn't apply
    // Let's verify the actual implementation behavior
    // WindowMax is set to current window (25872) * (17/20) for fast convergence = 21991
    uint32_t WindowAfterFirstLoss = InitialWindow * 7 / 10;  // 25872
    uint32_t ExpectedWindowMax = WindowAfterFirstLoss * 17 / 20;  // 21991
    ASSERT_EQ(Cubic->WindowMax, ExpectedWindowMax);
}

//
// Test 18: Recovery Exit Path
// Scenario: Tests exiting from recovery state when an ACK is received for a packet
// sent after recovery started. This is the recovery completion logic.
//
TEST(CubicTest, Recovery_ExitOnNewAck)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set recovery state by triggering a loss event
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 10; // Set packet number before loss

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 8, 10, TRUE);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Now in recovery state
    ASSERT_TRUE(Cubic->IsInRecovery);

    // Send new packet after recovery started
    Connection.Send.NextPacketNumber = 15;

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 15, 20, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Should exit recovery
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
}

//
// Test 19: Zero Bytes Acknowledged - Early Exit
// Scenario: Tests the early exit path when BytesAcked is zero in recovery state.
// This can occur with ACKs that don't contain retransmittable data.
//
TEST(CubicTest, ZeroBytesAcked_EarlyExit)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send some data to have bytes in flight
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 5, 10, 0);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Window should not change with zero bytes acked
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 20: Pacing with Slow Start Window Estimation
// Scenario: Tests pacing calculation during slow start phase. When in slow start,
// the estimated window is 2x current window (exponential growth). This covers
// the EstimatedWnd calculation branch in GetSendAllowance.
//
TEST(CubicTest, Pacing_SlowStartWindowEstimation)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Ensure in slow start (SlowStartThreshold is UINT32_MAX by default after init)
    // Send data to have bytes in flight
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow / 2);

    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Pacing formula: (EstimatedWnd * TimeSinceLastSend) / SmoothedRtt
    // In slow start: EstimatedWnd = min(2 * CongestionWindow, SlowStartThreshold) = 24640
    // CongestionWindow = (1280 - 48) * 10 = 12320
    // Allowance = (24640 * 10000) / 50000 = 4928
    uint32_t ExpectedAllowance = 4928;
    ASSERT_EQ(Allowance, ExpectedAllowance);

    // Now test the case where estimated window (2x current) exceeds threshold
    // Set threshold to be between current window and 2x current window
    uint32_t CurrentWindow = Cubic->CongestionWindow;
    Cubic->SlowStartThreshold = CurrentWindow + (CurrentWindow / 2); // 1.5x current window = 18480

    // Call GetSendAllowance again
    // EstimatedWnd = min(2 * 12320, 18480) = 18480
    // Allowance = LastSendAllowance + (18480 * 10000) / 50000 = 4928 + 3696 = 8624
    // BUT capped at available window = CongestionWindow - BytesInFlight = 12320 - 6160 = 6160
    uint32_t Allowance2 = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Verify exact calculated value (capped at available window)
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;
    uint32_t ExpectedAllowance2 = AvailableWindow;  // 6160 (capped)
    ASSERT_EQ(Allowance2, ExpectedAllowance2);
}

//
// Test 21: Pacing with Congestion Avoidance Window Estimation
// Scenario: Tests pacing calculation during congestion avoidance phase.
// When past slow start, estimated window is 1.25x current window (linear growth).
//
TEST(CubicTest, Pacing_CongestionAvoidanceEstimation)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    // MTU=1280, payload = 1280 - 48 = 1232
    // InitialWindow = 10 * 1232 = 12320

    uint32_t InitialWindow = Cubic->CongestionWindow;
    ASSERT_EQ(InitialWindow, (uint32_t)(DatagramPayloadLength * Settings.InitialWindowPackets));

    // Ensure in congestion avoidance by triggering a loss to set SlowStartThreshold
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);
    // BytesInFlight = 12320
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);
    // After loss: CongestionWindow = 12320 * 7 / 10 = 8624
    //             BytesInFlight = 12320 - 1200 = 11120
    //             SlowStartThreshold = 8624
    uint32_t WindowAfterLoss = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterLoss);
    ASSERT_EQ(Cubic->SlowStartThreshold, WindowAfterLoss);
    uint32_t BytesInFlightAfterLoss = InitialWindow - LossEvent.NumRetransmittableBytes;
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightAfterLoss);

    // Exit recovery by acknowledging packet sent after recovery started
    Connection.Send.NextPacketNumber = 15;

    // At this point:
    // - CongestionWindow = 8624
    // - BytesInFlight = 11120
    // - CongestionWindow < BytesInFlight, so CanSend = FALSE
    // We're CC blocked due to window reduction from loss
    // NumRetransmittableBytes = WindowAfterLoss / 2 = 4312
    uint32_t BytesAcked = WindowAfterLoss / 2;
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 15, 20, BytesAcked);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);
    // After ACK:
    // - BytesInFlight = 11120 - 4312 = 6808
    // - Still in recovery (LargestAck=15 < RecoveryWindow=11? No, exits recovery)
    // - CongestionWindow >= SlowStartThreshold, so in congestion avoidance

    uint32_t BytesInFlightAfterAck = BytesInFlightAfterLoss - BytesAcked;
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightAfterAck);
    ASSERT_FALSE(Cubic->IsInRecovery);

    // Now in congestion avoidance and out of recovery
    // GetSendAllowance with TimeSinceLastSend=10000us, pacing enabled:
    // - CongestionWindow >= SlowStartThreshold, so EstimatedWnd = CongestionWindow * 1.25
    // - EstimatedWnd = 8624 + 8624/4 = 8624 + 2156 = 10780
    // - SendAllowance = LastSendAllowance + (EstimatedWnd * TimeSinceLastSend) / SmoothedRtt
    // - LastSendAllowance = 0 (first call after ACK)
    // - SendAllowance = 0 + (10780 * 10000) / 50000 = 107800000 / 50000 = 2156
    // - AvailableWindow = CongestionWindow - BytesInFlight = 8624 - 6808 = 1816
    // - SendAllowance (2156) > AvailableWindow (1816), so capped to 1816
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    uint64_t EstimatedWnd = WindowAfterLoss + (WindowAfterLoss >> 2);
    uint32_t AvailableWindow = WindowAfterLoss - BytesInFlightAfterAck;
    uint32_t CalculatedAllowance = (uint32_t)((EstimatedWnd * 10000) / 50000);
    uint32_t ExpectedAllowance = (CalculatedAllowance > AvailableWindow) ? AvailableWindow : CalculatedAllowance;

    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 22: Pacing SendAllowance Overflow Handling
// Scenario: Tests the overflow detection in pacing calculation. When the pacing
// calculation causes SendAllowance to overflow, it should be capped at the available window.
//
TEST(CubicTest, Pacing_OverflowHandling)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 1000; // Very small RTT

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Send data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 1000);

    // Note: LastSendAllowance is internal state that gets set during GetSendAllowance calls
    // We can't directly manipulate it, but we can test overflow by using very large time deltas

    // Very large time delta to trigger overflow
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000000, TRUE);

    // Should be capped at available window, not overflow
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;
    ASSERT_EQ(Allowance, AvailableWindow);
}

//
// Test 23: Congestion Avoidance AIMD vs CUBIC Window Selection
// Scenario: After loss triggers recovery and an ACK exits recovery, a subsequent
// ACK in congestion avoidance exercises the CUBIC formula and AIMD accumulator.
// The max(CUBIC, AIMD) selection determines the new window.
//
TEST(CubicTest, CongestionAvoidance_AIMDvsCubicSelection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Trigger loss to enter congestion avoidance
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    uint32_t WindowAfterLoss = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterLoss);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // First ACK: exit recovery (LargestAck=11 > RecoverySentPacketNumber=10)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 20;

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &ExitAck);

    ASSERT_FALSE(Cubic->IsInRecovery);
    // Recovery exit goes to Exit label; window unchanged this ACK
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterLoss);

    // Second ACK: now in congestion avoidance, CUBIC/AIMD selection runs
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 3000);

    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1100000, 15, 25, 1200);

    uint32_t WindowBeforeCongAvoid = Cubic->CongestionWindow;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &CongAvoidAck);

    // Congestion avoidance ran: CW >= SSThresh so slow start is skipped,
    // CUBIC formula and AIMD both execute, max() selects the winner.
    // Window should change from the post-loss value.
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_NE(Cubic->CongestionWindow, WindowBeforeCongAvoid);
}

//
// Test 24: AIMD Accumulator - Below WindowPrior (half-rate growth)
// Scenario: In congestion avoidance with AimdWindow < WindowPrior, the AIMD
// accumulator grows at half rate (BytesAcked / 2). This tests the Reno-friendly
// region where CUBIC is still catching up to the previous maximum window.
//
TEST(CubicTest, AIMD_AccumulatorBelowWindowPrior)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Trigger congestion avoidance by causing a loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);
    // After loss: AimdWindow = CW * 7/10, WindowPrior = original CW
    // So AimdWindow < WindowPrior → half-rate accumulator path

    // First ACK: exit recovery
    Connection.Send.NextPacketNumber = 15;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &ExitAck);
    ASSERT_FALSE(Cubic->IsInRecovery);

    // Second ACK: congestion avoidance runs, AIMD accumulator exercised
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 3000);

    uint32_t BytesAcked = 600; // Half MTU
    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1100000, 16, 25, BytesAcked);

    ASSERT_EQ(Cubic->AimdAccumulator, 0u);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &CongAvoidAck);

    // AimdWindow < WindowPrior, so accumulator += BytesAcked / 2 = 300
    ASSERT_EQ(Cubic->AimdAccumulator, BytesAcked / 2);
}

//
// Test 25: AIMD Accumulator - Above WindowPrior (full-rate growth)
// Scenario: In congestion avoidance with AimdWindow >= WindowPrior, the AIMD
// accumulator grows at full rate (BytesAcked). This tests the path where CUBIC
// has surpassed its previous maximum and enters the convex region.
//
TEST(CubicTest, AIMD_AccumulatorAboveWindowPrior)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Trigger congestion avoidance
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    // Exit recovery
    Connection.Send.NextPacketNumber = 15;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &ExitAck);
    ASSERT_FALSE(Cubic->IsInRecovery);

    // Force AimdWindow >= WindowPrior so the full-rate accumulator path runs.
    // After loss, WindowPrior = original CW and AimdWindow = CW * 7/10.
    // Set AimdWindow = WindowPrior to enter the above-WindowPrior path.
    Cubic->AimdWindow = Cubic->WindowPrior;
    ASSERT_EQ(Cubic->AimdAccumulator, 0u);

    // ACK in congestion avoidance with full-rate accumulation
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 3000);

    uint32_t BytesAcked = 1200;
    QUIC_ACK_EVENT CongAvoidAck = MakeAckEvent(1100000, 16, 25, BytesAcked);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &CongAvoidAck);

    // AimdWindow >= WindowPrior, so accumulator += BytesAcked (full rate, not halved)
    ASSERT_EQ(Cubic->AimdAccumulator, BytesAcked);
}

//
// Test 26: CubicWindow Overflow to BytesInFlightMax
// Scenario: Tests that when the CUBIC window formula overflows (producing a negative
// int64 result), the window is capped at 2*BytesInFlightMax. After exiting recovery,
// we manipulate TimeOfCongAvoidStart so the CUBIC formula's DeltaT produces a large
// negative value (KCubic >> TimeInCongAvoid), causing the cubic term to overflow.
//
TEST(CubicTest, CubicWindow_OverflowToBytesInFlightMax)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Trigger loss → recovery
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);
    uint32_t WindowAfterLoss = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterLoss);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // Exit recovery with first ACK
    Connection.Send.NextPacketNumber = 15;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &ExitAck);
    ASSERT_FALSE(Cubic->IsInRecovery);

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
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 3000);

    QUIC_ACK_EVENT OverflowAck = MakeAckEvent(1100000, 16, 25, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &OverflowAck);

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
// Test 27: UpdateBlockedState - Unblock Flow
// Scenario: Tests the flow control unblocking path. When congestion window opens up
// (CanSend transitions from FALSE to TRUE), the function should return TRUE and
// remove the congestion control blocked reason.
//
TEST(CubicTest, UpdateBlockedState_UnblockFlow)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    // MTU=1280, payload = 1280 - 48 = 1232
    // InitialWindow = 10 * 1232 = 12320
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);

    // Start with blocked state by filling the window
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);
    // BytesInFlight = 12320

    // Now free up space by acknowledging half the data
    uint32_t BytesAcked = InitialWindow / 2;  // 6160
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1000000, 5, 10, BytesAcked);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);

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
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);

    uint32_t ExpectedAllowance = NewWindow - BytesInFlightAfterAck;
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 28: Spurious Congestion Event Rollback
// Scenario: Tests the spurious congestion event handling. When a congestion event
// is determined to be spurious (false positive), CUBIC should restore the previous
// state before the congestion event occurred.
//
TEST(CubicTest, SpuriousCongestion_StateRollback)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Trigger a congestion event first
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 10000);
    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeLoss, InitialWindow);
    Connection.Send.NextPacketNumber = 15;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 10, 15);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // After loss: Window = InitialWindow * 7 / 10
    uint32_t ExpectedWindowAfterLoss = WindowBeforeLoss * 7 / 10;
    uint32_t WindowAfterLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowAfterLoss, ExpectedWindowAfterLoss);

    // Now declare it spurious
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(
        &Connection.CongestionControl);

    // State should be restored
    ASSERT_EQ(Cubic->CongestionWindow, WindowBeforeLoss);
}

//
// Test 29: App Limited API Coverage
// Scenario: Tests the IsAppLimited and SetAppLimited API functions. In the current
// CUBIC implementation, these are stub functions that don't track app-limited state.
// This test verifies the API is callable and doesn't crash.
//
TEST(CubicTest, AppLimited_APICoverage)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // IsAppLimited currently always returns FALSE (stub implementation)
    BOOLEAN IsAppLimited = Connection.CongestionControl.QuicCongestionControlIsAppLimited(
        &Connection.CongestionControl);
    ASSERT_FALSE(IsAppLimited);

    // SetAppLimited is a no-op in current implementation but should not crash
    Connection.CongestionControl.QuicCongestionControlSetAppLimited(
        &Connection.CongestionControl);

    // Still returns FALSE after SetAppLimited (stub behavior)
    IsAppLimited = Connection.CongestionControl.QuicCongestionControlIsAppLimited(
        &Connection.CongestionControl);
    ASSERT_FALSE(IsAppLimited);
}

//
// Test 30: Time Gap in ACKs - Idle Period Handling
// Scenario: Tests the idle-period time gap clamping logic.
// After exiting recovery, a large gap between ACKs (exceeding SendIdleTimeoutMs
// and RTT+4*RttVariance) should advance TimeOfCongAvoidStart to prevent the
// CUBIC formula from producing unrealistic window growth.
//
TEST(CubicTest, TimeGap_IdlePeriodHandling)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000; // 1 second idle timeout

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;  // 50ms
    Connection.Paths[0].RttVariance = 5000;   // 5ms

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Trigger loss → recovery
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(1200, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // First ACK: exit recovery. This sets TimeOfCongAvoidStart and TimeOfLastAck.
    Connection.Send.NextPacketNumber = 15;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1050000, 11, 20, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &ExitAck);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->TimeOfLastAckValid);

    uint64_t TimeOfCongAvoidBefore = Cubic->TimeOfCongAvoidStart;

    // Second ACK: small gap (50ms), well within idle timeout. No time gap adjustment.
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 3000);

    QUIC_ACK_EVENT NormalAck = MakeAckEvent(1100000, 14, 22, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &NormalAck);

    // Small gap: TimeOfCongAvoidStart unchanged
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, TimeOfCongAvoidBefore);

    TimeOfCongAvoidBefore = Cubic->TimeOfCongAvoidStart;

    // Third ACK: 5-second idle gap (exceeds SendIdleTimeoutMs=1000ms and
    // RTT+4*RttVar=50000+20000=70000µs). Time gap clamping should fire.
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 3000);

    QUIC_ACK_EVENT IdleAck = MakeAckEvent(6100000, 18, 25, 1200);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &IdleAck);

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
// Test 31: HyStart++ Initialization State Verification
// Transition: Initial state check
// Scenario: Verifies that when HyStartEnabled=TRUE, the system initializes
// to HYSTART_NOT_STARTED with all supporting variables correctly set.
// This establishes the precondition for all other HyStart++ transitions.
//
TEST(CubicTest, HyStart_InitialStateVerification)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;  // Enable HyStart++

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
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
// Test 32: HyStart++ T5 - Direct Transition NOT_STARTED → DONE via Loss
// Transition: T5 in state model
// Scenario: Tests direct transition from NOT_STARTED to DONE when packet loss
// occurs before HyStart++ detection logic activates. This is the most common
// path when network conditions cause loss during initial slow start.
//
TEST(CubicTest, HyStart_T5_NotStartedToDone_ViaLoss)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Verify in NOT_STARTED state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeLoss, InitialWindow);

    // Send data to have bytes in flight
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 10;

    // Trigger loss event while still in NOT_STARTED
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

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
// Test 33: HyStart++ T5 - Direct Transition NOT_STARTED → DONE via ECN
// Transition: T5 in state model
// Scenario: Tests direct transition from NOT_STARTED to DONE when ECN marking
// is received, indicating congestion before HyStart++ activates.
//
TEST(CubicTest, HyStart_T5_NotStartedToDone_ViaECN)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;
    Settings.EcnEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Verify in NOT_STARTED state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    uint32_t WindowBeforeECN = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeECN, InitialWindow);

    // Send data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 15;

    // Trigger ECN event
    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnEcn(
        &Connection.CongestionControl,
        &EcnEvent);

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
// Test 34: HyStart++ T4 - Transition to DONE via Persistent Congestion
// Transition: T4 in state model
// Scenario: Tests transition from any state to DONE when persistent congestion
// is detected. This is the most severe congestion signal, causing drastic
// window reduction to minimum (2 packets).
//
TEST(CubicTest, HyStart_T4_AnyToDone_ViaPersistentCongestion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 30;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Can be in any state (we'll test from NOT_STARTED)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);

    uint32_t WindowBeforePersistent = Cubic->CongestionWindow;
    // Verify window is large (InitialWindow = 30 * 1232 = 36960)
    ASSERT_EQ(WindowBeforePersistent, InitialWindow);

    // Send data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 15000);
    Connection.Send.NextPacketNumber = 20;

    // Trigger persistent congestion
    QUIC_LOSS_EVENT PersistentLoss = MakeLossEvent(8000, 15, 20, TRUE);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &PersistentLoss);

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
// Test 35: HyStart++ Terminal State - DONE is Absorbing
// Transition: Verification that DONE has no outgoing transitions
// Scenario: Tests the mathematical proof that HYSTART_DONE is an absorbing state.
// Once in DONE, no further state transitions can occur (all HyStart++ logic is
// bypassed). This verifies the guard.
//
TEST(CubicTest, HyStart_TerminalState_DoneIsAbsorbing)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Transition to DONE state via loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Verify in DONE state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Exit recovery to enable further ACK processing
    Connection.Send.NextPacketNumber = 20;

    // First, ACK the packet that exits recovery (sent after RecoverySentPacketNumber)
    QUIC_ACK_EVENT RecoveryExitAck = MakeAckEvent(1500000, 20, 25, 0, 50000, 48000);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &RecoveryExitAck);

    ASSERT_FALSE(Cubic->IsInRecovery);  // Should have exited recovery

    // Attempt to trigger state changes with various ACK patterns
    // None of these should change the state from DONE

    // Pattern 1: ACKs with varying RTT (would trigger T1 if not in DONE)
    for (int i = 0; i < 2 * QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            2000000 + (i * 10000), 20 + i, 25 + i, BytesToSend,
            50000, 45000 + (i * 1000));

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        // State should remain DONE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    }

    // Pattern 2: Cross multiple round boundaries (would trigger T2 if in ACTIVE)
    for (int round = 0; round < 5; round++) {
        Connection.Send.NextPacketNumber = 100 + (round * 20);

        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT BoundaryAck = MakeAckEvent(
            3000000 + (round * 60000),
            Connection.Send.NextPacketNumber,
            Connection.Send.NextPacketNumber + 5,
            BytesToSend, 50000, 48000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &BoundaryAck);

        // State should remain DONE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    }

    // Pattern 3: Decreasing RTT (would trigger T6 if in ACTIVE)
    uint32_t BytesToSend = 1200;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

    QUIC_ACK_EVENT DecreaseAck = MakeAckEvent(4000000, 150, 160, BytesToSend, 50000, 30000);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &DecreaseAck);

    // Final verification: State is still DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
}

//
// Test 36: HyStart++ Disabled - State Unchanged on Congestion Events
// Transition: Verification of early-exit guard
// Scenario: When HyStartEnabled=FALSE (on Connection.Settings), the loss handler's
// HyStart state transition logic is guarded by the enabled flag. The state remains
// NOT_STARTED because the code path `Cubic->HyStartState = HYSTART_DONE` is only
// executed when HyStartEnabled=TRUE. Recovery still occurs normally.
//
TEST(CubicTest, HyStart_Disabled_NoTransitions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = FALSE;  // Explicitly disabled

    InitializeMockConnection(Connection, 1280);
    // Do NOT set Connection.Settings.HyStartEnabled - keep it FALSE for this test
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Initial state should be NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);

    // Attempt various operations that would trigger transitions if enabled

    // 1. Send ACKs with increasing RTT (would trigger T1)
    for (int i = 0; i < 2 * QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 1200);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), i, i + 5, 1200,
            50000, 50000 + (i * 2000));

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        // State should remain NOT_STARTED
        ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    }

    // 2. Trigger loss (would trigger T5)
    Connection.Send.NextPacketNumber = 20;

    // First send more data to have BytesInFlight for the loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 15, 20);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // HyStart state unchanged: When HyStartEnabled=FALSE, loss handler skips
    // the `Cubic->HyStartState = HYSTART_DONE` assignment. Recovery still occurs.
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_TRUE(Cubic->IsInRecovery); // Recovery happens independent of HyStart
}

//
// Test 37: HyStart++ State Invariant - Growth Divisor Consistency
// Transition: Verification of Growth Divisor Invariant from state model
// Scenario: Verifies CWndSlowStartGrowthDivisor is consistent across all
// three states by transitioning NOT_STARTED → ACTIVE → DONE:
// - NOT_STARTED → divisor = 1
// - ACTIVE → divisor = 4 (triggered via delay increase detection)
// - DONE → divisor = 1 (triggered via loss)
//
TEST(CubicTest, HyStart_StateInvariant_GrowthDivisor)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(
            &Connection.CongestionControl, 1200);
        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, 1200,
            50000, 46000);
        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl, &AckEvent);
    }
    ASSERT_EQ(Cubic->HyStartAckCount, 8u);

    // 9th ACK triggers delay increase detection → ACTIVE
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 1200);
    QUIC_ACK_EVENT TriggerAck = MakeAckEvent(1100000, 20, 25, 1200, 50000, 47000);
    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &TriggerAck);

    // Invariant 2: ACTIVE → divisor = 4
    ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 4u);

    // Transition ACTIVE → DONE via loss.
    // Send enough data to cover the loss bytes.
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 30;
    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 25, 30);
    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent);

    // Invariant 3: DONE → divisor = 1
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 38: HyStart++ Multiple Congestion Events - State Stability
// Transition: Multiple T5/T4 transitions
// Scenario: Tests that multiple congestion events keep the state in DONE and
// don't cause state corruption. Each event should trigger recovery logic but
// state should remain DONE.
//
TEST(CubicTest, HyStart_MultipleCongestionEvents_StateStability)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 30;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // First congestion event: NOT_STARTED → DONE
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT FirstLoss = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &FirstLoss);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    // After first loss: Window = InitialWindow * 7 / 10
    uint32_t WindowAfterFirst = InitialWindow * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterFirst);

    // Exit recovery
    Connection.Send.NextPacketNumber = 20;
    QUIC_ACK_EVENT RecoveryExitAck = MakeAckEvent(1100000, 20, 25, 1200, 50000, 48000);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &RecoveryExitAck);

    // Second congestion event: DONE → DONE (should remain)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 30;

    QUIC_LOSS_EVENT SecondLoss = MakeLossEvent(1800, 28, 30);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &SecondLoss);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
    // After second loss: Window = WindowAfterFirst * 7 / 10
    uint32_t WindowAfterSecond = WindowAfterFirst * 7 / 10;
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterSecond);

    // Third congestion event via ECN: DONE → DONE
    Connection.Send.NextPacketNumber = 40;
    QUIC_ECN_EVENT EcnEvent{};
    EcnEvent.LargestPacketNumberAcked = 35;
    EcnEvent.LargestSentPacketNumber = 40;

    Connection.CongestionControl.QuicCongestionControlOnEcn(&Connection.CongestionControl, &EcnEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
}

//
// Test 39: HyStart++ Recovery Exit with State Persistence
// Transition: Verification that recovery exit doesn't affect HyStart state
// Scenario: When exiting recovery (IsInRecovery: TRUE → FALSE), the HyStart
// state should remain unchanged. Recovery is orthogonal to HyStart++ state.
//
TEST(CubicTest, HyStart_RecoveryExit_StatePersistence)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Transition to DONE and enter recovery
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(2400, 5, 10);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // Exit recovery by ACKing packet sent after recovery started
    Connection.Send.NextPacketNumber = 20;

    QUIC_ACK_EVENT ExitAck = MakeAckEvent(1100000, 20, 25, 1200, 50000, 48000);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &ExitAck);

    // Recovery should be exited but HyStart state unchanged
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
}

//
// Test 40: HyStart++ Spurious Congestion with State Verification
// Transition: State behavior during spurious congestion recovery
// Scenario: When a congestion event is declared spurious, window state is rolled
// back but HyStart state is NOT rolled back (it remains DONE). This is because
// HyStart++ state transitions are one-way and not part of the spurious recovery.
//
TEST(CubicTest, HyStart_SpuriousCongestion_StateNotRolledBack)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 25;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;

    // Precondition: Start in NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowBeforeLoss, InitialWindow);

    // Trigger congestion event (NOT_STARTED → DONE)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 10000);
    Connection.Send.NextPacketNumber = 15;

    QUIC_LOSS_EVENT LossEvent = MakeLossEvent(3600, 10, 15);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    // After loss: Window = InitialWindow * 7 / 10
    uint32_t ExpectedWindowAfterLoss = WindowBeforeLoss * 7 / 10;
    uint32_t WindowAfterLoss = Cubic->CongestionWindow;
    ASSERT_EQ(WindowAfterLoss, ExpectedWindowAfterLoss);

    // Declare congestion event spurious
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(&Connection.CongestionControl);

    // Window state should be rolled back
    ASSERT_EQ(Cubic->CongestionWindow, WindowBeforeLoss);
    ASSERT_FALSE(Cubic->IsInRecovery);

    // BUT HyStart state should remain DONE (not rolled back)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Verify HyStart logic is still bypassed after spurious recovery
    QUIC_ACK_EVENT AckEvent = MakeAckEvent(1200000, 20, 25, 1200, 50000, 55000);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);

    // State still DONE (HyStart++ logic bypassed)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
}

//
// Test 41: HyStart++ Delay Increase Detection - Eta Calculation and Condition Check
// Scenario: Covers the case of  triggering the delay increase
// detection logic after sampling phase completes. Tests the Eta calculation and
// the condition that checks if RTT has increased beyond the threshold.
//
TEST(CubicTest, HyStart_DelayIncreaseDetection_EtaCalculationAndCondition)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 42000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);
    }

    // After 8 ACKs, we should have completed sampling
    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED); // Still in NOT_STARTED
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 42000u);

    // Phase 2: Send one more ACK with MinRtt below the increase threshold
    // This triggers HyStartAckCount >= 8 and state is NOT_STARTED
    {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        // MinRtt = 43000, which is less than MinRttInLastRound (40000) + Eta (40000/8 = 5000)
        // 43000 < 45000
        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 43000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        // Should still be in NOT_STARTED since delay increase wasn't significant
        ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
        ASSERT_EQ(Cubic->HyStartAckCount, 8u); // Should still be 8, not reset
    }
}

//
// Test 42: HyStart++ Delay Increase Detection - Trigger ACTIVE Transition
// Scenario: Triggers the delay increase detection logic with
// a significant RTT increase that causes transition from NOT_STARTED to ACTIVE state.
//
TEST(CubicTest, HyStart_DelayIncreaseDetection_TriggerActiveTransition)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 46000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);
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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 47000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        // Should transition to HYSTART_ACTIVE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);

        // Verify state changes from
        ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 4u); // QUIC_CONSERVATIVE_SLOW_START_DEFAULT_GROWTH_DIVISOR
        ASSERT_EQ(Cubic->ConservativeSlowStartRounds, 5u); // QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS
        ASSERT_EQ(Cubic->CssBaselineMinRtt, 46000u); // Set to MinRttInCurrentRound
    }
}

//
// Test 43: HyStart++ RTT Decrease Detection - Return to NOT_STARTED
// Scenario: Covers the RTT decrease detection logic.
// When in HYSTART_ACTIVE state, if RTT decreases below the baseline, the algorithm
// assumes the previous slow start exit was spurious and returns to NOT_STARTED state.
//
TEST(CubicTest, HyStart_RttDecreaseDetection_ReturnToNotStarted)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set Connection.Send.NextPacketNumber high to avoid round boundary crossing
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;

    // Set up initial MinRttInLastRound
    Cubic->MinRttInLastRound = 40000;

    // Phase 1: Collect 8 samples with high RTT to complete sampling
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 46000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);
    }

    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 46000u);

    // Phase 2: Trigger transition to HYSTART_ACTIVE with high RTT
    {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 47000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1200000, 100, 105, BytesToSend, 50000, 46000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1300000 + (i * 10000), 110 + i, 115 + i, BytesToSend,
            50000, 38000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);
    }

    ASSERT_EQ(Cubic->HyStartAckCount, 8u);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, 38000u);

    // Phase 5: Send one more ACK to trigger the else branch RTT decrease detection
    // Now HyStartAckCount >= 8 and HyStartState == HYSTART_ACTIVE
    // MinRttInCurrentRound (38000) < CssBaselineMinRtt (46000), so should transition
    {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1400000, 120, 125, BytesToSend, 50000, 39000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        // Should transition back to NOT_STARTED due to RTT decrease
        ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
        ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u); // Reset to normal slow start
    }
}

//
// Test 44: HyStart++ Conservative Slow Start Rounds - Transition to DONE
// Scenario: Covers the round boundary crossing logic
// when in HYSTART_ACTIVE state. After completing the configured number of
// conservative slow start rounds, the algorithm transitions to HYSTART_DONE.
//
TEST(CubicTest, HyStart_ConservativeSlowStartRounds_TransitionToDone)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set Connection.Send.NextPacketNumber to control round boundaries
    Connection.Send.NextPacketNumber = 100;
    Cubic->HyStartRoundEnd = 100;

    Cubic->MinRttInLastRound = 40000;

    // Phase 1: Collect 8 samples with high RTT
    for (uint32_t i = 0; i < QUIC_HYSTART_DEFAULT_N_SAMPLING; i++) {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1000000 + (i * 10000), 10 + i, 15 + i, BytesToSend,
            50000, 46000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);
    }

    // Phase 2: Transition to HYSTART_ACTIVE
    {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent = MakeAckEvent(1100000, 20, 25, BytesToSend, 50000, 47000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
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
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        // Use LargestAck >= current HyStartRoundEnd to trigger round boundary
        QUIC_ACK_EVENT AckEvent = MakeAckEvent(
            1200000 + (round * 100000),
            Cubic->HyStartRoundEnd,
            Connection.Send.NextPacketNumber + 10,
            BytesToSend, 50000, 46000);

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        if (round < QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS - 1) {
            // Still in HYSTART_ACTIVE for first n-1 rounds
            ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
            ASSERT_NE(Cubic->SlowStartThreshold, Cubic->CongestionWindow);
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
// Test 45: Congestion Avoidance Time Gap - Overflow Protection
// Scenario: Covers the overflow protection logic when a large time gap causes
// TimeOfCongAvoidStart adjustment to overflow. Tests the boundary condition
// where TimeOfCongAvoidStart might exceed TimeNowUs after adjustment.
//
TEST(CubicTest, CongestionAvoidance_TimeGapOverflowProtection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Paths[0].RttVariance = 10000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

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
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(TimeNowUs, 10, 15, BytesToSend, 50000, 45000, FALSE);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // TimeOfCongAvoidStart should be clamped to TimeNowUs to prevent issues
    // in TimeInCongAvoid calculation
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, TimeNowUs);
}

//
// Test 46: Cubic Window Calculation Overflow Protection
// Scenario: Tests the overflow handling in cubic window calculation.
// When WindowMax is extremely large, the cubic formula can overflow,
// causing CubicWindow to become negative.
//
TEST(CubicTest, CongestionAvoidance_CubicWindowOverflow)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Force into congestion avoidance
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 20000;

    // Set WindowMax to maximum value - when combined with large DeltaT in cubic
    // calculation, this will cause int64 overflow
    // The formula: CubicWindow = (((DeltaT^3) * MTU * C) >> 20) + WindowMax
    Cubic->WindowMax = UINT32_MAX; // Maximum possible value
    Cubic->BytesInFlightMax = 50000; // Set a reasonable max

    // Set up time to have been in congestion avoidance for a very long time
    // to maximize DeltaT in the cubic calculation
    uint64_t TimeNowUs = 30000000000ULL; // 30000 seconds (8+ hours)
    Cubic->TimeOfCongAvoidStart = 1000000; // Started very long ago
    Cubic->KCubic = 0; // K = 0 to maximize DeltaT
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->TimeOfLastAck = TimeNowUs - 100000; // Recent ACK

    // Send data
    uint32_t BytesToSend = 1200;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

    QUIC_ACK_EVENT AckEvent = MakeAckEvent(TimeNowUs, 10, 15, BytesToSend, 50000, 45000, FALSE);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Window should be valid after processing the ACK
    // The exact value depends on CUBIC formula and any clamping that occurs
    // We verify the algorithm doesn't crash and produces a reasonable value
    ASSERT_EQ(Cubic->CongestionWindow, 20616u); // Actual computed value
}

//
// Test 47: Slow Start Window Overflow After Persistent Congestion
// Scenario: After persistent congestion, window is reset to 2*MTU while threshold
// remains at a higher value, creating window < threshold condition. A large ACK
// can then trigger the overflow logic where window grows beyond threshold.
//
TEST(CubicTest, SlowStart_WindowOverflowAfterPersistentCongestion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    const uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t InitialWindow = DatagramPayloadLength * Settings.InitialWindowPackets;
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);

    // Trigger PERSISTENT congestion directly (window will be reduced to 2*MTU)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 1200);
    Connection.Send.NextPacketNumber = 25;

    QUIC_LOSS_EVENT PersistentLoss = MakeLossEvent(1200, 20, 25, TRUE);

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &PersistentLoss);

    // After persistent congestion:
    // - Window is reset to 2 * DatagramPayloadLength (minimum window)
    // - Threshold is set to old_window * 0.7
    uint32_t ExpectedWindowAfterPC = DatagramPayloadLength * QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS;
    uint32_t ExpectedThresholdAfterPC = InitialWindow * 7 / 10;
    uint32_t WindowAfterPC = Cubic->CongestionWindow;
    uint32_t ThresholdAfterPC = Cubic->SlowStartThreshold;

    ASSERT_EQ(WindowAfterPC, ExpectedWindowAfterPC);
    ASSERT_EQ(ThresholdAfterPC, ExpectedThresholdAfterPC);

    // We're in recovery after persistent congestion. Need to exit recovery first.
    // Exit recovery by ACKing a packet sent after the recovery started
    Connection.Send.NextPacketNumber = 30;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 1200);

    QUIC_ACK_EVENT RecoveryExitAck = MakeAckEvent(1100000, 30, 31, 1200, 50000, 45000, FALSE);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &RecoveryExitAck);

    // Recovery exits but window doesn't grow on the same ACK (code goes to Exit)
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterPC); // Window unchanged on recovery exit

    // Now send and ACK enough bytes to exceed threshold
    // In slow start, window grows by BytesAcked
    uint32_t BytesToExceedThreshold = ThresholdAfterPC - WindowAfterPC + 1000;

    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToExceedThreshold);

    QUIC_ACK_EVENT LargeAck = MakeAckEvent(1200000, 30, 35, BytesToExceedThreshold, 50000, 45000, FALSE);

    // Before ACK: verify we're in slow start
    // Window after recovery exit + BytesInFlight may be < threshold

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &LargeAck);

    // After ACK: verify overflow logic executed
    // 1. TimeOfCongAvoidStart should be set
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, LargeAck.TimeNow);

    // 2. Window should be clamped to threshold
    ASSERT_EQ(Cubic->CongestionWindow, ThresholdAfterPC);
}
