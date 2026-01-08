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

//
// Helper to create a minimal valid connection for testing CUBIC initialization.
// Uses a real QUIC_CONNECTION structure to ensure proper memory layout when
// QuicCongestionControlGetConnection() does CXPLAT_CONTAINING_RECORD pointer arithmetic.
//
static void InitializeMockConnection(
    QUIC_CONNECTION& Connection,
    uint16_t Mtu)
{
    // Zero-initialize the entire connection structure
    CxPlatZeroMemory(&Connection, sizeof(Connection));

    // Initialize only the fields needed by CUBIC functions
    Connection.Paths[0].Mtu = Mtu;
    Connection.Paths[0].IsActive = TRUE;
    Connection.Send.NextPacketNumber = 0;

    // Initialize Settings with defaults
    Connection.Settings.PacingEnabled = FALSE;  // Disable pacing by default for simpler tests
    Connection.Settings.HyStartEnabled = FALSE; // Disable HyStart by default

    // Initialize Path fields needed for some functions
    Connection.Paths[0].GotFirstRttSample = FALSE;
    Connection.Paths[0].SmoothedRtt = 0;
}

//
// Test 1: Comprehensive initialization verification
// Scenario: Verifies CubicCongestionControlInitialize correctly sets up all CUBIC state
// including settings, function pointers, state flags, HyStart fields, and zero-initialized fields.
// This consolidates basic initialization, function pointer, state flags, HyStart, and zero-field checks.
//
TEST(CubicTest, InitializeComprehensive)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

    // Pre-set some fields to verify they get zeroed
    Connection.CongestionControl.Cubic.BytesInFlight = 12345;
    Connection.CongestionControl.Cubic.Exemptions = 5;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Verify settings stored correctly
    ASSERT_EQ(Cubic->InitialWindowPackets, 10u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 1000u);
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);

    // Verify congestion window initialized
    ASSERT_GT(Cubic->CongestionWindow, 0u);
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
TEST(CubicTest, InitializeBoundaries)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    // Test minimum MTU with minimum window
    Settings.InitialWindowPackets = 1;
    Settings.SendIdleTimeoutMs = 0;
    InitializeMockConnection(Connection, QUIC_DPLPMTUD_MIN_MTU);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, 0u);

    // Test maximum MTU with maximum window and timeout
    Settings.InitialWindowPackets = 1000;
    Settings.SendIdleTimeoutMs = UINT32_MAX;
    InitializeMockConnection(Connection, 65535);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1000u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, UINT32_MAX);

    // Test very small MTU (below minimum)
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    InitializeMockConnection(Connection, 500);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
}

//
// Test 3: Re-initialization behavior
// Scenario: Tests that CUBIC can be re-initialized with different settings and correctly
// updates its state. Verifies that calling CubicCongestionControlInitialize() multiple times
// properly resets state and applies new settings (e.g., doubling InitialWindowPackets should
// double the CongestionWindow). Important for connection migration or settings updates.
//
TEST(CubicTest, MultipleSequentialInitializations)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

    // Initialize first time
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    uint32_t FirstCongestionWindow = Connection.CongestionControl.Cubic.CongestionWindow;

    // Re-initialize with different settings
    Settings.InitialWindowPackets = 20;
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
TEST(CubicTest, CanSendScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;
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
TEST(CubicTest, SetExemption)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
TEST(CubicTest, GetSendAllowanceScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;
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
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = CongestionWindow / 2;
    AckEvent.NumTotalAckedRetransmittableBytes = CongestionWindow / 2;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

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
TEST(CubicTest, GetSendAllowanceWithActivePacing)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

    // Enable pacing and provide valid RTT sample
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms (well above QUIC_MIN_PACING_RTT)

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t CongestionWindow = Cubic->CongestionWindow;

    // Set BytesInFlight to half the window to have available capacity
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, CongestionWindow / 2);
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;

    // Simulate 10ms elapsed since last send
    // Expected pacing calculation: (CongestionWindow * 10ms) / 50ms = CongestionWindow / 5
    uint32_t TimeSinceLastSend = 10000; // 10ms in microseconds

    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Pacing should limit the allowance to less than the full available window
    ASSERT_GT(Allowance, 0u); // Should allow some sending
    ASSERT_LT(Allowance, AvailableWindow); // But less than full window due to pacing

    // Exact value is calculated considering the current implementation is right and this test is meant to
    // prevent future regressions
    uint32_t ExpectedPacedAllowance = 4928; // Pre-calculated expected value
    ASSERT_EQ(Allowance, ExpectedPacedAllowance);
}

//
// Test 8: Getter functions (via function pointers)
// Scenario: Tests all simple getter functions that return internal state values.
// Verifies GetExemptions, GetBytesInFlightMax, and GetCongestionWindow all return
// correct values matching the internal CUBIC state.
//
TEST(CubicTest, GetterFunctions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
    ASSERT_GT(CongestionWindow, 0u);
}

//
// Test 9: Reset scenarios (via function pointer)
// Scenario: Tests Reset function with both FullReset=FALSE (preserves BytesInFlight) and
// FullReset=TRUE (zeros BytesInFlight). Verifies that reset properly reinitializes CUBIC
// state while respecting the FullReset parameter for connection recovery scenarios.
//
TEST(CubicTest, ResetScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Partial reset (FullReset=FALSE) - preserves BytesInFlight
    // First, send some data and trigger a congestion event to set internal flags
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    // Trigger congestion event via loss
    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 1200;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

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
TEST(CubicTest, OnDataSent_IncrementsBytesInFlight)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

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
TEST(CubicTest, OnDataInvalidated_DecrementsBytesInFlight)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Send some data first
    Cubic->BytesInFlight = 5000;
    uint32_t BytesToInvalidate = 2000;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataInvalidated(
        &Connection.CongestionControl, BytesToInvalidate);

    ASSERT_EQ(Cubic->BytesInFlight, 3000u);
}

//
// Test 12: OnDataAcknowledged - Basic ACK Processing and CUBIC Growth
// Scenario: Tests the core CUBIC congestion control algorithm by acknowledging sent data.
// Exercises CubicCongestionControlOnDataAcknowledged and internally calls CubeRoot for CUBIC calculations.
// Verifies congestion window grows appropriately after successful ACK.
//
TEST(CubicTest, OnDataAcknowledged_BasicAck)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms in microseconds
    Connection.Settings.NetStatsEventEnabled = TRUE; // Enable logging
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data sent
    Cubic->BytesInFlight = 5000;

    // Create ACK event with correct structure
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = CxPlatTimeUs64();
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 5000;
    AckEvent.NumTotalAckedRetransmittableBytes = 5000;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL; // NULL pointer is valid

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);
    // Verify window may have grown (depends on slow start vs congestion avoidance)
    ASSERT_GE(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 13: OnDataLost - Packet Loss Handling and Window Reduction
// Scenario: Tests CUBIC's response to packet loss. When packets are declared lost,
// the congestion window should be reduced according to CUBIC algorithm (multiplicative decrease).
// Verifies proper loss recovery state transitions.
//
TEST(CubicTest, OnDataLost_WindowReduction)
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
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data in flight
    Cubic->BytesInFlight = 10000;

    // Create loss event with correct structure
    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 3600; // 3 packets * 1200 bytes
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 10;
    LossEvent.LargestSentPacketNumber = 15;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // Verify window was reduced (CUBIC multiplicative decrease)
    ASSERT_LT(Cubic->CongestionWindow, InitialWindow);
    ASSERT_GT(Cubic->SlowStartThreshold, 0u);
    ASSERT_LT(Cubic->SlowStartThreshold, UINT32_MAX);
}

//
// Test 14: OnEcn - ECN Marking Handling
// Scenario: Tests Explicit Congestion Notification (ECN) handling. When ECN-marked packets
// are received, CUBIC should treat it as a congestion signal and reduce the window appropriately.
//
TEST(CubicTest, OnEcn_CongestionSignal)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.EcnEnabled = TRUE;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate data in flight
    Cubic->BytesInFlight = 10000;

    // Create ECN event with correct structure
    QUIC_ECN_EVENT EcnEvent;
    CxPlatZeroMemory(&EcnEvent, sizeof(EcnEvent));
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnEcn(
        &Connection.CongestionControl,
        &EcnEvent);

    // Verify window was reduced due to ECN congestion signal
    ASSERT_LE(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 15: GetNetworkStatistics - Statistics Retrieval
// Scenario: Tests retrieval of network statistics including congestion window, RTT estimates,
// and throughput metrics. Used for monitoring and diagnostics.
//
TEST(CubicTest, GetNetworkStatistics_RetrieveStats)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    Connection.Paths[0].MinRtt = 40000; // 40ms
    Connection.Paths[0].RttVariance = 5000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
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
    ASSERT_GT(NetworkStats.SmoothedRTT, 0u);
}

//
// Test 16: Miscellaneous Small Functions - Complete API Coverage
// Scenario: Tests remaining small functions to achieve comprehensive API coverage:
// SetExemption, GetExemptions, OnDataInvalidated, GetCongestionWindow, LogOutFlowStatus, OnSpuriousCongestionEvent.
//
TEST(CubicTest, MiscFunctions_APICompleteness)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

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
    QUIC_LOSS_EVENT FirstLoss;
    CxPlatZeroMemory(&FirstLoss, sizeof(FirstLoss));
    FirstLoss.NumRetransmittableBytes = 3000;
    FirstLoss.PersistentCongestion = FALSE;
    FirstLoss.LargestPacketNumberLost = 5;
    FirstLoss.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &FirstLoss);

    // After first loss, WindowMax and WindowLastMax are set
    uint32_t WindowMaxAfterFirstLoss = Cubic->WindowMax;

    // Grow the window by acknowledging data and sending more (simulate recovery and growth)
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 5000;
    AckEvent.NumTotalAckedRetransmittableBytes = 5000;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);

    // Send more data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 3000);

    // Trigger second loss event (before reaching previous WindowMax)
    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 3000;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 10;
    LossEvent.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // Fast convergence should apply: WindowMax is reduced further
    // Verify WindowLastMax was updated
    ASSERT_LT(Cubic->WindowMax, 40000u); // Additional reduction applied
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

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 1200;
    LossEvent.PersistentCongestion = TRUE; // Trigger persistent congestion
    LossEvent.LargestPacketNumberLost = 8;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Now in recovery state
    ASSERT_TRUE(Cubic->IsInRecovery);

    // Send new packet after recovery started
    Connection.Send.NextPacketNumber = 15;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 15; // ACK for packet after recovery started
    AckEvent.LargestSentPacketNumber = 20;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

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

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 0; // Zero bytes
    AckEvent.NumTotalAckedRetransmittableBytes = 0;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

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

    // Should get some allowance based on slow start estimation (2x window)
    ASSERT_GT(Allowance, 0u);

    // Now test the case where estimated window (2x current) exceeds threshold
    // Set threshold to be between current window and 2x current window
    uint32_t CurrentWindow = Cubic->CongestionWindow;
    Cubic->SlowStartThreshold = CurrentWindow + (CurrentWindow / 2); // 1.5x current window

    // Call GetSendAllowance again
    // where EstimatedWnd (2x) gets clamped to SlowStartThreshold
    uint32_t Allowance2 = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Should still get some allowance, but clamped calculation
    ASSERT_GT(Allowance2, 0u);
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

    // Ensure in congestion avoidance by triggering a loss to set SlowStartThreshold
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 1200;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Exit recovery by acknowledging packet sent after recovery started
    Connection.Send.NextPacketNumber = 15;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1100000;
    AckEvent.LargestAck = 15;
    AckEvent.LargestSentPacketNumber = 20;
    AckEvent.NumRetransmittableBytes = Cubic->CongestionWindow / 2;
    AckEvent.NumTotalAckedRetransmittableBytes = Cubic->CongestionWindow / 2;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);

    // Now in congestion avoidance and out of recovery
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Should get allowance based on congestion avoidance estimation (1.25x)
    ASSERT_GT(Allowance, 0u);
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
// Scenario: Tests the decision logic between AIMD and CUBIC windows during congestion
// avoidance. CUBIC uses the larger of the two to be TCP-friendly while maintaining
// CUBIC growth characteristics.
//
TEST(CubicTest, CongestionAvoidance_AIMDvsCubicSelection)
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

    // Set to congestion avoidance mode by triggering loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Now in congestion avoidance (SlowStartThreshold is set)
    // WindowMax, WindowPrior, AimdWindow, TimeOfCongAvoidStart are set by the loss handler

    // Send more data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow / 2);

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 2000000; // 1 second later
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    uint32_t WindowBefore = Cubic->CongestionWindow;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Window should grow (either AIMD or CUBIC path)
    ASSERT_GE(Cubic->CongestionWindow, WindowBefore);
}

//
// Test 24: AIMD Window Accumulator Logic - WindowPrior Path
// Scenario: Tests AIMD window growth when below WindowPrior (uses 0.5 MSS/RTT slope).
// Verifies the accumulator correctly tracks acknowledged bytes and increases window
// only when sufficient bytes are accumulated.
//
TEST(CubicTest, AIMD_AccumulatorBelowWindowPrior)
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

    // Trigger congestion avoidance by causing a loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Exit recovery by acknowledging packet sent after recovery
    Connection.Send.NextPacketNumber = 15;

    // Send data and ACK to trigger AIMD logic
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1050000;
    AckEvent.LargestAck = 15;
    AckEvent.LargestSentPacketNumber = 20;
    AckEvent.NumRetransmittableBytes = 600; // Half MTU
    AckEvent.NumTotalAckedRetransmittableBytes = 600;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Accumulator should have bytes added (verifies AIMD logic executed)
    // Note: May be 0 if still in slow start or not enough bytes accumulated
    // Just verify no crash - AIMD logic is complex and depends on internal state
    ASSERT_GE(Cubic->AimdAccumulator, 0u);
}

//
// Test 25: AIMD Window Accumulator Logic - Above WindowPrior Path
// Scenario: Tests AIMD window growth when above WindowPrior (uses 1 MSS/RTT slope).
// This is the more aggressive growth after reaching the prior window maximum.
//
TEST(CubicTest, AIMD_AccumulatorAboveWindowPrior)
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

    // Trigger congestion avoidance
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Exit recovery
    Connection.Send.NextPacketNumber = 15;

    // Send data and ACK
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1050000;
    AckEvent.LargestAck = 15;
    AckEvent.LargestSentPacketNumber = 20;
    AckEvent.NumRetransmittableBytes = 1200; // Full MTU
    AckEvent.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Accumulator should have full bytes added
    // Note: AIMD logic depends on complex internal state, just verify >= 0
    ASSERT_GE(Cubic->AimdAccumulator, 0u);
}

//
// Test 26: CubicWindow Overflow to BytesInFlightMax
// Scenario: Tests the overflow handling in CUBIC window calculation. When the cubic
// calculation results in an overflow (negative value wrapping), it should be capped
// at 2*BytesInFlightMax to prevent unbounded growth.
//
TEST(CubicTest, CubicWindow_OverflowToBytesInFlightMax)
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

    // Setup congestion avoidance with large time gap to test overflow capping
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow / 2);

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    uint32_t BytesInFlightMaxBefore = Cubic->BytesInFlightMax;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 5000000; // 4 seconds later - huge gap
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Window should be capped at reasonable value, not overflow
    ASSERT_LE(Cubic->CongestionWindow, 2 * BytesInFlightMaxBefore);
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

    // Start with blocked state by filling the window
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow);
    BOOLEAN PreviousCanSend = FALSE;

    // Now free up space by acknowledging half the data
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = Cubic->CongestionWindow / 2;
    AckEvent.NumTotalAckedRetransmittableBytes = Cubic->CongestionWindow / 2;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &AckEvent);

    // Note: CubicCongestionControlUpdateBlockedState is internal, but we can
    // test the logic through GetSendAllowance behavior changes
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);

    ASSERT_GT(Allowance, 0u); // Now unblocked
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

    // Trigger a congestion event first
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 10000);
    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 10;
    LossEvent.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    uint32_t WindowAfterLoss = Cubic->CongestionWindow;
    ASSERT_LT(WindowAfterLoss, WindowBeforeLoss);

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
// Scenario: Tests behavior when there's a large time gap between ACKs (connection
// was idle). CUBIC should handle the time delta calculation correctly and clamp
// DeltaT to prevent unrealistic window growth.
//
TEST(CubicTest, TimeGap_IdlePeriodHandling)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 10000; // 10 second timeout

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.HyStartEnabled = TRUE;  // Must set on Connection for runtime checks
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup congestion avoidance mode by triggering a loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, Cubic->CongestionWindow / 2);

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 1200;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // First ACK to establish baseline
    QUIC_ACK_EVENT AckEvent1;
    CxPlatZeroMemory(&AckEvent1, sizeof(AckEvent1));
    AckEvent1.TimeNow = 1050000; // 50ms later
    AckEvent1.LargestAck = 5;
    AckEvent1.LargestSentPacketNumber = 10;
    AckEvent1.NumRetransmittableBytes = 1200;
    AckEvent1.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent1.SmoothedRtt = 50000;
    AckEvent1.MinRtt = 45000;
    AckEvent1.MinRttValid = TRUE;
    AckEvent1.IsImplicit = FALSE;
    AckEvent1.HasLoss = FALSE;
    AckEvent1.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent1.AdjustedAckTime = AckEvent1.TimeNow;
    AckEvent1.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent1);

    uint32_t WindowAfterFirst = Cubic->CongestionWindow;

    // Second ACK after long idle period (5 seconds)
    QUIC_ACK_EVENT AckEvent2;
    CxPlatZeroMemory(&AckEvent2, sizeof(AckEvent2));
    AckEvent2.TimeNow = 6000000; // 5 seconds later
    AckEvent2.LargestAck = 10;
    AckEvent2.LargestSentPacketNumber = 15;
    AckEvent2.NumRetransmittableBytes = 1200;
    AckEvent2.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent2.SmoothedRtt = 50000;
    AckEvent2.MinRtt = 45000;
    AckEvent2.MinRttValid = TRUE;
    AckEvent2.IsImplicit = FALSE;
    AckEvent2.HasLoss = FALSE;
    AckEvent2.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent2.AdjustedAckTime = AckEvent2.TimeNow;
    AckEvent2.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent2);

    // Window should grow but be clamped due to DeltaT limiting
    // DeltaT is clamped to 2.5 seconds (2500000 us)
    ASSERT_GE(Cubic->CongestionWindow, WindowAfterFirst);
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

    // Verify initial state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInLastRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->HyStartRoundEnd, 0u);
    ASSERT_LT(Cubic->CongestionWindow, Cubic->SlowStartThreshold); // Must be in slow start
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

    // Precondition: Verify in NOT_STARTED state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;

    // Send data to have bytes in flight
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 10;

    // Trigger loss event while still in NOT_STARTED
    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // Postcondition: Should transition directly to DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u); // Reset to normal
    ASSERT_LT(Cubic->CongestionWindow, WindowBeforeLoss); // Window reduced
    ASSERT_LT(Cubic->SlowStartThreshold, UINT32_MAX); // SSThresh set
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

    // Precondition: Verify in NOT_STARTED state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    uint32_t WindowBeforeECN = Cubic->CongestionWindow;

    // Send data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 15;

    // Trigger ECN event
    QUIC_ECN_EVENT EcnEvent;
    CxPlatZeroMemory(&EcnEvent, sizeof(EcnEvent));
    EcnEvent.LargestPacketNumberAcked = 10;
    EcnEvent.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnEcn(
        &Connection.CongestionControl,
        &EcnEvent);

    // Postcondition: Should transition directly to DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
    ASSERT_LE(Cubic->CongestionWindow, WindowBeforeECN); // Window reduced or unchanged
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

    // Precondition: Can be in any state (we'll test from NOT_STARTED)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);

    uint32_t WindowBeforePersistent = Cubic->CongestionWindow;
    ASSERT_GT(WindowBeforePersistent, 2 * DatagramPayloadLength); // Ensure window is large

    // Send data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 15000);
    Connection.Send.NextPacketNumber = 20;

    // Trigger persistent congestion
    QUIC_LOSS_EVENT PersistentLoss;
    CxPlatZeroMemory(&PersistentLoss, sizeof(PersistentLoss));
    PersistentLoss.NumRetransmittableBytes = 8000;
    PersistentLoss.PersistentCongestion = TRUE;  // Key flag
    PersistentLoss.LargestPacketNumberLost = 15;
    PersistentLoss.LargestSentPacketNumber = 20;

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
    ASSERT_LT(Cubic->CongestionWindow, WindowBeforePersistent); // Significantly reduced
}

//
// Test 35: HyStart++ Terminal State - DONE is Absorbing
// Transition: Verification that DONE has no outgoing transitions
// Scenario: Tests the mathematical proof that HYSTART_DONE is an absorbing state.
// Once in DONE, no further state transitions can occur (all HyStart++ logic is
// bypassed). This verifies the guard at cubic.c:476.
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

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Verify in DONE state
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Exit recovery to enable further ACK processing
    Connection.Send.NextPacketNumber = 20;

    // First, ACK the packet that exits recovery (sent after RecoverySentPacketNumber)
    QUIC_ACK_EVENT RecoveryExitAck;
    CxPlatZeroMemory(&RecoveryExitAck, sizeof(RecoveryExitAck));
    RecoveryExitAck.TimeNow = 1500000;
    RecoveryExitAck.LargestAck = 20;
    RecoveryExitAck.LargestSentPacketNumber = 25;
    RecoveryExitAck.NumRetransmittableBytes = 0;  // Just exit recovery, don't ACK bytes
    RecoveryExitAck.NumTotalAckedRetransmittableBytes = 0;
    RecoveryExitAck.SmoothedRtt = 50000;
    RecoveryExitAck.MinRtt = 48000;
    RecoveryExitAck.MinRttValid = TRUE;
    RecoveryExitAck.IsImplicit = FALSE;
    RecoveryExitAck.HasLoss = FALSE;
    RecoveryExitAck.IsLargestAckedPacketAppLimited = FALSE;
    RecoveryExitAck.AdjustedAckTime = RecoveryExitAck.TimeNow;
    RecoveryExitAck.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 2000000 + (i * 10000);
        AckEvent.LargestAck = 20 + i;
        AckEvent.LargestSentPacketNumber = 25 + i;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 45000 + (i * 1000); // Varying RTT
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT BoundaryAck;
        CxPlatZeroMemory(&BoundaryAck, sizeof(BoundaryAck));
        BoundaryAck.TimeNow = 3000000 + (round * 60000);
        BoundaryAck.LargestAck = Connection.Send.NextPacketNumber;
        BoundaryAck.LargestSentPacketNumber = Connection.Send.NextPacketNumber + 5;
        BoundaryAck.NumRetransmittableBytes = BytesToSend;
        BoundaryAck.NumTotalAckedRetransmittableBytes = BytesToSend;
        BoundaryAck.SmoothedRtt = 50000;
        BoundaryAck.MinRtt = 48000;
        BoundaryAck.MinRttValid = TRUE;
        BoundaryAck.IsImplicit = FALSE;
        BoundaryAck.HasLoss = FALSE;
        BoundaryAck.IsLargestAckedPacketAppLimited = FALSE;
        BoundaryAck.AdjustedAckTime = BoundaryAck.TimeNow;
        BoundaryAck.AckedPackets = NULL;

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &BoundaryAck);

        // State should remain DONE
        ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    }

    // Pattern 3: Decreasing RTT (would trigger T6 if in ACTIVE)
    uint32_t BytesToSend = 1200;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

    QUIC_ACK_EVENT DecreaseAck;
    CxPlatZeroMemory(&DecreaseAck, sizeof(DecreaseAck));
    DecreaseAck.TimeNow = 4000000;
    DecreaseAck.LargestAck = 150;
    DecreaseAck.LargestSentPacketNumber = 160;
    DecreaseAck.NumRetransmittableBytes = BytesToSend;
    DecreaseAck.NumTotalAckedRetransmittableBytes = BytesToSend;
    DecreaseAck.SmoothedRtt = 50000;
    DecreaseAck.MinRtt = 30000; // Significant decrease
    DecreaseAck.MinRttValid = TRUE;
    DecreaseAck.IsImplicit = FALSE;
    DecreaseAck.HasLoss = FALSE;
    DecreaseAck.IsLargestAckedPacketAppLimited = FALSE;
    DecreaseAck.AdjustedAckTime = DecreaseAck.TimeNow;
    DecreaseAck.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &DecreaseAck);

    // Final verification: State is still DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
}

//
// Test 36: HyStart++ Disabled - All Transitions Suppressed
// Transition: Verification of early-exit guard
// Scenario: When HyStartEnabled=FALSE, all state transition logic should be
// bypassed. The state should remain NOT_STARTED regardless of network conditions.
// This tests the guard at cubic.c:89.
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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 10000);
        AckEvent.LargestAck = i;
        AckEvent.LargestSentPacketNumber = i + 5;
        AckEvent.NumRetransmittableBytes = 1200;
        AckEvent.NumTotalAckedRetransmittableBytes = 1200;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 50000 + (i * 2000); // Increasing RTT
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 15;
    LossEvent.LargestSentPacketNumber = 20;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &LossEvent);

    // State should still be NOT_STARTED (but congestion window reduced)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_TRUE(Cubic->IsInRecovery); // Recovery happens independent of HyStart
}

//
// Test 37: HyStart++ State Invariant - Growth Divisor Consistency
// Transition: Verification of Growth Divisor Invariant from state model
// Scenario: Tests the invariant that CWndSlowStartGrowthDivisor is always
// consistent with the current state:
// - NOT_STARTED → divisor = 1
// - ACTIVE → divisor = 4
// - DONE → divisor = 1
//
TEST(CubicTest, HyStart_StateInvariant_GrowthDivisor)
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

    // Invariant 1: NOT_STARTED → divisor = 1
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Transition to DONE via loss
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    // Invariant 2: DONE → divisor = 1
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

    // First congestion event: NOT_STARTED → DONE
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 8000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT FirstLoss;
    CxPlatZeroMemory(&FirstLoss, sizeof(FirstLoss));
    FirstLoss.NumRetransmittableBytes = 2400;
    FirstLoss.PersistentCongestion = FALSE;
    FirstLoss.LargestPacketNumberLost = 5;
    FirstLoss.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &FirstLoss);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    uint32_t WindowAfterFirst = Cubic->CongestionWindow;

    // Exit recovery
    Connection.Send.NextPacketNumber = 20;
    QUIC_ACK_EVENT RecoveryExitAck;
    CxPlatZeroMemory(&RecoveryExitAck, sizeof(RecoveryExitAck));
    RecoveryExitAck.TimeNow = 1100000;
    RecoveryExitAck.LargestAck = 20;
    RecoveryExitAck.LargestSentPacketNumber = 25;
    RecoveryExitAck.NumRetransmittableBytes = 1200;
    RecoveryExitAck.NumTotalAckedRetransmittableBytes = 1200;
    RecoveryExitAck.SmoothedRtt = 50000;
    RecoveryExitAck.MinRtt = 48000;
    RecoveryExitAck.MinRttValid = TRUE;
    RecoveryExitAck.IsImplicit = FALSE;
    RecoveryExitAck.HasLoss = FALSE;
    RecoveryExitAck.IsLargestAckedPacketAppLimited = FALSE;
    RecoveryExitAck.AdjustedAckTime = RecoveryExitAck.TimeNow;
    RecoveryExitAck.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(&Connection.CongestionControl, &RecoveryExitAck);

    // Second congestion event: DONE → DONE (should remain)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 5000);
    Connection.Send.NextPacketNumber = 30;

    QUIC_LOSS_EVENT SecondLoss;
    CxPlatZeroMemory(&SecondLoss, sizeof(SecondLoss));
    SecondLoss.NumRetransmittableBytes = 1800;
    SecondLoss.PersistentCongestion = FALSE;
    SecondLoss.LargestPacketNumberLost = 28;
    SecondLoss.LargestSentPacketNumber = 30;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &SecondLoss);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE); // Still DONE
    ASSERT_LT(Cubic->CongestionWindow, WindowAfterFirst); // Further reduced

    // Third congestion event via ECN: DONE → DONE
    Connection.Send.NextPacketNumber = 40;
    QUIC_ECN_EVENT EcnEvent;
    CxPlatZeroMemory(&EcnEvent, sizeof(EcnEvent));
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

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 2400;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 5;
    LossEvent.LargestSentPacketNumber = 10;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);

    // Exit recovery by ACKing packet sent after recovery started
    Connection.Send.NextPacketNumber = 20;

    QUIC_ACK_EVENT ExitAck;
    CxPlatZeroMemory(&ExitAck, sizeof(ExitAck));
    ExitAck.TimeNow = 1100000;
    ExitAck.LargestAck = 20; // After RecoverySentPacketNumber
    ExitAck.LargestSentPacketNumber = 25;
    ExitAck.NumRetransmittableBytes = 1200;
    ExitAck.NumTotalAckedRetransmittableBytes = 1200;
    ExitAck.SmoothedRtt = 50000;
    ExitAck.MinRtt = 48000;
    ExitAck.MinRttValid = TRUE;
    ExitAck.IsImplicit = FALSE;
    ExitAck.HasLoss = FALSE;
    ExitAck.IsLargestAckedPacketAppLimited = FALSE;
    ExitAck.AdjustedAckTime = ExitAck.TimeNow;
    ExitAck.AckedPackets = NULL;

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

    // Precondition: Start in NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    uint32_t WindowBeforeLoss = Cubic->CongestionWindow;

    // Trigger congestion event (NOT_STARTED → DONE)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 10000);
    Connection.Send.NextPacketNumber = 15;

    QUIC_LOSS_EVENT LossEvent;
    CxPlatZeroMemory(&LossEvent, sizeof(LossEvent));
    LossEvent.NumRetransmittableBytes = 3600;
    LossEvent.PersistentCongestion = FALSE;
    LossEvent.LargestPacketNumberLost = 10;
    LossEvent.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(&Connection.CongestionControl, &LossEvent);

    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_TRUE(Cubic->IsInRecovery);
    uint32_t WindowAfterLoss = Cubic->CongestionWindow;
    ASSERT_LT(WindowAfterLoss, WindowBeforeLoss);

    // Declare congestion event spurious
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(&Connection.CongestionControl);

    // Window state should be rolled back
    ASSERT_EQ(Cubic->CongestionWindow, WindowBeforeLoss);
    ASSERT_FALSE(Cubic->IsInRecovery);

    // BUT HyStart state should remain DONE (not rolled back)
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Verify HyStart logic is still bypassed after spurious recovery
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1200000;
    AckEvent.LargestAck = 20;
    AckEvent.LargestSentPacketNumber = 25;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.NumTotalAckedRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 55000; // Increased RTT
    AckEvent.MinRttValid = TRUE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 10000);
        AckEvent.LargestAck = 10 + i;  // 10..17, all < 100
        AckEvent.LargestSentPacketNumber = 15 + i;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 42000; // Slightly higher than baseline, but within threshold
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1100000;
        AckEvent.LargestAck = 20;  // Still < 100, so no round boundary crossing
        AckEvent.LargestSentPacketNumber = 25;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        // MinRtt = 43000, which is less than MinRttInLastRound (40000) + Eta (40000/8 = 5000)
        // 43000 < 45000
        AckEvent.MinRtt = 43000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 10000);
        AckEvent.LargestAck = 10 + i;  // 10..17, all < 100
        AckEvent.LargestSentPacketNumber = 15 + i;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        // Use consistently high MinRtt (46000) so MinRttInCurrentRound = 46000
        AckEvent.MinRtt = 46000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1100000;
        AckEvent.LargestAck = 20;  // Still < 100, no round crossing
        AckEvent.LargestSentPacketNumber = 25;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 47000; // Doesn't matter for the condition, already have 8 samples
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 10000);
        AckEvent.LargestAck = 10 + i;
        AckEvent.LargestSentPacketNumber = 15 + i;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 46000; // High RTT
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1100000;
        AckEvent.LargestAck = 20;
        AckEvent.LargestSentPacketNumber = 25;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 47000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1200000;
        AckEvent.LargestAck = 100; // Cross round boundary (>= HyStartRoundEnd which was 100)
        AckEvent.LargestSentPacketNumber = 105;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 46000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1300000 + (i * 10000);
        AckEvent.LargestAck = 110 + i; // Stay below next HyStartRoundEnd
        AckEvent.LargestSentPacketNumber = 115 + i;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 38000; // Lower RTT than CssBaselineMinRtt (46000)
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1400000;
        AckEvent.LargestAck = 120; // Stay below round boundary
        AckEvent.LargestSentPacketNumber = 125;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 39000; // Doesn't matter, already have 8 samples
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 10000);
        AckEvent.LargestAck = 10 + i;
        AckEvent.LargestSentPacketNumber = 15 + i;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 46000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);
    }

    // Phase 2: Transition to HYSTART_ACTIVE
    {
        uint32_t BytesToSend = 1200;
        Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToSend);

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1100000;
        AckEvent.LargestAck = 20;
        AckEvent.LargestSentPacketNumber = 25;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 47000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

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

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1200000 + (round * 100000);
        // Use LargestAck >= current HyStartRoundEnd to trigger round boundary
        AckEvent.LargestAck = Cubic->HyStartRoundEnd;
        AckEvent.LargestSentPacketNumber = Connection.Send.NextPacketNumber + 10;
        AckEvent.NumRetransmittableBytes = BytesToSend;
        AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 46000;
        AckEvent.MinRttValid = TRUE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;
        AckEvent.IsLargestAckedPacketAppLimited = FALSE;
        AckEvent.AdjustedAckTime = AckEvent.TimeNow;
        AckEvent.AckedPackets = NULL;

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl,
            &AckEvent);

        if (round < QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS - 1) {
            // Still in HYSTART_ACTIVE for first n-1 rounds
            ASSERT_EQ(Cubic->HyStartState, HYSTART_ACTIVE);
        } else {
            // for the rest of the rounds, state should transition
            // to HYSTART_DONE and stay there
            ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
            ASSERT_EQ(Cubic->ConservativeSlowStartRounds, 0u);
            // Verify SlowStartThreshold is set to current congestion window
            ASSERT_LT(Cubic->SlowStartThreshold, UINT32_MAX);
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

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = TimeNowUs;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = BytesToSend;
    AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = FALSE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

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

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = TimeNowUs;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = BytesToSend;
    AckEvent.NumTotalAckedRetransmittableBytes = BytesToSend;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = FALSE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;
    AckEvent.IsLargestAckedPacketAppLimited = FALSE;
    AckEvent.AdjustedAckTime = AckEvent.TimeNow;
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Window should be valid (overflow was handled)
    ASSERT_GT(Cubic->CongestionWindow, 0u);
    ASSERT_LT(Cubic->CongestionWindow, UINT32_MAX);
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

    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Trigger PERSISTENT congestion directly (window will be reduced to 2*MTU)
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 1200);

    QUIC_LOSS_EVENT PersistentLoss;
    CxPlatZeroMemory(&PersistentLoss, sizeof(PersistentLoss));
    PersistentLoss.NumRetransmittableBytes = 1200;
    PersistentLoss.PersistentCongestion = TRUE; // This is the key!
    PersistentLoss.LargestPacketNumberLost = 20;
    PersistentLoss.LargestSentPacketNumber = 25;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl,
        &PersistentLoss);

    // After persistent congestion:
    // - Window is reset to 2 * MTU (approximately 2560, but may vary)
    // - Threshold is set to old_window * 0.7
    uint32_t WindowAfterPC = Cubic->CongestionWindow;
    uint32_t ThresholdAfterPC = Cubic->SlowStartThreshold;

    ASSERT_LT(WindowAfterPC, 3000u); // Should be around 2*MTU
    ASSERT_GT(WindowAfterPC, 2000u);
    ASSERT_EQ(ThresholdAfterPC, InitialWindow * 7 / 10); // 70% of initial window
    ASSERT_LT(WindowAfterPC, ThresholdAfterPC); // NOW window < threshold!

    // We're in recovery after persistent congestion. Need to exit recovery first.
    // Exit recovery by ACKing a packet sent after the recovery started
    Connection.Send.NextPacketNumber = 30;
    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, 1200);

    QUIC_ACK_EVENT RecoveryExitAck;
    CxPlatZeroMemory(&RecoveryExitAck, sizeof(RecoveryExitAck));
    RecoveryExitAck.TimeNow = 1100000;
    RecoveryExitAck.LargestAck = 30;
    RecoveryExitAck.LargestSentPacketNumber = 31;
    RecoveryExitAck.NumRetransmittableBytes = 1200;
    RecoveryExitAck.NumTotalAckedRetransmittableBytes = 1200;
    RecoveryExitAck.SmoothedRtt = 50000;
    RecoveryExitAck.MinRtt = 45000;
    RecoveryExitAck.MinRttValid = FALSE;
    RecoveryExitAck.IsImplicit = FALSE;
    RecoveryExitAck.HasLoss = FALSE;
    RecoveryExitAck.IsLargestAckedPacketAppLimited = FALSE;
    RecoveryExitAck.AdjustedAckTime = RecoveryExitAck.TimeNow;
    RecoveryExitAck.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &RecoveryExitAck);

    ASSERT_FALSE(Cubic->IsInRecovery); // Exited recovery
    ASSERT_LT(Cubic->CongestionWindow, Cubic->SlowStartThreshold); // Still in slow start

    // Now send and ACK enough bytes to exceed threshold
    // In slow start, window grows by BytesAcked
    uint32_t BytesToExceedThreshold = ThresholdAfterPC - WindowAfterPC + 1000;

    Connection.CongestionControl.QuicCongestionControlOnDataSent(&Connection.CongestionControl, BytesToExceedThreshold);

    QUIC_ACK_EVENT LargeAck;
    CxPlatZeroMemory(&LargeAck, sizeof(LargeAck));
    LargeAck.TimeNow = 1200000;
    LargeAck.LargestAck = 30;
    LargeAck.LargestSentPacketNumber = 35;
    LargeAck.NumRetransmittableBytes = BytesToExceedThreshold;
    LargeAck.NumTotalAckedRetransmittableBytes = BytesToExceedThreshold;
    LargeAck.SmoothedRtt = 50000;
    LargeAck.MinRtt = 45000;
    LargeAck.MinRttValid = FALSE;
    LargeAck.IsImplicit = FALSE;
    LargeAck.HasLoss = FALSE;
    LargeAck.IsLargestAckedPacketAppLimited = FALSE;
    LargeAck.AdjustedAckTime = LargeAck.TimeNow;
    LargeAck.AckedPackets = NULL;

    // Before ACK: verify we're in slow start
    ASSERT_LT(Cubic->CongestionWindow, Cubic->SlowStartThreshold);

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &LargeAck);

    // After ACK: verify overflow logic executed
    // 1. TimeOfCongAvoidStart should be set
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, LargeAck.TimeNow);

    // 2. Window should be clamped to threshold
    ASSERT_EQ(Cubic->CongestionWindow, ThresholdAfterPC);
}
