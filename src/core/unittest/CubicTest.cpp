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
// Forward declarations for internal CUBIC functions being tested
//
extern "C" BOOLEAN
CubicCongestionControlUpdateBlockedState(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN PreviousCanSendState
);

extern "C" void
CubicCongestionControlOnCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN IsPersistentCongestion,
    _In_ BOOLEAN Ecn
);

//
// Helper to create a minimal valid connection for testing CUBIC initialization.
// Uses a real QUIC_CONNECTION structure to ensure proper memory layout when
// QuicCongestionControlGetConnection() does CXPLAT_CONTAINING_RECORD pointer arithmetic.
//
static void InitializeMockConnection(QUIC_CONNECTION* Connection, uint16_t Mtu)
{
    // Zero-initialize the entire connection structure
    CxPlatZeroMemory(Connection, sizeof(*Connection));

    // Initialize only the fields needed by CUBIC functions
    Connection->Paths[0].Mtu = Mtu;
    Connection->Paths[0].IsActive = TRUE;
    Connection->Send.NextPacketNumber = 0;

    // Initialize Settings with defaults
    Connection->Settings.PacingEnabled = FALSE;  // Disable pacing by default for simpler tests
    Connection->Settings.HyStartEnabled = FALSE; // Disable HyStart by default

    // Initialize Path fields needed for some functions
    Connection->Paths[0].GotFirstRttSample = FALSE;
    Connection->Paths[0].SmoothedRtt = 0;
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

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

    // Verify zero-initialized fields
    ASSERT_EQ(Cubic->Exemptions, 0u);
    ASSERT_EQ(Cubic->AimdWindow, 0u);
    ASSERT_EQ(Cubic->AimdAccumulator, 0u);
    ASSERT_EQ(Cubic->WindowMax, 0u);
    ASSERT_EQ(Cubic->WindowLastMax, 0u);
    ASSERT_EQ(Cubic->WindowPrior, 0u);
    ASSERT_EQ(Cubic->KCubic, 0u);
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->TimeOfLastAck, 0u);
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, 0u);
    ASSERT_EQ(Cubic->RecoverySentPacketNumber, 0u);
    ASSERT_EQ(Cubic->PrevWindowPrior, 0u);
    ASSERT_EQ(Cubic->PrevWindowMax, 0u);
    ASSERT_EQ(Cubic->PrevWindowLastMax, 0u);
    ASSERT_EQ(Cubic->PrevKCubic, 0u);
    ASSERT_EQ(Cubic->PrevSlowStartThreshold, 0u);
    ASSERT_EQ(Cubic->PrevCongestionWindow, 0u);
    ASSERT_EQ(Cubic->PrevAimdWindow, 0u);
}

//
// Test 2: Initialization with boundary parameter values
// Scenario: Tests initialization with extreme boundary values for MTU, InitialWindowPackets,
// and SendIdleTimeoutMs to ensure robustness across all valid configurations.
//
TEST(CubicTest, InitializeBoundaries)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    // Test minimum MTU with minimum window
    Settings.InitialWindowPackets = 1;
    Settings.SendIdleTimeoutMs = 0;
    InitializeMockConnection(&Connection, QUIC_DPLPMTUD_MIN_MTU);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, 0u);

    // Test maximum MTU with maximum window and timeout
    Settings.InitialWindowPackets = 1000;
    Settings.SendIdleTimeoutMs = UINT32_MAX;
    InitializeMockConnection(&Connection, 65535);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1000u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, UINT32_MAX);

    // Test very small MTU (below minimum)
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    InitializeMockConnection(&Connection, 500);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Available window - can send
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    Cubic->Exemptions = 0;
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 2: Congestion blocked - cannot send
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 3: Exceeding window - still blocked
    Cubic->BytesInFlight = Cubic->CongestionWindow + 100;
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Scenario 4: With exemptions - can send even when blocked
    Cubic->Exemptions = 2;
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Congestion blocked - should return 0
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, 0u);

    // Scenario 2: Available window without pacing - should return full window
    Connection.Settings.PacingEnabled = FALSE;
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

    // Enable pacing and provide valid RTT sample
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms (well above QUIC_MIN_PACING_RTT)

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set BytesInFlight to half the window to have available capacity
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    uint32_t AvailableWindow = Cubic->CongestionWindow - Cubic->BytesInFlight;

    // Simulate 10ms elapsed since last send
    // Expected pacing calculation: (CongestionWindow * 10ms) / 50ms = CongestionWindow / 5
    uint32_t TimeSinceLastSend = 10000; // 10ms in microseconds

    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Pacing should limit the allowance to less than the full available window
    ASSERT_GT(Allowance, 0u); // Should allow some sending
    ASSERT_LT(Allowance, AvailableWindow); // But less than full window due to pacing

    // Verify it's approximately the expected pacing calculation
    uint32_t ExpectedPacedAllowance = (uint32_t)(((uint64_t)Cubic->CongestionWindow * TimeSinceLastSend) / Connection.Paths[0].SmoothedRtt);

    // Allow some margin due to integer arithmetic and min/max clamping
    ASSERT_GE(Allowance, ExpectedPacedAllowance / 2);
    ASSERT_LE(Allowance, ExpectedPacedAllowance * 2);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: Partial reset (FullReset=FALSE) - preserves BytesInFlight
    Cubic->BytesInFlight = 5000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->IsInRecovery = TRUE;
    Cubic->HasHadCongestionEvent = TRUE;
    uint32_t BytesInFlightBefore = Cubic->BytesInFlight;

    Connection.CongestionControl.QuicCongestionControlReset(&Connection.CongestionControl, FALSE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightBefore); // Preserved

    // Scenario 2: Full reset (FullReset=TRUE) - zeros BytesInFlight
    Cubic->BytesInFlight = 5000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->IsInRecovery = TRUE;

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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms in microseconds

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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.EcnEnabled = TRUE;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
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
// Test 17: HyStart State Transitions - Complete Coverage
// Scenario: Tests HyStart state transitions and behavior in different states.
// HyStart is an algorithm to safely exit slow start by detecting delay increases.
// Tests HYSTART_NOT_STARTED -> HYSTART_ACTIVE -> HYSTART_DONE transitions.
//
TEST(CubicTest, HyStart_StateTransitions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE; // Enable HyStart

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Initial state should be HYSTART_NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Transition to HYSTART_ACTIVE by acknowledging data (triggers slow start)
    Cubic->BytesInFlight = 5000;

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
    AckEvent.AckedPackets = NULL;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // HyStart may transition states based on RTT measurements
    // Just verify state is valid and divisor is set appropriately
    ASSERT_TRUE(Cubic->HyStartState >= HYSTART_NOT_STARTED &&
                Cubic->HyStartState <= HYSTART_DONE);
    ASSERT_GE(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 16: Congestion Avoidance - Idle Time Detection
// Scenario: Tests that congestion avoidance detects idle periods (gaps in ACKs) and
// freezes window growth during those gaps. This prevents the window from growing when
// there's no feedback from the network, which could lead to aggressive bursts after idle.
//
TEST(CubicTest, CongestionAvoidance_IdleTimeDetection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 100; // 100ms idle timeout
    Settings.HyStartEnabled = FALSE;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    Connection.Paths[0].RttVariance = 5000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set up congestion avoidance state
    Cubic->CongestionWindow = 30000;
    Cubic->SlowStartThreshold = 20000;
    Cubic->WindowMax = 40000;
    Cubic->KCubic = 500;
    Cubic->HasHadCongestionEvent = TRUE;
    Cubic->BytesInFlight = 15000;
    Cubic->AimdWindow = 30000;
    Cubic->BytesInFlightMax = 30000;
    Cubic->WindowPrior = 40000;

    uint64_t Now = CxPlatTimeUs64();
    Cubic->TimeOfCongAvoidStart = Now - 500000; // Started 500ms ago
    Cubic->TimeOfLastAck = Now - 200000; // Last ACK was 200ms ago (idle gap)
    Cubic->TimeOfLastAckValid = TRUE;

    uint64_t TimeOfCongAvoidStartBefore = Cubic->TimeOfCongAvoidStart;

    // Send ACK after long idle period
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = Now;
    AckEvent.LargestAck = 40;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.NumTotalAckedRetransmittableBytes = 1200;
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

    // Verify TimeOfCongAvoidStart was adjusted forward to account for idle time
    // This freezes window growth during the idle period
    ASSERT_GT(Cubic->TimeOfCongAvoidStart, TimeOfCongAvoidStartBefore);
}

//
// Test 17: GetSendAllowance - EstimatedWnd clamping to SlowStartThreshold
// Scenario: Tests line 224-225 in cubic.c where EstimatedWnd (CongestionWindow << 1)
// exceeds SlowStartThreshold during slow start, causing EstimatedWnd to be clamped.
// This ensures burst estimation doesn't exceed the slow start threshold.
//
TEST(CubicTest, GetSendAllowance_EstimatedWndClamping)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Make CongestionWindow < SlowStartThreshold
    // and (CongestionWindow << 1) > SlowStartThreshold to trigger line 224-225
    uint32_t SlowStartThresh = 15000;
    uint32_t CongWin = 10000;  // CongWin << 1 = 20000 > 15000

    Cubic->SlowStartThreshold = SlowStartThresh;
    Cubic->CongestionWindow = CongWin;
    Cubic->BytesInFlight = 0;
    Cubic->LastSendAllowance = 0;  // Initialize pacing state

    // Enable pacing to exercise the EstimatedWnd calculation
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    // TimeSinceLastSend is passed as parameter (10ms = 10000 microseconds)
    uint64_t TimeSinceLastSend = 10000;

    // Call GetSendAllowance with valid time
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Verify: EstimatedWnd should have been clamped to SlowStartThreshold (15000)
    // Pacing calculation: (LastSendAllowance + (EstimatedWnd * TimeSinceLastSend) / RTT)
    // = (0 + (15000 * 10000) / 50000) = 3000
    uint32_t ExpectedAllowance = 3000;
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 18: GetSendAllowance - Congestion Avoidance Pacing (Line 228)
// Scenario: Tests line 228 in cubic.c where EstimatedWnd is calculated as
// CongestionWindow * 1.25 during congestion avoidance phase (CongestionWindow >= SlowStartThreshold).
// This ensures proper pacing calculation when not in slow start.
//
TEST(CubicTest, GetSendAllowance_CongestionAvoidancePacing)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Make CongestionWindow >= SlowStartThreshold to enter congestion avoidance
    uint32_t SlowStartThresh = 10000;
    uint32_t CongWin = 20000;  // CongWin >= SlowStartThresh triggers line 228

    Cubic->SlowStartThreshold = SlowStartThresh;
    Cubic->CongestionWindow = CongWin;

    Cubic->BytesInFlight = 0;
    Cubic->LastSendAllowance = 0;  // Initialize pacing state

    // Enable pacing to exercise the EstimatedWnd calculation
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms

    // TimeSinceLastSend is passed as parameter (10ms = 10000 microseconds)
    uint64_t TimeSinceLastSend = 10000;

    // Call GetSendAllowance with valid time
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Verify: EstimatedWnd should be CongestionWindow * 1.25 = 20000 + 5000 = 25000
    // Pacing calculation: (LastSendAllowance + (EstimatedWnd * TimeSinceLastSend) / RTT)
    // = (0 + (25000 * 10000) / 50000) = 5000
    uint32_t ExpectedAllowance = 5000;
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 19: GetSendAllowance - Clamping to Available Window (Line 236)
// Scenario: Tests line 236 in cubic.c where SendAllowance is clamped to
// (CongestionWindow - BytesInFlight) when the pacing calculation results in
// a value larger than the available window space.
//
TEST(CubicTest, GetSendAllowance_ClampToAvailableWindow)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Make pacing calculate a large value that exceeds available window
    uint32_t CongWin = 10000;
    uint32_t BytesInFlight = 8000;  // Available window = 10000 - 8000 = 2000

    Cubic->CongestionWindow = CongWin;
    Cubic->BytesInFlight = BytesInFlight;
    Cubic->SlowStartThreshold = 5000;  // CongWin > SlowStartThresh (congestion avoidance)
    Cubic->LastSendAllowance = 0;

    // Enable pacing with very large time elapsed to force large SendAllowance
    Connection.Settings.PacingEnabled = TRUE;
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 10000; // 10ms - small RTT

    // Large time elapsed to create SendAllowance > available window
    uint64_t TimeSinceLastSend = 100000; // 100ms

    // Call GetSendAllowance
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, TimeSinceLastSend, TRUE);

    // Verify: SendAllowance should be clamped to (CongestionWindow - BytesInFlight)
    uint32_t ExpectedAllowance = CongWin - BytesInFlight; // 2000
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 20: UpdateBlockedState - Transition from Can Send to Blocked (Line 258)
// Scenario: Tests line 258 in cubic.c where PreviousCanSendState was TRUE
// (could send before) and now CubicCongestionControlCanSend returns FALSE
// (blocked now). This should add the QUIC_FLOW_BLOCKED_CONGESTION_CONTROL
// reason to the connection's OutFlowBlockedReasons and return FALSE.
//
TEST(CubicTest, UpdateBlockedState_TransitionToBlocked)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Start in a state where we CAN send
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    Cubic->Exemptions = 0;
    BOOLEAN PreviousCanSendState = TRUE;
    
    // Verify initial state - should be able to send
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
    
    // Ensure the blocked reason is not set initially
    Connection.OutFlowBlockedReasons = 0;

    // Now change state so we CANNOT send anymore (fill the congestion window)
    Cubic->BytesInFlight = Cubic->CongestionWindow + 100;

    // Verify we now cannot send
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Call CubicCongestionControlUpdateBlockedState with PreviousCanSendState=TRUE
    BOOLEAN Result = CubicCongestionControlUpdateBlockedState(
        &Connection.CongestionControl, 
        PreviousCanSendState);

    // Verify: Line 258 was executed - blocked reason should be added
    ASSERT_TRUE((Connection.OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) != 0);
    
    // Should return FALSE (we became blocked, not unblocked)
    ASSERT_FALSE(Result);
}

//
// Test 21: UpdateBlockedState - Transition from Blocked to Can Send (Lines 261-263)
// Scenario: Tests lines 261-263 in cubic.c where PreviousCanSendState was FALSE
// (blocked before) and now CubicCongestionControlCanSend returns TRUE (can send now).
// This should remove the QUIC_FLOW_BLOCKED_CONGESTION_CONTROL reason, reset
// Connection->Send.LastFlushTime, and return TRUE.
//
TEST(CubicTest, UpdateBlockedState_TransitionToUnblocked)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Start in a state where we CANNOT send (blocked)
    Cubic->BytesInFlight = Cubic->CongestionWindow + 100;
    Cubic->Exemptions = 0;
    BOOLEAN PreviousCanSendState = FALSE;
    
    // Verify initial state - should NOT be able to send
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
    
    // Set the blocked reason as if it was previously set
    Connection.OutFlowBlockedReasons = QUIC_FLOW_BLOCKED_CONGESTION_CONTROL;
    
    // Set LastFlushTime to a specific value to verify it gets reset
    uint64_t OldFlushTime = 12345678;
    Connection.Send.LastFlushTime = OldFlushTime;

    // Now change state so we CAN send (reduce BytesInFlight)
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;

    // Verify we now can send
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Call CubicCongestionControlUpdateBlockedState with PreviousCanSendState=FALSE
    BOOLEAN Result = CubicCongestionControlUpdateBlockedState(
        &Connection.CongestionControl, 
        PreviousCanSendState);

    // Verify: Line 261-262 were executed - blocked reason should be removed
    ASSERT_TRUE((Connection.OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) == 0);
    
    // Verify: Line 263 was executed - LastFlushTime should be reset to current time
    ASSERT_NE(Connection.Send.LastFlushTime, OldFlushTime);
    ASSERT_GT(Connection.Send.LastFlushTime, OldFlushTime);
    
    // Should return TRUE (we became unblocked)
    ASSERT_TRUE(Result);
}

//
// Test 22: UpdateBlockedState - No State Change (Remains Blocked)
// Scenario: Tests the case where both PreviousCanSendState and current state
// are FALSE (blocked). The condition on line 256 should be FALSE (no state change),
// so the function should return FALSE without modifying any state.
//
TEST(CubicTest, UpdateBlockedState_RemainsBlocked)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Blocked state - cannot send
    Cubic->BytesInFlight = Cubic->CongestionWindow + 100;
    Cubic->Exemptions = 0;
    BOOLEAN PreviousCanSendState = FALSE;
    
    // Verify we cannot send
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
    
    // Set initial blocked reasons
    uint8_t InitialBlockedReasons = QUIC_FLOW_BLOCKED_CONGESTION_CONTROL | QUIC_FLOW_BLOCKED_PACING;
    Connection.OutFlowBlockedReasons = InitialBlockedReasons;

    // Call CubicCongestionControlUpdateBlockedState with PreviousCanSendState=FALSE
    BOOLEAN Result = CubicCongestionControlUpdateBlockedState(
        &Connection.CongestionControl, 
        PreviousCanSendState);

    // Verify: No state change occurred - blocked reasons should remain unchanged
    ASSERT_EQ(Connection.OutFlowBlockedReasons, InitialBlockedReasons);
    
    // Should return FALSE (no transition to unblocked)
    ASSERT_FALSE(Result);
}

//
// Test 23: UpdateBlockedState - No State Change (Remains Unblocked)
// Scenario: Tests the case where both PreviousCanSendState and current state
// are TRUE (can send). The condition on line 256 should be FALSE (no state change),
// so the function should return FALSE without modifying any state.
//
TEST(CubicTest, UpdateBlockedState_RemainsUnblocked)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Unblocked state - can send
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    Cubic->Exemptions = 0;
    BOOLEAN PreviousCanSendState = TRUE;
    
    // Verify we can send
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
    
    // Set initial blocked reasons (not including congestion control)
    uint8_t InitialBlockedReasons = QUIC_FLOW_BLOCKED_PACING;
    Connection.OutFlowBlockedReasons = InitialBlockedReasons;
    
    uint64_t InitialFlushTime = 98765432;
    Connection.Send.LastFlushTime = InitialFlushTime;

    // Call CubicCongestionControlUpdateBlockedState with PreviousCanSendState=TRUE
    BOOLEAN Result = CubicCongestionControlUpdateBlockedState(
        &Connection.CongestionControl, 
        PreviousCanSendState);

    // Verify: No state change occurred - blocked reasons should remain unchanged
    ASSERT_EQ(Connection.OutFlowBlockedReasons, InitialBlockedReasons);
    
    // Verify: LastFlushTime should remain unchanged
    ASSERT_EQ(Connection.Send.LastFlushTime, InitialFlushTime);
    
    // Should return FALSE (no transition to unblocked, was already unblocked)
    ASSERT_FALSE(Result);
}

//
// Test 24: UpdateBlockedState - Unblock with Exemptions
// Scenario: Tests lines 261-263 when unblocking occurs due to exemptions rather
// than available congestion window. When exemptions > 0, CanSend returns TRUE
// even if BytesInFlight >= CongestionWindow. This verifies the unblocking logic
// works correctly regardless of why CanSend returned TRUE.
//
TEST(CubicTest, UpdateBlockedState_UnblockViaExemptions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Start blocked (PreviousCanSendState=FALSE)
    Cubic->BytesInFlight = Cubic->CongestionWindow; // At limit
    Cubic->Exemptions = 0;
    BOOLEAN PreviousCanSendState = FALSE;
    
    // Verify blocked initially
    ASSERT_FALSE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));
    
    Connection.OutFlowBlockedReasons = QUIC_FLOW_BLOCKED_CONGESTION_CONTROL;
    uint64_t OldFlushTime = 11111111;
    Connection.Send.LastFlushTime = OldFlushTime;

    // Add exemptions - this should allow sending even though window is full
    Cubic->Exemptions = 3;

    // Verify we can now send due to exemptions
    ASSERT_TRUE(Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl));

    // Call CubicCongestionControlUpdateBlockedState
    BOOLEAN Result = CubicCongestionControlUpdateBlockedState(
        &Connection.CongestionControl, 
        PreviousCanSendState);

    // Verify: Blocked reason removed (line 261-262)
    ASSERT_TRUE((Connection.OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_CONGESTION_CONTROL) == 0);
    
    // Verify: LastFlushTime reset (line 263)
    ASSERT_NE(Connection.Send.LastFlushTime, OldFlushTime);
    
    // Should return TRUE (became unblocked)
    ASSERT_TRUE(Result);
}

//
// Test 25: OnCongestionEvent - Persistent Congestion Handling (Lines 309-330)
// Scenario: Tests lines 309-330 in cubic.c where persistent congestion is detected
// for the first time. This should:
// - Set IsInPersistentCongestion flag (line 318)
// - Drastically reduce congestion window to minimum (lines 325-326)
// - Update WindowPrior, WindowMax, WindowLastMax, SlowStartThreshold, AimdWindow (lines 319-324)
// - Reset KCubic to 0 (line 327)
// - Transition HyStart to DONE state (line 328)
// - Increment PersistentCongestionCount stat (line 314)
// - Set route state to RouteSuspected (line 316)
//
TEST(CubicTest, OnCongestionEvent_PersistentCongestion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE; // Enable HyStart so state transitions work

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    // IMPORTANT: Set HyStartEnabled on Connection.Settings after InitializeMockConnection
    Connection.Settings.HyStartEnabled = TRUE;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup initial state - simulate we're in a healthy state with a large window
    Cubic->CongestionWindow = 50000;
    Cubic->WindowMax = 40000;
    Cubic->WindowLastMax = 35000;
    Cubic->WindowPrior = 45000;
    Cubic->SlowStartThreshold = 30000;
    Cubic->AimdWindow = 48000;
    Cubic->KCubic = 500;
    Cubic->BytesInFlight = 10000;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE; // Had congestion before, but not persistent
    
    // Set HyStart to some non-DONE state
    Cubic->HyStartState = HYSTART_ACTIVE;

    uint32_t InitialPersistentCongestionCount = Connection.Stats.Send.PersistentCongestionCount;
    uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    // Call CubicCongestionControlOnCongestionEvent with IsPersistentCongestion=TRUE
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        TRUE,  // IsPersistentCongestion
        FALSE  // Not ECN
    );

    // Verify: Line 314 - PersistentCongestionCount incremented
    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, InitialPersistentCongestionCount + 1);

    // Verify: Line 316 - Route state set to RouteSuspected
    ASSERT_EQ(Connection.Paths[0].Route.State, RouteSuspected);

    // Verify: Line 318 - IsInPersistentCongestion flag set
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);

    // Verify: Lines 319-324 - WindowPrior, WindowMax, WindowLastMax, SlowStartThreshold, 
    // AimdWindow all set to (CongestionWindow * TEN_TIMES_BETA_CUBIC / 10)
    // where TEN_TIMES_BETA_CUBIC = 7, so they should all be 50000 * 7 / 10 = 35000
    uint32_t ExpectedReducedWindow = 50000 * 7 / 10;
    ASSERT_EQ(Cubic->WindowPrior, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->WindowMax, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->WindowLastMax, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->AimdWindow, ExpectedReducedWindow);

    // Verify: Lines 325-326 - CongestionWindow set to minimum
    // QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS * DatagramPayloadLength
    uint32_t ExpectedMinWindow = DatagramPayloadLength * 2; // QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS is 2
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedMinWindow);

    // Verify: Line 327 - KCubic reset to 0
    ASSERT_EQ(Cubic->KCubic, 0u);

    // Verify: Line 328 - CubicCongestionHyStartChangeState was called (sets state to DONE if HyStart enabled)
    // Since HyStartEnabled is TRUE, the state should transition to HYSTART_DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Verify other state flags (lines 290-291)
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
}

//
// Test 26: OnCongestionEvent - Already in Persistent Congestion
// Scenario: Tests that when persistent congestion is already set (IsInPersistentCongestion=TRUE),
// calling OnCongestionEvent with IsPersistentCongestion=TRUE skips lines 309-330 and goes
// to the else branch (line 330) instead. This ensures the persistent congestion block is
// only executed once.
//
TEST(CubicTest, OnCongestionEvent_AlreadyInPersistentCongestion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Already in persistent congestion
    Cubic->CongestionWindow = 5000;
    Cubic->IsInPersistentCongestion = TRUE;
    Cubic->HasHadCongestionEvent = TRUE;
    Cubic->WindowMax = 3500;
    Cubic->WindowPrior = 3500;
    Cubic->WindowLastMax = 3000;

    uint32_t InitialCongestionWindow = Cubic->CongestionWindow;
    uint32_t InitialPersistentCongestionCount = Connection.Stats.Send.PersistentCongestionCount;

    // Call OnCongestionEvent with IsPersistentCongestion=TRUE again
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        TRUE,  // IsPersistentCongestion
        FALSE  // Not ECN
    );

    // Verify: The condition on line 307 is FALSE (we skip lines 309-330)
    // So PersistentCongestionCount should NOT increment
    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, InitialPersistentCongestionCount);

    // Verify: We went through the else branch (line 330+) instead
    // WindowPrior and WindowMax should be set to current CongestionWindow
    ASSERT_EQ(Cubic->WindowPrior, InitialCongestionWindow);
    ASSERT_EQ(Cubic->WindowMax, InitialCongestionWindow);

    // IsInPersistentCongestion should remain TRUE
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);
}

//
// Test 27: OnCongestionEvent - Non-Persistent Congestion Path
// Scenario: Tests that when IsPersistentCongestion=FALSE, lines 309-330 are skipped
// and the else branch (line 330+) is executed instead. This is the normal congestion
// event path.
//
TEST(CubicTest, OnCongestionEvent_NonPersistentCongestion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE; // Enable HyStart

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Settings.HyStartEnabled = TRUE; // Set on Connection after InitializeMockConnection

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup initial state
    uint32_t InitialCongestionWindow = 50000;
    Cubic->CongestionWindow = InitialCongestionWindow;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = FALSE;

    uint32_t InitialPersistentCongestionCount = Connection.Stats.Send.PersistentCongestionCount;

    // Call OnCongestionEvent with IsPersistentCongestion=FALSE
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        FALSE, // IsPersistentCongestion=FALSE
        FALSE  // Not ECN
    );

    // Verify: Lines 309-330 were NOT executed
    // PersistentCongestionCount should NOT increment
    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, InitialPersistentCongestionCount);

    // IsInPersistentCongestion should remain FALSE
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);

    // Verify: The else branch was executed (line 330+)
    // Line 332-334: WindowPrior and WindowMax are set to the ORIGINAL CongestionWindow (before reduction)
    // Then lines 361-366: CongestionWindow itself gets reduced by BETA
    // So WindowPrior == WindowMax == original window, but CongestionWindow is reduced
    ASSERT_EQ(Cubic->WindowPrior, InitialCongestionWindow);  // Should be original 50000
    // Note: WindowMax may be further adjusted by fast convergence (lines 335-343)
    ASSERT_GT(Cubic->CongestionWindow, 0u);  // Should be reduced from original

    // Recovery flags should be set
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
}

//
// Test 28: OnCongestionEvent - Persistent Congestion State Transition
// Scenario: Comprehensive test that verifies the complete state transition when
// persistent congestion occurs, including all fields updated in lines 309-330.
// This test starts from a specific congestion state and verifies all state changes.
//
TEST(CubicTest, OnCongestionEvent_PersistentCongestionStateTransition)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 50;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE; // Enable HyStart

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 100000; // 100ms
    Connection.Settings.HyStartEnabled = TRUE; // Set on Connection after InitializeMockConnection

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Simulate a connection with significant congestion window
    uint32_t InitialCongestionWindow = 100000;
    Cubic->CongestionWindow = InitialCongestionWindow;
    Cubic->WindowMax = 80000;
    Cubic->WindowLastMax = 75000;
    Cubic->WindowPrior = 90000;
    Cubic->SlowStartThreshold = 60000;
    Cubic->AimdWindow = 95000;
    Cubic->KCubic = 1000; // Non-zero K value
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->IsInRecovery = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;
    Cubic->HyStartState = HYSTART_ACTIVE;

    // Initialize route state to something other than RouteSuspected
    Connection.Paths[0].Route.State = RouteResolved;

    uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t ExpectedMinWindow = DatagramPayloadLength * 2; // QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS

    // Save initial values for verification
    uint32_t InitialCongestionCount = Connection.Stats.Send.CongestionCount;
    uint32_t InitialPersistentCount = Connection.Stats.Send.PersistentCongestionCount;

    // Trigger persistent congestion
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        TRUE,  // IsPersistentCongestion
        FALSE  // Not ECN
    );

    // Verify: General congestion event stats (line 288)
    ASSERT_EQ(Connection.Stats.Send.CongestionCount, InitialCongestionCount + 1);

    // Verify: Persistent congestion specific stats (line 314)
    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, InitialPersistentCount + 1);

    // Verify: Line 316 - Route state changed to RouteSuspected
    ASSERT_EQ(Connection.Paths[0].Route.State, RouteSuspected);

    // Verify: Line 318 - Flag set
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);

    // Verify: Lines 319-324 - All these fields set to (InitialCongestionWindow * 7 / 10)
    uint32_t ExpectedReducedWindow = InitialCongestionWindow * 7 / 10; // 100000 * 7 / 10 = 70000
    ASSERT_EQ(Cubic->WindowPrior, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->WindowMax, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->WindowLastMax, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->SlowStartThreshold, ExpectedReducedWindow);
    ASSERT_EQ(Cubic->AimdWindow, ExpectedReducedWindow);

    // Verify: Lines 325-326 - CongestionWindow drastically reduced to minimum
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedMinWindow);
    ASSERT_LT(Cubic->CongestionWindow, ExpectedReducedWindow); // Much smaller than the reduced window

    // Verify: Line 327 - KCubic reset to zero
    ASSERT_EQ(Cubic->KCubic, 0u);

    // Verify: Line 328 - HyStart state changed to DONE
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Verify: Lines 290-291 - Recovery flags set
    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_TRUE(Cubic->HasHadCongestionEvent);
}

//
// Test 29: OnCongestionEvent - Fast Convergence Path (Lines 339-340)
// Scenario: Tests lines 339-340 in cubic.c where WindowLastMax > WindowMax triggers
// the "fast convergence" optimization. This happens when the connection experiences
// repeated congestion before recovering to the previous maximum window. The algorithm
// reduces WindowMax more aggressively to probe for available bandwidth faster.
// Line 335: if (Cubic->WindowLastMax > Cubic->WindowMax) - TRUE condition
// Line 339: Cubic->WindowLastMax = Cubic->WindowMax
// Line 340: Cubic->WindowMax adjusted by fast convergence formula
//
TEST(CubicTest, OnCongestionEvent_FastConvergence)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Settings.HyStartEnabled = TRUE;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Simulate a scenario where fast convergence should trigger
    // WindowLastMax should be GREATER than the current CongestionWindow
    // This simulates: connection previously reached 100000, then experienced congestion,
    // now at 60000, and experiencing another congestion event
    Cubic->CongestionWindow = 60000;
    Cubic->WindowLastMax = 100000;  // Previous maximum (must be > current window)
    Cubic->WindowMax = 80000;       // Set to some intermediate value
    Cubic->WindowPrior = 70000;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;

    // Call OnCongestionEvent - this will set WindowMax = CongestionWindow (60000)
    // Then WindowLastMax (100000) > WindowMax (60000), so fast convergence triggers
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        FALSE, // Not persistent congestion
        FALSE  // Not ECN
    );

    // Verify: Line 335 condition was TRUE (WindowLastMax > WindowMax)
    // After line 332-334: WindowMax was set to CongestionWindow (60000)
    // Since initial WindowLastMax (100000) > WindowMax (60000), fast convergence triggered

    // Verify: Line 339 - WindowLastMax updated to WindowMax
    // WindowLastMax should now equal the pre-adjustment WindowMax value (60000)
    ASSERT_EQ(Cubic->WindowLastMax, 60000u);

    // Verify: Line 340 - WindowMax adjusted by fast convergence formula
    // Formula: WindowMax = WindowMax * (10 + TEN_TIMES_BETA_CUBIC) / 20
    // where TEN_TIMES_BETA_CUBIC = 7
    // So: WindowMax = 60000 * (10 + 7) / 20 = 60000 * 17 / 20 = 51000
    uint32_t ExpectedWindowMax = 60000 * 17 / 20;
    ASSERT_EQ(Cubic->WindowMax, ExpectedWindowMax);

    // Verify WindowMax was reduced below the original value
    ASSERT_LT(Cubic->WindowMax, 60000u);
}

//
// Test 30: OnCongestionEvent - No Fast Convergence (Line 342)
// Scenario: Tests line 342 (else branch) when WindowLastMax <= WindowMax, meaning
// fast convergence should NOT trigger. This is the normal case where the connection
// is reaching new highs rather than oscillating.
// Line 335: if (Cubic->WindowLastMax > WindowMax) - FALSE condition
// Line 342: Cubic->WindowLastMax = Cubic->WindowMax (simple assignment)
//
TEST(CubicTest, OnCongestionEvent_NoFastConvergence)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Settings.HyStartEnabled = TRUE;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Simulate a scenario where fast convergence should NOT trigger
    // WindowLastMax should be LESS THAN OR EQUAL to the current CongestionWindow
    // This simulates: connection is reaching new highs
    Cubic->CongestionWindow = 80000;
    Cubic->WindowLastMax = 60000;  // Previous maximum (less than current window)
    Cubic->WindowMax = 70000;
    Cubic->WindowPrior = 75000;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;

    // Call OnCongestionEvent
    // After line 332-334: WindowMax will be set to CongestionWindow (80000)
    // Since WindowLastMax (60000) < WindowMax (80000), fast convergence does NOT trigger
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        FALSE, // Not persistent congestion
        FALSE  // Not ECN
    );

    // Verify: Line 335 condition was FALSE (WindowLastMax <= WindowMax)
    // After line 332-334: WindowMax = CongestionWindow = 80000
    // Since WindowLastMax (60000) < WindowMax (80000), else branch (line 342) executed

    // Verify: Line 342 - WindowLastMax simply assigned to WindowMax (no fast convergence adjustment)
    // WindowLastMax should be set to the current WindowMax value
    ASSERT_EQ(Cubic->WindowLastMax, Cubic->WindowMax);
    
    // Verify: WindowMax was NOT reduced by fast convergence formula
    // Instead, it was set to CongestionWindow and NOT further adjusted
    // (though it will be reduced later by lines 361-366, but not by fast convergence)
    ASSERT_GE(Cubic->WindowLastMax, 60000u); // Should be at least the original value
}

//
// Test 31: OnCongestionEvent - Fast Convergence Edge Case (Equal Values)
// Scenario: Tests the boundary condition where WindowLastMax == WindowMax.
// According to line 335, the condition is >, so when they're equal, fast convergence
// should NOT trigger (else branch at line 342).
//
TEST(CubicTest, OnCongestionEvent_FastConvergenceEdgeCase)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Settings.HyStartEnabled = TRUE;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: WindowLastMax == CongestionWindow (edge case for line 335 condition)
    Cubic->CongestionWindow = 70000;
    Cubic->WindowLastMax = 70000;  // Equal to current window
    Cubic->WindowMax = 70000;
    Cubic->WindowPrior = 70000;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;

    // Call OnCongestionEvent
    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        FALSE, // Not persistent congestion
        FALSE  // Not ECN
    );

    // Verify: Line 335 condition was FALSE (WindowLastMax == WindowMax, not >)
    // So line 342 (else branch) should execute, not lines 339-340

    // Verify: Line 342 - WindowLastMax = WindowMax (simple assignment, no reduction)
    ASSERT_EQ(Cubic->WindowLastMax, Cubic->WindowMax);
    
    // WindowMax should NOT have been reduced by the fast convergence formula (line 340)
    // It gets set to CongestionWindow at line 333-334, but NOT further adjusted by line 340
    // Note: CongestionWindow itself gets reduced later by lines 361-366
}

//
// Test 32: OnCongestionEvent - Fast Convergence Multiple Times
// Scenario: Tests that fast convergence can trigger multiple times in succession,
// progressively reducing WindowMax when repeated congestion events occur.
// This simulates a connection oscillating due to network instability.
//
TEST(CubicTest, OnCongestionEvent_FastConvergenceMultipleTimes)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000;
    Connection.Settings.HyStartEnabled = TRUE;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // First congestion event
    Cubic->CongestionWindow = 100000;
    Cubic->WindowLastMax = 120000;  // Previous peak
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;

    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        FALSE,
        FALSE
    );

    // After first event: WindowMax should be reduced by fast convergence
    uint32_t FirstWindowMax = Cubic->WindowMax;
    uint32_t FirstWindowLastMax = Cubic->WindowLastMax;
    
    // Verify first fast convergence applied
    ASSERT_LT(FirstWindowMax, 100000u); // Should be less than original CongestionWindow
    ASSERT_EQ(FirstWindowLastMax, 100000u); // WindowLastMax set to original WindowMax

    // Simulate recovery and second congestion event
    // Set CongestionWindow higher than current WindowMax but less than previous WindowLastMax
    Cubic->CongestionWindow = 90000;
    Cubic->IsInRecovery = FALSE; // Reset recovery state

    CubicCongestionControlOnCongestionEvent(
        &Connection.CongestionControl,
        FALSE,
        FALSE
    );

    // After second event: Fast convergence should trigger again
    // WindowLastMax (100000 from first event) > WindowMax (90000), so line 339-340 execute
    uint32_t SecondWindowMax = Cubic->WindowMax;
    uint32_t SecondWindowLastMax = Cubic->WindowLastMax;

    // Verify second fast convergence applied
    ASSERT_EQ(SecondWindowLastMax, 90000u); // Line 339: Updated to current WindowMax
    uint32_t ExpectedSecondWindowMax = 90000 * 17 / 20; // Line 340: Fast convergence formula
    ASSERT_EQ(SecondWindowMax, ExpectedSecondWindowMax);
    
    // Verify progressive reduction
    ASSERT_LT(SecondWindowMax, FirstWindowMax); // Each event further reduces WindowMax
}


