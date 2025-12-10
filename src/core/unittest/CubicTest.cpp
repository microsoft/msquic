/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for CUBIC congestion control initialization logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CubicTest.cpp.clog.h"
#endif

//
// Mock structures for testing
//

typedef struct MOCK_CONNECTION
{
    QUIC_CONGESTION_CONTROL CongestionControl;
    QUIC_PATH Paths[QUIC_MAX_PATH_COUNT];
    QUIC_SEND Send;
    QUIC_SETTINGS_INTERNAL Settings;
} MOCK_CONNECTION;

//
// Helper to create a minimal valid mock connection
//
static void InitializeMockConnection(MOCK_CONNECTION *MockConn, uint16_t Mtu)
{
    CxPlatZeroMemory(MockConn, sizeof(*MockConn));
    MockConn->Paths[0].Mtu = Mtu;
    MockConn->Paths[0].IsActive = TRUE;
    MockConn->Send.NextPacketNumber = 0;

    // Initialize Settings with defaults
    MockConn->Settings.PacingEnabled = FALSE;  // Disable pacing by default for simpler tests
    MockConn->Settings.HyStartEnabled = FALSE; // Disable HyStart by default

    // Initialize Path fields needed for some functions
    MockConn->Paths[0].GotFirstRttSample = FALSE;
    MockConn->Paths[0].SmoothedRtt = 0;
}

//
// Test 1: Basic initialization with default settings
// Scenario: Verifies that CubicCongestionControlInitialize correctly sets up all critical
// CUBIC state fields with typical default values (standard MTU, moderate initial window).
// This is the baseline test that validates the most common initialization path.
//
TEST(CubicTest, InitializeWithDefaultSettings)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    // Set default values
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);

    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Verify basic initialization
    ASSERT_EQ(Cubic->InitialWindowPackets, 10u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 1000u);
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Verify CongestionWindow and BytesInFlightMax are initialized correctly
    ASSERT_GT(Cubic->CongestionWindow, 0u);
    ASSERT_EQ(Cubic->BytesInFlightMax, Cubic->CongestionWindow / 2);
}

//
// Test 2: MTU boundary conditions
// Scenario: Verifies initialization handles extreme MTU values correctly (minimum, maximum,
// and below-minimum). Tests that CongestionWindow calculation doesn't overflow or underflow
// with edge-case MTU values, ensuring robustness across different network path configurations.
//
TEST(CubicTest, InitializeWithMtuBoundaries)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    // Test minimum MTU
    InitializeMockConnection(&MockConn, QUIC_DPLPMTUD_MIN_MTU);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_GT(MockConn.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(MockConn.CongestionControl.Cubic.InitialWindowPackets, 10u);

    // Test maximum MTU
    InitializeMockConnection(&MockConn, 65535);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_GT(MockConn.CongestionControl.Cubic.CongestionWindow, 0u);

    // Test very small MTU (below minimum)
    InitializeMockConnection(&MockConn, 500);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_GT(MockConn.CongestionControl.Cubic.CongestionWindow, 0u);
}

//
// Test 3: InitialWindowPackets boundary values
// Scenario: Tests minimum (1 packet) and maximum (1000 packets) InitialWindowPackets settings.
// Verifies that CongestionWindow scales correctly with InitialWindowPackets and handles both
// conservative (single packet) and aggressive (large window) initial congestion window sizes.
//
TEST(CubicTest, InitializeWithInitialWindowBoundaries)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.SendIdleTimeoutMs = 1000;

    // Test minimum: single packet window
    Settings.InitialWindowPackets = 1;
    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_EQ(MockConn.CongestionControl.Cubic.InitialWindowPackets, 1u);
    ASSERT_GT(MockConn.CongestionControl.Cubic.CongestionWindow, 0u);
    uint32_t SinglePacketWindow = MockConn.CongestionControl.Cubic.CongestionWindow;

    // Test large window (1000 packets)
    Settings.InitialWindowPackets = 1000;
    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_EQ(MockConn.CongestionControl.Cubic.InitialWindowPackets, 1000u);
    ASSERT_GT(MockConn.CongestionControl.Cubic.CongestionWindow, SinglePacketWindow * 100);
}

//
// Test 4: SendIdleTimeoutMs boundary values
// Scenario: Tests extreme SendIdleTimeoutMs values (0 and UINT32_MAX). Verifies that
// the idle timeout is correctly stored and doesn't cause initialization to fail even
// with edge-case timeout values (disabled timeout or maximum possible timeout).
//
TEST(CubicTest, InitializeWithSendIdleTimeoutBoundaries)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;

    // Test zero timeout (disabled)
    Settings.SendIdleTimeoutMs = 0;
    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_EQ(MockConn.CongestionControl.Cubic.SendIdleTimeoutMs, 0u);
    ASSERT_GT(MockConn.CongestionControl.Cubic.CongestionWindow, 0u);

    // Test maximum timeout
    Settings.SendIdleTimeoutMs = UINT32_MAX;
    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    ASSERT_EQ(MockConn.CongestionControl.Cubic.SendIdleTimeoutMs, UINT32_MAX);
}

//
// Test 5: HyStart++ state initialization
// Scenario: Verifies all HyStart++ related fields are correctly initialized. HyStart++ is
// CUBIC's mechanism for early slow-start exit. Tests that HyStartState, round tracking,
// RTT sampling, and growth divisor are properly set up for the slow-start phase.
//
TEST(CubicTest, VerifyHyStartInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);

    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Verify HyStart fields - HyStartRoundEnd should be set to Connection->Send.NextPacketNumber
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartRoundEnd, 0u); // NextPacketNumber starts at 0
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInLastRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 6: Function pointer initialization
// Scenario: Verifies all 17 CUBIC algorithm function pointers are correctly assigned.
// The initialization must copy function pointers from the static template to the instance,
// enabling polymorphic congestion control behavior. Critical for ensuring CUBIC operations
// are callable after initialization.
//
TEST(CubicTest, VerifyFunctionPointers)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);

    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    // Verify all 17 function pointers are set (non-null)
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlCanSend, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlSetExemption, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlReset, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlGetSendAllowance, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlOnDataSent, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlOnDataInvalidated, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlOnDataAcknowledged, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlOnDataLost, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlOnEcn, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlLogOutFlowStatus, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlGetExemptions, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlGetBytesInFlightMax, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlIsAppLimited, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlSetAppLimited, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlGetCongestionWindow, nullptr);
    ASSERT_NE(MockConn.CongestionControl.QuicCongestionControlGetNetworkStatistics, nullptr);
}

//
// Test 7: Boolean state flags initialization
// Scenario: Verifies congestion and recovery state flags are initialized to FALSE.
// These flags track whether congestion has occurred (HasHadCongestionEvent), whether
// currently in recovery (IsInRecovery), persistent congestion state, and ACK timing.
// All must start FALSE for correct initial congestion control behavior.
//
TEST(CubicTest, VerifyInitialStateFlags)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);

    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Verify initial boolean flags (should be FALSE/0 after initialization)
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
    ASSERT_FALSE(Cubic->TimeOfLastAckValid);
}

//
// Test 8: Zero-initialized numeric fields
// Scenario: Verifies that all CUBIC state tracking fields are zero-initialized. This includes
// BytesInFlightMax (max bytes allowed in flight), pacing state (LastSendAllowance),
// AIMD fallback fields (AimdWindow, AimdAccumulator), CUBIC window tracking (WindowMax,
// WindowLastMax, WindowPrior, KCubic), timing fields (TimeOfLastAck, TimeOfCongAvoidStart),
// recovery tracking (RecoverySentPacketNumber), and previous state for spurious congestion
// recovery (all Prev* fields). Tests that struct copy from static template zeros these fields.
//
TEST(CubicTest, VerifyZeroInitializedFields)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);

    // Pre-set some fields to non-zero to verify they get zeroed
    MockConn.CongestionControl.Cubic.BytesInFlight = 12345;
    MockConn.CongestionControl.Cubic.Exemptions = 5;

    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Verify BytesInFlightMax is calculated correctly
    ASSERT_EQ(Cubic->BytesInFlightMax, Cubic->CongestionWindow / 2);

    // Verify Exemptions is zeroed
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // AIMD related fields should be 0
    ASSERT_EQ(Cubic->AimdWindow, 0u);
    ASSERT_EQ(Cubic->AimdAccumulator, 0u);

    // WindowMax and related CUBIC fields should be 0
    ASSERT_EQ(Cubic->WindowMax, 0u);
    ASSERT_EQ(Cubic->WindowLastMax, 0u);
    ASSERT_EQ(Cubic->WindowPrior, 0u);
    ASSERT_EQ(Cubic->KCubic, 0u);

    // Pacing field should be 0
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);

    // Timing fields should be 0
    ASSERT_EQ(Cubic->TimeOfLastAck, 0u);
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, 0u);

    // Recovery field should be 0
    ASSERT_EQ(Cubic->RecoverySentPacketNumber, 0u);

    // All Prev* fields for spurious congestion handling should be 0
    ASSERT_EQ(Cubic->PrevWindowPrior, 0u);
    ASSERT_EQ(Cubic->PrevWindowMax, 0u);
    ASSERT_EQ(Cubic->PrevWindowLastMax, 0u);
    ASSERT_EQ(Cubic->PrevKCubic, 0u);
    ASSERT_EQ(Cubic->PrevSlowStartThreshold, 0u);
    ASSERT_EQ(Cubic->PrevCongestionWindow, 0u);
    ASSERT_EQ(Cubic->PrevAimdWindow, 0u);
}

//
// Test 9: Re-initialization behavior
// Scenario: Tests that CUBIC can be re-initialized with different settings and correctly
// updates its state. Verifies that calling CubicCongestionControlInitialize() multiple times
// properly resets state and applies new settings (e.g., doubling InitialWindowPackets should
// double the CongestionWindow). Important for connection migration or settings updates.
//
TEST(CubicTest, MultipleSequentialInitializations)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);

    // Initialize first time
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    uint32_t FirstCongestionWindow = MockConn.CongestionControl.Cubic.CongestionWindow;

    // Re-initialize with different settings
    Settings.InitialWindowPackets = 20;
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Should reflect new settings with doubled window
    ASSERT_EQ(Cubic->InitialWindowPackets, 20u);
    ASSERT_EQ(Cubic->CongestionWindow, FirstCongestionWindow * 2);
}

//
// Test 10: CanSend scenarios (via function pointer)
// Scenario: Comprehensive test of CanSend logic covering: available window (can send),
// congestion blocked (cannot send), and exemptions (bypass blocking). Tests the core
// congestion control decision logic.
//
TEST(CubicTest, CanSendScenarios)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Scenario 1: Available window - can send
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    Cubic->Exemptions = 0;
    ASSERT_TRUE(MockConn.CongestionControl.QuicCongestionControlCanSend(&MockConn.CongestionControl));

    // Scenario 2: Congestion blocked - cannot send
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    ASSERT_FALSE(MockConn.CongestionControl.QuicCongestionControlCanSend(&MockConn.CongestionControl));

    // Scenario 3: Exceeding window - still blocked
    Cubic->BytesInFlight = Cubic->CongestionWindow + 100;
    ASSERT_FALSE(MockConn.CongestionControl.QuicCongestionControlCanSend(&MockConn.CongestionControl));

    // Scenario 4: With exemptions - can send even when blocked
    Cubic->Exemptions = 2;
    ASSERT_TRUE(MockConn.CongestionControl.QuicCongestionControlCanSend(&MockConn.CongestionControl));
}

//
// Test 11: SetExemption (via function pointer)
// Scenario: Tests SetExemption to verify it correctly sets the number of packets that
// can bypass congestion control. Used for probe packets and other special cases.
//
TEST(CubicTest, SetExemption)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Initially should be 0
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Set exemptions via function pointer
    MockConn.CongestionControl.QuicCongestionControlSetExemption(&MockConn.CongestionControl, 5);
    ASSERT_EQ(Cubic->Exemptions, 5u);

    // Set to zero
    MockConn.CongestionControl.QuicCongestionControlSetExemption(&MockConn.CongestionControl, 0);
    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Set to max
    MockConn.CongestionControl.QuicCongestionControlSetExemption(&MockConn.CongestionControl, 255);
    ASSERT_EQ(Cubic->Exemptions, 255u);
}

//
// Test 12: GetSendAllowance scenarios (via function pointer)
// Scenario: Tests GetSendAllowance under different conditions: congestion blocked (returns 0),
// available window without pacing (returns full window), and invalid time (skips pacing).
// Covers the main decision paths in send allowance calculation.
//
TEST(CubicTest, GetSendAllowanceScenarios)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Scenario 1: Congestion blocked - should return 0
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    uint32_t Allowance = MockConn.CongestionControl.QuicCongestionControlGetSendAllowance(
        &MockConn.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, 0u);

    // Scenario 2: Available window without pacing - should return full window
    MockConn.Settings.PacingEnabled = FALSE;
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    uint32_t ExpectedAllowance = Cubic->CongestionWindow - Cubic->BytesInFlight;
    Allowance = MockConn.CongestionControl.QuicCongestionControlGetSendAllowance(
        &MockConn.CongestionControl, 1000, TRUE);
    ASSERT_EQ(Allowance, ExpectedAllowance);

    // Scenario 3: Invalid time - should skip pacing and return full window
    MockConn.Settings.PacingEnabled = TRUE;
    MockConn.Paths[0].GotFirstRttSample = TRUE;
    MockConn.Paths[0].SmoothedRtt = 50000;
    Allowance = MockConn.CongestionControl.QuicCongestionControlGetSendAllowance(
        &MockConn.CongestionControl, 1000, FALSE); // FALSE = invalid time
    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 13: Getter functions (via function pointers)
// Scenario: Tests all simple getter functions that return internal state values.
// Verifies GetExemptions, GetBytesInFlightMax, and GetCongestionWindow all return
// correct values matching the internal CUBIC state.
//
TEST(CubicTest, GetterFunctions)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Test GetExemptions
    uint8_t Exemptions = MockConn.CongestionControl.QuicCongestionControlGetExemptions(&MockConn.CongestionControl);
    ASSERT_EQ(Exemptions, 0u);
    Cubic->Exemptions = 3;
    Exemptions = MockConn.CongestionControl.QuicCongestionControlGetExemptions(&MockConn.CongestionControl);
    ASSERT_EQ(Exemptions, 3u);

    // Test GetBytesInFlightMax
    uint32_t MaxBytes = MockConn.CongestionControl.QuicCongestionControlGetBytesInFlightMax(&MockConn.CongestionControl);
    ASSERT_EQ(MaxBytes, Cubic->BytesInFlightMax);
    ASSERT_EQ(MaxBytes, Cubic->CongestionWindow / 2);

    // Test GetCongestionWindow
    uint32_t CongestionWindow = MockConn.CongestionControl.QuicCongestionControlGetCongestionWindow(&MockConn.CongestionControl);
    ASSERT_EQ(CongestionWindow, Cubic->CongestionWindow);
    ASSERT_GT(CongestionWindow, 0u);
}

//
// Test 14: Reset scenarios (via function pointer)
// Scenario: Tests Reset function with both FullReset=FALSE (preserves BytesInFlight) and
// FullReset=TRUE (zeros BytesInFlight). Verifies that reset properly reinitializes CUBIC
// state while respecting the FullReset parameter for connection recovery scenarios.
//
TEST(CubicTest, ResetScenarios)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&MockConn, 1280);
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &MockConn.CongestionControl.Cubic;

    // Scenario 1: Partial reset (FullReset=FALSE) - preserves BytesInFlight
    Cubic->BytesInFlight = 5000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->IsInRecovery = TRUE;
    Cubic->HasHadCongestionEvent = TRUE;
    uint32_t BytesInFlightBefore = Cubic->BytesInFlight;

    MockConn.CongestionControl.QuicCongestionControlReset(&MockConn.CongestionControl, FALSE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->BytesInFlight, BytesInFlightBefore); // Preserved

    // Scenario 2: Full reset (FullReset=TRUE) - zeros BytesInFlight
    Cubic->BytesInFlight = 5000;
    Cubic->SlowStartThreshold = 10000;
    Cubic->IsInRecovery = TRUE;

    MockConn.CongestionControl.QuicCongestionControlReset(&MockConn.CongestionControl, TRUE);

    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->BytesInFlight, 0u); // Zeroed with full reset
}
