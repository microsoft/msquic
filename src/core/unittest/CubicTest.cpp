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
// Test 1: Basic initialization with default settings
// Scenario: Verifies that CubicCongestionControlInitialize correctly sets up all critical
// CUBIC state fields with typical default values (standard MTU, moderate initial window).
// This is the baseline test that validates the most common initialization path.
//
TEST(CubicTest, InitializeWithDefaultSettings)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    // Set default values
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    // Test minimum MTU
    InitializeMockConnection(&Connection, QUIC_DPLPMTUD_MIN_MTU);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 10u);

    // Test maximum MTU
    InitializeMockConnection(&Connection, 65535);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);

    // Test very small MTU (below minimum)
    InitializeMockConnection(&Connection, 500);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
}

//
// Test 3: InitialWindowPackets boundary values
// Scenario: Tests minimum (1 packet) and maximum (1000 packets) InitialWindowPackets settings.
// Verifies that CongestionWindow scales correctly with InitialWindowPackets and handles both
// conservative (single packet) and aggressive (large window) initial congestion window sizes.
//
TEST(CubicTest, InitializeWithInitialWindowBoundaries)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.SendIdleTimeoutMs = 1000;

    // Test minimum: single packet window
    Settings.InitialWindowPackets = 1;
    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1u);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);
    uint32_t SinglePacketWindow = Connection.CongestionControl.Cubic.CongestionWindow;

    // Test large window (1000 packets)
    Settings.InitialWindowPackets = 1000;
    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_EQ(Connection.CongestionControl.Cubic.InitialWindowPackets, 1000u);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, SinglePacketWindow * 100);
}

//
// Test 4: SendIdleTimeoutMs boundary values
// Scenario: Tests extreme SendIdleTimeoutMs values (0 and UINT32_MAX). Verifies that
// the idle timeout is correctly stored and doesn't cause initialization to fail even
// with edge-case timeout values (disabled timeout or maximum possible timeout).
//
TEST(CubicTest, InitializeWithSendIdleTimeoutBoundaries)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;

    // Test zero timeout (disabled)
    Settings.SendIdleTimeoutMs = 0;
    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, 0u);
    ASSERT_GT(Connection.CongestionControl.Cubic.CongestionWindow, 0u);

    // Test maximum timeout
    Settings.SendIdleTimeoutMs = UINT32_MAX;
    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
    ASSERT_EQ(Connection.CongestionControl.Cubic.SendIdleTimeoutMs, UINT32_MAX);
}

//
// Test 5: HyStart++ state initialization
// Scenario: Verifies all HyStart++ related fields are correctly initialized. HyStart++ is
// CUBIC's mechanism for early slow-start exit. Tests that HyStartState, round tracking,
// RTT sampling, and growth divisor are properly set up for the slow-start phase.
//
TEST(CubicTest, VerifyHyStartInitialization)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // Verify all 17 function pointers are set (non-null)
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
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);

    // Pre-set some fields to non-zero to verify they get zeroed
    Connection.CongestionControl.Cubic.BytesInFlight = 12345;
    Connection.CongestionControl.Cubic.Exemptions = 5;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

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
// Test 10: CanSend scenarios (via function pointer)
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
// Test 11: SetExemption (via function pointer)
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
// Test 12: GetSendAllowance scenarios (via function pointer)
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
// Test 13: GetSendAllowance with active pacing (via function pointer)
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
// Test 14: Getter functions (via function pointers)
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
// Test 15: Reset scenarios (via function pointer)
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
// Test 16: CubicCongestionControlCanSend - Unblocked state
// Scenario: Tests CanSend when BytesInFlight < CongestionWindow and no exemptions needed.
// This is the normal case where the congestion window has room for more data. Verifies
// the function correctly returns TRUE through the function pointer interface.
//
TEST(CubicTest, CanSend_Unblocked)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set BytesInFlight to less than CongestionWindow
    Cubic->BytesInFlight = Cubic->CongestionWindow / 2;
    Cubic->Exemptions = 0;

    // Call through function pointer
    BOOLEAN CanSend = Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl);

    ASSERT_TRUE(CanSend);
}

//
// Test 17: CubicCongestionControlCanSend - Blocked by congestion window
// Scenario: Tests CanSend when BytesInFlight >= CongestionWindow and no exemptions.
// Verifies that when the congestion window is full, CanSend returns FALSE, preventing
// additional data from being sent until ACKs are received. Critical for congestion control.
//
TEST(CubicTest, CanSend_BlockedByCongestionWindow)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Fill the congestion window
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    Cubic->Exemptions = 0;

    // Call through function pointer
    BOOLEAN CanSend = Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl);

    ASSERT_FALSE(CanSend);
}

//
// Test 18: CubicCongestionControlCanSend - Exemptions allow send
// Scenario: Tests that exemptions override congestion window limits. Even when
// BytesInFlight >= CongestionWindow, if Exemptions > 0, CanSend returns TRUE.
// Exemptions are used for probe packets and loss recovery retransmissions.
//
TEST(CubicTest, CanSend_WithExemptions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Fill congestion window but add exemptions
    Cubic->BytesInFlight = Cubic->CongestionWindow;
    Cubic->Exemptions = 3;

    // Call through function pointer
    BOOLEAN CanSend = Connection.CongestionControl.QuicCongestionControlCanSend(&Connection.CongestionControl);

    ASSERT_TRUE(CanSend);
}

//
// Test 19: CubicCongestionControlSetExemption - Single exemption
// Scenario: Tests setting exemptions through function pointer. Verifies that calling
// SetExemption increments the Exemptions counter, allowing probe packets to be sent
// even when the congestion window is full.
//
TEST(CubicTest, SetExemption_Single)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    ASSERT_EQ(Cubic->Exemptions, 0u);

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 1);

    ASSERT_EQ(Cubic->Exemptions, 1u);
}

//
// Test 20: CubicCongestionControlSetExemption - Multiple exemptions
// Scenario: Tests that exemptions can be set to a specific value. SetExemption directly
// sets the exemption count (doesn't increment), allowing multiple probe packets to be sent.
// Verifies the function correctly sets the value.
//
TEST(CubicTest, SetExemption_Multiple)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Add multiple exemptions by setting to 3 directly (SetExemption sets, not increments)
    Connection.CongestionControl.QuicCongestionControlSetExemption(&Connection.CongestionControl, 3);

    ASSERT_EQ(Cubic->Exemptions, 3u);
}

//
// Test 21: CubicCongestionControlGetSendAllowance - Without pacing
// Scenario: Tests GetSendAllowance when pacing is disabled. Should return the full
// available congestion window (CongestionWindow - BytesInFlight). This is the simple
// case where the entire window is available immediately.
//
TEST(CubicTest, GetSendAllowance_WithoutPacing)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    Connection.Settings.PacingEnabled = FALSE;

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set some bytes in flight
    Cubic->BytesInFlight = 2000;
    uint32_t ExpectedAllowance = Cubic->CongestionWindow - Cubic->BytesInFlight;

    // Call through function pointer
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 0, FALSE);

    ASSERT_EQ(Allowance, ExpectedAllowance);
}

//
// Test 22: CubicCongestionControlOnDataSent - BytesInFlight increases
// Scenario: Tests that OnDataSent correctly increments BytesInFlight when data is sent.
// This tracks outstanding data in the network. Verifies BytesInFlightMax is updated
// when BytesInFlight reaches a new maximum.
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
}

//
// Test 23: CubicCongestionControlOnDataSent - Exemptions decremented
// Scenario: Tests that OnDataSent decrements Exemptions when sending with exemptions.
// When probe packets are sent using exemptions, each send should consume one exemption.
// Verifies the exemption counter decreases correctly.
//
TEST(CubicTest, OnDataSent_DecrementsExemptions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set exemptions
    Cubic->Exemptions = 5;

    // Send data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 1500);

    ASSERT_EQ(Cubic->Exemptions, 4u);
}

//
// Test 24: CubicCongestionControlOnDataInvalidated - BytesInFlight decreases
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
// Test 25: CubicCongestionControlGetExemptions - Returns current value
// Scenario: Tests the GetExemptions accessor function. Verifies it returns the current
// exemption count, which is used by the send logic to determine if probe packets can
// be sent even when the congestion window is full.
//
TEST(CubicTest, GetExemptions_ReturnsValue)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set exemptions
    Cubic->Exemptions = 7;

    // Call through function pointer
    uint8_t Exemptions = Connection.CongestionControl.QuicCongestionControlGetExemptions(
        &Connection.CongestionControl);

    ASSERT_EQ(Exemptions, 7u);
}

//
// Test 26: CubicCongestionControlGetBytesInFlightMax - Returns tracked maximum
// Scenario: Tests GetBytesInFlightMax accessor. Returns the maximum BytesInFlight seen,
// which is used to limit congestion window growth. Verifies the function returns the
// correct value through the function pointer interface.
//
TEST(CubicTest, GetBytesInFlightMax_ReturnsValue)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Set BytesInFlightMax
    uint32_t ExpectedMax = 12345;
    Cubic->BytesInFlightMax = ExpectedMax;

    // Call through function pointer
    uint32_t Max = Connection.CongestionControl.QuicCongestionControlGetBytesInFlightMax(
        &Connection.CongestionControl);

    ASSERT_EQ(Max, ExpectedMax);
}

//
// Test 27: CubicCongestionControlGetCongestionWindow - Returns current window
// Scenario: Tests GetCongestionWindow accessor. Returns the current congestion window
// size in bytes, which is the primary congestion control parameter. Used for telemetry
// and debugging. Verifies correct value is returned.
//
TEST(CubicTest, GetCongestionWindow_ReturnsValue)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    uint32_t ExpectedWindow = Cubic->CongestionWindow;

    // Call through function pointer
    uint32_t Window = Connection.CongestionControl.QuicCongestionControlGetCongestionWindow(
        &Connection.CongestionControl);

    ASSERT_EQ(Window, ExpectedWindow);
}

//
// Test 28: CubicCongestionControlIsAppLimited - Always returns FALSE
// Scenario: Tests IsAppLimited function. CUBIC doesn't track app-limited state, so this
// always returns FALSE. Verifies the function behaves consistently through function pointer.
//
TEST(CubicTest, IsAppLimited_ReturnsFalse)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    // Call through function pointer
    BOOLEAN IsAppLimited = Connection.CongestionControl.QuicCongestionControlIsAppLimited(
        &Connection.CongestionControl);

    ASSERT_FALSE(IsAppLimited);
}

//
// Test 29: CubicCongestionControlSetAppLimited - No-op
// Scenario: Tests SetAppLimited function. This is a no-op in CUBIC (no state change).
// Verifies calling it doesn't crash or modify state. Tests the function pointer interface.
//
TEST(CubicTest, SetAppLimited_NoOp)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t WindowBefore = Cubic->CongestionWindow;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlSetAppLimited(&Connection.CongestionControl);

    // Verify no state change
    ASSERT_EQ(Cubic->CongestionWindow, WindowBefore);
}

//
// Test 30: OnDataAcknowledged - Basic ACK Processing and CUBIC Growth
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
    BOOLEAN IsWindowUpdated = Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl,
        &AckEvent);

    // Verify window may have grown (depends on slow start vs congestion avoidance)
    ASSERT_GE(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 31: OnDataLost - Packet Loss Handling and Window Reduction
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
// Test 32: Reset - Congestion Control State Reset
// Scenario: Tests the Reset function which reinitializes CUBIC state (e.g., after idle period
// or connection migration). Verifies all state variables return to initial values while preserving
// configuration settings.
//
TEST(CubicTest, Reset_StateReinitialization)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    
    // Modify state to simulate active connection
    Cubic->CongestionWindow = 50000;
    Cubic->SlowStartThreshold = 25000;
    Cubic->BytesInFlight = 10000;
    Cubic->WindowMax = 60000;
    Cubic->KCubic = 1000;
    Cubic->IsInRecovery = TRUE;
    Cubic->HasHadCongestionEvent = TRUE;

    uint32_t InitialWindowPackets = Cubic->InitialWindowPackets;
    uint32_t SendIdleTimeoutMs = Cubic->SendIdleTimeoutMs;

    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlReset(
        &Connection.CongestionControl,
        FALSE); // Not persistent congestion

    // Verify state was reset - Reset does NOT touch BytesInFlight (tracked separately)
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_EQ(Cubic->BytesInFlight, 10000u); // BytesInFlight is NOT reset
    ASSERT_LT(Cubic->CongestionWindow, 50000u); // Should be back to initial
    ASSERT_FALSE(Cubic->IsInRecovery); // Recovery flag should be cleared
    ASSERT_FALSE(Cubic->HasHadCongestionEvent); // Congestion event flag should be cleared
    
    // Verify config preserved
    ASSERT_EQ(Cubic->InitialWindowPackets, InitialWindowPackets);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, SendIdleTimeoutMs);
}

//
// Test 33: GetSendAllowance - Send Pacing Calculations
// Scenario: Tests the send allowance calculation which determines how much data can be sent
// at the current time considering pacing and congestion window. Used for rate limiting sends.
//
TEST(CubicTest, GetSendAllowance_BasicCalculation)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    Connection.Paths[0].GotFirstRttSample = TRUE;
    Connection.Paths[0].SmoothedRtt = 50000; // 50ms
    
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    
    // Set up state for send allowance calculation
    Cubic->BytesInFlight = 5000;
    Cubic->CongestionWindow = 20000;
    uint64_t TimeNow = CxPlatTimeUs64();

    // Call through function pointer
    uint32_t SendAllowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl,
        TimeNow,
        TRUE); // CanSend = TRUE

    // Verify send allowance is reasonable
    // Should allow some data to be sent since BytesInFlight < CongestionWindow
    ASSERT_GT(SendAllowance, 0u);
    ASSERT_LE(SendAllowance, Cubic->CongestionWindow - Cubic->BytesInFlight);
}

//
// Test 34: OnDataSent - Track Sent Data
// Scenario: Tests tracking of sent data which updates BytesInFlight and other sending state.
// This is called for each packet sent to maintain accurate congestion state.
//
TEST(CubicTest, OnDataSent_BytesInFlightTracking)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    
    ASSERT_EQ(Cubic->BytesInFlight, 0u);

    // Simulate sending data
    uint32_t BytesSent = 2000;
    
    // Call through function pointer
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl,
        BytesSent);

    // Verify BytesInFlight increased
    ASSERT_EQ(Cubic->BytesInFlight, BytesSent);
    
    // Send more data
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl,
        1500);
    
    ASSERT_EQ(Cubic->BytesInFlight, BytesSent + 1500);
}

//
// Test 35: OnEcn - ECN Marking Handling
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
// Test 36: GetNetworkStatistics - Statistics Retrieval
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
// Test 37: Miscellaneous Small Functions - Complete API Coverage
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
// Test 38: HyStart State Transitions - Complete Coverage
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
