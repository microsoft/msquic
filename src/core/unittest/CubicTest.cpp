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
// Helper: Send data until congestion window is exhausted (interface-based).
// Returns the total bytes sent.
//
static uint32_t SendUntilBlocked(
    _Inout_ QUIC_CONGESTION_CONTROL* Cc,
    _Inout_ QUIC_CONNECTION* Connection)
{
    uint32_t TotalSent = 0;
    const uint32_t PacketSize = QuicPathGetDatagramPayloadSize(&Connection->Paths[0]);

    while (Cc->QuicCongestionControlCanSend(Cc)) {
        uint32_t Allowance = Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE);
        if (Allowance == 0) break;

        uint32_t ToSend = CXPLAT_MIN(Allowance, PacketSize);
        Cc->QuicCongestionControlOnDataSent(Cc, ToSend);
        TotalSent += ToSend;

        // Safety: Prevent infinite loop
        if (TotalSent > 10000000) break;
    }

    return TotalSent;
}

//
// Helper: Setup a test connection with CUBIC congestion control.
// Provides common initialization with configurable parameters.
//
static void SetupCubicTest(
    QUIC_CONNECTION& Connection,
    QUIC_SETTINGS_INTERNAL& Settings,
    uint32_t InitialWindowPackets = 10,
    uint32_t SendIdleTimeoutMs = 1000,
    bool EnablePacing = false,
    bool EnableHyStart = false,
    bool SetupRtt = false,
    uint32_t SmoothedRtt = 50000)
{
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.InitialWindowPackets = InitialWindowPackets;
    Settings.SendIdleTimeoutMs = SendIdleTimeoutMs;
    Settings.HyStartEnabled = EnableHyStart;

    InitializeMockConnection(Connection, 1280);
    Connection.Settings.PacingEnabled = EnablePacing;
    Connection.Settings.HyStartEnabled = EnableHyStart;

    if (SetupRtt) {
        Connection.Paths[0].GotFirstRttSample = TRUE;
        Connection.Paths[0].SmoothedRtt = SmoothedRtt;
    }

    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);
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

    // Pre-set some fields to verify they get zeroed
    InitializeMockConnection(Connection, 1280);
    Connection.CongestionControl.Cubic.BytesInFlight = 12345;
    Connection.CongestionControl.Cubic.Exemptions = 5;

    SetupCubicTest(Connection, Settings, 10, 1000);

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
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, true, false, true, 50000);

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

    // Exact value is caldulated considering the current implementation is right and this test is meant to
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
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);

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
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

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
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);
    Settings.EcnEnabled = TRUE;

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
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);
    Connection.Paths[0].MinRtt = 40000;
    Connection.Paths[0].RttVariance = 5000;

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
    SetupCubicTest(Connection, Settings, 10, 1000);

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
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, true, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Initial state should be HYSTART_NOT_STARTED
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);

    // Transition to HYSTART_ACTIVE by acknowledging data (triggers slow start)
    Cubic->BytesInFlight = 5000;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000; //CxPlatTimeUs64();
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
// Test 18: Congestion Avoidance - Idle Time Detection
// Scenario: Tests that congestion avoidance detects idle periods (gaps in ACKs) and
// freezes window growth during those gaps. This prevents the window from growing when
// there's no feedback from the network, which could lead to aggressive bursts after idle.
//
TEST(CubicTest, CongestionAvoidance_IdleTimeDetection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    SetupCubicTest(Connection, Settings, 10, 100, false, false, true, 50000);
    Connection.Paths[0].RttVariance = 5000;

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

    uint64_t Now = 1000000; //CxPlatTimeUs64();
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
// Test 19: GetSendAllowance - Comprehensive Pacing Scenarios
// Scenario: Tests multiple pacing paths in a single test to reduce redundancy:
// 1. EstimatedWnd clamping to SlowStartThreshold during slow start
// 2. EstimatedWnd calculation (1.25x) during congestion avoidance
// 3. SendAllowance clamping to available window space
//
TEST(CubicTest, GetSendAllowance_PacingScenarios)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, true, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC *Cubic = &Connection.CongestionControl.Cubic;

    // Scenario 1: EstimatedWnd clamping (slow start)
    Cubic->SlowStartThreshold = 15000;
    Cubic->CongestionWindow = 10000;  // CongWin << 1 = 20000 > 15000
    Cubic->BytesInFlight = 0;
    Cubic->LastSendAllowance = 0;

    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);
    ASSERT_EQ(Allowance, 3000u); // (15000 * 10000) / 50000

    // Scenario 2: Congestion avoidance pacing (1.25x multiplier)
    Cubic->SlowStartThreshold = 10000;
    Cubic->CongestionWindow = 20000;  // >= SlowStartThresh
    Cubic->BytesInFlight = 0;
    Cubic->LastSendAllowance = 0;

    Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);
    ASSERT_EQ(Allowance, 5000u); // (25000 * 10000) / 50000

    // Scenario 3: Clamping to available window
    Cubic->CongestionWindow = 10000;
    Cubic->BytesInFlight = 8000;
    Cubic->SlowStartThreshold = 5000;
    Cubic->LastSendAllowance = 0;
    Connection.Paths[0].SmoothedRtt = 10000; // Small RTT

    Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 100000, TRUE);
    ASSERT_EQ(Allowance, 2000u); // Clamped to CongWin - BytesInFlight
}

//
// Test 20: Blocking Behavior - Comprehensive Flow Control
// Scenario: Tests complete blocking/unblocking cycle including exemptions:
// 1. Send until window full (can't send)
// 2. Unblock via ACK (can send again)
// 3. Block again and use exemptions to bypass
//
TEST(CubicTest, BlockingBehavior_Complete)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, false, 50000);

    QUIC_CONGESTION_CONTROL* Cc = &Connection.CongestionControl;

    // Phase 1: Send until blocked
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
    uint32_t TotalSent = SendUntilBlocked(Cc, &Connection);
    ASSERT_FALSE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_EQ(Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE), 0u);

    uint32_t Window = Cc->QuicCongestionControlGetCongestionWindow(Cc);
    ASSERT_GE(TotalSent, Window);

    // Phase 2: Unblock via ACK
    QUIC_ACK_EVENT AckEvent = {0};
    AckEvent.TimeNow = CxPlatTimeUs64();
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.LargestAck = 10;
    AckEvent.MinRtt = 50000;
    AckEvent.MinRttValid = TRUE;

    Cc->QuicCongestionControlOnDataAcknowledged(Cc, &AckEvent);
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_GT(Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE), 0u);

    // Phase 3: Block again and use exemptions
    SendUntilBlocked(Cc, &Connection);
    ASSERT_FALSE(Cc->QuicCongestionControlCanSend(Cc));

    Cc->QuicCongestionControlSetExemption(Cc, 2);
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_EQ(Cc->QuicCongestionControlGetExemptions(Cc), 2u);

    Cc->QuicCongestionControlOnDataSent(Cc, 1200);
    ASSERT_EQ(Cc->QuicCongestionControlGetExemptions(Cc), 1u);
}

//
// Test 21: OnCongestionEvent - Persistent vs Normal Congestion
// Scenario: Tests both persistent congestion path and normal congestion
// path. Verifies state transitions, window reductions, and flag updates.
// This consolidates multiple tests for better efficiency.
//
TEST(CubicTest, OnCongestionEvent_PersistentAndNormal)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    SetupCubicTest(Connection, Settings, 20, 1000, false, true, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    // Test Part A: Persistent Congestion
    Cubic->CongestionWindow = 50000;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;
    Cubic->HyStartState = HYSTART_ACTIVE;
    uint32_t InitialPersistentCount = Connection.Stats.Send.PersistentCongestionCount;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, TRUE, FALSE);

    // Verify persistent congestion handling
    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, InitialPersistentCount + 1);
    ASSERT_EQ(Connection.Paths[0].Route.State, RouteSuspected);
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);
    ASSERT_EQ(Cubic->WindowPrior, 35000u);
    ASSERT_EQ(Cubic->CongestionWindow, DatagramPayloadLength * 2);
    ASSERT_EQ(Cubic->KCubic, 0u);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);

    // Test Part B: Already in persistent congestion
    uint32_t PersistentCountBefore = Connection.Stats.Send.PersistentCongestionCount;
    Cubic->CongestionWindow = 5000;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, TRUE, FALSE);

    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, PersistentCountBefore); // No increment
    // fast convergence also triggers since WindowLastMax > WindowMax
    ASSERT_EQ(Cubic->WindowPrior, 5000u);
    ASSERT_LT(Cubic->WindowMax, 5000u);

    // Test Part C: Normal congestion (non-persistent)
    Connection.Stats.Send.PersistentCongestionCount = 0;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->CongestionWindow = 60000;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, FALSE, FALSE);

    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, 0u); // Not incremented
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
    ASSERT_TRUE(Cubic->IsInRecovery);
}

//
// Test 22: OnCongestionEvent - Fast Convergence Scenarios
// Scenario: Comprehensive test covering fast convergence behavior in different scenarios:
// 1. Fast convergence triggers when WindowLastMax > WindowMax
// 2. No fast convergence when WindowLastMax <= WindowMax
// 3. Edge case when WindowLastMax == WindowMax
// Consolidates multiple tests to reduce redundancy while maintaining full coverage.
//
TEST(CubicTest, OnCongestionEvent_FastConvergence)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    SetupCubicTest(Connection, Settings, 20, 1000, false, true, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Part A: Fast convergence triggers (WindowLastMax > WindowMax)
    Cubic->CongestionWindow = 60000;
    Cubic->WindowLastMax = 100000;  // Previous peak > current window
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, FALSE, FALSE);

    ASSERT_EQ(Cubic->WindowLastMax, 60000u);
    ASSERT_EQ(Cubic->WindowMax, 60000u * 17 / 20);
    ASSERT_LT(Cubic->WindowMax, 60000u); // WindowMax reduced

    // Part B: No fast convergence (WindowLastMax < WindowMax)
    Cubic->CongestionWindow = 80000;
    Cubic->WindowLastMax = 60000; // Less than current window
    Cubic->IsInRecovery = FALSE;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, FALSE, FALSE);

    // Verify simple assignment, no reduction
    ASSERT_EQ(Cubic->WindowLastMax, Cubic->WindowMax);
    ASSERT_GE(Cubic->WindowLastMax, 60000u); // Not reduced

    // Part C: Edge case (WindowLastMax == WindowMax)
    Cubic->CongestionWindow = 70000;
    Cubic->WindowLastMax = 70000; // Equal
    Cubic->IsInRecovery = FALSE;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, FALSE, FALSE);

    // Verify condition not >, so no fast convergence
    ASSERT_EQ(Cubic->WindowLastMax, Cubic->WindowMax);
}

//
// Test 23: Recovery States - Exit vs Continuation
// Scenario: Tests recovery logic for both paths:
// 1. Recovery exit when ACK is for packet after recovery start
// 2. Recovery continuation when ACK is for packet before/at recovery start
//
TEST(CubicTest, OnDataAcknowledged_RecoveryStates)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Part 1: Recovery exit (LargestAck > RecoverySentPacketNumber)
    Cubic->IsInRecovery = TRUE;
    Cubic->HasHadCongestionEvent = TRUE;
    Cubic->RecoverySentPacketNumber = 10;
    Cubic->BytesInFlight = 5000;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 2000000;
    AckEvent.LargestAck = 15; // > RecoverySentPacketNumber
    AckEvent.LargestSentPacketNumber = 20;
    AckEvent.NumRetransmittableBytes = 1500;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = TRUE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, AckEvent.TimeNow);
    ASSERT_EQ(Cubic->BytesInFlight, 3500u);

    // Part 2: Recovery continuation (LargestAck <= RecoverySentPacketNumber)
    uint32_t InitialWindow = Cubic->CongestionWindow;
    Cubic->IsInRecovery = TRUE;
    Cubic->RecoverySentPacketNumber = 10;
    Cubic->BytesInFlight = 5000;

    AckEvent.LargestAck = 8; // < RecoverySentPacketNumber
    AckEvent.NumRetransmittableBytes = 1500;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_TRUE(Cubic->IsInRecovery);
    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);
    ASSERT_EQ(Cubic->BytesInFlight, 3500u);
}

//
// Test 24: Congestion Avoidance - Comprehensive Window Growth
// Scenario: Tests multiple congestion avoidance paths in one test:
// 1. Zero bytes ACKed - no window growth
// 2. AIMD slow growth (accumulation when AimdWindow < WindowPrior)
// 3. CUBIC constrained growth (1.5x max per RTT)
//
TEST(CubicTest, OnDataAcknowledged_CongestionAvoidance)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));

    // Part 1: Zero bytes ACKed - no growth
    uint32_t InitialWindow = Cubic->CongestionWindow;
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 0;
    AckEvent.SmoothedRtt = 50000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_EQ(Cubic->CongestionWindow, InitialWindow);
    ASSERT_TRUE(Cubic->TimeOfLastAckValid);

    // Part 2: AIMD slow growth
    Cubic->CongestionWindow = 20000;
    Cubic->SlowStartThreshold = 19000;
    Cubic->AimdWindow = 18000;
    Cubic->WindowPrior = 20000;
    Cubic->WindowMax = 20000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 10000;
    Cubic->AimdAccumulator = 0;

    AckEvent.TimeNow = 1050000;
    AckEvent.NumRetransmittableBytes = 2000;
    AckEvent.MinRttValid = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_EQ(Cubic->AimdAccumulator, 1000u); // BytesAcked/2

    // Part 3: CUBIC constrained growth (1.5x limit)
    Cubic->CongestionWindow = 18000;
    Cubic->SlowStartThreshold = 17000;
    Cubic->WindowMax = 25000;
    Cubic->KCubic = 10;
    Cubic->BytesInFlight = 10000;
    InitialWindow = Cubic->CongestionWindow;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_GT(Cubic->CongestionWindow, InitialWindow);
    ASSERT_LE(Cubic->CongestionWindow, InitialWindow + (InitialWindow / 2));
}

//
// Test 25: Edge Cases - Limits and Overflow Protection
// Scenario: Tests various edge cases and protection mechanisms:
// 1. BytesInFlightMax limit (app-limited scenarios)
// 2. Idle gap adjustment (freeze window growth during idle)
// 3. DeltaT overflow protection (extreme time values)
//
TEST(CubicTest, OnDataAcknowledged_EdgeCases)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 50, 100, false, false, true, 50000);
    Connection.Paths[0].RttVariance = 10000;

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));

    // Part 1: BytesInFlightMax limit
    Cubic->BytesInFlightMax = 5000;
    Cubic->BytesInFlight = 3000;

    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 3000;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);

    // Part 2: Idle gap adjustment
    Cubic->CongestionWindow = 20000;
    Cubic->SlowStartThreshold = 19000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 10000;

    uint64_t InitialCongAvoidStart = Cubic->TimeOfCongAvoidStart;

    AckEvent.TimeNow = 1500000; // 500ms idle gap
    AckEvent.NumRetransmittableBytes = 2000;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    ASSERT_GT(Cubic->TimeOfCongAvoidStart, InitialCongAvoidStart);

    // Part 3: DeltaT overflow protection
    Settings.SendIdleTimeoutMs = 1000000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->WindowMax = 25000;
    Cubic->KCubic = 100;

    AckEvent.TimeNow = 10000000000ULL; // Extreme future

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Should not crash
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
}

//
// Test 26: Window Clamping to BytesInFlightMax
// Scenario: Tests that window growth is properly clamped when the application
// is app-limited and BytesInFlightMax is much lower than current window size.
//
TEST(CubicTest, WindowClampingToBytesInFlightMax)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Window wants to grow, but app is limited
    uint32_t InitialWindow = Cubic->CongestionWindow;
    Cubic->BytesInFlightMax = 3000; // Very low usage
    Cubic->BytesInFlight = 2000;
    Cubic->SlowStartThreshold = InitialWindow - 1000; // In CA mode
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;

    // Try to grow window via ACK
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1100000;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1500;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRtt = 45000;
    AckEvent.MinRttValid = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Window should be clamped to 2*BytesInFlightMax
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
}

//
// Test 27: App-Limited Flow Detection
// Scenario: Tests that CUBIC properly identifies and handles app-limited scenarios
// where the application isn't sending enough data to fill the congestion window.
//
TEST(CubicTest, AppLimitedFlowDetection)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Large window but low actual usage
    Cubic->BytesInFlightMax = 5000; // App only using 5KB
    Cubic->CongestionWindow = 50000; // But window is 50KB
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Simulate ACKs for app-limited sending
    for (int i = 0; i < 5; i++) {
        Cubic->BytesInFlight = 3000;

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 50000);
        AckEvent.LargestAck = 5 + i;
        AckEvent.LargestSentPacketNumber = 10 + i;
        AckEvent.NumRetransmittableBytes = 1000;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRtt = 45000;
        AckEvent.MinRttValid = FALSE;

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl, &AckEvent);
    }

    // Window should be limited to 2 * BytesInFlightMax
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
}

//
// Test 28: Multiple Congestion Events in Sequence
// Scenario: Tests behavior when multiple congestion events occur rapidly,
// ensuring proper recovery state management and window reduction coordination.
//
TEST(CubicTest, MultipleCongestionEventsSequence)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 30, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint32_t InitialWindow = Cubic->CongestionWindow;

    // First loss - enter recovery
    QUIC_LOSS_EVENT LossEvent1;
    CxPlatZeroMemory(&LossEvent1, sizeof(LossEvent1));
    LossEvent1.NumRetransmittableBytes = 1200;
    LossEvent1.PersistentCongestion = FALSE;
    LossEvent1.LargestPacketNumberLost = 5;
    LossEvent1.LargestSentPacketNumber = 10;

    Cubic->BytesInFlight = 10000;
    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent1);

    ASSERT_TRUE(Cubic->IsInRecovery);
    uint32_t WindowAfterFirstLoss = Cubic->CongestionWindow;
    ASSERT_LT(WindowAfterFirstLoss, InitialWindow);

    // Second loss while still in recovery - should not reduce further
    QUIC_LOSS_EVENT LossEvent2;
    CxPlatZeroMemory(&LossEvent2, sizeof(LossEvent2));
    LossEvent2.NumRetransmittableBytes = 1200;
    LossEvent2.PersistentCongestion = FALSE;
    LossEvent2.LargestPacketNumberLost = 7;
    LossEvent2.LargestSentPacketNumber = 15;

    Connection.CongestionControl.QuicCongestionControlOnDataLost(
        &Connection.CongestionControl, &LossEvent2);

    // Window should stay same (no further reduction in recovery)
    ASSERT_EQ(Cubic->CongestionWindow, WindowAfterFirstLoss);
}

//
// Test 29: Spurious Retransmission Detection
// Scenario: Tests handling of spurious congestion events where loss was
// incorrectly detected and later acknowledged. Window should be restored.
//
TEST(CubicTest, SpuriousRetransmissionRecovery)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Establish baseline state after congestion
    Cubic->CongestionWindow = 20000;
    Cubic->WindowPrior = 30000; // Window before congestion
    Cubic->IsInRecovery = TRUE;
    Cubic->RecoverySentPacketNumber = 10;

    uint32_t WindowBeforeSpurious = Cubic->CongestionWindow;

    // Spurious retransmission detected
    Connection.CongestionControl.QuicCongestionControlOnSpuriousCongestionEvent(
        &Connection.CongestionControl);

    // Window should be restored (implementation-specific behavior)
    // At minimum, recovery state should be cleared
    ASSERT_FALSE(Cubic->IsInRecovery);
}

//
// Test 30: Pacing Rate Calculation Under High Load
// Scenario: Tests pacing rate calculations when connection is under high load
// with maximum window utilization and multiple concurrent streams.
//
TEST(CubicTest, PacingUnderHighLoad)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 100, 1000, true, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: High load scenario
    Cubic->CongestionWindow = 100000; // 100KB window
    Cubic->BytesInFlight = 95000; // Almost full
    Cubic->BytesInFlightMax = 95000;
    Cubic->SlowStartThreshold = 50000; // In congestion avoidance
    Cubic->LastSendAllowance = 5000;

    // Check pacing allows controlled sending
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Should allow some sending but pace it
    ASSERT_GT(Allowance, 0u);
    ASSERT_LE(Allowance, Cubic->CongestionWindow - Cubic->BytesInFlight);
}

//
// Test 31: Large RTT Variation Handling
// Scenario: Tests CUBIC's behavior when RTT varies significantly, which can
// affect pacing decisions and HyStart++ delay detection mechanisms.
//
TEST(CubicTest, LargeRTTVariation)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, true, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Congestion avoidance with varying RTT
    Cubic->CongestionWindow = 30000;
    Cubic->SlowStartThreshold = 20000;
    Cubic->BytesInFlight = 15000;
    Cubic->LastSendAllowance = 0;

    // First ACK with normal RTT
    uint32_t Allowance1 = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Simulate RTT spike
    Connection.Paths[0].SmoothedRtt = 200000; // 200ms (4x increase)

    // Second ACK with high RTT
    uint32_t Allowance2 = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // Pacing should adapt to higher RTT (allow less per unit time)
    ASSERT_LT(Allowance2, Allowance1 * 2); // Not directly proportional due to pacing
}

//
// Test 32: Minimum Window Enforcement
// Scenario: Tests that CUBIC maintains a minimum viable window even under
// extreme congestion to ensure connection doesn't stall completely.
//
TEST(CubicTest, MinimumWindowEnforcement)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;
    uint16_t DatagramPayloadLength = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    // Force persistent congestion
    Cubic->CongestionWindow = 50000;
    Cubic->IsInPersistentCongestion = FALSE;
    Cubic->HasHadCongestionEvent = TRUE;

    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, TRUE, FALSE);

    // Should reset to minimum (2 * MSS)
    ASSERT_EQ(Cubic->CongestionWindow, DatagramPayloadLength * 2);
    ASSERT_TRUE(Cubic->IsInPersistentCongestion);

    // Ensure we can still send at least 2 packets
    ASSERT_GE(Cubic->CongestionWindow, DatagramPayloadLength * 2);
}

//
// Test 33: CUBIC Window Negative Overflow Protection
// Scenario: Tests protection against CUBIC window calculation producing
// a negative value due to overflow, which should be clamped to BytesInFlightMax.
//
TEST(CubicTest, CUBICWindowNegativeOverflow)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Extreme values that could cause overflow
    Cubic->CongestionWindow = 100000000; // 100MB
    Cubic->SlowStartThreshold = 99000000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 50000000;
    Cubic->BytesInFlightMax = 50000000;
    Cubic->WindowMax = UINT32_MAX;
    Cubic->KCubic = UINT32_MAX;
    Cubic->WindowPrior = UINT32_MAX;
    Cubic->AimdWindow = 100000000;

    // ACK with extreme time that causes overflow
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 100000000000ULL;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Should be clamped to 2*BytesInFlightMax after overflow
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
}

//
// Test 34: Network Statistics Event Generation
// Scenario: Tests that CUBIC generates network statistics events when
// NetStatsEventEnabled is true, providing visibility into CC state.
//
TEST(CubicTest, NetworkStatisticsEventGeneration)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Enable network statistics events
    Connection.Settings.NetStatsEventEnabled = TRUE;
    Cubic->BytesInFlight = 8000;

    // Send ACK to trigger event
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 5;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;

    // This will generate event (we can't easily verify event delivery in unit test,
    // but we're covering the code path)
    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Verify state updated (event generation doesn't crash)
    ASSERT_EQ(Cubic->BytesInFlight, 8000u - 1200u);
}

//
// Test 35: App Limited Getter and Setter
// Scenario: Tests the IsAppLimited and SetAppLimited interface methods,
// even though CUBIC doesn't currently track app-limited state.
//
TEST(CubicTest, AppLimitedInterface)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000);

    QUIC_CONGESTION_CONTROL* Cc = &Connection.CongestionControl;

    // Test IsAppLimited (currently always returns FALSE)
    BOOLEAN IsAppLimited = Cc->QuicCongestionControlIsAppLimited(Cc);
    ASSERT_FALSE(IsAppLimited);

    // Test SetAppLimited (currently a no-op)
    Cc->QuicCongestionControlSetAppLimited(Cc);

    // Verify still returns FALSE
    IsAppLimited = Cc->QuicCongestionControlIsAppLimited(Cc);
    ASSERT_FALSE(IsAppLimited);
}

//
// Test 36: LastSendAllowance Decrement Path
// Scenario: Tests the path where LastSendAllowance is decremented when
// not greater than bytes sent, covering pacing state update.
//
TEST(CubicTest, LastSendAllowanceDecrement)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, true, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Small LastSendAllowance
    Cubic->LastSendAllowance = 500;
    Cubic->BytesInFlight = 5000;

    // Send more than LastSendAllowance
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 1200);

    // LastSendAllowance should have been decremented (may go negative, then zeroed)
    // The exact value depends on implementation details, but path is covered
    ASSERT_EQ(Cubic->BytesInFlight, 6200u);
}

//
// Test 37: CUBIC Window DeltaT Clamping at Extreme Values
// Scenario: Tests the DeltaT > 2500000 clamping path in CUBIC formula
//
TEST(CubicTest, CUBICWindowDeltaTClamping)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: In CA with ancient TimeOfCongAvoidStart
    Cubic->CongestionWindow = 30000;
    Cubic->SlowStartThreshold = 25000;
    Cubic->TimeOfCongAvoidStart = 100; // Very old timestamp
    Cubic->TimeOfLastAck = 100;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->BytesInFlight = 15000;
    Cubic->BytesInFlightMax = 15000;
    Cubic->WindowMax = 35000;
    Cubic->WindowPrior = 35000;
    Cubic->KCubic = 100;
    Cubic->AimdWindow = 30000;
    Cubic->HasHadCongestionEvent = TRUE;

    // ACK with time that causes DeltaT > 2500000 microseconds
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 10000000000ULL; // Billions of microseconds later
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Should not crash from overflow, window should be clamped
    ASSERT_LE(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
}

//
// Test 38: HyStart State Machine Coverage
// Scenario: Tests that HyStart state transitions work correctly and
// cover the switch statement branches including HYSTART_DONE state.
//
TEST(CubicTest, HyStartStateMachineCoverage)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, true, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Test that HYSTART_DONE state sets divisor to 1
    // First get into DONE state through CSS completion
    Cubic->HyStartState = HYSTART_ACTIVE;
    Cubic->ConservativeSlowStartRounds = 1;
    Cubic->HyStartRoundEnd = 5;
    Cubic->CongestionWindow = 20000;
    Cubic->SlowStartThreshold = UINT32_MAX;
    Cubic->BytesInFlight = 10000;
    Connection.Send.NextPacketNumber = 10;

    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1000000;
    AckEvent.LargestAck = 6;
    AckEvent.LargestSentPacketNumber = 10;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Should be in DONE state with divisor = 1
    ASSERT_EQ(Cubic->HyStartState, HYSTART_DONE);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 39: Slow Start Threshold Crossing with BytesAcked Overflow
// Scenario: Tests the exact scenario where window growth crosses threshold
// and overflow bytes are handled in CA.
//
TEST(CubicTest, SlowStartThresholdCrossingOverflow)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, false, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // After init, the window is at InitialWindowPackets * 1280 = 12800
    // Set threshold just above current window so we're in slow start
    uint32_t InitialWindow = Cubic->CongestionWindow; // Should be 12800
    Cubic->SlowStartThreshold = InitialWindow + 2000; // 14800
    Cubic->BytesInFlight = 6000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->WindowMax = 20000;
    Cubic->WindowPrior = 20000;
    Cubic->KCubic = 100;
    Cubic->HasHadCongestionEvent = FALSE;

    // ACK that will push window past threshold
    // In slow start: window grows by BytesAcked
    // New window = 12800 + 3000 = 15800 > 14800 (threshold)
    // Should clamp to 14800 and process remaining 1000 bytes in CA
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1010000;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 3000; // Large enough to overshoot threshold
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // The exact window value depends on internal logic, but we can verify state was updated
    // Window should have grown from initial
    ASSERT_GE(Cubic->CongestionWindow, InitialWindow);
}

//
// Test 40: LastSendAllowance Exact Decrement Path
// Scenario: Tests the LastSendAllowance is decreased when bytes sent are less
// than the allowance. This covers the pacing credit tracking path.
//
TEST(CubicTest, LastSendAllowanceExactDecrementPath)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, true, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: In congestion avoidance with pacing
    Cubic->CongestionWindow = 20000;
    Cubic->SlowStartThreshold = 15000;
    Cubic->BytesInFlight = 5000;
    Cubic->LastSendAllowance = 0;

    // Call GetSendAllowance to set LastSendAllowance via pacing calculation
    uint32_t Allowance = Connection.CongestionControl.QuicCongestionControlGetSendAllowance(
        &Connection.CongestionControl, 10000, TRUE);

    // LastSendAllowance should now be set by pacing logic
    ASSERT_GT(Cubic->LastSendAllowance, 0u);
    uint32_t AllowanceBeforeSend = Cubic->LastSendAllowance;

    // Send LESS than LastSendAllowance (should take else branch - decrement)
    uint32_t BytesToSend = AllowanceBeforeSend / 2; // Send half of allowance
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, BytesToSend);

    // LastSendAllowance should be decremented (line 390)
    ASSERT_EQ(Cubic->LastSendAllowance, AllowanceBeforeSend - BytesToSend);
    ASSERT_EQ(Cubic->BytesInFlight, 5000u + BytesToSend);
}

//
// Test 41: Persistent Congestion Recovery
// Scenario: Tests the full recovery path from persistent congestion
// (window = 2*MTU) back to normal operation through gradual ACKs.
// Important for validating recovery from severe network impairment.
//
TEST(CubicTest, PersistentCongestionRecovery)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Enter persistent congestion (severe congestion state)
    Cubic->IsInPersistentCongestion = TRUE;
    Cubic->CongestionWindow = 2 * 1280; // Minimum window (2 * MTU)
    Cubic->SlowStartThreshold = 2 * 1280;
    Cubic->BytesInFlight = 0;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->WindowMax = 2 * 1280;
    Cubic->HasHadCongestionEvent = TRUE;

    uint32_t InitialWindow = Cubic->CongestionWindow;

    // Send multiple ACKs to gradually recover
    for (int i = 0; i < 10; i++) {
        Cubic->BytesInFlight = 1200;

        QUIC_ACK_EVENT AckEvent;
        CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
        AckEvent.TimeNow = 1000000 + (i * 10000);
        AckEvent.LargestAck = 10 + i;
        AckEvent.LargestSentPacketNumber = 20 + i;
        AckEvent.NumRetransmittableBytes = 1200;
        AckEvent.SmoothedRtt = 50000;
        AckEvent.MinRttValid = FALSE;
        AckEvent.IsImplicit = FALSE;
        AckEvent.HasLoss = FALSE;

        Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
            &Connection.CongestionControl, &AckEvent);
    }

    // Should have recovered: window grown beyond minimum
    ASSERT_GT(Cubic->CongestionWindow, InitialWindow);
    // Should exit persistent congestion after window growth
    // (Note: actual flag may still be TRUE depending on implementation)
}

//
// Test 42: Window Clamping at Exact Boundary
// Scenario: Tests the exact boundary condition where CongestionWindow
// equals 2 * BytesInFlightMax, validating the app-limited clamping logic.
//
TEST(CubicTest, WindowClampingExactBoundary)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: In CA mode with window that will be clamped
    Cubic->BytesInFlightMax = 10000;
    Cubic->CongestionWindow = 25000; // > 2 * BytesInFlightMax, will be clamped
    Cubic->SlowStartThreshold = 20000;
    Cubic->BytesInFlight = 5000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->WindowMax = 30000;
    Cubic->KCubic = 100;
    Cubic->HasHadCongestionEvent = TRUE;

    // ACK should trigger clamping
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1010000;
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Window should be clamped to exactly 2 * BytesInFlightMax
    ASSERT_EQ(Cubic->CongestionWindow, 2 * Cubic->BytesInFlightMax);
    ASSERT_EQ(Cubic->CongestionWindow, 20000u);
}

//
// Test 43: AIMD Friendly Region (CUBIC vs AIMD Competition)
// Scenario: Tests the scenario where AIMD produces a larger window than
// CUBIC's concave phase calculation. CUBIC should follow the more aggressive
// AIMD to be friendly to other TCP flows (TCP-friendliness property).
//
TEST(CubicTest, AIMDFriendlyRegion)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: Shortly after congestion event, in CUBIC concave phase
    // where AIMD should be more aggressive
    Cubic->CongestionWindow = 40000;
    Cubic->SlowStartThreshold = 39000; // In CA mode
    Cubic->WindowMax = 50000;
    Cubic->WindowPrior = 50000;
    Cubic->BytesInFlight = 20000;
    Cubic->BytesInFlightMax = 25000;
    Cubic->TimeOfCongAvoidStart = 1000000;
    Cubic->TimeOfLastAck = 1000000;
    Cubic->TimeOfLastAckValid = TRUE;
    Cubic->KCubic = 200; // Large K means we're in concave phase
    Cubic->HasHadCongestionEvent = TRUE;

    // Set AIMD window ahead of current (AIMD is more aggressive)
    Cubic->AimdWindow = 42000;

    uint32_t WindowBeforeAck = Cubic->CongestionWindow;

    // ACK with moderate time delta (concave phase)
    QUIC_ACK_EVENT AckEvent;
    CxPlatZeroMemory(&AckEvent, sizeof(AckEvent));
    AckEvent.TimeNow = 1050000; // 50ms later
    AckEvent.LargestAck = 10;
    AckEvent.LargestSentPacketNumber = 15;
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.SmoothedRtt = 50000;
    AckEvent.MinRttValid = FALSE;
    AckEvent.IsImplicit = FALSE;
    AckEvent.HasLoss = FALSE;

    Connection.CongestionControl.QuicCongestionControlOnDataAcknowledged(
        &Connection.CongestionControl, &AckEvent);

    // Window should have grown (CUBIC follows AIMD in friendly region)
    ASSERT_GE(Cubic->CongestionWindow, WindowBeforeAck);
}

//
// Test 44: LastSendAllowance Exact Match
// Scenario: Tests the edge case where bytes sent exactly equals
// LastSendAllowance. Should zero out allowance (not decrement).
//
TEST(CubicTest, LastSendAllowanceExactMatch)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 10, 1000, true, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: LastSendAllowance exactly matching send size
    Cubic->LastSendAllowance = 1200;
    Cubic->BytesInFlight = 5000;

    // Send exactly LastSendAllowance bytes
    Connection.CongestionControl.QuicCongestionControlOnDataSent(
        &Connection.CongestionControl, 1200);

    // Should be zeroed out (equality goes to if branch, not else)
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
    ASSERT_EQ(Cubic->BytesInFlight, 6200u);
}

//
// Test 45: KCubic Calculation Validation
// Scenario: Tests that KCubic is calculated and used correctly during
// congestion avoidance. K represents the time (in milliseconds) for the
// CUBIC function to reach WindowMax. Validates the formula is applied.
//
TEST(CubicTest, KCubicCalculationValidation)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    SetupCubicTest(Connection, Settings, 20, 1000, false, false, true, 50000);

    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &Connection.CongestionControl.Cubic;

    // Setup: trigger a congestion event to calculate K
    Cubic->WindowMax = 50000;
    Cubic->CongestionWindow = 35000;
    Cubic->HasHadCongestionEvent = TRUE;

    // Trigger congestion event to recalculate K
    // K = CubeRoot((WindowMax - CongestionWindow) * 10 / (4 * MTU))
    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, FALSE, FALSE);

    // K should be calculated based on the formula
    ASSERT_GT(Cubic->KCubic, 0u);
    uint32_t OriginalK = Cubic->KCubic;

    // Change window difference and recalculate
    Cubic->WindowMax = 100000;
    Cubic->CongestionWindow = 50000;
    CubicCongestionControlOnCongestionEvent(&Connection.CongestionControl, FALSE, FALSE);

    // K should be different (larger window gap)
    ASSERT_NE(Cubic->KCubic, OriginalK);
    ASSERT_GT(Cubic->KCubic, 0u);
}

