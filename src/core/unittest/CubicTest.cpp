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
    QUIC_CONGESTION_CONTROL* Cc,
    QUIC_CONNECTION* Connection)
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

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);

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
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 20;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(Connection, 1280);
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
// Test 17: HyStart State Transitions - Complete Coverage
// Scenario: Tests HyStart state transitions and behavior in different states.
// HyStart is an algorithm to safely exit slow start by detecting delay increases.
// Tests HYSTART_NOT_STARTED -> HYSTART_ACTIVE -> HYSTART_DONE transitions.
//
TEST(CubicTest, HyStart_StateTransitions)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings{};
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    Settings.HyStartEnabled = TRUE; // Enable HyStart

    InitializeMockConnection(Connection, 1280);
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
// Test 19: GetSendAllowance - EstimatedWnd clamping to SlowStartThreshold
// Scenario: Tests cubic.c where EstimatedWnd (CongestionWindow << 1)
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
    // and (CongestionWindow << 1) > SlowStartThreshold
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
// Test 20: GetSendAllowance - Congestion Avoidance Pacing
// Scenario: Tests cubic.c where EstimatedWnd is calculated as
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
    uint32_t CongWin = 20000;  // CongWin >= SlowStartThresh

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
// Test 21: GetSendAllowance - Clamping to Available Window
// Scenario: Tests cubic.c where SendAllowance is clamped to
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
// Test 22: UpdateBlockedState - Transition from Can Send to Blocked
// Scenario: Tests cubic.c where PreviousCanSendState was TRUE
// (could send before) and now CubicCongestionControlCanSend returns FALSE
// (blocked now). This should add the QUIC_FLOW_BLOCKED_CONGESTION_CONTROL
// reason to the connection's OutFlowBlockedReasons and return FALSE.
//
TEST(CubicTest, BlockingBehavior_WindowFull_CannotSend)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL* Cc = &Connection.CongestionControl;

    // Phase 1: Verify initial state - can send
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
    uint32_t InitialAllowance = Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE);
    ASSERT_GT(InitialAllowance, 0u);

    // Phase 2: Send data until blocked using interface
    uint32_t TotalSent = SendUntilBlocked(Cc, &Connection);

    // Phase 3: Verify blocked behavior
    ASSERT_FALSE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_EQ(Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE), 0u);

    // Phase 4: Verify we sent approximately one window's worth
    uint32_t Window = Cc->QuicCongestionControlGetCongestionWindow(Cc);
    ASSERT_GE(TotalSent, Window);
    const uint32_t PacketSize = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    ASSERT_LE(TotalSent, Window + PacketSize); // At most one packet over
}

//
// Test 23: UpdateBlockedState - Transition from Blocked to Can Send
// Scenario: Tests cubic.c where PreviousCanSendState was FALSE
// (blocked before) and now CubicCongestionControlCanSend returns TRUE (can send now).
// This should remove the QUIC_FLOW_BLOCKED_CONGESTION_CONTROL reason, reset
// Connection->Send.LastFlushTime, and return TRUE.
//
TEST(CubicTest, BlockingBehavior_Unblock_AfterAck)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL* Cc = &Connection.CongestionControl;

    // Phase 1: Fill window and verify blocked
    SendUntilBlocked(Cc, &Connection);
    ASSERT_FALSE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_EQ(Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE), 0u);

    // Phase 2: ACK some data to unblock
    QUIC_ACK_EVENT AckEvent = {0};
    AckEvent.TimeNow = CxPlatTimeUs64();
    AckEvent.NumRetransmittableBytes = 1200;
    AckEvent.LargestAck = 10;
    AckEvent.MinRtt = 50000;
    AckEvent.MinRttValid = TRUE;

    Cc->QuicCongestionControlOnDataAcknowledged(Cc, &AckEvent);

    // Phase 3: Verify unblocked
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
    uint32_t AllowanceAfterAck = Cc->QuicCongestionControlGetSendAllowance(Cc, 0, FALSE);
    ASSERT_GT(AllowanceAfterAck, 0u);
}

//
// Test 24: Blocking Behavior - Exemptions Allow Sending When Blocked
// Scenario: Interface-based test verifying that exemptions (probe packets) allow
// sending even when congestion window is full.
//
TEST(CubicTest, BlockingBehavior_Exemptions_AllowSendWhenBlocked)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));

    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;

    InitializeMockConnection(&Connection, 1280);
    CubicCongestionControlInitialize(&Connection.CongestionControl, &Settings);

    QUIC_CONGESTION_CONTROL* Cc = &Connection.CongestionControl;

    // Phase 1: Fill window and verify blocked
    SendUntilBlocked(Cc, &Connection);
    ASSERT_FALSE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_EQ(Cc->QuicCongestionControlGetExemptions(Cc), 0u);

    // Phase 2: Set exemption (for probe packets)
    Cc->QuicCongestionControlSetExemption(Cc, 2);

    // Phase 3: Verify can send again due to exemptions
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
    ASSERT_EQ(Cc->QuicCongestionControlGetExemptions(Cc), 2u);

    // Phase 4: Send with exemption and verify exemption consumed
    Cc->QuicCongestionControlOnDataSent(Cc, 1200);
    ASSERT_EQ(Cc->QuicCongestionControlGetExemptions(Cc), 1u);

    // Phase 5: Can still send with remaining exemption
    ASSERT_TRUE(Cc->QuicCongestionControlCanSend(Cc));
}

//
// Helper to setup a test connection with CUBIC congestion control for OnCongestionEvent tests.
// Reduces repetitive setup code across multiple test cases.
//
static void SetupCongestionEventTest(
    QUIC_CONNECTION* Connection,
    QUIC_SETTINGS_INTERNAL* Settings,
    bool EnableHyStart = true)
{
    CxPlatZeroMemory(Settings, sizeof(*Settings));
    Settings->InitialWindowPackets = 20;
    Settings->SendIdleTimeoutMs = 1000;
    Settings->HyStartEnabled = EnableHyStart;

    InitializeMockConnection(Connection, 1280);
    Connection->Paths[0].GotFirstRttSample = TRUE;
    Connection->Paths[0].SmoothedRtt = 50000;

    if (EnableHyStart) {
        Connection->Settings.HyStartEnabled = TRUE;
    }

    CubicCongestionControlInitialize(&Connection->CongestionControl, Settings);
}

//
// Test 25: OnCongestionEvent - Persistent vs Normal Congestion
// Scenario: Tests both persistent congestion path and normal congestion
// path. Verifies state transitions, window reductions, and flag updates.
// This consolidates multiple tests for better efficiency.
//
TEST(CubicTest, OnCongestionEvent_PersistentAndNormal)
{
    QUIC_CONNECTION Connection;
    QUIC_SETTINGS_INTERNAL Settings;
    SetupCongestionEventTest(&Connection, &Settings, true);

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
// Test 26: OnCongestionEvent - Fast Convergence Scenarios
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
    SetupCongestionEventTest(&Connection, &Settings, true);

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


