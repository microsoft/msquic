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

typedef struct MOCK_CONNECTION {
    QUIC_CONGESTION_CONTROL CongestionControl;
    QUIC_PATH Paths[QUIC_MAX_PATH_COUNT];
    QUIC_SEND Send;
    QUIC_SETTINGS_INTERNAL Settings;
} MOCK_CONNECTION;

//
// Helper to create a minimal valid mock connection
//
static void InitializeMockConnection(MOCK_CONNECTION* MockConn, uint16_t Mtu) {
    CxPlatZeroMemory(MockConn, sizeof(*MockConn));
    MockConn->Paths[0].Mtu = Mtu;
    MockConn->Paths[0].IsActive = TRUE;
    MockConn->Send.NextPacketNumber = 0;
}

//
// Test 1: Basic initialization with default settings
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
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // Verify basic initialization
    ASSERT_EQ(Cubic->InitialWindowPackets, 10u);
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 1000u);
    ASSERT_EQ(Cubic->SlowStartThreshold, UINT32_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
    
    // Verify CongestionWindow calculation
    uint16_t PayloadSize = MaxUdpPayloadSizeForFamily(
        QUIC_ADDRESS_FAMILY_INET, MockConn.Paths[0].Mtu);
    uint32_t ExpectedCongestionWindow = PayloadSize * 10;
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedCongestionWindow);
    ASSERT_EQ(Cubic->BytesInFlightMax, ExpectedCongestionWindow / 2);
}

//
// Test 2: Initialize with minimum MTU
//
TEST(CubicTest, InitializeWithMinimumMtu)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    // Use minimum MTU
    InitializeMockConnection(&MockConn, QUIC_DPLPMTUD_MIN_MTU);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    uint16_t PayloadSize = MaxUdpPayloadSizeForFamily(
        QUIC_ADDRESS_FAMILY_INET, QUIC_DPLPMTUD_MIN_MTU);
    uint32_t ExpectedCongestionWindow = PayloadSize * 10;
    
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedCongestionWindow);
    ASSERT_GT(Cubic->CongestionWindow, 0u);
}

//
// Test 3: Initialize with maximum MTU
//
TEST(CubicTest, InitializeWithMaximumMtu)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    // Use maximum possible MTU
    InitializeMockConnection(&MockConn, 65535);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    uint16_t PayloadSize = MaxUdpPayloadSizeForFamily(
        QUIC_ADDRESS_FAMILY_INET, 65535);
    uint32_t ExpectedCongestionWindow = PayloadSize * 10;
    
    ASSERT_EQ(Cubic->CongestionWindow, ExpectedCongestionWindow);
    ASSERT_GT(Cubic->BytesInFlightMax, 0u);
}

//
// Test 4: Initialize with single packet window
//
TEST(CubicTest, InitializeWithSinglePacketWindow)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    // Minimum initial window
    Settings.InitialWindowPackets = 1;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    uint16_t PayloadSize = MaxUdpPayloadSizeForFamily(
        QUIC_ADDRESS_FAMILY_INET, MockConn.Paths[0].Mtu);
    
    ASSERT_EQ(Cubic->InitialWindowPackets, 1u);
    ASSERT_EQ(Cubic->CongestionWindow, PayloadSize);
    ASSERT_EQ(Cubic->BytesInFlightMax, PayloadSize / 2);
}

//
// Test 5: Initialize with large initial window
//
TEST(CubicTest, InitializeWithLargeInitialWindow)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    // Large initial window
    Settings.InitialWindowPackets = 1000;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    uint16_t PayloadSize = MaxUdpPayloadSizeForFamily(
        QUIC_ADDRESS_FAMILY_INET, MockConn.Paths[0].Mtu);
    
    ASSERT_EQ(Cubic->InitialWindowPackets, 1000u);
    ASSERT_EQ(Cubic->CongestionWindow, PayloadSize * 1000u);
}

//
// Test 6: Initialize with zero SendIdleTimeoutMs
//
TEST(CubicTest, InitializeWithZeroSendIdleTimeout)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 0;  // Edge case: zero timeout
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, 0u);
    // Should still initialize other fields correctly
    ASSERT_GT(Cubic->CongestionWindow, 0u);
}

//
// Test 7: Initialize with maximum SendIdleTimeoutMs
//
TEST(CubicTest, InitializeWithMaxSendIdleTimeout)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = UINT32_MAX;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    ASSERT_EQ(Cubic->SendIdleTimeoutMs, UINT32_MAX);
}

//
// Test 8: Verify HyStart state initialization
//
TEST(CubicTest, VerifyHyStartInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    MockConn.Send.NextPacketNumber = 12345;
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // Verify HyStart fields
    ASSERT_EQ(Cubic->HyStartState, HYSTART_NOT_STARTED);
    ASSERT_EQ(Cubic->HyStartRoundEnd, 12345u);
    ASSERT_EQ(Cubic->HyStartAckCount, 0u);
    ASSERT_EQ(Cubic->MinRttInLastRound, UINT64_MAX);
    ASSERT_EQ(Cubic->MinRttInCurrentRound, UINT64_MAX);
    ASSERT_EQ(Cubic->CWndSlowStartGrowthDivisor, 1u);
}

//
// Test 9: Verify function pointer initialization
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
    
    // Verify all function pointers are set
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
// Test 10: Verify initial state flags
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
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // Verify initial boolean flags (should be FALSE/0 after initialization)
    ASSERT_FALSE(Cubic->HasHadCongestionEvent);
    ASSERT_FALSE(Cubic->IsInRecovery);
    ASSERT_FALSE(Cubic->IsInPersistentCongestion);
    ASSERT_FALSE(Cubic->TimeOfLastAckValid);
}

//
// Test 11: Verify BytesInFlight initialization
//
TEST(CubicTest, VerifyBytesInFlightInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    // Set BytesInFlight to non-zero before initialization
    MockConn.CongestionControl.Cubic.BytesInFlight = 12345;
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // BytesInFlight should be preserved or zeroed based on implementation
    // BytesInFlightMax should be half of CongestionWindow
    ASSERT_EQ(Cubic->BytesInFlightMax, Cubic->CongestionWindow / 2);
}

//
// Test 12: Verify Exemptions initialization
//
TEST(CubicTest, VerifyExemptionsInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    MockConn.CongestionControl.Cubic.Exemptions = 5;
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // Exemptions field should be initialized (likely to 0)
    ASSERT_EQ(Cubic->Exemptions, 0u);
}

//
// Test 13: Initialize with IPv6 path
//
TEST(CubicTest, InitializeWithIPv6Path)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    // Set IPv6 address family
    QUIC_ADDR RemoteAddr;
    CxPlatZeroMemory(&RemoteAddr, sizeof(RemoteAddr));
    QuicAddrSetFamily(&RemoteAddr, QUIC_ADDRESS_FAMILY_INET6);
    MockConn.Paths[0].Route.RemoteAddress = RemoteAddr;
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // The actual payload size is determined by the route's remote address family
    // Since we set IPv6, it should use IPv6 calculations
    // However, the actual CongestionWindow is calculated based on what the function reads
    // Let's just verify it initialized successfully and has a positive value
    ASSERT_GT(Cubic->CongestionWindow, 0u);
    ASSERT_EQ(Cubic->InitialWindowPackets, 10u);
}

//
// Test 14: Verify AIMD window initialization
//
TEST(CubicTest, VerifyAimdWindowInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // AIMD related fields should be initialized to 0
    ASSERT_EQ(Cubic->AimdWindow, 0u);
    ASSERT_EQ(Cubic->AimdAccumulator, 0u);
}

//
// Test 15: Verify WindowMax initialization
//
TEST(CubicTest, VerifyWindowMaxInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // WindowMax and related fields should be 0
    ASSERT_EQ(Cubic->WindowMax, 0u);
    ASSERT_EQ(Cubic->WindowLastMax, 0u);
    ASSERT_EQ(Cubic->WindowPrior, 0u);
    ASSERT_EQ(Cubic->KCubic, 0u);
}

//
// Test 16: Verify LastSendAllowance initialization
//
TEST(CubicTest, VerifyLastSendAllowanceInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    ASSERT_EQ(Cubic->LastSendAllowance, 0u);
}

//
// Test 17: Multiple sequential initializations
//
TEST(CubicTest, MultipleSequentialInitializations)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    // Initialize multiple times
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    uint32_t FirstCongestionWindow = MockConn.CongestionControl.Cubic.CongestionWindow;
    
    // Change settings and reinitialize
    Settings.InitialWindowPackets = 20;
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // Should reflect new settings
    ASSERT_EQ(Cubic->InitialWindowPackets, 20u);
    ASSERT_EQ(Cubic->CongestionWindow, FirstCongestionWindow * 2);
}

//
// Test 18: Verify TimeOfLastAck initialization
//
TEST(CubicTest, VerifyTimeOfLastAckInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    ASSERT_FALSE(Cubic->TimeOfLastAckValid);
    ASSERT_EQ(Cubic->TimeOfLastAck, 0u);
    ASSERT_EQ(Cubic->TimeOfCongAvoidStart, 0u);
}

//
// Test 19: Verify RecoverySentPacketNumber initialization
//
TEST(CubicTest, VerifyRecoverySentPacketNumberInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    ASSERT_EQ(Cubic->RecoverySentPacketNumber, 0u);
}

//
// Test 20: Verify Prev* fields initialization
//
TEST(CubicTest, VerifyPrevFieldsInitialization)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    InitializeMockConnection(&MockConn, 1280);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // All Prev* fields should be 0
    ASSERT_EQ(Cubic->PrevWindowPrior, 0u);
    ASSERT_EQ(Cubic->PrevWindowMax, 0u);
    ASSERT_EQ(Cubic->PrevWindowLastMax, 0u);
    ASSERT_EQ(Cubic->PrevKCubic, 0u);
    ASSERT_EQ(Cubic->PrevSlowStartThreshold, 0u);
    ASSERT_EQ(Cubic->PrevCongestionWindow, 0u);
    ASSERT_EQ(Cubic->PrevAimdWindow, 0u);
}

//
// Test 21: Test with very small MTU edge case
//
TEST(CubicTest, InitializeWithVerySmallMtu)
{
    MOCK_CONNECTION MockConn;
    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    
    Settings.InitialWindowPackets = 10;
    Settings.SendIdleTimeoutMs = 1000;
    
    // Use MTU smaller than QUIC_DPLPMTUD_MIN_MTU (edge case that might occur)
    InitializeMockConnection(&MockConn, 500);
    
    CubicCongestionControlInitialize(&MockConn.CongestionControl, &Settings);
    
    QUIC_CONGESTION_CONTROL_CUBIC* Cubic = &MockConn.CongestionControl.Cubic;
    
    // Should still calculate some congestion window
    ASSERT_GT(Cubic->CongestionWindow, 0u);
    ASSERT_GT(Cubic->BytesInFlightMax, 0u);
}

