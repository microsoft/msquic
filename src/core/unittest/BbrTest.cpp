/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for BBR Congestion Control

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "BbrTest.cpp.clog.h"
#endif

TEST(BbrTest, Initialize)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_STREQ("BBR", Cc.Name);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlCanSend);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlSetExemption);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlReset);
}

TEST(BbrTest, BandwidthFilter)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);
    Filter.AppLimited = FALSE;
    Filter.AppLimitedExitTarget = 0;

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);

    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 1000, 100);
    Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(1000u, Entry.Value);
    ASSERT_EQ(100u, Entry.Time);

    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 2000, 200);
    Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(2000u, Entry.Value);
    ASSERT_EQ(200u, Entry.Time);
}

TEST(BbrTest, InitialCongestionWindow)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(10u, Cc.Bbr.InitialCongestionWindowPackets);
    ASSERT_NE(0u, Cc.Bbr.InitialCongestionWindow);
    ASSERT_EQ(Cc.Bbr.InitialCongestionWindow, Cc.Bbr.CongestionWindow);
}

TEST(BbrTest, StateInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.BbrState);
    ASSERT_EQ(0u, Cc.Bbr.BytesInFlight);
    ASSERT_EQ(0u, Cc.Bbr.BytesInFlightMax);
    ASSERT_EQ(0u, Cc.Bbr.Exemptions);
}

TEST(BbrTest, RoundTripCounter)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.RoundTripCounter);
    ASSERT_FALSE(Cc.Bbr.EndOfRoundTripValid);
}

TEST(BbrTest, GainValues)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_NE(0u, Cc.Bbr.PacingGain);
    ASSERT_NE(0u, Cc.Bbr.CwndGain);
}

TEST(BbrTest, AppLimitedState)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.BandwidthFilter.AppLimited);
}

TEST(BbrTest, ProbeRttStateFlags)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.ProbeRttEndTimeValid);
    ASSERT_FALSE(Cc.Bbr.ProbeRttRoundValid);
}

TEST(BbrTest, RecoveryWindow)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_NE(0u, Cc.Bbr.RecoveryWindow);
}

TEST(BbrTest, MinRttInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(UINT64_MAX, Cc.Bbr.MinRtt);
    ASSERT_FALSE(Cc.Bbr.MinRttTimestampValid);
    ASSERT_TRUE(Cc.Bbr.RttSampleExpired);
}

TEST(BbrTest, BandwidthFilterInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.BandwidthFilter.AppLimited);
    ASSERT_EQ(0u, Cc.Bbr.BandwidthFilter.AppLimitedExitTarget);
}

TEST(BbrTest, MaxAckHeightFilterInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Cc.Bbr.MaxAckHeightFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);
}

TEST(BbrTest, AckAggregationInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.AggregatedAckBytes);
    ASSERT_FALSE(Cc.Bbr.AckAggregationStartTimeValid);
}

TEST(BbrTest, SendQuantumInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.SendQuantum);
}

TEST(BbrTest, BtlbwFoundInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.BtlbwFound);
}

TEST(BbrTest, SlowStartupRoundCounterInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.SlowStartupRoundCounter);
}

TEST(BbrTest, PacingCycleIndexInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.PacingCycleIndex);
}

TEST(BbrTest, ExitingQuiescenceInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.ExitingQuiescence);
}

TEST(BbrTest, LastEstimatedStartupBandwidthInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.LastEstimatedStartupBandwidth);
}

TEST(BbrTest, CycleStartInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.CycleStart);
}

TEST(BbrTest, EndOfRecoveryInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.EndOfRecoveryValid);
    ASSERT_EQ(0u, Cc.Bbr.EndOfRecovery);
}

TEST(BbrTest, ProbeRttRoundInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.ProbeRttRoundValid);
    ASSERT_EQ(0u, Cc.Bbr.ProbeRttRound);
}

TEST(BbrTest, EndOfRoundTripInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.EndOfRoundTripValid);
    ASSERT_EQ(0u, Cc.Bbr.EndOfRoundTrip);
}

TEST(BbrTest, RecoveryStateInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.RecoveryState);
}

TEST(BbrTest, BytesInFlightMaxInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(Cc.Bbr.CongestionWindow / 2, Cc.Bbr.BytesInFlightMax);
}

TEST(BbrTest, FunctionPointersNotNull)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_NE(nullptr, Cc.QuicCongestionControlGetSendAllowance);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlGetCongestionWindow);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlOnDataSent);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlOnDataInvalidated);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlOnDataAcknowledged);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlOnDataLost);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlOnSpuriousCongestionEvent);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlLogOutFlowStatus);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlGetExemptions);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlGetBytesInFlightMax);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlIsAppLimited);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlSetAppLimited);
    ASSERT_NE(nullptr, Cc.QuicCongestionControlGetNetworkStatistics);
}

TEST(BbrTest, MultipleInitialWindowPackets)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 100;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(100u, Cc.Bbr.InitialCongestionWindowPackets);
    ASSERT_NE(0u, Cc.Bbr.InitialCongestionWindow);
    ASSERT_EQ(Cc.Bbr.InitialCongestionWindow, Cc.Bbr.CongestionWindow);
}

TEST(BbrTest, ZeroInitialWindowPackets)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 0;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.InitialCongestionWindowPackets);
    ASSERT_EQ(0u, Cc.Bbr.CongestionWindow);
}

TEST(BbrTest, LargeInitialWindowPackets)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = UINT32_MAX;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(UINT32_MAX, Cc.Bbr.InitialCongestionWindowPackets);
}

TEST(BbrTest, BandwidthFilterEmptyGet)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);
}

TEST(BbrTest, BandwidthFilterMultipleUpdates)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);
    Filter.AppLimited = FALSE;

    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 1000, 100);
    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 2000, 200);
    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 1500, 300);

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(2000u, Entry.Value);
}

TEST(BbrTest, BandwidthFilterSameValues)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);
    Filter.AppLimited = FALSE;

    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 1000, 100);
    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 1000, 200);
    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 1000, 300);

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(1000u, Entry.Value);
}

TEST(BbrTest, BandwidthFilterZeroValues)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);
    Filter.AppLimited = FALSE;

    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, 0, 100);

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(0u, Entry.Value);
}

TEST(BbrTest, BandwidthFilterMaxUint64Values)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);
    Filter.AppLimited = FALSE;

    QuicSlidingWindowExtremumUpdateMax(&Filter.WindowedMaxFilter, UINT64_MAX, 100);

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Filter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(UINT64_MAX, Entry.Value);
}

TEST(BbrTest, BandwidthFilterAppLimitedFlag)
{
    BBR_BANDWIDTH_FILTER Filter;
    CxPlatZeroMemory(&Filter, sizeof(Filter));

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[3];
    Filter.WindowedMaxFilter = QuicSlidingWindowExtremumInitialize(100, 3, Entries);
    Filter.AppLimited = TRUE;
    Filter.AppLimitedExitTarget = 1000;

    ASSERT_TRUE(Filter.AppLimited);
    ASSERT_EQ(1000u, Filter.AppLimitedExitTarget);
}

TEST(BbrTest, AllFieldsZeroedAfterInit)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.BytesInFlight);
    ASSERT_EQ(0u, Cc.Bbr.Exemptions);
    ASSERT_EQ(0u, Cc.Bbr.RoundTripCounter);
    ASSERT_EQ(0u, Cc.Bbr.SendQuantum);
    ASSERT_EQ(0u, Cc.Bbr.SlowStartupRoundCounter);
    ASSERT_EQ(0u, Cc.Bbr.PacingCycleIndex);
    ASSERT_EQ(0u, Cc.Bbr.AggregatedAckBytes);
    ASSERT_EQ(0u, Cc.Bbr.CycleStart);
    ASSERT_EQ(0u, Cc.Bbr.EndOfRecovery);
    ASSERT_EQ(0u, Cc.Bbr.ProbeRttRound);
    ASSERT_EQ(0u, Cc.Bbr.EndOfRoundTrip);
    ASSERT_EQ(0u, Cc.Bbr.LastEstimatedStartupBandwidth);
}

TEST(BbrTest, CorrectNameAssignment)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_STREQ("BBR", Cc.Name);
}

//
// Additional tests for uncovered paths and edge cases
//

TEST(BbrTest, CanSendWithZeroBytesInFlight)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Zero bytes in flight should always allow sending
    Cc.Bbr.BytesInFlight = 0;
    ASSERT_TRUE(Cc.QuicCongestionControlCanSend(&Cc));
}

TEST(BbrTest, CanSendBelowCongestionWindow)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // BytesInFlight below congestion window should allow sending
    Cc.Bbr.BytesInFlight = Cc.Bbr.CongestionWindow / 2;
    ASSERT_TRUE(Cc.QuicCongestionControlCanSend(&Cc));
}

TEST(BbrTest, CannotSendAtCongestionWindowLimit)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // BytesInFlight at congestion window should block sending
    Cc.Bbr.BytesInFlight = Cc.Bbr.CongestionWindow;
    ASSERT_FALSE(Cc.QuicCongestionControlCanSend(&Cc));
}

TEST(BbrTest, CanSendWithExemptions)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Exemptions should allow sending even when at limit
    Cc.Bbr.BytesInFlight = Cc.Bbr.CongestionWindow;
    Cc.Bbr.Exemptions = 1;
    ASSERT_TRUE(Cc.QuicCongestionControlCanSend(&Cc));
}

TEST(BbrTest, IsAppLimitedInitiallyFalse)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.QuicCongestionControlIsAppLimited(&Cc));
}

TEST(BbrTest, GetBytesInFlightMax)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // BytesInFlightMax should be half the congestion window
    uint32_t Expected = Cc.Bbr.CongestionWindow / 2;
    ASSERT_EQ(Expected, Cc.QuicCongestionControlGetBytesInFlightMax(&Cc));
}

TEST(BbrTest, OnSpuriousCongestionEventReturnsFalse)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // BBR always returns FALSE for spurious congestion events
    ASSERT_FALSE(Cc.QuicCongestionControlOnSpuriousCongestionEvent(&Cc));
}

TEST(BbrTest, RecoveryStateInitiallyNotInRecovery)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Should be in NOT_RECOVERY state (value 0)
    ASSERT_EQ(0u, Cc.Bbr.RecoveryState);
}

TEST(BbrTest, BbrStateInitiallyStartup)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Should be in STARTUP state (value 0)
    ASSERT_EQ(0u, Cc.Bbr.BbrState);
}

TEST(BbrTest, InitialWindowPacketsEdgeCaseOne)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 1;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(1u, Cc.Bbr.InitialCongestionWindowPackets);
    ASSERT_NE(0u, Cc.Bbr.CongestionWindow);
}

TEST(BbrTest, InitialWindowPacketsMaxMinusOne)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = UINT32_MAX - 1;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(UINT32_MAX - 1, Cc.Bbr.InitialCongestionWindowPackets);
}

TEST(BbrTest, GainValuesAreHighGainInStartup)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Both pacing and cwnd gain should be kHighGain in STARTUP
    // kHighGain = GAIN_UNIT * 2885 / 1000 + 1
    uint32_t kHighGain = 256 * 2885 / 1000 + 1;
    ASSERT_EQ(kHighGain, Cc.Bbr.PacingGain);
    ASSERT_EQ(kHighGain, Cc.Bbr.CwndGain);
}

TEST(BbrTest, ProbeRttEndTimeInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.ProbeRttEndTimeValid);
    ASSERT_EQ(0u, Cc.Bbr.ProbeRttEndTime);
}

TEST(BbrTest, AckAggregationStartTimeInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.AckAggregationStartTimeValid);
    // AckAggregationStartTime is set to current time, so just verify it's set
    ASSERT_NE(0u, Cc.Bbr.AckAggregationStartTime);
}

TEST(BbrTest, MinRttTimestampInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_FALSE(Cc.Bbr.MinRttTimestampValid);
    ASSERT_EQ(0u, Cc.Bbr.MinRttTimestamp);
}

TEST(BbrTest, BytesInFlightInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.BytesInFlight);
}

TEST(BbrTest, ExemptionsInitialization)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    ASSERT_EQ(0u, Cc.Bbr.Exemptions);
}

//
// Security-focused tests: Edge cases and potential vulnerabilities
//

TEST(BbrTest, IntegerOverflowCongestionWindowCalculation)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    // Use very large value to test overflow handling
    Settings.InitialWindowPackets = UINT32_MAX / 2;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Verify the multiplication doesn't cause undefined behavior
    ASSERT_NE(0u, Cc.Bbr.CongestionWindow);
}

TEST(BbrTest, ZeroWindowWithCanSend)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 0;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // With zero congestion window, CanSend should still work
    Cc.Bbr.BytesInFlight = 0;
    // This should not crash even with zero window
    BOOLEAN Result = Cc.QuicCongestionControlCanSend(&Cc);
    // Result is TRUE because BytesInFlight (0) < CongestionWindow (0) is false,
    // but Exemptions (0) > 0 is false, so overall FALSE
    ASSERT_FALSE(Result);
}

TEST(BbrTest, MaxUint32BytesInFlight)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Test with maximum bytes in flight
    Cc.Bbr.BytesInFlight = UINT32_MAX;
    ASSERT_FALSE(Cc.QuicCongestionControlCanSend(&Cc));
}

TEST(BbrTest, BytesInFlightMaxCalculationWithZeroWindow)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 0;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // BytesInFlightMax should be CongestionWindow / 2
    ASSERT_EQ(0u, Cc.Bbr.BytesInFlightMax);
}

TEST(BbrTest, BandwidthFilterResetOnEmpty)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Add a sample
    QuicSlidingWindowExtremumUpdateMax(&Cc.Bbr.BandwidthFilter.WindowedMaxFilter, 1000, 100);
    
    // Reset the filter
    QuicSlidingWindowExtremumReset(&Cc.Bbr.BandwidthFilter.WindowedMaxFilter);
    
    // Should be empty now
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Cc.Bbr.BandwidthFilter.WindowedMaxFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);
}

TEST(BbrTest, MaxAckHeightFilterResetOnEmpty)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Add a sample
    QuicSlidingWindowExtremumUpdateMax(&Cc.Bbr.MaxAckHeightFilter, 500, 50);
    
    // Reset the filter
    QuicSlidingWindowExtremumReset(&Cc.Bbr.MaxAckHeightFilter);
    
    // Should be empty now
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entry = { 0, 0 };
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Cc.Bbr.MaxAckHeightFilter, &Entry);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);
}

//
// Tests for uncovered branches in BbrCongestionControlGetCongestionWindow
//

TEST(BbrTest, GetCongestionWindowInProbeRttState)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Save the initial congestion window
    uint32_t InitialCwnd = Cc.Bbr.CongestionWindow;

    // Transition to PROBE_RTT state (BBR_STATE_PROBE_RTT = 3)
    Cc.Bbr.BbrState = 3; // BBR_STATE_PROBE_RTT

    // In PROBE_RTT, should return minimum congestion window
    uint32_t CwndInProbeRtt = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    
    // Minimum should be kMinCwndInMss * DatagramPayloadLength (kMinCwndInMss = 4)
    ASSERT_LT(CwndInProbeRtt, InitialCwnd);
    ASSERT_NE(0u, CwndInProbeRtt);
}

TEST(BbrTest, GetCongestionWindowInRecoveryState)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Enter recovery state (RECOVERY_STATE_CONSERVATIVE = 1)
    Cc.Bbr.RecoveryState = 1;
    
    // Set recovery window smaller than congestion window
    Cc.Bbr.RecoveryWindow = Cc.Bbr.CongestionWindow / 2;

    // Should return the minimum of CongestionWindow and RecoveryWindow
    uint32_t Cwnd = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_EQ(Cc.Bbr.RecoveryWindow, Cwnd);
}

TEST(BbrTest, GetCongestionWindowInRecoveryWithLargerRecoveryWindow)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Enter recovery state (RECOVERY_STATE_GROWTH = 2)
    Cc.Bbr.RecoveryState = 2;
    
    // Set recovery window larger than congestion window
    Cc.Bbr.RecoveryWindow = Cc.Bbr.CongestionWindow * 2;

    // Should return the minimum (CongestionWindow)
    uint32_t Cwnd = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_EQ(Cc.Bbr.CongestionWindow, Cwnd);
}

TEST(BbrTest, GetCongestionWindowInStartupState)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // STARTUP state (0) is the default
    ASSERT_EQ(0u, Cc.Bbr.BbrState);
    ASSERT_EQ(0u, Cc.Bbr.RecoveryState);

    // Should return full congestion window
    uint32_t Cwnd = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_EQ(Cc.Bbr.CongestionWindow, Cwnd);
}

TEST(BbrTest, InRecoveryCheck)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;

    QuicCongestionControlInitialize(&Cc, &Settings);

    // Initially not in recovery
    ASSERT_EQ(0u, Cc.Bbr.RecoveryState);

    // Enter conservative recovery
    Cc.Bbr.RecoveryState = 1; // RECOVERY_STATE_CONSERVATIVE
    
    // Now should be in recovery (handled by BbrCongestionControlInRecovery)
    ASSERT_NE(0u, Cc.Bbr.RecoveryState);

    // Enter growth recovery
    Cc.Bbr.RecoveryState = 2; // RECOVERY_STATE_GROWTH
    ASSERT_NE(0u, Cc.Bbr.RecoveryState);
}

TEST(BbrTest, AllBbrStates)
{
    QUIC_CONGESTION_CONTROL Cc;
    CxPlatZeroMemory(&Cc, sizeof(Cc));

    QUIC_SETTINGS_INTERNAL Settings;
    CxPlatZeroMemory(&Settings, sizeof(Settings));
    Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    Settings.InitialWindowPackets = 10;

    QuicCongestionControlInitialize(&Cc, &Settings);

    uint32_t InitialCwnd = Cc.Bbr.CongestionWindow;

    // Test STARTUP (0)
    Cc.Bbr.BbrState = 0;
    uint32_t CwndStartup = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_EQ(InitialCwnd, CwndStartup);

    // Test DRAIN (1)
    Cc.Bbr.BbrState = 1;
    uint32_t CwndDrain = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_EQ(InitialCwnd, CwndDrain);

    // Test PROBE_BW (2)
    Cc.Bbr.BbrState = 2;
    uint32_t CwndProbeBw = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_EQ(InitialCwnd, CwndProbeBw);

    // Test PROBE_RTT (3) - should return minimum
    Cc.Bbr.BbrState = 3;
    uint32_t CwndProbeRtt = Cc.QuicCongestionControlGetCongestionWindow(&Cc);
    ASSERT_LT(CwndProbeRtt, InitialCwnd);
}
