/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

struct QUIC_SENT_PACKET_POOL;
struct QUIC_LOSS_DETECTION;
struct QUIC_PATH;
struct QUIC_CONGESTION_CONTROL;
struct QUIC_SETTINGS_INTERNAL;
struct QUIC_SENT_PACKET_METADATA;

extern "C" {
void QuicSentPacketPoolInitialize(QUIC_SENT_PACKET_POOL* Pool);
void QuicSentPacketPoolUninitialize(QUIC_SENT_PACKET_POOL* Pool);
void QuicLossDetectionInitialize(QUIC_LOSS_DETECTION* LossDetection);
void QuicLossDetectionUninitialize(QUIC_LOSS_DETECTION* LossDetection);
void QuicLossDetectionOnPacketSent(
    QUIC_LOSS_DETECTION* LossDetection,
    QUIC_PATH* Path,
    QUIC_SENT_PACKET_METADATA* Packet);
void QuicCongestionControlInitialize(
    QUIC_CONGESTION_CONTROL* Cc,
    const QUIC_SETTINGS_INTERNAL* Settings);
}

#include "BbrTestHelpers.h"

extern "C" {
uint64_t BbrV3CongestionControlGetBandwidth(const QUIC_CONGESTION_CONTROL* Cc);
uint32_t BbrV3CongestionControlGetTargetCwnd(QUIC_CONGESTION_CONTROL* Cc, uint32_t Gain);
void BbrV3CongestionControlUpdateCongestionWindow(QUIC_CONGESTION_CONTROL* Cc, uint64_t TotalBytesAcked, uint64_t AckedBytes);
}

namespace {

constexpr uint64_t TestTime = 1000000;

class BbrV3Test : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection{};
    QUIC_CONGESTION_CONTROL& Cc = Connection.CongestionControl;
    BBR_COMMON& Bbr = Cc.BbrV3.Common;
    BBR_V3_MODEL& Model = Cc.BbrV3.Model;

    void SetUp() override {
        Initialize();
    }

    void Initialize(uint32_t WindowPackets = 100, uint16_t Mtu = 1280, bool PacingEnabled = false) {
        Connection._.Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection.PathsCount = 1;
        Connection.Paths[0].Mtu = Mtu;
        Connection.Paths[0].IsActive = TRUE;
        Connection.Paths[0].IsPeerValidated = TRUE;
        Connection.Paths[0].SmoothedRtt = 50000;
        Connection.Settings.InitialWindowPackets = WindowPackets;
        Connection.Settings.PacingEnabled = PacingEnabled ? TRUE : FALSE;
        Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3;
        Connection.Send.PeerMaxData = UINT64_MAX;
        CxPlatListInitializeHead(&Connection.Send.SendStreams);
        BbrV3CongestionControlInitialize(&Cc, &Connection.Settings);
    }

    void EnterCruise() {
        Bbr.BtlbwFound = TRUE;
        Bbr.BbrState = BBR_STATE_PROBE_BW;
        Bbr.PacingGain = 256;
        Bbr.CwndGain = 512;
        Bbr.CycleStart = TestTime;
        Bbr.MinRtt = 50000;
        Bbr.MinRttTimestamp = TestTime;
        Bbr.MinRttTimestampValid = TRUE;
        Model.ProbeRttMin = 50000;
        Model.ProbeRttMinTimestamp = TestTime;
        Model.Phase = BBR_V3_PHASE_CRUISE;
        Model.ProbeWait = 3000000;
        Model.ProbeSamples = FALSE;
        QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    }

    QUIC_MAX_SENT_PACKET_METADATA LossPacket(uint64_t Number, uint16_t Length) {
        QUIC_MAX_SENT_PACKET_METADATA Storage{};
        auto& Packet = Storage.Metadata;
        Packet.PacketNumber = Number;
        Packet.PacketLength = Length;
        Packet.SentTime = TestTime - 50000;
        Packet.Flags.IsAckEliciting = TRUE;
        Packet.Flags.IsBbrProbe = TRUE;
        Packet.InflightAtSend = Bbr.BytesInFlight;
        Packet.TotalBytesLost = Model.TotalBytesLost;
        return Storage;
    }

    QUIC_ACK_EVENT Ack(uint32_t Bytes, uint64_t Number = 1) {
        return MakeBbrAckEvent(TestTime + 1, Number, 100, Bytes, 50000, 50000);
    }
};

class BbrV3TransportTest : public BbrV3Test {
protected:
    QUIC_PARTITION Partition{};

    void SetUp() override {
        BbrV3Test::SetUp();
        Connection.Partition = &Partition;
        QuicSentPacketPoolInitialize(&Partition.SentPacketPool);
        QuicLossDetectionInitialize(&Connection.LossDetection);
        Connection.EarliestExpirationTime = UINT64_MAX;
        for (auto& Expiration : Connection.ExpirationTimes) {
            Expiration = UINT64_MAX;
        }
    }

    void TearDown() override {
        QuicLossDetectionUninitialize(&Connection.LossDetection);
        QuicSentPacketPoolUninitialize(&Partition.SentPacketPool);
    }

    void SendPacket(uint64_t Number, uint16_t Length) {
        QUIC_MAX_SENT_PACKET_METADATA Storage{};
        auto& Packet = Storage.Metadata;
        Packet.PacketNumber = Number;
        Packet.PacketLength = Length;
        Packet.SentTime = TestTime;
        Packet.Flags.KeyType = QUIC_PACKET_KEY_1_RTT;
        Packet.Flags.IsAckEliciting = TRUE;
        Packet.FrameCount = 1;
        Packet.Frames[0].Type = QUIC_FRAME_PING;
        QuicLossDetectionOnPacketSent(&Connection.LossDetection, &Connection.Paths[0], &Packet);
    }
};

TEST_F(BbrV3TransportTest, SentSnapshotUsesActiveControllerAndIncludesCurrentPacket)
{
    Connection.State.Started = TRUE;
    // Updating settings after startup does not replace the active controller.
    Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    Model.TotalBytesLost = 456;
    SendPacket(1, 1200);
    const auto* First = Connection.LossDetection.SentPackets;
    ASSERT_NE(First, nullptr);
    EXPECT_EQ(First->InflightAtSend, 1200u);
    EXPECT_EQ(First->TotalBytesLost, 456u);
    EXPECT_TRUE(First->Flags.IsBbrProbe);

    Model.TotalBytesLost = 789;
    SendPacket(2, 1000);
    ASSERT_NE(First->Next, nullptr);
    EXPECT_EQ(First->Next->InflightAtSend, 2200u);
    EXPECT_EQ(First->Next->TotalBytesLost, 789u);
    EXPECT_EQ(First->InflightAtSend, 1200u);
    EXPECT_EQ(First->TotalBytesLost, 456u);
}

TEST_F(BbrV3TransportTest, CubicDoesNotCaptureBbrStateFromChangedSettings)
{
    Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
    QuicCongestionControlInitialize(&Cc, &Connection.Settings);
    Connection.State.Started = TRUE;
    Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3;
    SendPacket(1, 1200);
    const auto* Packet = Connection.LossDetection.SentPackets;
    ASSERT_NE(Packet, nullptr);
    EXPECT_EQ(Packet->InflightAtSend, 0u);
    EXPECT_EQ(Packet->TotalBytesLost, 0u);
    EXPECT_FALSE(Packet->Flags.IsBbrProbe);
}

TEST_F(BbrV3TransportTest, BbrDoesNotCaptureBbrV3StateFromChangedSettings)
{
    Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
    QuicCongestionControlInitialize(&Cc, &Connection.Settings);
    Connection.State.Started = TRUE;
    Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3;
    SendPacket(1, 1200);
    const auto* Packet = Connection.LossDetection.SentPackets;
    ASSERT_NE(Packet, nullptr);
    EXPECT_EQ(Packet->InflightAtSend, 0u);
    EXPECT_EQ(Packet->TotalBytesLost, 0u);
    EXPECT_FALSE(Packet->Flags.IsBbrProbe);
}

TEST_F(BbrV3Test, ImplicitAckRemovesFlightOnceWithoutProducingRttSamples)
{
    QuicCongestionControlOnDataSent(&Cc, 3600);
    auto Implicit = Ack(1200);
    Implicit.IsImplicit = TRUE;
    Implicit.MinRttValid = FALSE;
    Implicit.NumTotalAckedRetransmittableBytes = 0;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Implicit);
    EXPECT_EQ(Bbr.BytesInFlight, 2400u);
    EXPECT_FALSE(Bbr.MinRttTimestampValid);
    EXPECT_EQ(Bbr.RoundTripCounter, 0u);

    auto Explicit = Ack(2400, 2);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Explicit);
    EXPECT_EQ(Bbr.BytesInFlight, 0u);
}

TEST_F(BbrV3Test, MixedLossListCountsOnlyAckElicitingBytes)
{
    EnterCruise();
    Model.Phase = BBR_V3_PHASE_UP;
    Model.ProbeSamples = TRUE;
    Bbr.PacingGain = 320;
    QuicCongestionControlOnDataSent(&Cc, 100000);
    auto FirstStorage = LossPacket(1, 1200);
    auto& First = FirstStorage.Metadata;
    auto AckOnlyStorage = LossPacket(2, 65000);
    auto& AckOnly = AckOnlyStorage.Metadata;
    AckOnly.Flags.IsAckEliciting = FALSE;
    auto LastStorage = LossPacket(3, 1200);
    auto& Last = LastStorage.Metadata;
    auto ExtraStorage = LossPacket(4, 1200);
    First.Next = &AckOnly;
    AckOnly.Next = &Last;
    Last.Next = &ExtraStorage.Metadata;
    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &First;
    Loss.NumRetransmittableBytes = 3600;
    Loss.LargestPacketNumberLost = 4;
    Loss.LargestSentPacketNumber = 100;
    QuicCongestionControlOnDataLost(&Cc, &Loss);

    EXPECT_EQ(Model.TotalBytesLost, 3600u);
    EXPECT_EQ(Bbr.BytesInFlight, 96400u);
    EXPECT_GT(Model.InflightHigh, 90000u);
    EXPECT_LT(Model.InflightHigh, UINT32_MAX);
    EXPECT_EQ(Model.Phase, BBR_V3_PHASE_DOWN);
    // DOWN starts a fresh short-term round after adapting the probe bound.
    EXPECT_FALSE(Model.LossInRound);
}

TEST_F(BbrV3Test, CruiseTailLossDoesNotCollapseLongTermInflightBound)
{
    EnterCruise();
    Model.InflightHigh = 60000;
    QuicCongestionControlOnDataSent(&Cc, 1200);
    auto Storage = LossPacket(10, 1200);
    auto& Packet = Storage.Metadata;
    Packet.InflightAtSend = 60000;
    Packet.Flags.IsBbrProbe = FALSE;
    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &Packet;
    Loss.NumRetransmittableBytes = 1200;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 10;
    QuicCongestionControlOnDataLost(&Cc, &Loss);

    EXPECT_EQ(Bbr.BytesInFlight, 0u);
    EXPECT_EQ(Model.InflightHigh, 60000u);
    EXPECT_EQ(Model.Phase, BBR_V3_PHASE_CRUISE);
}

TEST_F(BbrV3Test, PartialResetRetainsLossCounterAndRejectsOldPathSamples)
{
    Model.TotalBytesLost = 9000;
    QuicCongestionControlOnDataSent(&Cc, 5000);
    auto Storage = LossPacket(10, 1200);
    auto& OldPacket = Storage.Metadata;
    OldPacket.InflightAtSend = 1200;
    Connection.Send.NextPacketNumber = 20;
    Connection.LossDetection.LargestSentPacketNumber = 19;
    QuicCongestionControlReset(&Cc, FALSE);
    EXPECT_EQ(Bbr.BytesInFlight, 5000u);
    EXPECT_EQ(Model.TotalBytesLost, 9000u);
    EXPECT_EQ(Model.MinValidPacketNumber, 20u);

    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &OldPacket;
    Loss.NumRetransmittableBytes = 1200;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 19;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    EXPECT_EQ(Bbr.BytesInFlight, 3800u);
    // Old-path losses leave flight, but cannot pollute the new path's samples.
    EXPECT_EQ(Model.TotalBytesLost, 9000u);
    EXPECT_EQ(Model.InflightHigh, UINT32_MAX);
    EXPECT_FALSE(Model.LossInRound);
    EXPECT_FALSE(Model.ExcessiveLossInRound);
    EXPECT_EQ(Model.StartupLossEvents, 0u);
}

TEST_F(BbrV3Test, SpuriousLossRestoresBoundsAndRecoveryWithoutDoubleAck)
{
    EnterCruise();
    Model.Phase = BBR_V3_PHASE_UP;
    Model.ProbeSamples = TRUE;
    Bbr.PacingGain = 320;
    Model.InflightHigh = 100000;
    Model.InflightLow = 90000;
    const auto PriorWindow = Bbr.CongestionWindow;
    QuicCongestionControlOnDataSent(&Cc, 60000);
    auto Storage = LossPacket(10, 2400);
    auto& Packet = Storage.Metadata;
    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &Packet;
    Loss.NumRetransmittableBytes = 2400;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 50;
    Loss.PersistentCongestion = TRUE;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    ASSERT_LT(Model.InflightHigh, 100000u);
    ASSERT_LT(Model.InflightLow, 90000u);
    ASSERT_NE(Bbr.RecoveryState, RECOVERY_STATE_NOT_RECOVERY);

    QuicCongestionControlOnSpuriousCongestionEvent(&Cc);
    EXPECT_EQ(Model.InflightHigh, 100000u);
    EXPECT_EQ(Model.InflightLow, 90000u);
    EXPECT_GE(Bbr.CongestionWindow, PriorWindow);
    EXPECT_EQ(Bbr.RecoveryState, RECOVERY_STATE_NOT_RECOVERY);
    EXPECT_EQ(Bbr.BbrState, BBR_STATE_PROBE_BW);
    EXPECT_EQ(Model.Phase, BBR_V3_PHASE_UP);
    EXPECT_EQ(Bbr.PacingGain, 320u);
    EXPECT_FALSE(Model.UndoValid);

    // A spurious-loss ACK still supplies packet metadata, but no bytes to
    // remove from flight because the loss event removed them already.
    auto Spurious = Ack(0, 10);
    Spurious.AckedPackets = &Packet;
    Spurious.NumTotalAckedRetransmittableBytes = 2400;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Spurious);
    EXPECT_EQ(Bbr.BytesInFlight, 57600u);
}

TEST_F(BbrV3Test, OldPathLossCannotPushCurrentProbeOverLossThreshold)
{
    Model.TotalBytesLost = 9000;
    QuicCongestionControlOnDataSent(&Cc, 100000);
    auto OldStorage = LossPacket(10, 1200);
    Connection.Send.NextPacketNumber = 20;
    Connection.LossDetection.LargestSentPacketNumber = 19;
    QuicCongestionControlReset(&Cc, FALSE);
    EnterCruise();
    Model.Phase = BBR_V3_PHASE_UP;
    Model.ProbeSamples = TRUE;
    Bbr.PacingGain = 320;
    auto CurrentStorage = LossPacket(20, 1200);

    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &OldStorage.Metadata;
    Loss.NumRetransmittableBytes = 1200;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 100;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    Loss.LostPackets = &CurrentStorage.Metadata;
    Loss.LargestPacketNumberLost = 20;
    QuicCongestionControlOnDataLost(&Cc, &Loss);

    // The current path lost 1.2% of the sampled flight, not 2.4%.
    EXPECT_EQ(Model.TotalBytesLost, 10200u);
    EXPECT_FALSE(Model.ExcessiveLossInRound);
    EXPECT_EQ(Model.InflightHigh, UINT32_MAX);
    EXPECT_EQ(Model.Phase, BBR_V3_PHASE_UP);
    EXPECT_EQ(Bbr.BytesInFlight, 97600u);
}

TEST_F(BbrV3Test, SpuriousProbeLossDoesNotInterruptProbeRtt)
{
    EnterCruise();
    Model.Phase = BBR_V3_PHASE_UP;
    Model.ProbeSamples = TRUE;
    Bbr.PacingGain = 320;
    Model.InflightHigh = 100000;
    QuicCongestionControlOnDataSent(&Cc, 60000);
    auto Storage = LossPacket(10, 2400);
    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &Storage.Metadata;
    Loss.NumRetransmittableBytes = 2400;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 50;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    ASSERT_LT(Model.InflightHigh, 100000u);

    // MinRTT sampling may start while the lost probe is still awaiting an ACK.
    Bbr.BbrState = BBR_STATE_PROBE_RTT;
    Bbr.PacingGain = 256;
    Bbr.CwndGain = 256;
    Bbr.ProbeRttEndTimeValid = TRUE;
    Bbr.ProbeRttEndTime = TestTime + 200000;
    QuicCongestionControlOnSpuriousCongestionEvent(&Cc);
    EXPECT_EQ(Model.InflightHigh, 100000u);
    EXPECT_EQ(Bbr.RecoveryState, RECOVERY_STATE_NOT_RECOVERY);
    EXPECT_EQ(Bbr.BbrState, BBR_STATE_PROBE_RTT);
    EXPECT_EQ(Bbr.PacingGain, 256u);
    EXPECT_EQ(Bbr.CwndGain, 256u);
    EXPECT_TRUE(Bbr.ProbeRttEndTimeValid);
    EXPECT_EQ(Bbr.ProbeRttEndTime, TestTime + 200000);
}

TEST_F(BbrV3Test, CleanAckDoesNotRelaxShortTermInflightBound)
{
    EnterCruise();
    Model.InflightLow = 20000;
    Bbr.EndOfRoundTripValid = TRUE;
    Bbr.EndOfRoundTrip = 100;
    QuicCongestionControlOnDataSent(&Cc, 1200);
    auto Event = Ack(1200, 10);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Event);
    EXPECT_EQ(Model.InflightLow, 20000u);
    EXPECT_EQ(Model.Phase, BBR_V3_PHASE_CRUISE);
    EXPECT_EQ(Bbr.BytesInFlight, 0u);
}

TEST_F(BbrV3Test, OldPathAckIgnoresGlobalAckHighWatermarkForModelUpdates)
{
    QuicCongestionControlOnDataSent(&Cc, 5000);
    auto OldStorage = LossPacket(10, 1200);
    Connection.Send.NextPacketNumber = 20;
    QuicCongestionControlReset(&Cc, FALSE);
    const auto PriorWindow = Bbr.CongestionWindow;
    const auto PriorMinRtt = Bbr.MinRtt;
    const auto PriorProbeRttMin = Model.ProbeRttMin;

    auto Event = Ack(1200, 100);
    Event.AckedPackets = &OldStorage.Metadata;
    Event.MinRtt = 10;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Event);

    // LargestAck is the transport's global watermark, not the generation of
    // the packet newly acknowledged by this event.
    EXPECT_EQ(Bbr.BytesInFlight, 3800u);
    EXPECT_EQ(Bbr.CongestionWindow, PriorWindow);
    EXPECT_EQ(Bbr.MinRtt, PriorMinRtt);
    EXPECT_FALSE(Bbr.MinRttTimestampValid);
    EXPECT_EQ(Model.ProbeRttMin, PriorProbeRttMin);
    EXPECT_EQ(Bbr.RoundTripCounter, 0u);
    EXPECT_FALSE(Bbr.EndOfRoundTripValid);
    EXPECT_EQ(Model.BandwidthLatest, 0u);
    EXPECT_EQ(Model.InflightLatest, 0u);
}

TEST_F(BbrV3Test, MixedPathAckMeasuresRttFromCurrentGenerationPacket)
{
    QuicCongestionControlOnDataSent(&Cc, 5000);
    auto OldStorage = LossPacket(10, 1200);
    Connection.Send.NextPacketNumber = 20;
    QuicCongestionControlReset(&Cc, FALSE);
    auto CurrentStorage = LossPacket(20, 1200);
    OldStorage.Metadata.Next = &CurrentStorage.Metadata;

    auto Event = Ack(2400, 100);
    Event.AckedPackets = &OldStorage.Metadata;
    Event.AdjustedAckTime = Event.TimeNow - 5000;
    OldStorage.Metadata.SentTime = Event.TimeNow - 10000;
    CurrentStorage.Metadata.SentTime = Event.TimeNow - 50000;
    Event.MinRtt = 5000; // The transport's minimum came from the old path.
    QuicCongestionControlOnDataAcknowledged(&Cc, &Event);

    EXPECT_EQ(Bbr.BytesInFlight, 2600u);
    EXPECT_TRUE(Bbr.MinRttTimestampValid);
    EXPECT_EQ(Bbr.MinRtt, 45000u);
    EXPECT_EQ(Model.ProbeRttMin, 45000u);
    EXPECT_EQ(Bbr.RoundTripCounter, 1u);
    // Normalization must not relink transport-owned metadata.
    EXPECT_EQ(OldStorage.Metadata.Next, &CurrentStorage.Metadata);
    EXPECT_EQ(CurrentStorage.Metadata.Next, nullptr);
}

TEST_F(BbrV3Test, ProbeLossFloorIgnoresRecoveryWindowFromPreviousEpisode)
{
    const uint32_t MinimumWindow = 4 * QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t PreviousHigh = 0;
    for (uint32_t StaleRecoveryWindow : {MinimumWindow, 200000u}) {
        BbrV3CongestionControlInitialize(&Cc, &Connection.Settings);
        EnterCruise();
        Model.Phase = BBR_V3_PHASE_UP;
        Model.ProbeSamples = TRUE;
        Bbr.PacingGain = 320;
        Bbr.CongestionWindow = 100000;
        Bbr.RecoveryState = RECOVERY_STATE_NOT_RECOVERY;
        Bbr.RecoveryWindow = StaleRecoveryWindow;
        // Two MB/s over 50 ms gives a 100 KB BDP.
        QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 16000000, 0);
        QuicCongestionControlOnDataSent(&Cc, 100000);
        ASSERT_EQ(QuicCongestionControlGetCongestionWindow(&Cc), 100000u);
        auto Storage = LossPacket(1, 1200);
        Storage.Metadata.InflightAtSend = 1200;
        QUIC_LOSS_EVENT Loss{};
        Loss.TimeNow = TestTime;
        Loss.LostPackets = &Storage.Metadata;
        Loss.NumRetransmittableBytes = 1200;
        Loss.LargestPacketNumberLost = 1;
        Loss.LargestSentPacketNumber = 100;
        QuicCongestionControlOnDataLost(&Cc, &Loss);

        EXPECT_GE(Model.InflightHigh, 70000u);
        if (PreviousHigh != 0) {
            EXPECT_EQ(Model.InflightHigh, PreviousHigh);
        }
        PreviousHigh = Model.InflightHigh;
    }
}

TEST_F(BbrV3Test, InitializationSelectsV3Controller)
{
    QuicCongestionControlInitialize(&Cc, &Connection.Settings);
    ASSERT_STREQ(Cc.Name, "BBRv3");
    ASSERT_EQ(Model.InflightHigh, UINT32_MAX);
    ASSERT_EQ(Model.InflightLow, UINT32_MAX);
}

TEST_F(BbrV3Test, PacingUsesBytesPerMicrosecond)
{
    Initialize(100, 1280, true);
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Bbr.PacingGain = 256;
    Bbr.MinRtt = 50000;
    Bbr.MinRttTimestampValid = TRUE;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);

    // 1 MB/s permits 1 KB in one millisecond, independent of the much larger cwnd.
    ASSERT_EQ(QuicCongestionControlGetSendAllowance(&Cc, 1000, TRUE), 1000u);
    ASSERT_EQ(QuicCongestionControlGetSendAllowance(&Cc, 0, TRUE), 0u);
}

TEST_F(BbrV3Test, SendQuantumIsOneMillisecond)
{
    Initialize(10);
    Bbr.PacingGain = 256;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 240000000, 0);
    BbrSetSendQuantum(&Bbr, BbrV3CongestionControlGetBandwidth(&Cc),
        QuicPathGetDatagramPayloadSize(&Connection.Paths[0]));
    ASSERT_EQ(Bbr.SendQuantum, 30000u);
}

TEST_F(BbrV3Test, AckAggregationCannotBypassInflightBound)
{
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Bbr.PacingGain = 256;
    Bbr.MinRtt = 50000;
    Bbr.MinRttTimestampValid = TRUE;
    Model.InflightLow = 20000;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    QuicSlidingWindowExtremumUpdateMax(&Bbr.MaxAckHeightFilter, 40000, 0);
    BbrV3CongestionControlUpdateCongestionWindow(&Cc, 200000, 10000);
    ASSERT_LE(QuicCongestionControlGetCongestionWindow(&Cc), 20000u);
}

TEST_F(BbrV3Test, CruiseDoesNotAdvanceOnEveryAck)
{
    Initialize(10);
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_CRUISE;
    Bbr.PacingGain = 256;
    Bbr.CycleStart = 1000000;
    Bbr.MinRtt = 50000;
    Bbr.MinRttTimestamp = 1000000;
    Bbr.MinRttTimestampValid = TRUE;
    QuicCongestionControlOnDataSent(&Cc, 1200);
    auto Ack = MakeBbrAckEvent(1000001, 1, 2, 1200);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.Phase, BBR_V3_PHASE_CRUISE);
}

TEST_F(BbrV3Test, RefillClearsShortTermBoundsAndWaitsForPacketRound)
{
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_CRUISE;
    Bbr.CycleStart = 1000000;
    Model.ProbeWait = 2000000;
    Model.InflightLow = 20000;
    Model.BandwidthLow = 4000000;
    Model.InflightHigh = 40000;

    auto Ack = MakeBbrAckEvent(3000000, 10, 100, 0);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.Phase, BBR_V3_PHASE_REFILL);
    ASSERT_EQ(Model.InflightLow, UINT32_MAX);
    ASSERT_EQ(Model.BandwidthLow, UINT64_MAX);
    ASSERT_EQ(Model.InflightHigh, 40000u);
    Ack.LargestAck = 99;
    Ack.TimeNow += 50000;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.Phase, BBR_V3_PHASE_REFILL);
    Ack.LargestAck = 101;
    Ack.LargestSentPacketNumber = 110;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.Phase, BBR_V3_PHASE_UP);
    ASSERT_EQ(Bbr.PacingGain, 320u);
}

TEST_F(BbrV3Test, ProbeLossThresholdUsesSentFlight)
{
    for (uint16_t LostBytes : {uint16_t(1000), uint16_t(1001)}) {
        Initialize(100);
        Bbr.BtlbwFound = TRUE;
        Bbr.BbrState = BBR_STATE_PROBE_BW;
        Model.Phase = BBR_V3_PHASE_UP;
        Model.ProbeSamples = TRUE;
        Bbr.PacingGain = 320;
        Bbr.CycleStart = 1000000;
        // By detection time the rest of the 50 KB flight has already drained.
        QuicCongestionControlOnDataSent(&Cc, LostBytes);
        QUIC_MAX_SENT_PACKET_METADATA Packet{};
        Packet.Metadata.Flags.IsAckEliciting = TRUE;
        Packet.Metadata.Flags.IsBbrProbe = TRUE;
        Packet.Metadata.InflightAtSend = 50000;
        Packet.Metadata.PacketLength = LostBytes;
        Packet.Metadata.PacketNumber = 1;
        auto Loss = MakeBbrLossEvent(LostBytes, 1, 10);
        Loss.TimeNow = 1100000;
        Loss.LostPackets = &Packet.Metadata;
        QuicCongestionControlOnDataLost(&Cc, &Loss);
        if (LostBytes == 1000) {
            ASSERT_EQ(Model.InflightHigh, UINT32_MAX);
            ASSERT_EQ(Model.Phase, BBR_V3_PHASE_UP);
        } else {
            ASSERT_GT(Model.InflightHigh, 40000u);
            ASSERT_EQ(Model.Phase, BBR_V3_PHASE_DOWN);
            ASSERT_EQ(Bbr.CycleStart, Loss.TimeNow);
        }
    }
}

TEST_F(BbrV3Test, ShortTermBandwidthAdaptsOncePerLossRound)
{
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_CRUISE;
    Bbr.CycleStart = 1000000;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    QuicCongestionControlOnDataSent(&Cc, 10000);
    auto Loss = MakeBbrLossEvent(1200, 1, 10);
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    auto Ack = MakeBbrAckEvent(1100000, 11, 20, 1200);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.BandwidthLow, 5600000u);
    ASSERT_EQ(BbrV3CongestionControlGetBandwidth(&Cc), 5600000u);
    uint32_t InflightLow = Model.InflightLow;
    Ack.LargestAck = 12;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.BandwidthLow, 5600000u);
    ASSERT_EQ(Model.InflightLow, InflightLow);
}

TEST_F(BbrV3Test, StartupUsesTheBandwidthPacer)
{
    Initialize(100, 1280, true);
    Bbr.MinRtt = 50000;
    Bbr.MinRttTimestampValid = TRUE;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    ASSERT_EQ(QuicCongestionControlGetSendAllowance(&Cc, 1000, TRUE), 2769u);
}

TEST_F(BbrV3Test, ProbeRttUsesHalfBdpAndACompleteRound)
{
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_CRUISE;
    Bbr.CycleStart = 5900000;
    Bbr.MinRtt = 50000;
    Bbr.MinRttTimestampValid = TRUE;
    Bbr.MinRttTimestamp = 1000000;
    Model.ProbeRttMin = 50000;
    Model.ProbeRttMinTimestamp = 1000000;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    auto Ack = MakeBbrAckEvent(6000001, 1, 100, 0, 60000, 60000);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Bbr.BbrState, (uint32_t)BBR_STATE_PROBE_RTT);
    ASSERT_EQ(QuicCongestionControlGetCongestionWindow(&Cc), 25000u);
    Ack.TimeNow += 200001;
    Ack.LargestAck = 99;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Bbr.BbrState, (uint32_t)BBR_STATE_PROBE_RTT);
    Ack.LargestAck = 101;
    Ack.LargestSentPacketNumber = 110;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Bbr.BbrState, (uint32_t)BBR_STATE_PROBE_BW);
}

TEST_F(BbrV3Test, ProbeRttRespectsModelAndRecoveryBounds)
{
    Bbr.BbrState = BBR_STATE_PROBE_RTT;
    Bbr.MinRtt = 100000;
    Bbr.MinRttTimestampValid = TRUE;
    Model.InflightHigh = 10000;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    ASSERT_EQ(QuicCongestionControlGetCongestionWindow(&Cc), 8500u);
    QuicCongestionControlOnDataSent(&Cc, 1200);
    auto Loss = MakeBbrLossEvent(1200, 1, 2, TRUE);
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    ASSERT_EQ(QuicCongestionControlGetCongestionWindow(&Cc),
        4u * QuicPathGetDatagramPayloadSize(&Connection.Paths[0]));
}

TEST_F(BbrV3Test, ProbeLossCannotRaiseBoundFromStaleBandwidth)
{
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_UP;
    Model.ProbeSamples = TRUE;
    Model.InflightHigh = 10000;
    Bbr.MinRtt = 100000;
    Bbr.MinRttTimestampValid = TRUE;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    QUIC_MAX_SENT_PACKET_METADATA Packet{};
    Packet.Metadata.Flags.IsAckEliciting = TRUE;
    Packet.Metadata.Flags.IsBbrProbe = TRUE;
    Packet.Metadata.PacketNumber = 1;
    Packet.Metadata.PacketLength = 1200;
    Packet.Metadata.InflightAtSend = 10000;
    QuicCongestionControlOnDataSent(&Cc, 1200);
    auto Loss = MakeBbrLossEvent(1200, 1, 10);
    Loss.LostPackets = &Packet.Metadata;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    ASSERT_LE(Model.InflightHigh, 10000u);
}

TEST_F(BbrV3Test, RecoveryRestoresWindowBeforeModelCaps)
{
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_CRUISE;
    Bbr.CycleStart = 1000000;
    Bbr.MinRtt = 100000;
    Bbr.MinRttTimestampValid = TRUE;
    Bbr.MinRttTimestamp = 1000000;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    QuicCongestionControlOnDataSent(&Cc, 2400);
    auto Loss = MakeBbrLossEvent(1200, 1, 10);
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    auto Ack = MakeBbrAckEvent(1100000, 2, 10, 1200);
    Ack.HasLoss = TRUE;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_LE(Bbr.CongestionWindow, 4u * QuicPathGetDatagramPayloadSize(&Connection.Paths[0]));
    // A clean round permits normal recovery exit; the current model still bounds it.
    Model.LossInRound = FALSE;
    Model.InflightLow = 40000;
    Ack.LargestAck = 11;
    Ack.LargestSentPacketNumber = 12;
    Ack.NumRetransmittableBytes = 0;
    Ack.HasLoss = FALSE;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(QuicCongestionControlGetCongestionWindow(&Cc), 40000u);
}

TEST_F(BbrV3Test, LargeBdpSaturatesWithoutWrapping)
{
    Bbr.MinRtt = UINT64_MAX / 2;
    Bbr.MinRttTimestampValid = TRUE;
    QuicSlidingWindowExtremumUpdateMax(&Bbr.BandwidthFilter.WindowedMaxFilter, 8000000, 0);
    ASSERT_EQ(BbrV3CongestionControlGetTargetCwnd(&Cc, 512), UINT32_MAX);
}

TEST_F(BbrV3Test, WindowLimitedProbeGrowsInsteadOfDeclaringPlateau)
{
    Bbr.BtlbwFound = TRUE;
    Bbr.BbrState = BBR_STATE_PROBE_BW;
    Model.Phase = BBR_V3_PHASE_UP;
    Model.ProbeSamples = TRUE;
    Model.ProbeStartPacketNumber = 101;
    Model.InflightHigh = 10000;
    Model.ProbeUpCount = 10000;
    Bbr.CongestionWindow = 10000;
    Bbr.EndOfRoundTripValid = TRUE;
    Bbr.EndOfRoundTrip = 100;
    Bbr.SlowStartupRoundCounter = 2;
    Bbr.LastEstimatedStartupBandwidth = 8000000;
    Bbr.PacingGain = 320;
    Bbr.CwndGain = 512;
    auto Packet = MakeBbrPacket(5000, TRUE, FALSE,
        6000, 1000000, 1000, 995000, 0, 1045000, 1045000);
    Packet.Metadata.PacketNumber = 101;
    Packet.Metadata.InflightAtSend = 10000;
    Packet.Metadata.Flags.IsBbrProbe = TRUE;
    QuicCongestionControlOnDataSent(&Cc, 10000);
    auto Ack = MakeBbrAckEvent(1050000, 101, 200, 5000);
    Ack.AckedPackets = &Packet.Metadata;
    QuicCongestionControlOnDataAcknowledged(&Cc, &Ack);
    ASSERT_EQ(Model.Phase, BBR_V3_PHASE_UP);
    ASSERT_EQ(Bbr.SlowStartupRoundCounter, 0u);
    ASSERT_EQ(Model.InflightHigh, 10000u + QuicPathGetDatagramPayloadSize(&Connection.Paths[0]));
    ASSERT_EQ(QuicCongestionControlGetCongestionWindow(&Cc), Model.InflightHigh);
}

TEST_F(BbrV3Test, AggregateLossUsesPacketConservationWithoutInventingProbeBound)
{
    Initialize(10);
    const uint32_t InitialWindow = Bbr.CongestionWindow;
    const uint32_t LostBytes = 2 * QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    QuicCongestionControlOnDataSent(&Cc, InitialWindow);
    auto Loss = MakeBbrLossEvent(LostBytes, 5, 10);
    QuicCongestionControlOnDataLost(&Cc, &Loss);

    ASSERT_EQ(Model.InflightHigh, UINT32_MAX);
    ASSERT_EQ(Bbr.RecoveryWindow, InitialWindow - LostBytes);
}

} // namespace
