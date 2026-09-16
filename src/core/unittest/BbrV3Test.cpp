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

#include "main.h"

namespace {

constexpr uint32_t BbrStateProbeBw = 2;
constexpr uint32_t BbrStateProbeRtt = 3;
constexpr uint32_t BbrRecoveryNone = 0;
constexpr uint64_t TestTime = 1000000;

class BbrV3Test : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection{};
    QUIC_CONGESTION_CONTROL& Cc = Connection.CongestionControl;
    QUIC_CONGESTION_CONTROL_BBR& Bbr = Cc.Bbr;

    void SetUp() override {
        Connection._.Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection.PathsCount = 1;
        Connection.Paths[0].Mtu = 1280;
        Connection.Paths[0].IsActive = TRUE;
        Connection.Paths[0].IsPeerValidated = TRUE;
        Connection.Paths[0].SmoothedRtt = 50000;
        Connection.Settings.InitialWindowPackets = 100;
        Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR_V3;
        Connection.Send.PeerMaxData = UINT64_MAX;
        CxPlatListInitializeHead(&Connection.Send.SendStreams);
        BbrCongestionControlInitializeV3(&Cc, &Connection.Settings);
    }

    void EnterCruise() {
        Bbr.BtlbwFound = TRUE;
        Bbr.BbrState = BbrStateProbeBw;
        Bbr.PacingGain = 256;
        Bbr.CwndGain = 512;
        Bbr.CycleStart = TestTime;
        Bbr.MinRtt = 50000;
        Bbr.MinRttTimestamp = TestTime;
        Bbr.MinRttTimestampValid = TRUE;
        Bbr.V3.ProbeRttMin = 50000;
        Bbr.V3.ProbeRttMinTimestamp = TestTime;
        Bbr.V3.Phase = BBR_V3_PHASE_CRUISE;
        Bbr.V3.ProbeWait = 3000000;
        Bbr.V3.ProbeSamples = FALSE;
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
        Packet.TotalBytesLost = Bbr.V3.TotalBytesLost;
        return Storage;
    }

    QUIC_ACK_EVENT Ack(uint32_t Bytes, uint64_t Number = 1) {
        QUIC_ACK_EVENT Event{};
        Event.TimeNow = TestTime + 1;
        Event.AdjustedAckTime = Event.TimeNow;
        Event.LargestAck = Number;
        Event.LargestSentPacketNumber = 100;
        Event.NumRetransmittableBytes = Bytes;
        Event.NumTotalAckedRetransmittableBytes = Bytes;
        Event.SmoothedRtt = 50000;
        Event.MinRtt = 50000;
        Event.MinRttValid = TRUE;
        return Event;
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
    Bbr.V3.TotalBytesLost = 456;
    SendPacket(1, 1200);
    const auto* First = Connection.LossDetection.SentPackets;
    ASSERT_NE(First, nullptr);
    EXPECT_EQ(First->InflightAtSend, 1200u);
    EXPECT_EQ(First->TotalBytesLost, 456u);
    EXPECT_TRUE(First->Flags.IsBbrProbe);

    Bbr.V3.TotalBytesLost = 789;
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
    Bbr.V3.Phase = BBR_V3_PHASE_UP;
    Bbr.V3.ProbeSamples = TRUE;
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

    EXPECT_EQ(Bbr.V3.TotalBytesLost, 3600u);
    EXPECT_EQ(Bbr.BytesInFlight, 96400u);
    EXPECT_GT(Bbr.V3.InflightHigh, 90000u);
    EXPECT_LT(Bbr.V3.InflightHigh, UINT32_MAX);
    EXPECT_EQ(Bbr.V3.Phase, BBR_V3_PHASE_DOWN);
    // DOWN starts a fresh short-term round after adapting the probe bound.
    EXPECT_FALSE(Bbr.V3.LossInRound);
}

TEST_F(BbrV3Test, CruiseTailLossDoesNotCollapseLongTermInflightBound)
{
    EnterCruise();
    Bbr.V3.InflightHigh = 60000;
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
    EXPECT_EQ(Bbr.V3.InflightHigh, 60000u);
    EXPECT_EQ(Bbr.V3.Phase, BBR_V3_PHASE_CRUISE);
}

TEST_F(BbrV3Test, PartialResetRetainsLossCounterAndRejectsOldPathSamples)
{
    Bbr.V3.TotalBytesLost = 9000;
    QuicCongestionControlOnDataSent(&Cc, 5000);
    auto Storage = LossPacket(10, 1200);
    auto& OldPacket = Storage.Metadata;
    OldPacket.InflightAtSend = 1200;
    Connection.Send.NextPacketNumber = 20;
    Connection.LossDetection.LargestSentPacketNumber = 19;
    QuicCongestionControlReset(&Cc, FALSE);
    EXPECT_EQ(Bbr.BytesInFlight, 5000u);
    EXPECT_EQ(Bbr.V3.TotalBytesLost, 9000u);
    EXPECT_EQ(Bbr.V3.MinValidPacketNumber, 20u);

    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &OldPacket;
    Loss.NumRetransmittableBytes = 1200;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 19;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    EXPECT_EQ(Bbr.BytesInFlight, 3800u);
    // Old-path losses leave flight, but cannot pollute the new path's samples.
    EXPECT_EQ(Bbr.V3.TotalBytesLost, 9000u);
    EXPECT_EQ(Bbr.V3.InflightHigh, UINT32_MAX);
    EXPECT_FALSE(Bbr.V3.LossInRound);
    EXPECT_FALSE(Bbr.V3.ExcessiveLossInRound);
    EXPECT_EQ(Bbr.V3.StartupLossEvents, 0u);
}

TEST_F(BbrV3Test, SpuriousLossRestoresBoundsAndRecoveryWithoutDoubleAck)
{
    EnterCruise();
    Bbr.V3.Phase = BBR_V3_PHASE_UP;
    Bbr.V3.ProbeSamples = TRUE;
    Bbr.PacingGain = 320;
    Bbr.V3.InflightHigh = 100000;
    Bbr.V3.InflightLow = 90000;
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
    ASSERT_LT(Bbr.V3.InflightHigh, 100000u);
    ASSERT_LT(Bbr.V3.InflightLow, 90000u);
    ASSERT_NE(Bbr.RecoveryState, BbrRecoveryNone);

    QuicCongestionControlOnSpuriousCongestionEvent(&Cc);
    EXPECT_EQ(Bbr.V3.InflightHigh, 100000u);
    EXPECT_EQ(Bbr.V3.InflightLow, 90000u);
    EXPECT_GE(Bbr.CongestionWindow, PriorWindow);
    EXPECT_EQ(Bbr.RecoveryState, BbrRecoveryNone);
    EXPECT_EQ(Bbr.BbrState, BbrStateProbeBw);
    EXPECT_EQ(Bbr.V3.Phase, BBR_V3_PHASE_UP);
    EXPECT_EQ(Bbr.PacingGain, 320u);
    EXPECT_FALSE(Bbr.V3.UndoValid);

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
    Bbr.V3.TotalBytesLost = 9000;
    QuicCongestionControlOnDataSent(&Cc, 100000);
    auto OldStorage = LossPacket(10, 1200);
    Connection.Send.NextPacketNumber = 20;
    Connection.LossDetection.LargestSentPacketNumber = 19;
    QuicCongestionControlReset(&Cc, FALSE);
    EnterCruise();
    Bbr.V3.Phase = BBR_V3_PHASE_UP;
    Bbr.V3.ProbeSamples = TRUE;
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
    EXPECT_EQ(Bbr.V3.TotalBytesLost, 10200u);
    EXPECT_FALSE(Bbr.V3.ExcessiveLossInRound);
    EXPECT_EQ(Bbr.V3.InflightHigh, UINT32_MAX);
    EXPECT_EQ(Bbr.V3.Phase, BBR_V3_PHASE_UP);
    EXPECT_EQ(Bbr.BytesInFlight, 97600u);
}

TEST_F(BbrV3Test, SpuriousProbeLossDoesNotInterruptProbeRtt)
{
    EnterCruise();
    Bbr.V3.Phase = BBR_V3_PHASE_UP;
    Bbr.V3.ProbeSamples = TRUE;
    Bbr.PacingGain = 320;
    Bbr.V3.InflightHigh = 100000;
    QuicCongestionControlOnDataSent(&Cc, 60000);
    auto Storage = LossPacket(10, 2400);
    QUIC_LOSS_EVENT Loss{};
    Loss.TimeNow = TestTime;
    Loss.LostPackets = &Storage.Metadata;
    Loss.NumRetransmittableBytes = 2400;
    Loss.LargestPacketNumberLost = 10;
    Loss.LargestSentPacketNumber = 50;
    QuicCongestionControlOnDataLost(&Cc, &Loss);
    ASSERT_LT(Bbr.V3.InflightHigh, 100000u);

    // MinRTT sampling may start while the lost probe is still awaiting an ACK.
    Bbr.BbrState = BbrStateProbeRtt;
    Bbr.PacingGain = 256;
    Bbr.CwndGain = 256;
    Bbr.ProbeRttEndTimeValid = TRUE;
    Bbr.ProbeRttEndTime = TestTime + 200000;
    QuicCongestionControlOnSpuriousCongestionEvent(&Cc);
    EXPECT_EQ(Bbr.V3.InflightHigh, 100000u);
    EXPECT_EQ(Bbr.RecoveryState, BbrRecoveryNone);
    EXPECT_EQ(Bbr.BbrState, BbrStateProbeRtt);
    EXPECT_EQ(Bbr.PacingGain, 256u);
    EXPECT_EQ(Bbr.CwndGain, 256u);
    EXPECT_TRUE(Bbr.ProbeRttEndTimeValid);
    EXPECT_EQ(Bbr.ProbeRttEndTime, TestTime + 200000);
}

TEST_F(BbrV3Test, CleanAckDoesNotRelaxShortTermInflightBound)
{
    EnterCruise();
    Bbr.V3.InflightLow = 20000;
    Bbr.EndOfRoundTripValid = TRUE;
    Bbr.EndOfRoundTrip = 100;
    QuicCongestionControlOnDataSent(&Cc, 1200);
    auto Event = Ack(1200, 10);
    QuicCongestionControlOnDataAcknowledged(&Cc, &Event);
    EXPECT_EQ(Bbr.V3.InflightLow, 20000u);
    EXPECT_EQ(Bbr.V3.Phase, BBR_V3_PHASE_CRUISE);
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
    const auto PriorProbeRttMin = Bbr.V3.ProbeRttMin;

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
    EXPECT_EQ(Bbr.V3.ProbeRttMin, PriorProbeRttMin);
    EXPECT_EQ(Bbr.RoundTripCounter, 0u);
    EXPECT_FALSE(Bbr.EndOfRoundTripValid);
    EXPECT_EQ(Bbr.V3.BandwidthLatest, 0u);
    EXPECT_EQ(Bbr.V3.InflightLatest, 0u);
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
    EXPECT_EQ(Bbr.V3.ProbeRttMin, 45000u);
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
        BbrCongestionControlInitializeV3(&Cc, &Connection.Settings);
        EnterCruise();
        Bbr.V3.Phase = BBR_V3_PHASE_UP;
        Bbr.V3.ProbeSamples = TRUE;
        Bbr.PacingGain = 320;
        Bbr.CongestionWindow = 100000;
        Bbr.RecoveryState = BbrRecoveryNone;
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

        EXPECT_GE(Bbr.V3.InflightHigh, 70000u);
        if (PreviousHigh != 0) {
            EXPECT_EQ(Bbr.V3.InflightHigh, PreviousHigh);
        }
        PreviousHigh = Bbr.V3.InflightHigh;
    }
}

} // namespace
