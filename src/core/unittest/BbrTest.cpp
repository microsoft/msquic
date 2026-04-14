/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for BBR congestion control.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "BbrTest.cpp.clog.h"
#endif

extern "C" {
void BbrCongestionControlInitialize(QUIC_CONGESTION_CONTROL* Cc, const QUIC_SETTINGS_INTERNAL* Settings);
uint64_t BbrCongestionControlGetBandwidth(const QUIC_CONGESTION_CONTROL* Cc);
}

//
// State definitions mirrored from bbr.c for readable assertions.
//
enum BBR_STATE {
    BBR_STATE_STARTUP   = 0,
    BBR_STATE_DRAIN     = 1,
    BBR_STATE_PROBE_BW  = 2,
    BBR_STATE_PROBE_RTT = 3
};

enum RECOVERY_STATE {
    RECOVERY_STATE_NOT_RECOVERY = 0,
    RECOVERY_STATE_CONSERVATIVE = 1,
    RECOVERY_STATE_GROWTH       = 2
};

//
// Tracks the most recent NETWORK_STATISTICS event delivered by the callback.
//
static bool NetStatsCallbackInvoked = false;
static QUIC_NETWORK_STATISTICS LastNetStats = {};

static
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
DummyConnectionCallback(
    _In_ HQUIC /* Connection */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    if (Event->Type == QUIC_CONNECTION_EVENT_NETWORK_STATISTICS) {
        NetStatsCallbackInvoked = true;
        LastNetStats = Event->NETWORK_STATISTICS;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Reuse helpers matching CubicTest.cpp conventions.
//
static void InitBbrMockConnection(
    QUIC_CONNECTION& Connection,
    uint16_t Mtu)
{
    Connection.Paths[0].Mtu = Mtu;
    Connection.Paths[0].IsActive = TRUE;
    Connection.Send.NextPacketNumber = 0;
    Connection.Settings.PacingEnabled = FALSE;
    Connection.Settings.HyStartEnabled = FALSE;
    Connection.Settings.NetStatsEventEnabled = FALSE;
    Connection.Paths[0].GotFirstRttSample = FALSE;
    Connection.Paths[0].SmoothedRtt = 0;
    Connection.Paths[0].OneWayDelay = 0;
    Connection.Stats.Send.CongestionCount = 0;
    Connection.Stats.Send.PersistentCongestionCount = 0;
    Connection.Send.PeerMaxData = UINT64_MAX;
    Connection.Send.OrderedStreamBytesSent = 0;
    Connection.SendBuffer.PostedBytes = 0;
    Connection.SendBuffer.IdealBytes = 0;
    Connection.Stats.Send.TotalBytes = 0;
    Connection.LossDetection.LargestSentPacketNumber = 0;
}

static QUIC_ACK_EVENT MakeBbrAckEvent(
    uint64_t TimeNow,
    uint64_t LargestAck,
    uint64_t LargestSentPacketNumber,
    uint32_t BytesAcked,
    uint64_t SmoothedRtt = 50000,
    uint64_t MinRtt = 45000,
    BOOLEAN MinRttValid = TRUE)
{
    QUIC_ACK_EVENT Ack{};
    Ack.TimeNow = TimeNow;
    Ack.LargestAck = LargestAck;
    Ack.LargestSentPacketNumber = LargestSentPacketNumber;
    Ack.NumRetransmittableBytes = BytesAcked;
    Ack.NumTotalAckedRetransmittableBytes = BytesAcked;
    Ack.SmoothedRtt = SmoothedRtt;
    Ack.MinRtt = MinRtt;
    Ack.MinRttValid = MinRttValid;
    Ack.AdjustedAckTime = TimeNow;
    return Ack;
}

static QUIC_LOSS_EVENT MakeBbrLossEvent(
    uint32_t LostBytes,
    uint64_t LargestPacketNumberLost,
    uint64_t LargestSentPacketNumber,
    BOOLEAN PersistentCongestion = FALSE)
{
    QUIC_LOSS_EVENT Loss{};
    Loss.NumRetransmittableBytes = LostBytes;
    Loss.LargestPacketNumberLost = LargestPacketNumberLost;
    Loss.LargestSentPacketNumber = LargestSentPacketNumber;
    Loss.PersistentCongestion = PersistentCongestion;
    return Loss;
}

static QUIC_MAX_SENT_PACKET_METADATA MakeBbrPacket(
    uint16_t PacketLength,
    BOOLEAN HasLastAckedPacketInfo,
    BOOLEAN IsAppLimited,
    uint64_t TotalBytesSent,
    uint64_t SentTime,
    uint64_t LastTotalBytesSent = 0,
    uint64_t LastSentTime = 0,
    uint64_t LastTotalBytesAcked = 0,
    uint64_t LastAdjustedAckTime = 0,
    uint64_t LastAckTime = 0)
{
    QUIC_MAX_SENT_PACKET_METADATA PacketBuf{};
    auto& Pkt = PacketBuf.Metadata;
    Pkt.PacketLength = PacketLength;
    Pkt.Flags.HasLastAckedPacketInfo = HasLastAckedPacketInfo;
    Pkt.Flags.IsAppLimited = IsAppLimited;
    Pkt.TotalBytesSent = TotalBytesSent;
    Pkt.SentTime = SentTime;
    Pkt.LastAckedPacketInfo.TotalBytesSent = LastTotalBytesSent;
    Pkt.LastAckedPacketInfo.SentTime = LastSentTime;
    Pkt.LastAckedPacketInfo.TotalBytesAcked = LastTotalBytesAcked;
    Pkt.LastAckedPacketInfo.AdjustedAckTime = LastAdjustedAckTime;
    Pkt.LastAckedPacketInfo.AckTime = LastAckTime;
    Pkt.Next = NULL;
    return PacketBuf;
}

//
// GoogleTest fixture for BBR congestion control tests.
//
class BbrTest : public ::testing::Test {
protected:
    static constexpr uint16_t kIPv6UdpOverhead = 48;

    QUIC_CONNECTION Connection{};
    QUIC_SETTINGS_INTERNAL Settings{};
    QUIC_CONGESTION_CONTROL_BBR* Bbr;
    QUIC_CONGESTION_CONTROL* CC;

    void InitializeWithDefaults(
        uint32_t WindowPackets = 10,
        uint16_t Mtu = 1280,
        bool PacingEnabled = false,
        bool NetStatsEnabled = false)
    {
        Settings.InitialWindowPackets = WindowPackets;
        InitBbrMockConnection(Connection, Mtu);
        Connection.Settings.PacingEnabled = PacingEnabled ? TRUE : FALSE;
        Connection.Settings.NetStatsEventEnabled = NetStatsEnabled ? TRUE : FALSE;
        if (NetStatsEnabled) {
            Connection.ClientCallbackHandler = DummyConnectionCallback;
            NetStatsCallbackInvoked = false;
            LastNetStats = {};
        }
        CC = &Connection.CongestionControl;
        BbrCongestionControlInitialize(CC, &Settings);
        Bbr = &CC->Bbr;
    }

    //
    // Helper: Pump a bandwidth sample into the BBR filter via OnDataAcknowledged.
    // Constructs packet metadata so that BbrBandwidthFilterOnPacketAcked
    // computes DeliveryRate = BW_UNIT * SendRate_BytesPerSec.
    // Returns the TimeNow used so callers can build on it.
    //
    // Key invariant: SendRate == AckRate == BW_UNIT * SendRate_BytesPerSec.
    //   SendElapsedUs = BytesAcked * 1e6 / SendRate_BytesPerSec
    //   AckElapsed = SendElapsedUs (by construction: LastAdjustedAckTime = TimeNow - SendElapsedUs)
    //
    uint64_t PumpBandwidthSample(
        uint64_t TimeNow,
        uint64_t PacketNumber,
        uint32_t BytesAcked,
        uint64_t SendRate_BytesPerSec,
        uint64_t MinRttUs = 45000)
    {
        uint64_t SendElapsedUs = (uint64_t)BytesAcked * 1000000ULL / SendRate_BytesPerSec;
        if (SendElapsedUs == 0) SendElapsedUs = 1;

        auto PacketBuf = MakeBbrPacket(
            (uint16_t)BytesAcked, TRUE, FALSE,
            10000 + BytesAcked, TimeNow - MinRttUs,
            10000, TimeNow - MinRttUs - SendElapsedUs,
            0, TimeNow - SendElapsedUs, TimeNow - SendElapsedUs);
        auto& Packet = PacketBuf.Metadata;

        CC->QuicCongestionControlOnDataSent(CC, BytesAcked);

        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(
            TimeNow, PacketNumber, PacketNumber + 1, BytesAcked,
            50000, (uint32_t)MinRttUs, TRUE);
        Ack.AckedPackets = &Packet;
        Ack.IsLargestAckedPacketAppLimited = FALSE;

        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
        return TimeNow;
    }

    //
    // Helper: drive BBR through STARTUP to detect BtlbwFound by sending
    // rounds with non-growing bandwidth. Returns the TimeNow after transitions.
    //
    // To trigger BtlbwFound:
    // 1. NewRoundTrip must be TRUE: LargestAck must exceed EndOfRoundTrip
    // 2. LastAckedPacketAppLimited must be FALSE: AckedPackets != NULL
    // 3. After initial bandwidth sets LastEstimatedStartupBandwidth,
    //    the next 3 rounds must have CurrentBandwidth < LastEstimatedStartupBandwidth * 5/4
    //
    uint64_t DriveToBtlbwFound(uint64_t StartTime = 1000000)
    {
        uint64_t TimeNow = StartTime;

        // Each "round" needs: send data, ack it with a bandwidth sample,
        // and LargestAck > previous EndOfRoundTrip (= previous LargestSentPacketNumber).

        // Round 1: Establish bandwidth in the filter.
        // Send 12000 bytes over 100ms => rate ~120KB/s => BW_UNIT*120000 bps in filter
        {
            auto PacketBuf = MakeBbrPacket(
                1200, TRUE, FALSE,
                12000, TimeNow,
                0, TimeNow - 100000,
                0, TimeNow - 50000, TimeNow - 50000);
            auto& Pkt = PacketBuf.Metadata;

            CC->QuicCongestionControlOnDataSent(CC, 1200);
            TimeNow += 50000;

            QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, 10, 20, 1200, 50000, 45000, TRUE);
            Ack.AckedPackets = &Pkt;
            Ack.IsLargestAckedPacketAppLimited = FALSE;
            Ack.NumTotalAckedRetransmittableBytes = 12000;
            CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
        }
        // Now LastEstimatedStartupBandwidth = CurrentBandwidth (some value)
        // BandwidthTarget for next round = LastEstimatedStartupBandwidth * 320/256 = 1.25x

        // Rounds 2-4: Same bandwidth => CurrentBandwidth < BandwidthTarget (1.25x)
        // Each round must trigger NewRoundTrip by having LargestAck > EndOfRoundTrip.
        // EndOfRoundTrip was set to LargestSentPacketNumber from previous ack.
        uint64_t LargestAck = 25; // Must exceed previous EndOfRoundTrip (20)
        uint64_t LargestSent = 30;

        for (int round = 0; round < 4; round++) {
            auto PacketBuf = MakeBbrPacket(
                1200, TRUE, FALSE,
                12000, TimeNow,
                0, TimeNow - 100000,
                0, TimeNow - 50000, TimeNow - 50000);
            auto& Pkt = PacketBuf.Metadata;

            CC->QuicCongestionControlOnDataSent(CC, 1200);
            TimeNow += 50000;

            QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, LargestAck, LargestSent, 1200, 50000, 45000, TRUE);
            Ack.AckedPackets = &Pkt;
            Ack.IsLargestAckedPacketAppLimited = FALSE;
            Ack.NumTotalAckedRetransmittableBytes = 12000;
            CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

            LargestAck = LargestSent + 5; // Ensure next round's LargestAck > EndOfRoundTrip
            LargestSent += 10;

            if (Bbr->BtlbwFound) break;
        }

        return TimeNow;
    }

    //
    // Helper: enter recovery by sending data then losing some.
    //
    void EnterRecovery(uint32_t SendBytes = 5000, uint32_t LostBytes = 1200)
    {
        CC->QuicCongestionControlOnDataSent(CC, SendBytes);
        Connection.Send.NextPacketNumber = 10;

        QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(LostBytes, 5, 10);
        CC->QuicCongestionControlOnDataLost(CC, &Loss);
    }
};

//====================================================================
//
//  Specification-conformance tests
//
//  These tests validate behavior defined by the BBR congestion
//  control algorithm (draft-cardwell-iccrg-bbr-congestion-control).
//  They verify the state machine, bandwidth estimation, recovery,
//  and pacing gain cycle behavior. They would remain valid across
//  any conforming BBR implementation.
//
//  Reference:
//    https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control
//
//====================================================================

//
// Test: OnDataLost - Enter CONSERVATIVE Recovery
// Scenario: Sends 5000 bytes via OnDataSent, then triggers a loss event of 1200 bytes
// with LargestPacketNumberLost=5 and LargestSentPacketNumber=10. BBR should enter
// CONSERVATIVE recovery on the first loss event.
TEST_F(BbrTest, OnDataLost_EnterRecovery)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);

    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_CONSERVATIVE);
    ASSERT_TRUE(Bbr->EndOfRecoveryValid);
    ASSERT_EQ(Bbr->BytesInFlight, 5000u - 1200u);
}

//
// Test: OnDataLost - Persistent Congestion Sets MinCW
// Scenario: Sends 10000 bytes via OnDataSent, then triggers a loss of 3000 bytes with
// PersistentCongestion=TRUE. When persistent congestion is detected, BBR should reset
// RecoveryWindow to the minimum congestion window (4 * DatagramPayloadLength = 4928).
//
TEST_F(BbrTest, OnDataLost_PersistentCongestion)
{
    InitializeWithDefaults();
    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t MinCW = 4 * DatagramPayloadLength;

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(3000, 5, 10, TRUE);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);

    ASSERT_EQ(Bbr->RecoveryWindow, MinCW);
    ASSERT_EQ(Connection.Stats.Send.PersistentCongestionCount, 1u);
}

//
// Test: OnDataLost - Non-Persistent Loss Reduces RecoveryWindow
// Scenario: Sends 10000 bytes via OnDataSent, then triggers a non-persistent loss of
// 1200 bytes. The RecoveryWindow is max(BytesInFlight - 1200, MinCW) =
// max(8800 - 1200, 4928) = max(7600, 4928) = 7600.
//
TEST_F(BbrTest, OnDataLost_NonPersistent)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(1200, 5, 10, FALSE);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);

    // RecoveryWindow = max(BIF=8800, MinCW=4928) - 1200 = 7600
    ASSERT_EQ(Bbr->RecoveryWindow, 7600u);
    ASSERT_EQ(Connection.Stats.Send.CongestionCount, 1u);
}

//
// Test: OnDataLost - No Re-Entry When Already in Recovery
// Scenario: Sends 10000 bytes, triggers a first loss of 1200 bytes entering CONSERVATIVE
// recovery, then triggers a second loss of 600 bytes while still in recovery. BBR should
// not re-enter recovery but should adjust the RecoveryWindow.
//
TEST_F(BbrTest, OnDataLost_AlreadyInRecovery)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    // First loss
    QUIC_LOSS_EVENT Loss1 = MakeBbrLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss1);
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_CONSERVATIVE);

    // Second loss while in recovery
    QUIC_LOSS_EVENT Loss2 = MakeBbrLossEvent(600, 8, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss2);

    // Still in recovery, window adjusted
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_CONSERVATIVE);
}

//
// Test: OnDataAcknowledged - MinRtt Update on Valid Sample
// Scenario: Sends 5000 bytes via OnDataSent, then acknowledges 1200 bytes with
// MinRtt=30000us and MinRttValid=TRUE. BBR should update its MinRtt to the new
// sample.
//
TEST_F(BbrTest, OnDataAcknowledged_MinRttUpdate)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(Bbr->MinRtt, 30000u);
    ASSERT_TRUE(Bbr->MinRttTimestampValid);
}

//
// Test: OnDataAcknowledged - MinRtt Expires and Updates to New Value
// Scenario: First ACK establishes MinRtt=30000us. Second ACK arrives 11 seconds later
// (past kBbrMinRttExpirationInMicroSecs=10s) with MinRtt=50000us. Since the old MinRtt
// has expired, BBR accepts the new (larger) value.
//
TEST_F(BbrTest, OnDataAcknowledged_MinRttExpired)
{
    InitializeWithDefaults();

    // First ACK establishes MinRtt
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 1200, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);
    ASSERT_EQ(Bbr->MinRtt, 30000u);

    // Second ACK 11 seconds later - MinRtt expires (kBbrMinRttExpirationInMicroSecs = 10s)
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    uint64_t ExpiredTime = 1000000 + 11000000; // 11 seconds later
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 3, 4, 1200, 50000, 50000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    // MinRtt should be updated to the new (larger) value since old one expired
    ASSERT_EQ(Bbr->MinRtt, 50000u);
}

//
// Test: OnDataAcknowledged - MinRtt Not Updated When MinRttValid is FALSE
// Scenario: Sends 5000 bytes, then acknowledges with MinRttValid=FALSE. When the RTT
// sample is marked invalid, BBR should not update MinRtt.
//
TEST_F(BbrTest, OnDataAcknowledged_MinRttNotValid)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200, 50000, 30000, FALSE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // MinRtt should remain at UINT64_MAX since MinRttValid is FALSE
    ASSERT_EQ(Bbr->MinRtt, UINT64_MAX);
}

//
// Test: OnDataAcknowledged - MinRtt Not Updated When New Sample is Larger
// Scenario: First ACK sets MinRtt=30000us. Second ACK arrives within the expiration
// window with MinRtt=40000us. Since the new sample (40000) is larger than the
// existing MinRtt (30000) and the timer has not expired, BBR keeps the old value.
//
TEST_F(BbrTest, OnDataAcknowledged_MinRttNoUpdate)
{
    InitializeWithDefaults();

    // First ACK sets MinRtt = 30000
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 1200, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);
    ASSERT_EQ(Bbr->MinRtt, 30000u);

    // Second ACK within expiration time with larger MinRtt
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(2000000, 3, 4, 1200, 50000, 40000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    // MinRtt should NOT be updated (30000 < 40000 and not expired)
    ASSERT_EQ(Bbr->MinRtt, 30000u);
}

//
// Test: OnDataAcknowledged - New Round Trip Detection
// Scenario: Sends 5000 bytes via OnDataSent, then acknowledges 1200 bytes with
// LargestAck=5. Since this is the first ACK, it triggers a new round trip.
//
TEST_F(BbrTest, OnDataAcknowledged_NewRoundTrip)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // EndOfRoundTripValid should now be TRUE, RoundTripCounter incremented
    ASSERT_TRUE(Bbr->EndOfRoundTripValid);
    ASSERT_EQ(Bbr->RoundTripCounter, 1u);
}

//
// Test: OnDataAcknowledged - Recovery Transition CONSERVATIVE to GROWTH
// Scenario: Enters CONSERVATIVE recovery via a 1200-byte loss from 10000 bytes in
// flight. Then sends 5000 more bytes and ACKs 1200 with HasLoss=TRUE and LargestAck=15
// (triggering a new round trip while still in recovery). The new round trip causes
// RecoveryState to transition from CONSERVATIVE to GROWTH.
//
TEST_F(BbrTest, OnDataAcknowledged_RecoveryConservativeToGrowth)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    // Enter recovery
    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_CONSERVATIVE);

    // ACK that triggers a new round trip while in recovery and has loss
    Connection.Send.NextPacketNumber = 20;
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1100000, 15, 20, 1200);
    Ack.HasLoss = TRUE; // Stay in recovery
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_GROWTH);
}

//
// Test: OnDataAcknowledged - Recovery Exit on No-Loss ACK Past Recovery Point
// Scenario: Enters CONSERVATIVE recovery via a 1200-byte loss. Then ACKs with
// HasLoss=FALSE and LargestAck=15 (exceeding EndOfRecovery). With no ongoing loss
// and the ACK past the recovery point, BBR should exit recovery.
//
TEST_F(BbrTest, OnDataAcknowledged_RecoveryExit)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    // Enter recovery
    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_CONSERVATIVE);

    // ACK past recovery point with no loss
    Connection.Send.NextPacketNumber = 20;
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1200000, 15, 25, 1200);
    Ack.HasLoss = FALSE;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_NOT_RECOVERY);
}

//
// Test: OnDataAcknowledged - Stay in Recovery When Loss Continues
// Scenario: Enters CONSERVATIVE recovery via a 1200-byte loss from 10000 bytes in
// flight. Then ACKs 1200 bytes with HasLoss=TRUE and LargestAck=3 (below EndOfRecovery).
// Since loss is still present and the ACK hasn't passed the recovery point, BBR stays
// in recovery and updates the RecoveryWindow.
//
TEST_F(BbrTest, OnDataAcknowledged_RecoveryStayUpdateWindow)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    // Enter recovery
    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);

    // ACK while still in recovery (HasLoss=TRUE, LargestAck < EndOfRecovery)
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1100000, 3, 12, 1200);
    Ack.HasLoss = TRUE;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // Should still be in recovery
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_CONSERVATIVE);
}

//
// Test: OnDataAcknowledged - Transition to PROBE_RTT When MinRtt Expires
// Scenario: First ACK at T=1000000 establishes MinRtt=30000 and sets MinRttTimestamp.
// Second ACK arrives 11 seconds later (past the 10s expiration). With
// ExitingQuiescence=FALSE, the expired MinRtt triggers a transition to BBR_STATE_PROBE_RTT.
//
TEST_F(BbrTest, OnDataAcknowledged_TransitToProbeRtt)
{
    InitializeWithDefaults();

    // First ACK establishes MinRtt and MinRttTimestamp
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 1200, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);
    ASSERT_TRUE(Bbr->MinRttTimestampValid);

    // Second ACK after MinRtt expiration (10s+), triggers PROBE_RTT
    // ExitingQuiescence must be FALSE (it is after first ack)
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    uint64_t ExpiredTime = 1000000 + 11000000;
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 3, 4, 1200, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_RTT);
}

//
// Test: OnDataAcknowledged - ExitingQuiescence Suppresses PROBE_RTT
// Scenario: Establishes MinRtt via first ACK, then drains BytesInFlight to 0 and sets
// AppLimited. The next OnDataSent sets ExitingQuiescence=TRUE (BytesInFlight was 0 and
// AppLimited). An ACK 11 seconds later with expired MinRtt would normally trigger
// PROBE_RTT, but ExitingQuiescence suppresses the transition and is then cleared.
//
TEST_F(BbrTest, OnDataAcknowledged_ExitingQuiescenceSuppressesProbeRtt)
{
    InitializeWithDefaults();

    // First ACK establishes MinRtt
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 1200, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);

    // Now set app limited + zero BytesInFlight to trigger ExitingQuiescence on next send
    // First ack all inflight data
    CC->QuicCongestionControlOnDataSent(CC, 3800);
    QUIC_ACK_EVENT AckAll = MakeBbrAckEvent(1050000, 5, 6, 3800 + 5000 - 1200);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckAll);

    CC->QuicCongestionControlSetAppLimited(CC);

    // Now send+ack with expired MinRtt but ExitingQuiescence = TRUE
    CC->QuicCongestionControlOnDataSent(CC, 5000); // This should set ExitingQuiescence
    uint64_t ExpiredTime = 1000000 + 11000000;
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 10, 12, 1200, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    // ExitingQuiescence suppressed PROBE_RTT, then was cleared
    ASSERT_FALSE(Bbr->ExitingQuiescence);
    // The key assertion: BbrState should NOT be PROBE_RTT
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
}

//
// Test: OnDataAcknowledged - BtlbwFound Detection in STARTUP
// Scenario: Drives BBR through STARTUP using DriveToBtlbwFound(), which pumps multiple
// rounds of stagnant bandwidth (below the 1.25x growth target). After enough consecutive
// non-growing rounds, BBR detects that bottleneck bandwidth has been found.
//
TEST_F(BbrTest, OnDataAcknowledged_BtlbwFoundDetection)
{
    InitializeWithDefaults();
    DriveToBtlbwFound();
    // After driving with stagnant bandwidth, BtlbwFound should be TRUE
    ASSERT_TRUE(Bbr->BtlbwFound);
}

//
// Test: OnDataAcknowledged - STARTUP to DRAIN Transition
// Scenario: Manually replicates BtlbwFound detection but inflates BytesInFlight to
// 100000 before the final round, so BytesInFlight > TargetCwnd and the DRAIN→PROBE_BW
// transition does NOT fire immediately. BBR should be in DRAIN after BtlbwFound.
//
TEST_F(BbrTest, OnDataAcknowledged_StartupToDrain)
{
    InitializeWithDefaults();
    uint64_t TimeNow = 1000000;

    // Round 1: Establish bandwidth in the filter.
    {
        auto PacketBuf = MakeBbrPacket(
            1200, TRUE, FALSE,
            12000, TimeNow,
            0, TimeNow - 100000,
            0, TimeNow - 50000, TimeNow - 50000);
        auto& Pkt = PacketBuf.Metadata;

        CC->QuicCongestionControlOnDataSent(CC, 1200);
        TimeNow += 50000;

        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, 10, 20, 1200, 50000, 45000, TRUE);
        Ack.AckedPackets = &Pkt;
        Ack.IsLargestAckedPacketAppLimited = FALSE;
        Ack.NumTotalAckedRetransmittableBytes = 12000;
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
    }

    // Rounds 2-4: Same bandwidth → triggers BtlbwFound after 3 non-growing rounds.
    uint64_t LargestAck = 25;
    uint64_t LargestSent = 30;

    for (int round = 0; round < 4; round++) {
        auto PacketBuf = MakeBbrPacket(
            1200, TRUE, FALSE,
            12000, TimeNow,
            0, TimeNow - 100000,
            0, TimeNow - 50000, TimeNow - 50000);
        auto& Pkt = PacketBuf.Metadata;

        CC->QuicCongestionControlOnDataSent(CC, 1200);

        // Before the last round, inflate BytesInFlight so DRAIN doesn't immediately
        // transition to PROBE_BW (requires BytesInFlight > TargetCwnd).
        if (round == 3 || (round >= 2 && Bbr->SlowStartupRoundCounter >= 2)) {
            CC->QuicCongestionControlOnDataSent(CC, 100000);
        }

        TimeNow += 50000;

        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, LargestAck, LargestSent, 1200, 50000, 45000, TRUE);
        Ack.AckedPackets = &Pkt;
        Ack.IsLargestAckedPacketAppLimited = FALSE;
        Ack.NumTotalAckedRetransmittableBytes = 12000;
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

        LargestAck = LargestSent + 5;
        LargestSent += 10;

        if (Bbr->BtlbwFound) break;
    }

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_DRAIN);
}

//
// Test: OnDataAcknowledged - DRAIN to PROBE_BW Transition
// Scenario: Calls DriveToBtlbwFound() which transitions through STARTUP → DRAIN.
// Because BytesInFlight is near zero after the helper completes, the DRAIN → PROBE_BW
// transition fires immediately upon entering DRAIN.
//
TEST_F(BbrTest, OnDataAcknowledged_DrainToProbeBw)
{
    InitializeWithDefaults();

    DriveToBtlbwFound();

    // BytesInFlight=0 after DriveToBtlbwFound so DRAIN->PROBE_BW happens immediately
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_BW);
}

//
// Test: HandleAckInProbeRtt - Start ProbeRtt Timer
// Scenario: Drives BBR to PROBE_RTT by establishing MinRtt, then sending an ACK 11
// seconds later to expire the MinRtt timer. Once in PROBE_RTT, sends 100 bytes and
// ACKs to trigger the probe RTT timer start (BytesInFlight falls below the probe
// threshold of 4*DatagramPayloadLength).
//
TEST_F(BbrTest, HandleAckInProbeRtt_StartTimer)
{
    InitializeWithDefaults();

    // Drive to PROBE_RTT state
    CC->QuicCongestionControlOnDataSent(CC, 2000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 2000, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);

    // Trigger PROBE_RTT via expired MinRtt (keep BytesInFlight low)
    CC->QuicCongestionControlOnDataSent(CC, 1000);
    uint64_t ExpiredTime = 1000000 + 11000000;
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 3, 4, 1000, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    CC->QuicCongestionControlOnDataSent(CC, 100);
    QUIC_ACK_EVENT ProbeAck = MakeBbrAckEvent(ExpiredTime + 1000, 7, 8, 100);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &ProbeAck);

    ASSERT_TRUE(Bbr->ProbeRttEndTimeValid);
}

//
// Test: HandleAckInProbeRtt - Exit PROBE_RTT to STARTUP
// Scenario: Drives BBR to PROBE_RTT state via expired MinRtt. Then pumps small
// send/ack pairs (100 bytes each) over 20 iterations until the ProbeRtt timer expires
// and BBR exits. With BtlbwFound=FALSE (never detected bottleneck bandwidth), BBR
// transitions back to STARTUP.
//
TEST_F(BbrTest, HandleAckInProbeRtt_ExitToStartup)
{
    InitializeWithDefaults();

    // Establish MinRtt
    CC->QuicCongestionControlOnDataSent(CC, 2000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 2000, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);

    // Trigger PROBE_RTT via expired MinRtt
    CC->QuicCongestionControlOnDataSent(CC, 1000);
    uint64_t ExpiredTime = 1000000 + 11000000;
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 3, 4, 1000, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_RTT);

    uint64_t T = ExpiredTime;
    for (int i = 0; i < 20; i++) {
        T += 50000;
        CC->QuicCongestionControlOnDataSent(CC, 100);
        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(T, 10 + i, 20 + i, 100);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

        if (Bbr->BbrState != (uint32_t)BBR_STATE_PROBE_RTT) break;
    }

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
}

//
// Test: HandleAckInProbeRtt - Exit PROBE_RTT to PROBE_BW
// Scenario: Drives BBR to PROBE_BW via DriveToBtlbwFound() (BtlbwFound=TRUE), then
// triggers PROBE_RTT by waiting 11 seconds for MinRtt expiration. Pumps small send/ack
// pairs over 30 iterations until the ProbeRtt timer expires. With BtlbwFound=TRUE, BBR
// transitions to PROBE_BW instead of STARTUP.
//
TEST_F(BbrTest, HandleAckInProbeRtt_ExitToProbeBw)
{
    InitializeWithDefaults();

    // Drive to BtlbwFound then to PROBE_RTT
    uint64_t TimeNow = DriveToBtlbwFound();

    // Drive to PROBE_BW first
    for (int i = 0; i < 20; i++) {
        TimeNow += 50000;
        CC->QuicCongestionControlOnDataSent(CC, 1200);
        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, 200 + i, 210 + i, 1200);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
        if (Bbr->BbrState == (uint32_t)BBR_STATE_PROBE_BW) break;
    }

    // Now trigger PROBE_RTT by waiting 10+ seconds
    uint64_t ExpiredTime = TimeNow + 11000000;
    CC->QuicCongestionControlOnDataSent(CC, 1000);
    QUIC_ACK_EVENT AckExpired = MakeBbrAckEvent(ExpiredTime, 300, 310, 1000, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &AckExpired);

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_RTT);

    uint64_t T = ExpiredTime;
    for (int i = 0; i < 30; i++) {
        T += 50000;
        CC->QuicCongestionControlOnDataSent(CC, 100);
        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(T, 400 + i, 410 + i, 100);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
        if (Bbr->BbrState != (uint32_t)BBR_STATE_PROBE_RTT) break;
    }

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_BW);
}

//
// Test: BandwidthFilter - Delivery Rate with HasLastAckedPacketInfo
// Scenario: Creates a packet with HasLastAckedPacketInfo containing send/ack timing
// data (TotalBytesSent=15000, LastTotalBytesSent=10000, SendElapsed=100000us,
// AckElapsed=100000us). Pumps it through OnDataAcknowledged to update the bandwidth
// filter.
//
TEST_F(BbrTest, BandwidthFilter_WithLastAckedInfo)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(
        1200, TRUE, FALSE,
        15000, 1000000,
        10000, 900000,
        8000, 950000, 950000);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    Ack.NumTotalAckedRetransmittableBytes = 12000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)320000);
}

//
// Test: BandwidthFilter - Delivery Rate Without HasLastAckedPacketInfo
// Scenario: Creates a packet with HasLastAckedPacketInfo=FALSE and SentTime=900000.
// When no last-acked info is available, BBR computes bandwidth using TimeNow - SentTime
// as the interval. With 1200 bytes over 150000us, rate = 1200*8*1000000/150000 = 64000.
//
TEST_F(BbrTest, BandwidthFilter_NoLastAckedInfo)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(1200, FALSE, FALSE, 0, 900000);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)64000);
}

//
// Test: BandwidthFilter - Zero SendElapsed Fallback
// Scenario: Creates a packet with HasLastAckedPacketInfo where SentTime equals
// LastAckedPacketInfo.SentTime, making SendElapsed=0. When SendElapsed is zero, BBR
// uses AckElapsed to compute the delivery rate. With AckElapsed=100000us and 4000
// bytes delivered (NumTotalAcked=12000 - LastTotalBytesAcked=8000), AckRate=320000.
//
TEST_F(BbrTest, BandwidthFilter_ZeroSendElapsed)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(
        1200, TRUE, FALSE,
        15000, 1000000,
        10000, 1000000,
        8000, 950000, 950000);
    auto& Packet = PacketBuf.Metadata;
    // SentTime == LastAckedPacketInfo.SentTime → SendElapsed = 0

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    Ack.NumTotalAckedRetransmittableBytes = 12000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)320000);
}

//
// Test: BandwidthFilter - AckElapsed via Second Branch
// Scenario: Creates a packet where AdjustedAckTime (1100000) > AckEvent.AdjustedAckTime
// (1050000), triggering the second AckElapsed computation branch which uses
// AckTime - LastAckTime instead. With SendElapsed=100000us yielding SendRate=400000
// and AckElapsed=150000us yielding AckRate=213333, the min is used.
//
TEST_F(BbrTest, BandwidthFilter_AckElapsedSecondBranch)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(
        1200, TRUE, FALSE,
        15000, 1000000,
        10000, 900000,
        8000, 1100000, 900000);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    Ack.AdjustedAckTime = 1050000;
    Ack.NumTotalAckedRetransmittableBytes = 12000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)213333);
}

//
// Test: BandwidthFilter - Zero AckElapsed Uses SendRate Only
// Scenario: Creates a packet where LastAdjustedAckTime equals AckEvent.AdjustedAckTime,
// making AckElapsed=0. When AckElapsed is zero, AckRate becomes UINT64_MAX and BBR
// uses SendRate alone. With SendElapsed=100000us and 5000 sent bytes
// (TotalBytesSent=15000 - LastTotalBytesSent=10000), SendRate=400000.
// min(400000, UINT64_MAX) = 400000.
//
TEST_F(BbrTest, BandwidthFilter_ZeroAckElapsed)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(
        1200, TRUE, FALSE,
        15000, 1000000,
        10000, 900000,
        8000, 1050000, 1050000);
    auto& Packet = PacketBuf.Metadata;
    // AdjustedAckTime == AckEvent.AdjustedAckTime → normal path with 0 elapsed

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    Ack.AdjustedAckTime = 1050000;
    Ack.NumTotalAckedRetransmittableBytes = 12000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)400000);
}

//
// Test: BandwidthFilter - Zero-Length Packets Are Skipped
// Scenario: Creates a packet with PacketLength=0. BbrBandwidthFilterOnPacketAcked
// skips zero-length packets without updating the bandwidth filter. Sends 1200 bytes
// via OnDataSent and acknowledges with the zero-length packet metadata.
//
TEST_F(BbrTest, BandwidthFilter_ZeroLengthSkipped)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(0, FALSE, FALSE, 0, 0);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)0);
}

//
// Test: BandwidthFilter - Both Rates UINT64_MAX Skips Update
// Scenario: Creates a packet where SentTime equals TimeNow (TimeDiff=0), making the
// delivery rate computation produce UINT64_MAX for both SendRate and AckRate. When
// both rates are UINT64_MAX, the bandwidth filter update is skipped.
//
TEST_F(BbrTest, BandwidthFilter_BothRatesMaxSkip)
{
    InitializeWithDefaults();

    auto PacketBuf = MakeBbrPacket(1200, FALSE, FALSE, 0, 1050000);
    auto& Packet = PacketBuf.Metadata;
    // SentTime == TimeNow → TimeDiff = 0

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = &Packet;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)0);
}

//
// Test: BandwidthFilter - AppLimited Exit on ACK
// Scenario: Sets AppLimited via SetAppLimited, then sends 1200 bytes and acknowledges
// with LargestAck=100 (exceeding AppLimitedExitTarget which was set to
// NextPacketNumber at SetAppLimited time). When LargestAck exceeds the exit target,
// AppLimited is cleared.
//
TEST_F(BbrTest, BandwidthFilter_AppLimitedExit)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlSetAppLimited(CC);

    auto PacketBuf = MakeBbrPacket(1200, FALSE, FALSE, 0, 900000);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    // LargestAck > AppLimitedExitTarget triggers AppLimited = FALSE
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 100, 110, 1200);
    Ack.AckedPackets = &Packet;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_FALSE(CC->QuicCongestionControlIsAppLimited(CC));
}

//
// Test: BandwidthFilter - AppLimited Packet Does Not Replace Filter Maximum
// Scenario: Pumps a high bandwidth sample (rate=10,000,000 → BW=80,000,000 in filter
// units) to establish a filter maximum. Then sends an app-limited packet
// (IsAppLimited=TRUE) with lower delivery rate (48000). Since 48000 < 80,000,000
// and IsAppLimited=TRUE, both conditions of the update guard are FALSE,
// so the filter is NOT updated.
//
TEST_F(BbrTest, BandwidthFilter_AppLimitedNoUpdate)
{
    InitializeWithDefaults();

    // First pump a high bandwidth sample
    PumpBandwidthSample(1050000, 1, 1200, 10000000, 45000);

    uint64_t BwBefore = BbrCongestionControlGetBandwidth(CC);

    // Now send an app-limited packet with lower delivery rate
    auto PacketBuf = MakeBbrPacket(1200, FALSE, TRUE, 0, 1000000);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1200000, 10, 15, 1200);
    Ack.AckedPackets = &Packet;
    Ack.IsLargestAckedPacketAppLimited = TRUE;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // Filter maximum should NOT be replaced by the lower app-limited rate
    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), BwBefore);
}

//
// Test: BandwidthFilter - Multiple Packets in Single ACK
// Scenario: Creates two chained packets (Packet1.Next = &Packet2) with different
// timing data and acknowledges them together. Packet1 has SendRate=400000/AckRate=480000
// (DeliveryRate=min=400000) and Packet2 has a higher rate. BbrBandwidthFilterOnPacketAckedprocesses both packets
// and the filter retains the maximum.
//
TEST_F(BbrTest, BandwidthFilter_MultiplePackets)
{
    InitializeWithDefaults();

    auto Packet1Buf = MakeBbrPacket(
        1200, TRUE, FALSE,
        15000, 1000000,
        10000, 900000,
        8000, 950000, 950000);
    auto& Packet1 = Packet1Buf.Metadata;

    auto Packet2Buf = MakeBbrPacket(
        600, TRUE, FALSE,
        16200, 1010000,
        12000, 950000,
        10000, 980000, 980000);
    auto& Packet2 = Packet2Buf.Metadata;

    Packet1.Next = &Packet2;

    CC->QuicCongestionControlOnDataSent(CC, 1800);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1800);
    Ack.AckedPackets = &Packet1;
    Ack.NumTotalAckedRetransmittableBytes = 14000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)457142);
}

//
// Test: BtlbwFound - Growing Bandwidth Resets Stagnation Counter
// Scenario: Pumps 5 rounds of exponentially growing bandwidth (doubling each round from
// 500000). Since each round's bandwidth exceeds the 1.25x growth target relative to the
// previous round, the SlowStartupRoundCounter resets and BtlbwFound never triggers.
//
TEST_F(BbrTest, BtlbwFound_BandwidthGrowingResetsCounter)
{
    InitializeWithDefaults();

    uint64_t TimeNow = 1000000;
    uint64_t PktNum = 1;
    uint64_t Rate = 500000;

    // Keep growing bandwidth → SlowStartupRoundCounter should stay at 0
    for (int i = 0; i < 5; i++) {
        Rate = Rate * 2; // Double each round → well above kStartupGrowthTarget
        TimeNow += 50000;
        PumpBandwidthSample(TimeNow, PktNum++, 1200, Rate, 45000);
    }

    // BtlbwFound should still be FALSE since bandwidth keeps growing
    ASSERT_FALSE(Bbr->BtlbwFound);
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
}

//
// Test: UpdateRecoveryWindow - GROWTH State Adds Bytes
// Scenario: Enters CONSERVATIVE recovery via 1200-byte loss from 10000 bytes in flight.
// Then sends 5000 more bytes and ACKs 2000 with HasLoss=TRUE and LargestAck=15
// (new round trip triggers CONSERVATIVE → GROWTH). In GROWTH state, RecoveryWindow
// increases by BytesAcked: max(RecoveryWindow + BytesAcked, BytesInFlight + BytesAcked).
//
TEST_F(BbrTest, RecoveryWindow_GrowthAddsBytes)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 10000);
    Connection.Send.NextPacketNumber = 10;

    // Enter recovery
    QUIC_LOSS_EVENT Loss = MakeBbrLossEvent(1200, 5, 10);
    CC->QuicCongestionControlOnDataLost(CC, &Loss);

    // ACK in recovery with new round trip → CONSERVATIVE → GROWTH
    Connection.Send.NextPacketNumber = 20;
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1100000, 15, 25, 2000);
    Ack.HasLoss = TRUE;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_GROWTH);
    // RecoveryWindow = max(RecoveryWinAfterLoss + BytesAcked, BytesInFlight + BytesAcked)
    ASSERT_EQ(Bbr->RecoveryWindow, 13800u);
}

//
// Test: PROBE_BW - Pacing Gain Cycle Active After Transition
// Scenario: Drives to PROBE_BW via DriveToBtlbwFound(), then pumps up to 20 send/ack
// pairs (1200 bytes each, 50000us apart) while already in PROBE_BW. Verifies that BBR
// enters PROBE_BW and the state machine is stable under repeated send/ack cycles.
//
TEST_F(BbrTest, ProbeBw_HighGainNoAdvance)
{
    InitializeWithDefaults();

    uint64_t TimeNow = DriveToBtlbwFound();

    // Drive to PROBE_BW
    for (int i = 0; i < 20; i++) {
        TimeNow += 50000;
        CC->QuicCongestionControlOnDataSent(CC, 1200);
        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, 200 + i, 210 + i, 1200);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
        if (Bbr->BbrState == (uint32_t)BBR_STATE_PROBE_BW) break;
    }

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_BW);
}

//====================================================================
//
//  Implementation-specific tests - loosely coupled
//
//  These tests exercise MsQuic-specific features (pacing API,
//  exemptions, statistics, blocked state) but assert only through
//  public CC vtable outputs. They would survive an internal refactor.
//
//====================================================================

//
// Test: CanSend - Returns TRUE When BytesInFlight Below CongestionWindow
// Scenario: Initializes BBR with defaults (BytesInFlight=0). With no data in flight,
// BytesInFlight < CongestionWindow so sending is allowed.
//
TEST_F(BbrTest, CanSend_BelowCW)
{
    InitializeWithDefaults();
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));
}

//
// Test: CanSend - Returns TRUE With Exemptions Despite Full Window
// Scenario: Sets 5 exemptions via SetExemption, then sends CW bytes to fill the
// congestion window. Even though BytesInFlight == CW, the remaining exemptions bypass
// the congestion blocked check.
//
TEST_F(BbrTest, CanSend_WithExemptions)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);

    CC->QuicCongestionControlSetExemption(CC, 5);
    CC->QuicCongestionControlOnDataSent(CC, CW);

    // BytesInFlight == CW, but exemptions remain (5-1 from send = 4 if decremented,
    // or still > 0)
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));
}

//
// Test: CanSend - Returns FALSE When Congestion Blocked
// Scenario: Sends exactly CW bytes to fill the congestion window with no exemptions
// set. With BytesInFlight >= CW and Exemptions == 0, the connection is congestion
// blocked.
//
TEST_F(BbrTest, CanSend_Blocked)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);

    // Send exactly CW worth of data
    CC->QuicCongestionControlOnDataSent(CC, CW);
    ASSERT_FALSE(CC->QuicCongestionControlCanSend(CC));
}

//
// Test: GetSendAllowance - Returns 0 When Congestion Blocked
// Scenario: Sends CW bytes to fill the congestion window, then calls
// GetSendAllowance with TimeSinceLastSend=1000 and SlowStartup=TRUE. When the
// connection is congestion blocked (BytesInFlight >= CW), the allowance is 0.
//
TEST_F(BbrTest, GetSendAllowance_CcBlocked)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);

    CC->QuicCongestionControlOnDataSent(CC, CW);

    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 1000, TRUE);
    ASSERT_EQ(Allowance, 0u);
}

//
// Test: GetSendAllowance - No Pacing With Invalid TimeSinceLastSend
// Scenario: Sends 1000 bytes with pacing disabled, then calls GetSendAllowance with
// TimeSinceLastSend=0 and SlowStartup=FALSE. Without pacing, the allowance is simply
// CW - BytesInFlight regardless of timing.
//
TEST_F(BbrTest, GetSendAllowance_NoPacing_TimeSinceLastSendInvalid)
{
    InitializeWithDefaults();
    CC->QuicCongestionControlOnDataSent(CC, 1000);

    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 0, FALSE);
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(Allowance, CW - 1000u);
}

//
// Test: GetSendAllowance - Pacing Disabled Falls Back to Window
// Scenario: Initializes with PacingEnabled=FALSE, sends 1000 bytes, then calls
// GetSendAllowance with TimeSinceLastSend=50000 and SlowStartup=TRUE. With pacing
// disabled, allowance equals CW - BytesInFlight.
//
TEST_F(BbrTest, GetSendAllowance_PacingDisabled)
{
    InitializeWithDefaults(10, 1280, false); // PacingEnabled = FALSE
    CC->QuicCongestionControlOnDataSent(CC, 1000);

    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 50000, TRUE);
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(Allowance, CW - 1000u);
}

//
// Test: GetSendAllowance - MinRtt at UINT64_MAX With Pacing
// Scenario: Initializes with PacingEnabled=TRUE. MinRtt starts at UINT64_MAX (no RTT
// sample yet). The sentinel check in bbr.c compares MinRtt to UINT32_MAX, so
// UINT64_MAX != UINT32_MAX causes pacing to fall through to the STARTUP formula:
// max(BW*PacingGain*Time, CW*PacingGain/GAIN_UNIT - BIF). With BW=0, the first term
// is 0; the second is large (12320*739/256 - 1000 = 34564). This is capped first to
// CW-BIF=11320, then to CW>>2=3080.
//
TEST_F(BbrTest, GetSendAllowance_MinRttMax)
{
    InitializeWithDefaults(10, 1280, true); // PacingEnabled = TRUE
    CC->QuicCongestionControlOnDataSent(CC, 1000);

    // MinRtt is UINT64_MAX initially. The sentinel check compares to UINT32_MAX,
    // so it falls through to pacing code.
    // STARTUP formula: max(BW*PacingGain*Time/GAIN_UNIT, CW*PacingGain/GAIN_UNIT - BIF)
    // = max(0, 12320*739/256 - 1000) = 34564, capped to CW-BIF=11320, then CW>>2=3080.
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 50000, TRUE);
    ASSERT_EQ(Allowance, 3080u);
}

//
// Test: GetSendAllowance - MinRtt Below QUIC_SEND_PACING_INTERVAL
// Scenario: Initializes with PacingEnabled=TRUE. Establishes a very small MinRtt=500us
// via ACK (below QUIC_SEND_PACING_INTERVAL=1000us). When MinRtt is below the pacing
// interval, pacing is skipped and allowance falls back to CW - BytesInFlight.
//
TEST_F(BbrTest, GetSendAllowance_MinRttBelowPacingInterval)
{
    InitializeWithDefaults(10, 1280, true); // PacingEnabled = TRUE

    // Set a very small MinRtt via ACK
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 1, 2, 1200, 50000, 500, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
    ASSERT_EQ(Bbr->MinRtt, 500u); // < QUIC_SEND_PACING_INTERVAL (1000)

    CC->QuicCongestionControlOnDataSent(CC, 1000);
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 50000, TRUE);
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(Allowance, CW - Bbr->BytesInFlight);
}

//
// Test: GetSendAllowance - STARTUP Pacing Formula
// Scenario: Initializes with PacingEnabled=TRUE. Establishes MinRtt=5000us (above
// QUIC_SEND_PACING_INTERVAL) and some bandwidth via ACK. In STARTUP state with pacing,
// the allowance uses kHighGain (739/256) as PacingGain. Calls GetSendAllowance with
// TimeSinceLastSend=10000.
//
TEST_F(BbrTest, GetSendAllowance_StartupPacing)
{
    InitializeWithDefaults(10, 1280, true); // PacingEnabled = TRUE

    // Establish a MinRtt >= QUIC_SEND_PACING_INTERVAL and some bandwidth
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 1, 2, 1200, 50000, 5000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
    ASSERT_EQ(Bbr->MinRtt, 5000u);
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);

    // Now get send allowance with pacing
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 10000, TRUE);
    // CW=13520 after ack, BIF=3800, BW=0. Pacing: CW*739/256-BIF capped CW-BIF, CW>>2
    ASSERT_EQ(Allowance, 3380u);
}

//
// Test: GetSendAllowance - Capped by CW >> 2
// Scenario: Initializes with PacingEnabled=TRUE. Establishes MinRtt and bandwidth via
// ACK, then calls GetSendAllowance with a very large TimeSinceLastSend=10000000 to
// produce a pacing allowance exceeding CW >> 2. The allowance is capped at CW >> 2.
//
TEST_F(BbrTest, GetSendAllowance_CappedByQuarter)
{
    InitializeWithDefaults(10, 1280, true); // PacingEnabled = TRUE

    // Establish MinRtt and bandwidth
    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 1, 2, 5000, 50000, 5000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // Send with a very large TimeSinceLastSend to trigger the CW>>2 cap
    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 10000000, TRUE);
    // CW=17320 after acking 5000. CW>>2 = 4330
    ASSERT_EQ(Allowance, 4330u);
}

//
// Test: GetSendAllowance - Non-STARTUP Pacing Formula in PROBE_BW
// Scenario: Drives BBR to PROBE_BW state via DriveToBtlbwFound() with PacingEnabled=TRUE.
// In PROBE_BW, the pacing gain uses the cycle gain values instead of kHighGain. Calls
// GetSendAllowance with TimeSinceLastSend=10000.
//
TEST_F(BbrTest, GetSendAllowance_NonStartupPacing)
{
    InitializeWithDefaults(10, 1280, true);

    // Drive to PROBE_BW state with bandwidth and MinRtt established
    uint64_t TimeNow = DriveToBtlbwFound();

    for (int i = 0; i < 20; i++) {
        TimeNow += 50000;
        CC->QuicCongestionControlOnDataSent(CC, 1200);
        QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, 200 + i, 210 + i, 1200);
        CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
        if (Bbr->BbrState == (uint32_t)BBR_STATE_PROBE_BW) break;
    }

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_BW);

    uint32_t Allowance = CC->QuicCongestionControlGetSendAllowance(CC, 10000, TRUE);
    // Verify non-startup pacing produces a valid result
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(Allowance, CW >> 2);
}

//
// Test: GetCongestionWindow - Returns Normal CW in STARTUP
// Scenario: Initializes BBR with defaults in STARTUP state. GetCongestionWindow should
// return the full CongestionWindow (no recovery or PROBE_RTT reduction).
//
TEST_F(BbrTest, GetCongestionWindow_Normal)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(CW, Bbr->CongestionWindow);
}

//
// Test: GetCongestionWindow - Returns MIN(CW, RecoveryWindow) in Recovery
// Scenario: Enters recovery via EnterRecovery() helper (sends 5000, loses 1200).
// In recovery, GetCongestionWindow returns min(CongestionWindow, RecoveryWindow).
// The RecoveryWindow after loss is 4928 (MinCW).
//
TEST_F(BbrTest, GetCongestionWindow_InRecovery)
{
    InitializeWithDefaults();
    EnterRecovery();

    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(CW, 4928u);
}

//
// Test: GetCongestionWindow - Returns MinCW in PROBE_RTT
// Scenario: Drives BBR to PROBE_RTT state by establishing MinRtt, then sending an
// ACK 11 seconds later to expire the MinRtt timer. In PROBE_RTT, GetCongestionWindow
// returns the minimum congestion window (4 * DatagramPayloadLength).
//
TEST_F(BbrTest, GetCongestionWindow_ProbeRtt)
{
    InitializeWithDefaults();
    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    uint32_t MinCW = 4 * DatagramPayloadLength;

    // Drive to PROBE_RTT
    CC->QuicCongestionControlOnDataSent(CC, 2000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 2000, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);

    CC->QuicCongestionControlOnDataSent(CC, 1000);
    uint64_t ExpiredTime = 1000000 + 11000000;
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 3, 4, 1000, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_RTT);

    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    ASSERT_EQ(CW, MinCW);
}

//
// Test: GetNetworkStatistics - Returns Valid Statistics
// Scenario: Sends 5000 bytes via OnDataSent, then calls GetNetworkStatistics. The
// returned QUIC_NETWORK_STATISTICS should reflect current state.
//
TEST_F(BbrTest, GetNetworkStatistics)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_NETWORK_STATISTICS Stats{};
    CC->QuicCongestionControlGetNetworkStatistics(&Connection, CC, &Stats);

    ASSERT_EQ(Stats.BytesInFlight, 5000u);
    ASSERT_EQ(Stats.CongestionWindow, CC->QuicCongestionControlGetCongestionWindow(CC));
}

//
// Test: OnSpuriousCongestionEvent - Always Returns FALSE
// Scenario: Calls OnSpuriousCongestionEvent on a freshly initialized BBR instance.
// BBR does not implement spurious congestion event handling and always returns FALSE.
//
TEST_F(BbrTest, SpuriousCongestionEvent_ReturnsFalse)
{
    InitializeWithDefaults();
    BOOLEAN Result = CC->QuicCongestionControlOnSpuriousCongestionEvent(CC);
    ASSERT_FALSE(Result);
}

//
// Test: LogOutFlowStatus - Does Not Crash
// Scenario: Calls LogOutFlowStatus on a freshly initialized BBR instance to verify
// the logging path executes without crashing or corrupting state.
//
TEST_F(BbrTest, LogOutFlowStatus_NoCrash)
{
    InitializeWithDefaults();
    CC->QuicCongestionControlLogOutFlowStatus(CC);

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
}

//
// Test: UpdateBlockedState - Becomes Blocked After Filling Window
// Scenario: Verifies CanSend returns TRUE initially (BytesInFlight=0), then sends
// exactly CW bytes to fill the congestion window. After the send, BytesInFlight >= CW
// and the connection becomes congestion blocked.
//
TEST_F(BbrTest, UpdateBlockedState_BecameBlocked)
{
    InitializeWithDefaults();
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));

    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);
    // Sending CW bytes will block
    CC->QuicCongestionControlOnDataSent(CC, CW);
    ASSERT_FALSE(CC->QuicCongestionControlCanSend(CC));
}

//
// Test: UpdateBlockedState - Becomes Unblocked via ACK
// Scenario: Sends CW bytes to block the connection (CanSend=FALSE), then acknowledges
// CW/2 bytes. The ACK reduces BytesInFlight below CW, unblocking the connection.
//
TEST_F(BbrTest, UpdateBlockedState_BecameUnblocked)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);

    CC->QuicCongestionControlOnDataSent(CC, CW);
    ASSERT_FALSE(CC->QuicCongestionControlCanSend(CC));

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, CW / 2);
    BOOLEAN Unblocked = CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);
    ASSERT_TRUE(Unblocked);
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));
}

//
// Test: IsAppLimited - Returns FALSE Initially
// Scenario: Checks the initial AppLimited state on a freshly initialized BBR instance.
// By default, AppLimited is FALSE since no application-limited condition has been
// signaled.
//
TEST_F(BbrTest, IsAppLimited_NotLimited)
{
    InitializeWithDefaults();
    ASSERT_FALSE(CC->QuicCongestionControlIsAppLimited(CC));
}

//
// Test: SetAppLimited - Sets AppLimited When BytesInFlight <= CW
// Scenario: Calls SetAppLimited with BytesInFlight=0 (below CongestionWindow). When
// BytesInFlight is at or below CW, the AppLimited flag is set and AppLimitedExitTarget
// is recorded.
//
TEST_F(BbrTest, SetAppLimited_BelowCW)
{
    InitializeWithDefaults();
    CC->QuicCongestionControlSetAppLimited(CC);
    ASSERT_TRUE(CC->QuicCongestionControlIsAppLimited(CC));
}

//
// Test: SetAppLimited - No Effect When BytesInFlight > CW
// Scenario: Sets 10 exemptions and sends CW + 1000 bytes (exceeding the congestion
// window via exemptions). Then calls SetAppLimited. When BytesInFlight > CW, the
// AppLimited flag is not set.
//
TEST_F(BbrTest, SetAppLimited_AboveCW)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);

    // Fill beyond CW using exemptions
    CC->QuicCongestionControlSetExemption(CC, 10);
    CC->QuicCongestionControlOnDataSent(CC, CW + 1000);

    CC->QuicCongestionControlSetAppLimited(CC);
    ASSERT_FALSE(CC->QuicCongestionControlIsAppLimited(CC));
}

//
// Test: SetExemption and GetExemptions - Round Trip
// Scenario: Verifies the exemption count starts at 0, then sets it to 5 via
// SetExemption.
//
TEST_F(BbrTest, SetExemption_GetExemptions)
{
    InitializeWithDefaults();
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 0u);

    CC->QuicCongestionControlSetExemption(CC, 5);
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 5u);
}

//
// Test: GetBytesInFlightMax - Tracks Maximum BytesInFlight
// Scenario: Records the initial BytesInFlightMax, then sends 20000 bytes via
// OnDataSent (exceeding the initial max). GetBytesInFlightMax should return the
// new high-water mark.
//
TEST_F(BbrTest, GetBytesInFlightMax)
{
    InitializeWithDefaults();
    CC->QuicCongestionControlOnDataSent(CC, 20000);
    ASSERT_EQ(CC->QuicCongestionControlGetBytesInFlightMax(CC), 20000u);
}

//====================================================================
//
//  Implementation-specific tests - tightly coupled
//
//  These tests directly read internal QUIC_CONGESTION_CONTROL_BBR
//  struct fields. If the BBR implementation is refactored -- even
//  while preserving identical congestion control behavior -- these
//  tests would break.
//
//====================================================================

//
// Test: Initialize - Verifies Correct Default State
// Scenario: Initializes BBR with default settings (10 window packets, MTU=1280) and
// inspects all internal fields. Verifies Name=="BBR", BbrState==STARTUP,
// RecoveryState==NOT_RECOVERY, CongestionWindow==10*DatagramPayloadLength,
// BytesInFlight==0, Exemptions==0, RoundTripCounter==0, all validity flags are
// correctly initialized, MinRtt==UINT64_MAX, and BandwidthFilter.AppLimited==FALSE.
//
TEST_F(BbrTest, Initialize_DefaultState)
{
    InitializeWithDefaults();
    const uint16_t DatagramPayloadLength =
        QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);

    ASSERT_STREQ(CC->Name, "BBR");
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_NOT_RECOVERY);
    ASSERT_EQ(Bbr->CongestionWindow, (uint32_t)(10 * DatagramPayloadLength));
    ASSERT_EQ(Bbr->InitialCongestionWindow, (uint32_t)(10 * DatagramPayloadLength));
    ASSERT_EQ(Bbr->BytesInFlight, 0u);
    ASSERT_EQ(Bbr->Exemptions, 0u);
    ASSERT_EQ(Bbr->RoundTripCounter, 0u);
    ASSERT_FALSE(Bbr->BtlbwFound);
    ASSERT_FALSE(Bbr->ExitingQuiescence);
    ASSERT_FALSE(Bbr->EndOfRecoveryValid);
    ASSERT_FALSE(Bbr->EndOfRoundTripValid);
    ASSERT_FALSE(Bbr->AckAggregationStartTimeValid);
    ASSERT_FALSE(Bbr->ProbeRttRoundValid);
    ASSERT_FALSE(Bbr->ProbeRttEndTimeValid);
    ASSERT_TRUE(Bbr->RttSampleExpired);
    ASSERT_FALSE(Bbr->MinRttTimestampValid);
    ASSERT_EQ(Bbr->MinRtt, UINT64_MAX);
    ASSERT_FALSE(Bbr->BandwidthFilter.AppLimited);
}

//
// Test: Reset - FullReset=TRUE Zeroes BytesInFlight
// Scenario: Sends 5000 bytes to set BytesInFlight=5000, then calls Reset with
// FullReset=TRUE. Full reset should zero BytesInFlight and reinitialize all BBR state.
// MinRtt==UINT64_MAX.
//
TEST_F(BbrTest, Reset_FullReset)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    ASSERT_EQ(Bbr->BytesInFlight, 5000u);

    CC->QuicCongestionControlReset(CC, TRUE);

    ASSERT_EQ(Bbr->BytesInFlight, 0u);
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_NOT_RECOVERY);
    ASSERT_EQ(Bbr->MinRtt, UINT64_MAX);
}

//
// Test: Reset - FullReset=FALSE Preserves BytesInFlight
// Scenario: Sends 5000 bytes to set BytesInFlight=5000, then calls Reset with
// FullReset=FALSE. Partial reset preserves BytesInFlight but reinitializes other
// BBR state.
//
TEST_F(BbrTest, Reset_PartialReset)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    uint32_t BifBefore = Bbr->BytesInFlight;
    ASSERT_EQ(BifBefore, 5000u);

    CC->QuicCongestionControlReset(CC, FALSE);

    ASSERT_EQ(Bbr->BytesInFlight, BifBefore);
    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_STARTUP);
}

//
// Test: GetBandwidth - Returns Zero When Filter is Empty
// Scenario: On a freshly initialized BBR instance, the bandwidth filter is empty
// (no samples). BbrCongestionControlGetBandwidth returns 0.
//
TEST_F(BbrTest, GetBandwidth_Empty)
{
    InitializeWithDefaults();
    ASSERT_EQ(BbrCongestionControlGetBandwidth(CC), (uint64_t)0);
    ASSERT_EQ(CC->QuicCongestionControlGetCongestionWindow(CC), 12320u);
}

//
// Test: InRecovery - Returns FALSE Initially
// Scenario: Checks RecoveryState on a freshly initialized BBR instance. By default,
// no recovery is active.
//
TEST_F(BbrTest, InRecovery_NotInRecovery)
{
    InitializeWithDefaults();
    ASSERT_EQ(Bbr->RecoveryState, (uint32_t)RECOVERY_STATE_NOT_RECOVERY);
}

//
// Test: OnDataSent - Basic BytesInFlight Increment
// Scenario: Verifies BytesInFlight starts at 0, then sends 1200 bytes via
// OnDataSent. The sent bytes should be added to BytesInFlight.
//
TEST_F(BbrTest, OnDataSent_Basic)
{
    InitializeWithDefaults();
    ASSERT_EQ(Bbr->BytesInFlight, 0u);

    CC->QuicCongestionControlOnDataSent(CC, 1200);
    ASSERT_EQ(Bbr->BytesInFlight, 1200u);
}

//
// Test: OnDataSent - Sets ExitingQuiescence on Quiescence Exit
// Scenario: Sets AppLimited with BytesInFlight=0, then sends 1200 bytes. When
// BytesInFlight is 0 and AppLimited is TRUE at the time of OnDataSent, the
// ExitingQuiescence flag is set.
//
TEST_F(BbrTest, OnDataSent_QuiescenceExit)
{
    InitializeWithDefaults();
    CC->QuicCongestionControlSetAppLimited(CC);

    CC->QuicCongestionControlOnDataSent(CC, 1200);
    ASSERT_TRUE(Bbr->ExitingQuiescence);
}

//
// Test: OnDataSent - Updates BytesInFlightMax High-Water Mark
// Scenario: Records the initial BytesInFlightMax, then sends InitialMax + 1000 bytes.
// OnDataSent should update BytesInFlightMax when BytesInFlight exceeds the previous
// maximum.
//
TEST_F(BbrTest, OnDataSent_UpdateBytesInFlightMax)
{
    InitializeWithDefaults();
    uint32_t InitialMax = Bbr->BytesInFlightMax;

    CC->QuicCongestionControlOnDataSent(CC, InitialMax + 1000);
    ASSERT_EQ(Bbr->BytesInFlightMax, InitialMax + 1000u);
}

//
// Test: OnDataSent - Decrements Exemptions on Each Send
// Scenario: Sets 3 exemptions via SetExemption, then calls OnDataSent twice (1200
// bytes each). Each send should decrement the exemption counter by 1.
//
TEST_F(BbrTest, OnDataSent_DecrementExemptions)
{
    InitializeWithDefaults();
    CC->QuicCongestionControlSetExemption(CC, 3);
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 3u);

    CC->QuicCongestionControlOnDataSent(CC, 1200);
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 2u);

    CC->QuicCongestionControlOnDataSent(CC, 1200);
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 1u);
}

//
// Test: OnDataSent - Does Not Decrement Exemptions When Already Zero
// Scenario: Verifies Exemptions starts at 0, then sends 1200 bytes via OnDataSent.
// When Exemptions is already 0, OnDataSent should not underflow the counter.
//
TEST_F(BbrTest, OnDataSent_NoExemptionDecrement)
{
    InitializeWithDefaults();
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 0u);

    CC->QuicCongestionControlOnDataSent(CC, 1200);
    ASSERT_EQ(CC->QuicCongestionControlGetExemptions(CC), 0u);
}

//
// Test: OnDataInvalidated - Basic BytesInFlight Decrement
// Scenario: Sends 5000 bytes via OnDataSent, then invalidates 2000 bytes via
// OnDataInvalidated. The invalidated bytes should be subtracted from BytesInFlight.
//
TEST_F(BbrTest, OnDataInvalidated_Basic)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    ASSERT_EQ(Bbr->BytesInFlight, 5000u);

    CC->QuicCongestionControlOnDataInvalidated(CC, 2000);
    ASSERT_EQ(Bbr->BytesInFlight, 3000u);
}

//
// Test: OnDataInvalidated - Unblocks Congestion-Blocked Connection
// Scenario: Sends CW bytes to block the connection (CanSend=FALSE), then invalidates
// CW/2 bytes. The invalidation reduces BytesInFlight below CW, unblocking the
// connection.
//
TEST_F(BbrTest, OnDataInvalidated_BecomesUnblocked)
{
    InitializeWithDefaults();
    uint32_t CW = CC->QuicCongestionControlGetCongestionWindow(CC);

    CC->QuicCongestionControlOnDataSent(CC, CW);
    ASSERT_FALSE(CC->QuicCongestionControlCanSend(CC));

    BOOLEAN Result = CC->QuicCongestionControlOnDataInvalidated(CC, CW / 2);
    ASSERT_TRUE(CC->QuicCongestionControlCanSend(CC));
    ASSERT_TRUE(Result); // Became unblocked
}

//
// Test: OnDataAcknowledged - Implicit ACK Path
// Scenario: Sends 5000 bytes, then acknowledges 1200 with IsImplicit=TRUE. The
// implicit path calls UpdateCongestionWindow (growing CW by BytesAcked) but does NOT
// decrement BytesInFlight.
//
TEST_F(BbrTest, OnDataAcknowledged_Implicit)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    uint32_t CwBefore = Bbr->CongestionWindow;

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.IsImplicit = TRUE;

    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // Implicit path calls UpdateCongestionWindow but does NOT decrement BytesInFlight
    ASSERT_EQ(Bbr->BytesInFlight, 5000u);
    ASSERT_EQ(Bbr->CongestionWindow, CwBefore + 1200u);
}

//
// Test: OnDataAcknowledged - Implicit ACK With NetStats Enabled
// Scenario: Initializes with NetStatsEventEnabled=TRUE and a dummy callback, sends
// 5000 bytes, then acknowledges 1200 with IsImplicit=TRUE. The implicit path triggers
// the NetStats callback with current congestion state. BytesInFlight stays at 5000
// (implicit ACKs don't decrement it) and CongestionWindow grows by 1200.
//
TEST_F(BbrTest, OnDataAcknowledged_ImplicitWithNetStats)
{
    InitializeWithDefaults(10, 1280, false, true);

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.IsImplicit = TRUE;

    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_TRUE(NetStatsCallbackInvoked);
    ASSERT_EQ(LastNetStats.BytesInFlight, 5000u);
    ASSERT_EQ(LastNetStats.CongestionWindow, CC->QuicCongestionControlGetCongestionWindow(CC));
}

//
// Test: OnDataAcknowledged - Non-Implicit ACK With NetStats Enabled
// Scenario: Initializes with NetStatsEventEnabled=TRUE and a dummy callback, sends
// 5000 bytes, then acknowledges 1200 with IsImplicit=FALSE. The non-implicit path
// decrements BytesInFlight and triggers the NetStats callback with updated state.
//
TEST_F(BbrTest, OnDataAcknowledged_WithNetStats)
{
    InitializeWithDefaults(10, 1280, false, true);

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(Bbr->BytesInFlight, 5000u - 1200u);
    ASSERT_TRUE(NetStatsCallbackInvoked);
    ASSERT_EQ(LastNetStats.BytesInFlight, 5000u - 1200u);
    ASSERT_EQ(LastNetStats.CongestionWindow, CC->QuicCongestionControlGetCongestionWindow(CC));
    ASSERT_EQ(LastNetStats.Bandwidth, BbrCongestionControlGetBandwidth(CC) / 8);
}

//
// Test: OnDataAcknowledged - NULL AckedPackets With AppLimited Flag
// Scenario: Sends 5000 bytes, then acknowledges 1200 with AckedPackets=NULL and
// IsLargestAckedPacketAppLimited=TRUE. Since AckedPackets is NULL, the ternary
// resolves LastAckedPacketAppLimited to FALSE regardless of the flag.
// BytesInFlight is decremented normally.
//
TEST_F(BbrTest, OnDataAcknowledged_AppLimitedPacket)
{
    InitializeWithDefaults();

    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    Ack.AckedPackets = NULL;
    Ack.IsLargestAckedPacketAppLimited = TRUE;

    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_EQ(Bbr->BytesInFlight, 5000u - 1200u);
}

//
// Test: UpdateCongestionWindow - STARTUP Growth by Acked Bytes
// Scenario: Records InitialCW, sends 5000 bytes, then acknowledges 1200. In STARTUP
// with BtlbwFound=FALSE, UpdateCongestionWindow grows CW by the number of acked bytes.
//
TEST_F(BbrTest, UpdateCongestionWindow_StartupGrowth)
{
    InitializeWithDefaults();
    uint32_t InitialCW = Bbr->CongestionWindow;

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    // In STARTUP with !BtlbwFound, CW grows by acked bytes
    ASSERT_EQ(Bbr->CongestionWindow, InitialCW + 1200u);
}

//
// Test: UpdateCongestionWindow - No Update in PROBE_RTT State
// Scenario: Drives BBR to PROBE_RTT via expired MinRtt. Records CW before the probe,
// then sends and acknowledges 100 bytes with IsImplicit=FALSE. In PROBE_RTT state,
// UpdateCongestionWindow should not modify CongestionWindow.
//
TEST_F(BbrTest, UpdateCongestionWindow_ProbeRttNoUpdate)
{
    InitializeWithDefaults();

    // Drive to PROBE_RTT
    CC->QuicCongestionControlOnDataSent(CC, 2000);
    QUIC_ACK_EVENT Ack1 = MakeBbrAckEvent(1000000, 1, 2, 2000, 50000, 30000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack1);

    CC->QuicCongestionControlOnDataSent(CC, 1000);
    uint64_t ExpiredTime = 1000000 + 11000000;
    QUIC_ACK_EVENT Ack2 = MakeBbrAckEvent(ExpiredTime, 3, 4, 1000, 50000, 35000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack2);

    ASSERT_EQ(Bbr->BbrState, (uint32_t)BBR_STATE_PROBE_RTT);

    uint32_t CwBefore = Bbr->CongestionWindow;
    CC->QuicCongestionControlOnDataSent(CC, 100);
    QUIC_ACK_EVENT Ack3 = MakeBbrAckEvent(ExpiredTime + 1000, 5, 6, 100);
    Ack3.IsImplicit = FALSE;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack3);

    ASSERT_EQ(Bbr->CongestionWindow, CwBefore);
}

//
// Test: UpdateCongestionWindow - AckHeight Filter Applied When BtlbwFound
// Scenario: Drives to PROBE_BW via DriveToBtlbwFound() (BtlbwFound=TRUE). Then sends
// 5000 bytes with a 1000us gap to trigger ack aggregation excess (AggregatedAckBytes
// > ExpectedAckBytes). The excess (6080) is added to TargetCwnd via MaxAckHeightFilter.
// CW = min(TargetCwnd=20576, prevCW+AckedBytes=19496) = 19496.
//
TEST_F(BbrTest, UpdateCongestionWindow_AckHeightFilterEntry)
{
    InitializeWithDefaults();

    uint64_t TimeNow = DriveToBtlbwFound();

    //
    // Create ack aggregation excess while BtlbwFound=TRUE.
    // After DriveToBtlbwFound: BW~960,000, AggregatedAckBytes=1200,
    // AckAggregationStartTime=TimeNow.
    //
    // With a 1000us gap: ExpectedAckBytes = 960000*1000/1e6/8 = 120
    // AggregatedAckBytes(1200) > 120 → excess path → MaxAckHeightFilter populated
    // excess = (1200 + 5000) - 120 = 6080
    //
    // Then UpdateCongestionWindow reads the MaxAckHeightFilter:
    // TargetCwnd = BDP*CwndGain/GAIN_UNIT + 3*SendQuantum + 6080
    // CW = min(TargetCwnd, prevCW + AckedBytes)
    //
    TimeNow += 1000;
    CC->QuicCongestionControlOnDataSent(CC, 5000);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(TimeNow, 500, 510, 5000, 50000, 45000, TRUE);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    //
    // CW before this ack: 14496 (from DriveToBtlbwFound).
    // TargetCwnd = 10800 + 3696 + 6080 = 20576.
    // CW = min(20576, 14496+5000) = 19496.
    //
    ASSERT_EQ(Bbr->CongestionWindow, 19496u);
}

//
// Test: UpdateAckAggregation - First Call Initializes State
// Scenario: Verifies AckAggregationStartTimeValid is FALSE initially. Then sends 5000
// bytes and acknowledges 1200. The first call to UpdateAckAggregation initializes the
// aggregation tracking.
//
TEST_F(BbrTest, UpdateAckAggregation_FirstCall)
{
    InitializeWithDefaults();
    ASSERT_FALSE(Bbr->AckAggregationStartTimeValid);

    CC->QuicCongestionControlOnDataSent(CC, 5000);
    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200);
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    ASSERT_TRUE(Bbr->AckAggregationStartTimeValid);
}



//
// Test: SetSendQuantum - Medium Pacing Rate Sets 2x DatagramPayloadLength
// Scenario: Establishes bandwidth ~5,000,000 in the filter via a crafted packet with
// HasLastAckedPacketInfo. In STARTUP with PacingGain=739, PacingRate=14,433,593. This
// falls in the medium range (kLow*8=9,600,000 <= rate < kHigh*8=192,000,000), so
// SendQuantum is set to DatagramPayloadLength * 2.
//
TEST_F(BbrTest, SetSendQuantum_MediumPacingRate)
{
    InitializeWithDefaults();

    //
    // Establish bandwidth ~5,000,000 BW_UNIT in the filter.
    // SendRate = 1000000*8*(20000-10000)/16000 = 5,000,000
    // AckRate  = 1000000*8*(15000-5000)/16000  = 5,000,000
    // DeliveryRate = 5,000,000
    //
    auto PacketBuf = MakeBbrPacket(
        1200, TRUE, FALSE,
        20000, 1000000,
        10000, 984000,
        5000, 1034000, 1034000);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200, 50000, 45000, TRUE);
    Ack.AckedPackets = &Packet;
    Ack.AdjustedAckTime = 1050000;
    Ack.NumTotalAckedRetransmittableBytes = 15000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    //
    // BW=5,000,000. In STARTUP, PacingGain=kHighGain=739.
    // PacingRate = 5000000*739/256 = 14,433,593.
    // kLow*8=9,600,000 <= 14,433,593 < kHigh*8=192,000,000
    // → medium pacing rate path → SendQuantum = DatagramPayloadLength * 2
    //
    const uint16_t DPL = QuicPathGetDatagramPayloadSize(&Connection.Paths[0]);
    ASSERT_EQ(Bbr->SendQuantum, (uint64_t)(DPL * 2));
}

//
// Test: SetSendQuantum - High Pacing Rate Sets 64KB Cap
// Scenario: Establishes very high bandwidth ~100,000,000 in the filter via a crafted
// packet with tight timing (800us intervals). In STARTUP with PacingGain=739,
// PacingRate=288,671,875. This exceeds kHigh*8=192,000,000, so SendQuantum is set to
// min(PacingRate*1000/8, 65536) = 65536.
//
TEST_F(BbrTest, SetSendQuantum_HighPacingRate)
{
    InitializeWithDefaults();

    //
    // Establish very high bandwidth ~100,000,000 BW_UNIT in the filter.
    // SendRate = 1000000*8*(20000-10000)/800 = 100,000,000
    // AckRate  = 1000000*8*(15000-5000)/800  = 100,000,000
    // DeliveryRate = 100,000,000
    //
    auto PacketBuf = MakeBbrPacket(
        1200, TRUE, FALSE,
        20000, 1000000,
        10000, 999200,
        5000, 1049200, 1049200);
    auto& Packet = PacketBuf.Metadata;

    CC->QuicCongestionControlOnDataSent(CC, 1200);

    QUIC_ACK_EVENT Ack = MakeBbrAckEvent(1050000, 5, 10, 1200, 50000, 45000, TRUE);
    Ack.AckedPackets = &Packet;
    Ack.AdjustedAckTime = 1050000;
    Ack.NumTotalAckedRetransmittableBytes = 15000;
    CC->QuicCongestionControlOnDataAcknowledged(CC, &Ack);

    //
    // BW=100,000,000. In STARTUP, PacingGain=kHighGain=739.
    // PacingRate = 100000000*739/256 = 288,671,875.
    // 288,671,875 >= kHigh*8=192,000,000
    // → high pacing rate path → SendQuantum = min(288671875*1000/8, 65536) = 65536
    //
    ASSERT_EQ(Bbr->SendQuantum, (uint64_t)65536);
}
