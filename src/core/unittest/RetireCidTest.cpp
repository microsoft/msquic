/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for RETIRE_CONNECTION_ID frame validation.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "RetireCidTest.cpp.clog.h"
#endif

extern "C" {
BOOLEAN QuicConnRecvFrames(
    QUIC_CONNECTION* Connection, QUIC_PATH* Path,
    QUIC_RX_PACKET* Packet, CXPLAT_ECN_TYPE ECN);
}

class RetireCidTest : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection;
    QUIC_WORKER Worker = {};
    QUIC_BINDING Binding = {};
    QUIC_RX_PACKET Packet = {};
    uint8_t Payload[16] = {};
    const uint8_t InitialCidBytes[4] = { 1, 2, 3, 4 };
    const uint8_t OtherCidBytes[4] = { 1, 2, 3, 5 };

    void SetUp() override
    {
        QuicLookupInitialize(&Binding.Lookup);
        TEST_QUIC_SUCCEEDED(QuicTimerWheelInitialize(&Worker.TimerWheel));

        CxPlatZeroMemory(&Connection, sizeof(Connection));
        Connection.Partition = &MsQuicLib.Partitions[0];
        Connection.Worker = &Worker;
        Connection.State.ShareBinding = TRUE;
        Connection.Paths[0].Binding = &Binding;
        Connection.Paths[0].SmoothedRtt = 1000;
        Connection.RefCount = 100;
        CxPlatRefInitializeMultiple(Connection.RefTypeBiasedCount, QUIC_CONN_REF_COUNT);
        CxPlatListInitializeHead(&Connection.Send.SendStreams);

        for (QUIC_CONN_TIMER_TYPE Type = 0; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
            Connection.ExpirationTimes[Type] = UINT64_MAX;
        }
        Connection.EarliestExpirationTime = UINT64_MAX;

        ASSERT_TRUE(AddSourceCid(0, InitialCidBytes, sizeof(InitialCidBytes)));
        ASSERT_TRUE(AddSourceCid(1, OtherCidBytes, sizeof(OtherCidBytes)));
        Connection.NextSourceCidSequenceNumber = 2;

        CxPlatZeroMemory(&Packet, sizeof(Packet));
        Packet.KeyType = QUIC_PACKET_KEY_1_RTT;
        Packet.AvailBuffer = Payload;
        Packet.DestCid = InitialCidBytes;
        Packet.DestCidLen = sizeof(InitialCidBytes);
    }

    void TearDown() override
    {
        QuicLookupRemoveLocalCids(&Binding.Lookup, &Connection);
        QuicTimerWheelUninitialize(&Worker.TimerWheel);
        QuicLookupUninitialize(&Binding.Lookup);
    }

    bool AddSourceCid(uint64_t Sequence, const uint8_t* Bytes, uint8_t Length)
    {
        QUIC_CID_HASH_ENTRY* Cid = QuicCidNewSource(&Connection, Length, Bytes);
        if (Cid == nullptr) {
            return false;
        }
        Cid->CID.SequenceNumber = Sequence;
        if (!QuicLookupAddLocalCid(&Binding.Lookup, Cid, nullptr)) {
            CXPLAT_FREE(Cid, QUIC_POOL_CIDHASH);
            return false;
        }
        CxPlatListPushEntry(&Connection.SourceCids, &Cid->Link);
        return true;
    }

    QUIC_CID_HASH_ENTRY* FindSourceCid(uint64_t Sequence)
    {
        for (auto* Link = Connection.SourceCids.Next; Link != nullptr; Link = Link->Next) {
            auto* Cid = CXPLAT_CONTAINING_RECORD(Link, QUIC_CID_HASH_ENTRY, Link);
            if (Cid->CID.SequenceNumber == Sequence) {
                return Cid;
            }
        }
        return nullptr;
    }

    BOOLEAN Receive(uint64_t Sequence)
    {
        QUIC_RETIRE_CONNECTION_ID_EX Frame = { Sequence };
        uint16_t Length = 0;
        if (!QuicRetireConnectionIDFrameEncode(&Frame, &Length, sizeof(Payload), Payload)) {
            ADD_FAILURE() << "Could not encode RETIRE_CONNECTION_ID";
            return FALSE;
        }
        Packet.PayloadLength = Length;
        Packet.CompletelyValid = FALSE;
        ++Packet.PacketNumber;
        return QuicConnRecvFrames(&Connection, &Connection.Paths[0], &Packet, CXPLAT_ECN_NON_ECT);
    }

    void ExpectProtocolViolation()
    {
        EXPECT_TRUE(Connection.State.ClosedLocally);
        EXPECT_EQ(QUIC_ERROR_PROTOCOL_VIOLATION, Connection.CloseErrorCode);
        EXPECT_EQ(QUIC_STATUS_PROTOCOL_ERROR, Connection.CloseStatus);
        EXPECT_FALSE(Packet.CompletelyValid);
    }
};

class UnissuedRetireCidTest : public RetireCidTest,
    public ::testing::WithParamInterface<uint64_t> {};

TEST_P(UnissuedRetireCidTest, RejectWithoutRemovingCids)
{
    auto* First = Connection.SourceCids.Next;
    ASSERT_FALSE(Receive(GetParam()));
    ExpectProtocolViolation();
    EXPECT_EQ(First, Connection.SourceCids.Next);
    EXPECT_EQ(2u, Binding.Lookup.CidCount);
}

INSTANTIATE_TEST_SUITE_P(
    RetireCidTest, UnissuedRetireCidTest,
    ::testing::Values(uint64_t{2}, uint64_t{100}, uint64_t{QUIC_VAR_INT_MAX}));

TEST_F(RetireCidTest, RejectPacketDestinationCidWithoutRemovingIt)
{
    auto* Cid = FindSourceCid(0);
    ASSERT_NE(nullptr, Cid);
    ASSERT_FALSE(Receive(0));
    ExpectProtocolViolation();
    EXPECT_EQ(Cid, FindSourceCid(0));
    EXPECT_TRUE(Cid->CID.IsInLookupTable);
    EXPECT_EQ(2u, Binding.Lookup.CidCount);
}

TEST_F(RetireCidTest, AcceptOtherCidAndRepeatedRetirement)
{
    ASSERT_TRUE(Receive(1));
    EXPECT_TRUE(Packet.CompletelyValid);
    EXPECT_FALSE(Connection.State.ClosedLocally);
    EXPECT_EQ(nullptr, FindSourceCid(1));
    EXPECT_NE(nullptr, FindSourceCid(0));
    EXPECT_NE(nullptr, FindSourceCid(2));
    EXPECT_EQ(3u, Connection.NextSourceCidSequenceNumber);
    EXPECT_EQ(2u, Binding.Lookup.CidCount);

    // Retransmitting a retirement must not close the connection or issue another CID.
    ASSERT_TRUE(Receive(1));
    EXPECT_TRUE(Packet.CompletelyValid);
    EXPECT_FALSE(Connection.State.ClosedLocally);
    EXPECT_EQ(3u, Connection.NextSourceCidSequenceNumber);
    EXPECT_EQ(2u, Binding.Lookup.CidCount);
}

TEST_F(RetireCidTest, RejectZeroLengthPacketDestinationCid)
{
    QuicLookupRemoveLocalCids(&Binding.Lookup, &Connection);
    ASSERT_TRUE(AddSourceCid(0, InitialCidBytes, 0));
    Connection.NextSourceCidSequenceNumber = 1;
    Packet.DestCid = nullptr;
    Packet.DestCidLen = 0;

    auto* Cid = FindSourceCid(0);
    ASSERT_NE(nullptr, Cid);
    ASSERT_FALSE(Receive(0));
    ExpectProtocolViolation();
    EXPECT_EQ(Cid, FindSourceCid(0));
    EXPECT_TRUE(Cid->CID.IsInLookupTable);
    EXPECT_EQ(1u, Binding.Lookup.CidCount);
}

TEST_F(RetireCidTest, AcceptOtherCidWithMatchingPrefix)
{
    QuicLookupRemoveLocalCids(&Binding.Lookup, &Connection);
    ASSERT_TRUE(AddSourceCid(0, OtherCidBytes, sizeof(OtherCidBytes) - 1));
    ASSERT_TRUE(AddSourceCid(1, OtherCidBytes, sizeof(OtherCidBytes)));
    Packet.DestCid = OtherCidBytes;
    Packet.DestCidLen = sizeof(OtherCidBytes) - 1;

    ASSERT_TRUE(Receive(1));
    EXPECT_FALSE(Connection.State.ClosedLocally);
    EXPECT_EQ(nullptr, FindSourceCid(1));
    EXPECT_NE(nullptr, FindSourceCid(0));
    EXPECT_NE(nullptr, FindSourceCid(2));
}
