/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_API_ENABLE_INSECURE_FEATURES 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#include "quic_platform.h"
#include "quic_datapath.h"
#include "msquic.h"

extern "C" {
struct QUIC_CONNECTION;
struct QUIC_PATH;
struct QUIC_RX_PACKET;
struct QUIC_LOOKUP;
struct QUIC_CID_HASH_ENTRY;
struct QUIC_TIMER_WHEEL;

BOOLEAN QuicConnRecvFrames(
    QUIC_CONNECTION* Connection, QUIC_PATH* Path,
    QUIC_RX_PACKET* Packet, CXPLAT_ECN_TYPE ECN);
void QuicLookupInitialize(QUIC_LOOKUP* Lookup);
void QuicLookupUninitialize(QUIC_LOOKUP* Lookup);
BOOLEAN QuicLookupAddLocalCid(
    QUIC_LOOKUP* Lookup, QUIC_CID_HASH_ENTRY* SourceCid,
    QUIC_CONNECTION** Collision);
void QuicLookupRemoveLocalCids(QUIC_LOOKUP* Lookup, QUIC_CONNECTION* Connection);
QUIC_STATUS QuicTimerWheelInitialize(QUIC_TIMER_WHEEL* TimerWheel);
void QuicTimerWheelUninitialize(QUIC_TIMER_WHEEL* TimerWheel);
QUIC_STATUS QUIC_API MsQuicRegistrationOpen(
    const QUIC_REGISTRATION_CONFIG* Config, HQUIC* Registration);
void QUIC_API MsQuicRegistrationClose(HQUIC Registration);
QUIC_STATUS QUIC_API MsQuicConnectionOpen(
    HQUIC Registration, QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    void* Context, HQUIC* Connection);
void QUIC_API MsQuicConnectionClose(HQUIC Connection);
void MsQuicLibraryLazyUninitialize(void);
}

#include "main.h"

class RetireCidTest : public ::testing::Test {
protected:
    HQUIC Registration = nullptr;
    QUIC_CONNECTION* Connection = nullptr;
    QUIC_WORKER Worker = {};
    QUIC_BINDING Binding = {};
    QUIC_RX_PACKET Packet = {};
    uint8_t Payload[16] = {};
    const uint8_t InitialCidBytes[4] = { 1, 2, 3, 4 };
    const uint8_t OtherCidBytes[4] = { 1, 2, 3, 5 };
    uint32_t ShutdownCount = 0;
    QUIC_STATUS ShutdownStatus = QUIC_STATUS_SUCCESS;
    QUIC_UINT62 ShutdownError = QUIC_ERROR_NO_ERROR;
    BOOLEAN WasLazyInitComplete = FALSE;

    static QUIC_STATUS QUIC_API Callback(
        HQUIC, void* Context, QUIC_CONNECTION_EVENT* Event)
    {
        auto* Test = static_cast<RetireCidTest*>(Context);
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT) {
            ++Test->ShutdownCount;
            Test->ShutdownStatus = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
            Test->ShutdownError = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
        }
        return QUIC_STATUS_SUCCESS;
    }

    void SetUp() override
    {
        WasLazyInitComplete = MsQuicLib.LazyInitComplete;
        QuicLookupInitialize(&Binding.Lookup);
        TEST_QUIC_SUCCEEDED(QuicTimerWheelInitialize(&Worker.TimerWheel));
        TEST_QUIC_SUCCEEDED(MsQuicRegistrationOpen(nullptr, &Registration));
        HQUIC Handle = nullptr;
        TEST_QUIC_SUCCEEDED(MsQuicConnectionOpen(Registration, Callback, this, &Handle));
        Connection = reinterpret_cast<QUIC_CONNECTION*>(Handle);

        // Drive frame processing on this thread without starting a socket or worker.
        Connection->Worker = &Worker;
        Connection->WorkerThreadID = CxPlatCurThreadID();
        Connection->State.ShareBinding = TRUE;
        Connection->Paths[0].Binding = &Binding;

        ASSERT_TRUE(AddSourceCid(0, InitialCidBytes, sizeof(InitialCidBytes)));
        ASSERT_TRUE(AddSourceCid(1, OtherCidBytes, sizeof(OtherCidBytes)));
        Connection->NextSourceCidSequenceNumber = 2;
        Packet.KeyType = QUIC_PACKET_KEY_1_RTT;
        Packet.AvailBuffer = Payload;
        Packet.DestCid = InitialCidBytes;
        Packet.DestCidLen = sizeof(InitialCidBytes);
    }

    void TearDown() override
    {
        if (Connection != nullptr) {
            QuicLookupRemoveLocalCids(&Binding.Lookup, Connection);
            Connection->Paths[0].Binding = nullptr;
            MsQuicConnectionClose(reinterpret_cast<HQUIC>(Connection));
        }
        if (Registration != nullptr) {
            MsQuicRegistrationClose(Registration);
        }
        if (!WasLazyInitComplete && MsQuicLib.LazyInitComplete) {
            MsQuicLibraryLazyUninitialize();
        }
        QuicTimerWheelUninitialize(&Worker.TimerWheel);
        QuicLookupUninitialize(&Binding.Lookup);
    }

    bool AddSourceCid(uint64_t Sequence, const uint8_t* Bytes, uint8_t Length)
    {
        QUIC_CID_HASH_ENTRY* Cid = QuicCidNewSource(Connection, Length, Bytes);
        if (Cid == nullptr) {
            return false;
        }
        Cid->CID.SequenceNumber = Sequence;
        if (!QuicLookupAddLocalCid(&Binding.Lookup, Cid, nullptr)) {
            CXPLAT_FREE(Cid, QUIC_POOL_CIDHASH);
            return false;
        }
        CxPlatListPushEntry(&Connection->SourceCids, &Cid->Link);
        return true;
    }

    QUIC_CID_HASH_ENTRY* FindSourceCid(uint64_t Sequence)
    {
        for (auto* Link = Connection->SourceCids.Next; Link != nullptr; Link = Link->Next) {
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
        return QuicConnRecvFrames(Connection, &Connection->Paths[0], &Packet, CXPLAT_ECN_NON_ECT);
    }

    void ExpectProtocolViolation()
    {
        EXPECT_TRUE(Connection->State.ClosedLocally);
        EXPECT_EQ(QUIC_ERROR_PROTOCOL_VIOLATION, Connection->CloseErrorCode);
        EXPECT_FALSE(Packet.CompletelyValid);
        EXPECT_EQ(1u, ShutdownCount);
        EXPECT_EQ(QUIC_STATUS_PROTOCOL_ERROR, ShutdownStatus);
        EXPECT_EQ(QUIC_ERROR_PROTOCOL_VIOLATION, ShutdownError);
    }
};

class UnissuedRetireCidTest : public RetireCidTest,
    public ::testing::WithParamInterface<uint64_t> {};

TEST_P(UnissuedRetireCidTest, RejectWithoutRemovingCids)
{
    auto* First = Connection->SourceCids.Next;
    ASSERT_FALSE(Receive(GetParam()));
    ExpectProtocolViolation();
    EXPECT_EQ(First, Connection->SourceCids.Next);
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
    EXPECT_FALSE(Connection->State.ClosedLocally);
    EXPECT_EQ(0u, ShutdownCount);
    EXPECT_EQ(nullptr, FindSourceCid(1));
    EXPECT_NE(nullptr, FindSourceCid(0));
    EXPECT_NE(nullptr, FindSourceCid(2));
    EXPECT_EQ(3u, Connection->NextSourceCidSequenceNumber);
    EXPECT_EQ(2u, Binding.Lookup.CidCount);

    // Retransmitting a retirement must not close the connection or issue another CID.
    ASSERT_TRUE(Receive(1));
    EXPECT_TRUE(Packet.CompletelyValid);
    EXPECT_FALSE(Connection->State.ClosedLocally);
    EXPECT_EQ(0u, ShutdownCount);
    EXPECT_EQ(3u, Connection->NextSourceCidSequenceNumber);
    EXPECT_EQ(2u, Binding.Lookup.CidCount);
}

TEST_F(RetireCidTest, RejectZeroLengthPacketDestinationCid)
{
    QuicLookupRemoveLocalCids(&Binding.Lookup, Connection);
    ASSERT_TRUE(AddSourceCid(0, InitialCidBytes, 0));
    Connection->NextSourceCidSequenceNumber = 1;
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
    QuicLookupRemoveLocalCids(&Binding.Lookup, Connection);
    ASSERT_TRUE(AddSourceCid(0, OtherCidBytes, sizeof(OtherCidBytes) - 1));
    ASSERT_TRUE(AddSourceCid(1, OtherCidBytes, sizeof(OtherCidBytes)));
    Packet.DestCid = OtherCidBytes;
    Packet.DestCidLen = sizeof(OtherCidBytes) - 1;

    ASSERT_TRUE(Receive(1));
    EXPECT_FALSE(Connection->State.ClosedLocally);
    EXPECT_EQ(0u, ShutdownCount);
    EXPECT_EQ(nullptr, FindSourceCid(1));
    EXPECT_NE(nullptr, FindSourceCid(0));
    EXPECT_NE(nullptr, FindSourceCid(2));
}
