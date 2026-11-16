/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for connection path management.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "PathTest.cpp.clog.h"
#endif

class PathTest : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection{};
    QUIC_CID_LIST_ENTRY* EmptyCid{nullptr};

    void SetUp() override
    {
        Connection.Settings.MinimumMtu = 1280;
        Connection.Settings.InitialRttMs = 333;
        Connection.Settings.EcnEnabled = TRUE;
        Connection.Settings.QTIPEnabled = FALSE;
        CxPlatListInitializeHead(&Connection.DestCids);
        EmptyCid = QuicCidNewDestination(0, nullptr);
        ASSERT_NE(nullptr, EmptyCid);
    }

    void TearDown() override
    {
        CXPLAT_FREE(EmptyCid, QUIC_POOL_CIDLIST);
    }

    void InitializePaths(uint8_t Count)
    {
        CxPlatZeroMemory(&Connection.Paths, sizeof(Connection.Paths));
        Connection.Paths.Count = Count;
        Connection.Paths.NextPathId = Count;
        for (uint8_t i = 0; i < Count; ++i) {
            Connection.Paths.Paths[i].ID = i;
            Connection.Paths.Paths[i].InUse = TRUE;
        }
        Connection.Paths.Paths[0].IsActive = TRUE;
        Connection.Paths.PendingActivePathId = Connection.Paths.Paths[0].ID;
    }

    void AddDestCid(
        QUIC_CID_LIST_ENTRY& Cid,
        bool UsedLocally = false,
        uint32_t AssignedPathId = UINT32_MAX)
    {
        Cid.CID.UsedLocally = UsedLocally ? TRUE : FALSE;
#if DEBUG
        Cid.AssignedPathId = AssignedPathId;
#else
        UNREFERENCED_PARAMETER(AssignedPathId);
#endif
        CxPlatListInsertTail(&Connection.DestCids, &Cid.Link);
    }
};

TEST_F(PathTest, Initialize)
{
    Connection.Settings.MinimumMtu = 1400;
    Connection.Settings.InitialRttMs = 25;

    QuicPathSetInitialize(&Connection.Paths, &Connection);

    ASSERT_EQ(1, Connection.Paths.Count);
    ASSERT_EQ(1U, Connection.Paths.NextPathId);
    ASSERT_EQ(0U, Connection.Paths.PendingActivePathId);

    const QUIC_PATH* Path = QuicPathGetActive(&Connection.Paths);
    ASSERT_EQ(&Connection.Paths.Paths[0], Path);
    ASSERT_EQ(0U, Path->ID);
    ASSERT_TRUE(Path->InUse);
    ASSERT_TRUE(Path->IsActive);
    ASSERT_EQ(1400, Path->Mtu);
    ASSERT_EQ(25000U, Path->SmoothedRtt);
    ASSERT_EQ(12500U, Path->RttVariance);
    ASSERT_EQ(UINT32_MAX, Path->MinRtt);
    ASSERT_EQ(ECN_VALIDATION_TESTING, Path->EcnValidationState);
}

TEST_F(PathTest, GetPathById)
{
    InitializePaths(3);
    Connection.Paths.Paths[0].ID = 10;
    Connection.Paths.Paths[1].ID = 20;
    Connection.Paths.Paths[2].ID = 30;
    Connection.Paths.PendingActivePathId = 10;

    ASSERT_EQ(&Connection.Paths.Paths[0], QuicConnGetPathByID(&Connection, 10));
    ASSERT_EQ(&Connection.Paths.Paths[1], QuicConnGetPathByID(&Connection, 20));
    ASSERT_EQ(&Connection.Paths.Paths[2], QuicConnGetPathByID(&Connection, 30));
    ASSERT_EQ(nullptr, QuicConnGetPathByID(&Connection, 40));
}

TEST_F(PathTest, MatchPacket)
{
    QUIC_PATH Path{};
    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.1", 1000, &Path.Route.LocalAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.1", 2000, &Path.Route.RemoteAddress));

    CXPLAT_ROUTE PacketRoute{};
    PacketRoute.LocalAddress = Path.Route.LocalAddress;
    PacketRoute.RemoteAddress = Path.Route.RemoteAddress;
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    ASSERT_TRUE(QuicPathMatchPacket(&Path, &Packet));

    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.2", 1000, &PacketRoute.LocalAddress));
    ASSERT_FALSE(QuicPathMatchPacket(&Path, &Packet));
    PacketRoute.LocalAddress = Path.Route.LocalAddress;

    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.2", 2000, &PacketRoute.RemoteAddress));
    ASSERT_FALSE(QuicPathMatchPacket(&Path, &Packet));
}

TEST_F(PathTest, RemoveFromMiddle)
{
    InitializePaths(4);

    ASSERT_TRUE(QuicPathRemove(&Connection, &Connection.Paths.Paths[2]));

    ASSERT_EQ(3, Connection.Paths.Count);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    ASSERT_EQ(1U, Connection.Paths.Paths[1].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[2].ID);
    ASSERT_FALSE(Connection.Paths.Paths[3].InUse);
}

TEST_F(PathTest, RemoveFromFront)
{
    InitializePaths(4);
    for (uint8_t i = 0; i < Connection.Paths.Count; ++i) {
        Connection.Paths.Paths[i].DestCid = EmptyCid;
        ASSERT_TRUE(
            QuicAddrFromString(
                "198.51.100.1",
                static_cast<uint16_t>(2000 + i),
                &Connection.Paths.Paths[i].Route.RemoteAddress));
    }
    Connection.Paths.Paths[2].IsPeerValidated = TRUE;

    ASSERT_TRUE(QuicPathRemove(&Connection, &Connection.Paths.Paths[0]));

    ASSERT_EQ(3, Connection.Paths.Count);
    ASSERT_EQ(2U, Connection.Paths.Paths[0].ID);
    ASSERT_TRUE(Connection.Paths.Paths[0].IsActive);
    ASSERT_EQ(1U, Connection.Paths.Paths[1].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[2].ID);
    ASSERT_EQ(2U, Connection.Paths.PendingActivePathId);
    ASSERT_FALSE(Connection.Paths.Paths[3].InUse);
}

TEST_F(PathTest, RemoveWhileIteratingBackward)
{
    InitializePaths(4);

    //
    // Iterate backward when removing path to not invalidate the array.
    //
    for (int i = Connection.Paths.Count - 1; i > 0; --i) {
        QUIC_PATH* Path = &Connection.Paths.Paths[i];
        if (Path->ID == 1 || Path->ID == 2) {
            ASSERT_TRUE(QuicPathRemove(&Connection, Path));
        }
    }

    ASSERT_EQ(2, Connection.Paths.Count);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[1].ID);
    ASSERT_FALSE(Connection.Paths.Paths[2].InUse);
}

TEST_F(PathTest, GetPathForPacketReturnsExistingPath)
{
    InitializePaths(2);
    Connection.State.HandshakeConfirmed = TRUE;
    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.1", 1000, &Connection.Paths.Paths[1].Route.LocalAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.1", 2000, &Connection.Paths.Paths[1].Route.RemoteAddress));

    CXPLAT_ROUTE PacketRoute = Connection.Paths.Paths[1].Route;
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    ASSERT_EQ(
        &Connection.Paths.Paths[1],
        QuicConnGetPathForPacket(&Connection, &Packet));
    ASSERT_EQ(2, Connection.Paths.Count);
}

TEST_F(PathTest, GetPathForPacketCreatesNewPath)
{
    InitializePaths(2);
    Connection.State.HandshakeConfirmed = TRUE;
    Connection.Paths.Paths[0].DestCid = EmptyCid;
    Connection.Paths.Paths[0].Binding =
        reinterpret_cast<QUIC_BINDING*>(&Connection);
    Connection.Paths.Paths[1].GotValidPacket = TRUE;
    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.2", 1001, &Connection.Paths.Paths[1].Route.LocalAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.2", 2001, &Connection.Paths.Paths[1].Route.RemoteAddress));

    CXPLAT_ROUTE PacketRoute{};
    PacketRoute.DatapathType = 1; // CXPLAT_DATAPATH_TYPE_NORMAL
    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.1", 1000, &PacketRoute.LocalAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.1", 2000, &PacketRoute.RemoteAddress));
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    QUIC_PATH* Path = QuicConnGetPathForPacket(&Connection, &Packet);

    ASSERT_EQ(&Connection.Paths.Paths[1], Path);
    ASSERT_EQ(3, Connection.Paths.Count);
    ASSERT_EQ(2U, Path->ID);
    ASSERT_EQ(3U, Connection.Paths.NextPathId);
    ASSERT_TRUE(Path->InUse);
    ASSERT_EQ(Connection.Paths.Paths[0].Binding, Path->Binding);
    ASSERT_EQ(EmptyCid, Path->DestCid);
    ASSERT_EQ(1280, Path->Mtu);
    ASSERT_EQ(333000U, Path->SmoothedRtt);
    ASSERT_EQ(166500U, Path->RttVariance);
    ASSERT_EQ(UINT32_MAX, Path->MinRtt);
    ASSERT_EQ(ECN_VALIDATION_TESTING, Path->EcnValidationState);
    ASSERT_TRUE(QuicAddrCompare(&PacketRoute.LocalAddress, &Path->Route.LocalAddress));
    ASSERT_TRUE(QuicAddrCompare(&PacketRoute.RemoteAddress, &Path->Route.RemoteAddress));
    ASSERT_EQ(1U, Connection.Paths.Paths[2].ID);
    ASSERT_TRUE(Connection.Paths.Paths[2].GotValidPacket);
}

TEST_F(PathTest, GetPathForPacketReplacesReboundPathAtCapacity)
{
    InitializePaths(QUIC_MAX_PATH_COUNT);
    Connection.State.HandshakeConfirmed = TRUE;
    Connection.Paths.Paths[0].DestCid = EmptyCid;

    for (uint8_t i = 0; i < Connection.Paths.Count; ++i) {
        ASSERT_TRUE(
            QuicAddrFromString(
                "192.0.2.1",
                static_cast<uint16_t>(1000 + i),
                &Connection.Paths.Paths[i].Route.LocalAddress));
    }
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.1", 2000, &Connection.Paths.Paths[0].Route.RemoteAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.2", 2000, &Connection.Paths.Paths[1].Route.RemoteAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.3", 2000, &Connection.Paths.Paths[2].Route.RemoteAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.4", 2000, &Connection.Paths.Paths[3].Route.RemoteAddress));

    CXPLAT_ROUTE PacketRoute{};
    PacketRoute.DatapathType = 1; // CXPLAT_DATAPATH_TYPE_NORMAL
    PacketRoute.LocalAddress = Connection.Paths.Paths[2].Route.LocalAddress;
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.3", 2001, &PacketRoute.RemoteAddress));
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    QUIC_PATH* Path = QuicConnGetPathForPacket(&Connection, &Packet);

    ASSERT_EQ(&Connection.Paths.Paths[1], Path);
    ASSERT_EQ(QUIC_MAX_PATH_COUNT, Connection.Paths.Count);
    ASSERT_EQ(4U, Path->ID);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    ASSERT_EQ(1U, Connection.Paths.Paths[2].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[3].ID);
    ASSERT_EQ(nullptr, QuicConnGetPathByID(&Connection, 2));
    ASSERT_TRUE(QuicAddrCompare(&PacketRoute.LocalAddress, &Path->Route.LocalAddress));
    ASSERT_TRUE(QuicAddrCompare(&PacketRoute.RemoteAddress, &Path->Route.RemoteAddress));
}

TEST_F(PathTest, GetPathForPacketReturnsNullAtCapacityWithoutRebind)
{
    InitializePaths(QUIC_MAX_PATH_COUNT);
    Connection.State.HandshakeConfirmed = TRUE;

    for (uint8_t i = 0; i < Connection.Paths.Count; ++i) {
        ASSERT_TRUE(
            QuicAddrFromString(
                "192.0.2.1",
                static_cast<uint16_t>(1000 + i),
                &Connection.Paths.Paths[i].Route.LocalAddress));
        ASSERT_TRUE(
            QuicAddrFromString(
                "198.51.100.1",
                static_cast<uint16_t>(2000 + i),
                &Connection.Paths.Paths[i].Route.RemoteAddress));
    }

    CXPLAT_ROUTE PacketRoute{};
    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.10", 1000, &PacketRoute.LocalAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "203.0.113.1", 2000, &PacketRoute.RemoteAddress));
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    ASSERT_EQ(nullptr, QuicConnGetPathForPacket(&Connection, &Packet));
    ASSERT_EQ(QUIC_MAX_PATH_COUNT, Connection.Paths.Count);
}

TEST_F(PathTest, GetPathForPacketPreservesPendingReboundPathAtCapacity)
{
    InitializePaths(QUIC_MAX_PATH_COUNT);
    Connection.State.HandshakeConfirmed = TRUE;
    Connection.Paths.Paths[0].DestCid = EmptyCid;
    Connection.Paths.PendingActivePathId = Connection.Paths.Paths[3].ID;

    for (uint8_t i = 0; i < Connection.Paths.Count; ++i) {
        ASSERT_TRUE(
            QuicAddrFromString(
                "192.0.2.1",
                static_cast<uint16_t>(1000 + i),
                &Connection.Paths.Paths[i].Route.LocalAddress));
        ASSERT_TRUE(
            QuicAddrFromString(
                "198.51.100.1",
                static_cast<uint16_t>(2000 + i),
                &Connection.Paths.Paths[i].Route.RemoteAddress));
    }

    Connection.Paths.Paths[2].Route.LocalAddress =
        Connection.Paths.Paths[3].Route.LocalAddress;
    ASSERT_TRUE(
        QuicAddrFromString(
            "203.0.113.1", 2002, &Connection.Paths.Paths[2].Route.RemoteAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "203.0.113.1", 2003, &Connection.Paths.Paths[3].Route.RemoteAddress));

    CXPLAT_ROUTE PacketRoute{};
    PacketRoute.DatapathType = 1; // CXPLAT_DATAPATH_TYPE_NORMAL
    PacketRoute.LocalAddress = Connection.Paths.Paths[3].Route.LocalAddress;
    ASSERT_TRUE(
        QuicAddrFromString(
            "203.0.113.1", 2004, &PacketRoute.RemoteAddress));
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    QUIC_PATH* Path = QuicConnGetPathForPacket(&Connection, &Packet);

    ASSERT_EQ(&Connection.Paths.Paths[1], Path);
    ASSERT_EQ(QUIC_MAX_PATH_COUNT, Connection.Paths.Count);
    ASSERT_EQ(4U, Path->ID);
    ASSERT_EQ(nullptr, QuicConnGetPathByID(&Connection, 2));
    ASSERT_NE(nullptr, QuicConnGetPathByID(&Connection, 3));
    ASSERT_EQ(3U, Connection.Paths.PendingActivePathId);
}

TEST_F(PathTest, UpdateDestCidsPrioritizesActivePathForReplacement)
{
    InitializePaths(4);

    const uint8_t ActiveCidData[] = {0};
    const uint8_t NonActiveCidData[] = {1};
    const uint8_t ReplacementCidData[] = {2};
    QUIC_CID_LIST_ENTRY* ActiveCid =
        QuicCidNewDestination(sizeof(ActiveCidData), ActiveCidData);
    QUIC_CID_LIST_ENTRY* NonActiveCid =
        QuicCidNewDestination(sizeof(NonActiveCidData), NonActiveCidData);
    QUIC_CID_LIST_ENTRY* ReplacementCid =
        QuicCidNewDestination(sizeof(ReplacementCidData), ReplacementCidData);
    ASSERT_NE(nullptr, ActiveCid);
    ASSERT_NE(nullptr, NonActiveCid);
    ASSERT_NE(nullptr, ReplacementCid);
    AddDestCid(*ActiveCid, true, Connection.Paths.Paths[0].ID);
    AddDestCid(*NonActiveCid, true, Connection.Paths.Paths[1].ID);
    AddDestCid(*ReplacementCid);
    ActiveCid->CID.Retired = TRUE;
    NonActiveCid->CID.Retired = TRUE;
    Connection.Paths.Paths[0].DestCid = ActiveCid;
    Connection.Paths.Paths[1].DestCid = NonActiveCid;

    QuicPathUpdateDestCids(&Connection.Paths, &Connection);

    ASSERT_EQ(1, Connection.Paths.Count);
    ASSERT_EQ(ReplacementCid, Connection.Paths.Paths[0].DestCid);
    ASSERT_TRUE(ReplacementCid->CID.UsedLocally);
    ASSERT_TRUE(Connection.Paths.Paths[0].InitiatedCidUpdate);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    ASSERT_FALSE(Connection.Paths.Paths[1].InUse);
#if DEBUG
    ASSERT_EQ(Connection.Paths.Paths[0].ID, ReplacementCid->AssignedPathId);
#endif

    CxPlatListEntryRemove(&ActiveCid->Link);
    CxPlatListEntryRemove(&NonActiveCid->Link);
    CxPlatListEntryRemove(&ReplacementCid->Link);
    CXPLAT_FREE(ActiveCid, QUIC_POOL_CIDLIST);
    CXPLAT_FREE(NonActiveCid, QUIC_POOL_CIDLIST);
    CXPLAT_FREE(ReplacementCid, QUIC_POOL_CIDLIST);
}
