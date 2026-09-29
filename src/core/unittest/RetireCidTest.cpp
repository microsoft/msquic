/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"

TEST(RetireCidTest, RejectUnissuedSequence)
{
    QUIC_CONNECTION Connection = {};
    QUIC_RX_PACKET Packet = {};
    QUIC_CID_HASH_ENTRY* SourceCid = nullptr;
    Connection.NextSourceCidSequenceNumber = 1;

    EXPECT_EQ(
        QUIC_RETIRE_CID_UNISSUED,
        QuicConnValidateRetireCid(&Connection, &Packet, 1, &SourceCid));
    EXPECT_EQ(nullptr, SourceCid);
    EXPECT_EQ(
        QUIC_RETIRE_CID_UNISSUED,
        QuicConnValidateRetireCid(&Connection, &Packet, 100, &SourceCid));
    EXPECT_EQ(nullptr, SourceCid);

    // A repeated retirement of a previously issued CID is allowed.
    EXPECT_EQ(
        QUIC_RETIRE_CID_VALID,
        QuicConnValidateRetireCid(&Connection, &Packet, 0, &SourceCid));
    EXPECT_EQ(nullptr, SourceCid);
}

TEST(RetireCidTest, RejectPacketDestinationCidWithoutRemovingIt)
{
    QUIC_CONNECTION Connection = {};
    Connection.NextSourceCidSequenceNumber = 2;
    const uint8_t CidBytes[] = { 1, 2, 3, 4 };
    QUIC_CID_HASH_ENTRY* IssuedCid =
        QuicCidNewSource(&Connection, sizeof(CidBytes), CidBytes);
    ASSERT_NE(nullptr, IssuedCid);
    IssuedCid->CID.SequenceNumber = 1;
    Connection.SourceCids.Next = &IssuedCid->Link;
    IssuedCid->Link.Next = nullptr;

    QUIC_RX_PACKET Packet = {};
    Packet.DestCid = CidBytes;
    Packet.DestCidLen = sizeof(CidBytes);
    QUIC_CID_HASH_ENTRY* SourceCid = nullptr;

    EXPECT_EQ(
        QUIC_RETIRE_CID_CURRENT_PACKET,
        QuicConnValidateRetireCid(&Connection, &Packet, 1, &SourceCid));
    EXPECT_EQ(IssuedCid, SourceCid);
    EXPECT_EQ(&IssuedCid->Link, Connection.SourceCids.Next);

    const uint8_t OtherCidBytes[] = { 1, 2, 3, 5 };
    Packet.DestCid = OtherCidBytes;
    EXPECT_EQ(
        QUIC_RETIRE_CID_VALID,
        QuicConnValidateRetireCid(&Connection, &Packet, 1, &SourceCid));
    EXPECT_EQ(IssuedCid, SourceCid);

    Connection.SourceCids.Next = nullptr;
    CXPLAT_FREE(IssuedCid, QUIC_POOL_CIDHASH);
}
