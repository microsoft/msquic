/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"

TEST(PacketTest, LongHeaderCidLengths)
{
    QUIC_RX_PACKET Packet{};
    Packet.SourceCidLen = QUIC_MAX_CONNECTION_ID_LENGTH_V1;
    Packet.DestCidLen = QUIC_MAX_CONNECTION_ID_LENGTH_V1;
    EXPECT_TRUE(QuicPacketHasValidLongHeaderCidLengths(&Packet));

    ++Packet.SourceCidLen;
    EXPECT_FALSE(QuicPacketHasValidLongHeaderCidLengths(&Packet));

    --Packet.SourceCidLen;
    ++Packet.DestCidLen;
    EXPECT_FALSE(QuicPacketHasValidLongHeaderCidLengths(&Packet));
}
