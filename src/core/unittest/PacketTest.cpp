/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"

TEST(PacketTest, DecodeRetryToken)
{
    const uint16_t HeaderLength = 7 + 2 * QUIC_MAX_CONNECTION_ID_LENGTH_V1;
    uint8_t Buffer[HeaderLength + 1 + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1 + 1]{};
    QUIC_RX_PACKET Packet{};
    Packet.ValidatedHeaderInv = TRUE;
    Packet.AvailBuffer = Buffer;
    Packet.AvailBufferLength = sizeof(Buffer) - 1;
    Packet.HeaderLength = HeaderLength;
    Packet.SourceCidLen = QUIC_MAX_CONNECTION_ID_LENGTH_V1;
    Packet.DestCidLen = QUIC_MAX_CONNECTION_ID_LENGTH_V1;
    const uint8_t* Token = nullptr;
    uint16_t TokenLength = 0;
    ASSERT_EQ(nullptr, QuicPacketDecodeRetryHeaderV1(&Packet, &Token, &TokenLength));
    EXPECT_EQ(Buffer + HeaderLength, Token);
    EXPECT_EQ(1, TokenLength);

    ++Packet.HeaderLength;
    ++Packet.AvailBufferLength;
    ++Packet.SourceCidLen;
    EXPECT_NE(nullptr, QuicPacketDecodeRetryHeaderV1(&Packet, &Token, &TokenLength));

    --Packet.SourceCidLen;
    ++Packet.DestCidLen;
    EXPECT_NE(nullptr, QuicPacketDecodeRetryHeaderV1(&Packet, &Token, &TokenLength));

    --Packet.DestCidLen;
    Packet.HeaderLength = HeaderLength;
    Packet.AvailBufferLength = HeaderLength + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1;
    EXPECT_NE(nullptr, QuicPacketDecodeRetryHeaderV1(&Packet, &Token, &TokenLength));
}
