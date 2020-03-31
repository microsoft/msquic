/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the framing logic.

--*/

#include "main.h"

#ifdef QUIC_LOGS_WPP
#include "frametest.tmh"
#endif

// struct FrameTest : public ::testing::Test
// {
// protected:

// };

TEST(FrameTest, AckFrameEncodeDecode)
{
    QUIC_RANGE AckRange;

    TEST_QUIC_SUCCEEDED(QuicRangeInitialize((uint32_t)~0, &AckRange));

    
}

TEST(FrameTest, ResetStreamFrameEncodeDecode)
{
    QUIC_RESET_STREAM_EX Frame = {127, 4294967297, 65536};
    QUIC_RESET_STREAM_EX DecodedFrame = {0, 0, 0};
    uint8_t Buffer[15];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicResetStreamFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicResetStreamFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.ErrorCode, DecodedFrame.ErrorCode);
    ASSERT_EQ(Frame.FinalSize, DecodedFrame.FinalSize);
}

TEST(FrameTest, StopSendingFrameEncodeDecode)
{
    QUIC_STOP_SENDING_EX Frame = {42, 64};
    QUIC_STOP_SENDING_EX DecodedFrame = {0, 0};
    uint8_t Buffer[4];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStopSendingFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicStopSendingFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.ErrorCode, DecodedFrame.ErrorCode);
}

TEST(FrameTest, CryptoFrameEncodeDecode)
{
    uint8_t FrameBuf[sizeof(QUIC_CRYPTO_EX) + 3];
    uint8_t* CryptoData = FrameBuf + sizeof(QUIC_CRYPTO_EX);
    QUIC_CRYPTO_EX* Frame = (QUIC_CRYPTO_EX*) FrameBuf;
    Frame->Data = &FrameBuf[sizeof(QUIC_CRYPTO_EX)];
    Frame->Offset = 7;
    Frame->Length = 3;
    CryptoData[0] = CryptoData[1] = CryptoData[2] = 3;
    QUIC_CRYPTO_EX DecodedFrame;
    uint8_t Buffer[6];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));
    ASSERT_TRUE(QuicCryptoFrameEncode(Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicCryptoFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame->Offset, DecodedFrame.Offset);
    ASSERT_EQ(Frame->Length, DecodedFrame.Length);
    ASSERT_EQ(memcmp(Frame->Data, DecodedFrame.Data, DecodedFrame.Length), 0);
}

TEST(FrameTest, NewTokenFrameEncodeDecode)
{
    uint8_t FrameBuf[sizeof(QUIC_NEW_TOKEN_EX) + 3];
    uint8_t* TokenData = FrameBuf + sizeof(QUIC_NEW_TOKEN_EX);
    QUIC_NEW_TOKEN_EX* Frame = (QUIC_NEW_TOKEN_EX*) FrameBuf;
    Frame->TokenLength = 3;
    Frame->Token = &FrameBuf[8];
    TokenData[0] = TokenData[1] = TokenData[2] = 3;
    QUIC_NEW_TOKEN_EX DecodedFrame;
    uint8_t Buffer[5];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));
    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicNewTokenFrameEncode(Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicNewTokenFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame->TokenLength, DecodedFrame.TokenLength);
    ASSERT_EQ(memcmp(Frame->Token, DecodedFrame.Token, DecodedFrame.TokenLength), 0);
}

//
// Stream Tests
//

TEST(FrameTest, MaxDataFrameEncodeDecode)
{
    QUIC_MAX_DATA_EX Frame = {65536};
    QUIC_MAX_DATA_EX DecodedFrame = {0};
    uint8_t Buffer[5];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicMaxDataFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicMaxDataFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.MaximumData, DecodedFrame.MaximumData);
}

TEST(FrameTest, MaxStreamDataFrameEncodeDecode)
{
    QUIC_MAX_STREAM_DATA_EX Frame = {65, 65537};
    QUIC_MAX_STREAM_DATA_EX DecodedFrame = {0, 0};
    uint8_t Buffer[7];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicMaxStreamDataFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicMaxStreamDataFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.MaximumData, DecodedFrame.MaximumData);
}

TEST(FrameTest, MaxStreamsFrameEncodeDecode)
{
    QUIC_MAX_STREAMS_EX Frame = {1, 127};
}

TEST(FrameTest, DataBlockedFrameEncodeDecode)
{
    QUIC_DATA_BLOCKED_EX Frame = {127};
    QUIC_DATA_BLOCKED_EX DecodedFrame = {0};
    uint8_t Buffer[3];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicDataBlockedFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicDataBlockedFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.DataLimit, DecodedFrame.DataLimit);
}

TEST(FrameTest, StreamDataBlockedFrameEncodeDecode)
{
    QUIC_STREAM_DATA_BLOCKED_EX Frame = {127, 255};
    QUIC_STREAM_DATA_BLOCKED_EX DecodedFrame = {0, 0};
    uint8_t Buffer[5];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStreamDataBlockedFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicStreamDataBlockedFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.StreamDataLimit, DecodedFrame.StreamDataLimit);
}

TEST(FrameTest, StreamsBlockedFrameEncodeDecode)
{

}

TEST(FrameTest, NewConnectionIdFrameEncodeDecode)
{
    QUIC_NEW_CONNECTION_ID_EX Frame = {5, 63, 0,
        {5, 5, 5, 5, 5,
        16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}};
    QUIC_NEW_CONNECTION_ID_EX DecodedFrame;
    uint8_t Buffer[25];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, BufferLength);
    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));

    ASSERT_TRUE(QuicNewConnectionIDFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicNewConnectionIDFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.Length, DecodedFrame.Length);
    ASSERT_EQ(Frame.Sequence, DecodedFrame.Sequence);
    ASSERT_EQ(Frame.RetirePriorTo, DecodedFrame.RetirePriorTo);
    ASSERT_EQ(memcmp(Frame.Buffer, DecodedFrame.Buffer, 22), 0);
}

TEST(FrameTest, RetireConnectionIdFrameEncodeDecode)
{
    QUIC_RETIRE_CONNECTION_ID_EX Frame = {63};
    QUIC_RETIRE_CONNECTION_ID_EX DecodedFrame = {0};
    uint8_t Buffer[2];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    ASSERT_TRUE(QuicRetireConnectionIDFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicRetireConnectionIDFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.Sequence, DecodedFrame.Sequence);
}

//TODO: parameter for challenge/response
TEST(FrameTest, PathChallengeResponseFrameEncodeDecode)
{
    QUIC_PATH_CHALLENGE_EX Frame = {{8, 8, 8, 8, 8, 8, 8, 8}};
    QUIC_PATH_CHALLENGE_EX DecodedFrame;
    uint8_t Buffer[9];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, BufferLength);
    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));

    ASSERT_TRUE(QuicPathChallengeFrameEncode(QUIC_FRAME_PATH_CHALLENGE, &Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicPathChallengeFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(memcmp(Frame.Data, DecodedFrame.Data, sizeof(Frame.Data)), 0);
}

TEST(FrameTest, ConnectionCloseFrameEncodeDecode)
{
    char* ReasonPhrase = "no";
    QUIC_CONNECTION_CLOSE_EX Frame = {FALSE, 1, 63, 3, ReasonPhrase};
    QUIC_CONNECTION_CLOSE_EX DecodedFrame;
    uint8_t Buffer[7];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, BufferLength);

    ASSERT_TRUE(QuicConnCloseFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicConnCloseFrameDecode((QUIC_FRAME_TYPE) Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.ApplicationClosed, DecodedFrame.ApplicationClosed);
    ASSERT_EQ(Frame.ErrorCode, DecodedFrame.ErrorCode);
    ASSERT_EQ(Frame.FrameType, DecodedFrame.FrameType);
    ASSERT_EQ(Frame.ReasonPhraseLength, DecodedFrame.ReasonPhraseLength);
    ASSERT_EQ(strcmp(Frame.ReasonPhrase, DecodedFrame.ReasonPhrase), 0);
}