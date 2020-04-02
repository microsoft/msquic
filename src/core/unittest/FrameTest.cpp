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
    Frame->Token = &FrameBuf[sizeof(QUIC_NEW_TOKEN_EX)];
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

struct StreamFrameTest : ::testing::TestWithParam<QUIC_FRAME_TYPE> {
};

TEST_P(StreamFrameTest, StreamFrameEncodeDecode)
{
    const uint8_t DataLen = 10;
    QUIC_STREAM_FRAME_TYPE Type;
    Type.Type = (uint8_t)GetParam();
    QUIC_STREAM_EX Frame;
    QUIC_STREAM_EX DecodedFrame;
    uint8_t Buffer[6 + DataLen];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    Frame.ExplicitLength = Type.LEN;
    if (Type.LEN) {
        Frame.Length = DataLen;
    } else {
        Frame.Length = 0;
    }
    Frame.Fin = Type.FIN;
    if (Type.FIN) {
        Frame.Length = DataLen;
    }
    if (Type.OFF) {
        Frame.Offset = 127;
    } else {
        Frame.Offset = 0;
    }
    Frame.StreamID = 63;
    Frame.Data = &Buffer[QuicStreamFrameHeaderSize(&Frame)];

    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));
    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStreamFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_EQ(GetParam(), Buffer[0]);
    ASSERT_TRUE(QuicStreamFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.Fin, DecodedFrame.Fin);
    ASSERT_EQ(Frame.ExplicitLength, DecodedFrame.ExplicitLength);
    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.Offset, DecodedFrame.Offset);
    if (Type.LEN) {
        ASSERT_EQ(Frame.Length, DecodedFrame.Length);
    } else {
        ASSERT_EQ(DecodedFrame.Length, BufferLength - QuicStreamFrameHeaderSize(&DecodedFrame));
    }
    //
    // No stream data is actually copied into the buffer, so make sure the pointer is
    // in the right location.
    //
    ASSERT_EQ(DecodedFrame.Data, &Buffer[QuicStreamFrameHeaderSize(&DecodedFrame)]);
}

INSTANTIATE_TEST_SUITE_P(FrameTest, StreamFrameTest, ::testing::Values(QUIC_FRAME_STREAM, QUIC_FRAME_STREAM_1, QUIC_FRAME_STREAM_2, QUIC_FRAME_STREAM_3, QUIC_FRAME_STREAM_4, QUIC_FRAME_STREAM_5, QUIC_FRAME_STREAM_6, QUIC_FRAME_STREAM_7), ::testing::PrintToStringParamName());

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

struct MaxStreamsFrameTest : ::testing::TestWithParam<bool>
{
};

TEST_P(MaxStreamsFrameTest, MaxStreamsFrameEncodeDecode)
{
    QUIC_MAX_STREAMS_EX Frame = {GetParam(), 127};
    QUIC_MAX_STREAMS_EX DecodedFrame = {0, 0};
    uint8_t Buffer[3];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicMaxStreamsFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicMaxStreamsFrameDecode((QUIC_FRAME_TYPE)Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.BidirectionalStreams, DecodedFrame.BidirectionalStreams);
    ASSERT_EQ(Frame.MaximumStreams, DecodedFrame.MaximumStreams);
}

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    MaxStreamsFrameTest,
    ::testing::Bool(),
    [] (const ::testing::TestParamInfo<MaxStreamsFrameTest::ParamType>& info)
    {
        if (info.param == true)
            return "BidirectionalStream";
        else
            return "UnidirectionalStream";
    });

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

struct StreamsBlockedFrameTest : ::testing::TestWithParam<bool>
{
};

TEST_P(StreamsBlockedFrameTest, StreamsBlockedFrameEncodeDecode)
{
    QUIC_STREAMS_BLOCKED_EX Frame = {GetParam(), 63};
    QUIC_STREAMS_BLOCKED_EX DecodedFrame = {0, 0};
    uint8_t Buffer[2];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStreamsBlockedFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicStreamsBlockedFrameDecode((QUIC_FRAME_TYPE)Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.BidirectionalStreams, DecodedFrame.BidirectionalStreams);
    ASSERT_EQ(Frame.StreamLimit, DecodedFrame.StreamLimit);
}

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    StreamsBlockedFrameTest,
    ::testing::Bool(),
    [] (const ::testing::TestParamInfo<StreamsBlockedFrameTest::ParamType>& info)
    {
        if (info.param == true)
            return "BidirectionalStream";
        else
            return "UnidirectionalStream";
    });

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

struct PathChallengeResponseFrameTest : ::testing::TestWithParam<QUIC_FRAME_TYPE>
{
};

TEST_P(PathChallengeResponseFrameTest, PathChallengeResponseFrameEncodeDecode)
{
    QUIC_PATH_CHALLENGE_EX Frame = {{8, 8, 8, 8, 8, 8, 8, 8}};
    QUIC_PATH_CHALLENGE_EX DecodedFrame;
    uint8_t Buffer[9];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, BufferLength);
    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));

    ASSERT_TRUE(QuicPathChallengeFrameEncode(GetParam(), &Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicPathChallengeFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Buffer[0], GetParam());
    ASSERT_EQ(memcmp(Frame.Data, DecodedFrame.Data, sizeof(Frame.Data)), 0);
}

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    PathChallengeResponseFrameTest,
    ::testing::Values(QUIC_FRAME_PATH_CHALLENGE, QUIC_FRAME_PATH_RESPONSE),
    ::testing::PrintToStringParamName());

struct ConnectionCloseFrameTest : ::testing::TestWithParam<bool> {};

TEST_P(ConnectionCloseFrameTest, ConnectionCloseFrameEncodeDecode)
{
    char* ReasonPhrase = "no";
    QUIC_CONNECTION_CLOSE_EX Frame = {FALSE, GetParam(), 63, 3, ReasonPhrase};
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

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    ConnectionCloseFrameTest,
    ::testing::Bool(),
    [] (const ::testing::TestParamInfo<ConnectionCloseFrameTest::ParamType>& info) {
        if (info.param == true)
            return "ApplicationClosed";
        else
            return "QUICClosed";
    });
