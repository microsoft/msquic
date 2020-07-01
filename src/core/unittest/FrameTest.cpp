/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the framing logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "FrameTest.cpp.clog.h"
#endif

struct AckFrameTest : ::testing::TestWithParam<QUIC_FRAME_TYPE> {
};

TEST_P(AckFrameTest, AckFrameEncodeDecode)
{
    const uint64_t MaxPktNum = 10;
    const uint64_t ContigPktCount = 4;
    const uint64_t MinPktNum = 5;
    const uint64_t AckDelay = 0;
    QUIC_ACK_ECN_EX Ecn = {4, 4, 4};
    QUIC_ACK_ECN_EX DecodedEcn = {0, 0, 0};
    QUIC_RANGE AckRange;
    QUIC_RANGE DecodedAckRange;
    uint8_t Buffer[10];
    uint16_t BufferLength = (uint16_t) sizeof(Buffer);
    uint16_t Offset = 0;
    uint64_t DecodedAckDelay = 0;
    uint64_t RangeLength = 0;
    BOOLEAN InvalidFrame = FALSE;
    BOOLEAN IsLastRange = FALSE;
    BOOLEAN Unused;

    QuicZeroMemory(Buffer, sizeof(Buffer));

    TEST_QUIC_SUCCEEDED(QuicRangeInitialize(QUIC_MAX_RANGE_DECODE_ACKS, &AckRange));
    TEST_QUIC_SUCCEEDED(QuicRangeInitialize(QUIC_MAX_RANGE_DECODE_ACKS, &DecodedAckRange));

    ASSERT_TRUE(QuicRangeAddRange(&AckRange, MinPktNum, ContigPktCount, &Unused) != nullptr);
    ASSERT_TRUE(QuicRangeAddValue(&AckRange, MaxPktNum));

    ASSERT_TRUE(QuicAckFrameEncode(&AckRange, AckDelay, (GetParam() == QUIC_FRAME_ACK ? nullptr : &Ecn), &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_EQ(Buffer[0], GetParam());
    ASSERT_TRUE(QuicAckFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &InvalidFrame, &DecodedAckRange, &DecodedEcn, &DecodedAckDelay));

    ASSERT_FALSE(InvalidFrame);
    ASSERT_EQ(AckDelay, DecodedAckDelay);
    ASSERT_EQ(QuicRangeSize(&DecodedAckRange), QuicRangeSize(&AckRange));
    ASSERT_EQ(QuicRangeGetMin(&DecodedAckRange), MinPktNum);
    ASSERT_EQ(QuicRangeGetMax(&DecodedAckRange), MaxPktNum);
    ASSERT_TRUE(QuicRangeGetRange(&DecodedAckRange, MinPktNum, &RangeLength, &IsLastRange));
    ASSERT_EQ(RangeLength, ContigPktCount);
    ASSERT_FALSE(IsLastRange);
    ASSERT_TRUE(QuicRangeGetRange(&DecodedAckRange, MaxPktNum, &RangeLength, &IsLastRange));
    ASSERT_EQ(RangeLength, 1);
    ASSERT_TRUE(IsLastRange);

    if (GetParam() == QUIC_FRAME_ACK_1) {
        ASSERT_EQ(Ecn.CE_Count, DecodedEcn.CE_Count);
        ASSERT_EQ(Ecn.ECT_0_Count, DecodedEcn.ECT_0_Count);
        ASSERT_EQ(Ecn.ECT_1_Count, DecodedEcn.ECT_1_Count);
    }

    QuicRangeUninitialize(&AckRange);
    QuicRangeUninitialize(&DecodedAckRange);
}

TEST_P(AckFrameTest, DecodeAckFrameFail) {
    QUIC_ACK_ECN_EX DecodedEcn;
    uint8_t Buffer[18];
    uint16_t BufferLength;
    uint16_t Offset = 1;
    BOOLEAN InvalidFrame = FALSE;
    QUIC_RANGE DecodedAckBlocks;
    QUIC_VAR_INT AckDelay = 0;
    TEST_QUIC_SUCCEEDED(QuicRangeInitialize(QUIC_MAX_RANGE_DECODE_ACKS, &DecodedAckBlocks));
    Buffer[0] = (uint8_t)GetParam();

    //
    // Test Case: ACK Range count > number of ACK ranges
    //
    BufferLength = 7;
    Buffer[1] = 10; // Highest ACKed PN
    Buffer[2] = 1; // ACK Delay
    Buffer[3] = 3; // ACK range count
    Buffer[4] = 4; // First ACK range
    Buffer[5] = 4; // First ACK gap
    Buffer[6] = 0; // Second ACK range

    if (GetParam() == QUIC_FRAME_ACK_1) {
        BufferLength += 3;
        Buffer[7] = 1;
        Buffer[8] = 2;
        Buffer[9] = 3;
    }

    BOOLEAN Result = QuicAckFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &InvalidFrame, &DecodedAckBlocks, &DecodedEcn, &AckDelay);

    ASSERT_TRUE(InvalidFrame);
    ASSERT_FALSE(Result);
    QuicRangeReset(&DecodedAckBlocks);

    //
    // Test Case: ACK Range count > Highest ACKed PN
    //
    Offset = 1;
    InvalidFrame = FALSE;
    BufferLength = 15;
    Buffer[1] = 4; // Highest ACKed PN
    Buffer[2] = 1; // ACK Delay
    Buffer[3] = 5; // ACK range count
    Buffer[4] = 0; // First ACK range
    Buffer[5] = 0; // First ACK gap
    Buffer[6] = 0; // Second ACK Range
    Buffer[7] = 0; // Second ACK Gap
    Buffer[8] = 0; // Third ACK Range
    Buffer[9] = 0; // Third ACK Gap
    Buffer[10] = 0; // Fourth ACK Range
    Buffer[11] = 0; // Fourth ACK Gap
    Buffer[12] = 0; // Fifth ACK Range
    Buffer[13] = 0; // Fifth ACK Gap
    Buffer[14] = 0; // Sixth ACK Range

    if (GetParam() == QUIC_FRAME_ACK_1) {
        BufferLength += 3;
        Buffer[15] = 4;
        Buffer[16] = 5;
        Buffer[17] = 6;
    }

    Result = QuicAckFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &InvalidFrame, &DecodedAckBlocks, &DecodedEcn, &AckDelay);

    ASSERT_TRUE(InvalidFrame);
    ASSERT_FALSE(Result);
    QuicRangeReset(&DecodedAckBlocks);

    //
    // Test Case: First ACK range > Highest ACKed PN
    //
    Offset = 1;
    InvalidFrame = FALSE;
    BufferLength = 5;
    Buffer[1] = 5; // Highest ACKed PN
    Buffer[2] = 1; // ACK Delay
    Buffer[3] = 0; // ACK range count
    Buffer[4] = 6; // First ACK range

    if (GetParam() == QUIC_FRAME_ACK_1) {
        BufferLength += 3;
        Buffer[5] = 7;
        Buffer[6] = 8;
        Buffer[7] = 9;
    }

    Result = QuicAckFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &InvalidFrame, &DecodedAckBlocks, &DecodedEcn, &AckDelay);

    ASSERT_TRUE(InvalidFrame);
    ASSERT_FALSE(Result);
    QuicRangeReset(&DecodedAckBlocks);

    //
    // Test Case: ECN fields contain improperly-formatted QUIC VAR INTs.
    //
    if (GetParam() == QUIC_FRAME_ACK_1) {
        BufferLength = 8;
        Buffer[1] = 5; // Highest ACKed PN
        Buffer[2] = 1; // ACK Delay
        Buffer[3] = 0; // ACK range count
        Buffer[4] = 5; // First ACK range
        for (auto TestValue : {64, 255}) {
            for (uint8_t i = 1; i < 8; ++i) {
                Offset = 1;
                InvalidFrame = FALSE;
                //
                // ECT(0) COunt
                //
                Buffer[5] = (i & 1) ? TestValue : 0;
                //
                // ECT(1) Count
                //
                Buffer[6] = (i & 2) ? TestValue : 0;
                //
                // ECN-CE Count
                //
                Buffer[7] = (i & 4) ? TestValue : 0;

                ASSERT_FALSE(QuicAckFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &InvalidFrame, &DecodedAckBlocks, &DecodedEcn, &AckDelay));

                QuicRangeReset(&DecodedAckBlocks);
            }
        }
    }

    QuicRangeUninitialize(&DecodedAckBlocks);
}

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    AckFrameTest,
    ::testing::Values(QUIC_FRAME_ACK, QUIC_FRAME_ACK_1),
    ::testing::PrintToStringParamName());

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

struct ResetStreamFrameParams {
    uint8_t Buffer[4];
    uint16_t BufferLength = 4;

    static auto GenerateDecodeFailParams() {
        std::vector<ResetStreamFrameParams> Params;
        const uint16_t BufferLength = 4;
        for (uint32_t i = 1; i < 8; ++i) {
            ResetStreamFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_RESET_STREAM;

            for (uint32_t j = 0; j < 2; ++j) {
                uint8_t TestValue = (j & 1) ? 64 : 255;

                if (i & 1) {
                    Temp.Buffer[1] = TestValue;
                } else {
                    Temp.Buffer[1] = 0;
                }

                if (i & 2) {
                    Temp.Buffer[2] = TestValue;
                } else {
                    Temp.Buffer[2] = 0;
                }

                if (i & 4) {
                    Temp.Buffer[3] = TestValue;
                } else {
                    Temp.Buffer[3] = 0;
                }

                Params.push_back(Temp);
            }
        }
        return Params;
    }
};

struct ResetStreamFrameTest : ::testing::TestWithParam<ResetStreamFrameParams> {};

TEST_P(ResetStreamFrameTest, DecodeResetStreamFrameFail) {
    uint16_t Offset = 1;
    QUIC_RESET_STREAM_EX DecodedFrame;
    ASSERT_FALSE(QuicResetStreamFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    ResetStreamFrameTest,
    ::testing::ValuesIn(ResetStreamFrameParams::GenerateDecodeFailParams()));

TEST(FrameTest, StopSendingFrameEncodeDecode)
{
    QUIC_STOP_SENDING_EX Frame = {42, 64};
    QUIC_STOP_SENDING_EX DecodedFrame = {0, 0};
    uint8_t Buffer[4];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStopSendingFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicStopSendingFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.ErrorCode, DecodedFrame.ErrorCode);
}

struct StopSendingFrameParams {
    uint8_t Buffer[3];
    uint16_t BufferLength = 3;

    static auto GenerateDecodeFailParams() {
        std::vector<StopSendingFrameParams> Params;
        for (uint32_t i = 1; i < 4; ++i) {
            StopSendingFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_STOP_SENDING;

            for (uint32_t j = 0; j < 2; ++j) {
                uint8_t TestValue = (j & 1) ? 64 : 255;

                if (i & 1) {
                    Temp.Buffer[1] = TestValue;
                } else {
                    Temp.Buffer[1] = 0;
                }

                if (i & 2) {
                    Temp.Buffer[2] = TestValue;
                } else {
                    Temp.Buffer[2] = 0;
                }

                Params.push_back(Temp);
            }
        }
        return Params;
    }
};

struct StopSendingFrameTest : ::testing::TestWithParam<StopSendingFrameParams> {};

TEST_P(StopSendingFrameTest, DecodeStopSendingFrameFail) {
    QUIC_STOP_SENDING_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicStopSendingFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, StopSendingFrameTest, ::testing::ValuesIn(StopSendingFrameParams::GenerateDecodeFailParams()));

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
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));
    ASSERT_TRUE(QuicCryptoFrameEncode(Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicCryptoFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame->Offset, DecodedFrame.Offset);
    ASSERT_EQ(Frame->Length, DecodedFrame.Length);
    ASSERT_EQ(memcmp(Frame->Data, DecodedFrame.Data, DecodedFrame.Length), 0);
}

struct CryptoFrameParams {
    uint8_t Buffer[7];
    uint16_t BufferLength = 6;

    static auto GenerateDecodeFailParams() {
        std::vector<CryptoFrameParams> Params;
        for (uint32_t i = 1; i < 4; ++i) {
            CryptoFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_CRYPTO;
            Temp.Buffer[3] = Temp.Buffer[4] = Temp.Buffer[5] = Temp.Buffer[6] = 127;

            for (uint32_t j = 0; j < 2; ++j) {
                uint8_t TestValue = (j & 1) ? 64 : 255;

                if (i & 1) {
                    Temp.Buffer[1] = TestValue;
                } else {
                    Temp.Buffer[1] = 0;
                }

                if (i & 2) {
                    Temp.Buffer[2] = TestValue;
                } else {
                    Temp.Buffer[2] = 0;
                }
                Params.push_back(Temp);
            }
        }
        return Params;
    }
};

struct CryptoFrameTest : ::testing::TestWithParam<CryptoFrameParams> {};

TEST_P(CryptoFrameTest, DecodeCryptoFrameFail) {
    QUIC_CRYPTO_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicCryptoFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, CryptoFrameTest, ::testing::ValuesIn(CryptoFrameParams::GenerateDecodeFailParams()));

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
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));
    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicNewTokenFrameEncode(Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicNewTokenFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame->TokenLength, DecodedFrame.TokenLength);
    ASSERT_EQ(memcmp(Frame->Token, DecodedFrame.Token, DecodedFrame.TokenLength), 0);
}

struct NewTokenFrameParams {
    uint8_t Buffer[3];
    uint16_t BufferLength = 3;

    static auto GenerateDecodeFailParams() {
        std::vector<NewTokenFrameParams> Params;
        for (uint32_t i = 0; i < 2; ++i) {
            NewTokenFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_NEW_TOKEN;
            Temp.Buffer[1] = (i & 1) ? 65 : 255;
            Temp.Buffer[2] = 0;
            Params.push_back(Temp);
        }
        return Params;
    }
};

struct NewTokenFrameTest : ::testing::TestWithParam<NewTokenFrameParams> {};

TEST_P(NewTokenFrameTest, DecodeNewTokenFrameFail) {
    QUIC_NEW_TOKEN_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicNewTokenFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, NewTokenFrameTest, ::testing::ValuesIn(NewTokenFrameParams::GenerateDecodeFailParams()));

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
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
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

TEST_P(StreamFrameTest, DecodeStreamFrameFail) {
    const uint8_t DataLen = 1;
    QUIC_STREAM_FRAME_TYPE Type;
    Type.Type = (uint8_t)GetParam();
    QUIC_STREAM_EX DecodedFrame;
    uint8_t Buffer[1 + 1 + 1 + 1 + DataLen];
    uint16_t BufferLength;
    uint16_t Offset = 1;

    Buffer[0] = Type.Type;

    switch(GetParam()) {
        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
            QUIC_FRE_ASSERT(!Type.LEN && !Type.OFF);
            for(uint8_t i = 0; i < 2; ++i) {
                Offset = 1;
                //
                // Stream ID
                //
                if (i & 1) {
                    Buffer[1] = 255;
                    Buffer[2] = 0;
                    BufferLength = 3;
                } else {
                    Buffer[1] = 64;
                    BufferLength = 2;
                }
                ASSERT_FALSE(QuicStreamFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &DecodedFrame)) << "Test case: " << i;
            }
            break;

        case QUIC_FRAME_STREAM_2: // LEN
        case QUIC_FRAME_STREAM_3: // LEN + FIN
        case QUIC_FRAME_STREAM_4: // OFF
        case QUIC_FRAME_STREAM_5: // OFF + FIN
            QUIC_FRE_ASSERT(Type.LEN || Type.OFF);
            for (uint8_t i = 1; i < 4; ++i) {
                Offset = 1;
                //
                // Stream ID
                //
                if (i & 1) {
                    Buffer[1] = 255;
                } else {
                    Buffer[1] = 0;
                }

                //
                // Length or Offset
                //
                if (i & 2) {
                    Buffer[2] = 255;
                } else {
                    Buffer[2] = 0;
                }
                Buffer[3] = 1;
                BufferLength = 4;
                ASSERT_FALSE(QuicStreamFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &DecodedFrame)) << "Test case: " << i;
            }
            break;

        case QUIC_FRAME_STREAM_6: // OFF + LEN
        case QUIC_FRAME_STREAM_7: // OFF + LEN + FIN
            QUIC_FRE_ASSERT(Type.LEN && Type.OFF);
            for (uint8_t i = 1; i < 8; ++i) {
                Offset = 1;
                //
                // Stream ID
                //
                if (i & 1) {
                    Buffer[1] = 255;
                } else {
                    Buffer[1] = 0;
                }

                //
                // Offset
                //
                if (i & 2) {
                    Buffer[2] = 255;
                } else {
                    Buffer[2] = 0;
                }

                //
                // Length
                //
                if (i & 4) {
                    Buffer[3] = 255;
                } else {
                    Buffer[3] = 0;
                }
                Buffer[4] = 0;
                BufferLength = 4;
                ASSERT_FALSE(QuicStreamFrameDecode(GetParam(), BufferLength, Buffer, &Offset, &DecodedFrame)) << "Test case: " << i;
            }
            break;
        default:
            FAIL() << "Missing test case for " << GetParam();
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(
    FrameTest,
    StreamFrameTest,
    ::testing::Values(QUIC_FRAME_STREAM, QUIC_FRAME_STREAM_1, QUIC_FRAME_STREAM_2, QUIC_FRAME_STREAM_3, QUIC_FRAME_STREAM_4, QUIC_FRAME_STREAM_5, QUIC_FRAME_STREAM_6, QUIC_FRAME_STREAM_7),
    ::testing::PrintToStringParamName());

TEST(FrameTest, MaxDataFrameEncodeDecode)
{
    QUIC_MAX_DATA_EX Frame = {65536};
    QUIC_MAX_DATA_EX DecodedFrame = {0};
    uint8_t Buffer[5];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicMaxDataFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicMaxDataFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.MaximumData, DecodedFrame.MaximumData);
}

struct MaxDataFrameParams {
    uint8_t Buffer[2];
    uint16_t BufferLength = 2;

    static auto GenerateDecodeFailParams() {
        std::vector<MaxDataFrameParams> Params;
        for (uint32_t i = 0; i < 2; ++i) {
            MaxDataFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_MAX_DATA;
            Temp.Buffer[1] = (i & 1) ? 64 : 255;
            Params.push_back(Temp);
        }
        return Params;
    }
};

struct MaxDataFrameTest : ::testing::TestWithParam<MaxDataFrameParams> {};

TEST_P(MaxDataFrameTest, DecodeMaxDataFrameFail) {
    QUIC_MAX_DATA_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicMaxDataFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, MaxDataFrameTest, ::testing::ValuesIn(MaxDataFrameParams::GenerateDecodeFailParams()));

TEST(FrameTest, MaxStreamDataFrameEncodeDecode)
{
    QUIC_MAX_STREAM_DATA_EX Frame = {65, 65537};
    QUIC_MAX_STREAM_DATA_EX DecodedFrame = {0, 0};
    uint8_t Buffer[7];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicMaxStreamDataFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicMaxStreamDataFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.MaximumData, DecodedFrame.MaximumData);
}

struct MaxStreamDataFrameParams {
    uint8_t Buffer[3];
    uint16_t BufferLength = 3;

    static auto GenerateDecodeFailParams() {
        std::vector<MaxStreamDataFrameParams> Params;
        for (uint32_t i = 1; i < 4; ++i) {
            MaxStreamDataFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_MAX_STREAM_DATA;
            for (uint32_t j = 0; j < 2; ++j) {
                uint8_t TestValue = (j & 1) ? 64 : 255;
                if (i & 1) {
                    Temp.Buffer[1] = TestValue;
                } else {
                    Temp.Buffer[1] = 0;
                }

                if (i & 2) {
                    Temp.Buffer[2] = TestValue;
                } else {
                    Temp.Buffer[2] = 0;
                }
                Params.push_back(Temp);
            }
        }
        return Params;
    }
};

struct MaxStreamDataFrameTest : ::testing::TestWithParam<MaxStreamDataFrameParams> {};

TEST_P(MaxStreamDataFrameTest, DecodeMaxStreamDataFrameFail) {
    QUIC_MAX_STREAM_DATA_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicMaxStreamDataFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, MaxStreamDataFrameTest, ::testing::ValuesIn(MaxStreamDataFrameParams::GenerateDecodeFailParams()));

struct MaxStreamsFrameTest : ::testing::TestWithParam<bool>
{
};

TEST_P(MaxStreamsFrameTest, MaxStreamsFrameEncodeDecode)
{
    QUIC_MAX_STREAMS_EX Frame = {GetParam(), 127};
    QUIC_MAX_STREAMS_EX DecodedFrame = {0, 0};
    uint8_t Buffer[3];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicMaxStreamsFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicMaxStreamsFrameDecode((QUIC_FRAME_TYPE)Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.BidirectionalStreams, DecodedFrame.BidirectionalStreams);
    ASSERT_EQ(Frame.MaximumStreams, DecodedFrame.MaximumStreams);
}

TEST_P(MaxStreamsFrameTest, DecodeMaxStreamsFrameFail) {
    const uint16_t BufferLength = 2;
    QUIC_MAX_STREAMS_EX DecodedFrame;
    uint8_t Buffer[BufferLength];
    uint16_t Offset;
    for (uint32_t i = 0; i < 2; ++i) {
        Buffer[0] = GetParam() ? QUIC_FRAME_MAX_STREAMS : QUIC_FRAME_MAX_STREAMS_1;
        Buffer[1] = (i & 1) ? 64 : 255;
        Offset = 1;
        ASSERT_FALSE(QuicMaxStreamsFrameDecode((QUIC_FRAME_TYPE) Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));
    }
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
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicDataBlockedFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicDataBlockedFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.DataLimit, DecodedFrame.DataLimit);
}

struct DataBlockedFrameParams {
    uint8_t Buffer[2];
    uint16_t BufferLength = 2;

    static auto GenerateDecodeFailParams() {
        std::vector<DataBlockedFrameParams> Params;
        for (uint32_t i = 0; i < 2; ++i) {
            DataBlockedFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_DATA_BLOCKED;
            Temp.Buffer[1] = (i & 1) ? 64 : 255;
            Params.push_back(Temp);
        }
        return Params;
    }
};

struct DataBlockedFrameTest : ::testing::TestWithParam<DataBlockedFrameParams> {};

TEST_P(DataBlockedFrameTest, DecodeDataBlockedFrameFail) {
    QUIC_DATA_BLOCKED_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicDataBlockedFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, DataBlockedFrameTest, ::testing::ValuesIn(DataBlockedFrameParams::GenerateDecodeFailParams()));

TEST(FrameTest, StreamDataBlockedFrameEncodeDecode)
{
    QUIC_STREAM_DATA_BLOCKED_EX Frame = {127, 255};
    QUIC_STREAM_DATA_BLOCKED_EX DecodedFrame = {0, 0};
    uint8_t Buffer[5];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStreamDataBlockedFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicStreamDataBlockedFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.StreamID, DecodedFrame.StreamID);
    ASSERT_EQ(Frame.StreamDataLimit, DecodedFrame.StreamDataLimit);
}

struct StreamDataBlockedFrameParams {
    uint8_t Buffer[3];
    uint16_t BufferLength = 3;

    static auto GenerateDecodeFailParams() {
        std::vector<StreamDataBlockedFrameParams> Params;
        for (uint32_t i = 1; i < 4; ++i) {
            StreamDataBlockedFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_STREAM_DATA_BLOCKED;
            for (uint32_t j = 0; j < 2; ++j) {
                uint8_t TestValue = (j & 1) ? 64 : 255;
                if (i & 1) {
                    Temp.Buffer[1] = TestValue;
                } else {
                    Temp.Buffer[1] = 0;
                }

                if (i & 2) {
                    Temp.Buffer[2] = TestValue;
                } else {
                    Temp.Buffer[2] = 0;
                }
                Params.push_back(Temp);
            }
        }
        return Params;
    }
};

struct StreamDataBlockedFrameTest : ::testing::TestWithParam<StreamDataBlockedFrameParams> {};

TEST_P(StreamDataBlockedFrameTest, DecodeStreamDataBlockedFrameFail) {
    QUIC_STREAM_DATA_BLOCKED_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicStreamDataBlockedFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, StreamDataBlockedFrameTest, ::testing::ValuesIn(StreamDataBlockedFrameParams::GenerateDecodeFailParams()));

struct StreamsBlockedFrameTest : ::testing::TestWithParam<bool>
{
};

TEST_P(StreamsBlockedFrameTest, StreamsBlockedFrameEncodeDecode)
{
    QUIC_STREAMS_BLOCKED_EX Frame = {GetParam(), 63};
    QUIC_STREAMS_BLOCKED_EX DecodedFrame = {0, 0};
    uint8_t Buffer[2];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, sizeof(Buffer));
    ASSERT_TRUE(QuicStreamsBlockedFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicStreamsBlockedFrameDecode((QUIC_FRAME_TYPE)Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.BidirectionalStreams, DecodedFrame.BidirectionalStreams);
    ASSERT_EQ(Frame.StreamLimit, DecodedFrame.StreamLimit);
}

TEST_P(StreamsBlockedFrameTest, DecodeStreamsBlockedFrameFail) {
    const uint16_t BufferLength = 2;
    QUIC_STREAMS_BLOCKED_EX DecodedFrame;
    uint8_t Buffer[BufferLength];
    uint16_t Offset;
    for (uint32_t i = 0; i < 2; ++i) {
        Buffer[0] = GetParam() ? QUIC_FRAME_STREAMS_BLOCKED : QUIC_FRAME_STREAMS_BLOCKED_1;
        Buffer[1] = (i & 1) ? 64 : 255;
        Offset = 1;
        ASSERT_FALSE(QuicStreamsBlockedFrameDecode((QUIC_FRAME_TYPE) Buffer[0], BufferLength, Buffer, &Offset, &DecodedFrame));
    }
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
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
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

struct NewConnectionIdFrameParams {
    uint16_t BufferLength = 41;
    uint8_t Buffer[41];

    static auto GenerateDecodeFailParams() {
        std::vector<NewConnectionIdFrameParams> Params;
        for (uint32_t i = 1; i < 16; ++i) {
            NewConnectionIdFrameParams Frame;
            uint32_t Index = 0;
            uint16_t BufferLength = 0;
            Frame.Buffer[Index] = QUIC_FRAME_NEW_CONNECTION_ID;
            Index++;
            BufferLength++;

            //
            // Choose which fields to malform
            //
            if (i & 1) {
                //
                // Sequence number
                //
                Frame.Buffer[Index] = 255;
            } else {
                Frame.Buffer[Index] = 0;
            }
            Index++;
            BufferLength++;

            if (i & 2) {
                //
                // Retire prior to
                //
                Frame.Buffer[Index] = 255;
            } else {
                Frame.Buffer[Index] = 0;
            }
            Index++;
            BufferLength++;

            if (i & 4) {
                //
                // Connection ID.
                // Length can be 0, 1, 20, or 21.
                // When Length is 1 or 20, the buffer length should be adjusted to be too small.
                //
                uint16_t OldBufferLength = BufferLength;
                uint32_t OldIndex = Index;
                for (uint32_t j = 0; j < 4; ++j) {
                    BufferLength = OldBufferLength;
                    Index = OldIndex;
                    uint8_t CidLen;
                    if (j == 0) {
                        CidLen = 0;
                        BufferLength += 21;
                    } else if (j == 1) {
                        CidLen = 1;
                        // Don't increment BufferLength
                    } else if (j == 2) {
                        CidLen = 20;
                        BufferLength += 19;
                    } else {
                        CidLen = 21;
                        BufferLength += 21;
                    }
                    Frame.Buffer[Index] = CidLen;
                    Index++;
                    BufferLength++;
                    memset(&Frame.Buffer[Index], 127, CidLen);
                    Index += CidLen;

                    //
                    // Stateless Reset token.
                    // Since the contents of the token aren't specified, don't put enough buffer to hold it.
                    //
                    uint8_t TokenLen;
                    if (i & 8) {
                        TokenLen = 8;
                    } else {
                        TokenLen = 16;
                    }
                    memset(&Frame.Buffer[Index], 65, TokenLen);
                    Index += TokenLen;
                    BufferLength += TokenLen;

                    Frame.BufferLength = BufferLength;
                    Params.push_back(Frame);
                }
            } else {
                //
                // Connection ID is not altered, so use length of 1.
                //
                Frame.Buffer[Index] = 1;
                Index++;
                BufferLength++;
                Frame.Buffer[Index] = 127;
                Index++;
                BufferLength++;

                //
                // Stateless Reset token.
                // Since the contents of the token aren't specified, don't put enough buffer to hold it.
                //
                uint8_t TokenLen;
                if (i & 8) {
                    TokenLen = 8;
                } else {
                    TokenLen = 16;
                }
                memset(&Frame.Buffer[Index], 65, TokenLen);
                Index += TokenLen;
                BufferLength += TokenLen;

                Frame.BufferLength = BufferLength;
                Params.push_back(Frame);
            }
        }

        return Params;
    }
};

struct NewConnectionIdFrameTest : ::testing::TestWithParam<NewConnectionIdFrameParams> {};

TEST_P(NewConnectionIdFrameTest, DecodeNewConnectionIdFrameFail) {
    QUIC_NEW_CONNECTION_ID_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicNewConnectionIDFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, NewConnectionIdFrameTest, ::testing::ValuesIn(NewConnectionIdFrameParams::GenerateDecodeFailParams()));

TEST(FrameTest, RetireConnectionIdFrameEncodeDecode)
{
    QUIC_RETIRE_CONNECTION_ID_EX Frame = {63};
    QUIC_RETIRE_CONNECTION_ID_EX DecodedFrame = {0};
    uint8_t Buffer[2];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    ASSERT_TRUE(QuicRetireConnectionIDFrameEncode(&Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicRetireConnectionIDFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Frame.Sequence, DecodedFrame.Sequence);
}

struct RetireConnectionIdFrameParams {
    uint8_t Buffer[2];
    uint16_t BufferLength = 2;

    static auto GenerateDecodeFailParams() {
        std::vector<RetireConnectionIdFrameParams> Params;
        for (uint32_t i = 0; i < 2; ++i) {
            RetireConnectionIdFrameParams Temp;
            Temp.Buffer[0] = QUIC_FRAME_RETIRE_CONNECTION_ID;
            Temp.Buffer[1] = (i & 1) ? 64 : 255;
            Params.push_back(Temp);
        }
        return Params;
    }
};

struct RetireConnectionIdFrameTest : ::testing::TestWithParam<RetireConnectionIdFrameParams> {};

TEST_P(RetireConnectionIdFrameTest, DecodeRetireConnectionIdFrameFail) {
    QUIC_RETIRE_CONNECTION_ID_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicRetireConnectionIDFrameDecode(GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, RetireConnectionIdFrameTest, ::testing::ValuesIn(RetireConnectionIdFrameParams::GenerateDecodeFailParams()));

struct PathChallengeResponseFrameTest : ::testing::TestWithParam<QUIC_FRAME_TYPE>
{
};

TEST_P(PathChallengeResponseFrameTest, PathChallengeResponseFrameEncodeDecode)
{
    QUIC_PATH_CHALLENGE_EX Frame = {{8, 8, 8, 8, 8, 8, 8, 8}};
    QUIC_PATH_CHALLENGE_EX DecodedFrame;
    uint8_t Buffer[9];
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
    uint16_t Offset = 0;

    QuicZeroMemory(Buffer, BufferLength);
    QuicZeroMemory(&DecodedFrame, sizeof(DecodedFrame));

    ASSERT_TRUE(QuicPathChallengeFrameEncode(GetParam(), &Frame, &Offset, BufferLength, Buffer));
    Offset = 1;
    ASSERT_TRUE(QuicPathChallengeFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));

    ASSERT_EQ(Buffer[0], GetParam());
    ASSERT_EQ(memcmp(Frame.Data, DecodedFrame.Data, sizeof(Frame.Data)), 0);
}

TEST_P(PathChallengeResponseFrameTest, DecodePathChallengeResponseFrameFail) {
    const uint16_t BufferLength = 2;
    QUIC_PATH_CHALLENGE_EX DecodedFrame;
    uint8_t Buffer[BufferLength];
    uint16_t Offset = 1;

    Buffer[0] = (uint8_t) GetParam();
    Buffer[1] = 127;
    ASSERT_FALSE(QuicPathChallengeFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame));
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
    uint16_t BufferLength = (uint16_t)sizeof(Buffer);
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

struct ConnectionCloseFrameParams {
    uint8_t Buffer[5];
    uint16_t BufferLength;

    static auto GenerateDecodeFailParams() {
        std::vector<ConnectionCloseFrameParams> Params;
        for (uint8_t Type : {QUIC_FRAME_CONNECTION_CLOSE, QUIC_FRAME_CONNECTION_CLOSE_1}) {
            ConnectionCloseFrameParams Frame;
            Frame.Buffer[0] = Type;

            for (int TestValue : {65, 255}) {
                for (uint32_t i = 1; i < 4; ++i) {
                    Frame.Buffer[1] = (i & 1) ? TestValue : 0;

                    if (Type == QUIC_FRAME_CONNECTION_CLOSE) {
                        for (uint32_t j = 0; j < 2; ++j) {
                            Frame.Buffer[2] = (j & 1) ? TestValue : 0;

                            Frame.Buffer[3] = (i & 2) ? TestValue : 0;
                            if (Frame.Buffer[3]  > 0) {
                                Frame.Buffer[4] = 'Z';
                            } else {
                                Frame.Buffer[4] = 1;
                            }

                            Frame.BufferLength = 5;
                            Params.push_back(Frame);
                        }
                    } else {
                        Frame.Buffer[2] = (i & 2) ? TestValue : 0;
                        if (Frame.Buffer[2]  > 0) {
                            Frame.Buffer[3] = 'Z';
                        } else {
                            Frame.Buffer[3] = 1;
                        }

                        Frame.BufferLength = 4;
                        Params.push_back(Frame);
                    }
                }
            }
        }
        return Params;
    }
};

struct ConnectionCloseFrameDecodeTest : ::testing::TestWithParam<ConnectionCloseFrameParams> {};

TEST_P(ConnectionCloseFrameDecodeTest, DecodeConnectionCloseFrameFail) {
    QUIC_CONNECTION_CLOSE_EX DecodedFrame;
    uint16_t Offset = 1;
    ASSERT_FALSE(QuicConnCloseFrameDecode((QUIC_FRAME_TYPE)GetParam().Buffer[0], GetParam().BufferLength, GetParam().Buffer, &Offset, &DecodedFrame));
}

INSTANTIATE_TEST_SUITE_P(FrameTest, ConnectionCloseFrameDecodeTest, ::testing::ValuesIn(ConnectionCloseFrameParams::GenerateDecodeFailParams()));
