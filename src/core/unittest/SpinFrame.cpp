/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Fuzz/Stress test for the framing logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "SpinFrame.cpp.clog.h"
#endif

union QuicV1Frames {
    QUIC_ACK_EX AckFrame;
    QUIC_RESET_STREAM_EX ResetStreamFrame;
    QUIC_STOP_SENDING_EX StopSendingFrame;
    QUIC_CRYPTO_EX CryptoFrame;
    QUIC_NEW_TOKEN_EX NewTokenFrame;
    QUIC_STREAM_EX StreamFrame;
    QUIC_MAX_DATA_EX MaxDataFrame;
    QUIC_MAX_STREAM_DATA_EX MaxStreamDataFrame;
    QUIC_MAX_STREAMS_EX MaxStreamsFrame;
    QUIC_DATA_BLOCKED_EX DataBlockedFrame;
    QUIC_STREAM_DATA_BLOCKED_EX StreamDataBlockedFrame;
    QUIC_STREAMS_BLOCKED_EX StreamsBlockedFrame;
    QUIC_NEW_CONNECTION_ID_EX NewConnectionIdFrame;
    QUIC_RETIRE_CONNECTION_ID_EX RetireConnectionIdFrame;
    QUIC_PATH_CHALLENGE_EX PathChallengeFrame;
    QUIC_CONNECTION_CLOSE_EX ConnectionCloseFrame;
    QUIC_DATAGRAM_EX DatagramFrame;
};

TEST(SpinFrame, SpinFrame1000000)
{
    QuicV1Frames DecodedFrame;
    QUIC_ACK_ECN_EX Ecn;
    QUIC_RANGE AckBlocks;
    uint64_t AckDelay;
    uint32_t SuccessfulDecodes = 0;
    uint32_t FailedDecodes = 0;
    uint16_t Offset;
    BOOLEAN InvalidFrame;
    uint8_t Buffer[255];
    uint8_t BufferLength;
    uint8_t FrameType;

    TEST_QUIC_SUCCEEDED(QuicRangeInitialize(QUIC_MAX_RANGE_DECODE_ACKS, &AckBlocks));

    //
    // This test generates random "frames" of data to be decoded by the framing
    // module and ensures that it doesn't crash.
    // First it picks a random length and then fills the buffer with that
    // much data. Then it picks a frame type that has parsing logic (this
    // excludes padding, ping, and handshake done frames), and tries to decode
    // that random data as that frame type.
    //
    for (uint32_t Counter = 0; Counter < 1000000; ++Counter) {
        Offset = 0;

        TEST_QUIC_SUCCEEDED(QuicRandom(sizeof(BufferLength), &BufferLength));

        if (BufferLength > 0) {
            TEST_QUIC_SUCCEEDED(QuicRandom(BufferLength, Buffer));
        }

        do {
            TEST_QUIC_SUCCEEDED(QuicRandom(sizeof(FrameType), &FrameType));
        } while (!QUIC_FRAME_IS_KNOWN(FrameType));

        switch(FrameType) {
            case QUIC_FRAME_PADDING:
            case QUIC_FRAME_PING:
                break; // no-op
            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_1:
                QuicZeroMemory(&Ecn, sizeof(Ecn));
                if (QuicAckFrameDecode((QUIC_FRAME_TYPE) FrameType, BufferLength, Buffer, &Offset, &InvalidFrame, &AckBlocks, &Ecn, &AckDelay)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                QuicRangeReset(&AckBlocks);
                break;
            case QUIC_FRAME_RESET_STREAM:
                if (QuicResetStreamFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.ResetStreamFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_STOP_SENDING:
                if (QuicStopSendingFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.StopSendingFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_CRYPTO:
                if (QuicCryptoFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.CryptoFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_NEW_TOKEN:
                if (QuicNewTokenFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.NewTokenFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_STREAM:
            case QUIC_FRAME_STREAM_1:
            case QUIC_FRAME_STREAM_2:
            case QUIC_FRAME_STREAM_3:
            case QUIC_FRAME_STREAM_4:
            case QUIC_FRAME_STREAM_5:
            case QUIC_FRAME_STREAM_6:
            case QUIC_FRAME_STREAM_7:
                if (QuicStreamFrameDecode((QUIC_FRAME_TYPE) FrameType, BufferLength, Buffer, &Offset, &DecodedFrame.StreamFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_MAX_DATA:
                if (QuicMaxDataFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.MaxDataFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_MAX_STREAM_DATA:
                if (QuicMaxStreamDataFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.MaxStreamDataFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_MAX_STREAMS:
            case QUIC_FRAME_MAX_STREAMS_1:
                if (QuicMaxStreamsFrameDecode((QUIC_FRAME_TYPE) FrameType, BufferLength, Buffer, &Offset, &DecodedFrame.MaxStreamsFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_DATA_BLOCKED:
                if (QuicDataBlockedFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.DataBlockedFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_STREAM_DATA_BLOCKED:
                if (QuicStreamDataBlockedFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.StreamDataBlockedFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_STREAMS_BLOCKED:
            case QUIC_FRAME_STREAMS_BLOCKED_1:
                if (QuicStreamsBlockedFrameDecode((QUIC_FRAME_TYPE) FrameType, BufferLength, Buffer, &Offset, &DecodedFrame.StreamsBlockedFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_NEW_CONNECTION_ID:
                if (QuicNewConnectionIDFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.NewConnectionIdFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_RETIRE_CONNECTION_ID:
                if (QuicRetireConnectionIDFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.RetireConnectionIdFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_PATH_CHALLENGE:
            case QUIC_FRAME_PATH_RESPONSE:
                if (QuicPathChallengeFrameDecode(BufferLength, Buffer, &Offset, &DecodedFrame.PathChallengeFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_CONNECTION_CLOSE:
            case QUIC_FRAME_CONNECTION_CLOSE_1:
                if (QuicConnCloseFrameDecode((QUIC_FRAME_TYPE)FrameType, BufferLength, Buffer, &Offset, &DecodedFrame.ConnectionCloseFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            case QUIC_FRAME_HANDSHAKE_DONE:
                // no-op
                break;
            case QUIC_FRAME_DATAGRAM:
            case QUIC_FRAME_DATAGRAM_1:
                if (QuicDatagramFrameDecode((QUIC_FRAME_TYPE) FrameType, BufferLength, Buffer, &Offset, &DecodedFrame.DatagramFrame)) {
                    SuccessfulDecodes++;
                } else {
                    FailedDecodes++;
                }
                break;
            default:
                ASSERT_TRUE(FALSE) << "You have a test bug. FrameType: " << (QUIC_FRAME_TYPE) FrameType << " doesn't have a matching case.";
                break;
        }
    }

    QuicRangeUninitialize(&AckBlocks);

    RecordProperty("SuccessfulDecodes", SuccessfulDecodes);
    RecordProperty("FailedDecodes", FailedDecodes);
}
