/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC_RECV_BUFFER interface.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "RecvBufferTest.cpp.clog.h"
#endif

#define DEF_TEST_BUFFER_LENGTH 64

struct RecvBuffer {
    QUIC_RECV_BUFFER RecvBuf {0};
    QUIC_RECV_CHUNK* PreallocChunk {nullptr};
    ~RecvBuffer() {
        QuicRecvBufferUninitialize(&RecvBuf);
        if (PreallocChunk) {
            CXPLAT_FREE(PreallocChunk, QUIC_POOL_TEST);
        }
    }
    QUIC_STATUS Initialize(
        _In_ bool CopyOnDrain = true,
        _In_ bool PreallocatedChunk = false,
        _In_ uint32_t AllocBufferLength = DEF_TEST_BUFFER_LENGTH,
        _In_ uint32_t VirtualBufferLength = DEF_TEST_BUFFER_LENGTH
        ) {
        if (PreallocatedChunk) {
            PreallocChunk =
                (QUIC_RECV_CHUNK*)CXPLAT_ALLOC_NONPAGED(
                    sizeof(QUIC_RECV_CHUNK) + AllocBufferLength,
                    QUIC_POOL_TEST);
        }
        return QuicRecvBufferInitialize(&RecvBuf, AllocBufferLength, VirtualBufferLength, CopyOnDrain ? TRUE : FALSE, PreallocChunk);
    }
    void SetMultiReceiverMode() {
        RecvBuf.MultiReceiveMode = TRUE;
    }
    uint64_t GetTotalLength() {
        return QuicRecvBufferGetTotalLength(&RecvBuf);
    }
    void SetVirtualBufferLength(uint32_t Length) {
        QuicRecvBufferSetVirtualBufferLength(&RecvBuf, Length);
    }
    bool HasUnreadData() {
        return QuicRecvBufferHasUnreadData(&RecvBuf) != FALSE;
    }
    QUIC_STATUS Write(
        _In_ uint64_t BufferOffset,
        _In_ uint16_t BufferLength,
        _Inout_ uint64_t* WriteLength,
        _Out_ BOOLEAN* ReadyToRead
        ) {
        auto BufferToWrite = new (std::nothrow) uint8_t[BufferLength];
        for (uint16_t i = 0; i < BufferLength; ++i) {
            BufferToWrite[i] = (uint8_t)(BufferOffset + i);
        }
        auto Status = QuicRecvBufferWrite(&RecvBuf, BufferOffset, BufferLength, BufferToWrite, WriteLength, ReadyToRead);
        delete [] BufferToWrite;
        return Status;
    }
    bool Read(
        _Out_ uint64_t* BufferOffset,
        _Inout_ uint32_t* BufferCount,
        _Out_writes_all_(*BufferCount)
            QUIC_BUFFER* Buffers) {
        auto Result = QuicRecvBufferRead(&RecvBuf, BufferOffset, BufferCount, Buffers) != FALSE;
        if (Result) {
            auto Offset = *BufferOffset;
            for (uint32_t i = 0; i < *BufferCount; ++i) {
                ValidateBuffer(Buffers[i].Buffer, Buffers[i].Length, Offset);
                Offset += Buffers[i].Length;
            }
        }
        return Result;
    }
    bool Drain(_In_ uint64_t BufferOffset) {
        return QuicRecvBufferDrain(&RecvBuf, BufferOffset) != FALSE;
    }
    // Validates the value of the buffer is equal to the offset.
    static void ValidateBuffer(_In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint32_t BufferLength, _In_ uint64_t BufferOffset) {
        for (uint32_t i = 0; i < BufferLength; ++i) {
            ASSERT_EQ((uint8_t)(BufferOffset + i), Buffer[i]);
        }
    }
};

TEST(RecvBufferTest, Alloc)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(true));
}

TEST(RecvBufferTest, AllocWithChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(true, true));
}

void TestSingleWriteRead(uint16_t WriteLength, bool WriteFront, bool DrainAll = true)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            WriteFront ? 0 : 10, // Add small offset if not writing to front of buffer
            WriteLength,
            &InOutWriteLength,
            &ReadyToRead));
    if (!WriteFront) {
        ASSERT_EQ(WriteLength, InOutWriteLength); // All data was newly written
        ASSERT_FALSE(ReadyToRead);
        ASSERT_EQ(WriteLength+10, RecvBuf.GetTotalLength()); // Total length should be offset plus write length
    } else {
        ASSERT_EQ(WriteLength, InOutWriteLength); // All data was newly written
        ASSERT_TRUE(ReadyToRead);
        ASSERT_EQ(WriteLength, RecvBuf.GetTotalLength()); // Total length is just write length
    }
    uint64_t ReadOffset;
    uint32_t ReadBufferCount = 1;
    QUIC_BUFFER ReadBuffer;
    ASSERT_EQ(
        WriteFront, // If we didn't write to the front, then it's not ready to read yet
        RecvBuf.Read(
            &ReadOffset,
            &ReadBufferCount,
            &ReadBuffer));
    if (!WriteFront) return; // Nothing else to validate if we didn't write to the front
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1ul, ReadBufferCount);
    ASSERT_EQ(WriteLength, ReadBuffer.Length);
    if (DrainAll) {
        ASSERT_TRUE(RecvBuf.Drain(ReadBuffer.Length));
    } else {
        ASSERT_FALSE(RecvBuf.Drain(10));
    }
}

TEST(RecvBufferTest, WriteFrontAndReadAll)
{
    TestSingleWriteRead(30, true);
}

TEST(RecvBufferTest, WriteFrontAndReadPartial)
{
    TestSingleWriteRead(30, true, false);
}

TEST(RecvBufferTest, WriteGap)
{
    TestSingleWriteRead(30, false);
}

TEST(RecvBufferTest, WriteTooMuch)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(true, false, 8, 8)); // Small buffer
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        RecvBuf.Write(
            0,
            30, // Larger than small buffer
            BufferToWrite,
            &InOutWriteLength,
            &ReadyToRead));
}

TEST(RecvBufferTest, WriteTooMuch2)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = 10; // i.e. simulate a small connection-wide FC limit
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        RecvBuf.Write(
            0,
            30, // Larger than FC limit
            BufferToWrite,
            &InOutWriteLength,
            &ReadyToRead));
}
