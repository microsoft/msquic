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
#define LARGE_TEST_BUFFER_LENGTH 1024

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
        _In_ QUIC_RECV_BUF_MODE RecvMode = QUIC_RECV_BUF_MODE_SINGLE,
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
        return QuicRecvBufferInitialize(&RecvBuf, AllocBufferLength, VirtualBufferLength, RecvMode, PreallocChunk);
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
        _In_ uint64_t WriteOffset,
        _In_ uint16_t WriteLength,
        _Inout_ uint64_t* WriteLimit,
        _Out_ BOOLEAN* ReadyToRead
        ) {
        auto BufferToWrite = new (std::nothrow) uint8_t[WriteLength];
        CXPLAT_FRE_ASSERT(BufferToWrite);
        for (uint16_t i = 0; i < WriteLength; ++i) {
            BufferToWrite[i] = (uint8_t)(WriteOffset + i);
        }
        auto Status = QuicRecvBufferWrite(&RecvBuf, WriteOffset, WriteLength, BufferToWrite, WriteLimit, ReadyToRead);
        delete [] BufferToWrite;
        return Status;
    }
    void Read(
        _Out_ uint64_t* BufferOffset,
        _Inout_ uint32_t* BufferCount,
        _Out_writes_all_(*BufferCount)
            QUIC_BUFFER* Buffers) {
        QuicRecvBufferRead(&RecvBuf, BufferOffset, BufferCount, Buffers);
        auto Offset = *BufferOffset;
        for (uint32_t i = 0; i < *BufferCount; ++i) {
            ValidateBuffer(Buffers[i].Buffer, Buffers[i].Length, Offset);
            Offset += Buffers[i].Length;
        }
    }
    void Read(
        _Out_ uint64_t* BufferOffset,
        _Out_ QUIC_BUFFER* Buffer) {
        uint32_t BufferCount = 1;
        Read(BufferOffset, &BufferCount, Buffer);
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
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_SINGLE));
}

TEST(RecvBufferTest, AllocWithChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_SINGLE, true));
}

void TestSingleWriteRead(uint16_t WriteLength, uint64_t WriteOffset, uint64_t DrainLength = 0)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            WriteOffset,
            WriteLength,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_EQ(WriteOffset == 0, ReadyToRead != FALSE); // Only ready to read if we wrote to the front
    ASSERT_EQ(WriteLength+WriteOffset, InOutWriteLength); // All data was newly written
    ASSERT_EQ(WriteLength+WriteOffset, RecvBuf.GetTotalLength()); // Total length should be offset plus write length
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffer;
    if (!ReadyToRead) return; // Can't read if it's not ready
    RecvBuf.Read(&ReadOffset, &ReadBuffer);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(WriteLength, ReadBuffer.Length);
    ASSERT_EQ(
        DrainLength == WriteLength,
        RecvBuf.Drain(DrainLength));
}

TEST(RecvBufferTest, WriteFrontAndReadAll)
{
    TestSingleWriteRead(30, 0, 30);
}

TEST(RecvBufferTest, WriteFrontAndReadPartial)
{
    TestSingleWriteRead(30, 0, 20);
}

TEST(RecvBufferTest, WriteGap)
{
    TestSingleWriteRead(30, 10);
}

TEST(RecvBufferTest, WriteFillGap)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            10,
            20,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_FALSE(ReadyToRead);
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            10,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(0ull, InOutWriteLength);
    ASSERT_EQ(30ull, RecvBuf.GetTotalLength());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffer;
    RecvBuf.Read(&ReadOffset, &ReadBuffer);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(30u, ReadBuffer.Length);
}

TEST(RecvBufferTest, Overwrite)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            30,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            10,
            10,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_FALSE(ReadyToRead);
    ASSERT_EQ(0ull, InOutWriteLength); // No newly written data
    ASSERT_EQ(30ull, RecvBuf.GetTotalLength());
}

TEST(RecvBufferTest, OverwritePartial)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            30,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            25,
            10,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(5ull, InOutWriteLength); // Only 5 newly written bytes
    ASSERT_EQ(35ull, RecvBuf.GetTotalLength());
}

TEST(RecvBufferTest, WriteTooMuch)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_SINGLE, false, 8, 8)); // Small buffer
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        RecvBuf.Write(
            0,
            30, // Larger than small buffer
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
            &InOutWriteLength,
            &ReadyToRead));
}

TEST(RecvBufferTest, WriteWhilePendingRead)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            20,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffer;
    RecvBuf.Read(&ReadOffset, &ReadBuffer);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(20u, ReadBuffer.Length);
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            20,
            20,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead); // Still ready to read
    ASSERT_EQ(20ull, InOutWriteLength);
    ASSERT_EQ(40ull, RecvBuf.GetTotalLength());
    ASSERT_FALSE(RecvBuf.Drain(20));
}

TEST(RecvBufferTest, WriteLargeWhilePendingRead)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_SINGLE, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            20,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffer;
    RecvBuf.Read(&ReadOffset, &ReadBuffer);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(20u, ReadBuffer.Length);
    InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            20,
            512,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead); // Still ready to read
    ASSERT_EQ(512ull, InOutWriteLength);
    ASSERT_EQ(532ull, RecvBuf.GetTotalLength());
    ASSERT_FALSE(RecvBuf.Drain(20));
}

TEST(RecvBufferTest, WriteLarge)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_SINGLE, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            256,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(256ull, InOutWriteLength);
    ASSERT_EQ(256ull, RecvBuf.GetTotalLength());
}

TEST(RecvBufferTest, MultiWriteLarge)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_SINGLE, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
        BOOLEAN ReadyToRead = FALSE;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            RecvBuf.Write(
                i * 64,
                64,
                &InOutWriteLength,
                &ReadyToRead));
        ASSERT_TRUE(ReadyToRead);
        ASSERT_TRUE(ReadyToRead);
        ASSERT_EQ(64ull, InOutWriteLength);
        ASSERT_EQ((i + 1) * 64ull, RecvBuf.GetTotalLength());
    }
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffer;
    RecvBuf.Read(&ReadOffset, &ReadBuffer);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(256u, ReadBuffer.Length);
    ASSERT_TRUE(RecvBuf.Drain(256));
}

TEST(RecvBufferTest, ReadCircular)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_CIRCULAR, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            32,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(32ull, InOutWriteLength);
    ASSERT_EQ(32ull, RecvBuf.GetTotalLength());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[2];
    uint32_t BufferCount = 2;
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(32u, ReadBuffers[0].Length);
    ASSERT_FALSE(RecvBuf.Drain(16)); // Partial drain
    InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            32,
            48,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(48ull, InOutWriteLength);
    ASSERT_EQ(80ull, RecvBuf.GetTotalLength());
    BufferCount = 2;
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_EQ(16ull, ReadOffset);
    ASSERT_EQ(48u, ReadBuffers[0].Length);
    ASSERT_EQ(16u, ReadBuffers[1].Length);
    ASSERT_TRUE(RecvBuf.Drain(64));
}

TEST(RecvBufferTest, ReadCircularNewChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_CIRCULAR, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            32,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(32ull, InOutWriteLength);
    ASSERT_EQ(32ull, RecvBuf.GetTotalLength());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[2];
    uint32_t BufferCount = 2;
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(32u, ReadBuffers[0].Length);
    InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            32,
            48,
            &InOutWriteLength,
            &ReadyToRead));
    ASSERT_TRUE(ReadyToRead);
    ASSERT_EQ(48ull, InOutWriteLength);
    ASSERT_EQ(80ull, RecvBuf.GetTotalLength());
    ASSERT_FALSE(RecvBuf.Drain(32));
}
