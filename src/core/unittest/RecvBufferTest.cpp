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
        _In_ uint32_t AllocBufferLength = DEF_TEST_BUFFER_LENGTH,
        _In_ uint32_t VirtualBufferLength = DEF_TEST_BUFFER_LENGTH,
        _In_ bool CopyOnDrain = true,
        _In_ bool PreallocatedChunk = false
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
        _In_reads_bytes_(BufferLength) uint8_t const* Buffer,
        _Inout_ uint64_t* WriteLength,
        _Out_ BOOLEAN* ReadyToRead
        ) {
        return QuicRecvBufferWrite(&RecvBuf, BufferOffset, BufferLength, Buffer, WriteLength, ReadyToRead);
    }
    bool Read(
        _Out_ uint64_t* BufferOffset,
        _Inout_ uint32_t* BufferCount,
        _Out_writes_all_(*BufferCount)
            QUIC_BUFFER* Buffers) {
        return QuicRecvBufferRead(&RecvBuf, BufferOffset, BufferCount, Buffers) != FALSE;
    }
    bool Drain(_In_ uint64_t BufferOffset) {
        return QuicRecvBufferDrain(&RecvBuf, BufferOffset) != FALSE;
    }
};

TEST(RecvBufferTest, Alloc)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Initialize(
            QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE,
            QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE,
            true));
}

TEST(RecvBufferTest, AllocWithChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Initialize(
            QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE,
            QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE,
            true,
            true));
}

void TestSingleWriteRead(
    bool WriteFront,
    bool DrainAll = true
    )
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize());
    const uint8_t BufferToWrite[] = "2408959yhsndgfavh0s89oeh52enfaswgf";
    uint64_t WriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            WriteFront ? 0 : 10,
            sizeof(BufferToWrite),
            BufferToWrite,
            &WriteLength,
            &ReadyToRead));
    if (!WriteFront) {
        ASSERT_EQ(sizeof(BufferToWrite), WriteLength);
        ASSERT_FALSE(ReadyToRead);
        ASSERT_EQ(sizeof(BufferToWrite)+10, RecvBuf.GetTotalLength());
    } else {
        ASSERT_EQ(sizeof(BufferToWrite), WriteLength);
        ASSERT_TRUE(ReadyToRead);
        ASSERT_EQ(sizeof(BufferToWrite), RecvBuf.GetTotalLength());
    }
    uint64_t ReadOffset;
    uint32_t ReadBufferCount = 1;
    QUIC_BUFFER ReadBuffer;
    ASSERT_EQ(
        WriteFront,
        RecvBuf.Read(
            &ReadOffset,
            &ReadBufferCount,
            &ReadBuffer));
    if (!WriteFront) return;
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1ul, ReadBufferCount);
    ASSERT_EQ(sizeof(BufferToWrite), ReadBuffer.Length);
    ASSERT_EQ(0, memcmp(BufferToWrite, ReadBuffer.Buffer, sizeof(BufferToWrite)));
    if (DrainAll) {
        ASSERT_TRUE(RecvBuf.Drain(ReadBuffer.Length));
    } else {
        ASSERT_FALSE(RecvBuf.Drain(10));
    }
}

TEST(RecvBufferTest, WriteFrontAndReadAll)
{
    TestSingleWriteRead(true);
}

TEST(RecvBufferTest, WriteFrontAndReadPartial)
{
    TestSingleWriteRead(true, false);
}

TEST(RecvBufferTest, WriteGap)
{
    TestSingleWriteRead(false);
}

TEST(RecvBufferTest, WriteTooMuch)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(8, 8));
    const uint8_t BufferToWrite[] = "2408959yhsndgfavh0s89oeh52enfaswgf";
    uint64_t WriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN ReadyToRead = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        RecvBuf.Write(
            0,
            sizeof(BufferToWrite),
            BufferToWrite,
            &WriteLength,
            &ReadyToRead));
}
