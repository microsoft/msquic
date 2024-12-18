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
        printf("Initializing: [mode=%u,vlen=%u,alen=%u]\n", RecvMode, VirtualBufferLength, AllocBufferLength);
        auto Result = QuicRecvBufferInitialize(&RecvBuf, AllocBufferLength, VirtualBufferLength, RecvMode, PreallocChunk);
        Dump();
        return Result;
    }
    uint64_t GetTotalLength() {
        return QuicRecvBufferGetTotalLength(&RecvBuf);
    }
    bool HasUnreadData() {
        return QuicRecvBufferHasUnreadData(&RecvBuf) != FALSE;
    }
    void IncreaseVirtualBufferLength(uint32_t Length) {
        QuicRecvBufferIncreaseVirtualBufferLength(&RecvBuf, Length);
    }
    QUIC_STATUS Write(
        _In_ uint64_t WriteOffset,
        _In_ uint16_t WriteLength,
        _Inout_ uint64_t* WriteLimit,
        _Out_ BOOLEAN* NewDataReady
        ) {
        auto BufferToWrite = new (std::nothrow) uint8_t[WriteLength];
        memset(BufferToWrite, 0, WriteLength); // Zero out the buffer (for debugging purposes)
        CXPLAT_FRE_ASSERT(BufferToWrite);
        for (uint16_t i = 0; i < WriteLength; ++i) {
            BufferToWrite[i] = (uint8_t)(WriteOffset + i);
        }
        printf("Write: Offset=%llu, Length=%u\n", (unsigned long long)WriteOffset, WriteLength);
        auto Status = QuicRecvBufferWrite(&RecvBuf, WriteOffset, WriteLength, BufferToWrite, WriteLimit, NewDataReady);
        delete [] BufferToWrite;
        Dump();
        return Status;
    }
    void Read(
        _Out_ uint64_t* BufferOffset,
        _Inout_ uint32_t* BufferCount,
        _Out_writes_all_(*BufferCount)
            QUIC_BUFFER* Buffers) {
        QuicRecvBufferRead(&RecvBuf, BufferOffset, BufferCount, Buffers);
        auto Offset = *BufferOffset;
        printf("Read: Offset=%llu [ ", (unsigned long long)*BufferOffset);
        for (uint32_t i = 0; i < *BufferCount; ++i) {
            printf("%u ", Buffers[i].Length);
            ValidateBuffer(Buffers[i].Buffer, Buffers[i].Length, Offset);
            Offset += Buffers[i].Length;
        }
        printf("]\n");
        Dump();
    }
    bool Drain(_In_ uint64_t BufferLength) {
        auto Result = QuicRecvBufferDrain(&RecvBuf, BufferLength) != FALSE;
        printf("Drain: Len=%llu, Res=%u\n", (unsigned long long)BufferLength, Result);
        Dump();
        return Result;
    }
    void Check(
        _In_ uint32_t ReadStart,
        _In_ uint32_t ReadLength,
        _In_ uint32_t NumChunks,
        _In_ BOOLEAN* ExternalReferences
    ) {
        ASSERT_EQ(RecvBuf.ReadStart, ReadStart);
        ASSERT_EQ(RecvBuf.ReadLength, ReadLength);
        int ChunkCount = 1;
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuf.Chunks.Flink,
                QUIC_RECV_CHUNK,
                Link);
        ASSERT_EQ(Chunk->ExternalReference, ExternalReferences[0]);
        while (Chunk->Link.Flink != &RecvBuf.Chunks) {
            ChunkCount++;
            Chunk =
                CXPLAT_CONTAINING_RECORD(
                    Chunk->Link.Flink,
                    QUIC_RECV_CHUNK,
                    Link);
            ASSERT_EQ(Chunk->ExternalReference, ExternalReferences[ChunkCount - 1]);
        }
        ASSERT_EQ(ChunkCount, NumChunks);
    }
    void WriteAndCheck(
        _In_ uint64_t WriteOffset,
        _In_ uint16_t WriteLength,
        _In_ uint32_t ReadStart,
        _In_ uint32_t ReadLength,
        _In_ uint32_t NumChunks,
        _In_ BOOLEAN* ExternalReferences
    ) {
        uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
        BOOLEAN NewDataReady = FALSE;

        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            Write(
                WriteOffset,
                WriteLength,
                &InOutWriteLength,
                &NewDataReady));

        Check(ReadStart, ReadLength, NumChunks, ExternalReferences);
    }
    void ReadAndCheck(
        _In_ uint32_t BufferCount,
        _In_ uint32_t* LengthList,
        _In_ uint32_t ReadStart,
        _In_ uint32_t ReadLength,
        _In_ uint32_t NumChunks,
        _In_ BOOLEAN* ExternalReferences
    ) {
        uint64_t ReadOffset;
        QUIC_BUFFER ReadBuffers[3];
        uint32_t ActualBufferCount = ARRAYSIZE(ReadBuffers);
        Read(&ReadOffset, &ActualBufferCount, ReadBuffers);

        ASSERT_EQ(BufferCount, ActualBufferCount);
        for (uint32_t i = 0; i < ActualBufferCount; ++i) {
            ASSERT_EQ(LengthList[i], ReadBuffers[i].Length);
        }
        Check(ReadStart, ReadLength, NumChunks, ExternalReferences);
    }
    // Validates the value of the buffer is equal to the offset.
    static void ValidateBuffer(_In_reads_(BufferLength) const uint8_t* Buffer, _In_ uint32_t BufferLength, _In_ uint64_t BufferOffset) {
        for (uint32_t i = 0; i < BufferLength; ++i) {
            ASSERT_EQ((uint8_t)(BufferOffset + i), Buffer[i]);
        }
    }
    void Dump() {
        printf("RecvBuffer: %p [mode=%u,vlen=%u,base=%llu,pending=%llu]\n",
            &RecvBuf, RecvBuf.RecvMode, RecvBuf.VirtualBufferLength, (unsigned long long)RecvBuf.BaseOffset, (unsigned long long)RecvBuf.ReadPendingLength);

        printf(" Written Ranges:\n");
        uint32_t i = 0;
        QUIC_SUBRANGE* Sub;
        while ((Sub = QuicRangeGetSafe(&RecvBuf.WrittenRanges, i++)) != nullptr) {
            printf("  [%llu, %llu]\n", (unsigned long long)Sub->Low, (unsigned long long)(Sub->Low+Sub->Count-1));
        }

        printf(" Chunks:\n");
        CXPLAT_LIST_ENTRY* Entry = RecvBuf.Chunks.Flink;
        while (Entry != &RecvBuf.Chunks) {
            auto Chunk = CXPLAT_CONTAINING_RECORD(Entry, QUIC_RECV_CHUNK, Link);
            printf("  %p: Len=%u, Ext=%u", Chunk, Chunk->AllocLength, Chunk->ExternalReference);
            if (Entry == RecvBuf.Chunks.Flink) {
                printf(", Start=%u, Len=%u", RecvBuf.ReadStart, RecvBuf.ReadLength);
            }
            // Print hex output of buffer
            for (i = 0; i < Chunk->AllocLength; ++i) {
                if (i % 16 == 0) printf("\n    ");
                printf("%02X ", Chunk->Buffer[i]);
            }
            printf("\n");
            Entry = Entry->Flink;
        }
        printf("\n");
    }
};

struct WithMode : public ::testing::TestWithParam<QUIC_RECV_BUF_MODE> {
    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_P(WithMode, Alloc)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam()));
}

TEST_P(WithMode, AllocWithChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam(), true));
}

void TestSingleWriteRead(QUIC_RECV_BUF_MODE Mode, uint16_t WriteLength, uint64_t WriteOffset, uint64_t DrainLength)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            WriteOffset,
            WriteLength,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_EQ(WriteOffset == 0, NewDataReady != FALSE); // Only ready to read if we wrote to the front
    ASSERT_EQ(WriteOffset == 0, RecvBuf.HasUnreadData());
    ASSERT_EQ(WriteLength+WriteOffset, InOutWriteLength); // All data was newly written
    ASSERT_EQ(WriteLength+WriteOffset, RecvBuf.GetTotalLength()); // Total length should be offset plus write length
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    if (!NewDataReady) return; // Can't read if it's not ready
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1ul, BufferCount);
    ASSERT_EQ(WriteLength, ReadBuffers[0].Length);
    ASSERT_EQ(DrainLength == WriteLength, RecvBuf.Drain(DrainLength));
    ASSERT_EQ(DrainLength != WriteLength && Mode != QUIC_RECV_BUF_MODE_MULTIPLE, // In multiple mode, a partial drain doesn't mean you now have unread data
              RecvBuf.HasUnreadData());
}

TEST_P(WithMode, WriteFrontAndReadAll)
{
    TestSingleWriteRead(GetParam(), 30, 0, 30);
}

TEST_P(WithMode, WriteFrontAndReadPartial)
{
    TestSingleWriteRead(GetParam(), 30, 0, 20);
}

TEST_P(WithMode, WriteGap)
{
    TestSingleWriteRead(GetParam(), 30, 10, 0);
}

TEST_P(WithMode, DrainZero)
{
    TestSingleWriteRead(GetParam(), 30, 0, 0);
}

TEST_P(WithMode, WriteFillGap)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam()));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            10,
            20,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_FALSE(NewDataReady);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            10,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, InOutWriteLength);
    ASSERT_EQ(30ull, RecvBuf.GetTotalLength());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1ul, BufferCount);
    ASSERT_EQ(30u, ReadBuffers[0].Length);
}

TEST_P(WithMode, Overwrite)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam()));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            30,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            10,
            10,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_FALSE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData()); // Still ready to read from the first write
    ASSERT_EQ(0ull, InOutWriteLength); // No newly written data
    ASSERT_EQ(30ull, RecvBuf.GetTotalLength());
}

TEST_P(WithMode, OverwritePartial)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam()));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            30,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            25,
            10,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(5ull, InOutWriteLength); // Only 5 newly written bytes
    ASSERT_EQ(35ull, RecvBuf.GetTotalLength());
}

TEST_P(WithMode, WriteTooMuch)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam(), false, 8, 8)); // Small buffer
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        RecvBuf.Write(
            0,
            30, // Larger than small buffer
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_FALSE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, WriteTooMuch2)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam()));
    uint64_t InOutWriteLength = 10; // i.e. simulate a small connection-wide FC limit
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        RecvBuf.Write(
            0,
            30, // Larger than FC limit
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_FALSE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, WriteWhilePendingRead)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam()));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            20,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(20u, ReadBuffers[0].Length);
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            20,
            20,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady); // Still ready to read
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(20ull, InOutWriteLength);
    ASSERT_EQ(40ull, RecvBuf.GetTotalLength());
    ASSERT_FALSE(RecvBuf.Drain(20));
    ASSERT_TRUE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, WriteLargeWhilePendingRead)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            20,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(20u, ReadBuffers[0].Length);
    InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            20,
            512,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady); // Still ready to read
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(512ull, InOutWriteLength);
    ASSERT_EQ(532ull, RecvBuf.GetTotalLength());
    ASSERT_FALSE(RecvBuf.Drain(20) && Mode != QUIC_RECV_BUF_MODE_MULTIPLE);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, WriteLarge)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            256,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(256ull, InOutWriteLength);
    ASSERT_EQ(256ull, RecvBuf.GetTotalLength());
}

TEST_P(WithMode, MultiWriteLarge)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
        BOOLEAN NewDataReady = FALSE;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            RecvBuf.Write(
                i * 64,
                64,
                &InOutWriteLength,
                &NewDataReady));
        ASSERT_TRUE(NewDataReady);
        ASSERT_TRUE(RecvBuf.HasUnreadData());
        ASSERT_EQ(64ull, InOutWriteLength);
        ASSERT_EQ((i + 1) * 64ull, RecvBuf.GetTotalLength());
    }
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(256u, ReadBuffers[0].Length);
    ASSERT_TRUE(RecvBuf.Drain(256));
    ASSERT_FALSE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, ReadPartial)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            32,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(32ull, InOutWriteLength);
    ASSERT_EQ(32ull, RecvBuf.GetTotalLength());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(32u, ReadBuffers[0].Length);
    ASSERT_FALSE(RecvBuf.Drain(16)); // Partial drain
    ASSERT_TRUE(Mode == QUIC_RECV_BUF_MODE_MULTIPLE || RecvBuf.HasUnreadData());
    InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            32,
            48,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(48ull, InOutWriteLength);
    ASSERT_EQ(80ull, RecvBuf.GetTotalLength());
    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    if (Mode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        ASSERT_EQ(32ull, ReadOffset);
        ASSERT_EQ(2u, BufferCount);
        ASSERT_EQ(32u, ReadBuffers[0].Length);
        ASSERT_EQ(16u, ReadBuffers[1].Length);
    } else {
        ASSERT_EQ(16ull, ReadOffset);
        if (Mode == QUIC_RECV_BUF_MODE_SINGLE) {
            ASSERT_EQ(1u, BufferCount);
            ASSERT_EQ(64u, ReadBuffers[0].Length);
        } else {
            ASSERT_EQ(2u, BufferCount);
            ASSERT_EQ(48u, ReadBuffers[0].Length);
            ASSERT_EQ(16u, ReadBuffers[1].Length);
        }
    }
    ASSERT_TRUE(RecvBuf.Drain(64));
    ASSERT_FALSE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, ReadPendingMultiWrite)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            32,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(32ull, InOutWriteLength);
    ASSERT_EQ(32ull, RecvBuf.GetTotalLength());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
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
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(48ull, InOutWriteLength);
    ASSERT_EQ(80ull, RecvBuf.GetTotalLength());
    ASSERT_FALSE(RecvBuf.Drain(32) && Mode != QUIC_RECV_BUF_MODE_MULTIPLE);
    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(32ull, ReadOffset);
    if (Mode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        ASSERT_EQ(2u, BufferCount);
        ASSERT_EQ(32u, ReadBuffers[0].Length);
        ASSERT_EQ(16u, ReadBuffers[1].Length);
    } else {
        ASSERT_EQ(1u, BufferCount);
        ASSERT_EQ(48u, ReadBuffers[0].Length);
    }
    ASSERT_TRUE(RecvBuf.Drain(48));
    ASSERT_FALSE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, RecvCrypto) // Note - Values based on a previous failing MsQuic crypto test failure
{
#define CRYTPO_RECV_SIZE 128
#define CRYPTO_FC_SIZE 32768
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, CRYTPO_RECV_SIZE, CRYPTO_FC_SIZE));
    uint64_t InOutWriteLength = CRYPTO_FC_SIZE; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            48,
            16,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_FALSE(NewDataReady);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    InOutWriteLength = CRYPTO_FC_SIZE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            32,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.Drain(16)); // Partial drain
    ASSERT_TRUE(Mode == QUIC_RECV_BUF_MODE_MULTIPLE || RecvBuf.HasUnreadData());
    InOutWriteLength = CRYPTO_FC_SIZE;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            32,
            16,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(0ull, InOutWriteLength);
    ASSERT_EQ(64ull, RecvBuf.GetTotalLength());
    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(1ul, BufferCount);
    if (Mode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        ASSERT_EQ(32ull, ReadOffset);
        ASSERT_EQ(32u, ReadBuffers[0].Length);
    } else {
        ASSERT_EQ(16ull, ReadOffset);
        ASSERT_EQ(48u, ReadBuffers[0].Length);
    }
}

TEST_P(WithMode, DrainFrontChunkWithPendingGap)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(GetParam(), false));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;

    // place data at some future offset
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            2,
            1,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_FALSE(RecvBuf.HasUnreadData());

    // place data to the front and drain
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            0,
            1,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);

    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_EQ(1ul, BufferCount);
    ASSERT_EQ(1ul, ReadBuffers[0].Length);
    ASSERT_TRUE(RecvBuf.Drain(1));

    // insert missing chunk and drain the rest
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(
        QUIC_STATUS_SUCCESS,
        RecvBuf.Write(
            1,
            1,
            &InOutWriteLength,
            &NewDataReady));
    ASSERT_TRUE(NewDataReady);

    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    uint64_t TotalRead = 0;
    for (uint32_t i = 0; i < BufferCount; ++i) {
        TotalRead += ReadBuffers[i].Length;
    }
    ASSERT_EQ(2ul, TotalRead);
    ASSERT_FALSE(RecvBuf.Drain(1)); // more data left in buffer

    if (GetParam() != QUIC_RECV_BUF_MODE_MULTIPLE) {
        BufferCount = ARRAYSIZE(ReadBuffers);
        RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
        TotalRead = 0;
        for (uint32_t i = 0; i < BufferCount; ++i) {
            TotalRead += ReadBuffers[i].Length;
        }
        ASSERT_EQ(1ul, TotalRead);
    }
    ASSERT_TRUE(RecvBuf.Drain(1));
}

// Validate the gap can span the edge of a chunk
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
// |R, R, R, R, 4, 5, 6, x| ReadStart:0, ReadLength:7, Ext:1
// |R, R, R, R, 4, 5, 6, G] [G,9,10,11,....] ReadStart:0, ReadLength:7, Ext:1
// |R, R, R, R, 4, 5, 6, 7] [8,9,10,11,....] ReadStart:0, ReadLength:8, Ext:1
TEST(MultiRecvTest, GapEdge)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, x| ReadStart:0, ReadLength:7, Ext:1
    RecvBuf.WriteAndCheck(4, 3, 0, 7, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, G] [G,9,10,11,....] ReadStart:0, ReadLength:7, Ext:1
    RecvBuf.WriteAndCheck(9, 3, 0, 7, 2, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, 7] [8,9,10,11,....] ReadStart:0, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(7, 2, 0, 8, 2, ExternalReferences);

    LengthList[0] = 4;
    LengthList[1] = 4;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 0, 8, 2, ExternalReferences);
}

// Validate the gap can span the edge of a chunk (cycle)
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
// |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLength:4, Ext:0
// |D, D, D, D, R, R, R, R] ReadStart:4, ReadLength:4, Ext:1
// |8, 9,10, D, R, R, R, R] ReadStart:4, ReadLength:7, Ext:1
// |8, 9,10, G, R, R, R, R] [ G,13,14,15, ...] ReadStart:4, ReadLength:7, Ext:1
// |8, 9,10,11, R, R, R, R] [12,13,14,15, ...] ReadStart:4, ReadLength:8, Ext:1
TEST(MultiRecvTest, GapCycleEdge)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLength:4, Ext:0
    RecvBuf.Drain(4);
    // |D, D, D, D, R, R, R, R] ReadStart:4, ReadLength:4, Ext:1
    RecvBuf.ReadAndCheck(1, LengthList, 4, 4, 1, ExternalReferences);
    // |8, 9,10, D, R, R, R, R] ReadStart:4, ReadLength:7, Ext:1
    RecvBuf.WriteAndCheck(8, 3, 4, 7, 1, ExternalReferences);
    // |8, 9,10, G, R, R, R, R] [ G,13,14,15, ...] ReadStart:4, ReadLength:7, Ext:1
    RecvBuf.WriteAndCheck(13, 3, 4, 7, 2, ExternalReferences);
    // |8, 9,10,11, R, R, R, R] [12,13,14,15, ...] ReadStart:4, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(11, 2, 4, 8, 2, ExternalReferences);

    LengthList[1] = 4;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 4, 8, 2, ExternalReferences);
    RecvBuf.Drain(12);
}

// Validate if resized and copying content to bigger chunk
// |0, 1, 2, 3, x, x, x, x] ReadStart:0, ReadLengt:4, Ext:0
// |R, R, R, R, x, x, x, x] ReadStart:0, ReadLengt:4, Ext:1
// |R, R, R, R, 4, 5, 6, 7] ReadStart:0, ReadLengt:8, Ext:1
// |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLengt:4, Ext:0
// [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLengt:12, Ext:0
TEST(MultiRecvTest, PartialDrainGrow)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x] ReadStart:0, ReadLengt:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x] ReadStart:0, ReadLengt:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, 7] ReadStart:0, ReadLengt:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLengt:4, Ext:0
    RecvBuf.Drain(4);
    // [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLengt:12, Ext:0
    ExternalReferences[0] = FALSE;
    RecvBuf.WriteAndCheck(8, 8, 0, 12, 1, ExternalReferences);

    LengthList[0] = 12;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 12, 1, ExternalReferences);
    RecvBuf.Drain(12);
}

// Validate if resized and copying content to bigger chunk
// [0, 1, 2, 3, x, x, x, x] ReadStart:0, ReadLengt:4, Ext:0
// |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
// [R, R, R, R, 4, 5, 6, 7] ReadStart:0, ReadLengt:8, Ext:1
// [D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLengt:4, Ext:0
// [8, G, G,11, 4, 5, 6, 7] ReadStart:4, ReadLengt:5, Ext:0
// [4, 5, 6, 7, 8, G, G,11,12,13,14,15, ...] ReadStart:0, ReadLengt:5, Ext:0
// [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLengt:12, Ext:0
TEST(MultiRecvTest, PartialDrainGapGrow)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // [0, 1, 2, 3, x, x, x, x] ReadStart:0, ReadLengt:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // [R, R, R, R, 4, 5, 6, 7] ReadStart:0, ReadLengt:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // [D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLengt:4, Ext:0
    RecvBuf.Drain(4);
    ExternalReferences[0] = FALSE;
    // [8, G, G,11, 4, 5, 6, 7] ReadStart:4, ReadLengt:5, Ext:0
    RecvBuf.WriteAndCheck(8, 1, 4, 5, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(11, 1, 4, 5, 1, ExternalReferences);
    // [4, 5, 6, 7, 8, G, G,11,12,13,14,15, ...] ReadStart:0, ReadLengt:5, Ext:0
    RecvBuf.WriteAndCheck(12, 4, 0, 5, 1, ExternalReferences);
    // [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLengt:12, Ext:0
    RecvBuf.WriteAndCheck(9, 2, 0, 12, 1, ExternalReferences);

    LengthList[0] = 12;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 12, 1, ExternalReferences);
    RecvBuf.Drain(12);
}

// Validate if resized and copying content to bigger chunk
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
// |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
// |R, R, R, R, 4, 5, 6, x| ReadStart:0, ReadLength:7, Ext:1
// |D, D, D, D, 4, 5, 6, x] ReadStart:4, ReadLength:3, Ext:0
// |G, 9,10,11, 4, 5, 6, G] ReadStart:4, ReadLength:3, Ext:0
// [4, 5, 6, G, G, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLength:3,  Ext:0
// [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLength:12, Ext:0
TEST(MultiRecvTest, PartialDrainGapEdgeGrow)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, x| ReadStart:0, ReadLength:7, Ext:1
    RecvBuf.WriteAndCheck(4, 3, 0, 7, 1, ExternalReferences);
    // |D, D, D, D, 4, 5, 6, x] ReadStart:4, ReadLength:3, Ext:0
    RecvBuf.Drain(4);
    ExternalReferences[0] = FALSE;
    // |G, 9,10,11, 4, 5, 6, G] ReadStart:4, ReadLength:3, Ext:0
    RecvBuf.WriteAndCheck(9, 3, 4, 3, 1, ExternalReferences);
    // [4, 5, 6, G, G, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLength:3,  Ext:0
    RecvBuf.WriteAndCheck(12, 4, 0, 3, 1, ExternalReferences);
    // [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLength:12, Ext:0
    RecvBuf.WriteAndCheck(7, 2, 0, 12, 1, ExternalReferences);

    LengthList[0] = 12;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 12, 1, ExternalReferences);
    RecvBuf.Drain(12);
}

// Validate if resized and copying content to bigger chunk
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLength:4, Ext:0
// |8, 9,10, D, 4, 5, 6, 7] ReadStart:4, ReadLength:7, Ext:0
// [4, 5, 6, 7, 8, 9,10, G, G,13,14,15, ...] ReadStart:0, ReadLength:7,  Ext:0
// [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLength:12, Ext:0
TEST(MultiRecvTest, PartialDrainGapCycleEdgeGrow)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:8, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLength:4, Ext:0
    RecvBuf.Drain(4);
    ExternalReferences[0] = FALSE;
    // |8, 9,10, D, 4, 5, 6, 7] ReadStart:4, ReadLength:7, Ext:0
    RecvBuf.WriteAndCheck(8, 3, 4, 7, 1, ExternalReferences);
    // [4, 5, 6, 7, 8, 9,10, G, G,13,14,15, ...] ReadStart:0, ReadLength:7,  Ext:0
    RecvBuf.WriteAndCheck(13, 3, 0, 7, 1, ExternalReferences);
    // [4, 5, 6, 7, 8, 9,10,11,12,13,14,15, ...] ReadStart:0, ReadLength:12, Ext:0
    RecvBuf.WriteAndCheck(11, 2, 0, 12, 1, ExternalReferences);

    LengthList[0] = 12;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 12, 1, ExternalReferences);
    RecvBuf.Drain(12);
}

// Validate if resized, but appended
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
// |D, D, R, R, 4, 5, 6, 7] ReadStart:2, ReadLength:6, Ext:1
// |8, 9, R, R, 4, 5, 6, 7] ReadStart:2, ReadLength:8, Ext:1
// |8, 9, R, R, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:2, ReadLength:8, Ext:1
// |8, 9, D, D, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:2, ReadLength:6, Ext:0
// |8, 9, D, D, 4, 5, 6, 7] [10,11,12,13, ...] ReadStart:2, ReadLength:6, Ext:0
TEST(MultiRecvTest, PartialDrainSmallWriteAppend)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:8, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // |D, D, R, R, 4, 5, 6, 7] ReadStart:2, ReadLength:6, Ext:1
    RecvBuf.Drain(2);
    // |8, 9, R, R, 4, 5, 6, 7] ReadStart:2, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(8, 2, 2, 8, 1, ExternalReferences);
    // |8, 9, R, R, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:2, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(10, 2, 2, 8, 2, ExternalReferences);
    // |8, 9, D, D, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:2, ReadLength:6, Ext:0
    RecvBuf.Drain(2);
    ExternalReferences[0] = FALSE;
    // |8, 9, D, D, 4, 5, 6, 7] [10,11,12,13, ...] ReadStart:2, ReadLength:6, Ext:0
    RecvBuf.WriteAndCheck(12, 2, 4, 6, 2, ExternalReferences);

    LengthList[0] = 4;
    LengthList[1] = 2;
    LengthList[2] = 4;
    ExternalReferences[0] = TRUE;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(3, LengthList, 4, 6, 2, ExternalReferences);
    RecvBuf.Drain(10);
}

// Validate if resized, but appended
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
// |D, D, R, R, 4, 5, 6, 7] ReadStart:2, ReadLength:6, Ext:1
// |8, 9, R, R, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:2, ReadLength:8, Ext:1
// |8, 9, D, D, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:4, ReadLength:6, Ext:0
// |8, 9, D, D, 4, 5, 6, 7] [10,11,12,13, ...] ReadStart:4, ReadLength:6, Ext:0
TEST(MultiRecvTest, PartialDrainBigWriteAppend)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // |D, D, R, R, 4, 5, 6, 7] ReadStart:2, ReadLength:6, Ext:1
    RecvBuf.Drain(2);
    // |8, 9, R, R, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:2, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(8, 4, 2, 8, 2, ExternalReferences);
    // |8, 9, D, D, 4, 5, 6, 7] [10,11, x, x, ...] ReadStart:4, ReadLength:6, Ext:0
    RecvBuf.Drain(2);
    ExternalReferences[0] = FALSE;
    // |8, 9, D, D, 4, 5, 6, 7] [10,11,12,13, ...] ReadStart:4, ReadLength:6, Ext:0
    RecvBuf.WriteAndCheck(12, 2, 4, 6, 2, ExternalReferences);

    LengthList[0] = 4;
    LengthList[1] = 2;
    LengthList[2] = 4;
    ExternalReferences[0] = TRUE;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(3, LengthList, 4, 6, 2, ExternalReferences);
    RecvBuf.Drain(10);
}

// Validate ReadLength with 2 gaps
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:7, Ext:1
// |R, R, R, R, 4, x, x, x| ReadStart:0, ReadLength:5, Ext:1
// |R, R, R, R, 4, G, G, 7| [ 8, x, x, x, x, ...] ReadStart:0, ReadLength:5, Ext:1
// |D, D, D, D, 4, G, G, 7| [ 8, x, x, x, x, ...] ReadStart:4, ReadLength:1, Ext:0
// |D, D, D, D, 4, G, G, 7| [ 8, G,10,11, x, ...] ReadStart:4, ReadLength:1, Ext:0
// |D, D, D, D, 4, 5, 6, 7| [ 8, G,10,11, x, ...] ReadStart:4, ReadLength:4, Ext:0
// |D, D, D, D, R, R, R, R| [ R, G,10,11, x, ...] ReadStart:4, ReadLength:4, Ext:1
// |D, G,10,11, x, ...] ReadStart:1, ReadLength:0, Ext:0
// |D, 9,10,11, x, ...] ReadStart:1, ReadLength:3, Ext:0
TEST(MultiRecvTest, TwoGapWithTwoChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);

    RecvBuf.WriteAndCheck(4, 1, 0, 5, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(7, 2, 0, 5, 2, ExternalReferences);
    RecvBuf.Drain(4);
    ExternalReferences[0] = FALSE;

    RecvBuf.WriteAndCheck(10, 2, 4, 1, 2, ExternalReferences);

    RecvBuf.WriteAndCheck(5, 2, 4, 4, 2, ExternalReferences);

    LengthList[0] = 4;
    LengthList[1] = 1;
    ExternalReferences[0] = TRUE;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 4, 4, 2, ExternalReferences);
    RecvBuf.Drain(5);
    ExternalReferences[0] = FALSE;
    ExternalReferences[1] = FALSE;
    RecvBuf.WriteAndCheck(9, 1, 1, 3, 1, ExternalReferences);

    LengthList[0] = 3;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 1, 3, 1, ExternalReferences);
    RecvBuf.Drain(3);
}

// Validate ReadLength with 2 gaps
// |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
// |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
// |R, R, R, R, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, R, 4, 5, 6, 7| ReadStart:3, ReadLength:5, Ext:1
// |8, 9, D, R, 4, 5, 6, 7| ReadStart:3, ReadLength:7, Ext:1
// |8, 9, G, R, 4, 5, 6, 7| [ G,12, x, x, ...] ReadStart:3, ReadLength:7, Ext:0
// |8, 9,10, R, 4, 5, 6, 7| [ G,12, x, x, ...] ReadStart:3, ReadLength:8, Ext:0
// |8, 9,10, R, 4, 5, 6, 7| [11,12, G,14, ...] ReadStart:3, ReadLength:8, Ext:0
// |8, 9,10, R, 4, 5, 6, 7| [11,12,13,14, ...] ReadStart:3, ReadLength:8, Ext:0
TEST(MultiRecvTest, TwoGapCycleEdgeWithTwoChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};
    // |0, 1, 2, 3, x, x, x, x| ReadStart:0, ReadLength:4, Ext:0
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    // |R, R, R, R, x, x, x, x| ReadStart:0, ReadLength:4, Ext:1
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 4, 1, ExternalReferences);

    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(3);
    RecvBuf.WriteAndCheck(8, 2, 3, 7, 1, ExternalReferences);

    RecvBuf.WriteAndCheck(12, 1, 3, 7, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(14, 1, 3, 7, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(10, 2, 3, 8, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(13, 1, 3, 8, 2, ExternalReferences);

    LengthList[0] = 4;
    LengthList[1] = 3;
    LengthList[2] = 4;
    ExternalReferences[0] = TRUE;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(3, LengthList, 3, 8, 2, ExternalReferences);
    RecvBuf.Drain(12);
}

// |0, 1, 2, 3, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:0
// |R, R, R, R, R, R, R, R| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, D, D, D, R, R| ReadStart:6, ReadLength:2, Ext:1
// |8, 9,10,11,12,13, R, R| [14,15, x, x] ReadStart:6, ReadLength:8, Ext:1
// |R, R, R, R, R, R, R, R| [ R, R, x, x] ReadStart:6, ReadLength:8, Ext:1
// |D, D, R, R, R, R, D, D| [ R, R, x, x] ReadStart:2, ReadLength:4, Ext:1
// |D, D, R, R, R, R, D, D| [ R, R,16,17,18, ...] ReadStart:2, ReadLength:4, Ext:1
// [D, D,16,17,18, ...] ReadStart:2, ReadLength:3, Ext:0
TEST(MultiRecvTest, ReadCycleSpan)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(6);
    RecvBuf.WriteAndCheck(8, 8, 6, 8, 2, ExternalReferences);
    LengthList[0] = 6;
    LengthList[1] = 2;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 6, 8, 2, ExternalReferences);
    RecvBuf.Drain(4);
    RecvBuf.WriteAndCheck(16, 3, 2, 4, 2, ExternalReferences);
    RecvBuf.Drain(6);
    LengthList[0] = 3;
    RecvBuf.ReadAndCheck(1, LengthList, 2, 3, 1, ExternalReferences);
    RecvBuf.Drain(3);
}

// |0, 1, 2, 3, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:0
// |R, R, R, R, R, R, R, R| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, D, D, D, R, R| ReadStart:6, ReadLength:2, Ext:1
// |8, D, D, D, D, D, R, R| ReadStart:6, ReadLength:3, Ext:1
// |8, G, 7, D, D, D, R, R| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10, G, D, D, R, R| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10, G,12, D, R, R| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10, G,12, G, R, R| |14, x, x, x, ...| ReadStart:6, ReadLength:3, Ext:1 // dead
// |8, G,10, G,12, G, R, R| |14, G,16, x, ...| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10,11,12, G, R, R| |14, G,16, x, ...| ReadStart:6, ReadLength:3, Ext:1
// |8, 9,10,11,12, G, R, R| |14, G,16, x, ...| ReadStart:6, ReadLength:7, Ext:1
// |8, 9,10,11,12, G, R, R| |14,15,16, x, ...| ReadStart:6, ReadLength:7, Ext:1
// |8, 9,10,11,12,13, R, R| |14,15,16, x, ...| ReadStart:6, ReadLength:8, Ext:1
TEST(MultiRecvTest, MultiGap)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(6);
    RecvBuf.WriteAndCheck(8, 1, 6, 3, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(10, 1, 6, 3, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(12, 1, 6, 3, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(14, 1, 6, 3, 2, ExternalReferences); // dead
    RecvBuf.WriteAndCheck(16, 1, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(11, 1, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(9, 1, 6, 7, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(15, 1, 6, 7, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(13, 1, 6, 8, 2, ExternalReferences);

    LengthList[0] = 6;
    LengthList[1] = 3;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 6, 8, 2, ExternalReferences);
    RecvBuf.Drain(9);
}

TEST(MultiRecvTest, MultiGapOverwrap)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(6);
    RecvBuf.WriteAndCheck(8, 1, 6, 3, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(10, 1, 6, 3, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(12, 1, 6, 3, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(14, 1, 6, 3, 2, ExternalReferences); // dead
    RecvBuf.WriteAndCheck(16, 1, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(14, 2, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(11, 2, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(8, 5, 6, 7, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(11, 5, 6, 8, 2, ExternalReferences);

    LengthList[0] = 6;
    LengthList[1] = 3;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 6, 8, 2, ExternalReferences);
    RecvBuf.Drain(9);
}

// |0, 1, 2, 3, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:0
// |R, R, R, R, R, R, R, R| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, D, R, R, R, R| ReadStart:4, ReadLength:4, Ext:1
// |8, D, D, D, R, R, R, R| ReadStart:4, ReadLength:5, Ext:1
// |8, G,10, D, R, R, R, R| ReadStart:4, ReadLength:5, Ext:1
// |8, G,10, G, R, R, R, R| |12, x, x, ...| ReadStart:4, ReadLength:5, Ext:1 // dead
// |8, G,10, G, D, D, R, R| |12, x, x, ...| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10, G, D, D, R, R| |12, G,14, ...| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10,11, D, D, R, R| |12, G,14, ...| ReadStart:6, ReadLength:3, Ext:1
// |8, G,10,11, D, D, R, R| |12,13,14, ...| ReadStart:6, ReadLength:3, Ext:1
// |8, 9,10,11, D, D, R, R| |12,13,14, ...| ReadStart:6, ReadLength:6, Ext:1
TEST(MultiRecvTest, MultiGapDead)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(4);
    RecvBuf.WriteAndCheck(8, 1, 4, 5, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(10, 1, 4, 5, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(12, 1, 4, 5, 2, ExternalReferences); // dead
    RecvBuf.Drain(2);
    RecvBuf.WriteAndCheck(14, 1, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(11, 1, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(13, 1, 6, 3, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(9, 1, 6, 6, 2, ExternalReferences);

    LengthList[0] = 4;
    LengthList[1] = 3;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 6, 6, 2, ExternalReferences);
    RecvBuf.Drain(9);
}

// |0, 1, 2, 3, 4, 5, 6, 7| ReadStart:0, ReadLength:8, Ext:0
// |R, R, R, R, R, R, R, R| ReadStart:0, ReadLength:8, Ext:1
// |D, D, D, D, D, D, R, R| ReadStart:6, ReadLength:2, Ext:1
// |8, 9,10,11,12,13, R, R| [14,15, x, x] ReadStart:6, ReadLength:8, Ext:1
// |R, R, R, R, R, R, R, R| [ R, R, x, x] ReadStart:6, ReadLength:8, Ext:1
// [ D, R, x, x, x, ...] ReadStart:1, ReadLength:1, Ext:1
// [ D, R,16,17,18, ...] ReadStart:1, ReadLength:4, Ext:1
TEST(MultiRecvTest, ReadDrainCycleSpan)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(6);
    RecvBuf.WriteAndCheck(8, 8, 6, 8, 2, ExternalReferences);
    LengthList[0] = 6;
    LengthList[1] = 2;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 6, 8, 2, ExternalReferences);
    RecvBuf.Drain(9);
    RecvBuf.WriteAndCheck(16, 3, 1, 4, 1, ExternalReferences);
    LengthList[0] = 3;
    RecvBuf.ReadAndCheck(1, LengthList, 1, 4, 1, ExternalReferences);
    RecvBuf.Drain(3);
}

// |0, 1, 2, 3, 4, 5, x, x| ReadStart:0, ReadLength:6, Ext:0
// |R, R, R, R, R, R, x, x| ReadStart:0, ReadLength:6, Ext:1
// |R, R, R, R, R, R, 6, 7| ReadStart:0, ReadLength:8, Ext:1
// |D, D, R, R, R, R, 6, 7| ReadStart:2, ReadLength:6, Ext:1
// |8, 9, R, R, R, R, 6, 7| [10, x, x, x, ...] ReadStart:2, ReadLength:8, Ext:1
// |8, 9, R, R, R, R, 6, 7| [10, G,12, x, ...] ReadStart:2, ReadLength:8, Ext:1
// |R, R, D, D, R, R, R, R| [ R, G,12, x, ...] ReadStart:4, ReadLength:6, Ext:1
// |R, R, D, D, R, R, R, R| [ R, G,12, G,14, ...] ReadStart:4, ReadLength:6, Ext:1
// |D, R, D, D, D, D, D, D| [ R, G,12, G,14, ...] ReadStart:1, ReadLength:1, Ext:1 // expand 2nd?
// |D, R, D, D, D, D, D, D| [ R, G,12,13,14, ...] ReadStart:1, ReadLength:1, Ext:1
// [D, G,12,13,14, ...] ReadStart:1, ReadLength:0, Ext:0
// [D,11,12,13,14, ...] ReadStart:1, ReadLength:4, Ext:0
TEST(MultiRecvTest, Dead1stChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 6, 0, 6, 1, ExternalReferences);
    LengthList[0] = 6;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 6, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(6, 2, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(2);
    RecvBuf.WriteAndCheck(8, 3, 2, 8, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(12, 1, 2, 8, 2, ExternalReferences);
    LengthList[0] = 2;
    LengthList[1] = 2;
    LengthList[2] = 1;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(3, LengthList, 2, 8, 2, ExternalReferences);
    RecvBuf.Drain(2);
    RecvBuf.WriteAndCheck(14, 1, 4, 6, 2, ExternalReferences);
    RecvBuf.Drain(5);
    RecvBuf.WriteAndCheck(13, 1, 1, 1, 2, ExternalReferences);
    RecvBuf.Drain(2);
    ExternalReferences[0] = FALSE;
    RecvBuf.WriteAndCheck(11, 1, 1, 4, 1, ExternalReferences);
    LengthList[0] = 4;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 1, 4, 1, ExternalReferences);
    RecvBuf.Drain(4);
}

TEST(MultiRecvTest, Grow1stChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {160, 0, 0};
    RecvBuf.WriteAndCheck(0, 4, 0, 4, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(4, 8, 0, 12, 1, ExternalReferences); // grow -> 16
    RecvBuf.WriteAndCheck(12, 16, 0, 28, 1, ExternalReferences); // grow -> 32
    RecvBuf.WriteAndCheck(28, 32, 0, 60, 1, ExternalReferences); // grow -> 64
    RecvBuf.WriteAndCheck(60, 100, 0, 160, 1, ExternalReferences); // grow -> 256
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 160, 1, ExternalReferences);
    RecvBuf.Drain(160);
}

TEST(MultiRecvTest, Grow2ndChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    uint32_t LengthList[] = {8, 0, 0};
    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(8, 8, 0, 8, 2, ExternalReferences); // append -> 16
    RecvBuf.WriteAndCheck(16, 16, 0, 8, 2, ExternalReferences); // grow -> 32
    RecvBuf.WriteAndCheck(32, 64, 0, 8, 2, ExternalReferences); // grow -> 128
    ExternalReferences[1] = TRUE;
    LengthList[0] = 88;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 2, ExternalReferences);
    RecvBuf.Drain(96);
}

TEST(MultiRecvTest, Grow3rdChunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE, FALSE};
    uint32_t LengthList[] = {8, 0, 0};
    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(8, 32, 0, 8, 2, ExternalReferences); // append -> 32
    LengthList[0] = 32;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 2, ExternalReferences);
    RecvBuf.WriteAndCheck(40, 64, 0, 8, 3, ExternalReferences); // append -> 64
    RecvBuf.WriteAndCheck(104, 20, 0, 8, 3, ExternalReferences); // grow -> 128
    ExternalReferences[2] = TRUE;
    LengthList[0] = 84;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 3, ExternalReferences);
    RecvBuf.Drain(124);
}

TEST(MultiRecvTest, ReadPendingOver2Chunk)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_MULTIPLE, false, 8, LARGE_TEST_BUFFER_LENGTH));
    BOOLEAN ExternalReferences[] = {FALSE, FALSE, FALSE};
    uint32_t LengthList[] = {8, 0, 0};
    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences);
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.WriteAndCheck(8, 8, 0, 8, 2, ExternalReferences); // append -> 16
    LengthList[0] = 8;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 2, ExternalReferences);

    RecvBuf.WriteAndCheck(16, 8, 0, 8, 2, ExternalReferences); // append -> 16
    RecvBuf.Drain(16);
    LengthList[0] = 8;
    RecvBuf.ReadAndCheck(1, LengthList, 8, 8, 1, ExternalReferences);
    RecvBuf.Drain(8);
}

INSTANTIATE_TEST_SUITE_P(
    RecvBufferTest,
    WithMode,
    ::testing::Values(QUIC_RECV_BUF_MODE_SINGLE, QUIC_RECV_BUF_MODE_CIRCULAR, QUIC_RECV_BUF_MODE_MULTIPLE),
    testing::PrintToStringParamName());
