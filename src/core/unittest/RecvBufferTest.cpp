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

#include <array>
#include <vector>

#define DEF_TEST_BUFFER_LENGTH 64u
#define LARGE_TEST_BUFFER_LENGTH 1024u

struct RecvBuffer {
    QUIC_RECV_BUFFER RecvBuf {0};
    CXPLAT_POOL AppBufferChunkPool {};
    uint8_t* AppOwnedBuffer {nullptr};

    RecvBuffer() = default;
    RecvBuffer(const RecvBuffer&) = delete;
    RecvBuffer(RecvBuffer&&) = delete;
    RecvBuffer& operator=(const RecvBuffer&) = delete;
    RecvBuffer& operator=(RecvBuffer&&) = delete;

    ~RecvBuffer() {
        if (RecvBuf.ReadPendingLength != 0) {
            Drain(RecvBuf.ReadPendingLength);
        }
        QuicRecvBufferUninitialize(&RecvBuf);

        if (AppOwnedBuffer) {
            CXPLAT_FREE(AppOwnedBuffer, QUIC_POOL_TEST);
        }
        CxPlatPoolUninitialize(&AppBufferChunkPool);
    }
    QUIC_STATUS Initialize(
        _In_ QUIC_RECV_BUF_MODE RecvMode = QUIC_RECV_BUF_MODE_SINGLE,
        _In_ bool PreallocatedChunk = false,
        _In_ uint32_t AllocBufferLength = DEF_TEST_BUFFER_LENGTH,
        _In_ uint32_t VirtualBufferLength = DEF_TEST_BUFFER_LENGTH
        ) {
        CxPlatPoolInitialize(FALSE, sizeof(QUIC_RECV_CHUNK), QUIC_POOL_TEST, &AppBufferChunkPool);

        QUIC_RECV_CHUNK* PreallocChunk{nullptr};
        if (PreallocatedChunk) {
                PreallocChunk = (QUIC_RECV_CHUNK*)CXPLAT_ALLOC_NONPAGED(
                    sizeof(QUIC_RECV_CHUNK) + AllocBufferLength,
                    QUIC_POOL_RECVBUF); // Use the recv buffer pool tag as this memory is moved to the recv buffer.
            QuicRecvChunkInitialize(PreallocChunk, AllocBufferLength, (uint8_t*)(PreallocChunk + 1), FALSE);
        }
        printf("Initializing: [mode=%u,vlen=%u,alen=%u]\n", RecvMode, VirtualBufferLength, AllocBufferLength);

        auto Result = QuicRecvBufferInitialize(
            &RecvBuf, AllocBufferLength, VirtualBufferLength, RecvMode, PreallocChunk);
        if (Result != QUIC_STATUS_SUCCESS) {
            return Result;
        }

        if (RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED && AllocBufferLength > 0) {
            //
            // In app-owned mode, provide app-owned buffers.
            // Provide up to two chunks, so that:
            // - the first chunk has `AllocBufferLength` bytes
            // - the sum of the two is `VirtualBufferLength` bytes
            //
            CXPLAT_LIST_ENTRY ChunkList;
            CxPlatListInitializeHead(&ChunkList);
            AppOwnedBuffer = (uint8_t *)CXPLAT_ALLOC_NONPAGED(VirtualBufferLength, QUIC_POOL_TEST);
            auto* Chunk = (QUIC_RECV_CHUNK *)CxPlatPoolAlloc(&AppBufferChunkPool);
            QuicRecvChunkInitialize(Chunk, AllocBufferLength, AppOwnedBuffer, TRUE);
            CxPlatListInsertHead(&ChunkList, &Chunk->Link);
            if (VirtualBufferLength > AllocBufferLength) {
                auto* Chunk2 = (QUIC_RECV_CHUNK *)CxPlatPoolAlloc(&AppBufferChunkPool);
                QuicRecvChunkInitialize(Chunk2, VirtualBufferLength - AllocBufferLength, AppOwnedBuffer + AllocBufferLength, TRUE);
                CxPlatListInsertTail(&ChunkList, &Chunk2->Link);
            }
            Result = QuicRecvBufferProvideChunks(&RecvBuf, &ChunkList);
        }

        Dump();
        return Result;
    }
    uint64_t GetTotalLength() {
        return QuicRecvBufferGetTotalLength(&RecvBuf);
    }
    bool HasUnreadData() {
        return QuicRecvBufferHasUnreadData(&RecvBuf) != FALSE;
    }
    uint32_t ReadBufferNeededCount() {
        return QuicRecvBufferReadBufferNeededCount(&RecvBuf);
    }
    QUIC_STATUS ProvideChunks(CXPLAT_LIST_ENTRY& Chunks) {
        auto Result = QuicRecvBufferProvideChunks(&RecvBuf, &Chunks);
        Dump();
        return Result;
    }
    QUIC_STATUS ProvideChunks(
        const std::vector<uint32_t>& Sizes,
        size_t BufferSize,
        _In_reads_bytes_(BufferSize) uint8_t* Buffer
        )
    {
        CXPLAT_LIST_ENTRY ChunkList;
        QUIC_STATUS Status = MakeAppOwnedChunks(Sizes, BufferSize, Buffer, &ChunkList);
        if (Status != QUIC_STATUS_SUCCESS) {
            return Status;
        }
        Status = ProvideChunks(ChunkList);
        if (Status != QUIC_STATUS_SUCCESS) {
            FreeChunkList(ChunkList);
        }
        return Status;
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

        int ChunkCount = 0;
        for (CXPLAT_LIST_ENTRY* Entry = RecvBuf.Chunks.Flink;
             Entry != &RecvBuf.Chunks;
             Entry = Entry->Flink) {
            auto* Chunk = CXPLAT_CONTAINING_RECORD(Entry, QUIC_RECV_CHUNK, Link);
            ASSERT_EQ(Chunk->ExternalReference, ExternalReferences[ChunkCount]);
            ChunkCount++;
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
        //
        // Always provide at least 3 buffers since some modes assume that many
        //
        uint32_t ActualBufferCount = std::max(BufferCount, 3u);
        std::vector<QUIC_BUFFER> ReadBuffers(ActualBufferCount);
        Read(&ReadOffset, &ActualBufferCount, ReadBuffers.data());

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

    //
    // Helper to build a list of app-owned chunks
    //
    QUIC_STATUS MakeAppOwnedChunks(
        const std::vector<uint32_t>& ChunkSizes,
        size_t BufferSize,
        _In_reads_bytes_(BufferSize) uint8_t* Buffer,
        _Out_ CXPLAT_LIST_ENTRY* ChunkList) {

        uint64_t totalSize = 0;
        for (auto size: ChunkSizes) {
            totalSize += size;
        }
        if (totalSize > BufferSize) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        CxPlatListInitializeHead(ChunkList);
        for (auto size: ChunkSizes) {
            auto* chunk = reinterpret_cast<QUIC_RECV_CHUNK *>(CxPlatPoolAlloc(&AppBufferChunkPool));
            QuicRecvChunkInitialize(chunk, size, Buffer, TRUE);
            Buffer = Buffer + size;
            CxPlatListInsertTail(ChunkList, &chunk->Link);
        }

        return QUIC_STATUS_SUCCESS;
    }

    void FreeChunkList(CXPLAT_LIST_ENTRY& ChunkList) {
        while (!CxPlatListIsEmpty(&ChunkList)) {
            CxPlatPoolFree(
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&ChunkList), QUIC_RECV_CHUNK, Link));
        }
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
    const auto Mode = GetParam();
    if (Mode == QUIC_RECV_BUF_MODE_APP_OWNED) {
        // App-owned mode doesn't support preallocated chunks
        return;
    }
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
    for (uint32_t i = 0; i < ReadBuffers[0].Length; ++i) {
        ASSERT_EQ(i, ReadBuffers[0].Buffer[i]); // Read data is as expected
    }

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

    for (uint32_t i = 0; i < ReadBuffers[0].Length; ++i) {
        ASSERT_EQ(i, ReadBuffers[0].Buffer[i]); // Read data has not been overriden by the write
    }
    ASSERT_FALSE(RecvBuf.Drain(20) && Mode != QUIC_RECV_BUF_MODE_MULTIPLE);
    ASSERT_TRUE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, WriteLargeWhilePendingReadWithPartialDrain)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(0, 20, &InOutWriteLength, &NewDataReady));
    ASSERT_TRUE(NewDataReady);
    ASSERT_TRUE(RecvBuf.HasUnreadData());

    {
        QUIC_BUFFER ReadBuffers[3]{};
        uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
        uint64_t ReadOffset{};
        RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
        ASSERT_FALSE(RecvBuf.HasUnreadData());
        ASSERT_EQ(0ull, ReadOffset);
        ASSERT_EQ(1u, BufferCount);
        ASSERT_EQ(20u, ReadBuffers[0].Length);
    }

    //
    // Write a large chunk while the read is pending
    //
    InOutWriteLength = LARGE_TEST_BUFFER_LENGTH;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(20, 512, &InOutWriteLength, &NewDataReady));
    ASSERT_TRUE(NewDataReady); // Still ready to read
    ASSERT_TRUE(RecvBuf.HasUnreadData());
    ASSERT_EQ(512ull, InOutWriteLength);
    ASSERT_EQ(532ull, RecvBuf.GetTotalLength());

    ASSERT_FALSE(RecvBuf.Drain(0)); // Complete the read without draining any data

    //
    // Read again and check the data from the first write is still intact
    //
    {
        QUIC_BUFFER ReadBuffers[3]{};
        uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
        uint64_t ReadOffset{};
        RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
        ASSERT_TRUE(BufferCount > 0u);
        ASSERT_TRUE(ReadBuffers[0].Length >= 20);

        for (uint32_t i = 0; i < 20; ++i) {
            if (Mode == QUIC_RECV_BUF_MODE_MULTIPLE) {
                //
                // Multiple mode doesn't re-read the initial data
                //
                ASSERT_EQ(i + 20, ReadBuffers[0].Buffer[i]);
            } else {
                //
                // Read data has not been overwritten by the write
                //
                ASSERT_EQ(i, ReadBuffers[0].Buffer[i]);
            }
        }
    }
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
    if (Mode == QUIC_RECV_BUF_MODE_APP_OWNED) {
        ASSERT_EQ(2u, BufferCount);
        ASSERT_EQ(64u, ReadBuffers[0].Length);
        ASSERT_EQ(192u, ReadBuffers[1].Length);
    } else {
        ASSERT_EQ(1u, BufferCount);
        ASSERT_EQ(256u, ReadBuffers[0].Length);
    }
    ASSERT_TRUE(RecvBuf.Drain(256));
    ASSERT_FALSE(RecvBuf.HasUnreadData());
}

TEST_P(WithMode, MultiWriteLargeWhileReadPending)
{
    auto Mode = GetParam();
    RecvBuffer RecvBuf{};
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, DEF_TEST_BUFFER_LENGTH, LARGE_TEST_BUFFER_LENGTH));

    //
    // Write some data and read it so a read operation is pending
    //
    {
        uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
        BOOLEAN DataReady = FALSE;
        ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(0, 64, &InOutWriteLength, &DataReady));

        uint64_t ReadOffset{};
        QUIC_BUFFER ReadBuffers[3]{};
        uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
        RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
        ASSERT_FALSE(RecvBuf.HasUnreadData());
        ASSERT_EQ(1u, BufferCount);
        ASSERT_EQ(64u, ReadBuffers[0].Length);
    }

    //
    // Write more data while the read is pending, forcing buffer re-allocations
    //
    for (uint32_t i = 1; i < 4; ++i) {
        uint64_t InOutWriteLength = LARGE_TEST_BUFFER_LENGTH; // FC limit same as recv buffer size
        BOOLEAN DataReady = FALSE;
        ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(i * 64, 64, &InOutWriteLength, &DataReady));
        ASSERT_TRUE(DataReady);
        ASSERT_TRUE(RecvBuf.HasUnreadData());
        ASSERT_EQ(64ull, InOutWriteLength);
        ASSERT_EQ((i + 1) * 64ull, RecvBuf.GetTotalLength());
    }

    //
    // Drain the data from the first read
    //
    ASSERT_FALSE(RecvBuf.Drain(64));

    //
    // Read all the remaining data
    //
    uint64_t ReadOffset{};
    QUIC_BUFFER ReadBuffers[3]{};
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    ASSERT_FALSE(RecvBuf.HasUnreadData());
    ASSERT_EQ(64ull, ReadOffset);
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(192u, ReadBuffers[0].Length);

    //
    // Drain all the data.
    //
    ASSERT_TRUE(RecvBuf.Drain(192));
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
    } else if (Mode == QUIC_RECV_BUF_MODE_SINGLE) {
        ASSERT_EQ(16ull, ReadOffset);
        ASSERT_EQ(1u, BufferCount);
        ASSERT_EQ(64u, ReadBuffers[0].Length);
    } else { // Mode == QUIC_RECV_BUF_MODE_CIRCULAR || QUIC_RECV_BUF_MODE_APP_OWNED
        ASSERT_EQ(16ull, ReadOffset);
        ASSERT_EQ(2u, BufferCount);
        ASSERT_EQ(48u, ReadBuffers[0].Length);
        ASSERT_EQ(16u, ReadBuffers[1].Length);
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
    if (Mode == QUIC_RECV_BUF_MODE_MULTIPLE ||
        Mode == QUIC_RECV_BUF_MODE_APP_OWNED) {
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

TEST_P(WithMode, DrainFrontChunkWithPendingGap2)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, 8, DEF_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;

    // Fill the first chunk partially
    ASSERT_EQ(QUIC_STATUS_SUCCESS,RecvBuf.Write(0, 7, &InOutWriteLength, &NewDataReady));
    ASSERT_TRUE(RecvBuf.HasUnreadData());

    // Read the data
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);

    // Before completing the read, write more non-ajacent data forcing the use of a new chunk
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(9, 4, &InOutWriteLength, &NewDataReady));

    RecvBuf.Drain(7);

    // After draining, ensure the front chunk was removed only for mode that
    // copied the data to the new chunk
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    if (Mode == QUIC_RECV_BUF_MODE_SINGLE) {
        RecvBuf.Check(0, 0, 1, ExternalReferences);
    } else if  (Mode == QUIC_RECV_BUF_MODE_CIRCULAR) {
        RecvBuf.Check(7, 0, 1, ExternalReferences);
    } else {
        RecvBuf.Check(7, 0, 2, ExternalReferences);
    }

    // Write to fill the gap and read all data
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(7, 2, &InOutWriteLength, &NewDataReady));

    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    RecvBuf.Drain(6);
}

TEST_P(WithMode, DrainFrontChunkExactly)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, 8, DEF_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;

    // Fill the first chunk exactly
    ASSERT_EQ(QUIC_STATUS_SUCCESS,RecvBuf.Write(0, 8, &InOutWriteLength, &NewDataReady));
    ASSERT_TRUE(RecvBuf.HasUnreadData());

    // Read the data
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);

    // Before completing the read, write more non-ajacent data
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(9, 4, &InOutWriteLength, &NewDataReady));

    RecvBuf.Drain(8);

    // After draining, ensure the front chunk was properly removed
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    if (Mode == QUIC_RECV_BUF_MODE_CIRCULAR) {
        RecvBuf.Check(8, 0, 1, ExternalReferences);
    } else {
        RecvBuf.Check(0, 0, 1, ExternalReferences);
    }

    // Write to fill the gap and read all data
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(8, 1, &InOutWriteLength, &NewDataReady));

    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    RecvBuf.Drain(5);
}

TEST_P(WithMode, DrainFrontChunkExactly_NoGap)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, 8, DEF_TEST_BUFFER_LENGTH));
    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;

    // Fill the first chunk exactly
    ASSERT_EQ(QUIC_STATUS_SUCCESS,RecvBuf.Write(0, 8, &InOutWriteLength, &NewDataReady));
    ASSERT_TRUE(RecvBuf.HasUnreadData());

    // Read the data
    uint64_t ReadOffset;
    QUIC_BUFFER ReadBuffers[3];
    uint32_t BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);

    // Before completing the read, write more ajacent data
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(8, 4, &InOutWriteLength, &NewDataReady));

    RecvBuf.Drain(8);

    // After draining, ensure the front chunk was properly removed
    BOOLEAN ExternalReferences[] = {FALSE, FALSE};
    if (Mode == QUIC_RECV_BUF_MODE_CIRCULAR) {
        RecvBuf.Check(8, 4, 1, ExternalReferences);
    } else {
        RecvBuf.Check(0, 4, 1, ExternalReferences);
    }

    // Read the rest of the data
    BufferCount = ARRAYSIZE(ReadBuffers);
    RecvBuf.Read(&ReadOffset, &BufferCount, ReadBuffers);
    RecvBuf.Drain(4);
}

TEST_P(WithMode, IncreaseVirtualLength)
{
    RecvBuffer RecvBuf;
    auto Mode = GetParam();
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(Mode, false, 8, DEF_TEST_BUFFER_LENGTH));
    constexpr auto WriteLength = 2 * DEF_TEST_BUFFER_LENGTH;
    uint64_t InOutWriteLength = WriteLength;
    BOOLEAN NewDataReady = FALSE;

    ASSERT_EQ(QUIC_STATUS_BUFFER_TOO_SMALL, RecvBuf.Write(0, WriteLength, &InOutWriteLength, &NewDataReady));

    if (Mode != QUIC_RECV_BUF_MODE_APP_OWNED) {
        RecvBuf.IncreaseVirtualBufferLength(WriteLength);

        auto Status = RecvBuf.Write(0, WriteLength, &InOutWriteLength, &NewDataReady);
        ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    }
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
    // |R, R, R, R, 4, 5, 6, 7] ReadStart:0, ReadLength:8, Ext:1
    RecvBuf.WriteAndCheck(4, 4, 0, 8, 1, ExternalReferences);
    // |D, D, D, D, 4, 5, 6, 7] ReadStart:4, ReadLength:4, Ext:0
    RecvBuf.Drain(4);
    // [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, ...] ReadStart:0, ReadLengt:12, Ext:0
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
    uint32_t LengthList[] = {0, 0, 0};

    RecvBuf.WriteAndCheck(0, 8, 0, 8, 1, ExternalReferences); // append -> 8

    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);

    RecvBuf.WriteAndCheck(8, 32, 0, 8, 2, ExternalReferences); // grow -> 8 + 64, append -> 32

    LengthList[0] = 32;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 2, ExternalReferences);

    RecvBuf.WriteAndCheck(40, 64, 0, 8, 3, ExternalReferences); // grow -> 8 + 64 + 128, append -> 104
    RecvBuf.WriteAndCheck(104, 20, 0, 8, 3, ExternalReferences); // grow -> 128, append -> 124

    ExternalReferences[2] = TRUE;
    LengthList[0] = 32;
    LengthList[1] = 52;
    RecvBuf.ReadAndCheck(2, LengthList, 0, 8, 3, ExternalReferences);
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

TEST(AppOwnedBuffersTest, ProvideChunks)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    //
    // Providing app-owned chunks succeeds right after initialization.
    //
    std::array<uint8_t, 16> Buffer{};
    std::vector ChunkSizes{8u, 8u};
    CXPLAT_LIST_ENTRY ChunkList;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.MakeAppOwnedChunks(ChunkSizes, Buffer.size(), Buffer.data(), &ChunkList));
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkList));
    ASSERT_TRUE(CxPlatListIsEmpty(&ChunkList));

    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;
    RecvBuf.Write(0, 8, &InOutWriteLength, &NewDataReady);

    //
    // More app-owned buffers can be added, even after a write.
    //
    std::array<uint8_t, 16> Buffer2{};
    std::vector ChunkSizes2{8u, 8u};
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.MakeAppOwnedChunks(ChunkSizes2, Buffer2.size(), Buffer2.data(), &ChunkList));
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkList));
    ASSERT_TRUE(CxPlatListIsEmpty(&ChunkList));
}

TEST(AppOwnedBuffersTest, ProvideChunksOverflow)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    //
    // Ensure app-owned buffers cannot be provided in a way that would overflow
    // the virtual size.
    //
    std::array<uint8_t, 24> Buffer{};
    std::vector ChunkSizes{8u, 8u, 8u};
    CXPLAT_LIST_ENTRY ChunkList;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.MakeAppOwnedChunks(ChunkSizes, Buffer.size(), Buffer.data(), &ChunkList));

    for (CXPLAT_LIST_ENTRY* Entry = ChunkList.Flink;
         Entry != &ChunkList;
         Entry = Entry->Flink) {
        auto* Chunk = CXPLAT_CONTAINING_RECORD(Entry, QUIC_RECV_CHUNK, Link);
        //
        // Lie about the actual size of the chunk, nobody will look at it.
        // We don't want to allocate 4GB for real.
        //
        Chunk->AllocLength = 0x7000'0000;
    }

    ASSERT_EQ(QUIC_STATUS_INVALID_PARAMETER, RecvBuf.ProvideChunks(ChunkList));
    ASSERT_FALSE(CxPlatListIsEmpty(&ChunkList));

    RecvBuf.FreeChunkList(ChunkList);
}

TEST(AppOwnedBuffersTest, PartialDrain)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    const uint32_t NbChunks = 2;
    std::array<uint8_t, NbChunks * 8> Buffer{};
    std::vector ChunkSizes(NbChunks, 8u);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer.size(), Buffer.data()));

    std::vector<BOOLEAN> ExternalReferences(NbChunks, FALSE);
    RecvBuf.WriteAndCheck(0, 12, 0, 8, NbChunks, ExternalReferences.data());

    uint32_t LengthList[] = {8, 4};
    ExternalReferences[0] = TRUE;
    ExternalReferences[1] = TRUE;
    RecvBuf.ReadAndCheck(2, LengthList, 0, 8, NbChunks, ExternalReferences.data());
    RecvBuf.Drain(10);

    ExternalReferences[0] = FALSE;
    RecvBuf.Check(2, 2, 1, ExternalReferences.data());
    RecvBuf.RecvBuf.Capacity = 4;
}

TEST(AppOwnedBuffersTest, ReadWriteManyChunks)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    const uint32_t NbChunks = 5;
    std::array<uint8_t, NbChunks * 8> Buffer{};
    std::vector ChunkSizes(NbChunks, 8u);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer.size(), Buffer.data()));

    std::vector<BOOLEAN> ExternalReferences(NbChunks, FALSE);
    RecvBuf.WriteAndCheck(10, 20, 0, 0, NbChunks, ExternalReferences.data());
    RecvBuf.WriteAndCheck(0, 10, 0, 8, NbChunks, ExternalReferences.data());

    uint32_t LengthList[] = {8, 8, 8, 6};
    ExternalReferences[0] = TRUE;
    ExternalReferences[1] = TRUE;
    ExternalReferences[2] = TRUE;
    ExternalReferences[3] = TRUE;
    RecvBuf.ReadAndCheck(4, LengthList, 0, 8, NbChunks, ExternalReferences.data());
    RecvBuf.Drain(30);

    ExternalReferences[0] = FALSE;
    ExternalReferences[1] = FALSE;
    ExternalReferences[2] = FALSE;
    ExternalReferences[3] = FALSE;
    RecvBuf.Check(6, 0, 2, ExternalReferences.data());
}

TEST(AppOwnedBuffersTest, NumberOfBufferNeededForRead)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    const uint32_t NbChunks = 5;
    std::array<uint8_t, NbChunks * 8> Buffer{};
    std::vector ChunkSizes(NbChunks, 8u);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer.size(), Buffer.data()));

    ASSERT_EQ(RecvBuf.ReadBufferNeededCount(), 0);

    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(0, 5, &InOutWriteLength, &NewDataReady));
    ASSERT_EQ(RecvBuf.ReadBufferNeededCount(), 1);

    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(5, 11, &InOutWriteLength, &NewDataReady));
    ASSERT_EQ(RecvBuf.ReadBufferNeededCount(), 2);

    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(16, 20, &InOutWriteLength, &NewDataReady));
    ASSERT_EQ(RecvBuf.ReadBufferNeededCount(), 5);

    // Reading with less buffers than needed still works in app-owned mode.
    // (3 are needed for other modes)
    QUIC_BUFFER Buffers[5]{};
    uint32_t NumBuffers = 3;
    uint64_t BufferOffset = 0;
    RecvBuf.Read(&BufferOffset, &NumBuffers, Buffers);
    ASSERT_EQ(NumBuffers, 3);

    RecvBuf.Drain(8);
    ASSERT_EQ(RecvBuf.ReadBufferNeededCount(), 4);

    NumBuffers = 5;
    BufferOffset = 0;
    RecvBuf.Read(&BufferOffset, &NumBuffers, Buffers);
    RecvBuf.Drain(20);
    ASSERT_EQ(RecvBuf.ReadBufferNeededCount(), 2);
}

TEST(AppOwnedBuffersTest, WriteTooLong)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    std::array<uint8_t, 16> Buffer{};
    std::vector ChunkSizes{8u, 8u};
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer.size(), Buffer.data()));

    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;
    //
    // Write 1 more byte than we have buffer space for.
    //
    ASSERT_EQ(QUIC_STATUS_BUFFER_TOO_SMALL, RecvBuf.Write(0, 17, &InOutWriteLength, &NewDataReady));
}

TEST(AppOwnedBuffersTest, OutOfBuffers)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    std::array<uint8_t, DEF_TEST_BUFFER_LENGTH> Buffer{};
    std::vector ChunkSizes{DEF_TEST_BUFFER_LENGTH};
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer.size(), Buffer.data()));

    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(0, DEF_TEST_BUFFER_LENGTH, &InOutWriteLength, &NewDataReady));

    //
    // Fully read and drain the only chunk, causing the chunk list to be empty.
    //
    uint32_t LengthList[] = {DEF_TEST_BUFFER_LENGTH};
    BOOLEAN ExternalReferences[] = {TRUE};
    RecvBuf.ReadAndCheck(1, LengthList, 0, DEF_TEST_BUFFER_LENGTH, 1, ExternalReferences);

    RecvBuf.Drain(DEF_TEST_BUFFER_LENGTH);
    ExternalReferences[0] = FALSE;
    RecvBuf.Check(0, 0, 0, ExternalReferences);

    //
    // Make sure a write fail nicely in that state.
    //
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_BUFFER_TOO_SMALL, RecvBuf.Write(DEF_TEST_BUFFER_LENGTH, 8, &InOutWriteLength, &NewDataReady));

    //
    // Provide a new chunk and validate everything is back to normal.
    //
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer.size(), Buffer.data()));

    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(DEF_TEST_BUFFER_LENGTH, 8, &InOutWriteLength, &NewDataReady));
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(8);
}

TEST(AppOwnedBuffersTest, FreeBufferBeforeDrain)
{
    RecvBuffer RecvBuf;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Initialize(QUIC_RECV_BUF_MODE_APP_OWNED, false, 0, 0));

    auto Buffer1 = std::make_unique<uint8_t[]>(DEF_TEST_BUFFER_LENGTH);
    std::array<uint8_t, DEF_TEST_BUFFER_LENGTH> Buffer2{};
    std::vector ChunkSizes{DEF_TEST_BUFFER_LENGTH};
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, DEF_TEST_BUFFER_LENGTH, Buffer1.get()));
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.ProvideChunks(ChunkSizes, Buffer2.size(), Buffer2.data()));

    uint64_t InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    BOOLEAN NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(0, DEF_TEST_BUFFER_LENGTH, &InOutWriteLength, &NewDataReady));
    uint32_t LengthList[] = {DEF_TEST_BUFFER_LENGTH};
    BOOLEAN ExternalReferences[] = {TRUE, FALSE};
    RecvBuf.ReadAndCheck(1, LengthList, 0, DEF_TEST_BUFFER_LENGTH, 2, ExternalReferences);

    // Free Buffer1 before draining.
    Buffer1.reset();

    RecvBuf.Drain(DEF_TEST_BUFFER_LENGTH);

    // Everything still good when writting and reading to the second chunk.
    InOutWriteLength = DEF_TEST_BUFFER_LENGTH;
    NewDataReady = FALSE;
    ASSERT_EQ(QUIC_STATUS_SUCCESS, RecvBuf.Write(DEF_TEST_BUFFER_LENGTH, 8, &InOutWriteLength, &NewDataReady));
    LengthList[0] = 8;
    ExternalReferences[0] = TRUE;
    RecvBuf.ReadAndCheck(1, LengthList, 0, 8, 1, ExternalReferences);
    RecvBuf.Drain(8);
}

INSTANTIATE_TEST_SUITE_P(
    RecvBufferTest,
    WithMode,
    ::testing::Values(QUIC_RECV_BUF_MODE_SINGLE, QUIC_RECV_BUF_MODE_CIRCULAR, QUIC_RECV_BUF_MODE_MULTIPLE, QUIC_RECV_BUF_MODE_APP_OWNED),
    testing::PrintToStringParamName());
