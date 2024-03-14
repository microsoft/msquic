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
    ASSERT_EQ(1u, BufferCount);
    ASSERT_EQ(48u, ReadBuffers[0].Length);
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

INSTANTIATE_TEST_SUITE_P(
    RecvBufferTest,
    WithMode,
    ::testing::Values(QUIC_RECV_BUF_MODE_SINGLE, QUIC_RECV_BUF_MODE_CIRCULAR, QUIC_RECV_BUF_MODE_MULTIPLE),
    testing::PrintToStringParamName());
