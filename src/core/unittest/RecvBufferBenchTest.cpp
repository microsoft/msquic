/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Benchmark comparing the original QUIC_RECV_BUFFER with the verified
    (Pulse-extracted) CircularBuffer for out-of-order write and read workloads.

    Run with:
      msquiccoretest --gtest_filter='RecvBufferBench*'

--*/

#include "main.h"

#include <chrono>
#include <vector>
#include <numeric>
#include <algorithm>
#include <random>
#include <cstring>

// Include the verified implementation headers directly
extern "C" {
#include "verified/verified_recv_buffer.h"

// Forward declarations for verified functions and init
extern void krmlinit_globals(void);

// Verified buffer wrapper functions (from RecvBufferWrapper)
K____Pulse_Lib_CircularBuffer_cb_internal___FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range_____
RecvBufferWrapper_create(size_t alloc_length, size_t virtual_length);

void
RecvBufferWrapper_free(
    Pulse_Lib_CircularBuffer_cb_internal* cb,
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm);

size_t
RecvBufferWrapper_read_length(
    Pulse_Lib_CircularBuffer_cb_internal* cb,
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm);

Pulse_Lib_CircularBuffer_write_result
RecvBufferWrapper_write_buffer(
    Pulse_Lib_CircularBuffer_cb_internal* cb,
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm,
    size_t abs_off, uint8_t* src, size_t len);

Pulse_Lib_CircularBuffer_read_view
RecvBufferWrapper_read_zerocopy(
    Pulse_Lib_CircularBuffer_cb_internal* cb,
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm,
    size_t n);

void
RecvBufferWrapper_release_read(
    Pulse_Lib_CircularBuffer_cb_internal* cb,
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm,
    Pulse_Lib_CircularBuffer_read_view rv);

bool
RecvBufferWrapper_drain(
    Pulse_Lib_CircularBuffer_cb_internal* cb,
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm,
    size_t n);
}

// Thin verified buffer struct (avoids including the wrapper header which conflicts with msquic types)
struct VerifiedBuf {
    Pulse_Lib_CircularBuffer_cb_internal* cb;
    FStar_Pervasives_Native_option___Pulse_Lib_AVLTree_node__Pulse_Lib_RangeMap_range____* rm;

    QUIC_STATUS Init(uint32_t AllocLen, uint32_t VirtLen) {
        auto result = RecvBufferWrapper_create((size_t)AllocLen, (size_t)VirtLen);
        cb = result.fst;
        rm = result.snd;
        return QUIC_STATUS_SUCCESS;
    }

    void Uninit() {
        RecvBufferWrapper_free(cb, rm);
        cb = nullptr; rm = nullptr;
    }

    QUIC_STATUS Write(uint64_t Offset, uint16_t Length, const uint8_t* Data,
                      BOOLEAN* NewDataReady) {
        if (Length == 0) { *NewDataReady = FALSE; return QUIC_STATUS_SUCCESS; }
        auto wr = RecvBufferWrapper_write_buffer(
            cb, rm, (size_t)Offset, (uint8_t*)(uintptr_t)Data, (size_t)Length);
        *NewDataReady = wr.new_data_ready ? TRUE : FALSE;
        return wr.resize_failed ? QUIC_STATUS_OUT_OF_MEMORY : QUIC_STATUS_SUCCESS;
    }

    void Read(uint64_t* BufferOffset, uint32_t* BufferCount, QUIC_BUFFER* Buffers) {
        size_t rl = RecvBufferWrapper_read_length(cb, rm);
        if (rl == 0) { *BufferCount = 0; return; }
        *BufferOffset = (uint64_t)cb->bo;
        auto rv = RecvBufferWrapper_read_zerocopy(cb, rm, rl);
        Buffers[0].Buffer = rv.arr + rv.off1;
        Buffers[0].Length = (uint32_t)rv.len1;
        if (rv.len2 > 0) {
            Buffers[1].Buffer = rv.arr + rv.off2;
            Buffers[1].Length = (uint32_t)rv.len2;
            *BufferCount = 2;
        } else {
            *BufferCount = 1;
        }
        RecvBufferWrapper_release_read(cb, rm, rv);
    }

    BOOLEAN Drain(uint64_t Length) {
        return RecvBufferWrapper_drain(cb, rm, (size_t)Length) ? TRUE : FALSE;
    }
};

#define BENCH_ALLOC_LEN      65536u
#define BENCH_VIRT_LEN       65536u
#define BENCH_LARGE_ALLOC    (1u << 20)  // 1MB for large tests
#define BENCH_LARGE_VIRT     (1u << 20)

// ─── Timing helpers ─────────────────────────────────────────────────

using Clock = std::chrono::high_resolution_clock;

static double
ElapsedMs(Clock::time_point Start, Clock::time_point End)
{
    return std::chrono::duration<double, std::milli>(End - Start).count();
}

static double
OpsPerSec(uint64_t NOps, Clock::time_point Start, Clock::time_point End)
{
    double Secs = std::chrono::duration<double>(End - Start).count();
    return Secs > 0 ? (double)NOps / Secs : 0;
}

static double
ThroughputMBps(uint64_t TotalBytes, Clock::time_point Start, Clock::time_point End)
{
    double Secs = std::chrono::duration<double>(End - Start).count();
    return Secs > 0 ? ((double)TotalBytes / (1024.0 * 1024.0)) / Secs : 0;
}

// ─── Original recv_buffer wrapper ───────────────────────────────────

struct OrigRecvBuffer {
    QUIC_RECV_BUFFER RecvBuf{};

    QUIC_STATUS Init(uint32_t AllocLen, uint32_t VirtLen) {
        auto* Chunk = (QUIC_RECV_CHUNK*)CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_RECV_CHUNK) + AllocLen, QUIC_POOL_RECVBUF);
        if (!Chunk) return QUIC_STATUS_OUT_OF_MEMORY;
        QuicRecvChunkInitialize(Chunk, AllocLen, (uint8_t*)(Chunk + 1), FALSE);
        return QuicRecvBufferInitialize(
            &RecvBuf, AllocLen, VirtLen,
            QUIC_RECV_BUF_MODE_CIRCULAR, Chunk);
    }

    void Uninit() {
        if (RecvBuf.ReadPendingLength != 0) {
            QuicRecvBufferDrain(&RecvBuf, RecvBuf.ReadPendingLength);
        }
        QuicRecvBufferUninitialize(&RecvBuf);
    }

    QUIC_STATUS Write(uint64_t Offset, uint16_t Length, const uint8_t* Data,
                      BOOLEAN* NewDataReady) {
        uint64_t Quota = UINT64_MAX;
        uint64_t QuotaConsumed = 0;
        uint64_t SizeNeeded = 0;
        return QuicRecvBufferWrite(
            &RecvBuf, Offset, Length, Data,
            Quota, &QuotaConsumed, NewDataReady, &SizeNeeded);
    }

    void Read(uint64_t* Offset, uint32_t* Count, QUIC_BUFFER* Buffers) {
        QuicRecvBufferRead(&RecvBuf, Offset, Count, Buffers);
    }

    BOOLEAN Drain(uint64_t Length) {
        return QuicRecvBufferDrain(&RecvBuf, Length);
    }
};

// ─── Benchmark result struct ────────────────────────────────────────

struct BenchResult {
    const char* Name;
    const char* Impl;
    double TimeMs;
    double WriteOpsSec;
    double WriteMBps;
    uint64_t TotalWritten;
    uint32_t NWrites;
};

static void
PrintResult(const BenchResult& R)
{
    printf("  [%-10s] %-35s %8.2f ms  %10.0f write-ops/s  %8.2f MB/s\n",
           R.Impl, R.Name, R.TimeMs, R.WriteOpsSec, R.WriteMBps);
}

static void
PrintComparison(const BenchResult& Orig, const BenchResult& Verified)
{
    double Speedup = Orig.TimeMs / Verified.TimeMs;
    printf("  %-35s  Orig: %8.2f ms  Verified: %8.2f ms  Ratio: %.2fx %s\n",
           Orig.Name, Orig.TimeMs, Verified.TimeMs, Speedup,
           Speedup >= 1.0 ? "(verified faster)" : "(original faster)");
}

// ─── Test fixture ───────────────────────────────────────────────────

class RecvBufferBench : public ::testing::Test {
protected:
    static bool Initialized;

    static void SetUpTestSuite() {
        if (!Initialized) {
            krmlinit_globals();
            Initialized = true;
        }
    }

    void FillPattern(uint8_t* Buf, uint32_t Len, uint64_t Offset) {
        for (uint32_t i = 0; i < Len; i++) {
            Buf[i] = (uint8_t)((Offset + i) & 0xFF);
        }
    }
};

bool RecvBufferBench::Initialized = false;

// ─── Scenario 1: Sequential writes ─────────────────────────────────

TEST_F(RecvBufferBench, SequentialWrites256B)
{
    const uint32_t Iterations = 200;
    const uint32_t ChunkSize = 256;
    const uint32_t AllocLen = BENCH_ALLOC_LEN;
    const uint32_t NChunks = AllocLen / ChunkSize;
    std::vector<uint8_t> Data(ChunkSize);

    // ── Original ──
    BenchResult Orig = {"Sequential 256B", "original", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            OrigRecvBuffer Buf;
            ASSERT_EQ(QUIC_STATUS_SUCCESS, Buf.Init(AllocLen, AllocLen));
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i++) {
                FillPattern(Data.data(), ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize, (uint16_t)ChunkSize, Data.data(), &Ndr);
                Orig.NWrites++;
                Orig.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Orig.TimeMs = ElapsedMs(Start, End);
        Orig.WriteOpsSec = OpsPerSec(Orig.NWrites, Start, End);
        Orig.WriteMBps = ThroughputMBps(Orig.TotalWritten, Start, End);
    }

    // ── Verified ──
    BenchResult Verif = {"Sequential 256B", "verified", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            VerifiedBuf Buf;
            Buf.Init(AllocLen, AllocLen);
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i++) {
                FillPattern(Data.data(), ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize,
                                        (uint16_t)ChunkSize, Data.data(), &Ndr);
                Verif.NWrites++;
                Verif.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Verif.TimeMs = ElapsedMs(Start, End);
        Verif.WriteOpsSec = OpsPerSec(Verif.NWrites, Start, End);
        Verif.WriteMBps = ThroughputMBps(Verif.TotalWritten, Start, End);
    }

    printf("\n");
    PrintResult(Orig);
    PrintResult(Verif);
    PrintComparison(Orig, Verif);
    printf("\n");
}

// ─── Scenario 2: Out-of-order writes ───────────────────────────────

TEST_F(RecvBufferBench, OOOWrites256B)
{
    const uint32_t Iterations = 200;
    const uint32_t ChunkSize = 256;
    const uint32_t AllocLen = BENCH_ALLOC_LEN;
    const uint32_t NChunks = AllocLen / ChunkSize;
    std::vector<uint8_t> Data(ChunkSize);

    std::vector<uint32_t> Order(NChunks);
    std::iota(Order.begin(), Order.end(), 0);
    std::mt19937 Rng(42);

    // ── Original ──
    BenchResult Orig = {"OOO 256B", "original", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            OrigRecvBuffer Buf;
            ASSERT_EQ(QUIC_STATUS_SUCCESS, Buf.Init(AllocLen, AllocLen));
            std::shuffle(Order.begin(), Order.end(), Rng);
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i++) {
                uint64_t Off = (uint64_t)Order[i] * ChunkSize;
                FillPattern(Data.data(), ChunkSize, Off);
                Buf.Write(Off, (uint16_t)ChunkSize, Data.data(), &Ndr);
                Orig.NWrites++;
                Orig.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Orig.TimeMs = ElapsedMs(Start, End);
        Orig.WriteOpsSec = OpsPerSec(Orig.NWrites, Start, End);
        Orig.WriteMBps = ThroughputMBps(Orig.TotalWritten, Start, End);
    }

    // ── Verified ──
    BenchResult Verif = {"OOO 256B", "verified", 0, 0, 0, 0, 0};
    {
        Rng.seed(42);
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            VerifiedBuf Buf;
            Buf.Init(AllocLen, AllocLen);
            std::shuffle(Order.begin(), Order.end(), Rng);
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i++) {
                uint64_t Off = (uint64_t)Order[i] * ChunkSize;
                FillPattern(Data.data(), ChunkSize, Off);
                Buf.Write(Off, (uint16_t)ChunkSize,
                                        Data.data(), &Ndr);
                Verif.NWrites++;
                Verif.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Verif.TimeMs = ElapsedMs(Start, End);
        Verif.WriteOpsSec = OpsPerSec(Verif.NWrites, Start, End);
        Verif.WriteMBps = ThroughputMBps(Verif.TotalWritten, Start, End);
    }

    printf("\n");
    PrintResult(Orig);
    PrintResult(Verif);
    PrintComparison(Orig, Verif);
    printf("\n");
}

// ─── Scenario 3: Interleaved write/read/drain ──────────────────────

TEST_F(RecvBufferBench, InterleavedWriteReadDrain)
{
    const uint32_t Iterations = 200;
    const uint32_t ChunkSize = 256;
    const uint32_t AllocLen = BENCH_ALLOC_LEN;
    const uint32_t VirtLen = 1u << 20;
    const uint32_t BatchSize = 8;
    const uint32_t Cycles = 32;
    std::vector<uint8_t> Data(ChunkSize);

    // ── Original ──
    BenchResult Orig = {"Interleaved w/r/d", "original", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            OrigRecvBuffer Buf;
            ASSERT_EQ(QUIC_STATUS_SUCCESS, Buf.Init(AllocLen, VirtLen));
            uint64_t WriteOff = 0;
            for (uint32_t c = 0; c < Cycles; c++) {
                BOOLEAN Ndr;
                for (uint32_t i = 0; i < BatchSize; i++) {
                    FillPattern(Data.data(), ChunkSize, WriteOff);
                    Buf.Write(WriteOff, (uint16_t)ChunkSize, Data.data(), &Ndr);
                    WriteOff += ChunkSize;
                    Orig.NWrites++;
                    Orig.TotalWritten += ChunkSize;
                }
                uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
                Buf.Read(&Off, &Cnt, Bufs);
                uint64_t Total = 0;
                for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
                Buf.Drain(Total);
            }
            Buf.Uninit();
        }
        auto End = Clock::now();
        Orig.TimeMs = ElapsedMs(Start, End);
        Orig.WriteOpsSec = OpsPerSec(Orig.NWrites, Start, End);
        Orig.WriteMBps = ThroughputMBps(Orig.TotalWritten, Start, End);
    }

    // ── Verified ──
    BenchResult Verif = {"Interleaved w/r/d", "verified", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            VerifiedBuf Buf;
            Buf.Init(AllocLen, VirtLen);
            uint64_t WriteOff = 0;
            for (uint32_t c = 0; c < Cycles; c++) {
                BOOLEAN Ndr;
                for (uint32_t i = 0; i < BatchSize; i++) {
                    FillPattern(Data.data(), ChunkSize, WriteOff);
                    Buf.Write(WriteOff,
                                            (uint16_t)ChunkSize, Data.data(), &Ndr);
                    WriteOff += ChunkSize;
                    Verif.NWrites++;
                    Verif.TotalWritten += ChunkSize;
                }
                uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
                Buf.Read(&Off, &Cnt, Bufs);
                uint64_t Total = 0;
                for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
                Buf.Drain(Total);
            }
            Buf.Uninit();
        }
        auto End = Clock::now();
        Verif.TimeMs = ElapsedMs(Start, End);
        Verif.WriteOpsSec = OpsPerSec(Verif.NWrites, Start, End);
        Verif.WriteMBps = ThroughputMBps(Verif.TotalWritten, Start, End);
    }

    printf("\n");
    PrintResult(Orig);
    PrintResult(Verif);
    PrintComparison(Orig, Verif);
    printf("\n");
}

// ─── Scenario 4: Small OOO writes (gap stress) ─────────────────────

TEST_F(RecvBufferBench, SmallOOOWrites16B)
{
    const uint32_t Iterations = 200;
    const uint32_t ChunkSize = 16;
    const uint32_t AllocLen = 4096;
    const uint32_t NChunks = AllocLen / ChunkSize;
    uint8_t Data[16];

    // ── Original ──
    BenchResult Orig = {"Small OOO 16B gap", "original", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            OrigRecvBuffer Buf;
            ASSERT_EQ(QUIC_STATUS_SUCCESS, Buf.Init(AllocLen, AllocLen));
            BOOLEAN Ndr;
            // Write even chunks first, then odd (maximizes gaps)
            for (uint32_t i = 0; i < NChunks; i += 2) {
                FillPattern(Data, ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize, ChunkSize, Data, &Ndr);
                Orig.NWrites++; Orig.TotalWritten += ChunkSize;
            }
            for (uint32_t i = 1; i < NChunks; i += 2) {
                FillPattern(Data, ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize, ChunkSize, Data, &Ndr);
                Orig.NWrites++; Orig.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Orig.TimeMs = ElapsedMs(Start, End);
        Orig.WriteOpsSec = OpsPerSec(Orig.NWrites, Start, End);
        Orig.WriteMBps = ThroughputMBps(Orig.TotalWritten, Start, End);
    }

    // ── Verified ──
    BenchResult Verif = {"Small OOO 16B gap", "verified", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            VerifiedBuf Buf;
            Buf.Init(AllocLen, AllocLen);
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i += 2) {
                FillPattern(Data, ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize,
                                        ChunkSize, Data, &Ndr);
                Verif.NWrites++; Verif.TotalWritten += ChunkSize;
            }
            for (uint32_t i = 1; i < NChunks; i += 2) {
                FillPattern(Data, ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize,
                                        ChunkSize, Data, &Ndr);
                Verif.NWrites++; Verif.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Verif.TimeMs = ElapsedMs(Start, End);
        Verif.WriteOpsSec = OpsPerSec(Verif.NWrites, Start, End);
        Verif.WriteMBps = ThroughputMBps(Verif.TotalWritten, Start, End);
    }

    printf("\n");
    PrintResult(Orig);
    PrintResult(Verif);
    PrintComparison(Orig, Verif);
    printf("\n");
}

// ─── Scenario 5: Large sequential writes (throughput) ───────────────

TEST_F(RecvBufferBench, LargeSequential4KB)
{
    const uint32_t Iterations = 200;
    const uint32_t ChunkSize = 4096;
    const uint32_t AllocLen = BENCH_ALLOC_LEN;
    const uint32_t NChunks = AllocLen / ChunkSize;
    std::vector<uint8_t> Data(ChunkSize);

    // ── Original ──
    BenchResult Orig = {"Large seq 4KB", "original", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            OrigRecvBuffer Buf;
            ASSERT_EQ(QUIC_STATUS_SUCCESS, Buf.Init(AllocLen, AllocLen));
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i++) {
                FillPattern(Data.data(), ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize, (uint16_t)ChunkSize,
                          Data.data(), &Ndr);
                Orig.NWrites++; Orig.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Orig.TimeMs = ElapsedMs(Start, End);
        Orig.WriteOpsSec = OpsPerSec(Orig.NWrites, Start, End);
        Orig.WriteMBps = ThroughputMBps(Orig.TotalWritten, Start, End);
    }

    // ── Verified ──
    BenchResult Verif = {"Large seq 4KB", "verified", 0, 0, 0, 0, 0};
    {
        auto Start = Clock::now();
        for (uint32_t iter = 0; iter < Iterations; iter++) {
            VerifiedBuf Buf;
            Buf.Init(AllocLen, AllocLen);
            BOOLEAN Ndr;
            for (uint32_t i = 0; i < NChunks; i++) {
                FillPattern(Data.data(), ChunkSize, (uint64_t)i * ChunkSize);
                Buf.Write((uint64_t)i * ChunkSize,
                                        (uint16_t)ChunkSize, Data.data(), &Ndr);
                Verif.NWrites++; Verif.TotalWritten += ChunkSize;
            }
            uint64_t Off; uint32_t Cnt = 2; QUIC_BUFFER Bufs[2] = {};
            Buf.Read(&Off, &Cnt, Bufs);
            uint64_t Total = 0;
            for (uint32_t i = 0; i < Cnt; i++) Total += Bufs[i].Length;
            Buf.Drain(Total);
            Buf.Uninit();
        }
        auto End = Clock::now();
        Verif.TimeMs = ElapsedMs(Start, End);
        Verif.WriteOpsSec = OpsPerSec(Verif.NWrites, Start, End);
        Verif.WriteMBps = ThroughputMBps(Verif.TotalWritten, Start, End);
    }

    printf("\n");
    PrintResult(Orig);
    PrintResult(Verif);
    PrintComparison(Orig, Verif);
    printf("\n");
}
