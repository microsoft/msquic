/*
 * bench_recv_buffer.c
 *
 * Benchmark for the verified CircularBuffer (Karamel-extracted from Pulse).
 * Tests various out-of-order write and read patterns, reporting throughput
 * and latency metrics.
 *
 * Compile:
 *   gcc -O2 -I ~/karamel/include -I ~/karamel/krmllib/dist/minimal -I . -I .. \
 *       -include verified_support.h \
 *       bench_recv_buffer.c verified_recv_buffer.c krmlinit.c krmlinit_rv.c \
 *       verified_prims_support.c -o bench_recv_buffer -w
 *
 * Run:
 *   ./bench_recv_buffer [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <assert.h>

/* Include the wrapper which pulls in verified_recv_buffer.h */
#include "../verified_wrapper_recv_buffer.h"

/* From krmlinit */
extern void krmlinit_globals(void);

/* ─── Timing helpers ──────────────────────────────────────────────── */

static inline uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline double
elapsed_ms(uint64_t start, uint64_t end)
{
    return (double)(end - start) / 1e6;
}

static inline double
ops_per_sec(uint64_t n_ops, uint64_t start, uint64_t end)
{
    double secs = (double)(end - start) / 1e9;
    return secs > 0 ? (double)n_ops / secs : 0;
}

static inline double
throughput_mbps(uint64_t total_bytes, uint64_t start, uint64_t end)
{
    double secs = (double)(end - start) / 1e9;
    return secs > 0 ? ((double)total_bytes / (1024.0 * 1024.0)) / secs : 0;
}

/* ─── Simple PRNG (xorshift64) ────────────────────────────────────── */

static uint64_t rng_state = 0x123456789ABCDEF0ULL;

static inline uint64_t
xorshift64(void)
{
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

/* Fisher-Yates shuffle */
static void
shuffle(uint32_t* arr, uint32_t n)
{
    for (uint32_t i = n - 1; i > 0; i--) {
        uint32_t j = (uint32_t)(xorshift64() % (i + 1));
        uint32_t tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

/* ─── Fill buffer with deterministic pattern ──────────────────────── */

static void
fill_pattern(uint8_t* buf, uint32_t len, uint64_t offset)
{
    for (uint32_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((offset + i) & 0xFF);
    }
}

/* ─── Benchmark results ───────────────────────────────────────────── */

typedef struct {
    const char* name;
    double time_ms;
    double write_ops_sec;
    double read_ops_sec;
    double write_mbps;
    double read_mbps;
    uint64_t total_written;
    uint64_t total_read;
    uint32_t n_writes;
    uint32_t n_reads;
} bench_result_t;

static void
print_result(const bench_result_t* r)
{
    printf("  %-35s %8.2f ms\n", r->name, r->time_ms);
    if (r->n_writes > 0) {
        printf("    Writes: %6u ops, %10.0f ops/s, %8.2f MB/s (%lu bytes)\n",
               r->n_writes, r->write_ops_sec, r->write_mbps,
               (unsigned long)r->total_written);
    }
    if (r->n_reads > 0) {
        printf("    Reads:  %6u ops, %10.0f ops/s, %8.2f MB/s (%lu bytes)\n",
               r->n_reads, r->read_ops_sec, r->read_mbps,
               (unsigned long)r->total_read);
    }
    printf("\n");
}

/* ─── Scenario 1: Sequential writes ──────────────────────────────── */

static bench_result_t
bench_sequential_writes(uint32_t iterations, uint32_t chunk_size)
{
    bench_result_t result = { .name = "Sequential writes" };
    uint8_t* data = malloc(chunk_size);
    fill_pattern(data, chunk_size, 0);

    uint32_t alloc_len = 65536;
    uint32_t virt_len = alloc_len;

    uint64_t t_start = now_ns();
    uint64_t write_start, write_end, read_start, read_end;

    for (uint32_t iter = 0; iter < iterations; iter++) {
        VERIFIED_RECV_BUFFER buf = {0};
        VerifiedRecvBufferInitialize(&buf, alloc_len, virt_len);

        uint32_t n_chunks = alloc_len / chunk_size;
        BOOLEAN newDataReady;

        /* Write phase */
        write_start = now_ns();
        for (uint32_t i = 0; i < n_chunks; i++) {
            fill_pattern(data, chunk_size, (uint64_t)i * chunk_size);
            VerifiedRecvBufferWrite(&buf, (uint64_t)i * chunk_size,
                                    (uint16_t)chunk_size, data, &newDataReady);
        }
        write_end = now_ns();

        /* Read phase */
        read_start = now_ns();
        uint64_t offset;
        uint32_t count = 2;
        QUIC_BUFFER buffers[2] = {0};
        VerifiedRecvBufferRead(&buf, &offset, &count, buffers);
        read_end = now_ns();

        /* Drain */
        uint64_t total = 0;
        for (uint32_t i = 0; i < count; i++) total += buffers[i].Length;
        VerifiedRecvBufferDrain(&buf, total);

        result.n_writes += n_chunks;
        result.n_reads += 1;
        result.total_written += (uint64_t)n_chunks * chunk_size;
        result.total_read += total;

        VerifiedRecvBufferUninitialize(&buf);
    }

    uint64_t t_end = now_ns();
    result.time_ms = elapsed_ms(t_start, t_end);
    result.write_ops_sec = ops_per_sec(result.n_writes, t_start, t_end);
    result.read_ops_sec = ops_per_sec(result.n_reads, t_start, t_end);
    result.write_mbps = throughput_mbps(result.total_written, t_start, t_end);
    result.read_mbps = throughput_mbps(result.total_read, t_start, t_end);

    free(data);
    return result;
}

/* ─── Scenario 2: Out-of-order writes ────────────────────────────── */

static bench_result_t
bench_ooo_writes(uint32_t iterations, uint32_t chunk_size)
{
    bench_result_t result = { .name = "Out-of-order writes" };
    uint8_t* data = malloc(chunk_size);

    uint32_t alloc_len = 65536;
    uint32_t virt_len = alloc_len;
    uint32_t n_chunks = alloc_len / chunk_size;

    /* Create shuffled index array */
    uint32_t* order = malloc(n_chunks * sizeof(uint32_t));
    for (uint32_t i = 0; i < n_chunks; i++) order[i] = i;

    uint64_t t_start = now_ns();

    for (uint32_t iter = 0; iter < iterations; iter++) {
        VERIFIED_RECV_BUFFER buf = {0};
        VerifiedRecvBufferInitialize(&buf, alloc_len, virt_len);

        /* Shuffle write order each iteration */
        shuffle(order, n_chunks);

        BOOLEAN newDataReady;

        /* Write phase: out-of-order */
        for (uint32_t i = 0; i < n_chunks; i++) {
            uint64_t off = (uint64_t)order[i] * chunk_size;
            fill_pattern(data, chunk_size, off);
            VerifiedRecvBufferWrite(&buf, off, (uint16_t)chunk_size,
                                    data, &newDataReady);
        }

        /* Read phase */
        uint64_t offset;
        uint32_t count = 2;
        QUIC_BUFFER buffers[2] = {0};
        VerifiedRecvBufferRead(&buf, &offset, &count, buffers);

        uint64_t total = 0;
        for (uint32_t i = 0; i < count; i++) total += buffers[i].Length;
        VerifiedRecvBufferDrain(&buf, total);

        result.n_writes += n_chunks;
        result.n_reads += 1;
        result.total_written += (uint64_t)n_chunks * chunk_size;
        result.total_read += total;

        VerifiedRecvBufferUninitialize(&buf);
    }

    uint64_t t_end = now_ns();
    result.time_ms = elapsed_ms(t_start, t_end);
    result.write_ops_sec = ops_per_sec(result.n_writes, t_start, t_end);
    result.read_ops_sec = ops_per_sec(result.n_reads, t_start, t_end);
    result.write_mbps = throughput_mbps(result.total_written, t_start, t_end);
    result.read_mbps = throughput_mbps(result.total_read, t_start, t_end);

    free(order);
    free(data);
    return result;
}

/* ─── Scenario 3: Interleaved write/read/drain ───────────────────── */

static bench_result_t
bench_interleaved(uint32_t iterations, uint32_t chunk_size)
{
    bench_result_t result = { .name = "Interleaved write/read/drain" };
    uint8_t* data = malloc(chunk_size);

    uint32_t alloc_len = 65536;
    uint32_t virt_len = 1 << 20; /* 1MB virtual to allow many cycles */
    uint32_t batch_size = 8;     /* write 8 chunks, then read+drain */

    uint64_t t_start = now_ns();

    for (uint32_t iter = 0; iter < iterations; iter++) {
        VERIFIED_RECV_BUFFER buf = {0};
        VerifiedRecvBufferInitialize(&buf, alloc_len, virt_len);

        uint64_t write_offset = 0;
        uint32_t cycles = 32; /* 32 write-read-drain cycles per iteration */

        for (uint32_t c = 0; c < cycles; c++) {
            BOOLEAN newDataReady;

            /* Write a batch sequentially */
            for (uint32_t i = 0; i < batch_size; i++) {
                fill_pattern(data, chunk_size, write_offset);
                VerifiedRecvBufferWrite(&buf, write_offset,
                                        (uint16_t)chunk_size, data,
                                        &newDataReady);
                write_offset += chunk_size;
                result.n_writes++;
                result.total_written += chunk_size;
            }

            /* Read */
            uint64_t offset;
            uint32_t count = 2;
            QUIC_BUFFER buffers[2] = {0};
            VerifiedRecvBufferRead(&buf, &offset, &count, buffers);

            uint64_t total = 0;
            for (uint32_t i = 0; i < count; i++) total += buffers[i].Length;
            result.n_reads++;
            result.total_read += total;

            /* Drain everything */
            VerifiedRecvBufferDrain(&buf, total);
        }

        VerifiedRecvBufferUninitialize(&buf);
    }

    uint64_t t_end = now_ns();
    result.time_ms = elapsed_ms(t_start, t_end);
    result.write_ops_sec = ops_per_sec(result.n_writes, t_start, t_end);
    result.read_ops_sec = ops_per_sec(result.n_reads, t_start, t_end);
    result.write_mbps = throughput_mbps(result.total_written, t_start, t_end);
    result.read_mbps = throughput_mbps(result.total_read, t_start, t_end);

    free(data);
    return result;
}

/* ─── Scenario 4: Small OOO writes (stress gap tracking) ─────────── */

static bench_result_t
bench_small_ooo(uint32_t iterations)
{
    bench_result_t result = { .name = "Small OOO writes (16B, gap stress)" };
    uint32_t chunk_size = 16;
    uint8_t data[16];

    uint32_t alloc_len = 4096;
    uint32_t virt_len = alloc_len;
    uint32_t n_chunks = alloc_len / chunk_size; /* 256 chunks */

    uint32_t* order = malloc(n_chunks * sizeof(uint32_t));
    for (uint32_t i = 0; i < n_chunks; i++) order[i] = i;

    uint64_t t_start = now_ns();

    for (uint32_t iter = 0; iter < iterations; iter++) {
        VERIFIED_RECV_BUFFER buf = {0};
        VerifiedRecvBufferInitialize(&buf, alloc_len, virt_len);

        /* Write every other chunk first (max gaps), then fill */
        for (uint32_t i = 0; i < n_chunks; i += 2) {
            uint64_t off = (uint64_t)i * chunk_size;
            fill_pattern(data, chunk_size, off);
            BOOLEAN ndr;
            VerifiedRecvBufferWrite(&buf, off, chunk_size, data, &ndr);
            result.n_writes++;
            result.total_written += chunk_size;
        }

        /* Fill remaining gaps */
        for (uint32_t i = 1; i < n_chunks; i += 2) {
            uint64_t off = (uint64_t)i * chunk_size;
            fill_pattern(data, chunk_size, off);
            BOOLEAN ndr;
            VerifiedRecvBufferWrite(&buf, off, chunk_size, data, &ndr);
            result.n_writes++;
            result.total_written += chunk_size;
        }

        /* Read + drain */
        uint64_t offset;
        uint32_t count = 2;
        QUIC_BUFFER buffers[2] = {0};
        VerifiedRecvBufferRead(&buf, &offset, &count, buffers);
        uint64_t total = 0;
        for (uint32_t i = 0; i < count; i++) total += buffers[i].Length;
        result.n_reads++;
        result.total_read += total;
        VerifiedRecvBufferDrain(&buf, total);

        VerifiedRecvBufferUninitialize(&buf);
    }

    uint64_t t_end = now_ns();
    result.time_ms = elapsed_ms(t_start, t_end);
    result.write_ops_sec = ops_per_sec(result.n_writes, t_start, t_end);
    result.read_ops_sec = ops_per_sec(result.n_reads, t_start, t_end);
    result.write_mbps = throughput_mbps(result.total_written, t_start, t_end);
    result.read_mbps = throughput_mbps(result.total_read, t_start, t_end);

    free(order);
    return result;
}

/* ─── Scenario 5: Large sequential writes (throughput) ───────────── */

static bench_result_t
bench_large_sequential(uint32_t iterations)
{
    bench_result_t result = { .name = "Large sequential writes (4KB)" };
    uint32_t chunk_size = 4096;
    uint8_t* data = malloc(chunk_size);

    uint32_t alloc_len = 65536;
    uint32_t virt_len = alloc_len;
    uint32_t n_chunks = alloc_len / chunk_size; /* 16 chunks */

    uint64_t t_start = now_ns();

    for (uint32_t iter = 0; iter < iterations; iter++) {
        VERIFIED_RECV_BUFFER buf = {0};
        VerifiedRecvBufferInitialize(&buf, alloc_len, virt_len);

        BOOLEAN newDataReady;
        for (uint32_t i = 0; i < n_chunks; i++) {
            fill_pattern(data, chunk_size, (uint64_t)i * chunk_size);
            VerifiedRecvBufferWrite(&buf, (uint64_t)i * chunk_size,
                                    (uint16_t)chunk_size, data,
                                    &newDataReady);
            result.n_writes++;
            result.total_written += chunk_size;
        }

        uint64_t offset;
        uint32_t count = 2;
        QUIC_BUFFER buffers[2] = {0};
        VerifiedRecvBufferRead(&buf, &offset, &count, buffers);
        uint64_t total = 0;
        for (uint32_t i = 0; i < count; i++) total += buffers[i].Length;
        result.n_reads++;
        result.total_read += total;
        VerifiedRecvBufferDrain(&buf, total);

        VerifiedRecvBufferUninitialize(&buf);
    }

    uint64_t t_end = now_ns();
    result.time_ms = elapsed_ms(t_start, t_end);
    result.write_ops_sec = ops_per_sec(result.n_writes, t_start, t_end);
    result.read_ops_sec = ops_per_sec(result.n_reads, t_start, t_end);
    result.write_mbps = throughput_mbps(result.total_written, t_start, t_end);
    result.read_mbps = throughput_mbps(result.total_read, t_start, t_end);

    free(data);
    return result;
}

/* ─── Main ────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    uint32_t iterations = 100;
    if (argc > 1) {
        iterations = (uint32_t)atoi(argv[1]);
        if (iterations == 0) iterations = 100;
    }

    /* Initialize Karamel globals (cb_max_length_sz) */
    krmlinit_globals();

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Verified CircularBuffer Benchmark\n");
    printf("  Iterations per scenario: %u\n", iterations);
    printf("═══════════════════════════════════════════════════════════════\n\n");

    bench_result_t results[5];

    printf("Running: Sequential writes (256B chunks)...\n");
    results[0] = bench_sequential_writes(iterations, 256);
    print_result(&results[0]);

    printf("Running: Out-of-order writes (256B chunks)...\n");
    results[1] = bench_ooo_writes(iterations, 256);
    print_result(&results[1]);

    printf("Running: Interleaved write/read/drain (256B chunks)...\n");
    results[2] = bench_interleaved(iterations, 256);
    print_result(&results[2]);

    printf("Running: Small OOO writes (16B, gap stress)...\n");
    results[3] = bench_small_ooo(iterations);
    print_result(&results[3]);

    printf("Running: Large sequential writes (4KB)...\n");
    results[4] = bench_large_sequential(iterations);
    print_result(&results[4]);

    /* Summary table */
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Summary\n");
    printf("───────────────────────────────────────────────────────────────\n");
    printf("  %-35s %10s %10s\n", "Scenario", "Write MB/s", "Write ops/s");
    printf("───────────────────────────────────────────────────────────────\n");
    for (int i = 0; i < 5; i++) {
        printf("  %-35s %10.2f %10.0f\n",
               results[i].name, results[i].write_mbps, results[i].write_ops_sec);
    }
    printf("═══════════════════════════════════════════════════════════════\n");

    /* Write gnuplot-compatible data file if --gnuplot <file> is given */
    const char* gnuplot_file = NULL;
    const char* label = "verified";
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--gnuplot") == 0)
            gnuplot_file = argv[++i];
        else if (strcmp(argv[i], "--label") == 0)
            label = argv[++i];
    }
    if (gnuplot_file) {
        /*
         * Output format: tab-separated, one row per scenario.
         * Columns: Scenario  WriteMBps  WriteOps  ReadMBps  ReadOps  TimeMs
         *
         * To plot verified vs unverified, run each benchmark with a
         * different --label and append to the same file:
         *
         *   ./bench_recv_buffer 100 --gnuplot bench.dat --label verified
         *   ./bench_recv_buffer_orig 100 --gnuplot bench.dat --label unverified
         *
         * Then use gnuplot:
         *
         *   set terminal pngcairo size 900,500
         *   set output 'throughput.png'
         *   set style data linespoints
         *   set ylabel 'Write MB/s'
         *   set xtics rotate by -30
         *   plot 'bench.dat' index 0 using 2:xtic(1) title 'verified', \
         *        'bench.dat' index 1 using 2:xtic(1) title 'unverified'
         */
        int append = 0;
        /* Append if file already exists and is non-empty */
        FILE* check = fopen(gnuplot_file, "r");
        if (check) { append = (fgetc(check) != EOF); fclose(check); }

        FILE* fp = fopen(gnuplot_file, append ? "a" : "w");
        if (fp) {
            if (!append) {
                fprintf(fp, "# Benchmark data for gnuplot\n");
                fprintf(fp, "# Columns: Scenario  WriteMBps  WriteOps  ReadMBps  ReadOps  TimeMs\n");
                fprintf(fp, "# Use 'index N' in gnuplot to select dataset N\n\n");
            } else {
                /* Blank lines separate gnuplot data blocks (index N) */
                fprintf(fp, "\n\n");
            }
            fprintf(fp, "# %s\n", label);
            for (int i = 0; i < 5; i++) {
                fprintf(fp, "\"%s\"\t%.2f\t%.0f\t%.2f\t%.0f\t%.2f\n",
                        results[i].name,
                        results[i].write_mbps, results[i].write_ops_sec,
                        results[i].read_mbps, results[i].read_ops_sec,
                        results[i].time_ms);
            }
            fclose(fp);
            printf("\nGnuplot data written to %s (label: %s)\n", gnuplot_file, label);
        } else {
            fprintf(stderr, "Error: could not open %s for writing\n", gnuplot_file);
        }
    }

    return 0;
}
