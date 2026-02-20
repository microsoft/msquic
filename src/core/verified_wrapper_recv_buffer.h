/*
 * verified_wrapper_recv_buffer.h
 *
 * Thin wrapper adapting Karamel-extracted verified CircularBuffer to the
 * msquic recv_buffer.h API. The extracted verified_recv_buffer.{c,h} files
 * are NEVER hand-edited — only this wrapper is hand-written.
 *
 * Usage: Replace #include "recv_buffer.h" with this header.
 */

#ifndef VERIFIED_WRAPPER_RECV_BUFFER_H
#define VERIFIED_WRAPPER_RECV_BUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Include the Karamel-extracted verified implementation */
#include "verified/verified_recv_buffer.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* ─── Type aliases for readability ─────────────────────────────────── */

typedef Pulse_Lib_CircularBuffer_cb_internal* verified_cb_t;
typedef Pulse_Lib_Vector_vector_internal__Pulse_Lib_RangeVec_range* verified_rm_t;

/* ─── VERIFIED_RECV_BUFFER: wraps cb + rm ──────────────────────────── */

typedef struct VERIFIED_RECV_BUFFER {
    verified_cb_t cb;
    verified_rm_t rm;
} VERIFIED_RECV_BUFFER;

/* ─── QUIC_BUFFER compatibility (if not already defined) ───────────── */

#ifndef QUIC_BUFFER_DEFINED
typedef struct QUIC_BUFFER {
    uint32_t Length;
    uint8_t* Buffer;
} QUIC_BUFFER;
#define QUIC_BUFFER_DEFINED
#endif

/* QUIC_STATUS: 0 = success */
#ifndef QUIC_STATUS
typedef unsigned long QUIC_STATUS;
#define QUIC_STATUS_SUCCESS         ((QUIC_STATUS)0)
#define QUIC_STATUS_OUT_OF_MEMORY   ((QUIC_STATUS)0x80070057)
#endif

#ifndef BOOLEAN
typedef int BOOLEAN;
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif
#endif

/* ─── API Functions ────────────────────────────────────────────────── */

/*
 * Initialize a verified receive buffer.
 * Maps to: QuicRecvBufferInitialize
 *
 * AllocBufferLength and VirtualBufferLength must be powers of 2.
 * AllocBufferLength <= VirtualBufferLength.
 */
static inline
QUIC_STATUS
VerifiedRecvBufferInitialize(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint32_t AllocBufferLength,
    uint32_t VirtualBufferLength)
{
    K____Pulse_Lib_CircularBuffer_cb_internal___Pulse_Lib_Vector_vector_internal__Pulse_Lib_RangeVec_range_
        result = RecvBufferWrapper_create((size_t)AllocBufferLength, (size_t)VirtualBufferLength);
    RecvBuffer->cb = result.fst;
    RecvBuffer->rm = result.snd;
    return QUIC_STATUS_SUCCESS;
}

/*
 * Free the verified receive buffer.
 * Maps to: QuicRecvBufferUninitialize
 */
static inline
void
VerifiedRecvBufferUninitialize(
    VERIFIED_RECV_BUFFER* RecvBuffer)
{
    RecvBufferWrapper_free(RecvBuffer->cb, RecvBuffer->rm);
    RecvBuffer->cb = NULL;
    RecvBuffer->rm = NULL;
}

/*
 * Get total length of data written (including gaps).
 * Maps to: QuicRecvBufferGetTotalLength
 */
static inline
uint64_t
VerifiedRecvBufferGetTotalLength(
    const VERIFIED_RECV_BUFFER* RecvBuffer)
{
    return (uint64_t)RecvBufferWrapper_get_total_length(
        RecvBuffer->cb, RecvBuffer->rm);
}

/*
 * Returns TRUE if there is any unread contiguous data.
 * Maps to: QuicRecvBufferHasUnreadData
 */
static inline
BOOLEAN
VerifiedRecvBufferHasUnreadData(
    const VERIFIED_RECV_BUFFER* RecvBuffer)
{
    size_t rl = RecvBufferWrapper_read_length(RecvBuffer->cb, RecvBuffer->rm);
    return rl > 0 ? TRUE : FALSE;
}

/*
 * Increase the virtual buffer length.
 * Maps to: QuicRecvBufferIncreaseVirtualBufferLength
 *
 * NewLength must be a power of 2 and >= current virtual length.
 */
static inline
void
VerifiedRecvBufferIncreaseVirtualBufferLength(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint32_t NewLength)
{
    RecvBufferWrapper_set_virtual_length(
        RecvBuffer->cb, RecvBuffer->rm, (size_t)NewLength);
}

/*
 * Write data at an absolute stream offset (possibly out-of-order).
 * Maps to: QuicRecvBufferWrite
 *
 * WriteQuota/QuotaConsumed/BufferSizeNeeded are not tracked by the
 * verified buffer — the caller handles quota at a higher layer.
 */
static inline
QUIC_STATUS
VerifiedRecvBufferWrite(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint64_t WriteOffset,
    uint16_t WriteLength,
    const uint8_t* WriteBuffer,
    BOOLEAN* NewDataReady)
{
    if (WriteLength == 0) {
        if (NewDataReady) *NewDataReady = FALSE;
        return QUIC_STATUS_SUCCESS;
    }

    Pulse_Lib_CircularBuffer_write_result wr =
        RecvBufferWrapper_write_buffer(
            RecvBuffer->cb,
            RecvBuffer->rm,
            (size_t)WriteOffset,
            (uint8_t*)(uintptr_t)WriteBuffer, /* cast away const for verified API */
            (size_t)WriteLength);

    if (NewDataReady) {
        *NewDataReady = wr.new_data_ready ? TRUE : FALSE;
    }

    if (wr.resize_failed) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    return QUIC_STATUS_SUCCESS;
}

/*
 * Zero-copy read: returns pointers into the internal buffer.
 * Maps to: QuicRecvBufferRead
 *
 * BufferCount is set to the number of QUIC_BUFFERs filled (1 or 2).
 * BufferOffset is set to the base stream offset of the read.
 */
static inline
void
VerifiedRecvBufferRead(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint64_t* BufferOffset,
    uint32_t* BufferCount,
    QUIC_BUFFER* Buffers)
{
    size_t read_len = RecvBufferWrapper_read_length(
        RecvBuffer->cb, RecvBuffer->rm);

    if (read_len == 0) {
        *BufferCount = 0;
        return;
    }

    /* Get base offset from the internal cb struct */
    *BufferOffset = (uint64_t)RecvBuffer->cb->bo;

    Pulse_Lib_CircularBuffer_read_view rv =
        RecvBufferWrapper_read_zerocopy(
            RecvBuffer->cb, RecvBuffer->rm, read_len);

    /* Segment 1 is always present */
    Buffers[0].Buffer = rv.arr + rv.off1;
    Buffers[0].Length = (uint32_t)rv.len1;

    if (rv.len2 > 0) {
        /* Wrap-around: two segments */
        Buffers[1].Buffer = rv.arr + rv.off2;
        Buffers[1].Length = (uint32_t)rv.len2;
        *BufferCount = 2;
    } else {
        *BufferCount = 1;
    }

    /* Release the zero-copy read (verified buffer manages the trade) */
    RecvBufferWrapper_release_read(RecvBuffer->cb, RecvBuffer->rm, rv);
}

/*
 * Drain bytes from the front of the buffer.
 * Maps to: QuicRecvBufferDrain
 *
 * Returns TRUE if there is no more data available to read after draining.
 */
static inline
BOOLEAN
VerifiedRecvBufferDrain(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint64_t DrainLength)
{
    bool no_more = RecvBufferWrapper_drain(
        RecvBuffer->cb, RecvBuffer->rm, (size_t)DrainLength);
    return no_more ? TRUE : FALSE;
}

/*
 * Copy-based read into a caller-provided buffer.
 * Alternative to zero-copy read when the caller wants a flat copy.
 */
static inline
void
VerifiedRecvBufferReadCopy(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint8_t* Destination,
    uint32_t Length)
{
    RecvBufferWrapper_read_buffer(
        RecvBuffer->cb, RecvBuffer->rm,
        Destination, (size_t)Length);
}

/*
 * Get the current allocation length.
 */
static inline
uint32_t
VerifiedRecvBufferGetAllocLength(
    const VERIFIED_RECV_BUFFER* RecvBuffer)
{
    return (uint32_t)RecvBufferWrapper_get_alloc_length(
        RecvBuffer->cb, RecvBuffer->rm);
}

/*
 * Resize (grow) the buffer. new_alloc_len must be a power of 2.
 */
static inline
void
VerifiedRecvBufferResize(
    VERIFIED_RECV_BUFFER* RecvBuffer,
    uint32_t NewAllocLength)
{
    RecvBufferWrapper_resize(
        RecvBuffer->cb, RecvBuffer->rm, (size_t)NewAllocLength);
}

#if defined(__cplusplus)
}
#endif

#endif /* VERIFIED_WRAPPER_RECV_BUFFER_H */
