/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#if defined(__cplusplus)
extern "C" {
#endif

typedef enum QUIC_RECV_BUF_MODE {
    QUIC_RECV_BUF_MODE_SINGLE,      // Only one receive with a single contiguous buffer at a time.
    QUIC_RECV_BUF_MODE_CIRCULAR,    // Only one receive that may indicate two contiguous buffers at a time.
    QUIC_RECV_BUF_MODE_MULTIPLE,    // Multiple independent receives that may indicate up to two contiguous buffers at a time.
    QUIC_RECV_BUF_MODE_APP_OWNED    // Uses memory buffers provided by the app. Only one receive at a time,
                                    //   that may indicate up to the number of provided buffers.
} QUIC_RECV_BUF_MODE;

//
// Represents a single contiguous range of bytes.
//
typedef struct QUIC_RECV_CHUNK {
    CXPLAT_LIST_ENTRY Link;          // Link in the list of chunks.
    uint32_t AllocLength;            // Allocation size of Buffer
    uint8_t ExternalReference  : 1;  // Indicates the buffer is being used externally.
    uint8_t AllocatedFromPool  : 1;  // Indicates the buffer is was allocated from a pool.
    uint8_t* Buffer;                 // Pointer to the buffer itself. Doesn't need to be freed independently:
                                     //  - for internally allocated buffers, points in the same allocation.
                                     //  - for app-owned buffers, the buffer isn't owned
} QUIC_RECV_CHUNK;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvChunkInitialize(
    _Inout_ QUIC_RECV_CHUNK* Chunk,
    _In_ uint32_t AllocLength,
    _Inout_updates_(AllocLength) uint8_t* Buffer,
    _In_ BOOLEAN BufferAllocatedFromPool
    );

typedef struct QUIC_RECV_BUFFER {

    //
    // A list of chunks that make up the buffer.
    //
    CXPLAT_LIST_ENTRY Chunks;

    //
    // Optional, retired chunk waiting to no longer be referenced.
    //
    QUIC_RECV_CHUNK* RetiredChunk;

    //
    // Ranges of stream offsets that have been written to the buffer,
    // starting from 0 (not only what is currently in the buffer).
    // The first sub-range includes [0, BaseOffset + ReadLength),
    // and potentially more if ReadLength is constrained by the chunk size.
    //
    QUIC_RANGE WrittenRanges;

    //
    // The length of all pending reads to the app.
    //
    uint64_t ReadPendingLength;

    //
    // The stream offset of the byte at ReadStart.
    //
    uint64_t BaseOffset;

    //
    // Position of the reading head in the first chunk.
    //
    uint32_t ReadStart;

    //
    // The length of data available to read in the first "active" chunk,
    // starting at ReadStart.
    // ("Active" means a chunk that can targetted by a read or write.
    // In SINGLE and CIRCULAR modes, only the last chunk is "active".)
    //
    uint32_t ReadLength;

    //
    // Length of the buffer indicated to peers.
    // Invariant: BaseOffset + VirtualBufferLength must never decrease.
    //
    uint32_t VirtualBufferLength;

    //
    // Basically same as Chunk->AllocLength of first chunk, but start shrinking
    // by drain operation after next chunk is allocated.
    //
    uint32_t Capacity;

    //
    // Controls the behavior of the buffer, which changes the logic for
    // writing, reading and draining.
    //
    QUIC_RECV_BUF_MODE RecvMode;

} QUIC_RECV_BUFFER;

//
// Initialize a QUIC_RECV_BUFFER.
// Can only fail if PreallocatedChunk == NULL && RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED.
// PreallocatedChunk ownership is given to the receive buffer.
// PreallocatedChunk must be null if RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferInitialize(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t AllocBufferLength,
    _In_ uint32_t VirtualBufferLength,
    _In_ QUIC_RECV_BUF_MODE RecvMode,
    _In_opt_ QUIC_RECV_CHUNK* PreallocatedChunk
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferUninitialize(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    );

//
// Get the buffer's total length from offset 0. This does not necessarily mean
// all of this buffer is available to be read, as some of it may have already
// been read and drained, or only partially received (i.e. there are gaps).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRecvBufferGetTotalLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    );

//
// Returns TRUE there is any unread data in the receive buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferHasUnreadData(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    );

//
// Changes the buffer's virtual buffer length.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferIncreaseVirtualBufferLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t NewLength
    );

//
// Provide app-owned buffers. At least one chunk must be provided.
// Only valid for QUIC_RECV_BUF_MODE_APP_OWNED mode.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferProvideChunks(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _Inout_ CXPLAT_LIST_ENTRY* /* QUIC_RECV_CHUNKS */ Chunks
    );

//
// Buffers a (possibly out-of-order or duplicate) range of bytes.
//
// NewDataReady indicates if new in-order bytes are ready to be delivered to the
// client.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicRecvBufferWrite(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t WriteOffset,
    _In_ uint16_t WriteLength,
    _In_reads_bytes_(WriteLength) uint8_t const* WriteBuffer,
    _Inout_ uint64_t* WriteLimit,
    _Out_ BOOLEAN* NewDataReady
    );

//
// Returns how many QUIC_BUFFERs should be passed to `QuicRecvBufferRead` to
// read all the available data in the buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicRecvBufferReadBufferNeededCount(
    _In_ const QUIC_RECV_BUFFER* RecvBuffer
    );

//
// Returns a pointer into the buffer for data ready to be delivered to the
// client.
//
// Since this returns an internal pointer, the caller must retain exclusive
// access to the buffer until it calls QuicRecvBufferDrain.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _Out_ uint64_t* BufferOffset,
    _Inout_ uint32_t* BufferCount,
    _Out_writes_to_(*BufferCount, *BufferCount)
        QUIC_BUFFER* Buffers
    );

//
// Marks a number of bytes at the beginning of the buffer as delivered (freeing
// space in the buffer).
//
// When receive mode isn't MULTIPLE it invalidates the pointer returned by
// QuicRecvBufferRead.
//
// Returns TRUE if there is no more data available to be read.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t DrainLength
    );

//
// Indicates the caller is abandoning any pending read.
//   N.B. Currently only supported for QUIC_RECV_BUF_MODE_SINGLE mode.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferResetRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    );

#if defined(__cplusplus)
}
#endif
