/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Represents a single contiguous range of bytes.
//
typedef struct QUIC_RECV_CHUNK {
    struct QUIC_RECV_CHUNK* Next;
    uint32_t AllocLength : 31;      // Allocation size of Buffer
    uint32_t ExternalReference : 1; // Indicates the buffer is being used externally.
    uint8_t Buffer[0];
} QUIC_RECV_CHUNK;

#define MAX_RECV_CHUNK_SIZE 0x40000000UL // 1GB

typedef struct QUIC_RECV_BUFFER {

    //
    // A list of chunks that make up the buffer.
    //
    QUIC_RECV_CHUNK* Chunks;

    //
    // Optional, preallocated initial chunk.
    //
    QUIC_RECV_CHUNK* PreallocatedChunk;

    //
    // The ranges that currently have bytes written to them.
    //
    QUIC_RANGE WrittenRanges;

    //
    // The stream offset of the byte at BufferStart.
    //
    uint64_t BaseOffset;

    //
    // Start of the head in the circular of the first chunk.
    //
    uint32_t BufferStart;

    //
    // Length of the buffer indicated to peers.
    //
    uint32_t VirtualBufferLength;

    //
    // Flag to indicate that after a drain, copy any remaining bytes to the
    // front of the buffer or reset the pointers to 0.
    //
    BOOLEAN CopyOnDrain : 1;

    //
    // Flag to indicate multiple receives can be indicated to the app at once.
    // This also changes the draining logic to consider a chunk still referenced
    // by the app until it has been completely drained.
    //
    BOOLEAN MultiReceiveMode : 1;

} QUIC_RECV_BUFFER;

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferInitialize(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t AllocBufferLength,
    _In_ uint32_t VirtualBufferLength,
    _In_ BOOLEAN CopyOnDrain,
    _In_opt_ QUIC_RECV_CHUNK* PreallocatedChunk
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferUninitialize(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    );

//
// Get the buffer's total length from 0.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRecvBufferGetTotalLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    );

//
// Changes the buffer's virtual buffer length.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferSetVirtualBufferLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t NewLength
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
// Buffers a (possibly out-of-order or duplicate) range of bytes.
//
// Returns TRUE if in-order bytes are ready to be delivered
// to the client.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicRecvBufferWrite(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t BufferOffset,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength) uint8_t const* Buffer,
    _Inout_ uint64_t* WriteLength,
    _Out_ BOOLEAN* ReadyToRead
    );

//
// Returns a pointer into the buffer for data ready to be delivered
// to the client.
//
// Since this returns an internal pointer, the caller must retain
// exclusive access to the buffer until it calls QuicRecvBufferDrain.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRecvBufferRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _Out_ uint64_t* BufferOffset,
    _Inout_ uint32_t* BufferCount,
    _Out_writes_all_(*BufferCount)
        QUIC_BUFFER* Buffers
    );

//
// Marks a number of bytes at the beginning of the buffer as
// delivered (freeing space in the buffer).
//
// Invalidates the pointer returned by QuicRecvBufferRead.
//
// Returns TRUE if there is no more data available to be read.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t BufferLength
    );
