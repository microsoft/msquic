/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#define DEFAULT_RING_BUFFER_SIZE 0x8000         // 64 KB
#define MAX_IMMEDIATE_RING_BUFFER_SIZE 0x8000   // 64 KB
#define MIN_RING_BUFFER_SIZE 0x1000             // 4 KB
#define MAX_RING_BUFFER_SIZE 0x100000000        // 4 GB
#define MIN_FREE_BUFFER_THRESHOLD 0x80          // 128 Bytes
#define MAX_PAYLOAD_SIZE 0x1000000              // 16 MB
#define DEFAULT_OFFSET_BUFFER_SIZE 0x4          // 4 Bytes

typedef struct _RDMA_IO_COMPLETION_BUFFER
{
    uint32_t Offset;

    uint32_t Length;
    //
    // Hash table entry in the completion table.
    //
    CXPLAT_HASHTABLE_ENTRY TableEntry;
} RDMA_IO_COMPLETION_BUFFER;

//
// RDMA Ring Buffer
//
typedef struct _RDMA_SEND_RING_BUFFER
{
    uint8_t* Buffer;
    uint32_t Capacity;
    uint32_t CurSize;
    uint32_t Head;
    uint32_t Tail;
    uint32_t LocalToken;
    CXPLAT_POOL SendCompletionPool;
    CXPLAT_HASHTABLE* SendCompletionTable;
} RDMA_SEND_RING_BUFFER;

typedef struct _RDMA_RECV_RING_BUFFER
{
    uint8_t* Buffer; 
    uint32_t Capacity;
    uint32_t CurSize;
    uint8_t* OffsetBuffer;
    uint32_t OffsetBufferSize;
    uint32_t Head;
    uint32_t Tail;
    uint32_t LocalToken;
    uint32_t RemoteToken;
    uint32_t RemoteOffsetBufferToken;
    CXPLAT_POOL RecvCompletionPool;
    CXPLAT_HASHTABLE* RecvCompletionTable;
} RDMA_RECV_RING_BUFFER;


typedef struct _RDMA_REMOTE_RING_BUFFER
{
    uint64_t RemoteAddress;
    uint32_t Capacity;
    uint32_t RemoteToken;
    uint64_t RemoteOffsetBufferAddress;
    uint32_t RemoteOffsetBufferToken;
    uint8_t* OffsetBuffer; // Caches the offset information of the remote peer using 1-sided RDMA
    uint32_t OffsetBufferSize;
    uint32_t CurSize;
    uint32_t Head;
    uint32_t Tail;
} RDMA_REMOTE_RING_BUFFER;

//
// Initialize a new RDMA Send Ring Buffer
//
QUIC_STATUS
RdmaSendRingBufferInitialize(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Capacity,
    _In_ uint32_t LocalToken
    );

//
// Create a new RDMA Receive Ring Buffer Object
//
QUIC_STATUS
RdmaRecvRingBufferInitialize(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint8_t*  Buffer,
    _In_ uint32_t Capacity,
    _In_opt_ uint8_t* OffsetBuffer,
    _In_ uint32_t OffsetBufferSize,
    _In_ uint32_t LocalToken
    );

//
// Create a new RDMA Remote Ring Buffer Object
//
QUIC_STATUS
RdmaRemoteRingBufferInitialize(
    _In_ RDMA_REMOTE_RING_BUFFER* RemoteRingBuffer,
    _In_opt_ uint8_t* OffsetBuffer,
    _In_ uint32_t  OffsetBufferSize
    );

//
// UnInitialize a new RDMA Ring Buffer
//
QUIC_STATUS
RdmaRecvRingBufferUnInitialize(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer
    );

//
// Reserve Buffer from Send Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferReserve(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint32_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ uint32_t* Offset,
    _Out_ uint32_t* AllocLength
    );

//
// Release Buffer to Send Ring after Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferRelease(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Length,
    _In_ uint32_t Offset
    );

//
// Release Buffer to Receive Ring after reading the received data
//
QUIC_STATUS
RdmaLocalReceiveRingBufferRelease(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Offset,
    _In_ uint32_t Length
    );

//
// Reserve Buffer on the Remote Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaRemoteRecvRingBufferReserve(
    _In_ RDMA_REMOTE_RING_BUFFER* RemoteRingBuffer,
    _In_ uint32_t Length,
    _Out_ uint64_t* RemoteBuffer,
    _Out_ uint32_t* Offset,
    _Out_ uint32_t* AllocLength
    );

QUIC_STATUS
RdmaRemoteReceiveRingBufferRelease(
    _In_ RDMA_REMOTE_RING_BUFFER* RecvRingBuffer,
    _In_ uint32_t Length
    );