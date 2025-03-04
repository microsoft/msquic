/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "platform_internal.h"

#define DEFAULT_RING_BUFFER_SIZE 0x8000     // 64 KB
#define MIN_RING_BUFFER_SIZE 0x1000         // 4 KB
#define MAX_RING_BUFFER_SIZE 0x100000000    // 4 GB
#define MIN_FREE_BUFFER_THRESHOLD 0x20      // 32 Bytes
#define DEFAULT_OFFSET_BUFFER_SIZE 0x8      // 8 Bytes

//
// RDMA Ring Buffer
//
typedef struct _RDMA_NDSPI_SEND_RING_BUFFER
{
    uint8_t*  Buffer;
    size_t Capacity;
    size_t Size;
    size_t Head;
    size_t Tail;
    
} RDMA_SEND_RING_BUFFER, *PRDMA_SEND_RING_BUFFER;

typedef struct _RDMA_NDSPI_RECV_RING_BUFFER
{
    uint8_t* Buffer; 
    size_t Capacity;
    size_t Size;
    uint8_t* OffsetBuffer;
    size_t OffsetBufferSize;
    size_t Head;
    size_t Tail;
} RDMA_RECV_RING_BUFFER, *PRDMA_RECV_RING_BUFFER;

//
// Initialize a new RDMA Send Ring Buffer
//
QUIC_STATUS
RdmaSendRingBufferInitialize(
    _In_ uint8_t* Buffer,
    _In_ size_t Capacity,
    _Deref_out_ PRDMA_SEND_RING_BUFFER* SendRingBuffer
    );

//
// UnInitialize a new RDMA Ring Buffer
//
QUIC_STATUS
RdmaSendRingBufferUnInitialize(
    _In_ PRDMA_SEND_RING_BUFFER SendRingBuffer
    );

//
// Create a new RDMA Receive Ring Buffer
//
QUIC_STATUS
RdmaRecvRingBufferInitialize(
    _In_ uint8_t*  Buffer,
    _In_ size_t Capacity,
    _In_ uint8_t* OffsetBuffer,
    _In_ size_t  OffsetBufferSize,
    _Deref_out_ PRDMA_RECV_RING_BUFFER* RecvRingBuffer
    );

//
// UnInitialize a new RDMA Ring Buffer
//
QUIC_STATUS
RdmaRecvRingBufferUnInitialize(
    _In_ PRDMA_RECV_RING_BUFFER RecvRingBuffer
    );

//
// Reserve Buffer from Send Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferReserve(
    _In_ PRDMA_SEND_RING_BUFFER SendRingBuffer,
    _In_ size_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ size_t* AllocLength
    );

//
// Release Buffer to Send Ring after Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferRelease(
    _In_ PRDMA_SEND_RING_BUFFER SendRingBuffer,
    _In_ size_t Length,
    _In_ uint8_t* Buffer
    );

//
// Reserve Buffer on the Remote Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaRemoteRecvRingBufferReserve(
    _In_ PRDMA_RECV_RING_BUFFER RecvRingBuffer,
    _In_ size_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ size_t* AllocLength
    );

//
// Release Buffer to Receive Ring after reading the received data
//
QUIC_STATUS
RdmaLocalReceiveRingBufferRelease(
    _In_ PRDMA_RECV_RING_BUFFER RecvRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ size_t Length
    );