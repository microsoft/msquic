/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC RDMA Ring Buffer Implementation (User Mode) for
    single threaded operation

--*/
#include "platform_internal.h"
#include  "datapath_rdma_ring_buffer.h"

#ifdef QUIC_CLOG
#include "datapath_winuser.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses


//
// Initialize a new RDMA Send Ring Buffer
//
QUIC_STATUS
RdmaSendRingBufferInitialize(
    _In_ uint8_t* Buffer,
    _In_ size_t Capacity,
    _Inout_ RDMA_SEND_RING_BUFFER** SendRingBuffer
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (Buffer == NULL ||
        Capacity == 0)
    {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (*SendRingBuffer == NULL)
    {
        *SendRingBuffer = CXPLAT_ALLOC_NONPAGED(sizeof(RDMA_SEND_RING_BUFFER), QUIC_POOL_PLATFORM_GENERIC);
        if (*SendRingBuffer == NULL)
        {
            QuicTraceEvent(
                SendRingBufferAllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "RDMA_SEND_RING_BUFFER",
                sizeof(RDMA_SEND_RING_BUFFER));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
    }

    (*SendRingBuffer)->Buffer = Buffer;
    (*SendRingBuffer)->Capacity = Capacity;
    (*SendRingBuffer)->Size = 0;
    (*SendRingBuffer)->Head = 0;
    (*SendRingBuffer)->Tail = 0;

    memset((*SendRingBuffer)->Buffer, 0, Capacity);

Exit:
    return Status;
}

//
// UnInitialize a new RDMA Ring Buffer
//
QUIC_STATUS
RdmaSendRingBufferUnInitialize(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer
    )
{
    if (SendRingBuffer == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_FREE(SendRingBuffer, QUIC_POOL_PLATFORM_GENERIC);

    return QUIC_STATUS_SUCCESS;
}

//
// Create a new RDMA Receive Ring Buffer
//
QUIC_STATUS
RdmaRecvRingBufferInitialize(
    _In_ uint8_t*  Buffer,
    _In_ size_t Capacity,
    _In_opt_ uint8_t* OffsetBuffer,
    _In_ size_t  OffsetBufferSize,
    _Inout_ RDMA_RECV_RING_BUFFER** RecvRingBuffer
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (Buffer == NULL ||
        Capacity == 0)
    {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    if (*RecvRingBuffer == NULL)
    {
        *RecvRingBuffer = CXPLAT_ALLOC_NONPAGED(sizeof(RDMA_RECV_RING_BUFFER), QUIC_POOL_PLATFORM_GENERIC);
        if (*RecvRingBuffer == NULL) {
            QuicTraceEvent(
                RecvRingBufferAllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "RDMA_RECV_RING_BUFFER",
                sizeof(RDMA_RECV_RING_BUFFER));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
    }

    (*RecvRingBuffer)->Buffer = Buffer;
    (*RecvRingBuffer)->Capacity = Capacity;
    (*RecvRingBuffer)->Size = 0;
    (*RecvRingBuffer)->OffsetBuffer = OffsetBuffer;
    (*RecvRingBuffer)->OffsetBufferSize = OffsetBufferSize;
    (*RecvRingBuffer)->Head = 0;
    (*RecvRingBuffer)->Tail = 0;

    memset((*RecvRingBuffer)->Buffer, 0, Capacity);

Exit:
    return Status;       
}

//
// UnInitialize a new RDMA Ring Buffer
//
QUIC_STATUS
RdmaRecvRingBufferUnInitialize(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer
    )
{
    if (RecvRingBuffer == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_FREE(RecvRingBuffer, QUIC_POOL_PLATFORM_GENERIC);

    return QUIC_STATUS_SUCCESS;
}    

//
// Reserve Buffer from Send Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferReserve(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ size_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ size_t *AllocLength
    )
{
    if (SendRingBuffer == NULL ||
        Length == 0 ||
        Buffer == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    *Buffer = NULL;
    *AllocLength = 0;

    if (Length > SendRingBuffer->Capacity)
    {
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }
    else if (SendRingBuffer->Size != 0)
    {
        size_t AvailableSpace = SendRingBuffer->Capacity - SendRingBuffer->Size;

        if (AvailableSpace < Length || AvailableSpace < MIN_FREE_BUFFER_THRESHOLD)
        {

            //
            // If Head Offset is greater than Tail Offset, then
            // return error since it cannot wrap around the buffer
            //
            if (SendRingBuffer->Head >= SendRingBuffer->Tail)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // In this case, Head Offset is trailing Tail Offset and so it's safe to
            // wrap around 
            //
            SendRingBuffer->Tail = 0;
            SendRingBuffer->Size += SendRingBuffer->Capacity - SendRingBuffer->Size;

            if (SendRingBuffer->Size == SendRingBuffer->Capacity)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // Update Available Space for reserving the memory
            // and check
            //
            AvailableSpace = SendRingBuffer->Capacity - SendRingBuffer->Size;
            if (AvailableSpace < Length)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *Buffer = SendRingBuffer->Buffer + SendRingBuffer->Tail + Length;
    *AllocLength = Length;

    SendRingBuffer->Tail = (SendRingBuffer->Tail + Length) % SendRingBuffer->Capacity;
    SendRingBuffer->Size += Length;

    return QUIC_STATUS_SUCCESS;
}

//
// Release Buffer to Send Ring after Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferRelease(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ size_t Length,
    _In_ uint8_t* Buffer
    )
{
    if (SendRingBuffer == NULL ||
        Length == 0 ||
        Length > SendRingBuffer->Capacity ||
        Buffer == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    memset(Buffer, 0, Length);
    SendRingBuffer->Head = (SendRingBuffer->Head + Length) % SendRingBuffer->Capacity;
    SendRingBuffer->Size -= Length;

    //
    // Check if the Tail offset has wrapped around
    // the buffer and set the Head offset accordingly
    //
    if (SendRingBuffer->Tail < SendRingBuffer->Head &&
        *(SendRingBuffer->Buffer + SendRingBuffer->Head) == 0)
    {
        SendRingBuffer->Head = 0;
    }

    return QUIC_STATUS_SUCCESS;
}

//
// Reserve Buffer on the Remote Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaRemoteRecvRingBufferReserve(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ size_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ size_t* AllocLength
    )
{
    if (RecvRingBuffer == NULL ||
        Length == 0 ||
        Buffer == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    *Buffer = NULL;
    *AllocLength = 0;

    if (Length > RecvRingBuffer->Capacity)
    {
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }
    else if (RecvRingBuffer->Size != 0)
    {
        size_t AvailableSpace = RecvRingBuffer->Capacity - RecvRingBuffer->Size;

        if (AvailableSpace < Length || AvailableSpace < MIN_FREE_BUFFER_THRESHOLD)
        {
            //
            // If Head Offset is greater than Tail Offset, then
            // return error since it cannot wrap around the buffer
            //
            if (RecvRingBuffer->Head >= RecvRingBuffer->Tail)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // In this case, Head Offset is trailing Tail Offset and so it's safe to
            // wrap around 
            //
            RecvRingBuffer->Tail = 0;
            RecvRingBuffer->Size += RecvRingBuffer->Capacity - RecvRingBuffer->Size;

            if (RecvRingBuffer->Size == RecvRingBuffer->Capacity)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // Update Available Space for reserving the memory
            // and check
            //
            AvailableSpace = RecvRingBuffer->Capacity - RecvRingBuffer->Size;
            if (AvailableSpace < Length)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *Buffer = RecvRingBuffer->Buffer + RecvRingBuffer->Tail + Length;
    *AllocLength = Length;

    RecvRingBuffer->Tail = (RecvRingBuffer->Tail + Length) % RecvRingBuffer->Capacity;
    RecvRingBuffer->Size += Length;

    return QUIC_STATUS_SUCCESS;
}

//
// Release Buffer to Receive Ring after Reading the Data
//
QUIC_STATUS
RdmaLocalReceiveRingBufferRelease(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ size_t Length
    )
{
    if (RecvRingBuffer == NULL ||
        Buffer == NULL ||
        Length == 0 ||
        Length > RecvRingBuffer->Capacity)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    memset(Buffer, 0, Length);
    RecvRingBuffer->Head += Length;

    return QUIC_STATUS_SUCCESS;
}