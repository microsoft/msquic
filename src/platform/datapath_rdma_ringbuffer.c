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
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Capacity,
    _In_ uint32_t LocalToken
    )
{

    if (SendRingBuffer == NULL ||
        Buffer == NULL ||
        Capacity == 0 ||
        LocalToken == 0)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    SendRingBuffer->Buffer = Buffer;
    SendRingBuffer->Capacity = Capacity;
    SendRingBuffer->CurSize = 0;
    SendRingBuffer->Head = 0;
    SendRingBuffer->Tail = 0;
    SendRingBuffer->LocalToken = LocalToken;

    memset(SendRingBuffer->Buffer, 0, Capacity);

    return QUIC_STATUS_SUCCESS;
}

//
// Create a new RDMA Receive Ring Buffer
//
QUIC_STATUS
RdmaRecvRingBufferInitialize(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint8_t*  Buffer,
    _In_ uint32_t Capacity,
    _In_opt_ uint8_t* OffsetBuffer,
    _In_ uint32_t  OffsetBufferSize,
    _In_ uint32_t LocalToken
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (RecvRingBuffer == NULL ||
        Buffer == NULL ||
        Capacity == 0 ||
        LocalToken == 0)
    {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RecvRingBuffer->Buffer = Buffer;
    RecvRingBuffer->Capacity = Capacity;
    RecvRingBuffer->CurSize = 0;
    RecvRingBuffer->OffsetBuffer = OffsetBuffer;
    RecvRingBuffer->OffsetBufferSize = OffsetBufferSize;
    RecvRingBuffer->Head = 0;
    RecvRingBuffer->Tail = 0;
    RecvRingBuffer->LocalToken = LocalToken;
    RecvRingBuffer->RemoteToken = 0;
    RecvRingBuffer->OffsetBufferToken = 0;


    memset(RecvRingBuffer->Buffer, 0, Capacity);

    if (OffsetBuffer)
    {
        memset(RecvRingBuffer->OffsetBuffer, 0, OffsetBufferSize);
    }

Exit:
    return Status;       
}
  
QUIC_STATUS
RdmaRemoteRingBufferInitialize(
    _In_ RDMA_REMOTE_RING_BUFFER* RemoteRingBuffer,
    _In_ uint8_t* OffsetBuffer,
    _In_ uint32_t OffsetBufferSize
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (OffsetBuffer == NULL ||
        OffsetBufferSize == 0 ||
        RemoteRingBuffer == NULL)
    {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RemoteRingBuffer->RemoteAddress = 0;
    RemoteRingBuffer->Capacity = 0;
    RemoteRingBuffer->RemoteToken = 0;
    RemoteRingBuffer->RemoteOffsetBufferAddress = 0;
    RemoteRingBuffer->RemoteOffsetBufferToken = 0;
    RemoteRingBuffer->Head = 0;
    RemoteRingBuffer->Tail = 0;
    RemoteRingBuffer->OffsetBuffer = OffsetBuffer;
    RemoteRingBuffer->OffsetBufferSize = OffsetBufferSize;

    memset(RemoteRingBuffer->OffsetBuffer, 0, OffsetBufferSize);
}

    

//
// Reserve Buffer from Send Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferReserve(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint32_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ uint32_t *AllocLength
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
    else if (SendRingBuffer->CurSize != 0)
    {
        uint32_t AvailableSpace = SendRingBuffer->Capacity - SendRingBuffer->CurSize;

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
            SendRingBuffer->CurSize += SendRingBuffer->Capacity - SendRingBuffer->CurSize;

            if (SendRingBuffer->CurSize == SendRingBuffer->Capacity)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // Update Available Space for reserving the memory
            // and check
            //
            AvailableSpace = SendRingBuffer->Capacity - SendRingBuffer->CurSize;
            if (AvailableSpace < Length)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *Buffer = SendRingBuffer->Buffer + SendRingBuffer->Tail;
    *AllocLength = Length;

    SendRingBuffer->Tail = (SendRingBuffer->Tail + Length);
    SendRingBuffer->CurSize += Length;

    return QUIC_STATUS_SUCCESS;
}

//
// Release Buffer to Send Ring after Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferRelease(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint32_t Length,
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
    SendRingBuffer->CurSize -= Length;

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
RdmaPeerRecvRingBufferReserve(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint32_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ uint32_t* AllocLength
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
    else if (RecvRingBuffer->CurSize != 0)
    {
        uint32_t AvailableSpace = RecvRingBuffer->Capacity - RecvRingBuffer->CurSize;

        if (AvailableSpace < Length)
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
            RecvRingBuffer->CurSize += RecvRingBuffer->Capacity - RecvRingBuffer->CurSize;

            if (RecvRingBuffer->CurSize == RecvRingBuffer->Capacity)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // Update Available Space for reserving the memory
            // and check
            //
            AvailableSpace = RecvRingBuffer->Capacity - RecvRingBuffer->CurSize;
            if (AvailableSpace < Length)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *Buffer = RecvRingBuffer->Buffer + RecvRingBuffer->Tail;
    *AllocLength = Length;

    RecvRingBuffer->Tail = (RecvRingBuffer->Tail + Length);
    RecvRingBuffer->CurSize += Length;

    return QUIC_STATUS_SUCCESS;
}

//
// Release Buffer to Receive Ring after Reading the Data
//
QUIC_STATUS
RdmaLocalReceiveRingBufferRelease(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Length
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

//
// Release Buffer to Receive Ring after Reading the Data
//
QUIC_STATUS
RdmaRemoteReceiveRingBufferRelease(
    _In_ RDMA_REMOTE_RING_BUFFER* RemoteRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Length
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