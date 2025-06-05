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

    SendRingBuffer->SendCompletionTable = NULL;
    SendRingBuffer->Buffer = Buffer;
    SendRingBuffer->Capacity = Capacity;
    SendRingBuffer->CurSize = 0;
    SendRingBuffer->Head = 0;
    SendRingBuffer->Tail = 0;
    SendRingBuffer->LocalToken = LocalToken;

    memset(SendRingBuffer->Buffer, 0, Capacity);

    if (!CxPlatHashtableInitialize(&SendRingBuffer->SendCompletionTable, CXPLAT_HASH_MIN_SIZE))
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "SendCompletionTable",
            0);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatPoolInitialize(
        FALSE,
        sizeof(RDMA_IO_COMPLETION_BUFFER),
        QUIC_POOL_DATAPATH,
        &SendRingBuffer->SendCompletionPool);

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
    if (RecvRingBuffer == NULL ||
        Buffer == NULL ||
        Capacity == 0 ||
        LocalToken == 0)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    RecvRingBuffer->RecvCompletionTable = NULL;
    RecvRingBuffer->Buffer = Buffer;
    RecvRingBuffer->Capacity = Capacity;
    RecvRingBuffer->CurSize = 0;
    RecvRingBuffer->OffsetBuffer = OffsetBuffer;
    RecvRingBuffer->OffsetBufferSize = OffsetBufferSize;
    RecvRingBuffer->Head = 0;
    RecvRingBuffer->Tail = 0;
    RecvRingBuffer->LocalToken = LocalToken;
    RecvRingBuffer->RemoteToken = 0;
    RecvRingBuffer->RemoteOffsetBufferToken = 0;

    memset(RecvRingBuffer->Buffer, 0, Capacity);

    if (OffsetBuffer)
    {
        memset(RecvRingBuffer->OffsetBuffer, 0, OffsetBufferSize);
    }

    if (!CxPlatHashtableInitialize(&RecvRingBuffer->RecvCompletionTable, CXPLAT_HASH_MIN_SIZE))
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RecvCompletionTable",
            0);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatPoolInitialize(
        FALSE,
        sizeof(RDMA_IO_COMPLETION_BUFFER),
        QUIC_POOL_DATAPATH,
        &RecvRingBuffer->RecvCompletionPool);

    return QUIC_STATUS_SUCCESS;       
}
  
QUIC_STATUS
RdmaRemoteRingBufferInitialize(
    _In_ RDMA_REMOTE_RING_BUFFER* RemoteRingBuffer,
    _In_opt_ uint8_t* OffsetBuffer,
    _In_ uint32_t OffsetBufferSize
    )
{

    if (RemoteRingBuffer == NULL ||
        (OffsetBuffer && !OffsetBufferSize) ||
        (!OffsetBuffer && OffsetBufferSize))
    {
        return QUIC_STATUS_INVALID_PARAMETER;
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
    RemoteRingBuffer->CurSize = 0;

    memset(RemoteRingBuffer->OffsetBuffer, 0, OffsetBufferSize);

    return QUIC_STATUS_SUCCESS;
}

//
// Reserve Buffer from Send Ring for Performing RDMA Write
//
QUIC_STATUS
RdmaSendRingBufferReserve(
    _In_ RDMA_SEND_RING_BUFFER* SendRingBuffer,
    _In_ uint32_t Length,
    _Out_ uint8_t** Buffer,
    _Out_ uint32_t* Offset,
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
            // Add an entry in Send Completion Table for the Head Offset. This would ensure that
            // the head offset will wrap around when it hits this tail offset since there is no data
            //
            RDMA_IO_COMPLETION_BUFFER *buf = CxPlatPoolAlloc(&SendRingBuffer->SendCompletionPool);
            CXPLAT_DBG_ASSERT(buf != NULL);
            
            if (buf == NULL)
            {
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
    
            buf->Offset = SendRingBuffer->Tail;
            buf->Length = SendRingBuffer->Capacity - SendRingBuffer->CurSize;
    
            CxPlatHashtableInsert(
                SendRingBuffer->SendCompletionTable,
                &buf->TableEntry,
                (uint32_t)SendRingBuffer->Tail,
                NULL);


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
    *Offset = SendRingBuffer->Tail;
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
    _In_ uint8_t* Buffer,
    _In_ uint32_t Length,
    _In_ uint32_t Offset
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

    if (Offset == SendRingBuffer->Head)
    {
        SendRingBuffer->Head = (SendRingBuffer->Head + Length);
        SendRingBuffer->CurSize -= Length;

        CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
        CXPLAT_HASHTABLE_ENTRY* Entry =
        CxPlatHashtableLookup(SendRingBuffer->SendCompletionTable, (uint32_t)Offset, &Context);

        while (Entry != NULL)
        {
            RDMA_IO_COMPLETION_BUFFER* buf =
            CXPLAT_CONTAINING_RECORD(Entry, RDMA_IO_COMPLETION_BUFFER, TableEntry);

            memset(SendRingBuffer->Buffer + buf->Offset, 0, Length);

            SendRingBuffer->Head = buf->Offset + Length;
            SendRingBuffer->CurSize -= Length;
            Entry = CxPlatHashtableLookup(SendRingBuffer->SendCompletionTable, (uint32_t)SendRingBuffer->Head, &Context);
        }

        if (SendRingBuffer->Head == SendRingBuffer->Capacity)
        {
            SendRingBuffer->Head = 0;
        }
    }
    else
    {
        RDMA_IO_COMPLETION_BUFFER *buf = CxPlatPoolAlloc(&SendRingBuffer->SendCompletionPool);
        CXPLAT_DBG_ASSERT(buf != NULL);
        
        if (buf == NULL)
        {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        buf->Offset = Offset;
        buf->Length = Length;

        CxPlatHashtableInsert(
            SendRingBuffer->SendCompletionTable,
            &buf->TableEntry,
            (uint32_t)Offset,
            NULL);
    }

    return QUIC_STATUS_SUCCESS;
}

//
// Release Buffer to Receive Ring after Reading the Data
//
QUIC_STATUS
RdmaLocalReceiveRingBufferRelease(
    _In_ RDMA_RECV_RING_BUFFER* RecvRingBuffer,
    _In_ uint8_t* Buffer,
    _In_ uint32_t Offset,
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

    if (Offset == RecvRingBuffer->Head)
    {
        RecvRingBuffer->Head = (RecvRingBuffer->Head + Length);
        RecvRingBuffer->CurSize -= Length;

        CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
        CXPLAT_HASHTABLE_ENTRY* Entry =
        CxPlatHashtableLookup(RecvRingBuffer->RecvCompletionTable, (uint32_t)Offset, &Context);
        while (Entry != NULL)
        {
            RDMA_IO_COMPLETION_BUFFER* buf =
            CXPLAT_CONTAINING_RECORD(Entry, RDMA_IO_COMPLETION_BUFFER, TableEntry);

            memset(RecvRingBuffer->Buffer + buf->Offset, 0, Length);

            RecvRingBuffer->Head = buf->Offset + Length;
            RecvRingBuffer->CurSize -= Length;
            
            Entry = CxPlatHashtableLookup(RecvRingBuffer->RecvCompletionTable, (uint32_t)RecvRingBuffer->Head, &Context);
        }

        if (RecvRingBuffer->Head == RecvRingBuffer->Capacity)
        {
            RecvRingBuffer->Head = 0;
        }
    }
    else
    {
        RDMA_IO_COMPLETION_BUFFER *buf = CxPlatPoolAlloc(&RecvRingBuffer->RecvCompletionPool);
        CXPLAT_DBG_ASSERT(buf != NULL);
        
        if (buf == NULL)
        {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        buf->Offset = Offset;
        buf->Length = Length;

        CxPlatHashtableInsert(
            RecvRingBuffer->RecvCompletionTable,
            &buf->TableEntry,
            (uint32_t)Offset,
            NULL);
    }

    return QUIC_STATUS_SUCCESS;
}

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
    )
{
    if (RemoteRingBuffer == NULL ||
        Length == 0 ||
        RemoteBuffer == NULL ||
        AllocLength == NULL)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    *RemoteBuffer = 0;
    *Offset = 0;
    *AllocLength = 0;

    if (Length > RemoteRingBuffer->Capacity)
    {
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }
    else if (RemoteRingBuffer->CurSize != 0)
    {
        uint32_t AvailableSpace = RemoteRingBuffer->Capacity - RemoteRingBuffer->CurSize;

        if (AvailableSpace < Length)
        {
            //
            // If Head Offset is greater than Tail Offset, then
            // return error since it cannot wrap around the buffer
            //
            if (RemoteRingBuffer->Head >= RemoteRingBuffer->Tail)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // In this case, Head Offset is trailing Tail Offset and so it's safe to
            // wrap around 
            //
            RemoteRingBuffer->Tail = 0;
            RemoteRingBuffer->CurSize += RemoteRingBuffer->Capacity - RemoteRingBuffer->CurSize;

            if (RemoteRingBuffer->CurSize == RemoteRingBuffer->Capacity)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }

            //
            // Update Available Space for reserving the memory
            // and check
            //
            AvailableSpace = RemoteRingBuffer->Capacity - RemoteRingBuffer->CurSize;
            if (AvailableSpace < Length)
            {
                return QUIC_STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    *RemoteBuffer = RemoteRingBuffer->RemoteAddress + RemoteRingBuffer->Tail;
    *Offset = RemoteRingBuffer->Tail;
    *AllocLength = Length;

    RemoteRingBuffer->Tail = (RemoteRingBuffer->Tail + Length);
    RemoteRingBuffer->CurSize += Length;

    return QUIC_STATUS_SUCCESS;
}

//
// Release Buffer to Receive Ring after Reading the Data
//
QUIC_STATUS
RdmaRemoteReceiveRingBufferRelease(
    _In_ RDMA_REMOTE_RING_BUFFER* RemoteRingBuffer,
    _In_ uint32_t Length
    )
{
    if (RemoteRingBuffer == NULL ||
        Length == 0 ||
        Length > RemoteRingBuffer->Capacity)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    RemoteRingBuffer->Head += Length;
    RemoteRingBuffer->CurSize -= Length;

    return QUIC_STATUS_SUCCESS;
}