/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The receive buffer is a dynamically sized circular buffer for reassembling
    stream data and holding it until it's delivered to the client.

    When the buffer is resized, all bytes in the buffer are copied to a new
    backing memory of the requested size. The client must keep this in mind and
    only resize the buffer infrequently, for instance by resizing exponentially,
    or try to resize when few bytes are buffered.

    There are two size variables, AllocBufferLength and VirtualBufferLength.
    The first indicates the length of the physical buffer that has been
    allocated. The second indicates the maximum size the physical buffer is
    allowed to grow to. Generally, the physical buffer can stay much smaller
    than the virtual buffer length if the application is draining the data as
    it comes in. Only when data is received faster than the application can
    drain it does the physical buffer start to increase in size to accommodate
    the queued up buffer.

    When physical buffer space runs out, assuming more 'virtual' space is
    available, the physical buffer will be reallocated and copied over.
    Physical buffer space always doubles in size as it grows.

    The VirtualBufferLength is what is used to report the maximum allowed
    stream offset to the peer. Again, if the application drains at a fast
    enough rate compared to the incoming data, then this value can be much
    larger than the physical buffer. This has the effect of being able to
    receive a large buffer (given a flight of packets) but not needed to
    allocate memory for the entire buffer all at once.

    This does expose an attack surface though. In the common case we might be
    able to get by with a smaller buffer, but we need to be careful not to over
    commit. We must always be willing/able to allocate the buffer length
    advertised to the peer.

    Currently, only growing the virtual buffer length is supported.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "recv_buffer.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS // TODO - Can only fail if PreallocatedChunk == NULL
QuicRecvBufferInitialize(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t AllocBufferLength,
    _In_ uint32_t VirtualBufferLength,
    _In_ QUIC_RECV_BUF_MODE RecvMode,
    _In_opt_ QUIC_RECV_CHUNK* PreallocatedChunk
    )
{
    QUIC_STATUS Status;

    CXPLAT_DBG_ASSERT(AllocBufferLength != 0 && (AllocBufferLength & (AllocBufferLength - 1)) == 0);       // Power of 2
    CXPLAT_DBG_ASSERT(VirtualBufferLength != 0 && (VirtualBufferLength & (VirtualBufferLength - 1)) == 0); // Power of 2
    CXPLAT_DBG_ASSERT(AllocBufferLength <= VirtualBufferLength);

    QUIC_RECV_CHUNK* Chunk = NULL;
    if (PreallocatedChunk != NULL) {
        RecvBuffer->PreallocatedChunk = PreallocatedChunk;
        Chunk = PreallocatedChunk;
    } else {
        RecvBuffer->PreallocatedChunk = NULL;
        Chunk = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_RECV_CHUNK) + AllocBufferLength, QUIC_POOL_RECVBUF);
        if (Chunk == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "recv_buffer",
                sizeof(QUIC_RECV_CHUNK) + AllocBufferLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
    }

    QuicRangeInitialize(QUIC_MAX_RANGE_ALLOC_SIZE, &RecvBuffer->WrittenRanges);
    CxPlatListInitializeHead(&RecvBuffer->Chunks);
    CxPlatListInsertHead(&RecvBuffer->Chunks, &Chunk->Link);
    Chunk->AllocLength = AllocBufferLength;
    Chunk->ExternalReference = FALSE;
    RecvBuffer->BaseOffset = 0;
    RecvBuffer->ReadStart = 0;
    RecvBuffer->ReadPendingLength = 0;
    RecvBuffer->ReadLength = 0;
    RecvBuffer->VirtualBufferLength = VirtualBufferLength;
    RecvBuffer->RecvMode = RecvMode;
    Status = QUIC_STATUS_SUCCESS;

Error:

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferUninitialize(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    QuicRangeUninitialize(&RecvBuffer->WrittenRanges);
    while (!CxPlatListIsEmpty(&RecvBuffer->Chunks)) {
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&RecvBuffer->Chunks),
                QUIC_RECV_CHUNK,
                Link);
        if (Chunk != RecvBuffer->PreallocatedChunk) {
            CXPLAT_FREE(Chunk, QUIC_POOL_RECVBUF);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRecvBufferGetTotalLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    uint64_t TotalLength = 0;
    if (QuicRangeGetMaxSafe(&RecvBuffer->WrittenRanges, &TotalLength)) {
        TotalLength++; // Make this the byte AFTER the end.
    }
    CXPLAT_DBG_ASSERT(TotalLength >= RecvBuffer->BaseOffset);
    return TotalLength;
}

//
// Returns the current occupancy of the buffer, including gaps.
//
// This represents the minimum required size of the contiguous backing
// allocation to hold the current bytes.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicRecvBufferGetSpan(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    return (uint32_t)(QuicRecvBufferGetTotalLength(RecvBuffer) - RecvBuffer->BaseOffset);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferHasUnreadData(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    const QUIC_SUBRANGE* FirstRange = QuicRangeGetSafe(&RecvBuffer->WrittenRanges, 0);
    if (FirstRange == NULL || FirstRange->Low != 0) {
        return FALSE;
    }
    CXPLAT_DBG_ASSERT(FirstRange->Count >= RecvBuffer->BaseOffset);
    const uint64_t ContiguousLength = FirstRange->Count - RecvBuffer->BaseOffset;
    return ContiguousLength > RecvBuffer->ReadPendingLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferIncreaseVirtualBufferLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t NewLength
    )
{
    CXPLAT_DBG_ASSERT(NewLength >= RecvBuffer->VirtualBufferLength); // Don't support decrease.
    RecvBuffer->VirtualBufferLength = NewLength;
}

//
// Allocates a new contiguous buffer of the target size. Depending on the
// receive mode and any external references, this may copy the existing buffer,
// or it may simply be used for new data.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferResize(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t TargetBufferLength
    )
{
    CXPLAT_DBG_ASSERT(
        TargetBufferLength != 0 &&
        (TargetBufferLength & (TargetBufferLength - 1)) == 0); // Power of 2
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks)); // Should always have at least one chunk
    QUIC_RECV_CHUNK* LastChunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Blink,
            QUIC_RECV_CHUNK,
            Link);
    CXPLAT_DBG_ASSERT(TargetBufferLength > LastChunk->AllocLength); // Should only be called when buffer needs to grow
    BOOLEAN LastChunkIsFirst = LastChunk->Link.Blink == &RecvBuffer->Chunks;

    QUIC_RECV_CHUNK* NewChunk =
        CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_RECV_CHUNK) + TargetBufferLength, QUIC_POOL_RECVBUF);
    if (NewChunk == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "recv_buffer",
            sizeof(QUIC_RECV_CHUNK) + TargetBufferLength);
        return FALSE;
    }

    NewChunk->AllocLength = TargetBufferLength;
    NewChunk->ExternalReference = FALSE;
    CxPlatListInsertTail(&RecvBuffer->Chunks, &NewChunk->Link);

    if (!LastChunk->ExternalReference) {
        //
        // If the last chunk isn't externally referenced, then we can just
        // replace it with the new chunk.
        //
        if (LastChunkIsFirst) {
            //
            // If it's the first chunk, then the data may not start from the
            // beginning.
            //
            uint32_t Span = QuicRecvBufferGetSpan(RecvBuffer);
            if (Span < LastChunk->AllocLength) {
                Span = LastChunk->AllocLength;
            }
            uint32_t LengthTillWrap = LastChunk->AllocLength - RecvBuffer->ReadStart;
            if (Span <= LengthTillWrap) {
                CxPlatCopyMemory(
                    NewChunk->Buffer,
                    LastChunk->Buffer + RecvBuffer->ReadStart,
                    Span);
            } else {
                CxPlatCopyMemory(
                    NewChunk->Buffer,
                    LastChunk->Buffer + RecvBuffer->ReadStart,
                    LengthTillWrap);
                CxPlatCopyMemory(
                    NewChunk->Buffer + LengthTillWrap,
                    LastChunk->Buffer,
                    Span - LengthTillWrap);
            }
            RecvBuffer->ReadStart = 0;

        } else {
            //
            // If it's not the first chunk, then it always starts from the
            // beginning of the buffer.
            //
            CxPlatCopyMemory(
                NewChunk->Buffer,
                LastChunk->Buffer,
                LastChunk->AllocLength);
        }

        CxPlatListEntryRemove(&LastChunk->Link);
        if (LastChunk != RecvBuffer->PreallocatedChunk) {
            CXPLAT_FREE(LastChunk, QUIC_POOL_RECVBUF);
        }

        return TRUE;
    }

    //
    // If the chunk is already referenced, and if we're in multiple receive
    // mode, we can just add the new chunk to the end of the list. Otherwise,
    // we need to copy the data from the existing chunks into the new chunk.
    //

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        return TRUE;
    }

    //
    // If it's the first chunk, then it may not start from the beginning.
    //
    uint32_t Span = QuicRecvBufferGetSpan(RecvBuffer);
    uint32_t LengthTillWrap = LastChunk->AllocLength - RecvBuffer->ReadStart;
    if (Span <= LengthTillWrap) {
        CxPlatCopyMemory(
            NewChunk->Buffer,
            LastChunk->Buffer + RecvBuffer->ReadStart,
            Span);
    } else {
        CxPlatCopyMemory(
            NewChunk->Buffer,
            LastChunk->Buffer + RecvBuffer->ReadStart,
            LengthTillWrap);
        CxPlatCopyMemory(
            NewChunk->Buffer + LengthTillWrap,
            LastChunk->Buffer,
            Span - LengthTillWrap);
    }
    RecvBuffer->ReadStart = 0;

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicRecvBufferGetTotalAllocLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // In single and circular mode, the last chunk is the only chunk being
        // written to at any given time, and therefore the only chunk we care
        // about in terms of total allocation space.
        //
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Blink,
                QUIC_RECV_CHUNK,
                Link);
        return Chunk->AllocLength;
    }

    //
    // For multiple mode, several chunks may be used at any point in time, so we
    // need to consider the space allocated for all of them. Additionally, the
    // first one is special because it may be used as a circular buffer, and
    // already be partially drained.
    //
    QUIC_RECV_CHUNK* Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    if (Chunk->Link.Flink == &RecvBuffer->Chunks) {
        //
        // Only one chunk means we don't have an artificial "end", and will just
        // write to the whole allocated length.
        //
        return Chunk->AllocLength;
    }

    //
    // When we have additional chunks following this, then its possible part of
    // the first chunk has already been drained, so we don't use the allocated
    // length, but ReadLength instead when calculating total available space.
    //
    uint32_t AllocLength = RecvBuffer->ReadLength;
    while (Chunk->Link.Flink != &RecvBuffer->Chunks) {
        Chunk =
            CXPLAT_CONTAINING_RECORD(
                Chunk->Link.Flink,
                QUIC_RECV_CHUNK,
                Link);
        CXPLAT_DBG_ASSERT((uint64_t)AllocLength + (uint64_t)Chunk->AllocLength < UINT32_MAX);
        AllocLength += Chunk->AllocLength;
    }
    return AllocLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferCopyIntoChunks(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t WriteOffset,
    _In_ uint16_t WriteLength,
    _In_reads_bytes_(WriteLength)
        uint8_t const* WriteBuffer
    )
{
    //
    // Copy the data into the correct chunk(s). In multiple mode this may result
    // in copies to multiple buffers. For single/circular it should always be
    // just a single copy.
    //

    //
    // Adjust the offset, length and buffer to ignore anything before the
    // current base offset.
    //
    if (WriteOffset < RecvBuffer->BaseOffset) {
        CXPLAT_DBG_ASSERT(RecvBuffer->BaseOffset - (uint64_t)WriteOffset < UINT16_MAX);
        uint16_t Diff = (uint16_t)(RecvBuffer->BaseOffset - WriteOffset);
        WriteOffset += Diff;
        WriteLength -= Diff;
        WriteBuffer += Diff;
    }

    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // In single/circular mode we always just write to the last chunk.
        //
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Blink, // Last chunk
                QUIC_RECV_CHUNK,
                Link);
        CXPLAT_DBG_ASSERT(WriteLength <= Chunk->AllocLength); // Should always fit in the last chunk
        uint64_t RelativeOffset = WriteOffset - RecvBuffer->BaseOffset;
        uint32_t ChunkOffset = (RecvBuffer->ReadStart + RelativeOffset) % Chunk->AllocLength;

        if (ChunkOffset + WriteLength > Chunk->AllocLength) {
            uint32_t Part1Len = Chunk->AllocLength - ChunkOffset;
            CxPlatCopyMemory(Chunk->Buffer + ChunkOffset, WriteBuffer, Part1Len);
            CxPlatCopyMemory(Chunk->Buffer, WriteBuffer + Part1Len, WriteLength - Part1Len);
        } else {
            CxPlatCopyMemory(Chunk->Buffer + ChunkOffset, WriteBuffer, WriteLength);
        }

        if (Chunk->Link.Flink == &RecvBuffer->Chunks) {
            RecvBuffer->ReadLength =
                (uint32_t)(QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count - RecvBuffer->BaseOffset);
        }
    } else {
        //
        // In multiple mode we may have to write to multiple (two max) chunks.
        // We need to find the first chunk to start writing at and then
        // continue copying data into the chunks until we run out.
        //
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Flink, // First chunk
                QUIC_RECV_CHUNK,
                Link);
        uint32_t ChunkLength;
        uint32_t ChunkOffset = RecvBuffer->ReadStart;
        uint64_t BaseOffset = RecvBuffer->BaseOffset;
        if (Chunk->Link.Flink == &RecvBuffer->Chunks) {
            CXPLAT_DBG_ASSERT(WriteLength <= Chunk->AllocLength); // Should always fit if we only have one
            ChunkLength = Chunk->AllocLength;
            RecvBuffer->ReadLength =
                (uint32_t)(QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count - RecvBuffer->BaseOffset);
        } else {
            ChunkLength = RecvBuffer->ReadLength;
            while (BaseOffset + ChunkLength <= WriteOffset) {
                BaseOffset += ChunkLength;
                Chunk =
                    CXPLAT_CONTAINING_RECORD(
                        Chunk->Link.Flink,
                        QUIC_RECV_CHUNK,
                        Link);
                ChunkOffset = 0;
                ChunkLength = Chunk->AllocLength;
            }
        }

        do {
            uint64_t RelativeOffset = WriteOffset - BaseOffset;
            uint32_t ChunkWriteOffset = (ChunkOffset + RelativeOffset) % Chunk->AllocLength;
            uint32_t ChunkWriteLength = WriteLength;
            if (ChunkWriteLength > ChunkLength) {
                ChunkWriteLength = ChunkLength;
            }

            if (ChunkWriteOffset + WriteLength > Chunk->AllocLength) {
                uint32_t Part1Len = ChunkLength - ChunkWriteOffset;
                CxPlatCopyMemory(Chunk->Buffer + ChunkWriteOffset, WriteBuffer, Part1Len);
                CxPlatCopyMemory(Chunk->Buffer, WriteBuffer + Part1Len, WriteLength - Part1Len);
            } else {
                CxPlatCopyMemory(Chunk->Buffer + ChunkWriteOffset, WriteBuffer, WriteLength);
            }

            if (WriteLength == ChunkWriteLength) {
                break;
            }
            WriteOffset += ChunkWriteLength;
            WriteLength -= (uint16_t)ChunkWriteLength;
            WriteBuffer += ChunkWriteLength;
            BaseOffset += ChunkLength;
            Chunk =
                CXPLAT_CONTAINING_RECORD(
                    Chunk->Link.Flink,
                    QUIC_RECV_CHUNK,
                    Link);
            ChunkOffset = 0;
            ChunkLength = Chunk->AllocLength;

        } while (TRUE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicRecvBufferWrite(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t WriteOffset,
    _In_ uint16_t WriteLength,
    _In_reads_bytes_(WriteLength) uint8_t const* WriteBuffer,
    _Inout_ uint64_t* WriteLimit,
    _Out_ BOOLEAN* ReadyToRead
    )
{
    CXPLAT_DBG_ASSERT(WriteLength != 0);
    *ReadyToRead = FALSE; // Most cases below aren't ready to read.

    //
    // Check if the write buffer has already been completely written before.
    //
    uint64_t AbsoluteLength = WriteOffset + WriteLength;
    if (AbsoluteLength <= RecvBuffer->BaseOffset) {
        *WriteLimit = 0;
        return QUIC_STATUS_SUCCESS;
    }

    //
    // Check to see if the write buffer is trying to write beyond the virtual
    // allocation limit (i.e. max stream data size).
    //
    if (AbsoluteLength > RecvBuffer->BaseOffset + RecvBuffer->VirtualBufferLength) {
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Check to see if the write buffer is trying to write beyond the allowed
    // (input) limit. If it's in bounds, update the output to indicate how much
    // new data was actually written.
    //
    uint64_t CurrentMaxLength = QuicRecvBufferGetTotalLength(RecvBuffer);
    if (AbsoluteLength > CurrentMaxLength) {
        if (AbsoluteLength - CurrentMaxLength > *WriteLimit) {
            return QUIC_STATUS_BUFFER_TOO_SMALL;
        }
        *WriteLimit = AbsoluteLength - CurrentMaxLength;
    } else {
        *WriteLimit = 0;
    }

    //
    // Check to see if we need to make room for the data we are trying to write.
    //
    // N.B. We do this before updating the written ranges below so we don't have
    // to support rolling back those changes on the possible allocation failure
    // here.
    //
    uint32_t AllocLength = QuicRecvBufferGetTotalAllocLength(RecvBuffer);
    if (AbsoluteLength > RecvBuffer->BaseOffset + AllocLength) {
        //
        // If we don't currently have enough room then we will want to resize
        // the last chunk to be big enough to hold everything. We do this by
        // repeatedly doubling its size until it is large enough.
        //
        uint32_t NewBufferLength =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Blink,
                QUIC_RECV_CHUNK,
                Link)->AllocLength << 1;
        while (AbsoluteLength > RecvBuffer->BaseOffset + NewBufferLength) {
            NewBufferLength <<= 1;
        }
        if (!QuicRecvBufferResize(RecvBuffer, NewBufferLength)) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    //
    // Set the write offset/length as a valid written range.
    //
    BOOLEAN WrittenRangesUpdated;
    QUIC_SUBRANGE* UpdatedRange =
        QuicRangeAddRange(
            &RecvBuffer->WrittenRanges,
            WriteOffset,
            WriteLength,
            &WrittenRangesUpdated);
    if (!UpdatedRange) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "recv_buffer range",
            0);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    if (!WrittenRangesUpdated) {
        //
        // No changes are necessary. Exit immediately.
        //
        return QUIC_STATUS_SUCCESS;
    }

    //
    // We have new data to read if we just wrote to the front of the buffer.
    //
    *ReadyToRead = UpdatedRange->Low == 0;

    //
    // Write the data into the chunks now that everything has been validated.
    //
    QuicRecvBufferCopyIntoChunks(RecvBuffer, WriteOffset, WriteLength, WriteBuffer);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _Out_ uint64_t* BufferOffset,
    _Inout_ uint32_t* BufferCount,
    _Out_writes_all_(*BufferCount)
        QUIC_BUFFER* Buffers
    )
{
    CXPLAT_DBG_ASSERT(QuicRangeGetSafe(&RecvBuffer->WrittenRanges, 0) != NULL); // Only fail if you call read before write indicates read ready.
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks)); // Should always have at least one chunk
    CXPLAT_DBG_ASSERT(
        RecvBuffer->ReadPendingLength == 0 ||
        RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE);
    CXPLAT_DBG_ASSERT(
        RecvBuffer->Chunks.Flink->Flink == &RecvBuffer->Chunks || // Should only have one buffer if not using multiple receive mode
        RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE);

    //
    // Find the length of the data written in the front, after the BaseOffset.
    //
    const QUIC_SUBRANGE* FirstRange = QuicRangeGet(&RecvBuffer->WrittenRanges, 0);
    CXPLAT_DBG_ASSERT(FirstRange->Low == 0 || FirstRange->Count > RecvBuffer->BaseOffset);
    const uint64_t ContiguousLength = FirstRange->Count - RecvBuffer->BaseOffset;

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE) {
        //
        // In single mode, when a read occurs there should be no outstanding
        // reads/refences and only one chunk currently available.
        //
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Flink,
                QUIC_RECV_CHUNK,
                Link);
        CXPLAT_DBG_ASSERT(!Chunk->ExternalReference);
        CXPLAT_DBG_ASSERT(RecvBuffer->ReadStart == 0);
        CXPLAT_DBG_ASSERT(*BufferCount >= 1);
        CXPLAT_DBG_ASSERT(ContiguousLength <= (uint64_t)Chunk->AllocLength);

        *BufferCount = 1;
        *BufferOffset = RecvBuffer->BaseOffset;
        RecvBuffer->ReadPendingLength += ContiguousLength;
        Buffers[0].Length = (uint32_t)ContiguousLength;
        Buffers[0].Buffer = Chunk->Buffer;
        Chunk->ExternalReference = TRUE;

    } else if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_CIRCULAR) {
        //
        // In circular mode, when a read occurs there should be no outstanding
        // reads/refences and only one chunk currently available, but the start
        // offset may not be 0, so we may have to return it as two buffers.
        //
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Flink,
                QUIC_RECV_CHUNK,
                Link);
        CXPLAT_DBG_ASSERT(!Chunk->ExternalReference);
        CXPLAT_DBG_ASSERT(*BufferCount >= 2);
        CXPLAT_DBG_ASSERT(ContiguousLength <= (uint64_t)Chunk->AllocLength);

        *BufferOffset = RecvBuffer->BaseOffset;
        RecvBuffer->ReadPendingLength += ContiguousLength;
        Chunk->ExternalReference = TRUE;

        const uint64_t ReadStart = RecvBuffer->ReadStart;
        if (ReadStart + ContiguousLength > (uint64_t)Chunk->AllocLength) {
            *BufferCount = 2; // Circular buffer wrap around case.
            Buffers[0].Length = (uint32_t)(Chunk->AllocLength - ReadStart);
            Buffers[0].Buffer = Chunk->Buffer + ReadStart;
            Buffers[1].Length = (uint32_t)ContiguousLength - Buffers[0].Length;
            Buffers[1].Buffer = Chunk->Buffer;
        } else {
            *BufferCount = 1;
            Buffers[0].Length = (uint32_t)ContiguousLength;
            Buffers[0].Buffer = Chunk->Buffer + ReadStart;
        }

    } else {
        CXPLAT_DBG_ASSERT(RecvBuffer->ReadPendingLength < ContiguousLength); // Shouldn't call read if there is nothing new to read
        uint64_t WrittenLength = ContiguousLength - RecvBuffer->ReadPendingLength;

        //
        // Walk the chunks to find the data after ReadPendingLength, up to
        // WrittenLength, to return.
        //
        uint64_t ReadOffset = RecvBuffer->ReadPendingLength;
        QUIC_RECV_CHUNK* Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Flink,
                QUIC_RECV_CHUNK,
                Link);
        BOOLEAN IsFirstChunk = TRUE;
        uint32_t ChunkLength = RecvBuffer->ReadLength;
        while (ChunkLength <= ReadOffset) {
            CXPLAT_DBG_ASSERT(ChunkLength);
            CXPLAT_DBG_ASSERT(Chunk->ExternalReference);
            CXPLAT_DBG_ASSERT(Chunk->Link.Flink != &RecvBuffer->Chunks);
            ReadOffset -= ChunkLength;
            IsFirstChunk = FALSE;
            Chunk =
                CXPLAT_CONTAINING_RECORD(
                    Chunk->Link.Flink,
                    QUIC_RECV_CHUNK,
                    Link);
            ChunkLength = Chunk->AllocLength;
        }
        CXPLAT_DBG_ASSERT(*BufferCount >= 3);
        CXPLAT_DBG_ASSERT(ReadOffset <= UINT32_MAX);

        if (IsFirstChunk) {
            //
            // Only the first chunk may be used in a circular buffer fashion and
            // therefore use the RecvBuffer->ReadStart offset.
            //
            ChunkLength = RecvBuffer->ReadLength - (uint32_t)ReadOffset;
            ReadOffset = (RecvBuffer->ReadStart + ReadOffset) % Chunk->AllocLength;
            CXPLAT_DBG_ASSERT(ChunkLength <= WrittenLength);
        } else {
            //
            // Subsequent chunks do not use ReadStart or ReadLength, so we start
            // with a chunk length up to the entire length of the chunk.
            //
            ChunkLength = Chunk->AllocLength - (uint32_t)ReadOffset;
            if (ChunkLength > WrittenLength) {
                ChunkLength = (uint32_t)WrittenLength;
            }
        }

        CXPLAT_DBG_ASSERT(ChunkLength <= Chunk->AllocLength);
        if (ReadOffset + ChunkLength > Chunk->AllocLength) {
            *BufferCount = 2; // Circular buffer wrap around case.
            Buffers[0].Length = (uint32_t)(Chunk->AllocLength - ReadOffset);
            Buffers[0].Buffer = Chunk->Buffer + ReadOffset;
            Buffers[1].Length = ChunkLength - Buffers[0].Length;
            Buffers[1].Buffer = Chunk->Buffer;

        } else {
            *BufferCount = 1;
            Buffers[0].Length = ChunkLength;
            Buffers[0].Buffer = Chunk->Buffer + ReadOffset;
        }
        Chunk->ExternalReference = TRUE;

        if (WrittenLength > ChunkLength) {
            CXPLAT_DBG_ASSERT(Chunk->Link.Flink != &RecvBuffer->Chunks); // There must be another chunk to read from
            WrittenLength -= ChunkLength;
            Chunk =
                CXPLAT_CONTAINING_RECORD(
                    Chunk->Link.Flink,
                    QUIC_RECV_CHUNK,
                    Link);
            CXPLAT_DBG_ASSERT(WrittenLength <= Chunk->AllocLength); // Shouldn't be able to read more than the chunk size
            Buffers[*BufferCount].Length = (uint32_t)WrittenLength;
            Buffers[*BufferCount].Buffer = Chunk->Buffer;
            *BufferCount = *BufferCount + 1;
            Chunk->ExternalReference = TRUE;
        }

        *BufferOffset = RecvBuffer->BaseOffset + RecvBuffer->ReadPendingLength;
        RecvBuffer->ReadPendingLength += WrittenLength;
    }
}

//
// Handles draining just part of the first chunk.
//
void
QuicRecvBufferPartialDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t DrainLength
    )
{
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));
    QUIC_RECV_CHUNK* Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    CXPLAT_DBG_ASSERT(Chunk->ExternalReference);

    if (Chunk->Link.Flink != &RecvBuffer->Chunks &&
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // In single/circular mode, if there is another chunk, then that means
        // we no longer need this chunk at all because the other chunk contains
        // a copy of all this data already. Free this one and continue
        // operating on the next one.
        //
        CxPlatListEntryRemove(&Chunk->Link);
        if (Chunk != RecvBuffer->PreallocatedChunk) {
            CXPLAT_FREE(Chunk, QUIC_POOL_RECVBUF);
        }

        CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));
        Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Flink,
                QUIC_RECV_CHUNK,
                Link);
        CXPLAT_DBG_ASSERT(!Chunk->ExternalReference);
        RecvBuffer->ReadStart = 0;
    }

    RecvBuffer->BaseOffset += DrainLength;
    if (DrainLength != 0) {
        if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE) {
            CXPLAT_DBG_ASSERT(RecvBuffer->ReadStart == 0);
            //
            // In single mode, we need to keep any remaining bytes at the front
            // of the buffer, so copy remaining bytes in the buffer to the
            // beginning.
            //
            CxPlatMoveMemory(
                Chunk->Buffer,
                Chunk->Buffer + DrainLength,
                (size_t)(Chunk->AllocLength - (uint32_t)DrainLength)); // TODO - Might be able to copy less than the full alloc length

        } else { // Circular and multiple mode.
            //
            // Increment the buffer start, making sure to account for circular
            // buffer wrap around.
            //
            RecvBuffer->ReadStart =
                (uint32_t)((RecvBuffer->ReadStart + DrainLength) % Chunk->AllocLength);
        }

        RecvBuffer->ReadLength -= (uint32_t)DrainLength;
    }

    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // Unless we are in multiple mode, a partial drain means the app isn't
        // referencing any chunks anymore.
        //
        Chunk->ExternalReference = FALSE;
    }
}

//
// Handles draining the entire first chunk (and possibly more). Return the new
// drain length.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicRecvBufferFullDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t DrainLength
    )
{
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));
    QUIC_RECV_CHUNK* Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    CXPLAT_DBG_ASSERT(Chunk->ExternalReference);

    Chunk->ExternalReference = FALSE;
    DrainLength -= RecvBuffer->ReadLength;
    RecvBuffer->ReadStart = 0;
    RecvBuffer->BaseOffset += RecvBuffer->ReadLength;
    RecvBuffer->ReadLength =
        (uint32_t)(QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count - RecvBuffer->BaseOffset);

    if (Chunk->Link.Flink == &RecvBuffer->Chunks) {
        //
        // No more chunks to drain, so we should also be out of buffer length
        // to drain too. Return TRUE to indicate all data has been drained.
        //
        CXPLAT_FRE_ASSERTMSG(DrainLength == 0, "App drained more than was available!");
        CXPLAT_DBG_ASSERT(RecvBuffer->ReadLength == 0);
        return 0;
    }

    //
    // Cleanup the chunk that was just drained.
    //
    CxPlatListEntryRemove(&Chunk->Link);
    if (Chunk != RecvBuffer->PreallocatedChunk) {
        CXPLAT_FREE(Chunk, QUIC_POOL_RECVBUF);
    }

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // The rest of the contiguous data might not fit in just the next chunk
        // so we need to update the ReadLength of the first chunk to be no more
        // than the next chunk's allocation length.
        //
        Chunk =
            CXPLAT_CONTAINING_RECORD(
                RecvBuffer->Chunks.Flink,
                QUIC_RECV_CHUNK,
                Link);
        if (Chunk->AllocLength < RecvBuffer->ReadLength) {
            RecvBuffer->ReadLength = Chunk->AllocLength;
        }
    }

    return DrainLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t DrainLength
    )
{
    CXPLAT_DBG_ASSERT(DrainLength <= RecvBuffer->ReadPendingLength);
    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        RecvBuffer->ReadPendingLength = 0;
    } else {
        RecvBuffer->ReadPendingLength -= DrainLength;
    }

    do {
        if ((uint64_t)RecvBuffer->ReadLength > DrainLength) {
            QuicRecvBufferPartialDrain(RecvBuffer, DrainLength);
            return FALSE;
        }

        DrainLength = QuicRecvBufferFullDrain(RecvBuffer, DrainLength);
    } while (DrainLength != 0);

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferResetRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    CXPLAT_DBG_ASSERT(RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE);
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));
    QUIC_RECV_CHUNK* Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    Chunk->ExternalReference = FALSE;
    RecvBuffer->ReadPendingLength = 0;
}
