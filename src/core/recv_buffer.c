/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The receive buffer is a dynamically sized circular buffer for reassembling
    stream data and holding it until it's delivered to the client.

    It is implemented as a linked list of buffers to allow for different
    behaviors (modes) when managing memory.

    There are two size variables, AllocBufferLength and VirtualBufferLength.
    The first indicates the length of the physical buffer that has been
    allocated. The second indicates the maximum size the physical buffer is
    allowed to grow to. Generally, the physical buffer can stay much smaller
    than the virtual buffer length if the application is draining the data as
    it comes in. Only when data is received faster than the application can
    drain it does the physical buffer start to increase in size to accommodate
    the queued up buffer.

    When physical buffer space runs out, assuming more 'virtual' space is
    available, the physical buffer will be reallocated and may be copied over.
    Physical buffer space always doubles in size as it grows.

    The VirtualBufferLength is what is used to report the maximum allowed
    stream offset to the peer. Again, if the application drains at a fast
    enough rate compared to the incoming data, then this value can be much
    larger than the physical buffer. This has the effect of being able to
    receive a large buffer (given a flight of packets) but not need to
    allocate memory for the entire buffer all at once.

    This does expose an attack surface though. In the common case we might be
    able to get by with a smaller buffer, but we need to be careful not to over
    commit. We must always be willing/able to allocate the buffer length
    advertised to the peer.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "recv_buffer.c.clog.h"
#endif

typedef struct QUIC_RECV_CHUNK_ITERATOR {
    QUIC_RECV_CHUNK* CurrentChunk;
    CXPLAT_LIST_ENTRY* IteratorEnd;
    uint32_t StartOffset; // Offset of the first byte to read in the current chunk.
    uint32_t EndOffset;   // Offset of the last byte to read in the current chunk (inclusive!).
} QUIC_RECV_CHUNK_ITERATOR;

//
// Create an iterator over the receive buffer chunks, skipping `Offset` bytes from `ReadStart`.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_RECV_CHUNK_ITERATOR
QuicRecvBufferGetChunkIterator(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t Offset
    )
{
    QUIC_RECV_CHUNK_ITERATOR Iterator = { 0 };
    Iterator.CurrentChunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    Iterator.IteratorEnd = &RecvBuffer->Chunks;

    if (Offset < RecvBuffer->Capacity) {
        //
        // The offset is in the first chunk. Make sure to handle a wrap-around.
        //
        Iterator.StartOffset =
            (RecvBuffer->ReadStart + Offset) % Iterator.CurrentChunk->AllocLength;
        Iterator.EndOffset =
            (RecvBuffer->ReadStart + RecvBuffer->Capacity - 1) % Iterator.CurrentChunk->AllocLength;
        return Iterator;
    }

    //
    // Walk through chunks to skip the offset.
    //
    Offset -= RecvBuffer->Capacity;
    Iterator.CurrentChunk =
        CXPLAT_CONTAINING_RECORD(
            Iterator.CurrentChunk->Link.Flink,
            QUIC_RECV_CHUNK,
            Link);
    while (Offset >= Iterator.CurrentChunk->AllocLength) {
        CXPLAT_DBG_ASSERT(Iterator.CurrentChunk->Link.Flink != &RecvBuffer->Chunks);
        Offset -= Iterator.CurrentChunk->AllocLength;
        Iterator.CurrentChunk =
            CXPLAT_CONTAINING_RECORD(
                Iterator.CurrentChunk->Link.Flink,
                QUIC_RECV_CHUNK,
                Link);
    }
    Iterator.StartOffset = (uint32_t)Offset;
    Iterator.EndOffset = Iterator.CurrentChunk->AllocLength - 1;

    return Iterator;
}

//
// Provides the next contiguous span of data in the chunk list.
// Return FALSE if there is no data to read anymore.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return == TRUE)
BOOLEAN
QuicRecvChunkIteratorNext(
    _Inout_ QUIC_RECV_CHUNK_ITERATOR* Iterator,
    _In_ BOOLEAN ReferenceChunk,
    _Out_ QUIC_BUFFER* Buffer
    )
{
    if (Iterator->CurrentChunk == NULL) {
        return FALSE;
    }

    if (ReferenceChunk) {
        Iterator->CurrentChunk->ExternalReference = TRUE;
    }

    Buffer->Buffer = Iterator->CurrentChunk->Buffer + Iterator->StartOffset;

    if (Iterator->StartOffset > Iterator->EndOffset) {
        Buffer->Length = Iterator->CurrentChunk->AllocLength - Iterator->StartOffset;
        //
        // Wrap around case - next buffer start from the beginning of the chunk.
        //
        Iterator->StartOffset = 0;
    } else {
        Buffer->Length = Iterator->EndOffset - Iterator->StartOffset + 1;

        if (Iterator->CurrentChunk->Link.Flink == Iterator->IteratorEnd) {
            //
            // No more chunks to iterate over.
            //
            Iterator->CurrentChunk = NULL;
            return TRUE;
        }

        //
        // Move to the next chunk.
        //
        Iterator->CurrentChunk =
            CXPLAT_CONTAINING_RECORD(
                Iterator->CurrentChunk->Link.Flink,
                QUIC_RECV_CHUNK,
                Link);
        Iterator->StartOffset = 0;
        Iterator->EndOffset = Iterator->CurrentChunk->AllocLength - 1;
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvChunkInitialize(
    _Inout_ QUIC_RECV_CHUNK* Chunk,
    _In_ uint32_t AllocLength,
    _Inout_updates_(AllocLength) uint8_t* Buffer,
    _In_ BOOLEAN AppOwnedBuffer
    )
{
    Chunk->AllocLength = AllocLength;
    Chunk->Buffer = Buffer;
    Chunk->ExternalReference = FALSE;
    Chunk->AppOwnedBuffer = AppOwnedBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvChunkFree(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ QUIC_RECV_CHUNK* Chunk
    )
{
    if (Chunk == RecvBuffer->PreallocatedChunk) {
        return;
    }

    if (Chunk->AppOwnedBuffer) {
        CxPlatPoolFree(Chunk);
    } else {
        CXPLAT_FREE(Chunk, QUIC_POOL_RECVBUF);
    }
}

#if DEBUG
//
// Validate the receive buffer invariants.
// No-op in release builds.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferValidate(
    _In_ const QUIC_RECV_BUFFER* RecvBuffer
    )
{
    QUIC_RECV_CHUNK* FirstChunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);

    //
    // In Single and Circular modes, there is only ever one chunk in the list.
    //
    CXPLAT_DBG_ASSERT(
        (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_SINGLE &&
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_CIRCULAR) ||
        FirstChunk->Link.Flink == &RecvBuffer->Chunks);

    //
    // In Multiple and App-owned modes, there never is a retired buffer.
    //
    CXPLAT_DBG_ASSERT(
        (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE &&
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED) ||
        RecvBuffer->RetiredChunk == NULL);

    //
    // In Single mode, data always starts from the beginning of the chunk.
    //
    CXPLAT_DBG_ASSERT(
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_SINGLE ||
        RecvBuffer->ReadStart == 0);

    //
    // In Single and App-owned modes, the first chunk is never used in a circular way.
    //
    CXPLAT_DBG_ASSERT(
        (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_SINGLE &&
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED) ||
        RecvBuffer->ReadStart + RecvBuffer->ReadLength <= FirstChunk->AllocLength);

    //
    // There can be a retired chunk only when a read is pending.
    //
    CXPLAT_DBG_ASSERT(RecvBuffer->RetiredChunk == NULL || RecvBuffer->ReadPendingLength != 0);
}
#else
#define QuicRecvBufferValidate(RecvBuffer)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferInitialize(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t AllocBufferLength,
    _In_ uint32_t VirtualBufferLength,
    _In_ QUIC_RECV_BUF_MODE RecvMode,
    _In_opt_ QUIC_RECV_CHUNK* PreallocatedChunk
    )
{
    CXPLAT_DBG_ASSERT(AllocBufferLength != 0 || RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED);
    CXPLAT_DBG_ASSERT(VirtualBufferLength != 0 || RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED);
    CXPLAT_DBG_ASSERT((AllocBufferLength & (AllocBufferLength - 1)) == 0);     // Power of 2
    CXPLAT_DBG_ASSERT((VirtualBufferLength & (VirtualBufferLength - 1)) == 0); // Power of 2
    CXPLAT_DBG_ASSERT(AllocBufferLength <= VirtualBufferLength);

    RecvBuffer->BaseOffset = 0;
    RecvBuffer->ReadStart = 0;
    RecvBuffer->ReadPendingLength = 0;
    RecvBuffer->ReadLength = 0;
    RecvBuffer->RecvMode = RecvMode;
    RecvBuffer->PreallocatedChunk = PreallocatedChunk;
    RecvBuffer->RetiredChunk = NULL;
    QuicRangeInitialize(QUIC_MAX_RANGE_ALLOC_SIZE, &RecvBuffer->WrittenRanges);
    CxPlatListInitializeHead(&RecvBuffer->Chunks);

    if (RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED) {
        //
        // Setup an initial chunk.
        //
        QUIC_RECV_CHUNK* Chunk = NULL;
        if (PreallocatedChunk != NULL) {
            Chunk = PreallocatedChunk;
        } else {
            Chunk = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_RECV_CHUNK) + AllocBufferLength, QUIC_POOL_RECVBUF);
            if (Chunk == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "recv_buffer",
                    sizeof(QUIC_RECV_CHUNK) + AllocBufferLength);
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            QuicRecvChunkInitialize(Chunk, AllocBufferLength, (uint8_t*)(Chunk + 1), FALSE);
        }
        CxPlatListInsertHead(&RecvBuffer->Chunks, &Chunk->Link);
        RecvBuffer->Capacity = AllocBufferLength;
        RecvBuffer->VirtualBufferLength = VirtualBufferLength;
    } else {
        RecvBuffer->Capacity = 0;
        RecvBuffer->VirtualBufferLength = 0;
    }

    return QUIC_STATUS_SUCCESS;
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
        QuicRecvChunkFree(RecvBuffer, Chunk);
    }

    if (RecvBuffer->RetiredChunk != NULL) {
        QuicRecvChunkFree(RecvBuffer, RecvBuffer->RetiredChunk);
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
    CXPLAT_DBG_ASSERT(RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED);
    CXPLAT_DBG_ASSERT(NewLength >= RecvBuffer->VirtualBufferLength); // Don't support decrease.
    RecvBuffer->VirtualBufferLength = NewLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferProvideChunks(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _Inout_ CXPLAT_LIST_ENTRY* /* QUIC_RECV_CHUNKS */ Chunks
    )
{
    CXPLAT_DBG_ASSERT(RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED);
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(Chunks));

    uint64_t NewBufferLength = RecvBuffer->VirtualBufferLength;
    for (CXPLAT_LIST_ENTRY* Link = Chunks->Flink;
         Link != Chunks;
         Link = Link->Flink) {
        QUIC_RECV_CHUNK* Chunk = CXPLAT_CONTAINING_RECORD(Link, QUIC_RECV_CHUNK, Link);
        NewBufferLength += Chunk->AllocLength;
    }

    if (NewBufferLength > UINT32_MAX) {
        //
        // We can't handle that much buffer space.
        //
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CxPlatListIsEmpty(&RecvBuffer->Chunks)) {
        //
        // If a new chunk becomes the first chunk, update the capacity.
        //
        CXPLAT_DBG_ASSERT(RecvBuffer->ReadStart == 0);
        CXPLAT_DBG_ASSERT(RecvBuffer->ReadLength == 0);
        QUIC_RECV_CHUNK* FirstChunk = CXPLAT_CONTAINING_RECORD(Chunks->Flink, QUIC_RECV_CHUNK, Link);
        RecvBuffer->Capacity = FirstChunk->AllocLength;
    }

    RecvBuffer->VirtualBufferLength = (uint32_t)NewBufferLength;
    CxPlatListMoveItems(Chunks, &RecvBuffer->Chunks);

    return QUIC_STATUS_SUCCESS;
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
    CXPLAT_DBG_ASSERTMSG(
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED,
        "Should never resize in App-owned mode");
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

    QuicRecvChunkInitialize(NewChunk, TargetBufferLength, (uint8_t*)(NewChunk + 1), FALSE);
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
            CXPLAT_DBG_ASSERT(NewChunk->AllocLength == TargetBufferLength);
            RecvBuffer->Capacity = NewChunk->AllocLength;

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
        QuicRecvChunkFree(RecvBuffer, LastChunk);

        return TRUE;
    }

    //
    // If the chunk is already referenced, and if we're in multiple receive
    // mode, we can just add the new chunk to the end of the list.
    //
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        return TRUE;
    }

    //
    // Otherwise, we need to copy the data from the existing chunk
    // into the new chunk, and retire the existing chunk until we can free it.
    //

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
    RecvBuffer->Capacity = NewChunk->AllocLength;
    CxPlatListEntryRemove(&LastChunk->Link);
    CXPLAT_DBG_ASSERT(RecvBuffer->RetiredChunk == NULL);
    RecvBuffer->RetiredChunk = LastChunk;

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicRecvBufferGetTotalAllocLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE ||
        RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_CIRCULAR) {
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
    // For multiple mode and app-owned mode, several chunks may be used at any
    // point in time, so we need to consider the space allocated for all of them.
    // Additionally, the first one is special because it may be already partially
    // drained, making it only partially usable.
    //
    QUIC_RECV_CHUNK* Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE &&
        Chunk->Link.Flink == &RecvBuffer->Chunks) {
        //
        // In Multiple mode, only one chunk means we don't have an artificial
        // "end", and are using the full allocated length of the buffer in a
        // circular fashion.
        //
        return Chunk->AllocLength;
    }

    //
    // Otherwise, it is possible part of the first chunk has already been
    // drained, so we don't use the allocated length, but the Capacity instead
    // when calculating total available space.
    //
    uint32_t AllocLength = RecvBuffer->Capacity;
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
    // Copy the data into the correct chunk(s).
    // The caller is resonsible for ensuring there is enough space for the copy.
    // In single/circular modes, data will always be copied to a single chunk.
    // In multiple/app-owned mode this may result in copies to multiple chunks.
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

    const uint64_t RelativeOffset = WriteOffset - RecvBuffer->BaseOffset;

    //
    // Iterate over the list of chunk, copying the data.
    //
    QUIC_RECV_CHUNK_ITERATOR Iterator = QuicRecvBufferGetChunkIterator(RecvBuffer, RelativeOffset);
    QUIC_BUFFER Buffer;
    while (WriteLength != 0 && QuicRecvChunkIteratorNext(&Iterator, FALSE, &Buffer)) {
        const uint32_t CopyLength = CXPLAT_MIN(Buffer.Length, WriteLength);
        CxPlatCopyMemory(Buffer.Buffer, WriteBuffer, CopyLength);
        WriteBuffer += CopyLength;
        WriteLength -= (uint16_t)CopyLength;
    }
    CXPLAT_DBG_ASSERT(WriteLength == 0); // Should always have enough room to copy everything

    //
    // Update the amount of data readable in the first chunk.
    //
    QUIC_SUBRANGE* FirstRange = QuicRangeGet(&RecvBuffer->WrittenRanges, 0);
    if (FirstRange->Low == 0) {
        RecvBuffer->ReadLength = (uint32_t)CXPLAT_MIN(
            RecvBuffer->Capacity,
            FirstRange->Count - RecvBuffer->BaseOffset);
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
    // This is skipped in app-owned mode since the entire virtual length is
    // always allocated.
    //
    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED) {
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

    QuicRecvBufferValidate(RecvBuffer);
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicRecvBufferReadBufferNeededCount(
    _In_ const QUIC_RECV_BUFFER* RecvBuffer
    )
{
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE) {
        //
        // Single mode only ever need one buffer, that's what it's designed for.
        //
        return 1;
    }

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_CIRCULAR) {
        //
        // Circular mode need up to two buffers to deal with wrap around.
        //
        return 2;
    }

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // Multiple mode need up to three buffers to deal with wrap around and a
        // potential second chunk for overflow data.
        //
        return 3;
    }

    //
    // RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED
    // App-owned mode can need any number of buffer, we must count.
    //

    //
    // Determine how much data is readable
    //
    const QUIC_SUBRANGE* FirstRange = QuicRangeGetSafe(&RecvBuffer->WrittenRanges, 0);
    if (!FirstRange || FirstRange->Low != 0) {
        return 0;
    }
    const uint64_t ReadableData = FirstRange->Count - RecvBuffer->BaseOffset;

    //
    // Iterate through the chunks until they can contain all the readable data,
    // to find the number of buffers needed.
    //
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));
    QUIC_RECV_CHUNK* Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    uint32_t DataInChunks = RecvBuffer->Capacity;
    uint32_t BufferCount = 1;

    while (ReadableData > DataInChunks) {
        Chunk =
            CXPLAT_CONTAINING_RECORD(
                Chunk->Link.Flink,
                QUIC_RECV_CHUNK,
                Link);
        DataInChunks += Chunk->AllocLength;
        BufferCount++;
    }
    return BufferCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _Out_ uint64_t* BufferOffset,
    _Inout_ uint32_t* BufferCount,
    _Out_writes_to_(*BufferCount, *BufferCount)
        QUIC_BUFFER* Buffers
    )
{
    CXPLAT_DBG_ASSERT(QuicRangeGetSafe(&RecvBuffer->WrittenRanges, 0) != NULL); // Only fail if you call read before write indicates read ready.
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks)); // Should always have at least one chunk
    //
    // Only multiple mode allows concurrent reads
    //
    CXPLAT_DBG_ASSERT(
        RecvBuffer->ReadPendingLength == 0 ||
        RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE);

    //
    // Find the length of the data written in the front, after the BaseOffset.
    //
    const QUIC_SUBRANGE* FirstRange = QuicRangeGet(&RecvBuffer->WrittenRanges, 0);
    CXPLAT_DBG_ASSERT(FirstRange->Low == 0 || FirstRange->Count > RecvBuffer->BaseOffset);
    const uint64_t ContiguousLength = FirstRange->Count - RecvBuffer->BaseOffset;

    //
    // Iterate over the chunks, reading as much data as possible.
    //
    QUIC_RECV_CHUNK_ITERATOR Iterator =
        QuicRecvBufferGetChunkIterator(RecvBuffer, RecvBuffer->ReadPendingLength);
    uint64_t ReadableDataLeft = ContiguousLength - RecvBuffer->ReadPendingLength;
    uint32_t CurrentBufferId = 0;
    while (CurrentBufferId < *BufferCount &&
            ReadableDataLeft > 0 &&
            QuicRecvChunkIteratorNext(&Iterator, TRUE, &Buffers[CurrentBufferId])) {
        if (Buffers[CurrentBufferId].Length > ReadableDataLeft) {
            Buffers[CurrentBufferId].Length = (uint32_t)ReadableDataLeft;
        }
        ReadableDataLeft -= Buffers[CurrentBufferId].Length;
        CurrentBufferId++;
    }
    *BufferCount = CurrentBufferId;
    *BufferOffset = RecvBuffer->BaseOffset + RecvBuffer->ReadPendingLength;
    RecvBuffer->ReadPendingLength = ContiguousLength - ReadableDataLeft;

    //
    // Check that the invariants on the number of receive buffer are respected.
    //
    CXPLAT_DBG_ASSERT(
        RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED || ReadableDataLeft == 0);
    CXPLAT_DBG_ASSERT(
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_SINGLE || *BufferCount <= 1);
    CXPLAT_DBG_ASSERT(
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_CIRCULAR || *BufferCount <= 2);
    CXPLAT_DBG_ASSERT(
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE || *BufferCount <= 3);

    QuicRecvBufferValidate(RecvBuffer);
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

        } else { // Circular, multiple and app-owned mode.
            //
            // Increment the buffer start, making sure to account for circular
            // buffer wrap around.
            //
            RecvBuffer->ReadStart =
                (uint32_t)((RecvBuffer->ReadStart + DrainLength) % Chunk->AllocLength);
            if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED ||
                Chunk->Link.Flink != &RecvBuffer->Chunks) {
                //
                // Shrink the capacity of the first chunk in app-owned mode or
                // if there is another chunk (in which case we want to progressively
                // get rid of the first chunk).
                //
                CXPLAT_DBG_ASSERT(
                    RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE ||
                    RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED);
                RecvBuffer->Capacity -= (uint32_t)DrainLength;
            }
        }

        CXPLAT_DBG_ASSERT(RecvBuffer->ReadLength >= (uint32_t)DrainLength);
        RecvBuffer->ReadLength -= (uint32_t)DrainLength;
    }

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // If all ReadPending data is drained, then we can release the external reference.
        //
        Chunk->ExternalReference = RecvBuffer->ReadPendingLength != DrainLength;
        CXPLAT_DBG_ASSERT(DrainLength <= RecvBuffer->ReadPendingLength);
        RecvBuffer->ReadPendingLength -= DrainLength;
    } else if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED) {
        //
        // In app-owned mode, memory is never re-used: a drain consumes
        // virtual buffer length.
        //
        CXPLAT_DBG_ASSERT(RecvBuffer->VirtualBufferLength >= (uint32_t)DrainLength);
        RecvBuffer->VirtualBufferLength -= (uint32_t)DrainLength;
    }
}

//
// Handles draining the entire first chunk (and possibly more). This function
// expects the chunk to not contain more (unread) data. Return the new
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

    DrainLength -= RecvBuffer->ReadLength;
    RecvBuffer->ReadStart = 0;
    RecvBuffer->BaseOffset += RecvBuffer->ReadLength;
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        Chunk->ExternalReference = FALSE;
        RecvBuffer->ReadPendingLength -= RecvBuffer->ReadLength;
    }
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED) {
        //
        // In app-owned mode, memory is never re-used: a drain consumes
        // virtual buffer length.
        //
        RecvBuffer->VirtualBufferLength -= RecvBuffer->ReadLength;
    }
    RecvBuffer->ReadLength =
        (uint32_t)(QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count - RecvBuffer->BaseOffset);

    if (Chunk->Link.Flink == &RecvBuffer->Chunks) {
        //
        // We are completely draining the last chunk we have: ensure we are not
        // requested to drain more.
        //
        CXPLAT_FRE_ASSERTMSG(DrainLength == 0, "App drained more than was available!");
        CXPLAT_DBG_ASSERT(RecvBuffer->ReadLength == 0);

        if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED) {
            //
            // In app-owned mode, chunks are never re-used: free the last chunk.
            //
            CxPlatListEntryRemove(&Chunk->Link);
            QuicRecvChunkFree(RecvBuffer, Chunk);
            RecvBuffer->Capacity = 0;
        }

        return 0;
    }

    CXPLAT_DBG_ASSERT(RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE ||
                      RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED);
    //
    // We have more chunks and just drained this one completely: we are never
    // going to re-use this one. Free it.
    //
    CxPlatListEntryRemove(&Chunk->Link);
    QuicRecvChunkFree(RecvBuffer, Chunk);

    //
    // The rest of the contiguous data might not fit in just the next chunk
    // so we need to update the ReadLength of the first chunk to be no more
    // than the next chunk's allocation length.
    // Capacity is also updated to reflect the new first chunk's allocation length.
    //
    // Update the ReadLength and Capacity to match the new first chunk.
    //
    Chunk =
        CXPLAT_CONTAINING_RECORD(
            RecvBuffer->Chunks.Flink,
            QUIC_RECV_CHUNK,
            Link);
    RecvBuffer->Capacity = Chunk->AllocLength;
    if (Chunk->AllocLength < RecvBuffer->ReadLength) {
        RecvBuffer->ReadLength = Chunk->AllocLength;
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

    //
    // Free the retired chunk, now that it is no longer referenced.
    //
    if (RecvBuffer->RetiredChunk != NULL) {
        CXPLAT_DBG_ASSERT(
            RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE ||
            RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_CIRCULAR);

        QuicRecvChunkFree(RecvBuffer, RecvBuffer->RetiredChunk);
        RecvBuffer->RetiredChunk = NULL;
    }

    //
    // Mark chunks as no longer externally referenced and reset the read-pending data length.
    // For Multiple mode, this is done when each chunk is drained.
    //
    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        for (CXPLAT_LIST_ENTRY* Link = RecvBuffer->Chunks.Flink;
            Link != &RecvBuffer->Chunks;
            Link = Link->Flink) {
            QUIC_RECV_CHUNK* Chunk =
                CXPLAT_CONTAINING_RECORD(Link, QUIC_RECV_CHUNK, Link);
            Chunk->ExternalReference = FALSE;
        }
        RecvBuffer->ReadPendingLength = 0;
    }

    QUIC_SUBRANGE* FirstRange = QuicRangeGet(&RecvBuffer->WrittenRanges, 0);
    CXPLAT_DBG_ASSERT(FirstRange);
    CXPLAT_DBG_ASSERT(FirstRange->Low == 0);
    do {
        //
        // Whether all the available data has been drained or more is readily available.
        //
        BOOLEAN MoreDataReadable = (uint64_t)RecvBuffer->ReadLength > DrainLength;
        BOOLEAN GapInChunk = QuicRangeSize(&RecvBuffer->WrittenRanges) > 1 &&
                RecvBuffer->BaseOffset + RecvBuffer->ReadLength == FirstRange->Count;

        //
        // In single/circular mode, a full drain must be done only all the data
        // written in the buffer got read.
        // A partial drain is done if not all the readily readable data was read
        // or if the read is limited by a gap in the data.
        //
        BOOLEAN PartialDrain = MoreDataReadable || GapInChunk;
        if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
            //
            // In addition to the above, in multiple mode, a chunk must be fully
            // drained if its capacity is entirely consumed.
            //
            PartialDrain &= (uint64_t)RecvBuffer->Capacity > DrainLength;
        } else if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED) {
            //
            // In app-owned mode, the chunk must be fully drained only if its capacity reaches 0.
            // Otherwise, we either have more bytes to read, or more space to write.
            // Contrary to other modes, we cannot reset ReadStart to the start of the buffer
            // whenever we drained all written data.
            //
            PartialDrain = (uint64_t)RecvBuffer->Capacity > DrainLength;
        }

        if (PartialDrain) {
            QuicRecvBufferPartialDrain(RecvBuffer, DrainLength);
            return !MoreDataReadable;
        }

        //
        // The chunk doesn't contain anything useful anymore, it can be
        // discarded or reused without constraints.
        //
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
