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
    QUIC_RECV_CHUNK* NextChunk;
    CXPLAT_LIST_ENTRY* IteratorEnd;
    uint32_t StartOffset; // Offset of the first byte to read in the next chunk.
    uint32_t EndOffset;   // Offset of the last byte to read in the next chunk (inclusive!).
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
    Iterator.NextChunk =
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
            (RecvBuffer->ReadStart + Offset) % Iterator.NextChunk->AllocLength;
        Iterator.EndOffset =
            (RecvBuffer->ReadStart + RecvBuffer->Capacity - 1) % Iterator.NextChunk->AllocLength;
        return Iterator;
    }

    //
    // Walk through chunks to skip the offset.
    //
    Offset -= RecvBuffer->Capacity;
    Iterator.NextChunk =
        CXPLAT_CONTAINING_RECORD(
            Iterator.NextChunk->Link.Flink,
            QUIC_RECV_CHUNK,
            Link);
    while (Offset >= Iterator.NextChunk->AllocLength) {
        CXPLAT_DBG_ASSERT(Iterator.NextChunk->Link.Flink != &RecvBuffer->Chunks);
        Offset -= Iterator.NextChunk->AllocLength;
        Iterator.NextChunk =
            CXPLAT_CONTAINING_RECORD(
                Iterator.NextChunk->Link.Flink,
                QUIC_RECV_CHUNK,
                Link);
    }
    Iterator.StartOffset = (uint32_t)Offset;
    Iterator.EndOffset = Iterator.NextChunk->AllocLength - 1;

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
    Buffer->Buffer = NULL;
    Buffer->Length = 0;

    if (Iterator->NextChunk == NULL) {
        return FALSE;
    }

    if (ReferenceChunk) {
        Iterator->NextChunk->ExternalReference = TRUE;
    }

    Buffer->Buffer = Iterator->NextChunk->Buffer + Iterator->StartOffset;

    if (Iterator->StartOffset > Iterator->EndOffset) {
        Buffer->Length = Iterator->NextChunk->AllocLength - Iterator->StartOffset;
        //
        // Wrap around case - next buffer start from the beginning of the chunk.
        //
        Iterator->StartOffset = 0;
    } else {
        Buffer->Length = Iterator->EndOffset - Iterator->StartOffset + 1;

        if (Iterator->NextChunk->Link.Flink == Iterator->IteratorEnd) {
            //
            // No more chunks to iterate over.
            //
            Iterator->NextChunk = NULL;
            return TRUE;
        }

        //
        // Move to the next chunk.
        //
        Iterator->NextChunk =
            CXPLAT_CONTAINING_RECORD(
                Iterator->NextChunk->Link.Flink,
                QUIC_RECV_CHUNK,
                Link);
        Iterator->StartOffset = 0;
        Iterator->EndOffset = Iterator->NextChunk->AllocLength - 1;
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvChunkInitialize(
    _Inout_ QUIC_RECV_CHUNK* Chunk,
    _In_ uint32_t AllocLength,
    _Inout_updates_(AllocLength) uint8_t* Buffer,
    _In_ BOOLEAN AllocatedFromPool
    )
{
    Chunk->AllocLength = AllocLength;
    Chunk->Buffer = Buffer;
    Chunk->ExternalReference = FALSE;
    Chunk->AllocatedFromPool = AllocatedFromPool;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvChunkFree(
    _In_ QUIC_RECV_CHUNK* Chunk
    )
{
    //
    // The data buffer of the chunk is allocated in the same allocation
    // as the chunk itself if and only if it is owned by the receive buffer:
    // freeing the chunk will free the data buffer as needed.
    //
    if (Chunk->AllocatedFromPool) {
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
    // There can be a retired chunk only when a read is pending.
    //
    CXPLAT_DBG_ASSERT(RecvBuffer->RetiredChunk == NULL || RecvBuffer->ReadPendingLength != 0);

    //
    // Except for App-owned mode, there is always at least one chunk in the list.
    //
    CXPLAT_DBG_ASSERT(
        RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED ||
        !CxPlatListIsEmpty(&RecvBuffer->Chunks));

    if (CxPlatListIsEmpty(&RecvBuffer->Chunks)) {
        return;
    }

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
    // In Single and App-owned modes, the first chunk is never used in a circular way.
    //
    CXPLAT_DBG_ASSERT(
        (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_SINGLE &&
        RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED) ||
        RecvBuffer->ReadStart + RecvBuffer->ReadLength <= FirstChunk->AllocLength);
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
    CXPLAT_DBG_ASSERT(PreallocatedChunk == NULL || RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED);
    CXPLAT_DBG_ASSERT((AllocBufferLength & (AllocBufferLength - 1)) == 0);     // Power of 2
    CXPLAT_DBG_ASSERT((VirtualBufferLength & (VirtualBufferLength - 1)) == 0); // Power of 2
    CXPLAT_DBG_ASSERT(AllocBufferLength <= VirtualBufferLength);

    RecvBuffer->BaseOffset = 0;
    RecvBuffer->ReadStart = 0;
    RecvBuffer->ReadPendingLength = 0;
    RecvBuffer->ReadLength = 0;
    RecvBuffer->RecvMode = RecvMode;
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
        QuicRecvChunkFree(Chunk);
    }

    if (RecvBuffer->RetiredChunk != NULL) {
        QuicRecvChunkFree(RecvBuffer->RetiredChunk);
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
        CXPLAT_CONTAINING_RECORD(RecvBuffer->Chunks.Blink, QUIC_RECV_CHUNK, Link);
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

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE && LastChunk->ExternalReference) {
        //
        // In Multiple mode, if the last chunk is referenced, simply add the new chunk to the list.
        // The last chunk is still used for reads and writes but drains reduce its capacity until it
        // can be freed.
        //
        return TRUE;
    }

    //
    // In Single and Circular modes, or in Multiple mode when the last chunk is not referenced,
    // replace the last chunk is with the new one:
    // - copy the data to the new chunk
    // - remove the last chunk from the list
    //

    if (LastChunkIsFirst) {
        uint32_t WrittenSpan =
            CXPLAT_MIN(LastChunk->AllocLength, QuicRecvBufferGetSpan(RecvBuffer));
        uint32_t LengthBeforeWrap = LastChunk->AllocLength - RecvBuffer->ReadStart;
        if (WrittenSpan <= LengthBeforeWrap) {
            CxPlatCopyMemory(
                NewChunk->Buffer,
                LastChunk->Buffer + RecvBuffer->ReadStart,
                WrittenSpan);
        } else {
            CxPlatCopyMemory(
                NewChunk->Buffer,
                LastChunk->Buffer + RecvBuffer->ReadStart,
                LengthBeforeWrap);
            CxPlatCopyMemory(
                NewChunk->Buffer + LengthBeforeWrap,
                LastChunk->Buffer,
                WrittenSpan - LengthBeforeWrap);
        }
        RecvBuffer->ReadStart = 0;
        RecvBuffer->Capacity = NewChunk->AllocLength;
    } else {
        //
        // If it isn't the first chunk, it always starts from the beginning of the buffer.
        //
        CxPlatCopyMemory(NewChunk->Buffer, LastChunk->Buffer, LastChunk->AllocLength);
    }

    //
    // The chunk data has been copied, remove the chunk from the list.
    //
    CxPlatListEntryRemove(&LastChunk->Link);

    if (LastChunk->ExternalReference) {
        //
        // The chunk is referenced, so we need to retire it until we can free it.
        // (only one read can be pending at a time, so there is no retired chunk)
        //
        CXPLAT_DBG_ASSERT(
            RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE ||
            RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_CIRCULAR);
        CXPLAT_DBG_ASSERT(RecvBuffer->RetiredChunk == NULL);

        RecvBuffer->RetiredChunk = LastChunk;
    } else {
        QuicRecvChunkFree(LastChunk);
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicRecvBufferGetTotalAllocLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));

    //
    // The first chunk might have a reduced capacity (if more chunks are present and it is being
    // consumed). Other chunks are always allocated at their full alloc size.
    //
    uint32_t AllocLength = RecvBuffer->Capacity;
    for (CXPLAT_LIST_ENTRY* Link = RecvBuffer->Chunks.Flink->Flink; // Skip the first chunk
         Link != &RecvBuffer->Chunks;
         Link = Link->Flink) {
        QUIC_RECV_CHUNK* Chunk = CXPLAT_CONTAINING_RECORD(Link, QUIC_RECV_CHUNK, Link);
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
    const uint64_t AbsoluteLength = WriteOffset + WriteLength;
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
            // There isn't enough space to write the data.
            // Add a new chunk (or replace the existing one), doubling the size of the largest chunk
            // until there is enough space for the write.
            //
            QUIC_RECV_CHUNK* LastChunk =
                CXPLAT_CONTAINING_RECORD(RecvBuffer->Chunks.Blink, QUIC_RECV_CHUNK, Link);
            uint32_t NewBufferLength = LastChunk->AllocLength << 1;
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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferDrainFullChunks(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _Inout_ uint64_t* DrainLength
    )
{
    uint64_t RemainingDrainLength = *DrainLength;

    //
    // Find the first chunk that won't be fully drained: it will become the new first chunk.
    //
    QUIC_RECV_CHUNK_ITERATOR Iterator = QuicRecvBufferGetChunkIterator(RecvBuffer, 0);
    QUIC_RECV_CHUNK* NewFirstChunk = Iterator.NextChunk;
    QUIC_BUFFER Buffer;
    while (QuicRecvChunkIteratorNext(&Iterator, FALSE, &Buffer)) {
        if (RemainingDrainLength < Buffer.Length) {
            break;
        }

        RemainingDrainLength -= Buffer.Length;
        NewFirstChunk = Iterator.NextChunk;
    }

    if (NewFirstChunk != NULL && &NewFirstChunk->Link == RecvBuffer->Chunks.Flink) {
        //
        // The first chunk didn't change: there is nothing to fully drain.
        //
        return;
    }

    CXPLAT_DBG_ASSERT(RemainingDrainLength == 0 || NewFirstChunk != NULL);
    if (NewFirstChunk == NULL && RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_APP_OWNED) {
        //
        // All chunks have been fully drained. Recycle the last (and biggest) one.
        //
        NewFirstChunk = CXPLAT_CONTAINING_RECORD(RecvBuffer->Chunks.Blink, QUIC_RECV_CHUNK, Link);
        NewFirstChunk->ExternalReference = FALSE;
    }

    //
    // Delete fully drained chunks.
    //
    CXPLAT_LIST_ENTRY* ChunkIt = RecvBuffer->Chunks.Flink;
    CXPLAT_LIST_ENTRY* EndIt = NewFirstChunk != NULL ? &NewFirstChunk->Link : &RecvBuffer->Chunks;
    while (ChunkIt != EndIt) {
        QUIC_RECV_CHUNK* Chunk = CXPLAT_CONTAINING_RECORD(ChunkIt, QUIC_RECV_CHUNK, Link);
        ChunkIt = ChunkIt->Flink;

        CxPlatListEntryRemove(&Chunk->Link);
        QuicRecvChunkFree(Chunk);
    }

    RecvBuffer->Capacity = NewFirstChunk != NULL ? NewFirstChunk->AllocLength : 0;
    RecvBuffer->ReadStart = 0;
    RecvBuffer->ReadLength = CXPLAT_MIN(
            RecvBuffer->Capacity,
           (uint32_t)(QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count - RecvBuffer->BaseOffset));

    *DrainLength = RemainingDrainLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferDrainFirstChunk(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t DrainLength
    )
{
    //
    // Drain the first chunk by adapting the read start and capacity.
    //
    QUIC_RECV_CHUNK* FirstChunk =
        CXPLAT_CONTAINING_RECORD(RecvBuffer->Chunks.Flink, QUIC_RECV_CHUNK, Link);
    CXPLAT_DBG_ASSERT(DrainLength < RecvBuffer->Capacity);

    RecvBuffer->ReadStart = (RecvBuffer->ReadStart + DrainLength) % FirstChunk->AllocLength;

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED ||
        FirstChunk->Link.Flink != &RecvBuffer->Chunks) {
        //
        // In App-owned mode or when more than one chunk is present, reduce the capacity to ensure the
        // drained spaced is not reused and the chunk can eventually be freed.
        //
        RecvBuffer->Capacity -= (uint32_t)DrainLength;
    }

    RecvBuffer->ReadLength = CXPLAT_MIN(
            RecvBuffer->Capacity,
           (uint32_t)(QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count - RecvBuffer->BaseOffset));

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE && RecvBuffer->ReadStart != 0) {
        //
        // In Single mode, the readable data must always start at the front of the buffer,
        // move all written data if needed.
        //
        uint32_t WrittenSpan =
            CXPLAT_MIN(FirstChunk->AllocLength, QuicRecvBufferGetSpan(RecvBuffer));
        CxPlatMoveMemory(
            FirstChunk->Buffer, FirstChunk->Buffer + RecvBuffer->ReadStart, WrittenSpan);
        RecvBuffer->ReadStart = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t DrainLength
    )
{
    CXPLAT_DBG_ASSERT(QuicRangeGetSafe(&RecvBuffer->WrittenRanges, 0) != NULL);
    CXPLAT_DBG_ASSERT(DrainLength <= RecvBuffer->ReadPendingLength);
    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&RecvBuffer->Chunks));

    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE) {
        //
        // In Multiple mode, data not drained stays pending.
        //
        RecvBuffer->ReadPendingLength -= DrainLength;
    } else {
        RecvBuffer->ReadPendingLength = 0;
    }

    CXPLAT_DBG_ASSERT(DrainLength <= RecvBuffer->VirtualBufferLength);
    if (RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED) {
        //
        // In App-owned mode, memory is never reused: a drain consume virtual buffer length.
        //
        RecvBuffer->VirtualBufferLength -= (uint32_t)(DrainLength);
    }

    RecvBuffer->BaseOffset += DrainLength;

    //
    // Free the retired chunk, the app no longer references it now that the read completed.
    //
    if (RecvBuffer->RetiredChunk != NULL) {
        CXPLAT_DBG_ASSERT(
            RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_SINGLE ||
            RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_CIRCULAR);

        QuicRecvChunkFree(RecvBuffer->RetiredChunk);
        RecvBuffer->RetiredChunk = NULL;
    }

    //
    // Drain chunks that are entirely covered by the drain.
    //
    QuicRecvBufferDrainFullChunks(RecvBuffer, &DrainLength);

    if (CxPlatListIsEmpty(&RecvBuffer->Chunks)) {
        //
        // App-owned mode is the only mode where we can run out of chunks.
        // In all other modes, if the last chunk was fully drained, we recycle it instead.
        //
        CXPLAT_DBG_ASSERT(RecvBuffer->RecvMode == QUIC_RECV_BUF_MODE_APP_OWNED);
        CXPLAT_DBG_ASSERT(DrainLength == 0);
        return TRUE;
    }

    //
    // Now, we need to drain the new first chunk of the remaining amount of data by adapting the
    // read start, length and capacity.
    //
    QuicRecvBufferDrainFirstChunk(RecvBuffer, DrainLength);

    //
    // Finally, dereference all chunks.
    // For Multiple mode, chunks that still have read-pending data stay referenced.
    //
    if (RecvBuffer->RecvMode != QUIC_RECV_BUF_MODE_MULTIPLE) {
        for (CXPLAT_LIST_ENTRY* Link = RecvBuffer->Chunks.Flink;
             Link != &RecvBuffer->Chunks;
             Link = Link->Flink) {
            QUIC_RECV_CHUNK* Chunk = CXPLAT_CONTAINING_RECORD(Link, QUIC_RECV_CHUNK, Link);
            Chunk->ExternalReference = FALSE;
        }
    } else  {
        QUIC_RECV_CHUNK* FirstChunk =
            CXPLAT_CONTAINING_RECORD(RecvBuffer->Chunks.Flink, QUIC_RECV_CHUNK, Link);
        FirstChunk->ExternalReference = RecvBuffer->ReadPendingLength != 0;
    }

    QuicRecvBufferValidate(RecvBuffer);
    return RecvBuffer->ReadLength == 0;
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
