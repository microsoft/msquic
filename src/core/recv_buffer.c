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
    drain it does the physical buffer start to increase in size to accomodate
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
QUIC_STATUS
QuicRecvBufferInitialize(
    _Inout_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t AllocBufferLength,
    _In_ uint32_t VirtualBufferLength,
    _In_ BOOLEAN CopyOnDrain
    )
{
    QUIC_STATUS Status;

    QUIC_DBG_ASSERT(AllocBufferLength != 0 && (AllocBufferLength & (AllocBufferLength - 1)) == 0);       // Power of 2
    QUIC_DBG_ASSERT(VirtualBufferLength != 0 && (VirtualBufferLength & (VirtualBufferLength - 1)) == 0); // Power of 2
    QUIC_DBG_ASSERT(AllocBufferLength <= VirtualBufferLength);

    RecvBuffer->Buffer = QUIC_ALLOC_NONPAGED(AllocBufferLength);
    if (RecvBuffer->Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "recv_buffer",
            AllocBufferLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status =
        QuicRangeInitialize(
            QUIC_MAX_RANGE_ALLOC_SIZE,
            &RecvBuffer->WrittenRanges);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "recv_buffer written ranged",
            QUIC_MAX_RANGE_ALLOC_SIZE);
        QUIC_FREE(RecvBuffer->Buffer);
        goto Error;
    }

    RecvBuffer->AllocBufferLength = AllocBufferLength;
    RecvBuffer->VirtualBufferLength = VirtualBufferLength;
    RecvBuffer->BufferStart = 0;
    RecvBuffer->BaseOffset = 0;
    RecvBuffer->CopyOnDrain = CopyOnDrain;
    RecvBuffer->ExternalBufferReference = FALSE;
    RecvBuffer->OldBuffer = NULL;
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
    QUIC_FREE(RecvBuffer->Buffer);
    RecvBuffer->Buffer = NULL;
    if (RecvBuffer->OldBuffer != NULL) {
        QUIC_FREE(RecvBuffer->OldBuffer);
        RecvBuffer->OldBuffer = NULL;
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
    QUIC_DBG_ASSERT(TotalLength >= RecvBuffer->BaseOffset);
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

//
// Allocates a new contiguous buffer of the target size and copies the bytes
// into it.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferResize(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t TargetBufferLength
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    //
    // First check whether there is any work to do (since shrinks
    // can be deferred, a shrink request might be followed immediately
    // by a grow request before any real shrinking happens).
    //
    if (TargetBufferLength != RecvBuffer->AllocBufferLength) {

        uint32_t Span = QuicRecvBufferGetSpan(RecvBuffer);

        uint8_t* NewBuffer = QUIC_ALLOC_NONPAGED(TargetBufferLength);
        if (NewBuffer == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        uint32_t LengthTillWrap = RecvBuffer->AllocBufferLength - RecvBuffer->BufferStart;

        if (Span <= LengthTillWrap) {
            QuicCopyMemory(
                NewBuffer,
                RecvBuffer->Buffer + RecvBuffer->BufferStart,
                Span);
        } else {
            QuicCopyMemory(
                NewBuffer,
                RecvBuffer->Buffer + RecvBuffer->BufferStart,
                LengthTillWrap);
            QuicCopyMemory(
                NewBuffer + LengthTillWrap,
                RecvBuffer->Buffer,
                Span - LengthTillWrap);
        }

        if (RecvBuffer->ExternalBufferReference && RecvBuffer->OldBuffer == NULL) {
            RecvBuffer->OldBuffer = RecvBuffer->Buffer;
        } else {
            QUIC_FREE(RecvBuffer->Buffer);
        }

        RecvBuffer->Buffer = NewBuffer;
        RecvBuffer->AllocBufferLength = TargetBufferLength;
        RecvBuffer->BufferStart = 0;
    }

Error:

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvBufferSetVirtualBufferLength(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint32_t NewLength
    )
{
    QUIC_FRE_ASSERT(NewLength >= RecvBuffer->VirtualBufferLength); // Don't support decrease yet.
    RecvBuffer->VirtualBufferLength = NewLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferHasUnreadData(
    _In_ QUIC_RECV_BUFFER* RecvBuffer
    )
{
    return QuicRecvBufferGetTotalLength(RecvBuffer) > RecvBuffer->BaseOffset;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferAlreadyReadData(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t BufferOffset,
    _In_ uint16_t BufferLength
    )
{
    return BufferOffset + BufferLength <= RecvBuffer->BaseOffset;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicRecvBufferWrite(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t BufferOffset,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength) uint8_t const* Buffer,
    _Inout_ uint64_t* WriteLength,
    _Out_ BOOLEAN* ReadyToRead
    )
{
    QUIC_STATUS Status;
    BOOLEAN WrittenRangesUpdated;
    QUIC_SUBRANGE* UpdatedRange = NULL;

    QUIC_DBG_ASSERT(BufferLength != 0);

    //
    // Default the ready to read to false, as most exit cases need this.
    //
    *ReadyToRead = FALSE;

    uint32_t RelativeOffset;
    uint32_t WriteBufferStart;

    uint64_t AbsoluteLength = BufferOffset + BufferLength;

    //
    // Check if the input buffer has already been completely written.
    //
    if (AbsoluteLength <= RecvBuffer->BaseOffset) {
        Status = QUIC_STATUS_SUCCESS;
        *WriteLength = 0;
        goto Error;
    }

    //
    // Check to see if the input buffer is trying to write beyond the
    // allowed (stream) max data size.
    //
    if (AbsoluteLength > RecvBuffer->BaseOffset + RecvBuffer->VirtualBufferLength) {
        Status = QUIC_STATUS_BUFFER_TOO_SMALL;
        goto Error;
    }

    //
    // Check to see if the input buffer is trying to write beyond the allowed
    // (input) length. If it's in bounds, update the output to indicate how much
    // new data was actually written.
    //
    uint64_t CurrentMaxLength = QuicRecvBufferGetTotalLength(RecvBuffer);
    if (AbsoluteLength > CurrentMaxLength) {
        if (AbsoluteLength - CurrentMaxLength > *WriteLength) {
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            goto Error;
        }
        *WriteLength = AbsoluteLength - CurrentMaxLength;
    } else {
        *WriteLength = 0;
    }

    //
    // Check to see if the input buffer is trying to write beyond the
    // currently allocated length.
    //
    if (AbsoluteLength > RecvBuffer->BaseOffset + RecvBuffer->AllocBufferLength) {

        //
        // Make room for the new data.
        //

        uint32_t NewBufferLength = RecvBuffer->AllocBufferLength << 1;
        while (AbsoluteLength > RecvBuffer->BaseOffset + NewBufferLength) {
            NewBufferLength <<= 1;
        }

        Status = QuicRecvBufferResize(RecvBuffer, NewBufferLength);

        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    //
    // Set the input range as a valid written range.
    //
    UpdatedRange =
        QuicRangeAddRange(
            &RecvBuffer->WrittenRanges,
            BufferOffset,
            BufferLength,
            &WrittenRangesUpdated);
    if (!UpdatedRange) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "recv_buffer range",
            0);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    } else if (!WrittenRangesUpdated) {
        //
        // No changes are necessary. Exit immediately.
        //
        Status = QUIC_STATUS_SUCCESS;
        goto Error;
    }

    //
    // Calculate the relative offset from the stream buffer's current base offset.
    //
    if (BufferOffset < RecvBuffer->BaseOffset) {
        uint16_t Diff = (uint16_t)(RecvBuffer->BaseOffset - BufferOffset);
        BufferLength -= Diff;
        Buffer += Diff;
        RelativeOffset = 0;
    } else {
        RelativeOffset = (uint32_t)(BufferOffset - RecvBuffer->BaseOffset);
    }

    //
    // Calculate the actual starting point in the buffer that we will write to,
    // accounting for wrap around.
    //
    WriteBufferStart = (RecvBuffer->BufferStart + RelativeOffset) % RecvBuffer->AllocBufferLength;

    //
    // Copy the data; but make sure to account for wrap around on the circular buffer.
    //
    if (WriteBufferStart + BufferLength > RecvBuffer->AllocBufferLength) {

        //
        // The copy must be split into two parts.
        //
        uint16_t Part1Len = (uint16_t)(RecvBuffer->AllocBufferLength - WriteBufferStart);
        uint16_t Part2Len = BufferLength - Part1Len;

        //
        // Copy the first part, which is at the end of the circular buffer.
        //
        QuicCopyMemory(
            RecvBuffer->Buffer + WriteBufferStart,
            Buffer,
            Part1Len);

        //
        // Copy the second part, which is at the beginning of the circular buffer.
        //
        QuicCopyMemory(
            RecvBuffer->Buffer,
            Buffer + Part1Len,
            Part2Len);

    } else {

        //
        // Single copy case, because it doesn't overlap the end.
        //
        QuicCopyMemory(
            RecvBuffer->Buffer + WriteBufferStart,
            Buffer,
            BufferLength);
    }

    //
    // We have data to read if we just wrote to the front of the buffer.
    //
    *ReadyToRead = UpdatedRange->Low == 0;

    Status = QUIC_STATUS_SUCCESS;

Error:

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicRecvBufferRead(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _Out_ uint64_t* BufferOffset,
    _Inout_ uint32_t* BufferCount,
    _Out_writes_all_(*BufferCount)
        QUIC_BUFFER* Buffers
    )
{
    BOOLEAN BaseOffsetIsWritten;
    BOOLEAN LastWrittenRange;
    uint64_t WrittenRangeLength;

    QUIC_DBG_ASSERT(!RecvBuffer->ExternalBufferReference);

    //
    // Query if the front of the buffer has been written.
    //
    BaseOffsetIsWritten =
        QuicRangeGetRange(
            &RecvBuffer->WrittenRanges,
            RecvBuffer->BaseOffset,
            &WrittenRangeLength,
            &LastWrittenRange);

    //
    // Exit now if there isn't any data ready to be read.
    //
    if (!BaseOffsetIsWritten || WrittenRangeLength == 0) {
        return FALSE;
    }

    RecvBuffer->ExternalBufferReference = TRUE;
    *BufferOffset = RecvBuffer->BaseOffset;

    if (RecvBuffer->BufferStart + WrittenRangeLength > RecvBuffer->AllocBufferLength) {
        //
        // Circular buffer wrap around case.
        //
        QUIC_DBG_ASSERT(*BufferCount >= 2);
        *BufferCount = 2;
        Buffers[0].Length = (uint32_t)(RecvBuffer->AllocBufferLength - RecvBuffer->BufferStart);
        Buffers[0].Buffer = RecvBuffer->Buffer + RecvBuffer->BufferStart;
        Buffers[1].Length = (uint32_t)WrittenRangeLength - Buffers[0].Length;
        Buffers[1].Buffer = RecvBuffer->Buffer;

    } else {
        QUIC_DBG_ASSERT(*BufferCount >= 1);
        *BufferCount = 1;
        Buffers[0].Length = (uint32_t)WrittenRangeLength;
        Buffers[0].Buffer = RecvBuffer->Buffer + RecvBuffer->BufferStart;
    }

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicRecvBufferDrain(
    _In_ QUIC_RECV_BUFFER* RecvBuffer,
    _In_ uint64_t BufferLength
    )
{
    QUIC_DBG_ASSERT(RecvBuffer->ExternalBufferReference);
    RecvBuffer->ExternalBufferReference = FALSE;

    if (RecvBuffer->OldBuffer != NULL) {
        QUIC_FREE(RecvBuffer->OldBuffer);
        RecvBuffer->OldBuffer = NULL;
    }

    if (BufferLength == 0) {
        return FALSE;
    }

    RecvBuffer->BaseOffset += BufferLength;
    uint64_t TotalWrittenLength = QuicRangeGetMax(&RecvBuffer->WrittenRanges) + 1;

    if (RecvBuffer->BaseOffset == TotalWrittenLength) {
        //
        // All buffer has been drained. Just reset start back to beginning.
        //
        RecvBuffer->BufferStart = 0;
        return TRUE;
    }

    if (RecvBuffer->CopyOnDrain) {
        QUIC_DBG_ASSERT(RecvBuffer->BufferStart == 0);
        //
        // Copy remaining bytes in the buffer to the beginning.
        //
        QuicMoveMemory(
            RecvBuffer->Buffer,
            RecvBuffer->Buffer + BufferLength,
            (size_t)(TotalWrittenLength - RecvBuffer->BaseOffset));
    } else {
        //
        // Increment the buffer start, making sure to account for circular
        // buffer wrap around.
        //
        RecvBuffer->BufferStart =
            (uint32_t)(RecvBuffer->BufferStart + BufferLength) % RecvBuffer->AllocBufferLength;
    }

    //
    // Not all data was drained, but that doesn't mean it wasn't drained up to
    // the first gap. Get the length of the first sub range and compare that to
    // the current base read point. If all of it has been read, then there isn't
    // any more data available for read right now.
    //
    return RecvBuffer->BaseOffset == QuicRangeGet(&RecvBuffer->WrittenRanges, 0)->Count;
}
