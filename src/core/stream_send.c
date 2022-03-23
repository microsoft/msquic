/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    [   ][   ][   ][   ][   ][   ][   ][   ][   ] send requests
                     [   ]         [      ]       SACKs
       |                                          UnAckedOffset
                                             |    NextSendOffset
           |                                      RecoveryNextOffset
                          |                       RecoveryEndOffset
            xxxxxxxxxxxxxx                        Recovery window

    UnAckedOffset works just like TCP's SND.UNA and tracks cumulatively ACKed
    bytes. Any noncontiguous regions of ACKed bytes past UnAckedOffset
    are recorded with SACK blocks, which are subsumed as UnAckedOffset advances.

    Ordinarily we send bytes at (and advance) NextSendOffset. But if the
    recovery window is open (RecoveryNextOffset < RecoveryEndOffset), we
    send from (and advance) RecoveryNextOffset first (and continue sending
    from NextSendOffset once the recovery window is closed).

    Note that the recovery window being closed simply means we've resent
    all the bytes we want to recover, not that we have left recovery.
    We've "recovered successfully" when UnAckedOffset advances past
    RecoveryEndOffset.

    NextSendOffset is reset to UnAckedOffset on a retransmit timeout. We
    also reset RecoveryEndOffset to UnAckedOffset to close the recovery
    window (effectively giving up on that round of recovery).

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "stream_send.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamCompleteSendRequest(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SEND_REQUEST* SendRequest,
    _In_ BOOLEAN Canceled,
    _In_ BOOLEAN PreviouslyPosted
    );

#if DEBUG

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamValidateRecoveryState(
    _In_ QUIC_STREAM* Stream
    )
{
    if (RECOV_WINDOW_OPEN(Stream)) {
        QUIC_SUBRANGE* Sack;
        uint32_t i = 0;
        while ((Sack = QuicRangeGetSafe(&Stream->SparseAckRanges, i++)) != NULL &&
            Sack->Low < Stream->RecoveryNextOffset) {
            //
            // The recovery window should never start inside a SACK block.
            //
            CXPLAT_DBG_ASSERT(Sack->Low + Sack->Count <= Stream->RecoveryNextOffset);
        }
    }
}

#else

#define QuicStreamValidateRecoveryState(Stream)

#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateSendShutdownComplete(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN GracefulShutdown
    )
{
    CXPLAT_DBG_ASSERT(!Stream->Flags.SendEnabled);
    CXPLAT_DBG_ASSERT(Stream->ApiSendRequests == NULL);
    CXPLAT_DBG_ASSERT(Stream->SendRequests == NULL);

    if (!Stream->Flags.HandleSendShutdown) {
        Stream->Flags.HandleSendShutdown = TRUE;

        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE;
        Event.SEND_SHUTDOWN_COMPLETE.Graceful = GracefulShutdown;
        QuicTraceLogStreamVerbose(
            IndicateSendShutdownComplete,
            Stream,
            "Indicating QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE");
        (void)QuicStreamIndicateEvent(Stream, &Event);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSendShutdown(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN Graceful,
    _In_ BOOLEAN Silent,
    _In_ BOOLEAN DelaySend,
    _In_ QUIC_VAR_INT ErrorCode   // Only for !Graceful
    )
{
    if (Stream->Flags.LocalCloseAcked) {
        //
        // We have already closed (graceful or abortive) and it has been
        // acknowledged by the peer. Nothing else to be done.
        //
        goto Exit;
    }

    CxPlatDispatchLockAcquire(&Stream->ApiSendRequestLock);
    Stream->Flags.SendEnabled = FALSE;
    QUIC_SEND_REQUEST* ApiSendRequests = Stream->ApiSendRequests;
    Stream->ApiSendRequests = NULL;
    CxPlatDispatchLockRelease(&Stream->ApiSendRequestLock);

    if (Graceful) {
        CXPLAT_DBG_ASSERT(!Silent);
        if (Stream->Flags.LocalCloseFin || Stream->Flags.LocalCloseReset) {
            //
            // We have already closed the stream (graceful or abortive) so we
            // can't gracefully close it.
            //
            goto Exit;
        }

        while (ApiSendRequests != NULL) {
            //
            // These sends were queued by the app after queueing a graceful
            // shutdown. Bad app!
            //
            QUIC_SEND_REQUEST* SendRequest = ApiSendRequests;
            ApiSendRequests = ApiSendRequests->Next;
            QuicStreamCompleteSendRequest(Stream, SendRequest, TRUE, FALSE);
        }

        Stream->Flags.LocalCloseFin = TRUE;

        //
        // Queue up a FIN STREAM frame to be sent.
        //
        QuicSendSetStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_FIN,
            DelaySend);

    } else {

        //
        // Make sure to deliver all send request cancelled callbacks first.
        //
        while (Stream->SendRequests) {
            QUIC_SEND_REQUEST* Req = Stream->SendRequests;
            Stream->SendRequests = Stream->SendRequests->Next;
            QuicStreamCompleteSendRequest(Stream, Req, TRUE, TRUE);
        }
        Stream->SendRequestsTail = &Stream->SendRequests;

        while (ApiSendRequests != NULL) {
            QUIC_SEND_REQUEST* SendRequest = ApiSendRequests;
            ApiSendRequests = ApiSendRequests->Next;
            QuicStreamCompleteSendRequest(Stream, SendRequest, TRUE, FALSE);
        }

        if (Silent) {
            //
            // If we are doing an abortive, silent shutdown, then the handle is
            // being closed. Always clear all flags.
            //
            QuicSendClearStreamSendFlag(
                &Stream->Connection->Send,
                Stream,
                QUIC_STREAM_SEND_FLAGS_ALL);

            //
            // Since we are silently shutting down, implicitly treat the close
            // as acknowledged by the peer.
            //
            Stream->Flags.LocalCloseAcked = TRUE;
            QuicStreamIndicateSendShutdownComplete(Stream, FALSE);
        }

        if (Stream->Flags.LocalCloseReset) {
            //
            // We have already abortively closed the stream, so there isn't
            // anything else to do.
            //
            goto Exit;
        }

        Stream->Flags.LocalCloseReset = TRUE;
        Stream->SendShutdownErrorCode = ErrorCode;

        if (!Silent) {
            //
            // Queue up the send flag for the RESET frame.
            //
            QuicSendSetStreamSendFlag(
                &Stream->Connection->Send,
                Stream,
                QUIC_STREAM_SEND_FLAG_SEND_ABORT,
                FALSE);

            //
            // Clear any outstanding send path frames.
            //
            QuicSendClearStreamSendFlag(
                &Stream->Connection->Send,
                Stream,
                QUIC_STREAM_SEND_FLAG_DATA_BLOCKED |
                QUIC_STREAM_SEND_FLAG_DATA |
                QUIC_STREAM_SEND_FLAG_OPEN |
                QUIC_STREAM_SEND_FLAG_FIN);
        }
    }

    QuicStreamSendDumpState(Stream);

Exit:

    QuicTraceEvent(
        StreamSendState,
        "[strm][%p] Send State: %hhu",
        Stream,
        QuicStreamSendGetState(Stream));

    if (Silent) {
        QuicStreamTryCompleteShutdown(Stream);
    }
}

//
// Returns TRUE if the peer has indicated the stream ID is allowed to be used
// yet.
//
BOOLEAN
QuicStreamAllowedByPeer(
    _In_ const QUIC_STREAM* Stream
    )
{
    uint64_t StreamType = Stream->ID & STREAM_ID_MASK;
    uint64_t StreamCount = (Stream->ID >> 2) + 1;
    const QUIC_STREAM_TYPE_INFO* Info =
        &Stream->Connection->Streams.Types[StreamType];
    return Info->MaxTotalStreamCount >= StreamCount;
}

//
// Returns TRUE if the stream has any data queued to be sent.
//
BOOLEAN
QuicStreamHasPendingStreamData(
    _In_ const QUIC_STREAM* Stream
    )
{
    return
        RECOV_WINDOW_OPEN(Stream) ||
        (Stream->NextSendOffset < Stream->QueuedSendOffset);
}

//
// Returns TRUE if the Stream has any data that is allowed to be sent in 0-RTT
// still in the queue.
//
BOOLEAN
QuicStreamHasPending0RttData(
    _In_ const QUIC_STREAM* Stream
    )
{
    return
        Stream->Queued0Rtt > Stream->NextSendOffset ||
        (Stream->NextSendOffset == Stream->QueuedSendOffset &&
         (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_FIN));
}

//
// Returns TRUE if the stream can send a STREAM frame immediately. This
// function does not include any congestion control state checks.
//
BOOLEAN
QuicStreamSendCanWriteDataFrames(
    _In_ const QUIC_STREAM* Stream
    )
{
    CXPLAT_DBG_ASSERT(QuicStreamAllowedByPeer(Stream));
    CXPLAT_DBG_ASSERT(HasStreamDataFrames(Stream->SendFlags));

    if (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_OPEN) {
        //
        // Flow control doesn't block opening a new stream.
        //
        return TRUE;
    }

    if (RECOV_WINDOW_OPEN(Stream)) {
        //
        // We have some bytes to recover. Since these bytes are being
        // retransmitted, we can ignore flow control.
        //
        return TRUE;
    }

    if (Stream->NextSendOffset == Stream->QueuedSendOffset) {
        //
        // No unsent data. Can send only if a FIN is needed.
        //
        return !!(Stream->SendFlags & QUIC_STREAM_SEND_FLAG_FIN);
    }

    //
    // Some unsent data. Can send only if flow control will allow.
    //
    QUIC_SEND* Send = &Stream->Connection->Send;
    return
        Stream->NextSendOffset < Stream->MaxAllowedSendOffset &&
        Send->OrderedStreamBytesSent < Send->PeerMaxData;
}

BOOLEAN
QuicStreamCanSendNow(
    _In_ const QUIC_STREAM* Stream,
    _In_ BOOLEAN ZeroRtt
    )
{
    CXPLAT_DBG_ASSERT(Stream->SendFlags != 0);

    if (!QuicStreamAllowedByPeer(Stream)) {
        //
        // Peer doesn't allow it yet.
        //
        return FALSE;
    }

    if (HasStreamControlFrames(Stream->SendFlags) ||
        (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_OPEN)) {
        //
        // We can always send control frames and/or open new streams.
        //
        return TRUE;

    }

    if (QuicStreamSendCanWriteDataFrames(Stream)) {
        return ZeroRtt ? QuicStreamHasPending0RttData(Stream) : TRUE;
    }

    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamCompleteSendRequest(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SEND_REQUEST* SendRequest,
    _In_ BOOLEAN Canceled,
    _In_ BOOLEAN PreviouslyPosted
    )
{
    QUIC_CONNECTION* Connection = Stream->Connection;

    if (Stream->SendBookmark == SendRequest) {
        Stream->SendBookmark = SendRequest->Next;
    }
    if (Stream->SendBufferBookmark == SendRequest) {
        Stream->SendBufferBookmark = SendRequest->Next;
        CXPLAT_DBG_ASSERT(
            Stream->SendBufferBookmark == NULL ||
            !(Stream->SendBufferBookmark->Flags & QUIC_SEND_FLAG_BUFFERED));
    }

    if (!(SendRequest->Flags & QUIC_SEND_FLAG_BUFFERED)) {
        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_SEND_COMPLETE;
        Event.SEND_COMPLETE.Canceled = Canceled;
        Event.SEND_COMPLETE.ClientContext = SendRequest->ClientContext;

        if (Canceled) {
            QuicTraceLogStreamVerbose(
                IndicateSendCanceled,
                Stream,
                "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p] (Canceled)",
                SendRequest);
        } else {
            QuicTraceLogStreamVerbose(
                IndicateSendComplete,
                Stream,
                "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]",
                SendRequest);
        }

        (void)QuicStreamIndicateEvent(Stream, &Event);
    } else if (SendRequest->InternalBuffer.Length != 0) {
        QuicSendBufferFree(
            &Connection->SendBuffer,
            SendRequest->InternalBuffer.Buffer,
            SendRequest->InternalBuffer.Length);
    }

    if (PreviouslyPosted) {
        CXPLAT_DBG_ASSERT(Connection->SendBuffer.PostedBytes >= SendRequest->TotalLength);
        Connection->SendBuffer.PostedBytes -= SendRequest->TotalLength;

        if (Connection->Settings.SendBufferingEnabled) {
            QuicSendBufferFill(Connection);
        }
    }

    CxPlatPoolFree(&Connection->Worker->SendRequestPool, SendRequest);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamSendBufferRequest(
    _Inout_ QUIC_STREAM* Stream,
    _Inout_ QUIC_SEND_REQUEST* Req
    )
{
    QUIC_CONNECTION* Connection = Stream->Connection;

    CXPLAT_DBG_ASSERT(Req->TotalLength <= UINT32_MAX);

    if (Req->TotalLength != 0) {
        //
        // Copy the request bytes into an internal buffer.
        //
        uint8_t* Buf =
            QuicSendBufferAlloc(
                &Connection->SendBuffer,
                (uint32_t)Req->TotalLength);
        if (Buf == NULL) {
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
        uint8_t* CurBuf = Buf;
        for (uint32_t i = 0; i < Req->BufferCount; i++) {
            CxPlatCopyMemory(
                CurBuf, Req->Buffers[i].Buffer, Req->Buffers[i].Length);
            CurBuf += Req->Buffers[i].Length;
        }
        Req->InternalBuffer.Buffer = Buf;
    } else {
        Req->InternalBuffer.Buffer = NULL;
    }
    Req->BufferCount = 1;
    Req->Buffers = &Req->InternalBuffer;
    Req->InternalBuffer.Length = (uint32_t)Req->TotalLength;

    Req->Flags |= QUIC_SEND_FLAG_BUFFERED;
    Stream->SendBufferBookmark = Req->Next;
    CXPLAT_DBG_ASSERT(
        Stream->SendBufferBookmark == NULL ||
        !(Stream->SendBufferBookmark->Flags & QUIC_SEND_FLAG_BUFFERED));

    //
    // Complete the request.
    //
    QUIC_STREAM_EVENT Event;
    Event.Type = QUIC_STREAM_EVENT_SEND_COMPLETE;
    Event.SEND_COMPLETE.Canceled = FALSE;
    Event.SEND_COMPLETE.ClientContext = Req->ClientContext;
    QuicTraceLogStreamVerbose(
        IndicateSendComplete,
        Stream,
        "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]",
        Req);
    (void)QuicStreamIndicateEvent(Stream, &Event);

    Req->ClientContext = NULL;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSendFlush(
    _In_ QUIC_STREAM* Stream
    )
{
    CxPlatDispatchLockAcquire(&Stream->ApiSendRequestLock);
    QUIC_SEND_REQUEST* ApiSendRequests = Stream->ApiSendRequests;
    Stream->ApiSendRequests = NULL;
    CxPlatDispatchLockRelease(&Stream->ApiSendRequestLock);
    int64_t TotalBytesSent = 0;

    BOOLEAN Start = FALSE;

    while (ApiSendRequests != NULL) {

        QUIC_SEND_REQUEST* SendRequest = ApiSendRequests;
        ApiSendRequests = ApiSendRequests->Next;
        SendRequest->Next = NULL;
        TotalBytesSent += (int64_t) SendRequest->TotalLength;

        CXPLAT_DBG_ASSERT(!(SendRequest->Flags & QUIC_SEND_FLAG_BUFFERED));

        if (!Stream->Flags.SendEnabled) {
            //
            // Only possible if they queue muliple sends, with a FIN flag set
            // NOT in the last one.
            //
            QuicStreamCompleteSendRequest(Stream, SendRequest, TRUE, FALSE);
            continue;
        }

        Stream->Connection->SendBuffer.PostedBytes += SendRequest->TotalLength;

        //
        // Queue up the send request.
        //

        QuicStreamRemoveOutFlowBlockedReason(
            Stream, QUIC_FLOW_BLOCKED_APP);

        SendRequest->StreamOffset = Stream->QueuedSendOffset;
        Stream->QueuedSendOffset += SendRequest->TotalLength;

        if (SendRequest->Flags & QUIC_SEND_FLAG_ALLOW_0_RTT &&
            Stream->Queued0Rtt == SendRequest->StreamOffset) {
            Stream->Queued0Rtt = Stream->QueuedSendOffset;
        }

        //
        // The bookmarks are set to NULL once the entire request queue is
        // consumed. So if a bookmark is NULL here, we should set it to
        // point to the new request at the end of the queue, to prevent
        // a subsequent search over the entire queue in the code that
        // uses the bookmark.
        //
        if (Stream->SendBookmark == NULL) {
            Stream->SendBookmark = SendRequest;
        }
        if (Stream->SendBufferBookmark == NULL) {
            //
            // If we have no SendBufferBookmark, that must mean we have no
            // unbuffered send requests queued currently.
            //
            CXPLAT_DBG_ASSERT(
                Stream->SendRequests == NULL ||
                !!(Stream->SendRequests->Flags & QUIC_SEND_FLAG_BUFFERED));
            Stream->SendBufferBookmark = SendRequest;
        }

        *Stream->SendRequestsTail = SendRequest;
        Stream->SendRequestsTail = &SendRequest->Next;

        QuicTraceLogStreamVerbose(
            SendQueued,
            Stream,
            "Send Request [%p] queued with %llu bytes at offset %llu (flags 0x%x)",
            SendRequest,
            SendRequest->TotalLength,
            SendRequest->StreamOffset,
            SendRequest->Flags);

        if (SendRequest->Flags & QUIC_SEND_FLAG_START && !Stream->Flags.Started) {
            //
            // Start the stream if the flag is set.
            //
            Start = TRUE;
        }

        if (SendRequest->Flags & QUIC_SEND_FLAG_FIN) {
            //
            // Gracefully shutdown the send direction if the flag is set.
            //
            QuicStreamSendShutdown(
                Stream,
                TRUE,
                FALSE,
                !!(SendRequest->Flags & QUIC_SEND_FLAG_DELAY_SEND),
                0);
        }

        QuicSendSetStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_DATA,
            !!(SendRequest->Flags & QUIC_SEND_FLAG_DELAY_SEND));

        if (Stream->Connection->Settings.SendBufferingEnabled) {
            QuicSendBufferFill(Stream->Connection);
        }

        CXPLAT_DBG_ASSERT(Stream->SendRequests != NULL);

        QuicStreamSendDumpState(Stream);
    }

    if (Start) {
        (void)QuicStreamStart(
            Stream,
            QUIC_STREAM_START_FLAG_IMMEDIATE,
            FALSE);
    }

    QuicPerfCounterAdd(QUIC_PERF_COUNTER_APP_SEND_BYTES, TotalBytesSent);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamCopyFromSendRequests(
    _In_ QUIC_STREAM* Stream,
    _In_ uint64_t Offset,
    _Out_writes_bytes_(Len) uint8_t* Buf,
    _In_range_(>, 0) uint16_t Len
    )
{
    //
    // Copies up to Len stream bytes starting at Offset from the noncontiguous
    // send request queue into a contiguous frame buffer.
    //

    CXPLAT_DBG_ASSERT(Len > 0);
    CXPLAT_DBG_ASSERT(Stream->SendRequests != NULL);
    CXPLAT_DBG_ASSERT(Offset >= Stream->SendRequests->StreamOffset);

    //
    // Find the send request containing the first byte, using the bookmark if
    // possible (if the caller is requesting bytes before the bookmark, e.g.
    // for a retransmission, then we have to do a full search).
    //
    QUIC_SEND_REQUEST* Req;
    if (Stream->SendBookmark != NULL &&
        Stream->SendBookmark->StreamOffset <= Offset) {
        Req = Stream->SendBookmark;
    } else {
        Req = Stream->SendRequests;
    }
    while (Req->StreamOffset + Req->TotalLength <= Offset) {
        CXPLAT_DBG_ASSERT(Req->Next);
        Req = Req->Next;
    }

    CXPLAT_DBG_ASSERT(Req);

    //
    // Loop through the request's buffers to calculate the current index and
    // offset into that buffer.
    //
    uint32_t CurIndex = 0; // Index of the current buffer.
    uint64_t CurOffset = Offset - Req->StreamOffset; // Offset in the current buffer.
    while (CurOffset >= Req->Buffers[CurIndex].Length) {
        CurOffset -= Req->Buffers[CurIndex++].Length;
    }

    //
    // Starting with the current request, buffer and offset, continue copying
    // until we run out of the requested copy length.
    //
    for (;;) {
        CXPLAT_DBG_ASSERT(Req != NULL);
        CXPLAT_DBG_ASSERT(CurIndex < Req->BufferCount);
        CXPLAT_DBG_ASSERT(CurOffset < Req->Buffers[CurIndex].Length);
        CXPLAT_DBG_ASSERT(Len > 0);

        //
        // Copy the data from the request buffer to the frame buffer.
        //
        uint32_t BufferLeft = Req->Buffers[CurIndex].Length - (uint32_t)CurOffset;
        uint16_t CopyLength = Len < BufferLeft ? Len : (uint16_t)BufferLeft;
        CXPLAT_DBG_ASSERT(CopyLength > 0);
        CxPlatCopyMemory(Buf, Req->Buffers[CurIndex].Buffer + CurOffset, CopyLength);
        Len -= CopyLength;
        Buf += CopyLength;

        if (Len == 0) {
            break; // All data has been copied!
        }

        //
        // Move to the next non-zero length request buffer.
        //
        CurOffset = 0;
        do {
            if (++CurIndex == Req->BufferCount) {
                CurIndex = 0;
                CXPLAT_DBG_ASSERT(Req->Next != NULL);
                Req = Req->Next;
            }
        } while (Req->Buffers[CurIndex].Length == 0);
    }

    //
    // Save the bookmark for later.
    //
    Stream->SendBookmark = Req;
}

//
// Writes data at the requested stream offset to a stream frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamWriteOneFrame(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN ExplicitDataLength,
    _In_ uint64_t Offset,
    _Inout_ uint16_t* FramePayloadBytes,
    _Inout_ uint16_t* FrameBytes,
    _Out_writes_bytes_(*FrameBytes) uint8_t* Buffer,
    _Inout_ QUIC_SENT_PACKET_METADATA* PacketMetadata
    )
{
    QUIC_STREAM_EX Frame = { FALSE, ExplicitDataLength, Stream->ID, Offset, 0, NULL };
    uint16_t HeaderLength = 0;

    //
    // First calculate the header length to make sure there's at least room for
    // the header.
    //
    HeaderLength = QuicStreamFrameHeaderSize(&Frame);
    if (*FrameBytes < HeaderLength) {
        QuicTraceLogStreamVerbose(
            NoMoreRoom,
            Stream,
            "Can't squeeze in a frame (no room for header)");
        *FramePayloadBytes = 0;
        *FrameBytes = 0;
        return;
    }

    //
    // Notes:
    // -the value passed in as FramePayloadBytes is an upper limit on payload bytes.
    // -even if Frame.Length becomes zero, we might still write an empty FIN frame.
    //
    Frame.Length = *FrameBytes - HeaderLength;
    if (Frame.Length > *FramePayloadBytes) {
        Frame.Length = *FramePayloadBytes;
    }
    if (Frame.Length > 0) {
        CXPLAT_DBG_ASSERT(Offset < Stream->QueuedSendOffset);
        if (Frame.Length > Stream->QueuedSendOffset - Offset) {
            Frame.Length = Stream->QueuedSendOffset - Offset;
            CXPLAT_DBG_ASSERT(Frame.Length > 0);
        }
        Frame.Data = Buffer + HeaderLength;
        QuicStreamCopyFromSendRequests(
            Stream, Offset, (uint8_t*)Frame.Data, (uint16_t)Frame.Length);
        Stream->Connection->Stats.Send.TotalStreamBytes += Frame.Length;
    }

    if ((Stream->SendFlags & QUIC_STREAM_SEND_FLAG_FIN) &&
        Frame.Offset + Frame.Length == Stream->QueuedSendOffset) {
        Frame.Fin = TRUE;

    } else if (Frame.Length == 0 &&
        !(Stream->SendFlags & QUIC_STREAM_SEND_FLAG_OPEN)) {
        //
        // No bytes, no immediate open and no FIN, so no frame.
        //
        QuicTraceLogStreamVerbose(
            NoMoreFrames,
            Stream,
            "No more frames");
        *FramePayloadBytes = 0;
        *FrameBytes = 0;
        return;
    }

    QuicTraceLogStreamVerbose(
        AddFrame,
        Stream,
        "Built stream frame, offset=%llu len=%hu fin=%hhu",
        Frame.Offset,
        (uint16_t)Frame.Length,
        Frame.Fin);

    uint16_t BufferLength = *FrameBytes;

    *FrameBytes = 0;
    *FramePayloadBytes = (uint16_t)Frame.Length;

    //
    // We're definitely writing a frame and we know how many bytes it contains,
    // so do the real call to QuicFrameEncodeStreamHeader to write the header.
    //
    if (!QuicStreamFrameEncode(&Frame, FrameBytes, BufferLength, Buffer)) {
        CXPLAT_FRE_ASSERT(FALSE);
    }

    PacketMetadata->Flags.IsAckEliciting = TRUE;
    PacketMetadata->Frames[PacketMetadata->FrameCount].Type = QUIC_FRAME_STREAM;
    PacketMetadata->Frames[PacketMetadata->FrameCount].STREAM.Stream = Stream;
    PacketMetadata->Frames[PacketMetadata->FrameCount].StreamOffset = Frame.Offset;
    PacketMetadata->Frames[PacketMetadata->FrameCount].StreamLength = (uint16_t)Frame.Length;
    PacketMetadata->Frames[PacketMetadata->FrameCount].Flags = 0;
    if (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_OPEN) {
        Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_OPEN;
        PacketMetadata->Frames[PacketMetadata->FrameCount].Flags |= QUIC_SENT_FRAME_FLAG_STREAM_OPEN;
    }
    if (Frame.Fin) {
        Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_FIN;
        PacketMetadata->Frames[PacketMetadata->FrameCount].Flags |= QUIC_SENT_FRAME_FLAG_STREAM_FIN;
    }
    QuicStreamSentMetadataIncrement(Stream);
    PacketMetadata->FrameCount++;
}

//
// Writes STREAM frames into a packet buffer. The ExplicitDataLength flag
// indicates the caller wants the stream to include the data length field
// in the stream header explicitly because it will try to add more frames
// afterwards.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamWriteStreamFrames(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN ExplicitDataLength,
    _Inout_ QUIC_SENT_PACKET_METADATA* PacketMetadata,
    _Inout_ uint16_t* BufferLength,
    _Out_writes_bytes_(*BufferLength) uint8_t* Buffer
    )
{
    QUIC_SEND* Send = &Stream->Connection->Send;
    uint16_t BytesWritten = 0;

    //
    // FUTURE: implicit data length when possible.
    //
    ExplicitDataLength = TRUE;

    //
    // Write frames until we've filled the provided space.
    //

    while (BytesWritten < *BufferLength &&
        PacketMetadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET) {

        //
        // Find the bounds of this frame. Left is the offset of the first byte
        // in the frame, and Right is the offset of the first byte AFTER the
        // frame.
        //
        uint64_t Left;
        uint64_t Right;

        BOOLEAN Recovery;
        if (RECOV_WINDOW_OPEN(Stream)) {
            Left = Stream->RecoveryNextOffset;
            Recovery = TRUE;
        } else {
            Left = Stream->NextSendOffset;
            Recovery = FALSE;
        }
        Right = Left + *BufferLength - BytesWritten;

        if (Recovery &&
            Right > Stream->RecoveryEndOffset &&
            Stream->RecoveryEndOffset != Stream->NextSendOffset) {
            Right = Stream->RecoveryEndOffset;
        }

        //
        // Find the first SACK after the selected offset.
        //
        QUIC_SUBRANGE* Sack;
        if (Left == Stream->MaxSentLength) {
            //
            // Transmitting new bytes; no such SACK can exist.
            //
            Sack = NULL;
        } else {
            uint32_t i = 0;
            while ((Sack = QuicRangeGetSafe(&Stream->SparseAckRanges, i++)) != NULL &&
                Sack->Low < Left) {
                CXPLAT_DBG_ASSERT(Sack->Low + Sack->Count <= Left);
            }
        }

        if (Sack != NULL) {
            if (Right > Sack->Low) {
                Right = Sack->Low;
            }
        } else {
            if (Right > Stream->QueuedSendOffset) {
                Right = Stream->QueuedSendOffset;
            }
        }

        //
        // Stream flow control
        //
        if (Right > Stream->MaxAllowedSendOffset) {
            Right = Stream->MaxAllowedSendOffset;
        }

        //
        // Connection flow control
        //
        const uint64_t MaxConnFlowControlOffset =
             Stream->MaxSentLength + (Send->PeerMaxData - Send->OrderedStreamBytesSent);
        if (Right > MaxConnFlowControlOffset) {
            Right = MaxConnFlowControlOffset;
        }

        //
        // It's OK for Right and Left to be equal because there are cases where
        // stream frames will be written with no payload (initial or FIN).
        //
        CXPLAT_DBG_ASSERT(Right >= Left);

        uint16_t FrameBytes = *BufferLength - BytesWritten;
        uint16_t FramePayloadBytes = (uint16_t)(Right - Left);

        QuicStreamWriteOneFrame(
            Stream,
            ExplicitDataLength,
            Left,
            &FramePayloadBytes,
            &FrameBytes,
            Buffer + BytesWritten,
            PacketMetadata);

        BOOLEAN ExitLoop = FALSE;

        //
        // When FramePayloadBytes is returned as zero, an empty stream frame may
        // still have been written (i.e. FramePayloadBytes might be 0 but
        // FrameBytes is not).
        //
        BytesWritten += FrameBytes;
        if (FramePayloadBytes == 0) {
            ExitLoop = TRUE;
        }

        //
        // Recalculate Right since FramePayloadBytes may have been reduced.
        //
        Right = Left + FramePayloadBytes;

        CXPLAT_DBG_ASSERT(Right <= Stream->QueuedSendOffset);
        if (Right == Stream->QueuedSendOffset) {
            QuicStreamAddOutFlowBlockedReason(Stream, QUIC_FLOW_BLOCKED_APP);
            ExitLoop = TRUE;
        }

        CXPLAT_DBG_ASSERT(Right <= Stream->MaxAllowedSendOffset);
        if (Right == Stream->MaxAllowedSendOffset) {
            if (QuicStreamAddOutFlowBlockedReason(
                    Stream, QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL)) {
                QuicSendSetStreamSendFlag(
                    &Stream->Connection->Send,
                    Stream, QUIC_STREAM_SEND_FLAG_DATA_BLOCKED, FALSE);
            }
            ExitLoop = TRUE;
        }

        CXPLAT_DBG_ASSERT(Right <= MaxConnFlowControlOffset);
        if (Right == MaxConnFlowControlOffset) {
            if (QuicConnAddOutFlowBlockedReason(
                    Stream->Connection, QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL)) {
                QuicSendSetSendFlag(
                    &Stream->Connection->Send,
                    QUIC_CONN_SEND_FLAG_DATA_BLOCKED);
            }
            ExitLoop = TRUE;
        }

        //
        // Move the "next" offset (RecoveryNextOffset if we are sending recovery
        // bytes or NextSendOffset otherwise) forward by the number of bytes
        // we've written. If we wrote up to the edge of a SACK, skip past the
        // SACK.
        //

        if (Recovery) {
            CXPLAT_DBG_ASSERT(Stream->RecoveryNextOffset <= Right);
            Stream->RecoveryNextOffset = Right;
            if (Sack && Stream->RecoveryNextOffset == Sack->Low) {
                Stream->RecoveryNextOffset += Sack->Count;
            }
        }

        if (Stream->NextSendOffset < Right) {
            Stream->NextSendOffset = Right;
            if (Sack && Stream->NextSendOffset == Sack->Low) {
                Stream->NextSendOffset += Sack->Count;
            }
        }

        if (Stream->MaxSentLength < Right) {
            Send->OrderedStreamBytesSent += Right - Stream->MaxSentLength;
            CXPLAT_DBG_ASSERT(Send->OrderedStreamBytesSent <= Send->PeerMaxData);
            Stream->MaxSentLength = Right;
        }

        QuicStreamValidateRecoveryState(Stream);

        if (ExitLoop) {
            break;
        }
    }

    QuicStreamSendDumpState(Stream);

    *BufferLength = BytesWritten;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicStreamSendWrite(
    _In_ QUIC_STREAM* Stream,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET);
    uint8_t PrevFrameCount = Builder->Metadata->FrameCount;
    BOOLEAN RanOutOfRoom = FALSE;
    const BOOLEAN IsInitial =
        (Stream->Connection->Stats.QuicVersion != QUIC_VERSION_2 && Builder->PacketType == QUIC_INITIAL_V1) ||
        (Stream->Connection->Stats.QuicVersion == QUIC_VERSION_2 && Builder->PacketType == QUIC_INITIAL_V2);

    uint16_t AvailableBufferLength =
        (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;

    CXPLAT_DBG_ASSERT(Stream->SendFlags != 0);
    CXPLAT_DBG_ASSERT(
        Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_1_RTT ||
        Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_0_RTT);
    CXPLAT_DBG_ASSERT(QuicStreamAllowedByPeer(Stream));

    QuicTraceEvent(
        StreamWriteFrames,
        "[strm][%p] Writing frames to packet %llu",
        Stream,
        Builder->Metadata->PacketId);

    if (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_MAX_DATA) {

        QUIC_MAX_STREAM_DATA_EX Frame = { Stream->ID, Stream->MaxAllowedRecvOffset };

        if (QuicMaxStreamDataFrameEncode(
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_MAX_DATA;
            if (QuicPacketBuilderAddStreamFrame(Builder, Stream, QUIC_FRAME_MAX_STREAM_DATA)) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    if (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_SEND_ABORT) {

        QUIC_RESET_STREAM_EX Frame = { Stream->ID, Stream->SendShutdownErrorCode, Stream->MaxSentLength };

        if (QuicResetStreamFrameEncode(
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_SEND_ABORT;
            if (QuicPacketBuilderAddStreamFrame(Builder, Stream, QUIC_FRAME_RESET_STREAM)) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    if (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_RECV_ABORT) {

        QUIC_STOP_SENDING_EX Frame = { Stream->ID, Stream->RecvShutdownErrorCode };

        if (QuicStopSendingFrameEncode(
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_RECV_ABORT;
            if (QuicPacketBuilderAddStreamFrame(Builder, Stream, QUIC_FRAME_STOP_SENDING)) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    if (HasStreamDataFrames(Stream->SendFlags) &&
        QuicStreamSendCanWriteDataFrames(Stream)) {

        uint16_t StreamFrameLength = AvailableBufferLength - Builder->DatagramLength;
        QuicStreamWriteStreamFrames(
            Stream,
            IsInitial,
            Builder->Metadata,
            &StreamFrameLength,
            Builder->Datagram->Buffer + Builder->DatagramLength);

        if (StreamFrameLength > 0) {
            CXPLAT_DBG_ASSERT(StreamFrameLength <= AvailableBufferLength - Builder->DatagramLength);
            Builder->DatagramLength += StreamFrameLength;

            if (!QuicStreamHasPendingStreamData(Stream)) {
                Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_DATA;
            }

            if (Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    if (Stream->SendFlags & QUIC_STREAM_SEND_FLAG_DATA_BLOCKED) {

        QUIC_STREAM_DATA_BLOCKED_EX Frame = { Stream->ID, Stream->NextSendOffset };

        if (QuicStreamDataBlockedFrameEncode(
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            Stream->SendFlags &= ~QUIC_STREAM_SEND_FLAG_DATA_BLOCKED;
            if (QuicPacketBuilderAddStreamFrame(Builder, Stream, QUIC_FRAME_STREAM_DATA_BLOCKED)) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    //
    // The only valid reason to not have framed anything is that there was too
    // little room left in the packet to fit anything more.
    //
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount > PrevFrameCount || RanOutOfRoom);
    UNREFERENCED_PARAMETER(RanOutOfRoom);

    return Builder->Metadata->FrameCount > PrevFrameCount;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicStreamOnLoss(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    )
{
    if (Stream->Flags.LocalCloseReset) {
        //
        // Ignore any STREAM frame packet loss if we have already aborted the
        // send path.
        //
        return FALSE;
    }

    uint32_t AddSendFlags = 0;

    uint64_t Start = FrameMetadata->StreamOffset;
    uint64_t End = Start + FrameMetadata->StreamLength;

    if ((FrameMetadata->Flags & QUIC_SENT_FRAME_FLAG_STREAM_OPEN) &&
        !Stream->Flags.SendOpenAcked) {
        AddSendFlags |= QUIC_STREAM_SEND_FLAG_OPEN;
        QuicTraceLogStreamVerbose(
            RecoverOpen,
            Stream,
            "Recovering open STREAM frame");
    }

    if ((FrameMetadata->Flags & QUIC_SENT_FRAME_FLAG_STREAM_FIN) &&
        !Stream->Flags.FinAcked) {
        AddSendFlags |= QUIC_STREAM_SEND_FLAG_FIN;
        QuicTraceLogStreamVerbose(
            RecoverFin,
            Stream,
            "Recovering fin STREAM frame");
    }

    //
    // First check to make sure this data wasn't already acknowledged in a
    // different packet.
    //

    if (End <= Stream->UnAckedOffset) {
        goto Done;
    } else if (Start < Stream->UnAckedOffset) {
        //
        // The 'lost' range overlaps with UNA. Move Start forward.
        //
        Start = Stream->UnAckedOffset;
    }

    QUIC_SUBRANGE* Sack;
    uint32_t i = 0;
    while ((Sack = QuicRangeGetSafe(&Stream->SparseAckRanges, i++)) != NULL &&
        Sack->Low < End) {
        if (Start < Sack->Low + Sack->Count) {
            //
            // This SACK overlaps with the 'lost' range.
            //
            if (Start >= Sack->Low) {
                //
                // The SACK fully covers the Start of the 'lost' range.
                //
                if (End <= Sack->Low + Sack->Count) {
                    //
                    // The SACK fully covers the whole 'lost' range.
                    //
                    goto Done;

                } else {
                    //
                    // The SACK only covers the beginning of the 'lost'
                    // range. Move Start forward to the end of the SACK.
                    //
                    Start = Sack->Low + Sack->Count;
                }

            } else if (End <= Sack->Low + Sack->Count) {
                //
                // The SACK fully covers the End of the 'lost' range. Move
                // the End backward to right before the SACK.
                //
                End = Sack->Low;

            } else {
                //
                // The SACK is fully covered by the 'lost' range. Don't do
                // anything special in this case, because we still have stuff
                // that needs to be retransmitted in that case.
                //
            }
        }
    }

    BOOLEAN UpdatedRecoveryWindow = FALSE;

    //
    // Expand the recovery window to encompass the stream frame that was lost.
    //

    if (Start < Stream->RecoveryNextOffset) {
        Stream->RecoveryNextOffset = Start;
        UpdatedRecoveryWindow = TRUE;
    }

    if (Stream->RecoveryEndOffset < End) {
        Stream->RecoveryEndOffset = End;
        UpdatedRecoveryWindow = TRUE;
    }

    if (UpdatedRecoveryWindow) {

        QuicTraceLogStreamVerbose(
            RecoverRange,
            Stream,
            "Recovering offset %llu up to %llu",
            Start,
            End);
        AddSendFlags |= QUIC_STREAM_SEND_FLAG_DATA;
    }

Done:

    if (AddSendFlags != 0) {

        if (!Stream->Flags.InRecovery) {
            Stream->Flags.InRecovery = TRUE; // TODO - Do we really need to be in recovery if no real data bytes need to be recovered?
        }

        BOOLEAN DataQueued =
            QuicSendSetStreamSendFlag(
                &Stream->Connection->Send,
                Stream,
                AddSendFlags,
                FALSE);

        QuicStreamSendDumpState(Stream);
        QuicStreamValidateRecoveryState(Stream);

        return DataQueued;
    }

    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamOnAck(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_SEND_PACKET_FLAGS PacketFlags,
    _In_ QUIC_SENT_FRAME_METADATA* FrameMetadata
    )
{
    uint64_t Offset = FrameMetadata->StreamOffset;
    uint32_t Length = FrameMetadata->StreamLength;

    //
    // The offset directly following this frame.
    //
    uint64_t FollowingOffset = Offset + Length;

    uint32_t RemoveSendFlags = 0;

    CXPLAT_DBG_ASSERT(FollowingOffset <= Stream->QueuedSendOffset);

    QuicTraceLogStreamVerbose(
        AckRangeMsg,
        Stream,
        "Received ack for %d bytes, offset=%llu, FF=0x%hx",
        (int32_t)Length,
        Offset,
        FrameMetadata->Flags);

    if (PacketFlags.KeyType == QUIC_PACKET_KEY_0_RTT &&
        Stream->Sent0Rtt < FollowingOffset) {
        Stream->Sent0Rtt = FollowingOffset;
        QuicTraceLogStreamVerbose(
            Send0RttUpdated,
            Stream,
            "Updated sent 0RTT length to %llu",
            FollowingOffset);
    }

    if (!Stream->Flags.SendOpenAcked) {
        //
        // The peer has acknowledged a STREAM frame, so they definitely know
        // the stream is open.
        //
        Stream->Flags.SendOpenAcked = TRUE;
        RemoveSendFlags |= QUIC_STREAM_SEND_FLAG_OPEN;
    }

    if (FrameMetadata->Flags & QUIC_SENT_FRAME_FLAG_STREAM_FIN) {
        Stream->Flags.FinAcked = TRUE;
        RemoveSendFlags |= QUIC_STREAM_SEND_FLAG_FIN;
    }

    if (Offset <= Stream->UnAckedOffset) {

        //
        // No unacknowledged bytes before this ACK. If any new
        // bytes are acknowledged then we'll advance UnAckedOffset.
        //

        if (Stream->UnAckedOffset < FollowingOffset) {

            Stream->UnAckedOffset = FollowingOffset;

            //
            // Delete any SACKs that UnAckedOffset caught up to.
            //
            QuicRangeSetMin(&Stream->SparseAckRanges, Stream->UnAckedOffset);

            QUIC_SUBRANGE* Sack = QuicRangeGetSafe(&Stream->SparseAckRanges, 0);
            if (Sack && Sack->Low == Stream->UnAckedOffset) {
                Stream->UnAckedOffset = Sack->Low + Sack->Count;
                QuicRangeRemoveSubranges(&Stream->SparseAckRanges, 0, 1);
            }

            if (Stream->NextSendOffset < Stream->UnAckedOffset) {
                Stream->NextSendOffset = Stream->UnAckedOffset;
            }
            if (Stream->RecoveryNextOffset < Stream->UnAckedOffset) {
                Stream->RecoveryNextOffset = Stream->UnAckedOffset;
            }
            if (Stream->RecoveryEndOffset < Stream->UnAckedOffset) {
                Stream->Flags.InRecovery = FALSE;
            }
        }

        //
        // Pop any fully-ACKed send requests. Note that we complete send
        // requests in the order that they are queued.
        //
        while (Stream->SendRequests) {

            QUIC_SEND_REQUEST* Req = Stream->SendRequests;

            //
            // Cannot complete a request until UnAckedOffset is all the way past it.
            //
            if (Req->StreamOffset + Req->TotalLength > Stream->UnAckedOffset) {
                break;
            }

            Stream->SendRequests = Req->Next;
            if (Stream->SendRequests == NULL) {
                Stream->SendRequestsTail = &Stream->SendRequests;
            }

            QuicStreamCompleteSendRequest(Stream, Req, FALSE, TRUE);
        }

        if (Stream->UnAckedOffset == Stream->QueuedSendOffset && Stream->Flags.FinAcked) {
            CXPLAT_DBG_ASSERT(Stream->SendRequests == NULL);

            QuicTraceLogStreamVerbose(
                SendQueueDrained,
                Stream,
                "Send queue completely drained");

            //
            // We have completely sent all that needs to be sent. Update the Stream
            // state to reflect this and try to complete the Stream close if the
            // receive path has already been closed.
            //
            if (!Stream->Flags.LocalCloseAcked) {
                Stream->Flags.LocalCloseAcked = TRUE;
                QuicTraceEvent(
                    StreamSendState,
                    "[strm][%p] Send State: %hhu",
                    Stream,
                    QuicStreamSendGetState(Stream));
                QuicStreamIndicateSendShutdownComplete(Stream, TRUE);
                QuicStreamTryCompleteShutdown(Stream);
            }
        }

    } else {

        BOOLEAN SacksUpdated;
        QUIC_SUBRANGE* Sack =
            QuicRangeAddRange(
                &Stream->SparseAckRanges,
                Offset,
                Length,
                &SacksUpdated);
        if (Sack == NULL) {

            QuicConnTransportError(Stream->Connection, QUIC_ERROR_INTERNAL_ERROR);

        } else if (SacksUpdated) {

            //
            // Sack points to a new or expanded SACK, and any bytes that are
            // newly ACKed are covered by this SACK.
            //

            //
            // In QuicStreamSendWrite we assume that the starting offset
            // (NextSendOffset or RecoveryNextOffset) is not acknowledged, so
            // fix up these two offsets.
            //
            if (Stream->NextSendOffset >= Sack->Low &&
                Stream->NextSendOffset < Sack->Low + Sack->Count) {
                Stream->NextSendOffset = Sack->Low + Sack->Count;
            }
            if (Stream->RecoveryNextOffset >= Sack->Low &&
                Stream->RecoveryNextOffset < Sack->Low + Sack->Count) {
                Stream->RecoveryNextOffset = Sack->Low + Sack->Count;
            }
        }
    }

    if (!QuicStreamHasPendingStreamData(Stream)) {
        //
        // Make sure the stream isn't queued to send any stream data.
        //
        RemoveSendFlags |= QUIC_STREAM_SEND_FLAG_DATA;
    }

    if (RemoveSendFlags != 0) {
        QuicSendClearStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            RemoveSendFlags);
    }

    QuicStreamSendDumpState(Stream);
    QuicStreamValidateRecoveryState(Stream);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamOnResetAck(
    _In_ QUIC_STREAM* Stream
    )
{
    if (!Stream->Flags.LocalCloseAcked) {
        Stream->Flags.LocalCloseAcked = TRUE;
        QuicTraceEvent(
            StreamSendState,
            "[strm][%p] Send State: %hhu",
            Stream,
            QuicStreamSendGetState(Stream));
        QuicStreamIndicateSendShutdownComplete(Stream, FALSE);
        QuicStreamTryCompleteShutdown(Stream);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamSendDumpState(
    _In_ QUIC_STREAM* Stream
    )
{
    if (QuicTraceLogStreamVerboseEnabled()) {

        QuicTraceLogStreamVerbose(
            SendDump,
            Stream,
            "SF:%hX FC:%llu QS:%llu MAX:%llu UNA:%llu NXT:%llu RECOV:%llu-%llu",
            Stream->SendFlags,
            Stream->MaxAllowedSendOffset,
            Stream->QueuedSendOffset,
            Stream->MaxSentLength,
            Stream->UnAckedOffset,
            Stream->NextSendOffset,
            Stream->Flags.InRecovery ? Stream->RecoveryNextOffset : 0,
            Stream->Flags.InRecovery ? Stream->RecoveryEndOffset : 0);

        uint64_t UnAcked = Stream->UnAckedOffset;
        uint32_t i = 0;
        QUIC_SUBRANGE* Sack;
        while ((Sack = QuicRangeGetSafe(&Stream->SparseAckRanges, i++)) != NULL) {
            QuicTraceLogStreamVerbose(
                SendDumpAck,
                Stream,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Sack->Low);
            UnAcked = Sack->Low + Sack->Count;
        }
        if (UnAcked < Stream->MaxSentLength) {
            QuicTraceLogStreamVerbose(
                SendDumpAck,
                Stream,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Stream->MaxSentLength);
        }

        CXPLAT_DBG_ASSERT(Stream->NextSendOffset <= Stream->MaxAllowedSendOffset);
        CXPLAT_DBG_ASSERT(Stream->UnAckedOffset <= Stream->NextSendOffset);
        if (Stream->Flags.InRecovery) {
            CXPLAT_DBG_ASSERT(Stream->UnAckedOffset <= Stream->RecoveryNextOffset);
        }
    }
}
