/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A stream manages the send and receive queues for application data. This file
    contains the receive specific logic for the stream.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "stream_recv.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicStreamReceiveComplete(
    _In_ QUIC_STREAM* Stream,
    _In_ uint64_t BufferLength
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamProcessResetFrame(
    _In_ QUIC_STREAM* Stream,
    _In_ uint64_t FinalSize,
    _In_ QUIC_VAR_INT ErrorCode
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamRecvShutdown(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN Silent,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    if (Silent) {
        //
        // If we are silently closing, implicitly consider the remote stream as
        // closed and acknowledged as such.
        //
        Stream->Flags.SentStopSending = TRUE;
        Stream->Flags.RemoteCloseAcked = TRUE;
        Stream->Flags.ReceiveEnabled = FALSE;
        Stream->Flags.ReceiveDataPending = FALSE;
        goto Exit;
    }

    if (Stream->Flags.RemoteCloseAcked ||
        Stream->Flags.RemoteCloseFin ||
        Stream->Flags.RemoteCloseReset) {
        //
        // The peer already closed (graceful or abortive). Nothing else to be
        // done.
        //
        goto Exit;
    }

    if (Stream->Flags.SentStopSending) {
        //
        // We've already aborted locally. Just ignore any additional shutdowns.
        //
        goto Exit;
    }

    //
    // Disable all future receive events.
    //
    Stream->Flags.ReceiveEnabled = FALSE;
    Stream->Flags.ReceiveDataPending = FALSE;

    Stream->RecvShutdownErrorCode = ErrorCode;
    Stream->Flags.SentStopSending = TRUE;

    if (Stream->RecvMaxLength != UINT64_MAX) {
        //
        // The peer has already gracefully closed, but we just haven't drained
        // the receives to that point. Just treat the shutdown as if it was
        // already acknowledged by a reset frame.
        //
        QuicStreamProcessResetFrame(Stream, Stream->RecvMaxLength, 0);
        Silent = TRUE; // To indicate we try to shutdown complete.
        goto Exit;
    }

    //
    // Queue up a stop sending frame to be sent.
    //
    QuicSendSetStreamSendFlag(
        &Stream->Connection->Send,
        Stream,
        QUIC_STREAM_SEND_FLAG_RECV_ABORT,
        FALSE);

    //
    // Remove any flags we shouldn't be sending now the receive direction is
    // closed.
    //
    QuicSendClearStreamSendFlag(
        &Stream->Connection->Send,
        Stream,
        QUIC_STREAM_SEND_FLAG_MAX_DATA);

Exit:

    QuicTraceEvent(
        StreamRecvState,
        "[strm][%p] Recv State: %hhu",
        Stream,
        QuicStreamRecvGetState(Stream));

    if (Silent) {
        QuicStreamTryCompleteShutdown(Stream);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamRecvQueueFlush(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN AllowInlineFlush
    )
{
    //
    // The caller has indicated data is ready to be indicated to the
    // application. Queue a FLUSH_RECV if one isn't already queued.
    //
    if (Stream->Flags.ReceiveEnabled && Stream->Flags.ReceiveDataPending) {

        if (AllowInlineFlush) {
            QuicStreamRecvFlush(Stream);

        } else if (!Stream->Flags.ReceiveFlushQueued) {
            QuicTraceLogStreamVerbose(
                QueueRecvFlush,
                Stream,
                "Queuing recv flush");

            QUIC_OPERATION* Oper;
            if ((Oper = QuicOperationAlloc(Stream->Connection->Worker, QUIC_OPER_TYPE_FLUSH_STREAM_RECV)) != NULL) {
                Oper->FLUSH_STREAM_RECEIVE.Stream = Stream;
                QuicStreamAddRef(Stream, QUIC_STREAM_REF_OPERATION);
                QuicConnQueueOper(Stream->Connection, Oper);
                Stream->Flags.ReceiveFlushQueued = TRUE;
            } else {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "Flush Stream Recv operation",
                    0);
            }
        }
    }
}

//
// Deliver a notification to the app that the peer has aborted their send path.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicatePeerSendAbortedEvent(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    QuicTraceLogStreamInfo(
        RemoteCloseReset,
        Stream,
        "Closed remotely (reset)");
    QUIC_STREAM_EVENT Event;
    Event.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
    Event.PEER_SEND_ABORTED.ErrorCode = ErrorCode;
    QuicTraceLogStreamVerbose(
        IndicatePeerSendAbort,
        Stream,
        "Indicating QUIC_STREAM_EVENT_PEER_SEND_ABORTED (0x%llX)",
        ErrorCode);
    (void)QuicStreamIndicateEvent(Stream, &Event);
}

//
// Processes a received RELIABLE_RESET frame's payload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamProcessReliableResetFrame(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_VAR_INT ErrorCode,
    _In_ QUIC_VAR_INT ReliableOffset
    )
{
    if (!Stream->Connection->State.ReliableResetStreamNegotiated) {
        //
        // The peer tried to use an exprimental feature without
        // negotiating first. Kill the connection.
        //
        QuicTraceLogStreamWarning(
            ReliableResetNotNegotiatedError,
            Stream,
            "Received ReliableReset without negotiation.");
        QuicConnTransportError(Stream->Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
        return;
    }

    if (Stream->RecvMaxLength == 0 || ReliableOffset < Stream->RecvMaxLength) {
        //
        // As outlined in the spec, if we receive multiple CLOSE_STREAM frames, we only accept strictly
        // decreasing offsets.
        //
        Stream->RecvMaxLength = ReliableOffset;
        Stream->Flags.RemoteCloseResetReliable = TRUE;

        QuicTraceLogStreamInfo(
            ReliableRecvOffsetSet,
            Stream,
            "Reliable recv offset set to %llu",
            ReliableOffset);
    }

    if (Stream->RecvBuffer.BaseOffset >= Stream->RecvMaxLength) {
        QuicTraceEvent(
            StreamRecvState,
            "[strm][%p] Recv State: %hhu",
            Stream,
            QuicStreamRecvGetState(Stream));
        QuicStreamIndicatePeerSendAbortedEvent(Stream, ErrorCode);
        QuicStreamRecvShutdown(Stream, TRUE, ErrorCode);
    } else {
        //
        // We still have data to deliver to the app, just cache the error code for later.
        //
        Stream->RecvShutdownErrorCode = ErrorCode;
    }
}

//
// Processes a received RESET_STREAM frame's payload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamProcessResetFrame(
    _In_ QUIC_STREAM* Stream,
    _In_ uint64_t FinalSize,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    //
    // Make sure the stream is remotely closed if not already.
    //
    Stream->Flags.RemoteCloseReset = TRUE;

    if (!Stream->Flags.RemoteCloseAcked) {
        Stream->Flags.RemoteCloseAcked = TRUE;
        Stream->Flags.ReceiveEnabled = FALSE;
        Stream->Flags.ReceiveDataPending = FALSE;

        uint64_t TotalRecvLength = QuicRecvBufferGetTotalLength(&Stream->RecvBuffer);
        if (TotalRecvLength > FinalSize) {
            //
            // The peer indicated a final offset less than what they have
            // already sent to us. Kill the connection.
            //
            QuicTraceLogStreamWarning(
                ResetEarly,
                Stream,
                "Tried to reset at earlier final size!");
            QuicConnTransportError(Stream->Connection, QUIC_ERROR_FINAL_SIZE_ERROR);
            return;
        }

        if (TotalRecvLength < FinalSize) {
            //
            // The final offset is indicating that more data was sent than we
            // have actually received. Make sure to update our flow control
            // accounting so we stay in sync with the peer.
            //
            uint64_t FlowControlIncrease = FinalSize - TotalRecvLength;
            Stream->Connection->Send.OrderedStreamBytesReceived += FlowControlIncrease;
            if (Stream->Connection->Send.OrderedStreamBytesReceived < FlowControlIncrease ||
                Stream->Connection->Send.OrderedStreamBytesReceived > Stream->Connection->Send.MaxData) {
                //
                // The peer indicated a final offset more than allowed. Kill the
                // connection.
                //
                QuicTraceLogStreamWarning(
                    ResetTooBig,
                    Stream,
                    "Tried to reset with too big final size!");
                QuicConnTransportError(Stream->Connection, QUIC_ERROR_FINAL_SIZE_ERROR);
                return;
            }
        }

        uint64_t TotalReadLength = Stream->RecvBuffer.BaseOffset;
        if (TotalReadLength < FinalSize) {
            //
            // The final offset is indicating that more data was sent than the
            // app has completely read. Make sure to give the peer more credit
            // as a result.
            //
            uint64_t FlowControlIncrease = FinalSize - TotalReadLength;
            Stream->Connection->Send.MaxData += FlowControlIncrease;
            QuicSendSetSendFlag(
                &Stream->Connection->Send,
                QUIC_CONN_SEND_FLAG_MAX_DATA);
        }

        QuicTraceEvent(
            StreamRecvState,
            "[strm][%p] Recv State: %hhu",
            Stream,
            QuicStreamRecvGetState(Stream));

        if (!Stream->Flags.SentStopSending) {
            QuicStreamIndicatePeerSendAbortedEvent(Stream, ErrorCode);
        }

        //
        // Remove any flags we shouldn't be sending now that the receive
        // direction is closed.
        //
        QuicSendClearStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_MAX_DATA | QUIC_STREAM_SEND_FLAG_RECV_ABORT);

        QuicStreamTryCompleteShutdown(Stream);
    }
}

//
// Processes a received STOP_SENDING frame's payload.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamProcessStopSendingFrame(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    if (!Stream->Flags.LocalCloseAcked && !Stream->Flags.LocalCloseReset) {
        //
        // The STOP_SENDING frame only triggers a state change if we aren't
        // completely closed gracefully (i.e. our close has been acknowledged)
        // or if we have already been reset (abortive closure).
        //
        QuicTraceLogStreamInfo(
            LocalCloseStopSending,
            Stream,
            "Closed locally (stop sending)");
        Stream->Flags.ReceivedStopSending = TRUE;

        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED;
        Event.PEER_RECEIVE_ABORTED.ErrorCode = ErrorCode;
        QuicTraceLogStreamVerbose(
            IndicatePeerReceiveAborted,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED (0x%llX)",
            ErrorCode);
        (void)QuicStreamIndicateEvent(Stream, &Event);

        //
        // The peer has requested that we stop sending. Close abortively.
        //
        QuicStreamSendShutdown(
            Stream, FALSE, FALSE, FALSE, QUIC_ERROR_NO_ERROR);
    }
}

//
// Processes a STREAM frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamProcessStreamFrame(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN EncryptedWith0Rtt,
    _In_ const QUIC_STREAM_EX* Frame
    )
{
    QUIC_STATUS Status;
    BOOLEAN ReadyToDeliver = FALSE;
    uint64_t EndOffset = Frame->Offset + Frame->Length;

    if (Stream->Flags.RemoteNotAllowed) {
        QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Receive on unidirectional stream");
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    if (Stream->Flags.RemoteCloseFin || Stream->Flags.RemoteCloseReset) {
        //
        // Ignore the data if we are already closed remotely. Likely means we
        // received a copy of already processed data that was resent.
        //
        QuicTraceLogStreamVerbose(
            IgnoreRecvAfterClose,
            Stream,
            "Ignoring recv after close");
        Status = QUIC_STATUS_SUCCESS;
        goto Error;
    }

    if (Stream->Flags.SentStopSending) {
        //
        // The app has already aborting the receive path, but the peer might end
        // up sending a FIN instead of a reset. Ignore the data but treat any
        // FIN as a reset.
        //
        if (Frame->Fin) {
            QuicTraceLogStreamInfo(
                TreatFinAsReset,
                Stream,
                "Treating FIN after receive abort as reset");
            QuicStreamProcessResetFrame(Stream, Frame->Offset + Frame->Length, 0);

        } else {
            QuicTraceLogStreamVerbose(
                IgnoreRecvAfterAbort,
                Stream,
                "Ignoring received frame after receive abort");
        }
        Status = QUIC_STATUS_SUCCESS;
        goto Error;
    }

    if (Frame->Fin && Stream->RecvMaxLength != UINT64_MAX &&
        EndOffset != Stream->RecvMaxLength) {
        //
        // FIN disagrees with previous FIN.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Stream->Flags.RemoteCloseResetReliable) {
        if (Stream->RecvBuffer.BaseOffset >= Stream->RecvMaxLength) {
            //
            // We've aborted reliably, but the stream goes past reliable offset, we can just
            // ignore it.
            //
            Status = QUIC_STATUS_SUCCESS;
            goto Error;
        }
    } else if (EndOffset > Stream->RecvMaxLength) {
        //
        // Frame goes past the FIN, and the stream is not reset reliably.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (EndOffset > QUIC_VAR_INT_MAX) {
        //
        // Stream data cannot exceed VAR_INT_MAX because it's impossible
        // to provide flow control credit for that data.
        //
        QuicConnTransportError(Stream->Connection, QUIC_ERROR_FLOW_CONTROL_ERROR);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    if (Frame->Length == 0) {

        Status = QUIC_STATUS_SUCCESS;

    } else {

        //
        // This is initialized to inform QuicRecvBufferWrite of the
        // max number of allowed bytes per connection flow control.
        // On return from QuicRecvBufferWrite, this represents the
        // actual number of bytes written.
        //
        uint64_t WriteLength =
            Stream->Connection->Send.MaxData -
            Stream->Connection->Send.OrderedStreamBytesReceived;

        //
        // Write any nonduplicate data to the receive buffer.
        // QuicRecvBufferWrite will indicate if there is data to deliver.
        //
        Status =
            QuicRecvBufferWrite(
                &Stream->RecvBuffer,
                Frame->Offset,
                (uint16_t)Frame->Length,
                Frame->Data,
                &WriteLength,
                &ReadyToDeliver);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        //
        // Keep track of the total ordered bytes received.
        //
        Stream->Connection->Send.OrderedStreamBytesReceived += WriteLength;
        CXPLAT_DBG_ASSERT(Stream->Connection->Send.OrderedStreamBytesReceived <= Stream->Connection->Send.MaxData);
        CXPLAT_DBG_ASSERT(Stream->Connection->Send.OrderedStreamBytesReceived >= WriteLength);

        if (QuicRecvBufferGetTotalLength(&Stream->RecvBuffer) == Stream->MaxAllowedRecvOffset) {
            QuicTraceLogStreamVerbose(
                FlowControlExhausted,
                Stream,
                "Flow control window exhausted!");
        }

        if (EncryptedWith0Rtt) {
            //
            // Keep track of the maximum length of the 0-RTT payload so that we
            // can indicate that appropriately to the API client.
            //
            if (EndOffset > Stream->RecvMax0RttLength) {
                Stream->RecvMax0RttLength = EndOffset;
            }
        }

        Stream->Connection->Stats.Recv.TotalStreamBytes += Frame->Length;
    }

    if (Frame->Fin) {
        Stream->RecvMaxLength = EndOffset;
        if (Stream->RecvBuffer.BaseOffset == Stream->RecvMaxLength) {
            //
            // All data delivered. Deliver the FIN.
            //
            ReadyToDeliver = TRUE;
        }
    }

    if (ReadyToDeliver &&
        (Stream->RecvBuffer.RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE ||
         Stream->RecvBuffer.ReadPendingLength == 0)) {
        Stream->Flags.ReceiveDataPending = TRUE;
        QuicStreamRecvQueueFlush(
            Stream,
            Stream->RecvBuffer.BaseOffset == Stream->RecvMaxLength);
    }

    QuicTraceLogStreamVerbose(
        Receive,
        Stream,
        "Received %hu bytes, offset=%llu Ready=%hhu",
        (uint16_t)Frame->Length,
        Frame->Offset,
        ReadyToDeliver);

Error:

    if (Status == QUIC_STATUS_INVALID_PARAMETER) {
        QuicTraceLogStreamWarning(
            ReceiveTooBig,
            Stream,
            "Tried to write beyond end of buffer!");
        QuicConnTransportError(Stream->Connection, QUIC_ERROR_FINAL_SIZE_ERROR);
    } else if (Status == QUIC_STATUS_BUFFER_TOO_SMALL) {
        QuicTraceLogStreamWarning(
            ReceiveBeyondFlowControl,
            Stream,
            "Tried to write beyond flow control limit!");
        QuicConnTransportError(Stream->Connection, QUIC_ERROR_FLOW_CONTROL_ERROR);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamRecv(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _Inout_ uint16_t* Offset,
    _Inout_ BOOLEAN* UpdatedFlowControl
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QuicTraceEvent(
        StreamReceiveFrame,
        "[strm][%p] Processing frame in packet %llu",
        Stream,
        Packet->PacketId);

    switch (FrameType) {

    case QUIC_FRAME_RESET_STREAM: {
        QUIC_RESET_STREAM_EX Frame;
        if (!QuicResetStreamFrameDecode(BufferLength, Buffer, Offset, &Frame)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QuicStreamProcessResetFrame(
            Stream,
            Frame.FinalSize,
            Frame.ErrorCode);

        break;
    }

    case QUIC_FRAME_STOP_SENDING: {
        QUIC_STOP_SENDING_EX Frame;
        if (!QuicStopSendingFrameDecode(BufferLength, Buffer, Offset, &Frame)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QuicStreamProcessStopSendingFrame(
            Stream, Frame.ErrorCode);

        break;
    }

    case QUIC_FRAME_MAX_STREAM_DATA: {
        QUIC_MAX_STREAM_DATA_EX Frame;
        if (!QuicMaxStreamDataFrameDecode(BufferLength, Buffer, Offset, &Frame)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (Stream->MaxAllowedSendOffset < Frame.MaximumData) {
            Stream->MaxAllowedSendOffset = Frame.MaximumData;
            *UpdatedFlowControl = TRUE;

            //
            // NB: If there are ACK frames that advance UnAckedOffset after this
            // MAX_STREAM_DATA frame in the current packet, then SendWindow will
            // overestimate the peer's flow control window. If the peer is
            // MSQUIC, this problem will not occur because ACK frames always
            // come first. Other implementations will probably do the same.
            // This potential problem could be fixed by moving the SendWindow
            // update to the end of packet processing, but that would require
            // tracking the set of streams for which the packet advanced
            // MAX_STREAM_DATA.
            //
            Stream->SendWindow =
                (uint32_t)CXPLAT_MIN(Stream->MaxAllowedSendOffset - Stream->UnAckedOffset, UINT32_MAX);

            QuicSendBufferStreamAdjust(Stream);

            //
            // The peer has given us more allowance. In case the stream was
            // queued and blocked, schedule a send flush.
            //
            QuicStreamRemoveOutFlowBlockedReason(
                Stream, QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL);
            QuicSendClearStreamSendFlag(
                &Stream->Connection->Send,
                Stream,
                QUIC_STREAM_SEND_FLAG_DATA_BLOCKED);
            QuicStreamSendDumpState(Stream);

            QuicSendQueueFlush(
                &Stream->Connection->Send,
                REASON_STREAM_FLOW_CONTROL);
        }

        break;
    }

    case QUIC_FRAME_STREAM_DATA_BLOCKED: {
        QUIC_STREAM_DATA_BLOCKED_EX Frame;
        if (!QuicStreamDataBlockedFrameDecode(BufferLength, Buffer, Offset, &Frame)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QuicTraceLogStreamVerbose(
            RemoteBlocked,
            Stream,
            "Remote FC blocked (%llu)",
            Frame.StreamDataLimit);

        QuicSendSetStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_MAX_DATA,
            FALSE);

        break;
    }

    case QUIC_FRAME_RELIABLE_RESET_STREAM: {
        QUIC_RELIABLE_RESET_STREAM_EX Frame;
        if (!QuicReliableResetFrameDecode(BufferLength, Buffer, Offset, &Frame)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QuicStreamProcessReliableResetFrame(
            Stream,
            Frame.ErrorCode,
            Frame.ReliableSize);

        break;
    }

    default: // QUIC_FRAME_STREAM*
    {
        QUIC_STREAM_EX Frame;
        if (!QuicStreamFrameDecode(FrameType, BufferLength, Buffer, Offset, &Frame)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        Status =
            QuicStreamProcessStreamFrame(
                Stream, Packet->EncryptedWith0Rtt, &Frame);

        break;
    }
    }

    QuicTraceEvent(
        StreamReceiveFrameComplete,
        "[strm][%p] Done processing frame",
        Stream);

    return Status;
}

//
// Criteria for sending MAX_DATA/MAX_STREAM_DATA frames:
//
// Whenever bytes are delivered on a stream, a MAX_STREAM_DATA frame is sent if an ACK
// is already queued, or if the buffer tuning algorithm below increases the buffer size.
//
// The connection-wide MAX_DATA frame is sent independently from MAX_STREAM_DATA (see use
// of OrderedStreamBytesDeliveredAccumulator). This prevents issues in corner cases, like
// when many short streams are used, in which case we might never actually send a
// MAX_STREAM_DATA update since each stream's entire payload fits in the initial window.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamOnBytesDelivered(
    _In_ QUIC_STREAM* Stream,
    _In_ uint64_t BytesDelivered
    )
{
    const uint64_t RecvBufferDrainThreshold =
        Stream->RecvBuffer.VirtualBufferLength / QUIC_RECV_BUFFER_DRAIN_RATIO;

    Stream->RecvWindowBytesDelivered += BytesDelivered;
    Stream->Connection->Send.MaxData += BytesDelivered;

    Stream->Connection->Send.OrderedStreamBytesDeliveredAccumulator += BytesDelivered;
    if (Stream->Connection->Send.OrderedStreamBytesDeliveredAccumulator >=
        Stream->Connection->Settings.ConnFlowControlWindow / QUIC_RECV_BUFFER_DRAIN_RATIO) {
        Stream->Connection->Send.OrderedStreamBytesDeliveredAccumulator = 0;
        QuicSendSetSendFlag(
            &Stream->Connection->Send,
            QUIC_CONN_SEND_FLAG_MAX_DATA);
    }

    if (Stream->RecvWindowBytesDelivered >= RecvBufferDrainThreshold) {

        uint64_t TimeNow = CxPlatTimeUs64();

        //
        // Limit stream FC window growth by the connection FC window size.
        //
        if (Stream->RecvBuffer.VirtualBufferLength <
            Stream->Connection->Settings.ConnFlowControlWindow) {

            uint64_t TimeThreshold =
                ((Stream->RecvWindowBytesDelivered * Stream->Connection->Paths[0].SmoothedRtt) / RecvBufferDrainThreshold);
            if (CxPlatTimeDiff64(Stream->RecvWindowLastUpdate, TimeNow) <= TimeThreshold) {

                //
                // Buffer tuning:
                //
                // VirtualBufferLength limits the connection's throughput to:
                //   R = VirtualBufferLength / RTT
                //
                // We've delivered data at an average rate of at least:
                //   R / QUIC_RECV_BUFFER_DRAIN_RATIO
                //
                // Double VirtualBufferLength to make sure it doesn't limit
                // throughput.
                //
                // Mainly people complain about flow control when it limits
                // throughput. But if we grow the buffer limit and then the app
                // stops receiving data, bytes will pile up in the buffer. We could
                // add logic to shrink the buffer when the app absorb rate is too
                // low.
                //

                QuicTraceLogStreamVerbose(
                    IncreaseRxBuffer,
                    Stream,
                    "Increasing max RX buffer size to %u (MinRtt=%llu; TimeNow=%llu; LastUpdate=%llu)",
                    Stream->RecvBuffer.VirtualBufferLength * 2,
                    Stream->Connection->Paths[0].MinRtt,
                    TimeNow,
                    Stream->RecvWindowLastUpdate);

                QuicRecvBufferIncreaseVirtualBufferLength(
                    &Stream->RecvBuffer,
                    Stream->RecvBuffer.VirtualBufferLength * 2);
            }
        }

        Stream->RecvWindowLastUpdate = TimeNow;
        Stream->RecvWindowBytesDelivered = 0;

    } else if (!(Stream->Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK)) {
        //
        // We haven't hit the drain limit AND we don't have any ACKs to send
        // immediately, so we don't need to immediately update the max stream data
        // values.
        //
        return;
    }

    //
    // Advance MaxAllowedRecvOffset.
    //

    QuicTraceLogStreamVerbose(
        UpdateFlowControl,
        Stream,
        "Updating flow control window");

    CXPLAT_DBG_ASSERT(
        Stream->RecvBuffer.BaseOffset + Stream->RecvBuffer.VirtualBufferLength >
        Stream->MaxAllowedRecvOffset);

    Stream->MaxAllowedRecvOffset =
        Stream->RecvBuffer.BaseOffset + Stream->RecvBuffer.VirtualBufferLength;

    QuicSendSetSendFlag(
        &Stream->Connection->Send,
        QUIC_CONN_SEND_FLAG_MAX_DATA);
    QuicSendSetStreamSendFlag(
        &Stream->Connection->Send,
        Stream,
        QUIC_STREAM_SEND_FLAG_MAX_DATA,
        FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamRecvFlush(
    _In_ QUIC_STREAM* Stream
    )
{
    Stream->Flags.ReceiveFlushQueued = FALSE;

    if (!Stream->Flags.ReceiveDataPending) {
        //
        // Means flush was executed inline already.
        //
        return;
    }

    if (!Stream->Flags.ReceiveEnabled) {
        QuicTraceLogStreamVerbose(
            IgnoreRecvFlush,
            Stream,
            "Ignoring recv flush (recv disabled)");
        return;
    }

    BOOLEAN FlushRecv = TRUE;
    while (FlushRecv) {
        CXPLAT_DBG_ASSERT(!Stream->Flags.SentStopSending);

        QUIC_BUFFER RecvBuffers[3];
        QUIC_STREAM_EVENT Event = {0};
        Event.Type = QUIC_STREAM_EVENT_RECEIVE;
        Event.RECEIVE.BufferCount = ARRAYSIZE(RecvBuffers);
        Event.RECEIVE.Buffers = RecvBuffers;

        //
        // Try to read the next available buffers.
        //
        BOOLEAN DataAvailable = QuicRecvBufferHasUnreadData(&Stream->RecvBuffer);
        if (DataAvailable) {
            QuicRecvBufferRead(
                &Stream->RecvBuffer,
                &Event.RECEIVE.AbsoluteOffset,
                &Event.RECEIVE.BufferCount,
                RecvBuffers);
            for (uint32_t i = 0; i < Event.RECEIVE.BufferCount; ++i) {
                Event.RECEIVE.TotalBufferLength += RecvBuffers[i].Length;
            }
            CXPLAT_DBG_ASSERT(Event.RECEIVE.TotalBufferLength != 0);

            if (Event.RECEIVE.AbsoluteOffset < Stream->RecvMax0RttLength) {
                //
                // This data includes data encrypted with 0-RTT key.
                //
                Event.RECEIVE.Flags |= QUIC_RECEIVE_FLAG_0_RTT;

                //
                // TODO - Split mixed 0-RTT and 1-RTT data?
                //
            }

            if (Event.RECEIVE.AbsoluteOffset + Event.RECEIVE.TotalBufferLength == Stream->RecvMaxLength) {
                //
                // This data goes all the way to the FIN.
                //
                Event.RECEIVE.Flags |= QUIC_RECEIVE_FLAG_FIN;
            }

        } else {
            //
            // FIN only case.
            //
            Event.RECEIVE.AbsoluteOffset = Stream->RecvMaxLength;
            Event.RECEIVE.BufferCount = 0;
            Event.RECEIVE.Flags |= QUIC_RECEIVE_FLAG_FIN; // TODO - 0-RTT flag?
        }

        Stream->Flags.ReceiveEnabled = Stream->Flags.ReceiveMultiple;
        Stream->Flags.ReceiveCallActive = TRUE;
        Stream->RecvPendingLength += Event.RECEIVE.TotalBufferLength;
        CXPLAT_DBG_ASSERT(Stream->RecvPendingLength <= Stream->RecvBuffer.ReadPendingLength);

        QuicTraceEvent(
            StreamAppReceive,
            "[strm][%p] Indicating QUIC_STREAM_EVENT_RECEIVE [%llu bytes, %u buffers, 0x%x flags]",
            Stream,
            Event.RECEIVE.TotalBufferLength,
            Event.RECEIVE.BufferCount,
            Event.RECEIVE.Flags);

        QUIC_STATUS Status = QuicStreamIndicateEvent(Stream, &Event);

        Stream->Flags.ReceiveCallActive = FALSE;

        if (Status == QUIC_STATUS_CONTINUE) {
            CXPLAT_DBG_ASSERT(!Stream->Flags.SentStopSending);
            InterlockedExchangeAdd64(
                (int64_t*)&Stream->RecvCompletionLength,
                (int64_t)Event.RECEIVE.TotalBufferLength);
            FlushRecv = TRUE;
            //
            // The app has explicitly indicated it wants to continue to
            // receive callbacks, even if all the data wasn't drained.
            //
            Stream->Flags.ReceiveEnabled = TRUE;

        } else if (Status == QUIC_STATUS_PENDING) {
            //
            // The app called the receive complete API inline if
            // RecvCompletionLength is non-zero.
            //
            FlushRecv = (Stream->RecvCompletionLength != 0);

        } else {
            //
            // All failure status returns shouldn't be used by the app are
            // ignored. We fire a telemetry event and treat as success.
            //
            CXPLAT_TEL_ASSERTMSG_ARGS(
                QUIC_SUCCEEDED(Status),
                "App failed recv callback",
                Stream->Connection->Registration->AppName,
                Status, 0);

            InterlockedExchangeAdd64(
                (int64_t*)&Stream->RecvCompletionLength,
                (int64_t)Event.RECEIVE.TotalBufferLength);
            FlushRecv = TRUE;
        }

        if (FlushRecv) {
            uint64_t BufferLength = Stream->RecvCompletionLength;
            InterlockedExchangeAdd64(
                (int64_t*)&Stream->RecvCompletionLength,
                -(int64_t)BufferLength);
            FlushRecv = QuicStreamReceiveComplete(Stream, BufferLength);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamReceiveCompletePending(
    _In_ QUIC_STREAM* Stream
    )
{
    InterlockedExchangePointer(
        (void**)&Stream->ReceiveCompleteOperation,
        &Stream->ReceiveCompleteOperationStorage);

    uint64_t BufferLength = Stream->RecvCompletionLength;
    InterlockedExchangeAdd64(
        (int64_t*)&Stream->RecvCompletionLength,
        -(int64_t)BufferLength);

    if (QuicStreamReceiveComplete(Stream, BufferLength)) {
        QuicStreamRecvFlush(Stream);
    }

    //
    // Release the operation reference.
    //
    QuicStreamRelease(Stream, QUIC_STREAM_REF_OPERATION);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicStreamReceiveComplete(
    _In_ QUIC_STREAM* Stream,
    _In_ uint64_t BufferLength
    )
{
    if (Stream->Flags.SentStopSending || Stream->Flags.RemoteCloseFin) {
        //
        // The app has aborted their receive path. No need to process any more.
        //
        return FALSE;
    }

    QuicTraceEvent(
        StreamAppReceiveComplete,
        "[strm][%p] Receive complete [%llu bytes]",
        Stream,
        BufferLength);

    CXPLAT_TEL_ASSERTMSG(
        BufferLength <= Stream->RecvPendingLength,
        "App overflowed read buffer!");

    //
    // Reclaim any buffer space comsumed by the app.
    //
    if (Stream->RecvPendingLength == 0 ||
        QuicRecvBufferDrain(&Stream->RecvBuffer, BufferLength)) {
        Stream->Flags.ReceiveDataPending = FALSE; // No more pending data to deliver.
    }

    if (BufferLength != 0) {
        Stream->RecvPendingLength -= BufferLength;
        QuicPerfCounterAdd(QUIC_PERF_COUNTER_APP_RECV_BYTES, BufferLength);
        QuicStreamOnBytesDelivered(Stream, BufferLength);
    }

    if (Stream->RecvPendingLength == 0) {
        //
        // All data was drained, so additional callbacks can continue to be
        // delivered.
        //
        Stream->Flags.ReceiveEnabled = TRUE;

    } else if (!Stream->Flags.ReceiveMultiple) {
        //
        // The app didn't drain all the data, so we will need to wait for them
        // to request a new receive.
        //
        Stream->RecvPendingLength = 0;
    }

    if (!Stream->Flags.ReceiveEnabled) {
        //
        // The application layer can't drain any more right now. Pause the
        // receive callbacks until the application re-enables them.
        //
        QuicTraceEvent(
            StreamRecvState,
            "[strm][%p] Recv State: %hhu",
            Stream,
            QuicStreamRecvGetState(Stream));
        return FALSE;
    }

    if (Stream->Flags.ReceiveDataPending) {
        //
        // There is still more data for the app to process and it still has
        // receive callbacks enabled, so do another recv flush (if not already
        // doing multi-receive mode).
        //
        return !Stream->Flags.ReceiveMultiple;
    }

    if (Stream->RecvBuffer.BaseOffset == Stream->RecvMaxLength) {
        CXPLAT_DBG_ASSERT(!Stream->Flags.ReceiveDataPending);
        //
        // We have delivered all the payload that needs to be delivered. Deliver
        // the graceful close event now.
        //
        Stream->Flags.RemoteCloseFin = TRUE;
        Stream->Flags.RemoteCloseAcked = TRUE;

        QuicTraceEvent(
            StreamRecvState,
            "[strm][%p] Recv State: %hhu",
            Stream,
            QuicStreamRecvGetState(Stream));

        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN;
        QuicTraceLogStreamVerbose(
            IndicatePeerSendShutdown,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN");
        (void)QuicStreamIndicateEvent(Stream, &Event);

        //
        // Now that the close event has been delivered to the app, we can shut
        // down the stream.
        //
        QuicStreamTryCompleteShutdown(Stream);

        //
        // Remove any flags we shouldn't be sending now that the receive
        // direction is closed.
        //
        QuicSendClearStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_MAX_DATA | QUIC_STREAM_SEND_FLAG_RECV_ABORT);
    } else if (Stream->Flags.RemoteCloseResetReliable && Stream->RecvBuffer.BaseOffset >= Stream->RecvMaxLength) {
        //
        // ReliableReset was initiated by the peer, and we sent enough data to the app, we can alert the app
        // we're done and shutdown the RECV direction of this stream.
        //
        QuicTraceEvent(
            StreamRecvState,
            "[strm][%p] Recv State: %hhu",
            Stream,
            QuicStreamRecvGetState(Stream));
        QuicStreamIndicatePeerSendAbortedEvent(Stream, Stream->RecvShutdownErrorCode);
        QuicStreamRecvShutdown(Stream, TRUE, Stream->RecvShutdownErrorCode);
    }

    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamRecvSetEnabledState(
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN NewRecvEnabled
    )
{
    if (Stream->Flags.RemoteNotAllowed ||
        Stream->Flags.RemoteCloseFin ||
        Stream->Flags.RemoteCloseReset ||
        Stream->Flags.SentStopSending) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if (Stream->Flags.ReceiveEnabled != NewRecvEnabled) {
        CXPLAT_DBG_ASSERT(!Stream->Flags.SentStopSending);
        Stream->Flags.ReceiveEnabled = NewRecvEnabled;

        if (Stream->Flags.Started && NewRecvEnabled &&
            (Stream->RecvBuffer.RecvMode == QUIC_RECV_BUF_MODE_MULTIPLE ||
            Stream->RecvBuffer.ReadPendingLength == 0)) {
            //
            // The application just resumed receive callbacks. Queue a
            // flush receive operation to start draining the receive buffer.
            //
            QuicTraceEvent(
                StreamRecvState,
                "[strm][%p] Recv State: %hhu",
                Stream,
                QuicStreamRecvGetState(Stream));
            QuicStreamRecvQueueFlush(Stream, TRUE);
        }
    }

    return QUIC_STATUS_SUCCESS;
}
