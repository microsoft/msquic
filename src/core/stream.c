/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A stream manages the send and receive queues for application data. This file
    contains the initialization and cleanup functionality for the stream.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "stream.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicStreamInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OpenedRemotely,
    _In_ BOOLEAN Unidirectional,
    _In_ BOOLEAN Opened0Rtt,
    _Outptr_ _At_(*NewStream, __drv_allocatesMem(Mem))
        QUIC_STREAM** NewStream
    )
{
    QUIC_STATUS Status;
    QUIC_STREAM* Stream;
    uint8_t* PreallocatedRecvBuffer = NULL;
    uint32_t InitialRecvBufferLength;
    QUIC_WORKER* Worker = Connection->Worker;

    Stream = CxPlatPoolAlloc(&Worker->StreamPool);
    if (Stream == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicTraceEvent(
        StreamAlloc,
        "[strm][%p] Allocated, Conn=%p",
        Stream,
        Connection);
    CxPlatZeroMemory(Stream, sizeof(QUIC_STREAM));

#if DEBUG
    CxPlatDispatchLockAcquire(&Connection->Streams.AllStreamsLock);
    CxPlatListInsertTail(&Connection->Streams.AllStreams, &Stream->AllStreamsLink);
    CxPlatDispatchLockRelease(&Connection->Streams.AllStreamsLock);
#endif
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_STRM_ACTIVE);

    Stream->Type = QUIC_HANDLE_TYPE_STREAM;
    Stream->Connection = Connection;
    Stream->ID = UINT64_MAX;
    Stream->Flags.Unidirectional = Unidirectional;
    Stream->Flags.Opened0Rtt = Opened0Rtt;
    Stream->Flags.Allocated = TRUE;
    Stream->Flags.SendEnabled = TRUE;
    Stream->Flags.ReceiveEnabled = TRUE;
    Stream->RecvMaxLength = UINT64_MAX;
    Stream->RefCount = 1;
    Stream->SendRequestsTail = &Stream->SendRequests;
    Stream->SendPriority = QUIC_STREAM_PRIORITY_DEFAULT;
    CxPlatDispatchLockInitialize(&Stream->ApiSendRequestLock);
    CxPlatRefInitialize(&Stream->RefCount);
    QuicRangeInitialize(
        QUIC_MAX_RANGE_ALLOC_SIZE,
        &Stream->SparseAckRanges);
#if DEBUG
    Stream->RefTypeCount[QUIC_STREAM_REF_APP] = 1;
#endif

    if (Unidirectional) {
        if (!OpenedRemotely) {

            //
            // This is 'our' unidirectional stream, so that means just the send
            // path is used.
            //

            Stream->Flags.RemoteNotAllowed = TRUE;
            Stream->Flags.RemoteCloseAcked = TRUE;
            Stream->Flags.ReceiveEnabled = FALSE;

        } else {

            //
            // This is 'their' unidirectional stream, so that means just the recv
            // path is used.
            //

            Stream->Flags.LocalNotAllowed = TRUE;
            Stream->Flags.LocalCloseAcked = TRUE;
            Stream->Flags.SendEnabled = FALSE;
            Stream->Flags.HandleSendShutdown = TRUE;
        }
    }

    InitialRecvBufferLength = Connection->Settings.StreamRecvBufferDefault;
    if (InitialRecvBufferLength == QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE) {
        PreallocatedRecvBuffer = CxPlatPoolAlloc(&Worker->DefaultReceiveBufferPool);
        if (PreallocatedRecvBuffer == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
    }

    Status =
        QuicRecvBufferInitialize(
            &Stream->RecvBuffer,
            InitialRecvBufferLength,
            Connection->Settings.StreamRecvWindowDefault,
            FALSE,
            PreallocatedRecvBuffer);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    Stream->MaxAllowedRecvOffset = Stream->RecvBuffer.VirtualBufferLength;
    Stream->RecvWindowLastUpdate = CxPlatTimeUs32();

    Stream->Flags.Initialized = TRUE;
    *NewStream = Stream;
    Stream = NULL;
    PreallocatedRecvBuffer = NULL;

Exit:

    if (Stream) {
#if DEBUG
        CxPlatDispatchLockAcquire(&Connection->Streams.AllStreamsLock);
        CxPlatListEntryRemove(&Stream->AllStreamsLink);
        CxPlatDispatchLockRelease(&Connection->Streams.AllStreamsLock);
#endif
        QuicPerfCounterDecrement(QUIC_PERF_COUNTER_STRM_ACTIVE);
        CxPlatDispatchLockUninitialize(&Stream->ApiSendRequestLock);
        Stream->Flags.Freed = TRUE;
        CxPlatPoolFree(&Worker->StreamPool, Stream);
    }
    if (PreallocatedRecvBuffer) {
        CxPlatPoolFree(&Worker->DefaultReceiveBufferPool, PreallocatedRecvBuffer);
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamFree(
    _In_ __drv_freesMem(Mem) QUIC_STREAM* Stream
    )
{
    BOOLEAN WasStarted = Stream->Flags.Started;
    QUIC_CONNECTION* Connection = Stream->Connection;
    QUIC_WORKER* Worker = Connection->Worker;

    CXPLAT_TEL_ASSERT(Stream->RefCount == 0);
    CXPLAT_TEL_ASSERT(Connection->State.ClosedLocally || Stream->Flags.ShutdownComplete);
    CXPLAT_TEL_ASSERT(Connection->State.ClosedLocally || Stream->Flags.HandleClosed);
    CXPLAT_TEL_ASSERT(Stream->ClosedLink.Flink == NULL);
    CXPLAT_TEL_ASSERT(Stream->SendLink.Flink == NULL);

    Stream->Flags.Uninitialized = TRUE;

    CXPLAT_TEL_ASSERT(Stream->ApiSendRequests == NULL);
    CXPLAT_TEL_ASSERT(Stream->SendRequests == NULL);

#if DEBUG
    CxPlatDispatchLockAcquire(&Connection->Streams.AllStreamsLock);
    CxPlatListEntryRemove(&Stream->AllStreamsLink);
    CxPlatDispatchLockRelease(&Connection->Streams.AllStreamsLock);
#endif
    QuicPerfCounterDecrement(QUIC_PERF_COUNTER_STRM_ACTIVE);

    QuicRecvBufferUninitialize(&Stream->RecvBuffer);
    QuicRangeUninitialize(&Stream->SparseAckRanges);
    CxPlatDispatchLockUninitialize(&Stream->ApiSendRequestLock);
    CxPlatRefUninitialize(&Stream->RefCount);

    if (Stream->ReceiveCompleteOperation) {
        QuicOperationFree(Worker, Stream->ReceiveCompleteOperation);
    }

    if (Stream->RecvBuffer.PreallocatedBuffer) {
        CxPlatPoolFree(
            &Worker->DefaultReceiveBufferPool,
            Stream->RecvBuffer.PreallocatedBuffer);
    }

    Stream->Flags.Freed = TRUE;
    CxPlatPoolFree(&Worker->StreamPool, Stream);

    if (WasStarted) {
#pragma warning(push)
#pragma warning(disable:6001) // SAL doesn't understand we're logging just the address
        QuicTraceEvent(
            StreamDestroyed,
            "[strm][%p] Destroyed",
            Stream);
#pragma warning(pop)
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamStart(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STREAM_START_FLAGS Flags,
    _In_ BOOLEAN IsRemoteStream
    )
{
    QUIC_STATUS Status;

    BOOLEAN ClosedLocally = Stream->Connection->State.ClosedLocally;
    if ((ClosedLocally || Stream->Connection->State.ClosedRemotely) ||
        Stream->Flags.Started) {
        Status =
            (ClosedLocally || Stream->Flags.Started) ?
            QUIC_STATUS_INVALID_STATE :
            QUIC_STATUS_ABORTED;
        goto Exit;
    }

    if (!IsRemoteStream) {
        uint8_t Type =
            QuicConnIsServer(Stream->Connection) ?
                STREAM_ID_FLAG_IS_SERVER :
                STREAM_ID_FLAG_IS_CLIENT;

        if (Stream->Flags.Unidirectional) {
            Type |= STREAM_ID_FLAG_IS_UNI_DIR;
        }

        Status =
            QuicStreamSetNewLocalStream(
                &Stream->Connection->Streams,
                Type,
                !!(Flags & QUIC_STREAM_START_FLAG_FAIL_BLOCKED),
                Stream);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

    Stream->Flags.Started = TRUE;
    Stream->Flags.IndicatePeerAccepted = !!(Flags & QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT);

    //
    // Cache flow blocked timings on connection so that the queried blocked timings only
    // reflect time spent in a stream's lifetime.
    //
    uint64_t Now = CxPlatTimeUs64();
    Stream->BlockedTimings.CachedConnSchedulingUs =
        Stream->Connection->BlockedTimings.Scheduling.CumulativeTimeUs +
        Stream->Connection->BlockedTimings.Scheduling.LastStartTimeUs != 0 ?
            CxPlatTimeDiff64(Stream->Connection->BlockedTimings.Scheduling.LastStartTimeUs, Now) : 0;
    Stream->BlockedTimings.CachedConnPacingUs =
        Stream->Connection->BlockedTimings.Pacing.CumulativeTimeUs +
        Stream->Connection->BlockedTimings.Pacing.LastStartTimeUs != 0 ?
        CxPlatTimeDiff64(Stream->Connection->BlockedTimings.Pacing.LastStartTimeUs, Now) : 0;
    Stream->BlockedTimings.CachedConnAmplificationProtUs =
        Stream->Connection->BlockedTimings.AmplificationProt.CumulativeTimeUs +
        Stream->Connection->BlockedTimings.AmplificationProt.LastStartTimeUs != 0 ?
        CxPlatTimeDiff64(Stream->Connection->BlockedTimings.AmplificationProt.LastStartTimeUs, Now) : 0;
    Stream->BlockedTimings.CachedConnCongestionControlUs =
        Stream->Connection->BlockedTimings.CongestionControl.CumulativeTimeUs +
        Stream->Connection->BlockedTimings.CongestionControl.LastStartTimeUs != 0 ?
        CxPlatTimeDiff64(Stream->Connection->BlockedTimings.CongestionControl.LastStartTimeUs, Now) : 0;
    Stream->BlockedTimings.CachedConnFlowControlUs =
        Stream->Connection->BlockedTimings.FlowControl.CumulativeTimeUs +
        Stream->Connection->BlockedTimings.FlowControl.LastStartTimeUs != 0 ?
        CxPlatTimeDiff64(Stream->Connection->BlockedTimings.FlowControl.LastStartTimeUs, Now) : 0;

    QuicTraceEvent(
        StreamCreated,
        "[strm][%p] Created, Conn=%p ID=%llu IsLocal=%hhu",
        Stream,
        Stream->Connection,
        Stream->ID,
        !IsRemoteStream);
    QuicTraceEvent(
        StreamSendState,
        "[strm][%p] Send State: %hhu",
        Stream,
        QuicStreamSendGetState(Stream));
    QuicTraceEvent(
        StreamRecvState,
        "[strm][%p] Recv State: %hhu",
        Stream,
        QuicStreamRecvGetState(Stream));

    if (Stream->Flags.SendEnabled) {
        QuicStreamAddOutFlowBlockedReason(Stream, QUIC_FLOW_BLOCKED_APP);
    }

    if (Stream->SendFlags != 0) {
        //
        // Send flags were queued up before starting so we need to queue the
        // stream data to be sent out now.
        //
        QuicSendQueueFlushForStream(&Stream->Connection->Send, Stream, FALSE);
    }

    Stream->Flags.SendOpen = !!(Flags & QUIC_STREAM_START_FLAG_IMMEDIATE);
    if (Stream->Flags.SendOpen) {
        QuicSendSetStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_OPEN,
            FALSE);
    }

    Stream->MaxAllowedSendOffset =
        QuicStreamGetInitialMaxDataFromTP(
            Stream->ID,
            QuicConnIsServer(Stream->Connection),
            &Stream->Connection->PeerTransportParams);
    if (Stream->MaxAllowedSendOffset == 0) {
        QuicStreamAddOutFlowBlockedReason(Stream, QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL);
    }
    Stream->SendWindow = (uint32_t)CXPLAT_MIN(Stream->MaxAllowedSendOffset, UINT32_MAX);

Exit:

    if (!IsRemoteStream) {
        QuicStreamIndicateStartComplete(Stream, Status);

        if (QUIC_FAILED(Status) &&
            (Flags & QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL)) {
            QuicStreamShutdown(
                Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT | QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE,
                0);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamClose(
    _In_ __drv_freesMem(Mem) QUIC_STREAM* Stream
    )
{
    CXPLAT_DBG_ASSERT(!Stream->Flags.HandleClosed);
    Stream->Flags.HandleClosed = TRUE;

    if (!Stream->Flags.ShutdownComplete) {

        if (Stream->Flags.Started) {
            //
            // TODO - If the stream hasn't been aborted already, then this is a
            // fatal error for the connection. The QUIC transport cannot "just
            // pick an error" to shutdown the stream with. It must abort the
            // entire connection.
            //
            QuicTraceLogStreamWarning(
                CloseWithoutShutdown,
                Stream,
                "Closing handle without fully shutting down");
        }

        //
        // Abort any pending operations.
        //
        QuicStreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE,
            QUIC_ERROR_NO_ERROR);

            if (!Stream->Flags.Started) {
                //
                // The stream was abandoned before it could be successfully
                // started. Just mark it as completing the shutdown process now
                // since nothing else can be done with it now.
                //
                Stream->Flags.ShutdownComplete = TRUE;
            }
    }

    Stream->ClientCallbackHandler = NULL;

    QuicStreamRelease(Stream, QUIC_STREAM_REF_APP);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamTraceRundown(
    _In_ QUIC_STREAM* Stream
    )
{
    QuicTraceEvent(
        StreamRundown,
        "[strm][%p] Rundown, Conn=%p ID=%llu IsLocal=%hhu",
        Stream,
        Stream->Connection,
        Stream->ID,
        ((QuicConnIsClient(Stream->Connection)) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER)));
    QuicTraceEvent(
        StreamOutFlowBlocked,
        "[strm][%p] Send Blocked Flags: %hhu",
        Stream,
        Stream->OutFlowBlockedReasons);
    // TODO - More state dump.
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamIndicateEvent(
    _In_ QUIC_STREAM* Stream,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    QUIC_STATUS Status;
    if (Stream->ClientCallbackHandler != NULL) {
        //
        // MsQuic shouldn't indicate reentrancy to the app when at all
        // possible. The general exception to this rule is when the connection
        // or stream is being closed because the API MUST block until all work
        // is completed, so we have to execute the event callbacks inline. There
        // is also one additional exception for start complete when StreamStart
        // is called synchronously on an MsQuic thread.
        //
        CXPLAT_DBG_ASSERT(
            !Stream->Connection->State.InlineApiExecution ||
            Stream->Connection->State.HandleClosed ||
            Stream->Flags.HandleClosed ||
            Event->Type == QUIC_STREAM_EVENT_START_COMPLETE);
        Status =
            Stream->ClientCallbackHandler(
                (HQUIC)Stream,
                Stream->ClientContext,
                Event);
    } else {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogStreamWarning(
            EventSilentDiscard,
            Stream,
            "Event silently discarded");
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateStartComplete(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STATUS Status
    )
{
    if (Stream->Flags.StartedIndicated) {
        return;
    }
    Stream->Flags.StartedIndicated = TRUE;

    QUIC_STREAM_EVENT Event;
    Event.Type = QUIC_STREAM_EVENT_START_COMPLETE;
    Event.START_COMPLETE.Status = Status;
    Event.START_COMPLETE.ID = Stream->ID;
    Event.START_COMPLETE.PeerAccepted =
        QUIC_SUCCEEDED(Status) &&
        !(Stream->OutFlowBlockedReasons & QUIC_FLOW_BLOCKED_STREAM_ID_FLOW_CONTROL);
    QuicTraceLogStreamVerbose(
        IndicateStartComplete,
        Stream,
        "Indicating QUIC_STREAM_EVENT_START_COMPLETE [Status=0x%x ID=%llu Accepted=%hhu]",
        Status,
        Stream->ID,
        Event.START_COMPLETE.PeerAccepted);
    (void)QuicStreamIndicateEvent(Stream, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateShutdownComplete(
    _In_ QUIC_STREAM* Stream
    )
{
    if (!Stream->Flags.HandleShutdown) {
        Stream->Flags.HandleShutdown = TRUE;

        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
        Event.SHUTDOWN_COMPLETE.ConnectionShutdown =
            Stream->Connection->State.ClosedLocally ||
            Stream->Connection->State.ClosedRemotely;
        Event.SHUTDOWN_COMPLETE.AppCloseInProgress =
            Stream->Flags.HandleClosed;
        Event.SHUTDOWN_COMPLETE.ConnectionShutdownByApp =
            Stream->Connection->State.AppClosed;
        Event.SHUTDOWN_COMPLETE.ConnectionClosedRemotely =
            Stream->Connection->State.ClosedRemotely;
        Event.SHUTDOWN_COMPLETE.ConnectionErrorCode =
            Stream->Connection->CloseErrorCode;
        Event.SHUTDOWN_COMPLETE.ConnectionCloseStatus =
            Stream->Connection->CloseStatus;
        QuicTraceLogStreamVerbose(
            IndicateStreamShutdownComplete,
            Stream,
            "Indicating QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE [ConnectionShutdown=%hhu, ConnectionShutdownByApp=%hhu, ConnectionClosedRemotely=%hhu, ConnectionErrorCode=0x%llx, ConnectionCloseStatus=0x%x]",
            Event.SHUTDOWN_COMPLETE.ConnectionShutdown,
            Event.SHUTDOWN_COMPLETE.ConnectionShutdownByApp,
            Event.SHUTDOWN_COMPLETE.ConnectionClosedRemotely,
            Event.SHUTDOWN_COMPLETE.ConnectionErrorCode,
            Event.SHUTDOWN_COMPLETE.ConnectionCloseStatus);
        (void)QuicStreamIndicateEvent(Stream, &Event);

        Stream->ClientCallbackHandler = NULL;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamShutdown(
    _In_ QUIC_STREAM* Stream,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    CXPLAT_DBG_ASSERT(Flags != 0 && Flags != QUIC_STREAM_SHUTDOWN_SILENT);
    CXPLAT_DBG_ASSERT(
        !(Flags & QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL) ||
        !(Flags & (QUIC_STREAM_SHUTDOWN_FLAG_ABORT | QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE)));
    CXPLAT_DBG_ASSERT(
        !(Flags & QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE) ||
        Flags == (QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND));

    if (!!(Flags & (QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND))) {
        QuicStreamSendShutdown(
            Stream,
            !!(Flags & QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL),
            !!(Flags & QUIC_STREAM_SHUTDOWN_SILENT),
            FALSE,
            ErrorCode);
    }

    if (!!(Flags & QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE)) {
        QuicStreamRecvShutdown(
            Stream,
            !!(Flags & QUIC_STREAM_SHUTDOWN_SILENT),
            ErrorCode);
    }

    if (!!(Flags & QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE) &&
        !Stream->Flags.ShutdownComplete) {
        //
        // The app has requested that we immediately give them completion
        // events so they don't have to wait. Deliver the send shutdown complete
        // and shutdown complete events now, if they haven't already been
        // delivered.
        //
        QuicStreamIndicateSendShutdownComplete(Stream, FALSE);
        QuicStreamIndicateShutdownComplete(Stream);
    }
}

void
QuicStreamTryCompleteShutdown(
    _In_ QUIC_STREAM* Stream
    )
{
    if (!Stream->Flags.ShutdownComplete &&
        !Stream->Flags.ReceiveDataPending &&
        Stream->Flags.LocalCloseAcked &&
        Stream->Flags.RemoteCloseAcked) {

        //
        // Make sure to clean up any left over send flags.
        //
        QuicSendClearStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAGS_ALL);

        //
        // Mark the stream as shut down and deliver the completion notification
        // to the application layer.
        //
        Stream->Flags.ShutdownComplete = TRUE;
        QuicStreamIndicateShutdownComplete(Stream);

        //
        // Indicate the stream is completely shut down to the connection.
        //
        QuicStreamSetReleaseStream(&Stream->Connection->Streams, Stream);
    }
}

QUIC_STATUS
QuicStreamParamSet(
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_STREAM_ID:
    case QUIC_PARAM_STREAM_0RTT_LENGTH:
    case QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;

    case QUIC_PARAM_STREAM_PRIORITY: {

        if (BufferLength != sizeof(Stream->SendPriority)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Stream->SendPriority != *(uint16_t*)Buffer) {
            Stream->SendPriority = *(uint16_t*)Buffer;

            QuicTraceLogStreamInfo(
                UpdatePriority,
                Stream,
                "New send priority = %hu",
                Stream->SendPriority);

            if (Stream->Flags.Started && Stream->SendFlags != 0) {
                //
                // Update the stream's place in the send queue if necessary.
                //
                QuicSendUpdateStreamPriority(&Stream->Connection->Send, Stream);
            }
        }

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

QUIC_STATUS
QuicStreamParamGet(
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_STREAM_ID:

        if (*BufferLength < sizeof(Stream->ID)) {
            *BufferLength = sizeof(Stream->ID);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Stream->Flags.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(Stream->ID);
        *(uint64_t*)Buffer = Stream->ID;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_STREAM_0RTT_LENGTH:

        if (*BufferLength < sizeof(uint64_t)) {
            *BufferLength = sizeof(uint64_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Stream->Flags.Started ||
            !Stream->Flags.LocalCloseAcked) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(uint64_t);
        *(uint64_t*)Buffer = Stream->Sent0Rtt;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE:

        if (*BufferLength < sizeof(uint64_t)) {
            *BufferLength = sizeof(uint64_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint64_t);
        *(uint64_t*)Buffer =
            Stream->Connection->SendBuffer.IdealBytes;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_STREAM_PRIORITY:

        if (*BufferLength < sizeof(Stream->SendPriority)) {
            *BufferLength = sizeof(Stream->SendPriority);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Stream->SendPriority);
        *(uint16_t*)Buffer = Stream->SendPriority;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_STREAM_STATISTICS: {

        if (*BufferLength < sizeof(QUIC_STREAM_STATISTICS)) {
            *BufferLength = sizeof(QUIC_STREAM_STATISTICS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Stream->Flags.Started) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        uint64_t Now = CxPlatTimeUs64();
        QUIC_STREAM_STATISTICS* Stats = (QUIC_STREAM_STATISTICS*)Buffer;
        QUIC_CONNECTION* Connection = Stream->Connection;
        Stats->StreamBlockedByIdFlowControlUs = Stream->BlockedTimings.StreamIdFlowControl.CumulativeTimeUs;
        if (Stream->BlockedTimings.StreamIdFlowControl.LastStartTimeUs != 0) {
            Stats->StreamBlockedByIdFlowControlUs +=
                CxPlatTimeDiff64(Stream->BlockedTimings.StreamIdFlowControl.LastStartTimeUs, Now);
        }
        Stats->StreamBlockedByFlowControlUs = Stream->BlockedTimings.FlowControl.CumulativeTimeUs;
        if (Stream->BlockedTimings.FlowControl.LastStartTimeUs != 0) {
            Stats->StreamBlockedByFlowControlUs +=
                CxPlatTimeDiff64(Stream->BlockedTimings.FlowControl.LastStartTimeUs, Now);
        }
        Stats->StreamBlockedByAppUs = Stream->BlockedTimings.App.CumulativeTimeUs;
        if (Stream->BlockedTimings.App.LastStartTimeUs != 0) {
            Stats->StreamBlockedByAppUs +=
                CxPlatTimeDiff64(Stream->BlockedTimings.App.LastStartTimeUs, Now);
        }
        Stats->ConnBlockedBySchedulingUs = Connection->BlockedTimings.Scheduling.CumulativeTimeUs;
        if (Connection->BlockedTimings.Scheduling.LastStartTimeUs != 0) {
            Stats->ConnBlockedBySchedulingUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.Scheduling.LastStartTimeUs, Now);
        }
        Stats->ConnBlockedBySchedulingUs -= Stream->BlockedTimings.CachedConnSchedulingUs;
        Stats->ConnBlockedByPacingUs = Connection->BlockedTimings.Pacing.CumulativeTimeUs;
        if (Connection->BlockedTimings.Pacing.LastStartTimeUs != 0) {
            Stats->ConnBlockedByPacingUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.Pacing.LastStartTimeUs, Now);
        }
        Stats->ConnBlockedByPacingUs -= Stream->BlockedTimings.CachedConnPacingUs;
        Stats->ConnBlockedByAmplificationProtUs = Connection->BlockedTimings.AmplificationProt.CumulativeTimeUs;
        if (Connection->BlockedTimings.AmplificationProt.LastStartTimeUs != 0) {
            Stats->ConnBlockedByAmplificationProtUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.AmplificationProt.LastStartTimeUs, Now);
        }
        Stats->ConnBlockedByAmplificationProtUs -= Stream->BlockedTimings.CachedConnAmplificationProtUs;
        Stats->ConnBlockedByCongestionControlUs = Connection->BlockedTimings.CongestionControl.CumulativeTimeUs;
        if (Connection->BlockedTimings.CongestionControl.LastStartTimeUs != 0) {
            Stats->ConnBlockedByCongestionControlUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.CongestionControl.LastStartTimeUs, Now);
        }
        Stats->ConnBlockedByCongestionControlUs -= Stream->BlockedTimings.CachedConnCongestionControlUs;
        Stats->ConnBlockedByFlowControlUs = Connection->BlockedTimings.FlowControl.CumulativeTimeUs;
        if (Connection->BlockedTimings.FlowControl.LastStartTimeUs != 0) {
            Stats->ConnBlockedByFlowControlUs +=
                CxPlatTimeDiff64(Connection->BlockedTimings.FlowControl.LastStartTimeUs, Now);
        }
        Stats->ConnBlockedByFlowControlUs -= Stream->BlockedTimings.CachedConnFlowControlUs;

        *BufferLength = sizeof(QUIC_STREAM_STATISTICS);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }
    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
