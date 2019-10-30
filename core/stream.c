/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A stream manages the send and receive queues for application data. This file
    contains the initialization and cleanup functionality for the stream.

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "stream.tmh"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicStreamInitialize(
    _In_ PQUIC_CONNECTION Connection,
    _In_ BOOLEAN Unidirectional,
    _In_ BOOLEAN Opened0Rtt,
    _Outptr_ _At_(*NewStream, __drv_allocatesMem(Mem))
        PQUIC_STREAM* NewStream
    )
{
    QUIC_STATUS Status;
    PQUIC_STREAM Stream;

    Stream = QuicPoolAlloc(&Connection->Worker->StreamPool);
    if (Stream == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    QuicZeroMemory(Stream, sizeof(QUIC_STREAM));

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
    QuicDispatchLockInitialize(&Stream->ApiSendRequestLock);
    QuicRefInitialize(&Stream->RefCount);
#if QUIC_TEST_MODE
    Stream->RefTypeCount[QUIC_STREAM_REF_APP] = 1;
#endif

    Status =
        QuicRangeInitialize(
            QUIC_MAX_RANGE_ALLOC_SIZE,
            &Stream->SparseAckRanges);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    Status =
        QuicRecvBufferInitialize(
            &Stream->RecvBuffer,
            Connection->Session->Settings.StreamRecvBufferDefault,
            Connection->Session->Settings.StreamRecvWindowDefault,
            FALSE);
    if (QUIC_FAILED(Status)) {
        QuicRangeUninitialize(&Stream->SparseAckRanges);
        goto Exit;
    }

    Stream->MaxAllowedRecvOffset = Stream->RecvBuffer.VirtualBufferLength;
    Stream->RecvWindowLastUpdate = QuicTimeUs32();

    Stream->Flags.Initialized = TRUE;
    *NewStream = Stream;
    Stream = NULL;

Exit:

    if (Stream) {
        QuicDispatchLockUninitialize(&Stream->ApiSendRequestLock);
        Stream->Flags.Freed = TRUE;
        QuicPoolFree(&Connection->Worker->StreamPool, Stream);
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicStreamFree(
    _In_ __drv_freesMem(Mem) PQUIC_STREAM Stream
    )
{
    BOOLEAN WasStarted = Stream->Flags.Started;

    QUIC_TEL_ASSERT(Stream->RefCount == 0);
    QUIC_TEL_ASSERT(Stream->Flags.ShutdownComplete);
    QUIC_TEL_ASSERT(Stream->Flags.HandleClosed);
    QUIC_TEL_ASSERT(Stream->ClosedLink.Flink == NULL);
    QUIC_TEL_ASSERT(Stream->SendLink.Flink == NULL);

    Stream->Flags.Uninitialized = TRUE;

    QUIC_TEL_ASSERT(Stream->ApiSendRequests == NULL);
    QUIC_TEL_ASSERT(Stream->SendRequests == NULL);

    QuicRecvBufferUninitialize(&Stream->RecvBuffer);
    QuicRangeUninitialize(&Stream->SparseAckRanges);
    QuicDispatchLockUninitialize(&Stream->ApiSendRequestLock);
    QuicRefUninitialize(&Stream->RefCount);

    Stream->Flags.Freed = TRUE;
    QuicPoolFree(&Stream->Connection->Worker->StreamPool, Stream);

    if (WasStarted) {
        EventWriteQuicStreamDestroyed(Stream);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamStart(
    _In_ PQUIC_STREAM Stream,
    _In_ QUIC_STREAM_START_FLAGS Flags
    )
{
    QUIC_STATUS Status;

    if (QuicConnIsClosed(Stream->Connection) ||
        Stream->Flags.Started) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    if (!(Flags & QUIC_STREAM_START_FLAG_REMOTE)) {
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
    EventWriteQuicStreamCreated(Stream, Stream->Connection, Stream->ID,
        (!QuicConnIsServer(Stream->Connection) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER)));

    if (Stream->Flags.Unidirectional) {
        if (!(Flags & QUIC_STREAM_START_FLAG_REMOTE)) {

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

    EventWriteQuicStreamSendState(Stream, QuicStreamSendGetState(Stream));
    EventWriteQuicStreamRecvState(Stream, QuicStreamRecvGetState(Stream));

    if (Stream->Flags.SendEnabled) {
        Stream->OutFlowBlockedReasons |= QUIC_FLOW_BLOCKED_APP;
    }

    Stream->Flags.SendOpen = !!(Flags & QUIC_STREAM_START_FLAG_IMMEDIATE);
    if (Stream->Flags.SendOpen) {
        QuicSendSetStreamSendFlag(
            &Stream->Connection->Send,
            Stream,
            QUIC_STREAM_SEND_FLAG_OPEN);
    }

    Stream->MaxAllowedSendOffset =
        QuicStreamGetInitialMaxDataFromTP(
            Stream->ID,
            QuicConnIsServer(Stream->Connection),
            &Stream->Connection->PeerTransportParams);
    if (Stream->MaxAllowedSendOffset == 0) {
        Stream->OutFlowBlockedReasons |= QUIC_FLOW_BLOCKED_STREAM_FLOW_CONTROL;
    }
    Stream->SendWindow = (uint32_t)min(Stream->MaxAllowedSendOffset, UINT32_MAX);

    if (Stream->OutFlowBlockedReasons != 0) {
        EventWriteQuicStreamOutFlowBlocked(Stream, Stream->OutFlowBlockedReasons);
    }

Exit:

    if (!(Flags & QUIC_STREAM_START_FLAG_REMOTE)) {
        QuicStreamIndicateStartComplete(Stream, Status);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamClose(
    _In_ __drv_freesMem(Mem) PQUIC_STREAM Stream
    )
{
    if (!Stream->Flags.Started) {

        Stream->Flags.ShutdownComplete = TRUE;

    } else if (!Stream->Flags.ShutdownComplete) {

        LogWarning("[strm][%p][%llu] Closing handle without fully shutting down.",
            Stream, Stream->ID);

        //
        // Abort any pending operations.
        //
        QuicStreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE,
            QUIC_ERROR_NO_ERROR);
    }

    Stream->Flags.HandleClosed = TRUE;
    Stream->ClientCallbackHandler = NULL;

    QuicStreamRelease(Stream, QUIC_STREAM_REF_APP);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamTraceRundown(
    _In_ QUIC_STREAM* Stream
    )
{
    EventWriteQuicStreamRundown(Stream, Stream->Connection, Stream->ID,
        (!QuicConnIsServer(Stream->Connection) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER)));
    EventWriteQuicStreamOutFlowBlocked(Stream, Stream->OutFlowBlockedReasons);
    // TODO - More state dump.
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicStreamIndicateEvent(
    _In_ PQUIC_STREAM Stream,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    QUIC_STATUS Status;
    if (Stream->ClientCallbackHandler != NULL) {
        uint64_t StartTime = QuicTimeUs64();
        Status =
            Stream->ClientCallbackHandler(
                (HQUIC)Stream,
                Stream->ClientContext,
                Event);
        uint64_t EndTime = QuicTimeUs64();
        if (EndTime - StartTime > QUIC_MAX_CALLBACK_TIME_WARNING) {
            LogWarning("strm][%p][%llu] App took excessive time (%llu us) in callback.",
                Stream, Stream->ID, (EndTime - StartTime));
            QUIC_TEL_ASSERTMSG_ARGS(
                EndTime - StartTime < QUIC_MAX_CALLBACK_TIME_ERROR,
                "App extremely long time in stream callback",
                Stream->Connection->Registration == NULL ?
                    NULL : Stream->Connection->Registration->AppName,
                Event->Type, 0);
        }
    } else {
        Status = QUIC_STATUS_INVALID_STATE;
        LogWarning("[strm][%p][%llu] Event silently discarded.", Stream, Stream->ID);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateStartComplete(
    _In_ PQUIC_STREAM Stream,
    _In_ QUIC_STATUS Status
    )
{
    QUIC_STREAM_EVENT Event;
    Event.Type = QUIC_STREAM_EVENT_START_COMPLETE;
    Event.START_COMPLETE.Status = Status;
    Event.START_COMPLETE.ID = Stream->ID;
    LogVerbose("[strm][%p][%llu] Indicating QUIC_STREAM_EVENT_START_COMPLETE (0x%x)",
        Stream, Stream->ID, Status);
    (void)QuicStreamIndicateEvent(Stream, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamIndicateShutdownComplete(
    _In_ PQUIC_STREAM Stream
    )
{
    if (!Stream->Flags.HandleShutdown) {
        Stream->Flags.HandleShutdown = TRUE;

        QUIC_STREAM_EVENT Event;
        Event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
        LogVerbose("[strm][%p][%llu] Indicating QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE",
            Stream, Stream->ID);
        (void)QuicStreamIndicateEvent(Stream, &Event);

        Stream->ClientCallbackHandler = NULL;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicStreamShutdown(
    _In_ PQUIC_STREAM Stream,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ QUIC_VAR_INT ErrorCode
    )
{
    QUIC_DBG_ASSERT(Flags != 0 && Flags != QUIC_STREAM_SHUTDOWN_SILENT);
    QUIC_DBG_ASSERT(
        Flags == QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL ||
        !(Flags & QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL));
    QUIC_DBG_ASSERT(
        !(Flags & QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE) ||
        Flags == (QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND));

    if (!!(Flags & (QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND))) {
        QuicStreamSendShutdown(
            Stream,
            !!(Flags & QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL),
            !!(Flags & QUIC_STREAM_SHUTDOWN_SILENT),
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
    _In_ PQUIC_STREAM Stream
    )
{
    if (!Stream->Flags.ShutdownComplete &&
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
    _In_ PQUIC_STREAM Stream,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(Stream);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_INVALID_PARAMETER;
}

QUIC_STATUS
QuicStreamParamGet(
    _In_ PQUIC_STREAM Stream,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param)
    {
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

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}
