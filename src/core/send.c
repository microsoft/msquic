/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Send management. The general architecture here is that anything that needs
    to be sent (data or control frames) is queued up by adding a flag to
    indicate that frame needs to be sent. There are connection-wide frames and
    stream specific frames. The Send module manages the connection-wide via the
    'SendFlags' variable. The stream specific flags are stored on the stream's
    'SendFlags' variable and the Send module maintains a list of streams that
    currently have frames that need to be sent.

    The framing and sending are done while processing the FLUSH_SEND operation.
    The operation triggers a call to QuicSendProcessFlushSendOperation which
    processes a maximum number of packets worth of data before returning out,
    so as to not starve other operations.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "send.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendInitialize(
    _Inout_ QUIC_SEND* Send,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    CxPlatListInitializeHead(&Send->SendStreams);
    Send->MaxData = Settings->ConnFlowControlWindow;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendUninitialize(
    _In_ QUIC_SEND* Send
    )
{
    Send->Uninitialized = TRUE;
    Send->DelayedAckTimerActive = FALSE;
    Send->SendFlags = 0;

    if (Send->InitialToken != NULL) {
        CXPLAT_FREE(Send->InitialToken, QUIC_POOL_INITIAL_TOKEN);
        Send->InitialToken = NULL;
    }

    //
    // Release all the stream refs.
    //
    CXPLAT_LIST_ENTRY* Entry = Send->SendStreams.Flink;
    while (Entry != &Send->SendStreams) {

        QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink);
        CXPLAT_DBG_ASSERT(Stream->SendFlags != 0);

        Entry = Entry->Flink;
        Stream->SendFlags = 0;
        Stream->SendLink.Flink = NULL;

        QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendApplyNewSettings(
    _Inout_ QUIC_SEND* Send,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    )
{
    Send->MaxData = Settings->ConnFlowControlWindow;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendReset(
    _In_ QUIC_SEND* Send
    )
{
    Send->SendFlags = 0;
    Send->LastFlushTime = 0;
    if (Send->DelayedAckTimerActive) {
        QuicConnTimerCancel(QuicSendGetConnection(Send), QUIC_CONN_TIMER_ACK_DELAY);
        Send->DelayedAckTimerActive = FALSE;
    }
    QuicConnTimerCancel(
        QuicSendGetConnection(Send),
        QUIC_CONN_TIMER_PACING);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendCanSendFlagsNow(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    if (Connection->Crypto.TlsState.WriteKey < QUIC_PACKET_KEY_1_RTT) {
        if (Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_0_RTT] != NULL &&
            CxPlatListIsEmpty(&Send->SendStreams)) {
            return TRUE;
        }
        if ((!Connection->State.Started && QuicConnIsClient(Connection)) ||
            !(Send->SendFlags & QUIC_CONN_SEND_FLAG_ALLOWED_HANDSHAKE)) {
            return FALSE;
        }
    }
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendQueueFlush(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_SEND_FLUSH_REASON Reason
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    if (!Send->FlushOperationPending && QuicSendCanSendFlagsNow(Send)) {
        QUIC_OPERATION* Oper;
        if ((Oper = QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_FLUSH_SEND)) != NULL) {
            Send->FlushOperationPending = TRUE;
            QuicTraceEvent(
                ConnQueueSendFlush,
                "[conn][%p] Queueing send flush, reason=%u",
                Connection,
                Reason);
            QuicConnQueueOper(Connection, Oper);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendQueueFlushForStream(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream,
    _In_ BOOLEAN DelaySend
    )
{
    if (Stream->SendLink.Flink == NULL) {
        //
        // Not previously queued, so add the stream to the end of the queue.
        //
        CXPLAT_LIST_ENTRY* Entry = Send->SendStreams.Blink;
        while (Entry != &Send->SendStreams) {
            //
            // Search back to front for the right place (based on priority) to
            // insert the stream.
            //
            if (Stream->SendPriority <=
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink)->SendPriority) {
                break;
            }
            Entry = Entry->Blink;
        }
        CxPlatListInsertHead(Entry, &Stream->SendLink); // Insert after current Entry
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_SEND);
    }

    //
    // TODO - If send was delayed by the app, under what conditions should we
    // ignore that signal and queue anyways?
    //

    if (DelaySend) {
        Stream->Flags.SendDelayed = TRUE;

    } else if (Stream->Connection->State.Started) {
        //
        // Schedule the flush even if we didn't just queue the stream,
        // because it may have been previously blocked.
        //
        Stream->Flags.SendDelayed = FALSE;
        QuicSendQueueFlush(Send, REASON_STREAM_FLAGS);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendUpdateStreamPriority(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream
    )
{
    CXPLAT_DBG_ASSERT(Stream->SendLink.Flink != NULL);
    CxPlatListEntryRemove(&Stream->SendLink);

    CXPLAT_LIST_ENTRY* Entry = Send->SendStreams.Blink;
    while (Entry != &Send->SendStreams) {
        //
        // Search back to front for the right place (based on priority) to
        // insert the stream.
        //
        if (Stream->SendPriority <=
            CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink)->SendPriority) {
            break;
        }
        Entry = Entry->Blink;
    }
    CxPlatListInsertHead(Entry, &Stream->SendLink); // Insert after current Entry
}

#if DEBUG
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendValidate(
    _In_ QUIC_SEND* Send
    )
{
    if (Send->Uninitialized) {
        return;
    }

    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    BOOLEAN HasAckElicitingPacketsToAcknowledge = FALSE;
    for (uint32_t i = 0; i < QUIC_ENCRYPT_LEVEL_COUNT; ++i) {
        if (Connection->Packets[i] != NULL) {
            if (Connection->Packets[i]->AckTracker.AckElicitingPacketsToAcknowledge) {
                HasAckElicitingPacketsToAcknowledge = TRUE;
                break;
            }
        }
    }

    if (Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK) {
        CXPLAT_DBG_ASSERT(!Send->DelayedAckTimerActive);
        CXPLAT_DBG_ASSERT(HasAckElicitingPacketsToAcknowledge);
    } else if (Send->DelayedAckTimerActive) {
        CXPLAT_DBG_ASSERT(HasAckElicitingPacketsToAcknowledge);
    } else if (!Connection->State.ClosedLocally && !Connection->State.ClosedRemotely) {
        CXPLAT_DBG_ASSERT(!HasAckElicitingPacketsToAcknowledge);
    }
}
#else
#define QuicSendValidate(Send)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendClear(
    _In_ QUIC_SEND* Send
    )
{
    //
    // Remove all flags for things we aren't allowed to send once the connection
    // has been closed.
    //
    Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_CONN_CLOSED_MASK;

    //
    // Remove any queued up streams.
    //
    while (!CxPlatListIsEmpty(&Send->SendStreams)) {

        QUIC_STREAM* Stream =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Send->SendStreams), QUIC_STREAM, SendLink);

        CXPLAT_DBG_ASSERT(Stream->SendFlags != 0);
        Stream->SendFlags = 0;
        Stream->SendLink.Flink = NULL;

        QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendSetSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ uint32_t SendFlags
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    BOOLEAN IsCloseFrame =
        !!(SendFlags & (QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE));

    BOOLEAN CanSetFlag =
        !QuicConnIsClosed(Connection) || IsCloseFrame;

    if (SendFlags & QUIC_CONN_SEND_FLAG_ACK && Send->DelayedAckTimerActive) {
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_ACK_DELAY);
        Send->DelayedAckTimerActive = FALSE;
    }

    if (CanSetFlag && (Send->SendFlags & SendFlags) != SendFlags) {
        QuicTraceLogConnVerbose(
            ScheduleSendFlags,
            Connection,
            "Scheduling flags 0x%x to 0x%x",
            SendFlags,
            Send->SendFlags);
        Send->SendFlags |= SendFlags;
        QuicSendQueueFlush(Send, REASON_CONNECTION_FLAGS);
    }

    if (IsCloseFrame) {
        Connection->LastCloseResponseTimeUs = CxPlatTimeUs64();
        QuicSendClear(Send);
    }

    QuicSendValidate(Send);

    return CanSetFlag;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendClearSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ uint32_t SendFlags
    )
{
    if (Send->SendFlags & SendFlags) {
        QuicTraceLogConnVerbose(
            RemoveSendFlagsMsg,
            QuicSendGetConnection(Send),
            "Removing flags %x",
            (SendFlags & Send->SendFlags));
        Send->SendFlags &= ~SendFlags;
    }

    QuicSendValidate(Send);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendUpdateAckState(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    BOOLEAN HasAckElicitingPacketsToAcknowledge = FALSE;
    for (uint32_t i = 0; i < QUIC_ENCRYPT_LEVEL_COUNT; ++i) {
        if (Connection->Packets[i] != NULL &&
            Connection->Packets[i]->AckTracker.AckElicitingPacketsToAcknowledge) {
            HasAckElicitingPacketsToAcknowledge = TRUE;
            break;
        }
    }

    if (!HasAckElicitingPacketsToAcknowledge) {
        if (Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK) {
            CXPLAT_DBG_ASSERT(!Send->DelayedAckTimerActive);
            Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_ACK;
        } else if (Send->DelayedAckTimerActive) {
            QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_ACK_DELAY);
            Send->DelayedAckTimerActive = FALSE;
        }
    }

    QuicSendValidate(Send);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSendSetStreamSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t SendFlags,
    _In_ BOOLEAN DelaySend
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    if (QuicConnIsClosed(Connection)) {
        //
        // Ignore all frames if the connection is closed.
        //
        return FALSE;
    }

    //
    // Remove any flags being queued based on the current state.
    //
    if (Stream->Flags.LocalCloseAcked) {
        SendFlags &=
            ~(QUIC_STREAM_SEND_FLAG_SEND_ABORT |
              QUIC_STREAM_SEND_FLAG_RELIABLE_ABORT |
              QUIC_STREAM_SEND_FLAG_DATA_BLOCKED |
              QUIC_STREAM_SEND_FLAG_DATA |
              QUIC_STREAM_SEND_FLAG_OPEN |
              QUIC_STREAM_SEND_FLAG_FIN);
    } else if (Stream->Flags.LocalCloseReset) {
        SendFlags &=
            ~(QUIC_STREAM_SEND_FLAG_DATA_BLOCKED |
              QUIC_STREAM_SEND_FLAG_DATA |
              QUIC_STREAM_SEND_FLAG_OPEN |
              QUIC_STREAM_SEND_FLAG_FIN);
    }
    if (Stream->Flags.RemoteCloseAcked) {
        SendFlags &= ~(QUIC_STREAM_SEND_FLAG_RECV_ABORT | QUIC_STREAM_SEND_FLAG_MAX_DATA);
    } else if (Stream->Flags.RemoteCloseFin || Stream->Flags.RemoteCloseReset) {
        SendFlags &= ~QUIC_STREAM_SEND_FLAG_MAX_DATA;
    }

    if ((Stream->SendFlags | SendFlags) != Stream->SendFlags ||
        (Stream->Flags.SendDelayed && (SendFlags & QUIC_STREAM_SEND_FLAG_DATA))) {

        QuicTraceLogStreamVerbose(
            SetSendFlag,
            Stream,
            "Setting flags 0x%x (existing flags: 0x%x)",
            (SendFlags & (uint32_t)(~Stream->SendFlags)),
            Stream->SendFlags);

        if (Stream->Flags.Started) {
            //
            // Since this is new data for a started stream, we need to queue
            // up the send to flush the stream data.
            //
            QuicSendQueueFlushForStream(Send, Stream, DelaySend);
        }
        Stream->SendFlags |= SendFlags;
    }

    return SendFlags != 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendClearStreamSendFlag(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_STREAM* Stream,
    _In_ uint32_t SendFlags
    )
{
    UNREFERENCED_PARAMETER(Send);

    if (Stream->SendFlags & SendFlags) {

        QuicTraceLogStreamVerbose(
            ClearSendFlags,
            Stream,
            "Removing flags %x",
            (SendFlags & Stream->SendFlags));

        //
        // Remove the flags since they are present.
        //
        Stream->SendFlags &= ~SendFlags;

        if (Stream->SendFlags == 0 && Stream->SendLink.Flink != NULL) {
            //
            // Since there are no flags left, remove the stream from the queue.
            //
            CxPlatListEntryRemove(&Stream->SendLink);
            Stream->SendLink.Flink = NULL;
            QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSendWriteFrames(
    _In_ QUIC_SEND* Send,
    _Inout_ QUIC_PACKET_BUILDER* Builder
    )
{
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET);

    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    uint16_t AvailableBufferLength =
        (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;
    uint8_t PrevFrameCount = Builder->Metadata->FrameCount;
    BOOLEAN RanOutOfRoom = FALSE;

    QUIC_PACKET_SPACE* Packets = Connection->Packets[Builder->EncryptLevel];
    CXPLAT_DBG_ASSERT(Packets != NULL);

    BOOLEAN IsCongestionControlBlocked = !QuicPacketBuilderHasAllowance(Builder);

    BOOLEAN Is1RttEncryptionLevel =
        Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_1_RTT ||
        Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_0_RTT;

    //
    // Now fill the packet with available frames, in priority order, until we
    // run out of space. The order below was generally chosen based on the
    // perceived importance of each type of frame. ACKs are the most important
    // frame, followed by connection close and then the rest of the connection
    // specific frames.
    //

    uint8_t ZeroRttPacketType =
        Connection->Stats.QuicVersion == QUIC_VERSION_2 ?
            QUIC_0_RTT_PROTECTED_V2 : QUIC_0_RTT_PROTECTED_V1;
    if (Builder->PacketType != ZeroRttPacketType &&
        QuicAckTrackerHasPacketsToAck(&Packets->AckTracker)) {
        if (!QuicAckTrackerAckFrameEncode(&Packets->AckTracker, Builder)) {
            RanOutOfRoom = TRUE;
            goto Exit;
        }
    }

    if (!IsCongestionControlBlocked &&
        Send->SendFlags & QUIC_CONN_SEND_FLAG_CRYPTO) {
        if (QuicCryptoWriteFrames(&Connection->Crypto, Builder)) {
            if (Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    if (Send->SendFlags & (QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE)) {
        BOOLEAN IsApplicationClose =
            !!(Send->SendFlags & QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE);
        if (Connection->State.ClosedRemotely) {
            //
            // Application closed should only be the origination of the
            // connection close. If we're closed remotely already, we should
            // just acknowledge the close with a connection close frame.
            //
            IsApplicationClose = FALSE;
        }

        QUIC_VAR_INT CloseErrorCode = Connection->CloseErrorCode;
        char* CloseReasonPhrase = Connection->CloseReasonPhrase;

        if (IsApplicationClose && ! Is1RttEncryptionLevel) {
            //
            // A CONNECTION_CLOSE of type 0x1d MUST be replaced by a CONNECTION_CLOSE of
            // type 0x1c when sending the frame in Initial or Handshake packets. Otherwise,
            // information about the application state might be revealed. Endpoints MUST
            // clear the value of the Reason Phrase field and SHOULD use the APPLICATION_ERROR
            // code when converting to a CONNECTION_CLOSE of type 0x1c.
            //
            CloseErrorCode = QUIC_ERROR_APPLICATION_ERROR;
            CloseReasonPhrase = NULL;
            IsApplicationClose = FALSE;
        }

        QUIC_CONNECTION_CLOSE_EX Frame = {
            IsApplicationClose,
            CloseErrorCode,
            0, // TODO - Set the FrameType field.
            CloseReasonPhrase == NULL ? 0 : strlen(CloseReasonPhrase),
            CloseReasonPhrase
        };

        if (QuicConnCloseFrameEncode(
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                Builder->Datagram->Buffer)) {

            Builder->WrittenConnectionCloseFrame = TRUE;

            //
            // We potentially send the close frame on multiple protection levels.
            // We send in increasing encryption level so clear the flag only once
            // we send on the current protection level.
            //
            if (Builder->Key->Type == Connection->Crypto.TlsState.WriteKey) {
                Send->SendFlags &= ~(QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE);
            }

            (void)QuicPacketBuilderAddFrame(
                Builder, IsApplicationClose ? QUIC_FRAME_CONNECTION_CLOSE_1 : QUIC_FRAME_CONNECTION_CLOSE, FALSE);
        } else {
            return FALSE; // Ran out of room.
        }

        return TRUE;
    }

    if (IsCongestionControlBlocked) {
        //
        // Everything below this is not allowed to be sent while CC blocked.
        //
        RanOutOfRoom = TRUE;
        goto Exit;
    }

    if (Send->SendFlags & QUIC_CONN_SEND_FLAG_PATH_RESPONSE) {

        uint8_t i;
        for (i = 0; i < Connection->PathsCount; ++i) {
            QUIC_PATH* TempPath = &Connection->Paths[i];
            if (!TempPath->SendResponse) {
                continue;
            }

            QUIC_PATH_RESPONSE_EX Frame = { 0 };
            CxPlatCopyMemory(Frame.Data, TempPath->Response, sizeof(Frame.Data));

            if (QuicPathChallengeFrameEncode(
                    QUIC_FRAME_PATH_RESPONSE,
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {

                TempPath->SendResponse = FALSE;
                CxPlatCopyMemory(
                    Builder->Metadata->Frames[Builder->Metadata->FrameCount].PATH_RESPONSE.Data,
                    Frame.Data,
                    sizeof(Frame.Data));
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_PATH_RESPONSE, TRUE)) {
                    break;
                }
            } else {
                RanOutOfRoom = TRUE;
                break;
            }
        }

        if (i == Connection->PathsCount) {
            Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_PATH_RESPONSE;
        }

        if (Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
            return TRUE;
        }
    }

    if (Is1RttEncryptionLevel) {
        if (Builder->Metadata->Flags.KeyType == QUIC_PACKET_KEY_1_RTT &&
            Send->SendFlags & QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE) {

            if (Builder->DatagramLength < AvailableBufferLength) {
                Builder->Datagram->Buffer[Builder->DatagramLength++] = QUIC_FRAME_HANDSHAKE_DONE;
                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE;
                Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_HANDSHAKE_DONE, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if (Send->SendFlags & QUIC_CONN_SEND_FLAG_DATA_BLOCKED) {

            QUIC_DATA_BLOCKED_EX Frame = { Send->OrderedStreamBytesSent };

            if (QuicDataBlockedFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {

                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_DATA_BLOCKED;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_DATA_BLOCKED, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_MAX_DATA)) {

            QUIC_MAX_DATA_EX Frame = { Send->MaxData };

            if (QuicMaxDataFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {

                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_MAX_DATA;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_MAX_DATA, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI)) {

            QUIC_MAX_STREAMS_EX Frame = { TRUE, 0 };
            Frame.MaximumStreams =
                QuicConnIsServer(Connection) ?
                    Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount :
                    Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;

            if (QuicMaxStreamsFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {

                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_MAX_STREAMS, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if (Send->SendFlags & QUIC_CONN_SEND_FLAG_BIDI_STREAMS_BLOCKED) {

            uint64_t Mask = QuicConnIsServer(Connection) | STREAM_ID_FLAG_IS_BI_DIR;

            QUIC_STREAMS_BLOCKED_EX Frame = {
                TRUE,
                Connection->Streams.Types[Mask].MaxTotalStreamCount
            };

            if (QuicStreamsBlockedFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {
                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_BIDI_STREAMS_BLOCKED;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_STREAMS_BLOCKED, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if (Send->SendFlags & QUIC_CONN_SEND_FLAG_UNI_STREAMS_BLOCKED) {

            uint64_t Mask = QuicConnIsServer(Connection) | STREAM_ID_FLAG_IS_UNI_DIR;

            QUIC_STREAMS_BLOCKED_EX Frame = {
                FALSE,
                Connection->Streams.Types[Mask].MaxTotalStreamCount
            };

            if (QuicStreamsBlockedFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {
                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_UNI_STREAMS_BLOCKED;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_STREAMS_BLOCKED_1, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI)) {

            QUIC_MAX_STREAMS_EX Frame = { FALSE };
            Frame.MaximumStreams =
                QuicConnIsServer(Connection) ?
                    Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount :
                    Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;

            if (QuicMaxStreamsFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {

                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_MAX_STREAMS_1, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID)) {

            BOOLEAN HasMoreCidsToSend = FALSE;
            BOOLEAN MaxFrameLimitHit = FALSE;
            for (CXPLAT_SLIST_ENTRY* Entry = Connection->SourceCids.Next;
                    Entry != NULL;
                    Entry = Entry->Next) {
                QUIC_CID_HASH_ENTRY* SourceCid =
                    CXPLAT_CONTAINING_RECORD(
                        Entry,
                        QUIC_CID_HASH_ENTRY,
                        Link);
                if (!SourceCid->CID.NeedsToSend) {
                    continue;
                }
                if (MaxFrameLimitHit) {
                    HasMoreCidsToSend = TRUE;
                    break;
                }

                QUIC_NEW_CONNECTION_ID_EX Frame = {
                    SourceCid->CID.Length,
                    SourceCid->CID.SequenceNumber,
                    0,
                    { 0 } };
                CXPLAT_DBG_ASSERT(Connection->SourceCidLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
                if (Frame.Sequence >= Connection->SourceCidLimit) {
                    Frame.RetirePriorTo = Frame.Sequence + 1 - Connection->SourceCidLimit;
                }
                CxPlatCopyMemory(
                    Frame.Buffer,
                    SourceCid->CID.Data,
                    SourceCid->CID.Length);
                CXPLAT_DBG_ASSERT(SourceCid->CID.Length == MsQuicLib.CidTotalLength);
                QuicLibraryGenerateStatelessResetToken(
                    Connection->Partition,
                    SourceCid->CID.Data,
                    Frame.Buffer + SourceCid->CID.Length);

                if (QuicNewConnectionIDFrameEncode(
                        &Frame,
                        &Builder->DatagramLength,
                        AvailableBufferLength,
                        Builder->Datagram->Buffer)) {

                    SourceCid->CID.NeedsToSend = FALSE;
                    Builder->Metadata->Frames[
                        Builder->Metadata->FrameCount].NEW_CONNECTION_ID.Sequence =
                            SourceCid->CID.SequenceNumber;
                    MaxFrameLimitHit =
                        QuicPacketBuilderAddFrame(
                            Builder, QUIC_FRAME_NEW_CONNECTION_ID, TRUE);
                } else {
                    RanOutOfRoom = TRUE;
                    HasMoreCidsToSend = TRUE;
                    break;
                }
            }
            if (!HasMoreCidsToSend) {
                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID;
            }
            if (MaxFrameLimitHit) {
                return TRUE;
            }
        }

        if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID)) {

            BOOLEAN HasMoreCidsToSend = FALSE;
            BOOLEAN MaxFrameLimitHit = FALSE;
            for (CXPLAT_LIST_ENTRY* Entry = Connection->DestCids.Flink;
                    Entry != &Connection->DestCids;
                    Entry = Entry->Flink) {
                QUIC_CID_LIST_ENTRY* DestCid =
                    CXPLAT_CONTAINING_RECORD(
                        Entry,
                        QUIC_CID_LIST_ENTRY,
                        Link);
                if (!DestCid->CID.NeedsToSend) {
                    continue;
                }
                CXPLAT_DBG_ASSERT(DestCid->CID.Retired);
                if (MaxFrameLimitHit) {
                    HasMoreCidsToSend = TRUE;
                    break;
                }

                QUIC_RETIRE_CONNECTION_ID_EX Frame = {
                    DestCid->CID.SequenceNumber
                };
                if (QuicRetireConnectionIDFrameEncode(
                        &Frame,
                        &Builder->DatagramLength,
                        AvailableBufferLength,
                        Builder->Datagram->Buffer)) {

                    DestCid->CID.NeedsToSend = FALSE;
                    Builder->Metadata->Frames[
                        Builder->Metadata->FrameCount].RETIRE_CONNECTION_ID.Sequence =
                            DestCid->CID.SequenceNumber;
                    MaxFrameLimitHit =
                        QuicPacketBuilderAddFrame(
                            Builder, QUIC_FRAME_RETIRE_CONNECTION_ID, TRUE);
                } else {
                    RanOutOfRoom = TRUE;
                    HasMoreCidsToSend = TRUE;
                    break;
                }
            }
            if (!HasMoreCidsToSend) {
                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID;
            }
            if (MaxFrameLimitHit) {
                return TRUE;
            }
        }

        if (Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK_FREQUENCY) {

            QUIC_ACK_FREQUENCY_EX Frame;
            Frame.SequenceNumber = Connection->SendAckFreqSeqNum;
            Frame.AckElicitingThreshold = Connection->PeerPacketTolerance;
            Frame.RequestedMaxAckDelay = MS_TO_US(QuicConnGetAckDelay(Connection));
            Frame.ReorderingThreshold = Connection->PeerReorderingThreshold;

            if (QuicAckFrequencyFrameEncode(
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    Builder->Datagram->Buffer)) {

                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_ACK_FREQUENCY;
                Builder->Metadata->Frames[
                    Builder->Metadata->FrameCount].ACK_FREQUENCY.Sequence =
                        Frame.SequenceNumber;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_ACK_FREQUENCY, TRUE)) {
                    return TRUE;
                }
            } else {
                RanOutOfRoom = TRUE;
            }
        }

        if (Send->SendFlags & QUIC_CONN_SEND_FLAG_DATAGRAM) {
            RanOutOfRoom = QuicDatagramWriteFrame(&Connection->Datagram, Builder);
            if (Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
                return TRUE;
            }
        }
    }

    if (Send->SendFlags & QUIC_CONN_SEND_FLAG_PING) {

        if (Builder->DatagramLength < AvailableBufferLength) {
            Builder->Datagram->Buffer[Builder->DatagramLength++] = QUIC_FRAME_PING;
            Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_PING;
            if (Connection->KeepAlivePadding) {
                Builder->MinimumDatagramLength =
                    Builder->DatagramLength + Connection->KeepAlivePadding + Builder->EncryptionOverhead;
                if (Builder->MinimumDatagramLength > (uint16_t)Builder->Datagram->Length) {
                    Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
                }
            } else {
                Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
            }
            if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_PING, TRUE)) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

Exit:

    //
    // The only valid reason to not have framed anything is that there was too
    // little room left in the packet to fit anything more.
    //
    CXPLAT_DBG_ASSERT(Builder->Metadata->FrameCount > PrevFrameCount || RanOutOfRoom ||
        CxPlatIsRandomMemoryFailureEnabled());
    UNREFERENCED_PARAMETER(RanOutOfRoom);

    return Builder->Metadata->FrameCount > PrevFrameCount;
}

BOOLEAN
QuicSendCanSendStreamNow(
    _In_ QUIC_STREAM* Stream
    )
{
    CXPLAT_DBG_ASSERT(Stream->SendFlags != 0);

    QUIC_CONNECTION* Connection = Stream->Connection;

    if (Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
        return QuicStreamCanSendNow(Stream, FALSE);
    }

    if (Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_0_RTT] != NULL) {
        return QuicStreamCanSendNow(Stream, TRUE);
    }

    return FALSE;
}

_Success_(return != NULL)
QUIC_STREAM*
QuicSendGetNextStream(
    _In_ QUIC_SEND* Send,
    _Out_ uint32_t* PacketCount
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    CXPLAT_DBG_ASSERT(!QuicConnIsClosed(Connection) || CxPlatListIsEmpty(&Send->SendStreams));

    CXPLAT_LIST_ENTRY* Entry = Send->SendStreams.Flink;
    while (Entry != &Send->SendStreams) {

        //
        // TODO: performance: We currently search through blocked
        // streams repeatedly as we loop.
        //

        QUIC_STREAM* Stream = CXPLAT_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink);

        //
        // Make sure, given the current state of the connection and the stream,
        // that we can use the stream to frame a packet.
        //
        if (QuicSendCanSendStreamNow(Stream)) {

            if (Connection->State.UseRoundRobinStreamScheduling) {
                //
                // Move the stream after any streams of the same priority. Start
                // with the "next" entry in the list and keep going until the
                // next entry's priority is less. Then move the stream before
                // that entry.
                //
                CXPLAT_LIST_ENTRY* LastEntry = Stream->SendLink.Flink;
                while (LastEntry != &Send->SendStreams) {
                    if (Stream->SendPriority >
                        CXPLAT_CONTAINING_RECORD(LastEntry, QUIC_STREAM, SendLink)->SendPriority) {
                        break;
                    }
                    LastEntry = LastEntry->Flink;
                }
                if (LastEntry->Blink != &Stream->SendLink) {
                    CxPlatListEntryRemove(&Stream->SendLink);
                    CxPlatListInsertTail(LastEntry, &Stream->SendLink);
                }

                *PacketCount = QUIC_STREAM_SEND_BATCH_COUNT;

            } else { // FIFO prioritization scheme
                *PacketCount = UINT32_MAX;
            }

            return Stream;
        }

        Entry = Entry->Flink;
    }

    return NULL;
}

BOOLEAN
CxPlatIsRouteReady(
    _In_ QUIC_CONNECTION *Connection,
    _In_ QUIC_PATH* Path
    )
{
    //
    // Make sure the route is resolved before sending packets.
    //
    if (Path->Route.State == RouteResolved) {
        return TRUE;
    }

    //
    // We need to set the path challenge flag back on so that when route is resolved,
    // we know we need to continue to send the challenge.
    //
    if (Path->Route.State == RouteUnresolved || Path->Route.State == RouteSuspected) {
        QuicConnAddRef(Connection, QUIC_CONN_REF_ROUTE);
        QUIC_STATUS Status =
            CxPlatResolveRoute(
                Path->Binding->Socket, &Path->Route, Path->ID, (void*)Connection, QuicConnQueueRouteCompletion);
        if (Status == QUIC_STATUS_SUCCESS) {
            QuicConnRelease(Connection, QUIC_CONN_REF_ROUTE);
            return TRUE;
        }
        //
        // Route resolution failed or pended. We need to pause sending.
        //
        CXPLAT_DBG_ASSERT(Status == QUIC_STATUS_PENDING || QUIC_FAILED(Status));
    }
    //
    // Path->Route.State == RouteResolving
    // Can't send now. Once route resolution completes, we will resume sending.
    //
    return FALSE;
}

//
// This function sends a path challenge frame out on all paths that currently
// need one sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendPathChallenges(
    _In_ QUIC_SEND* Send
    )
{
#pragma warning(push)
#pragma warning(disable:6001) // Using uninitialized memory
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL);

    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {

        QUIC_PATH* Path = &Connection->Paths[i];
        if (!Connection->Paths[i].SendChallenge ||
            Connection->Paths[i].Allowance < QUIC_MIN_SEND_ALLOWANCE) {
            continue;
        }

        if (!CxPlatIsRouteReady(Connection, Path)) {
            Send->SendFlags |= QUIC_CONN_SEND_FLAG_PATH_CHALLENGE;
            continue;
        }

        QUIC_PACKET_BUILDER Builder = { 0 };
        if (!QuicPacketBuilderInitialize(&Builder, Connection, Path)) {
            continue;
        }
        _Analysis_assume_(Builder.Metadata != NULL);

        if (!QuicPacketBuilderPrepareForControlFrames(
                &Builder, FALSE, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE)) {
            continue;
        }

        if (!Path->IsMinMtuValidated) {
            //
            // Path challenges need to be padded to at least the same as initial
            // packets to validate min MTU.
            //
            Builder.MinimumDatagramLength =
                MaxUdpPayloadSizeForFamily(
                    QuicAddrGetFamily(&Builder.Path->Route.RemoteAddress),
                    Builder.Path->Mtu);

            if ((uint32_t)Builder.MinimumDatagramLength > Builder.Datagram->Length) {
                //
                // If we're limited by amplification protection, just pad up to
                // that limit instead.
                //
                Builder.MinimumDatagramLength = (uint16_t)Builder.Datagram->Length;
            }
        }

        uint16_t AvailableBufferLength =
            (uint16_t)Builder.Datagram->Length - Builder.EncryptionOverhead;

        QUIC_PATH_CHALLENGE_EX Frame;
        CxPlatCopyMemory(Frame.Data, Path->Challenge, sizeof(Frame.Data));

        BOOLEAN Result =
            QuicPathChallengeFrameEncode(
                QUIC_FRAME_PATH_CHALLENGE,
                &Frame,
                &Builder.DatagramLength,
                AvailableBufferLength,
                Builder.Datagram->Buffer);

        CXPLAT_DBG_ASSERT(Result);
        if (Result) {
            CxPlatCopyMemory(
                Builder.Metadata->Frames[0].PATH_CHALLENGE.Data,
                Frame.Data,
                sizeof(Frame.Data));

            Result = QuicPacketBuilderAddFrame(&Builder, QUIC_FRAME_PATH_CHALLENGE, TRUE);
            CXPLAT_DBG_ASSERT(!Result);
            UNREFERENCED_PARAMETER(Result);

            Path->SendChallenge = FALSE;
        }

        QuicPacketBuilderFinalize(&Builder, TRUE);
        QuicPacketBuilderCleanup(&Builder);
    }
#pragma warning(pop)
}

typedef enum QUIC_SEND_RESULT {

    QUIC_SEND_COMPLETE,
    QUIC_SEND_INCOMPLETE,
    QUIC_SEND_DELAYED_PACING

} QUIC_SEND_RESULT;

#pragma warning(push)
#pragma warning(disable:6001) // SAL is confused by the QuicConnAddRef followed by QuicConnRelease.
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSendFlush(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    QUIC_PATH* Path = &Connection->Paths[0];

    CXPLAT_DBG_ASSERT(!Connection->State.HandleClosed);

    if (!CxPlatIsRouteReady(Connection, Path)) {
        return TRUE;
    }

    QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_PACING);
    QuicConnRemoveOutFlowBlockedReason(
        Connection, QUIC_FLOW_BLOCKED_SCHEDULING | QUIC_FLOW_BLOCKED_PACING);

    if (Path->DestCid == NULL) {
        return TRUE;
    }

    uint64_t TimeNow = CxPlatTimeUs64();
    QuicMtuDiscoveryCheckSearchCompleteTimeout(Connection, TimeNow);

    //
    // If path is active without being peer validated, disable MTU flag if set.
    //
    if (!Path->IsPeerValidated) {
        Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_DPLPMTUD;
    }

    if (Send->SendFlags == 0 && CxPlatListIsEmpty(&Send->SendStreams)) {
        return TRUE;
    }

    //
    // Connection CID changes on idle state after an amount of time
    //
    if (Connection->Settings.DestCidUpdateIdleTimeoutMs != 0 &&
        Send->LastFlushTimeValid &&
        CxPlatTimeDiff64(Send->LastFlushTime, TimeNow) >= MS_TO_US(Connection->Settings.DestCidUpdateIdleTimeoutMs)) {
        (void)QuicConnRetireCurrentDestCid(Connection, Path);
    }

    //
    // Send path challenges.
    // `QuicSendPathChallenges` might re-queue a path challenge immediately.
    //
    if (Send->SendFlags & QUIC_CONN_SEND_FLAG_PATH_CHALLENGE) {
        Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_PATH_CHALLENGE;
        QuicSendPathChallenges(Send);
    }

    QUIC_PACKET_BUILDER Builder = { 0 };
    if (!QuicPacketBuilderInitialize(&Builder, Connection, Path)) {
        //
        // If this fails, the connection is in a bad (likely partially
        // uninitialized) state, so just ignore the send flush call. This can
        // happen if a loss detection fires right after shutdown.
        //
        return TRUE;
    }
    _Analysis_assume_(Builder.Metadata != NULL);

    if (Builder.Path->EcnValidationState == ECN_VALIDATION_CAPABLE) {
        Builder.EcnEctSet = TRUE;
    } else if (Builder.Path->EcnValidationState == ECN_VALIDATION_TESTING) {
        if (Builder.Path->EcnTestingEndingTime != 0) {
            if (!CxPlatTimeAtOrBefore64(TimeNow, Builder.Path->EcnTestingEndingTime)) {
                Builder.Path->EcnValidationState = ECN_VALIDATION_UNKNOWN;
                QuicTraceLogConnInfo(
                    EcnValidationUnknown,
                    Connection,
                    "ECN unknown.");
            }
        } else {
            uint64_t ThreePtosInUs =
                QuicLossDetectionComputeProbeTimeout(
                    &Connection->LossDetection,
                    &Connection->Paths[0],
                    QUIC_CLOSE_PTO_COUNT);
            Builder.Path->EcnTestingEndingTime = TimeNow + ThreePtosInUs;
        }
        Builder.EcnEctSet = TRUE;
    }

    QuicTraceEvent(
        ConnFlushSend,
        "[conn][%p] Flushing Send. Allowance=%u bytes",
        Connection,
        Builder.SendAllowance);

#if DEBUG
    uint32_t DeadlockDetection = 0;
    uint32_t PrevSendFlags = UINT32_MAX;        // N-1
    uint32_t PrevPrevSendFlags = UINT32_MAX;    // N-2
#endif

    QUIC_SEND_RESULT Result = QUIC_SEND_INCOMPLETE;
    QUIC_STREAM* Stream = NULL;
    uint32_t StreamPacketCount = 0;
    do {

        if (Path->Allowance < QUIC_MIN_SEND_ALLOWANCE) {
            QuicTraceLogConnVerbose(
                AmplificationProtectionBlocked,
                Connection,
                "Cannot send any more because of amplification protection");
            Result = QUIC_SEND_COMPLETE;
            break;
        }

        uint32_t SendFlags = Send->SendFlags;
        if (Connection->Crypto.TlsState.WriteKey < QUIC_PACKET_KEY_1_RTT) {
            SendFlags &= QUIC_CONN_SEND_FLAG_ALLOWED_HANDSHAKE;
        }
        if (Path->Allowance != UINT32_MAX) {
            //
            // Don't try to send datagrams until the peer's source address has
            // been validated because they might not fit in the limited space.
            //
            SendFlags &= ~QUIC_CONN_SEND_FLAG_DATAGRAM;
        }

        if (!QuicPacketBuilderHasAllowance(&Builder)) {
            //
            // While we are CC blocked, very few things are still allowed to
            // be sent. If those are queued then we can still send.
            //
            SendFlags &= QUIC_CONN_SEND_FLAGS_BYPASS_CC;
            if (!SendFlags) {
                if (QuicCongestionControlCanSend(&Connection->CongestionControl)) {
                    //
                    // The current pacing chunk is finished. We need to schedule a
                    // new pacing send.
                    //
                    QuicConnAddOutFlowBlockedReason(
                        Connection, QUIC_FLOW_BLOCKED_PACING);
                    QuicConnTimerSet(
                        Connection,
                        QUIC_CONN_TIMER_PACING,
                        QUIC_SEND_PACING_INTERVAL);
                    Result = QUIC_SEND_DELAYED_PACING;
                } else {
                    //
                    // No pure ACKs to send right now. All done sending for now.
                    //
                    Result = QUIC_SEND_COMPLETE;
                }
                break;
            }
        }

        //
        // We write data to packets in the following order:
        //
        //   1. Connection wide control data.
        //   2. Path MTU discovery packets.
        //   3. Stream (control and application) data.
        //

        BOOLEAN WrotePacketFrames;
        BOOLEAN FlushBatchedDatagrams = FALSE;
        BOOLEAN SendConnectionControlData =
            (SendFlags & ~(QUIC_CONN_SEND_FLAG_DPLPMTUD |
                            QUIC_CONN_SEND_FLAG_PATH_CHALLENGE)) != 0;
        if (SendConnectionControlData) {
            CXPLAT_DBG_ASSERT(QuicSendCanSendFlagsNow(Send));
            if (!QuicPacketBuilderPrepareForControlFrames(
                    &Builder,
                    Send->TailLossProbeNeeded,
                    SendFlags & ~QUIC_CONN_SEND_FLAG_DPLPMTUD)) {
                break;
            }
            WrotePacketFrames = QuicSendWriteFrames(Send, &Builder);
        } else if ((SendFlags & QUIC_CONN_SEND_FLAG_DPLPMTUD) != 0) {
            if (!QuicPacketBuilderPrepareForPathMtuDiscovery(&Builder)) {
                break;
            }
            FlushBatchedDatagrams = TRUE;
            Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_DPLPMTUD;
            if (Builder.Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET &&
                Builder.DatagramLength < Builder.Datagram->Length - Builder.EncryptionOverhead) {
                //
                // We are doing DPLPMTUD, so make sure there is a PING frame in there, if
                // we have room, just to make sure we get an ACK.
                //
                Builder.Datagram->Buffer[Builder.DatagramLength++] = QUIC_FRAME_PING;
                Builder.Metadata->Frames[Builder.Metadata->FrameCount++].Type = QUIC_FRAME_PING;
                WrotePacketFrames = TRUE;
            } else {
                WrotePacketFrames = FALSE;
            }
        } else if (Stream != NULL ||
            (Stream = QuicSendGetNextStream(Send, &StreamPacketCount)) != NULL) {
            if (!QuicPacketBuilderPrepareForStreamFrames(
                    &Builder,
                    Send->TailLossProbeNeeded)) {
                break;
            }

            //
            // Write any ACK frames if we have them.
            //
            QUIC_PACKET_SPACE* Packets = Connection->Packets[Builder.EncryptLevel];
            uint8_t ZeroRttPacketType =
                Connection->Stats.QuicVersion == QUIC_VERSION_2 ?
                    QUIC_0_RTT_PROTECTED_V2 : QUIC_0_RTT_PROTECTED_V1;
            WrotePacketFrames =
                Builder.PacketType != ZeroRttPacketType &&
                QuicAckTrackerHasPacketsToAck(&Packets->AckTracker) &&
                QuicAckTrackerAckFrameEncode(&Packets->AckTracker, &Builder);

            //
            // Write the stream frames.
            //
            WrotePacketFrames |= QuicStreamSendWrite(Stream, &Builder);

            if (Stream->SendFlags == 0 && Stream->SendLink.Flink != NULL) {
                //
                // If the stream no longer has anything to send, remove it from the
                // list and release Send's reference on it.
                //
                CxPlatListEntryRemove(&Stream->SendLink);
                Stream->SendLink.Flink = NULL;
                QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND);
                Stream = NULL;

            } else if ((WrotePacketFrames && --StreamPacketCount == 0) ||
                !QuicSendCanSendStreamNow(Stream)) {
                //
                // Try a new stream next loop iteration.
                //
                Stream = NULL;
            }

        } else {
            //
            // Nothing else left to send right now.
            //
            Result = QUIC_SEND_COMPLETE;
            break;
        }

        Send->TailLossProbeNeeded = FALSE;

        if (!WrotePacketFrames ||
            Builder.Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET ||
            Builder.Datagram->Length - Builder.DatagramLength < QUIC_MIN_PACKET_SPARE_SPACE) {

            //
            // We now have enough data in the current packet that we should
            // finalize it.
            //
            if (!QuicPacketBuilderFinalize(&Builder, !WrotePacketFrames || FlushBatchedDatagrams)) {
                //
                // Don't have any more space to send.
                //
                break;
            }
        }

#if DEBUG
        CXPLAT_DBG_ASSERT(++DeadlockDetection < 1000);
        UNREFERENCED_PARAMETER(PrevPrevSendFlags); // Used in debugging only
        PrevPrevSendFlags = PrevSendFlags;
        PrevSendFlags = SendFlags;
#endif

    } while (Builder.SendData != NULL ||
        Builder.TotalCountDatagrams < QUIC_MAX_DATAGRAMS_PER_SEND);

    if (Builder.SendData != NULL) {
        //
        // Final send, if there is anything left over.
        //
        QuicPacketBuilderFinalize(&Builder, TRUE);
        CXPLAT_DBG_ASSERT(Builder.SendData == NULL);
    }

    QuicPacketBuilderCleanup(&Builder);

    QuicTraceLogConnVerbose(
        SendFlushComplete,
        Connection,
        "Flush complete flags=0x%x",
        Send->SendFlags);

    if (Result == QUIC_SEND_INCOMPLETE) {
        //
        // The send is limited by the scheduling logic.
        //
        QuicConnAddOutFlowBlockedReason(Connection, QUIC_FLOW_BLOCKED_SCHEDULING);

        //
        // We have more data to send so we need to make sure a flush send
        // operation is queued to send the rest.
        //
        QuicSendQueueFlush(&Connection->Send, REASON_SCHEDULING);

        if (Builder.TotalCountDatagrams + 1 > Connection->PeerPacketTolerance) {
            //
            // We're scheduling limited, so we should tell the peer to use our
            // (max) batch size + 1 as the peer tolerance as a hint that they
            // should expect more than a single batch before needing to send an
            // acknowledgment back.
            //
            QuicConnUpdatePeerPacketTolerance(Connection, Builder.TotalCountDatagrams + 1);
        }

    } else if (Builder.TotalCountDatagrams > Connection->PeerPacketTolerance) {
        //
        // If we aren't scheduling limited, we should just use the current batch
        // size as the packet tolerance for the peer to use for acknowledging
        // packets.
        //
        // Temporarily disabled for now.
        //QuicConnUpdatePeerPacketTolerance(Connection, Builder.TotalCountDatagrams);
    }

    //
    // Clears the SendQueue list of not sent packets if the flag is applied
    //
    QuicDatagramCancelBlocked(Connection);

    return Result != QUIC_SEND_INCOMPLETE;
}
#pragma warning(pop)

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendStartDelayedAckTimer(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    CXPLAT_DBG_ASSERT(Connection->Settings.MaxAckDelayMs != 0);
    if (!Send->DelayedAckTimerActive &&
        !(Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK) &&
        !Connection->State.ClosedLocally &&
        !Connection->State.ClosedRemotely) {

        QuicTraceLogConnVerbose(
            StartAckDelayTimer,
            Connection,
            "Starting ACK_DELAY timer for %u ms",
            Connection->Settings.MaxAckDelayMs);
        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_ACK_DELAY,
            MS_TO_US(Connection->Settings.MaxAckDelayMs)); // TODO - Use smaller timeout when handshake data is outstanding.
        Send->DelayedAckTimerActive = TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendProcessDelayedAckTimer(
    _In_ QUIC_SEND* Send
    )
{
    CXPLAT_DBG_ASSERT(Send->DelayedAckTimerActive);
    CXPLAT_DBG_ASSERT(!(Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK));
    Send->DelayedAckTimerActive = FALSE;

    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    BOOLEAN AckElicitingPacketsToAcknowledge = FALSE;
    for (uint32_t i = 0; i < QUIC_ENCRYPT_LEVEL_COUNT; ++i) {
        if (Connection->Packets[i] != NULL &&
            Connection->Packets[i]->AckTracker.AckElicitingPacketsToAcknowledge) {
            AckElicitingPacketsToAcknowledge = TRUE;
            break;
        }
    }

    CXPLAT_DBG_ASSERT(AckElicitingPacketsToAcknowledge);
    if (AckElicitingPacketsToAcknowledge) {
        Send->SendFlags |= QUIC_CONN_SEND_FLAG_ACK;
    }

    QuicSendValidate(Send);
}
