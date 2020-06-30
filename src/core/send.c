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
    _Inout_ QUIC_SEND* Send
    )
{
    QuicListInitializeHead(&Send->SendStreams);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendUninitialize(
    _In_ QUIC_SEND* Send
    )
{
    Send->DelayedAckTimerActive = FALSE;

    if (Send->InitialToken != NULL) {
        QUIC_FREE(Send->InitialToken);
        Send->InitialToken = NULL;
    }

    //
    // Release all the stream refs.
    //
    QUIC_LIST_ENTRY* Entry = Send->SendStreams.Flink;
    while (Entry != &Send->SendStreams) {

        QUIC_STREAM* Stream =
            QUIC_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink);
        QUIC_DBG_ASSERT(Stream->SendFlags != 0);

        Entry = Entry->Flink;
        Stream->SendFlags = 0;
        Stream->SendLink.Flink = NULL;

        QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSendApplySettings(
    _Inout_ QUIC_SEND* Send,
    _In_ const QUIC_SETTINGS* Settings
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
        QuicTraceLogConnVerbose(
            CancelAckDelayTimer,
            QuicSendGetConnection(Send),
            "Canceling ACK_DELAY timer");
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
        if ((!Connection->State.Started && !QuicConnIsServer(Connection)) ||
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
    if (!Send->FlushOperationPending && QuicSendCanSendFlagsNow(Send)) {
        QUIC_OPERATION* Oper;
        QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
        if ((Oper = QuicOperationAlloc(Connection->Worker, QUIC_OPER_TYPE_FLUSH_SEND)) != NULL) {
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
    _In_ BOOLEAN WasPreviouslyQueued
    )
{
    if (!WasPreviouslyQueued) {
        //
        // Not previously queued, so add the stream to the end of the queue.
        //
        QUIC_DBG_ASSERT(Stream->SendLink.Flink == NULL);
        QuicListInsertTail(&Send->SendStreams, &Stream->SendLink);
        QuicStreamAddRef(Stream, QUIC_STREAM_REF_SEND);
    }

    if (Stream->Connection->State.Started) {
        //
        // Schedule the flush even if we didn't just queue the stream,
        // because it may have been previously blocked.
        //
        QuicSendQueueFlush(Send, REASON_STREAM_FLAGS);
    }
}

#if DEBUG
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendValidate(
    _In_ QUIC_SEND* Send
    )
{
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
        QUIC_DBG_ASSERT(!Send->DelayedAckTimerActive);
        QUIC_DBG_ASSERT(HasAckElicitingPacketsToAcknowledge);
    } else if (Send->DelayedAckTimerActive) {
        QUIC_DBG_ASSERT(HasAckElicitingPacketsToAcknowledge);
    } else if (!Connection->State.ClosedLocally && !Connection->State.ClosedRemotely) {
        QUIC_DBG_ASSERT(!HasAckElicitingPacketsToAcknowledge);
    }
}
#else
#define QuicSendValidate(Send)
#endif

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
        QuicTraceLogConnVerbose(
            CancelAckDelayTimer,
            Connection,
            "Canceling ACK_DELAY timer");
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

        //
        // Remove all flags for things we aren't allowed to send once the connection
        // has been closed.
        //
        Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_CONN_CLOSED_MASK;

        //
        // Remove any queued up streams.
        //
        while (!QuicListIsEmpty(&Send->SendStreams)) {

            QUIC_STREAM* Stream =
                QUIC_CONTAINING_RECORD(
                    QuicListRemoveHead(&Send->SendStreams), QUIC_STREAM, SendLink);

            QUIC_DBG_ASSERT(Stream->SendFlags != 0);
            Stream->SendFlags = 0;
            Stream->SendLink.Flink = NULL;

            QuicStreamRelease(Stream, QUIC_STREAM_REF_SEND);
        }
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
            RemoveSendFlags,
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
            QUIC_DBG_ASSERT(!Send->DelayedAckTimerActive);
            Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_ACK;
        } else if (Send->DelayedAckTimerActive) {
            QuicTraceLogConnVerbose(
                CancelAckDelayTimer,
                Connection,
                "Canceling ACK_DELAY timer");
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
    _In_ uint32_t SendFlags
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

    if ((Stream->SendFlags | SendFlags) != Stream->SendFlags) {

        QuicTraceLogStreamVerbose(
            SetSendFlag,
            Stream,
            "Setting flags 0x%x (existing flags: 0x%x)",
            (SendFlags & (~Stream->SendFlags)),
            Stream->SendFlags);

        if (Stream->Flags.Started &&
            (Stream->SendFlags & SendFlags) != SendFlags) {
            //
            // Since this is new data for a started stream, we need to queue
            // up the send to flush the stream data.
            //
            QuicSendQueueFlushForStream(Send, Stream, Stream->SendFlags != 0);
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

        if (Stream->SendFlags == 0 && Stream->Flags.Started) {
            //
            // Since there are no flags left, remove the stream from the queue.
            //
            QUIC_DBG_ASSERT(Stream->SendLink.Flink != NULL);
            QuicListEntryRemove(&Stream->SendLink);
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
    QUIC_DBG_ASSERT(Builder->Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET);

    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    uint16_t AvailableBufferLength =
        (uint16_t)Builder->Datagram->Length - Builder->EncryptionOverhead;
    uint8_t PrevFrameCount = Builder->Metadata->FrameCount;
    BOOLEAN RanOutOfRoom = FALSE;

    QUIC_PACKET_SPACE* Packets = Connection->Packets[Builder->EncryptLevel];
    QUIC_DBG_ASSERT(Packets != NULL);

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

    if (Builder->PacketType != QUIC_0_RTT_PROTECTED &&
        QuicAckTrackerHasPacketsToAck(&Packets->AckTracker)) {
        if (!QuicAckTrackerAckFrameEncode(&Packets->AckTracker, Builder)) {
            RanOutOfRoom = TRUE;
            goto Exit;
        }
    }

    if (!IsCongestionControlBlocked &&
        Send->SendFlags & QUIC_CONN_SEND_FLAG_CRYPTO &&
        Builder->PacketType == QuicEncryptLevelToPacketType(QuicCryptoGetNextEncryptLevel(&Connection->Crypto))) {
        if (QuicCryptoWriteFrames(&Connection->Crypto, Builder)) {
            if (Builder->Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET) {
                return TRUE;
            }
        } else {
            RanOutOfRoom = TRUE;
        }
    }

    if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE) ||
        ((Send->SendFlags & QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE) && Is1RttEncryptionLevel)) {
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

        QUIC_CONNECTION_CLOSE_EX Frame = {
            IsApplicationClose,
            Connection->State.ClosedRemotely ? 0 : Connection->CloseErrorCode,
            0, // TODO - Set the FrameType field.
            Connection->CloseReasonPhrase == NULL ? 0 : strlen(Connection->CloseReasonPhrase),
            Connection->CloseReasonPhrase
        };

        if (QuicConnCloseFrameEncode(
                &Frame,
                &Builder->DatagramLength,
                AvailableBufferLength,
                (uint8_t*)Builder->Datagram->Buffer)) {

            Send->SendFlags &= ~(QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE | QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE);
            (void)QuicPacketBuilderAddFrame(
                Builder, IsApplicationClose ? QUIC_FRAME_CONNECTION_CLOSE_1 : QUIC_FRAME_CONNECTION_CLOSE, FALSE);
        } else {
            RanOutOfRoom = TRUE;
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
            QuicCopyMemory(Frame.Data, TempPath->Response, sizeof(Frame.Data));

            if (QuicPathChallengeFrameEncode(
                    QUIC_FRAME_PATH_RESPONSE,
                    &Frame,
                    &Builder->DatagramLength,
                    AvailableBufferLength,
                    (uint8_t*)Builder->Datagram->Buffer)) {

                TempPath->SendResponse = FALSE;
                QuicCopyMemory(
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
                    (uint8_t*)Builder->Datagram->Buffer)) {

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
                    (uint8_t*)Builder->Datagram->Buffer)) {

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
                    (uint8_t*)Builder->Datagram->Buffer)) {

                Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI;
                if (QuicPacketBuilderAddFrame(Builder, QUIC_FRAME_MAX_STREAMS, TRUE)) {
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
                    (uint8_t*)Builder->Datagram->Buffer)) {

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
            for (QUIC_SINGLE_LIST_ENTRY* Entry = Connection->SourceCids.Next;
                    Entry != NULL;
                    Entry = Entry->Next) {
                QUIC_CID_HASH_ENTRY* SourceCid =
                    QUIC_CONTAINING_RECORD(
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
                QUIC_DBG_ASSERT(Connection->SourceCidLimit >= QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN);
                if (Frame.Sequence >= Connection->SourceCidLimit) {
                    Frame.RetirePriorTo = Frame.Sequence + 1 - Connection->SourceCidLimit;
                }
                QuicCopyMemory(
                    Frame.Buffer,
                    SourceCid->CID.Data,
                    SourceCid->CID.Length);
                QUIC_DBG_ASSERT(SourceCid->CID.Length == MsQuicLib.CidTotalLength);
                QuicBindingGenerateStatelessResetToken(
                    Builder->Path->Binding,
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
            if (MaxFrameLimitHit || RanOutOfRoom) {
                return TRUE;
            }
        }

        if ((Send->SendFlags & QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID)) {

            BOOLEAN HasMoreCidsToSend = FALSE;
            BOOLEAN MaxFrameLimitHit = FALSE;
            for (QUIC_LIST_ENTRY* Entry = Connection->DestCids.Flink;
                    Entry != &Connection->DestCids;
                    Entry = Entry->Flink) {
                QUIC_CID_QUIC_LIST_ENTRY* DestCid =
                    QUIC_CONTAINING_RECORD(
                        Entry,
                        QUIC_CID_QUIC_LIST_ENTRY,
                        Link);
                if (!DestCid->CID.NeedsToSend) {
                    continue;
                }
                QUIC_DBG_ASSERT(DestCid->CID.Retired);
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
            if (MaxFrameLimitHit || RanOutOfRoom) {
                return TRUE;
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
            Builder->MinimumDatagramLength = (uint16_t)Builder->Datagram->Length;
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
    QUIC_DBG_ASSERT(Builder->Metadata->FrameCount > PrevFrameCount || RanOutOfRoom);
    UNREFERENCED_PARAMETER(RanOutOfRoom);

    return Builder->Metadata->FrameCount > PrevFrameCount;
}

BOOLEAN
QuicSendCanSendStreamNow(
    _In_ QUIC_STREAM* Stream
    )
{
    QUIC_DBG_ASSERT(Stream->SendFlags != 0);

    QUIC_CONNECTION* Connection = Stream->Connection;

    if (Connection->Crypto.TlsState.WriteKey == QUIC_PACKET_KEY_1_RTT) {
        return QuicStreamCanSendNow(Stream, FALSE);
    } else if (Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_0_RTT] != NULL) {
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
    QUIC_DBG_ASSERT(!QuicConnIsClosed(Connection) || QuicListIsEmpty(&Send->SendStreams));

    QUIC_LIST_ENTRY* Entry = Send->SendStreams.Flink;
    while (Entry != &Send->SendStreams) {

        //
        // TODO: performance: We currently search through blocked
        // streams repeatedly as we loop.
        //

        QUIC_STREAM* Stream = QUIC_CONTAINING_RECORD(Entry, QUIC_STREAM, SendLink);

        //
        // Make sure, given the current state of the connection and the stream,
        // that we can use the stream to frame a packet.
        //
        if (QuicSendCanSendStreamNow(Stream)) {

            if (Connection->State.UseRoundRobinStreamScheduling) {
                //
                // Move the stream to the end of the queue.
                //
                QuicListEntryRemove(&Stream->SendLink);
                QuicListInsertTail(&Send->SendStreams, &Stream->SendLink);

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
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    QUIC_DBG_ASSERT(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL);

    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {

        QUIC_PATH* Path = &Connection->Paths[i];
        if (!Connection->Paths[i].SendChallenge ||
            Connection->Paths[i].Allowance < QUIC_MIN_SEND_ALLOWANCE) {
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

        uint16_t AvailableBufferLength =
            (uint16_t)Builder.Datagram->Length - Builder.EncryptionOverhead;

        QUIC_PATH_CHALLENGE_EX Frame;
        QuicCopyMemory(Frame.Data, Path->Challenge, sizeof(Frame.Data));

        BOOLEAN Result =
            QuicPathChallengeFrameEncode(
                QUIC_FRAME_PATH_CHALLENGE,
                &Frame,
                &Builder.DatagramLength,
                AvailableBufferLength,
                Builder.Datagram->Buffer);

        QUIC_DBG_ASSERT(Result);
        if (Result) {
            QuicCopyMemory(
                Builder.Metadata->Frames[0].PATH_CHALLENGE.Data,
                Frame.Data,
                sizeof(Frame.Data));

            Result = QuicPacketBuilderAddFrame(&Builder, QUIC_FRAME_PATH_CHALLENGE, TRUE);
            QUIC_DBG_ASSERT(!Result);
            UNREFERENCED_PARAMETER(Result);

            Path->SendChallenge = FALSE;
        }

        QuicPacketBuilderFinalize(&Builder, TRUE);
        QuicPacketBuilderCleanup(&Builder);
    }
}

typedef enum QUIC_SEND_RESULT {

    QUIC_SEND_COMPLETE,
    QUIC_SEND_INCOMPLETE,
    QUIC_SEND_DELAYED_PACING

} QUIC_SEND_RESULT;

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicSendFlush(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    QUIC_DBG_ASSERT(!Connection->State.HandleClosed);

    QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_PACING);
    QuicConnRemoveOutFlowBlockedReason(
        Connection, QUIC_FLOW_BLOCKED_SCHEDULING | QUIC_FLOW_BLOCKED_PACING);

    if (Send->SendFlags == 0 && QuicListIsEmpty(&Send->SendStreams)) {
        return TRUE;
    }

    QUIC_PATH* Path = &Connection->Paths[0];
    if (Path->DestCid == NULL) {
        return TRUE;
    }

    QUIC_DBG_ASSERT(QuicSendCanSendFlagsNow(Send));

    QUIC_SEND_RESULT Result = QUIC_SEND_INCOMPLETE;
    QUIC_STREAM* Stream = NULL;
    uint32_t StreamPacketCount = 0;

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

    QuicTraceLogConnVerbose(
        FlushSend,
        Connection,
        "Flushing send. Allowance=%u bytes",
        Builder.SendAllowance);

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
                    QuicTraceLogConnVerbose(
                        SetPacingTimer,
                        Connection,
                        "Setting delayed send (PACING) timer for %u ms",
                        QUIC_SEND_PACING_INTERVAL);
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
        //   2. Stream (control and application) data.
        //   3. Path MTU discovery packets.
        //

        BOOLEAN WrotePacketFrames;
        BOOLEAN FlushBatchedDatagrams = FALSE;
        if ((SendFlags & ~QUIC_CONN_SEND_FLAG_PMTUD) != 0) {
            QUIC_DBG_ASSERT(QuicSendCanSendFlagsNow(Send));
            if (!QuicPacketBuilderPrepareForControlFrames(
                    &Builder,
                    Send->TailLossProbeNeeded,
                    SendFlags & ~QUIC_CONN_SEND_FLAG_PMTUD)) {
                break;
            }
            WrotePacketFrames = QuicSendWriteFrames(Send, &Builder);

        } else if (Stream != NULL ||
            (Stream = QuicSendGetNextStream(Send, &StreamPacketCount)) != NULL) {
            if (!QuicPacketBuilderPrepareForStreamFrames(
                    &Builder,
                    Send->TailLossProbeNeeded)) {
                break;
            }
            WrotePacketFrames = QuicStreamSendWrite(Stream, &Builder);

            if (Stream->SendFlags == 0) {
                //
                // If the stream no longer has anything to send, remove it from the
                // list and release Send's reference on it.
                //
                QuicListEntryRemove(&Stream->SendLink);
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

        } else if (SendFlags == QUIC_CONN_SEND_FLAG_PMTUD) {
            if (!QuicPacketBuilderPrepareForPathMtuDiscovery(&Builder)) {
                break;
            }
            FlushBatchedDatagrams = TRUE;
            Send->SendFlags &= ~QUIC_CONN_SEND_FLAG_PMTUD;
            if (Builder.Metadata->FrameCount < QUIC_MAX_FRAMES_PER_PACKET &&
                Builder.DatagramLength < Builder.Datagram->Length - Builder.EncryptionOverhead) {
                //
                // We are doing PMTUD, so make sure there is a PING frame in there, if
                // we have room, just to make sure we get an ACK.
                //
                Builder.Datagram->Buffer[Builder.DatagramLength++] = QUIC_FRAME_PING;
                Builder.Metadata->Frames[Builder.Metadata->FrameCount++].Type = QUIC_FRAME_PING;
                WrotePacketFrames = TRUE;
            } else {
                WrotePacketFrames = FALSE;
            }

        } else {
            //
            // Nothing else left to send right now.
            //
            Result = QUIC_SEND_COMPLETE;
            break;
        }

        Send->TailLossProbeNeeded = FALSE;

        //
        // If the following assert is hit, then we just went through the
        // framing logic and nothing was written to the packet. This is bad!
        // It likely indicates an infinite loop will follow.
        //
        QUIC_DBG_ASSERT(Builder.Metadata->FrameCount != 0 || Builder.PacketStart != 0);

        if (!WrotePacketFrames ||
            Builder.Metadata->FrameCount == QUIC_MAX_FRAMES_PER_PACKET ||
            Builder.Datagram->Length - Builder.DatagramLength < QUIC_MIN_PACKET_SPARE_SPACE) {

            //
            // We now have enough data in the current packet that we should
            // finalize it.
            //
            QuicPacketBuilderFinalize(&Builder, FlushBatchedDatagrams);
        }

    } while (Builder.SendContext != NULL ||
        Builder.TotalCountDatagrams < QUIC_MAX_DATAGRAMS_PER_SEND);

    if (Builder.SendContext != NULL) {
        //
        // Final send, if there is anything left over.
        //
        QuicPacketBuilderFinalize(&Builder, TRUE);
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
    }

    return Result != QUIC_SEND_INCOMPLETE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendStartDelayedAckTimer(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);

    if (!Send->DelayedAckTimerActive &&
        !(Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK) &&
        !Connection->State.ClosedLocally &&
        !Connection->State.ClosedRemotely) {

        QuicTraceLogConnVerbose(
            StartAckDelayTimer,
            Connection,
            "Starting ACK_DELAY timer for %u ms",
            Connection->MaxAckDelayMs);
        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_ACK_DELAY,
            Connection->MaxAckDelayMs); // TODO - Use smaller timeout when handshake data is outstanding.
        Send->DelayedAckTimerActive = TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendProcessDelayedAckTimer(
    _In_ QUIC_SEND* Send
    )
{
    QUIC_DBG_ASSERT(Send->DelayedAckTimerActive);
    QUIC_DBG_ASSERT(!(Send->SendFlags & QUIC_CONN_SEND_FLAG_ACK));
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

    QUIC_DBG_ASSERT(AckElicitingPacketsToAcknowledge);
    if (AckElicitingPacketsToAcknowledge) {
        Send->SendFlags |= QUIC_CONN_SEND_FLAG_ACK;
    }

    QuicSendValidate(Send);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendOnMtuProbePacketAcked(
    _In_ QUIC_SEND* Send,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_SENT_PACKET_METADATA* Packet
    )
{
    QUIC_CONNECTION* Connection = QuicSendGetConnection(Send);
    Path->Mtu =
        PacketSizeFromUdpPayloadSize(
            QuicAddrGetFamily(&Path->RemoteAddress),
            Packet->PacketLength);
    QuicTraceLogConnInfo(
        PathMtuUpdated,
        QuicSendGetConnection(Send),
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);
    QuicDatagramOnSendStateChanged(&Connection->Datagram);
}
