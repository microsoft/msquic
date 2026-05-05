/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The QMux is a component of the connection that manages QMux operations.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "qmux.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxProcessHandshakeData(
    _In_ QUIC_QMUX* QMux,
    _In_reads_bytes_(*BufferLength)
        const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_QMUX** NewQMux
    )
{
    QUIC_QMUX* QMux = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QMux = CxPlatPoolAlloc(&Connection->Partition->ConnectionQMuxPool);
    if (QMux == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection QMux",
            sizeof(QUIC_QMUX));
        goto Error;
    }

    CxPlatZeroMemory(QMux, sizeof(QUIC_QMUX));

    QMux->RecvBufferAllocLength = QX_TP_MAX_RECORD_SIZE_DEFAULT + 2; // Add 2 bytes for length field.
    QMux->RecvBuffer = CXPLAT_ALLOC_NONPAGED(QMux->RecvBufferAllocLength, QUIC_POOL_QMUX_RECV_BUFFER);
    if (QMux->RecvBuffer == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QMux receive buffer",
            QMux->RecvBufferAllocLength);
        goto Error;
    }

    QMux->Connection = Connection;
    QMux->TcpReceiveQueueTail = &QMux->TcpReceiveQueue;
    CxPlatDispatchLockInitialize(&QMux->TcpReceiveQueueLock);
    CxPlatEventInitialize(&QMux->ConnectEvent, TRUE, FALSE);

    *NewQMux = QMux;
    return Status;

Error:
    if (QMux != NULL && QMux->RecvBuffer != NULL) {
        CXPLAT_FREE(QMux->RecvBuffer, QUIC_POOL_QMUX_RECV_BUFFER);
    }
    if (QMux != NULL) {
        CxPlatPoolFree(QMux);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicQMuxUninitialize(
    _In_ QUIC_QMUX* QMux
    )
{
    if (QMux->TcpReceiveQueue != NULL) {
        CxPlatRecvDataReturn(QMux->TcpReceiveQueue);
        QMux->TcpReceiveQueue = NULL;
    }

    if (QMux->RecvBuffer != NULL) {
        CXPLAT_FREE(QMux->RecvBuffer, QUIC_POOL_QMUX_RECV_BUFFER);
        QMux->RecvBuffer = NULL;
    }
    CxPlatPoolFree(QMux);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxInitializeTls(
    _Inout_ QUIC_QMUX* QMux,
    _In_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
    QUIC_CONNECTION* Connection = QMux->Connection;
    QUIC_STATUS Status;
    CXPLAT_TLS_CONFIG TlsConfig = { 0 };
    BOOLEAN IsServer = QuicConnIsServer(Connection);

    CXPLAT_DBG_ASSERT(SecConfig != NULL);
    CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);

    TlsConfig.IsQMux = TRUE;
    TlsConfig.IsServer = IsServer;
    TlsConfig.AlpnBuffer = Connection->Configuration->AlpnList;
    TlsConfig.AlpnBufferLength = Connection->Configuration->AlpnListLength;

    TlsConfig.SecConfig = SecConfig;
    TlsConfig.Connection = Connection;
    // TlsConfig.ResumptionTicketBuffer = Crypto->ResumptionTicket;
    // TlsConfig.ResumptionTicketLength = Crypto->ResumptionTicketLength;
    if (QuicConnIsClient(Connection)) {
        TlsConfig.ServerName = Connection->RemoteServerName;
    }
    TlsConfig.TlsSecrets = Connection->TlsSecrets;

    if (QMux->TLS != NULL) {
        CxPlatTlsUninitialize(QMux->TLS);
        QMux->TLS = NULL;
    }

    Status = CxPlatTlsInitialize(&TlsConfig, &QMux->TlsState, &QMux->TLS);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "CxPlatTlsInitialize");
        goto Error;
    }

    CxPlatTlsGetRecordOverhead(QMux->TLS, &QMux->TlsRecordOverhead);

    // Crypto->ResumptionTicket = NULL; // Owned by TLS now.
    // Crypto->ResumptionTicketLength = 0;
    if (QuicConnIsClient(Connection)) {
        uint32_t BufferLength = 0;
        Status = QuicQMuxProcessHandshakeData(QMux, NULL, &BufferLength);
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxProcessHandshakeData(
    _In_ QUIC_QMUX* QMux,
    _In_reads_bytes_(*BufferLength)
        const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength
    )
{
    QUIC_CONNECTION* Connection = QMux->Connection;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SEND_DATA* SendData = NULL;
    uint32_t TotalSendLength = 0;

    if (QMux->TLS == NULL) {
        //
        // The listener still hasn't given us the security config to initialize
        // TLS with yet.
        //
        goto Exit;
    }

    CXPLAT_SEND_CONFIG SendConfig = { &QMux->Route, 16384 + 256, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0 };

    SendData = CxPlatSendDataAlloc(QMux->Socket, &SendConfig);
    if (SendData == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "packet send context",
            0);
        goto Exit;
    }

    uint32_t BufferOffset = 0;
    uint32_t RemainingBufferLength = *BufferLength;
    uint32_t SendBufferLength;
    uint32_t SendBufferOffset = 0;
    QUIC_BUFFER* SendBuffer = NULL;
    do {
        if (SendBuffer == NULL || SendBufferOffset == SendBuffer->Length) {
            SendBuffer = CxPlatSendDataAllocBuffer(SendData, 16384 + 256);
            if (SendBuffer == NULL) {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "packet datagram",
                    16384 + 256);
                goto Exit;
            }
            SendBufferOffset = 0;
        }
        SendBufferLength = SendBuffer->Length - SendBufferOffset;

        QMux->ResultFlags =
            CxPlatTlsHandshake(
                QMux->TLS,
                CXPLAT_TLS_CRYPTO_DATA,
                Buffer + BufferOffset,
                &RemainingBufferLength,
                SendBuffer->Buffer + SendBufferOffset,
                &SendBufferLength,
                &QMux->TlsState);
        if (QMux->ResultFlags & CXPLAT_TLS_RESULT_ERROR) {
            Status = QUIC_STATUS_TLS_ERROR;
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "CxPlatTlsProcessData");
            QuicConnCloseLocally(
                Connection,
                QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                (uint64_t)Status,
                NULL);
            goto Exit;
        }
        BufferOffset = *BufferLength - RemainingBufferLength;
        *BufferLength = RemainingBufferLength;
        SendBufferOffset += SendBufferLength;
        TotalSendLength += SendBufferLength;
    } while (RemainingBufferLength > 0 || SendBufferLength > 0);
    SendBuffer->Length = SendBufferOffset;

    if (QMux->TlsState.HandshakeComplete) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_QX_TRANSPORT_PARAMETERS);
    }


Exit:
    if (SendData != NULL) {
        if (QUIC_SUCCEEDED(Status) && TotalSendLength > 0) {
            CxPlatSocketSend(QMux->Socket, &QMux->Route, SendData);
            QuicConnResetIdleTimeout(Connection);
        } else {
            CxPlatSendDataFree(SendData);
        }
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxQueueRecvData(
    _In_ QUIC_QMUX* QMux,
    _In_ CXPLAT_RECV_DATA* RecvDataChain,
    _In_ uint32_t RecvDataChainLength,
    _In_ uint32_t RecvDataChainByteLength
    )
{
    QUIC_CONNECTION* Connection = QMux->Connection;
    CXPLAT_RECV_DATA** RecvDataChainTail = (CXPLAT_RECV_DATA**)&RecvDataChain->Next;
    while (*RecvDataChainTail != NULL) {
        RecvDataChainTail = (CXPLAT_RECV_DATA**)&((*RecvDataChainTail)->Next);
    }

    QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u TCP data",
        RecvDataChainLength);

    BOOLEAN QueueOperation;
    CxPlatDispatchLockAcquire(&QMux->TcpReceiveQueueLock);
    *QMux->TcpReceiveQueueTail = RecvDataChain;
    QMux->TcpReceiveQueueTail = RecvDataChainTail;
    RecvDataChain = NULL;
    QueueOperation = (QMux->TcpReceiveQueueCount == 0);
    QMux->TcpReceiveQueueCount += RecvDataChainLength;
    QMux->TcpReceiveQueueByteCount += RecvDataChainByteLength;
    CxPlatDispatchLockRelease(&QMux->TcpReceiveQueueLock);

    if (QueueOperation) {
        QUIC_OPERATION* ConnOper =
            QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_FLUSH_TCP_RECV);
        if (ConnOper != NULL) {
            QuicConnQueueOper(Connection, ConnOper);
        } else {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Flush Recv TCP operation",
                0);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicQMuxRecvFrames(
    _In_ QUIC_QMUX* QMux,
    _In_reads_bytes_(PayloadLength)
        const uint8_t* Payload,
    _In_ uint16_t PayloadLength
    )
{
    QUIC_CONNECTION* Connection = QMux->Connection;
    BOOLEAN UpdatedFlowControl = FALSE;
    BOOLEAN Closed = Connection->State.ClosedLocally || Connection->State.ClosedRemotely;
    const BOOLEAN ClosingState = Connection->State.ClosedLocally && !Connection->State.ClosedRemotely;
    uint64_t RecvTime = CxPlatTimeUs64();

    //
    // In closing state, respond to any packet with a new close frame (rate-limited).
    // Note this excludes the draining state (i.e., ClosedRemotely == TRUE)
    // in which we should be silent.
    //
    if (ClosingState && !Connection->State.ShutdownComplete) {
        if (RecvTime - Connection->LastCloseResponseTimeUs >= QUIC_CLOSING_RESPONSE_MIN_INTERVAL) {
            QuicSendSetSendFlag(
                &Connection->Send,
                Connection->State.AppClosed ?
                    QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE :
                    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }
    }

    if (QuicConnIsClient(Connection) &&
        !Connection->State.GotFirstServerResponse) {
        Connection->State.GotFirstServerResponse = TRUE;
    }

    QuicFrameLogAll(
        Connection,
        TRUE,
        0,
        PayloadLength,
        Payload,
        0);

    uint16_t Offset = 0;
    while (Offset < PayloadLength) {

        //
        // Read the frame type.
        //
        QUIC_VAR_INT FrameType INIT_NO_SAL(0);
        if (!QuicVarIntDecode(PayloadLength, Payload, &Offset, &FrameType)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Frame type decode failure");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        if (!QUIC_FRAME_IS_KNOWN(FrameType)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unknown frame type");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        //
        // Validate allowable frames based on the packet type.
        //
        switch (FrameType) {
        //
        // The following frames are allowed pre-1-RTT encryption level:
        //
        case QUIC_FRAME_PADDING:
        case QUIC_FRAME_RESET_STREAM:
        case QUIC_FRAME_STOP_SENDING:
        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
        case QUIC_FRAME_MAX_DATA:
        case QUIC_FRAME_MAX_STREAM_DATA:
        case QUIC_FRAME_MAX_STREAMS:
        case QUIC_FRAME_DATA_BLOCKED:
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
        case QUIC_FRAME_STREAMS_BLOCKED:
        case QUIC_FRAME_STREAMS_BLOCKED_1:
        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_1:
        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1:
        case QX_FRAME_TRANSPORT_PARAMETERS:
        case QX_FRAME_PING:
        case QX_FRAME_PING_1:
            break;
        //
        // All other frame types are disallowed.
        //
        default:
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                (uint32_t)FrameType,
                "Disallowed frame type");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        //
        // Process the frame based on the frame type.
        //
        switch (FrameType) {

        case QX_FRAME_TRANSPORT_PARAMETERS: {
            QX_TRANSPORT_PARAMETERS_EX Frame;
            if (!QxTransportParametersFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding QX Transport Parameters frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            CXPLAT_DBG_ASSERT(Frame.Length <= UINT16_MAX);
            if (!QuicCryptoTlsDecodeTransportParameters(
                    Connection,
                    !QuicConnIsServer(Connection),
                    Frame.TP,
                    (uint16_t)Frame.Length,
                    &Connection->PeerTransportParams)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Processing transport parameters frame");
                return FALSE;
            }

            if (QUIC_FAILED(QuicConnProcessPeerTransportParameters(Connection, FALSE))) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Processing peer transport parameters");
                return FALSE;
            }

            break;
        }

        case QX_FRAME_PING:
        case QX_FRAME_PING_1: {
            QX_PING_EX Frame;
            if (!QxPingFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding QX PING frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (!Frame.IsResponse) {
                if (QMux->RecvPing &&
                    QMux->RecvPingSequenceNumber >= Frame.SequenceNumber) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Sequence number violation in QX PING frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                    return FALSE;
                }
                QMux->RecvPing = TRUE;
                QMux->RecvPingSequenceNumber = Frame.SequenceNumber;
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_QX_PING_RESPONSE);
            } else {
                if (QMux->NextPingSequenceNumber == 0) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Unexpected QX PING response frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                    return FALSE;
                } else if (QMux->NextPingSequenceNumber -1 < Frame.SequenceNumber) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Sequence number violation in QX PING response frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                    return FALSE;
                }
            }
        }

        case QUIC_FRAME_PADDING: {
            while (Offset < PayloadLength &&
                Payload[Offset] == QUIC_FRAME_PADDING) {
                Offset += sizeof(uint8_t);
            }
            break;
        }

        case QUIC_FRAME_RESET_STREAM:
        case QUIC_FRAME_STOP_SENDING:
        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
        case QUIC_FRAME_MAX_STREAM_DATA:
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
        case QUIC_FRAME_RELIABLE_RESET_STREAM: {
            if (Closed) {
                if (!QuicStreamFrameSkip(
                        FrameType, PayloadLength, Payload, &Offset)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping closed stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }
                break; // Ignore frame if we are closed.
            }

            uint64_t StreamId;
            if (!QuicStreamFramePeekID(
                    PayloadLength, Payload, Offset, &StreamId)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding stream ID from frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            BOOLEAN PeerOriginatedStream =
                QuicConnIsServer(Connection) ?
                    STREAM_ID_IS_CLIENT(StreamId) :
                    STREAM_ID_IS_SERVER(StreamId);

            if (STREAM_ID_IS_UNI_DIR(StreamId)) {
                BOOLEAN IsReceiverSideFrame =
                    FrameType == QUIC_FRAME_MAX_STREAM_DATA ||
                    FrameType == QUIC_FRAME_STOP_SENDING;
                if (PeerOriginatedStream == IsReceiverSideFrame) {
                    //
                    // For locally initiated unidirectional streams, the peer
                    // should only send receiver frame types, and vice versa
                    // for peer initiated unidirectional streams.
                    //
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid frame on unidirectional stream");
                    QuicConnTransportError(Connection, QUIC_ERROR_STREAM_STATE_ERROR);
                    break;
                }
            }

            BOOLEAN FatalError;
            QUIC_STREAM* Stream =
                QuicStreamSetGetStreamForPeer(
                    &Connection->Streams,
                    StreamId,
                    FALSE,
                    PeerOriginatedStream,
                    &FatalError);

            if (Stream) {
                QUIC_STATUS Status =
                    QuicStreamRecv(
                        Stream,
                        NULL,
                        FrameType,
                        PayloadLength,
                        Payload,
                        &Offset,
                        &UpdatedFlowControl);
                QuicStreamRelease(Stream, QUIC_STREAM_REF_LOOKUP);
                if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                    // QuicPacketLogDrop(Connection, Packet, "Stream frame process OOM");
                    return FALSE;
                }

                if (QUIC_FAILED(Status)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }

            } else if (FatalError) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Getting stream from ID");
                return FALSE;
            } else {
                //
                // Didn't find a matching Stream. Skip the frame as the Stream
                // might have been closed already.
                //
                QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
                if (!QuicStreamFrameSkip(
                        FrameType, PayloadLength, Payload, &Offset)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping ignored stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }
            }

            break;
        }

        case QUIC_FRAME_MAX_DATA: {
            QUIC_MAX_DATA_EX Frame;
            if (!QuicMaxDataFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_DATA frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Connection->Send.PeerMaxData < Frame.MaximumData) {
                Connection->Send.PeerMaxData = Frame.MaximumData;
                //
                // The peer has given us more allowance. Send packets from
                // any previously blocked streams.
                //
                UpdatedFlowControl = TRUE;
                QuicConnRemoveOutFlowBlockedReason(
                    Connection, QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL);
                QuicSendQueueFlush(
                    &Connection->Send, REASON_CONNECTION_FLOW_CONTROL);
            }

            break;
        }

        case QUIC_FRAME_MAX_STREAMS:
        case QUIC_FRAME_MAX_STREAMS_1: {
            QUIC_MAX_STREAMS_EX Frame;
            if (!QuicMaxStreamsFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_STREAMS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Frame.MaximumStreams > QUIC_TP_MAX_STREAMS_MAX) {
                QuicConnTransportError(Connection, QUIC_ERROR_STREAM_LIMIT_ERROR);
                break;
            }

            QuicStreamSetUpdateMaxStreams(
                &Connection->Streams,
                Frame.BidirectionalStreams,
                Frame.MaximumStreams);

            break;
        }

        case QUIC_FRAME_DATA_BLOCKED: {
            QUIC_DATA_BLOCKED_EX Frame;
            if (!QuicDataBlockedFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            //
            // TODO - Should we do anything else with this?
            //
            QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_MAX_DATA);

            break;
        }

        case QUIC_FRAME_STREAMS_BLOCKED:
        case QUIC_FRAME_STREAMS_BLOCKED_1: {
            QUIC_STREAMS_BLOCKED_EX Frame;
            if (!QuicStreamsBlockedFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding STREAMS_BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);

            uint8_t Type =
                (QuicConnIsServer(Connection) ? // Peer's role, so flip
                STREAM_ID_FLAG_IS_CLIENT : STREAM_ID_FLAG_IS_SERVER)
                |
                (Frame.BidirectionalStreams ?
                 STREAM_ID_FLAG_IS_BI_DIR : STREAM_ID_FLAG_IS_UNI_DIR);

            const QUIC_STREAM_TYPE_INFO* Info = &Connection->Streams.Types[Type];

            if (Info->MaxTotalStreamCount > Frame.StreamLimit) {
                break;
            }

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
            Event.PEER_NEEDS_STREAMS.Bidirectional = Frame.BidirectionalStreams;
            QuicTraceLogConnVerbose(
                IndicatePeerNeedStreamsV2,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s",
                Frame.BidirectionalStreams ? "Bidi" : "Unidi"
                );
            (void)QuicConnIndicateEvent(Connection, &Event);

            break;
        }

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_1: {
            QUIC_CONNECTION_CLOSE_EX Frame;
            if (!QuicConnCloseFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CONNECTION_CLOSE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            uint32_t Flags = QUIC_CLOSE_REMOTE | QUIC_CLOSE_SEND_NOTIFICATION;
            if (Frame.ApplicationClosed) {
                Flags |= QUIC_CLOSE_APPLICATION;
            }

            if (!Frame.ApplicationClosed && Frame.ErrorCode == QUIC_ERROR_APPLICATION_ERROR) {
                //
                // The APPLICATION_ERROR transport error should be sent only
                // when closing the connection before the handshake is
                // confirmed. In such case, we can also expect peer to send the
                // application CONNECTION_CLOSE frame in a 1-RTT packet
                // (presumably also in the same UDP datagram).
                //
                // We want to prioritize reporting the application-layer error
                // code to the application, so we postpone the call to
                // QuicConnTryClose and check again after processing incoming
                // datagrams in case it does not arrive.
                //
                QuicTraceEvent(
                    ConnDelayCloseApplicationError,
                    "[conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.",
                    Connection);
                Connection->State.DelayedApplicationError = TRUE;
            } else {
                QuicConnTryClose(
                    Connection,
                    Flags,
                    Frame.ErrorCode,
                    Frame.ReasonPhrase,
                    (uint16_t)Frame.ReasonPhraseLength);
            }


            if (Connection->State.HandleClosed) {
                //
                // If we are now closed, we should exit immediately. No need to
                // parse anything else.
                //
                goto Done;
            }
            break;
        }

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1: {
            if (!Connection->Settings.DatagramReceiveEnabled) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received DATAGRAM frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            if (!QuicDatagramProcessFrame(
                    &Connection->Datagram,
                    NULL,
                    FrameType,
                    PayloadLength,
                    Payload,
                    &Offset)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding DATAGRAM frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }
            break;
        }
        default:
            //
            // No default case necessary, as we have already validated the frame
            // type initially, but included for clang the compiler.
            //
            break;
        }
    }

Done:

    if (UpdatedFlowControl) {
        QuicConnLogOutFlowStats(Connection);
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicQMuxRecvData(
    _In_ QUIC_QMUX* QMux,
    _In_ CXPLAT_RECV_DATA* RecvDataChain,
    _In_ uint32_t RecvDataChainCount,
    _In_ uint32_t RecvDataChainByteCount
    )
{
    QUIC_CONNECTION* Connection = QMux->Connection;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QuicTraceEvent(
        QMuxRecvTcpData,
        "[conn][%p] Recv %u TCP data, %u bytes",
        Connection,
        RecvDataChainCount,
        RecvDataChainByteCount);

    CXPLAT_FRE_ASSERTMSG(
        QMux->TLS != NULL,
        "TLS state should have been initialized before receiving TCP data");

    CXPLAT_RECV_DATA* ReleaseChain = RecvDataChain;

    CXPLAT_RECV_DATA* RecvData;
    while ((RecvData = RecvDataChain) != NULL) {
        RecvDataChain = (CXPLAT_RECV_DATA*)RecvData->Next;

        uint32_t RecvDataLength = RecvData->BufferLength;
        uint32_t RemainingRecvDataLength = RecvDataLength;
        uint32_t RecvDataOffset = 0;
        CXPLAT_DBG_ASSERT(RecvData != NULL);
        if (!QMux->TlsState.HandshakeComplete) {            
            Status = QuicQMuxProcessHandshakeData(QMux, RecvData->Buffer, &RemainingRecvDataLength);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Processing handshake data");
                goto Error;
            }
            RecvDataOffset += RecvDataLength - RemainingRecvDataLength;
            RecvDataLength = RemainingRecvDataLength;
            if (QMux->TlsState.HandshakeComplete) {
                QuicTraceEvent(
                    ConnHandshakeComplete,
                    "[conn][%p] Handshake complete",
                    Connection);

                Connection->State.Connected = TRUE;
                QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_CONNECTED);

                QUIC_CONNECTION_EVENT Event = { 0 };
                Event.Type = QUIC_CONNECTION_EVENT_CONNECTED;
                Event.CONNECTED.NegotiatedAlpnLength = QMux->TlsState.NegotiatedAlpn[0];
                Event.CONNECTED.NegotiatedAlpn = QMux->TlsState.NegotiatedAlpn + 1;

                QuicTraceLogConnVerbose(
                    IndicateConnected,
                    Connection,
                    "Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)",
                    Event.CONNECTED.SessionResumed);
                (void)QuicConnIndicateEvent(Connection, &Event);

            }
        }

        if (QMux->TlsState.HandshakeComplete) {
            uint32_t RemainingRecvBufferLength;
            do {
                RemainingRecvBufferLength = QMux->RecvBufferAllocLength - QMux->RecvBufferOffset;
                if (!CxPlatTlsDecrypt(
                        QMux->TLS,
                        RecvData->Buffer + RecvDataOffset,
                        &RemainingRecvDataLength,
                        QMux->RecvBuffer + QMux->RecvBufferOffset,
                        &RemainingRecvBufferLength)) {
                    Status = QUIC_STATUS_TLS_ERROR;
                    QuicTraceEvent(
                        ConnErrorStatus,
                        "[conn][%p] ERROR, %u, %s.",
                        Connection,
                        Status,
                        "CxPlatTlsProcessData");
                    QuicConnCloseLocally(
                        Connection,
                        QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                        (uint64_t)Status,
                        NULL);
                    goto Error;
                }
                RecvDataOffset += RecvDataLength - RemainingRecvDataLength;
                RecvDataLength = RemainingRecvDataLength;
                QMux->RecvBufferOffset += RemainingRecvBufferLength;
                QMux->RecvBufferLength += RemainingRecvBufferLength;

                QUIC_VAR_INT RecordLength = 0;
                uint16_t RecordOffset = 0;
                uint32_t ProcessOffset = 0;
                do {
                    QuicVarIntDecode((uint16_t)(QMux->RecvBufferLength - ProcessOffset),
                        QMux->RecvBuffer + ProcessOffset,
                        &RecordOffset,
                        &RecordLength);
                    if (RecordLength == 0) {
                        break;
                    }
                    if (QMux->RecvBufferLength - ProcessOffset < RecordOffset + RecordLength) {
                        break;
                    }
                    QuicTraceEvent(
                        QMuxRecvPacket,
                        "[conn][%p][RX] %hu bytes",
                        Connection,
                        (uint16_t)RecordLength);

                    QuicQMuxRecvFrames(QMux, QMux->RecvBuffer + ProcessOffset + RecordOffset,
                        (uint16_t)RecordLength);
                    QuicConnResetIdleTimeout(Connection);
                    ProcessOffset += RecordOffset + RecordLength;
                } while (ProcessOffset < QMux->RecvBufferLength);
                if (ProcessOffset > 0 && ProcessOffset < QMux->RecvBufferLength) {
                    //
                    // Move any remaining data to the beginning of the buffer for the next
                    // receive.
                    //
                    memmove(QMux->RecvBuffer, QMux->RecvBuffer + ProcessOffset, QMux->RecvBufferLength - ProcessOffset);
                }
                    QMux->RecvBufferLength -= ProcessOffset;
                    QMux->RecvBufferOffset -= ProcessOffset;
            } while (RemainingRecvDataLength > 0 || RemainingRecvBufferLength > 0);
        }
    }    

Error:
    if (ReleaseChain != NULL) {
        CxPlatRecvDataReturn(ReleaseChain);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicQMuxFlushRecv(
    _In_ QUIC_QMUX* QMux
    )
{
    BOOLEAN FlushedAll;
    uint32_t TcpReceiveQueueCount, TcpReceiveQueueByteCount;
    CXPLAT_RECV_DATA* TcpReceiveQueue;

    CxPlatDispatchLockAcquire(&QMux->TcpReceiveQueueLock);
    TcpReceiveQueue = QMux->TcpReceiveQueue;
    FlushedAll = TRUE;
    TcpReceiveQueueCount = QMux->TcpReceiveQueueCount;
    TcpReceiveQueueByteCount = QMux->TcpReceiveQueueByteCount;
    QMux->TcpReceiveQueueCount = 0;
    QMux->TcpReceiveQueueByteCount = 0;
    QMux->TcpReceiveQueue = NULL;
    QMux->TcpReceiveQueueTail = &QMux->TcpReceiveQueue;
    CxPlatDispatchLockRelease(&QMux->TcpReceiveQueueLock);

    QuicQMuxRecvData(
        QMux, TcpReceiveQueue, TcpReceiveQueueCount, TcpReceiveQueueByteCount);

    return FlushedAll;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicQMuxProcessTcpDisconnect(
    _In_ QUIC_QMUX* QMux
    )
{
    QUIC_CONNECTION* Connection = QMux->Connection;
    //
    // Close the connection since the connection was disconnected.
    //
    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)QUIC_STATUS_ABORTED,
        NULL);

}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicQMuxTcpAccept(
    _In_ CXPLAT_SOCKET* ListenerSocket,
    _In_ void* ListenerContext,
    _In_ CXPLAT_SOCKET* AcceptSocket,
    _Out_ void** AcceptClientContext
    )
{
    UNREFERENCED_PARAMETER(ListenerSocket);
    *AcceptClientContext = NULL;
    QUIC_LISTENER* Listener = (QUIC_LISTENER*)ListenerContext;
    QUIC_CONNECTION* Connection;
    QUIC_STATUS Status =
        QuicConnQMuxAlloc(
            Listener->Registration,
            &MsQuicLib.Partitions[QuicLibraryGetCurrentPartition()->Index],
            NULL,
            TRUE,
            &Connection);
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    Connection->State.ListenerAccepted = TRUE;
    Connection->State.ExternalOwner = TRUE;

    QUIC_QMUX* QMux = QuicConnGetQMux(Connection);
    QMux->Socket = AcceptSocket;

    QUIC_NEW_CONNECTION_INFO Info = {0};
    Connection->State.LocalAddressSet = TRUE;
    CxPlatSocketGetLocalAddress(AcceptSocket, &QMux->Route.LocalAddress);
    Connection->State.RemoteAddressSet = TRUE;
    CxPlatSocketGetRemoteAddress(AcceptSocket, &QMux->Route.RemoteAddress);
    Info.LocalAddress = &QMux->Route.LocalAddress;
    Info.RemoteAddress = &QMux->Route.RemoteAddress;

    QUIC_LISTENER_EVENT Event;
    Event.Type = QUIC_LISTENER_EVENT_NEW_CONNECTION;
    Event.NEW_CONNECTION.Info = &Info;
    Event.NEW_CONNECTION.Connection = (HQUIC)Connection;

    QuicListenerAttachSilo(Listener);

    QuicTraceLogVerbose(
        ListenerIndicateNewConnection,
        "[list][%p] Indicating NEW_CONNECTION %p",
        Listener,
        Connection);

    Status = QuicListenerIndicateEvent(Listener, &Event);

    QuicListenerDetachSilo();

    if (QUIC_FAILED(Status)) {
        CXPLAT_FRE_ASSERTMSG(
            !Connection->State.HandleClosed,
            "App MUST not close and reject connection!");
        Connection->State.ExternalOwner = FALSE;
        QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "NEW_CONNECTION callback");
        QuicConnTransportError(
            Connection,
            QUIC_ERROR_CONNECTION_REFUSED);
        return QUIC_STATUS_SUCCESS; // Return success since the connection was handled, just rejected.
    }

    //
    // The application layer has accepted the connection.
    //
    CXPLAT_FRE_ASSERTMSG(
        Connection->State.HandleClosed ||
        Connection->ClientCallbackHandler != NULL,
        "App MUST set callback handler or close connection!");

    *AcceptClientContext = QMux;

    // start the connection's idle timer
    QuicConnResetIdleTimeout(Connection);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxTcpConnect(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ BOOLEAN Connected
    )
{
    UNREFERENCED_PARAMETER(Socket);
    QUIC_QMUX* QMux = (QUIC_QMUX*)Context;
    QUIC_CONNECTION* Connection = QMux->Connection;

    if (Connected) {
        QuicTraceLogConnInfo(
            TcpConnected,
            Connection,
            "TCP connected");
        Connection->State.TcpConnected = TRUE;
        CxPlatEventSet(QMux->ConnectEvent);
    } else {
        QuicTraceLogConnInfo(
            TcpDisconnected,
            Connection,
            "TCP disconnected");
        QUIC_OPERATION* ConnOper =
            QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_TCP_DISCONNECT);
        if (ConnOper != NULL) {
            QuicConnQueueOper(Connection, ConnOper);
        } else {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Disconnect TCP operation",
                0);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxTcpReceive(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    UNREFERENCED_PARAMETER(Socket);
    QUIC_QMUX* QMux = (QUIC_QMUX*)Context;
    QUIC_CONNECTION* Connection = QMux->Connection;
    uint32_t TotalChainLength = 0;
    uint32_t TotalChainByteLength = 0;
    CXPLAT_RECV_DATA* RecvData = RecvDataChain;
    while (RecvData != NULL) {
        TotalChainLength++;
        TotalChainByteLength += RecvData->BufferLength;
        RecvData = RecvData->Next;
    }        
    QuicTraceLogConnInfo(
        TcpDataReceived,
        Connection,
        "TCP data received: %u bytes in %u segments",
        TotalChainByteLength,
        TotalChainLength);
    QuicQMuxQueueRecvData(QMux, RecvDataChain, TotalChainLength, TotalChainByteLength);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicQMuxTcpSendComplete(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_ uint32_t ByteCount
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(ByteCount);
}
