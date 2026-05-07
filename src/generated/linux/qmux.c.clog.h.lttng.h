


/*----------------------------------------------------------
// Decoder Ring for ListenerIndicateNewConnection
// [list][%p] Indicating NEW_CONNECTION %p
// QuicTraceLogVerbose(
        ListenerIndicateNewConnection,
        "[list][%p] Indicating NEW_CONNECTION %p",
        Listener,
        Connection);
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Connection = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ListenerIndicateNewConnection,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer_hex(uint64_t, arg3, (uint64_t)arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IgnoreFrameAfterClose
// [conn][%p] Ignoring frame (%hhu) for already closed stream id = %llu
// QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint8_t)FrameType = arg3
// arg4 = arg4 = // This cast is safe because of the switch cases above.
                    StreamId = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, IgnoreFrameAfterClose,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TcpConnected
// [conn][%p] TCP connected
// QuicTraceLogConnInfo(
            TcpConnected,
            Connection,
            "TCP connected");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, TcpConnected,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TcpDisconnected
// [conn][%p] TCP disconnected
// QuicTraceLogConnInfo(
            TcpDisconnected,
            Connection,
            "TCP disconnected");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, TcpDisconnected,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TcpDataReceived
// [conn][%p] TCP data received: %u bytes in %u segments
// QuicTraceLogConnInfo(
        TcpDataReceived,
        Connection,
        "TCP data received: %u bytes in %u segments",
        TotalChainByteLength,
        TotalChainLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TotalChainByteLength = arg3
// arg4 = arg4 = TotalChainLength = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, TcpDataReceived,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TlsHandshakeData
// [conn][%p] TLS handshake data ready to send, length=%u
// QuicTraceLogConnVerbose(
                        TlsHandshakeData,
                        Connection,
                        "TLS handshake data ready to send, length=%u",
                        OutputBuffers[i].Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = OutputBuffers[i].Length = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, TlsHandshakeData,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for QueueDatagrams
// [conn][%p] Queuing %u TCP data
// QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u TCP data",
        RecvDataChainLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = RecvDataChainLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, QueueDatagrams,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PeerConnFCBlocked
// [conn][%p] Peer Connection FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.DataLimit = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, PeerConnFCBlocked,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PeerStreamFCBlocked
// [conn][%p] Peer Streams[%hu] FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.BidirectionalStreams = arg3
// arg4 = arg4 = Frame.StreamLimit = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, PeerStreamFCBlocked,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerNeedStreamsV2
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s
// QuicTraceLogConnVerbose(
                IndicatePeerNeedStreamsV2,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s",
                Frame.BidirectionalStreams ? "Bidi" : "Unidi"
                );
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.BidirectionalStreams ? "Bidi" : "Unidi" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, IndicatePeerNeedStreamsV2,
    TP_ARGS(
        const void *, arg1,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateConnected
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)
// QuicTraceLogConnVerbose(
                    IndicateConnected,
                    Connection,
                    "Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)",
                    Event.CONNECTED.SessionResumed);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.CONNECTED.SessionResumed = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, IndicateConnected,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection QMux",
            sizeof(QUIC_QMUX));
// arg2 = arg2 = "connection QMux" = arg2
// arg3 = arg3 = sizeof(QUIC_QMUX) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "CxPlatTlsInitialize");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "CxPlatTlsInitialize" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ConnErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Frame type decode failure");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Frame type decode failure" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDelayCloseApplicationError
// [conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.
// QuicTraceEvent(
                    ConnDelayCloseApplicationError,
                    "[conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.",
                    Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ConnDelayCloseApplicationError,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRecvTcpData
// [conn][%p] Recv %u TCP data, %u bytes
// QuicTraceEvent(
        ConnRecvTcpData,
        "[conn][%p] Recv %u TCP data, %u bytes",
        Connection,
        RecvDataChainCount,
        RecvDataChainByteCount);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = RecvDataChainCount = arg3
// arg4 = arg4 = RecvDataChainByteCount = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ConnRecvTcpData,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceEvent(
                    ConnHandshakeComplete,
                    "[conn][%p] Handshake complete",
                    Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ConnHandshakeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRecvPacket
// [conn][%p][RX] %hu bytes
// QuicTraceEvent(
                        ConnRecvPacket,
                        "[conn][%p][RX] %hu bytes",
                        Connection,
                        (uint16_t)RecordLength);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint16_t)RecordLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ConnRecvPacket,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ListenerErrorStatus
// [list][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "NEW_CONNECTION callback");
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "NEW_CONNECTION callback" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QMUX_C, ListenerErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
