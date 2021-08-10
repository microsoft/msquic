


/*----------------------------------------------------------
// Decoder Ring for CloseWithoutShutdown
// [strm][%p] Closing handle without fully shutting down
// QuicTraceLogStreamWarning(
                CloseWithoutShutdown,
                Stream,
                "Closing handle without fully shutting down");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, CloseWithoutShutdown,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for EventSilentDiscard
// [strm][%p] Event silently discarded
// QuicTraceLogStreamWarning(
            EventSilentDiscard,
            Stream,
            "Event silently discarded");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, EventSilentDiscard,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateStartComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_START_COMPLETE (0x%x)
// QuicTraceLogStreamVerbose(
        IndicateStartComplete,
        Stream,
        "Indicating QUIC_STREAM_EVENT_START_COMPLETE (0x%x)",
        Status);
// arg1 = arg1 = Stream
// arg3 = arg3 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, IndicateStartComplete,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateStreamShutdownComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
// QuicTraceLogStreamVerbose(
            IndicateStreamShutdownComplete,
            Stream,
            "Indicating QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, IndicateStreamShutdownComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamError
// [strm][%p] ERROR, %s.
// QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Unsupported receive buffer size");
// arg2 = arg2 = Stream
// arg3 = arg3 = "Unsupported receive buffer size"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamDestroyed
// [strm][%p] Destroyed
// QuicTraceEvent(
            StreamDestroyed,
            "[strm][%p] Destroyed",
            Stream);
// arg2 = arg2 = Stream
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamCreated
// [strm][%p] Created, Conn=%p ID=%llu IsLocal=%hhu
// QuicTraceEvent(
        StreamCreated,
        "[strm][%p] Created, Conn=%p ID=%llu IsLocal=%hhu",
        Stream,
        Stream->Connection,
        Stream->ID,
        !IsRemoteStream);
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->Connection
// arg4 = arg4 = Stream->ID
// arg5 = arg5 = !IsRemoteStream
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamCreated,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned long long, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamSendState
// [strm][%p] Send State: %hhu
// QuicTraceEvent(
        StreamSendState,
        "[strm][%p] Send State: %hhu",
        Stream,
        QuicStreamSendGetState(Stream));
// arg2 = arg2 = Stream
// arg3 = arg3 = QuicStreamSendGetState(Stream)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamSendState,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamRecvState
// [strm][%p] Recv State: %hhu
// QuicTraceEvent(
        StreamRecvState,
        "[strm][%p] Recv State: %hhu",
        Stream,
        QuicStreamRecvGetState(Stream));
// arg2 = arg2 = Stream
// arg3 = arg3 = QuicStreamRecvGetState(Stream)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamRecvState,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamOutFlowBlocked
// [strm][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            StreamOutFlowBlocked,
            "[strm][%p] Send Blocked Flags: %hhu",
            Stream,
            Stream->OutFlowBlockedReasons);
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->OutFlowBlockedReasons
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamOutFlowBlocked,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamRundown
// [strm][%p] Rundown, Conn=%p ID=%llu IsLocal=%hhu
// QuicTraceEvent(
        StreamRundown,
        "[strm][%p] Rundown, Conn=%p ID=%llu IsLocal=%hhu",
        Stream,
        Stream->Connection,
        Stream->ID,
        ((!QuicConnIsServer(Stream->Connection)) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER)));
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->Connection
// arg4 = arg4 = Stream->ID
// arg5 = arg5 = ((!QuicConnIsServer(Stream->Connection)) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER))
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_C, StreamRundown,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3,
        unsigned long long, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)
