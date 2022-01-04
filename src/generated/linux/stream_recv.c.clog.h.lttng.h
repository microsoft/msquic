


/*----------------------------------------------------------
// Decoder Ring for ResetEarly
// [strm][%p] Tried to reset at earlier final size!
// QuicTraceLogStreamWarning(
                ResetEarly,
                Stream,
                "Tried to reset at earlier final size!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, ResetEarly,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ResetTooBig
// [strm][%p] Tried to reset with too big final size!
// QuicTraceLogStreamWarning(
                    ResetTooBig,
                    Stream,
                    "Tried to reset with too big final size!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, ResetTooBig,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ReceiveTooBig
// [strm][%p] Tried to write beyond end of buffer!
// QuicTraceLogStreamWarning(
            ReceiveTooBig,
            Stream,
            "Tried to write beyond end of buffer!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, ReceiveTooBig,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ReceiveBeyondFlowControl
// [strm][%p] Tried to write beyond flow control limit!
// QuicTraceLogStreamWarning(
            ReceiveBeyondFlowControl,
            Stream,
            "Tried to write beyond flow control limit!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, ReceiveBeyondFlowControl,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RemoteCloseReset
// [strm][%p] Closed remotely (reset)
// QuicTraceLogStreamInfo(
                RemoteCloseReset,
                Stream,
                "Closed remotely (reset)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, RemoteCloseReset,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LocalCloseStopSending
// [strm][%p] Closed locally (stop sending)
// QuicTraceLogStreamInfo(
            LocalCloseStopSending,
            Stream,
            "Closed locally (stop sending)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, LocalCloseStopSending,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TreatFinAsReset
// [strm][%p] Treating FIN after receive abort as reset
// QuicTraceLogStreamInfo(
                TreatFinAsReset,
                Stream,
                "Treating FIN after receive abort as reset");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, TreatFinAsReset,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for QueueRecvFlush
// [strm][%p] Queuing recv flush
// QuicTraceLogStreamVerbose(
            QueueRecvFlush,
            Stream,
            "Queuing recv flush");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, QueueRecvFlush,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerSendAbort
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_SEND_ABORTED (0x%llX)
// QuicTraceLogStreamVerbose(
                IndicatePeerSendAbort,
                Stream,
                "Indicating QUIC_STREAM_EVENT_PEER_SEND_ABORTED (0x%llX)",
                ErrorCode);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = ErrorCode = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IndicatePeerSendAbort,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerReceiveAborted
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED (0x%llX)
// QuicTraceLogStreamVerbose(
            IndicatePeerReceiveAborted,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED (0x%llX)",
            ErrorCode);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = ErrorCode = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IndicatePeerReceiveAborted,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IgnoreRecvAfterClose
// [strm][%p] Ignoring recv after close
// QuicTraceLogStreamVerbose(
            IgnoreRecvAfterClose,
            Stream,
            "Ignoring recv after close");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IgnoreRecvAfterClose,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IgnoreRecvAfterAbort
// [strm][%p] Ignoring received frame after receive abort
// QuicTraceLogStreamVerbose(
                IgnoreRecvAfterAbort,
                Stream,
                "Ignoring received frame after receive abort");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IgnoreRecvAfterAbort,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FlowControlExhausted
// [strm][%p] Flow control window exhausted!
// QuicTraceLogStreamVerbose(
                FlowControlExhausted,
                Stream,
                "Flow control window exhausted!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, FlowControlExhausted,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for Receive
// [strm][%p] Received %hu bytes, offset=%llu Ready=%hhu
// QuicTraceLogStreamVerbose(
        Receive,
        Stream,
        "Received %hu bytes, offset=%llu Ready=%hhu",
        (uint16_t)Frame->Length,
        Frame->Offset,
        ReadyToDeliver);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (uint16_t)Frame->Length = arg3
// arg4 = arg4 = Frame->Offset = arg4
// arg5 = arg5 = ReadyToDeliver = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, Receive,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RemoteBlocked
// [strm][%p] Remote FC blocked (%llu)
// QuicTraceLogStreamVerbose(
            RemoteBlocked,
            Stream,
            "Remote FC blocked (%llu)",
            Frame.StreamDataLimit);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Frame.StreamDataLimit = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, RemoteBlocked,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IncreaseRxBuffer
// [strm][%p] Increasing max RX buffer size to %u (MinRtt=%u; TimeNow=%u; LastUpdate=%u)
// QuicTraceLogStreamVerbose(
                    IncreaseRxBuffer,
                    Stream,
                    "Increasing max RX buffer size to %u (MinRtt=%u; TimeNow=%u; LastUpdate=%u)",
                    Stream->RecvBuffer.VirtualBufferLength * 2,
                    Stream->Connection->Paths[0].MinRtt,
                    TimeNow,
                    Stream->RecvWindowLastUpdate);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Stream->RecvBuffer.VirtualBufferLength * 2 = arg3
// arg4 = arg4 = Stream->Connection->Paths[0].MinRtt = arg4
// arg5 = arg5 = TimeNow = arg5
// arg6 = arg6 = Stream->RecvWindowLastUpdate = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IncreaseRxBuffer,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for UpdateFlowControl
// [strm][%p] Updating flow control window
// QuicTraceLogStreamVerbose(
        UpdateFlowControl,
        Stream,
        "Updating flow control window");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, UpdateFlowControl,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IgnoreRecvFlush
// [strm][%p] Ignoring recv flush (recv disabled)
// QuicTraceLogStreamVerbose(
            IgnoreRecvFlush,
            Stream,
            "Ignoring recv flush (recv disabled)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IgnoreRecvFlush,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerSendShutdown
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
// QuicTraceLogStreamVerbose(
            IndicatePeerSendShutdown,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, IndicatePeerSendShutdown,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
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
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = QuicStreamRecvGetState(Stream) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, StreamRecvState,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Flush Stream Recv operation",
                0);
// arg2 = arg2 = "Flush Stream Recv operation" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamError
// [strm][%p] ERROR, %s.
// QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Receive on unidirectional stream");
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = "Receive on unidirectional stream" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, StreamError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamReceiveFrame
// [strm][%p] Processing frame in packet %llu
// QuicTraceEvent(
        StreamReceiveFrame,
        "[strm][%p] Processing frame in packet %llu",
        Stream,
        Packet->PacketId);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Packet->PacketId = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, StreamReceiveFrame,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamAppReceive
// [strm][%p] Indicating QUIC_STREAM_EVENT_RECEIVE [%llu bytes, %u buffers, 0x%x flags]
// QuicTraceEvent(
            StreamAppReceive,
            "[strm][%p] Indicating QUIC_STREAM_EVENT_RECEIVE [%llu bytes, %u buffers, 0x%x flags]",
            Stream,
            Event.RECEIVE.TotalBufferLength,
            Event.RECEIVE.BufferCount,
            Event.RECEIVE.Flags);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Event.RECEIVE.TotalBufferLength = arg3
// arg4 = arg4 = Event.RECEIVE.BufferCount = arg4
// arg5 = arg5 = Event.RECEIVE.Flags = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, StreamAppReceive,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamAppReceiveComplete
// [strm][%p] Receive complete [%llu bytes]
// QuicTraceEvent(
        StreamAppReceiveComplete,
        "[strm][%p] Receive complete [%llu bytes]",
        Stream,
        BufferLength);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = BufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_RECV_C, StreamAppReceiveComplete,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
