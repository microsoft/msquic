


/*----------------------------------------------------------
// Decoder Ring for IndicateSendShutdownComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
// QuicTraceLogStreamVerbose(
            IndicateSendShutdownComplete,
            Stream,
            "Indicating QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, IndicateSendShutdownComplete,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateSendCanceled
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p] (Canceled)
// QuicTraceLogStreamVerbose(
                IndicateSendCanceled,
                Stream,
                "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p] (Canceled)",
                SendRequest);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = SendRequest = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, IndicateSendCanceled,
    TP_ARGS(
        const void *, arg1,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicateSendComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]
// QuicTraceLogStreamVerbose(
                IndicateSendComplete,
                Stream,
                "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]",
                SendRequest);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = SendRequest = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, IndicateSendComplete,
    TP_ARGS(
        const void *, arg1,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SendQueued
// [strm][%p] Send Request [%p] queued with %llu bytes at offset %llu (flags 0x%x)
// QuicTraceLogStreamVerbose(
            SendQueued,
            Stream,
            "Send Request [%p] queued with %llu bytes at offset %llu (flags 0x%x)",
            SendRequest,
            SendRequest->TotalLength,
            SendRequest->StreamOffset,
            SendRequest->Flags);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = SendRequest = arg3
// arg4 = arg4 = SendRequest->TotalLength = arg4
// arg5 = arg5 = SendRequest->StreamOffset = arg5
// arg6 = arg6 = SendRequest->Flags = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, SendQueued,
    TP_ARGS(
        const void *, arg1,
        const void *, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned int, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer_hex(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NoMoreRoom
// [strm][%p] Can't squeeze in a frame (no room for header)
// QuicTraceLogStreamVerbose(
            NoMoreRoom,
            Stream,
            "Can't squeeze in a frame (no room for header)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, NoMoreRoom,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NoMoreFrames
// [strm][%p] No more frames
// QuicTraceLogStreamVerbose(
            NoMoreFrames,
            Stream,
            "No more frames");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, NoMoreFrames,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AddFrame
// [strm][%p] Built stream frame, offset=%llu len=%hu fin=%hhu
// QuicTraceLogStreamVerbose(
        AddFrame,
        Stream,
        "Built stream frame, offset=%llu len=%hu fin=%hhu",
        Frame.Offset,
        (uint16_t)Frame.Length,
        Frame.Fin);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Frame.Offset = arg3
// arg4 = arg4 = (uint16_t)Frame.Length = arg4
// arg5 = arg5 = Frame.Fin = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, AddFrame,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned short, arg4,
        unsigned char, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecoverOpen
// [strm][%p] Recovering open STREAM frame
// QuicTraceLogStreamVerbose(
            RecoverOpen,
            Stream,
            "Recovering open STREAM frame");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, RecoverOpen,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecoverFin
// [strm][%p] Recovering fin STREAM frame
// QuicTraceLogStreamVerbose(
            RecoverFin,
            Stream,
            "Recovering fin STREAM frame");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, RecoverFin,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RecoverRange
// [strm][%p] Recovering offset %llu up to %llu
// QuicTraceLogStreamVerbose(
            RecoverRange,
            Stream,
            "Recovering offset %llu up to %llu",
            Start,
            End);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Start = arg3
// arg4 = arg4 = End = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, RecoverRange,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AckRangeMsg
// [strm][%p] Received ack for %d bytes, offset=%llu, FF=0x%hx
// QuicTraceLogStreamVerbose(
        AckRangeMsg,
        Stream,
        "Received ack for %d bytes, offset=%llu, FF=0x%hx",
        (int32_t)Length,
        Offset,
        FrameMetadata->Flags);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (int32_t)Length = arg3
// arg4 = arg4 = Offset = arg4
// arg5 = arg5 = FrameMetadata->Flags = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, AckRangeMsg,
    TP_ARGS(
        const void *, arg1,
        int, arg3,
        unsigned long long, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for Send0RttUpdated
// [strm][%p] Updated sent 0RTT length to %llu
// QuicTraceLogStreamVerbose(
            Send0RttUpdated,
            Stream,
            "Updated sent 0RTT length to %llu",
            FollowingOffset);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = FollowingOffset = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, Send0RttUpdated,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SendQueueDrained
// [strm][%p] Send queue completely drained
// QuicTraceLogStreamVerbose(
                SendQueueDrained,
                Stream,
                "Send queue completely drained");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, SendQueueDrained,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SendDump
// [strm][%p] SF:%hX FC:%llu QS:%llu MAX:%llu UNA:%llu NXT:%llu RECOV:%llu-%llu
// QuicTraceLogStreamVerbose(
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
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Stream->SendFlags = arg3
// arg4 = arg4 = Stream->MaxAllowedSendOffset = arg4
// arg5 = arg5 = Stream->QueuedSendOffset = arg5
// arg6 = arg6 = Stream->MaxSentLength = arg6
// arg7 = arg7 = Stream->UnAckedOffset = arg7
// arg8 = arg8 = Stream->NextSendOffset = arg8
// arg9 = arg9 = Stream->Flags.InRecovery ? Stream->RecoveryNextOffset : 0 = arg9
// arg10 = arg10 = Stream->Flags.InRecovery ? Stream->RecoveryEndOffset : 0 = arg10
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, SendDump,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned long long, arg7,
        unsigned long long, arg8,
        unsigned long long, arg9,
        unsigned long long, arg10), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
        ctf_integer(uint64_t, arg8, arg8)
        ctf_integer(uint64_t, arg9, arg9)
        ctf_integer(uint64_t, arg10, arg10)
    )
)



/*----------------------------------------------------------
// Decoder Ring for SendDumpAck
// [strm][%p]   unACKed: [%llu, %llu]
// QuicTraceLogStreamVerbose(
                SendDumpAck,
                Stream,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Sack->Low);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = UnAcked = arg3
// arg4 = arg4 = Sack->Low = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, SendDumpAck,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
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
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = QuicStreamSendGetState(Stream) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, StreamSendState,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for StreamWriteFrames
// [strm][%p] Writing frames to packet %llu
// QuicTraceEvent(
        StreamWriteFrames,
        "[strm][%p] Writing frames to packet %llu",
        Stream,
        Builder->Metadata->PacketId);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Builder->Metadata->PacketId = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_SEND_C, StreamWriteFrames,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
