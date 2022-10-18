


/*----------------------------------------------------------
// Decoder Ring for IndicateIdealSendBuffer
// [strm][%p] Indicating QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = %llu
// QuicTraceLogStreamVerbose(
            IndicateIdealSendBuffer,
            Stream,
            "Indicating QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = %llu",
            Event.IDEAL_SEND_BUFFER_SIZE.ByteCount);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Event.IDEAL_SEND_BUFFER_SIZE.ByteCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_BUFFER_C, IndicateIdealSendBuffer,
    TP_ARGS(
        const void *, arg1,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "sendbuffer",
            Size);
// arg2 = arg2 = "sendbuffer" = arg2
// arg3 = arg3 = Size = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_SEND_BUFFER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
