


/*----------------------------------------------------------
// Decoder Ring for StreamOutFlowBlocked
// [strm][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            StreamOutFlowBlocked,
            "[strm][%p] Send Blocked Flags: %hhu",
            Stream,
            Stream->OutFlowBlockedReasons);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Stream->OutFlowBlockedReasons = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_STREAM_H, StreamOutFlowBlocked,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)
