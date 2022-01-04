


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "recv_buffer",
                AllocBufferLength);
// arg2 = arg2 = "recv_buffer" = arg2
// arg3 = arg3 = AllocBufferLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_RECV_BUFFER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
