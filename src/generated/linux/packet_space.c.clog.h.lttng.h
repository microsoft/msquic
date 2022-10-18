


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "packet space",
            sizeof(QUIC_PACKET_SPACE));
// arg2 = arg2 = "packet space" = arg2
// arg3 = arg3 = sizeof(QUIC_PACKET_SPACE) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_SPACE_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
