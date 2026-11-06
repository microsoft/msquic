


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "tiered range block",
                (unsigned long long)QUIC_RANGE_TIERED_BLOCK_BYTES);
// arg2 = arg2 = "tiered range block" = arg2
// arg3 = arg3 = (unsigned long long)QUIC_RANGE_TIERED_BLOCK_BYTES = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_RANGE_TIERED_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
