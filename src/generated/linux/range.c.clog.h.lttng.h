


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "range (realloc)",
            NewAllocLength);
// arg2 = arg2 = "range (realloc)" = arg2
// arg3 = arg3 = NewAllocLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_RANGE_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
