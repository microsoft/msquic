


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_HASHTABLE",
                sizeof(CXPLAT_HASHTABLE));
// arg2 = arg2 = "CXPLAT_HASHTABLE" = arg2
// arg3 = arg3 = sizeof(CXPLAT_HASHTABLE) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_HASHTABLE_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
