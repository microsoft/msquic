


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_PCP",
            PcpContextSize);
// arg2 = arg2 = "CXPLAT_PCP" = arg2
// arg3 = arg3 = PcpContextSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PCP_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PCP: Invalid length");
// arg2 = arg2 = "PCP: Invalid length" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PCP_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
