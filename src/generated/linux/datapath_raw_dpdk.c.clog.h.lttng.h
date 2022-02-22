


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatThreadCreate" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_DPDK_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No room in DPDK TX ring buffer");
// arg2 = arg2 = "No room in DPDK TX ring buffer" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_DPDK_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
