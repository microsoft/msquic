


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(CXPLAT_ROUTE_RESOLUTION_WORKER));
// arg2 = arg2 = "CXPLAT_DATAPATH" = arg2
// arg3 = arg3 = sizeof(CXPLAT_ROUTE_RESOLUTION_WORKER) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_LINUX_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_LINUX_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
