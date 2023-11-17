


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NmrRegisterProvider");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "NmrRegisterProvider" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_NMRPROVIDER_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
