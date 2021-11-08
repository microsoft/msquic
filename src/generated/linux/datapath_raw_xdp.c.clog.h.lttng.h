


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP Queues",
            Xdp->QueueCount * sizeof(*Xdp->Queues));
// arg2 = arg2 = "XDP Queues"
// arg3 = arg3 = Xdp->QueueCount * sizeof(*Xdp->Queues)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_C, AllocFailure,
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
                "XskCreate");
// arg2 = arg2 = Status
// arg3 = arg3 = "XskCreate"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
