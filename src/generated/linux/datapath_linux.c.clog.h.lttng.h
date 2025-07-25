


/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed");
// arg2 = arg2 = SocketContext->Binding = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_LINUX_C, DatapathErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
