


/*----------------------------------------------------------
// Decoder Ring for DatapathTcpAuxBinding
// [data][%p] Binding TCP socket to %s
// QuicTraceLogVerbose(
            DatapathTcpAuxBinding,
            "[data][%p] Binding TCP socket to %s",
            Socket,
            LocalAddressString.Address);
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = LocalAddressString.Address = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_COMMON_C, DatapathTcpAuxBinding,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "closesocket");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = Error = arg3
// arg4 = arg4 = "closesocket" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_COMMON_C, DatapathErrorStatus,
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
