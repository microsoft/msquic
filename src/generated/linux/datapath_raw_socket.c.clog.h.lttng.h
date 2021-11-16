


/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            Length,
            sizeof(IPV4_HEADER),
            "packet is too small for an IPv4 header");
// arg2 = arg2 = Length
// arg3 = arg3 = sizeof(IPV4_HEADER)
// arg4 = arg4 = "packet is too small for an IPv4 header"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DataPathParserError,
    TP_ARGS(
        unsigned int, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
