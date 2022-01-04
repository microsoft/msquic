


/*----------------------------------------------------------
// Decoder Ring for PathInitialized
// [conn][%p] Path[%hhu] Initialized
// QuicTraceLogConnInfo(
        PathInitialized,
        Connection,
        "Path[%hhu] Initialized",
        Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathInitialized,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathRemoved
// [conn][%p] Path[%hhu] Removed
// QuicTraceLogConnInfo(
        PathRemoved,
        Connection,
        "Path[%hhu] Removed",
        Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathRemoved,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathValidated
// [conn][%p] Path[%hhu] Validated (%s)
// QuicTraceLogConnInfo(
        PathValidated,
        Connection,
        "Path[%hhu] Validated (%s)",
        Path->ID,
        ReasonStrings[Reason]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = ReasonStrings[Reason] = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathValidated,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathActive
// [conn][%p] Path[%hhu] Set active (rebind=%hhu)
// QuicTraceLogConnInfo(
        PathActive,
        Connection,
        "Path[%hhu] Set active (rebind=%hhu)",
        Connection->Paths[0].ID,
        UdpPortChangeOnly);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Paths[0].ID = arg3
// arg4 = arg4 = UdpPortChangeOnly = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathActive,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)
