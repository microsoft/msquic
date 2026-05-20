


/*----------------------------------------------------------
// Decoder Ring for PathActiveFallback
// [conn][%p] Path[%hhu] removed; falling back to Path[%hhu]
// QuicTraceLogConnInfo(
            PathActiveFallback,
            Connection,
            "Path[%hhu] removed; falling back to Path[%hhu]",
            Path->ID,
            Connection->Paths[FallbackIndex].ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Connection->Paths[FallbackIndex].ID = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathActiveFallback,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathQeoEnabled
// [conn][%p] Path[%hhu] QEO enabled
// QuicTraceLogConnInfo(
                PathQeoEnabled,
                Connection,
                "Path[%hhu] QEO enabled",
                Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathQeoEnabled,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathQeoDisabled
// [conn][%p] Path[%hhu] QEO disabled
// QuicTraceLogConnInfo(
            PathQeoDisabled,
            Connection,
            "Path[%hhu] QEO disabled",
            Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathQeoDisabled,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathInitialized
// [conn][%p] Path[%hhu] Initialized
// QuicTraceEvent(
        ConnPathInitialized,
        "[conn][%p] Path[%hhu] Initialized",
        Connection,
        Path->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathInitialized,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathRemoved
// [conn][%p] Path[%hhu] Removed
// QuicTraceEvent(
        ConnPathRemoved,
        "[conn][%p] Path[%hhu] Removed",
        Connection,
        Path->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathRemoved,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathValidated
// [conn][%p] Path[%hhu] Validated (%hhu)
// QuicTraceEvent(
        ConnPathValidated,
        "[conn][%p] Path[%hhu] Validated (%hhu)",
        Connection,
        Path->ID,
        Reason);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Reason = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathValidated,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathActive
// [conn][%p] Path[%hhu] Set active (rebind=%hhu)
// QuicTraceEvent(
        ConnPathActive,
        "[conn][%p] Path[%hhu] Set active (rebind=%hhu)",
        Connection,
        Connection->Paths[0].ID,
        UdpPortChangeOnly);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Paths[0].ID = arg3
// arg4 = arg4 = UdpPortChangeOnly = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathActive,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)
