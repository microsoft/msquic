


/*----------------------------------------------------------
// Decoder Ring for NonActivePathCidRetired
// [conn][%p] Non-active path has no replacement for retired CID.
// QuicTraceLogConnWarning(
            NonActivePathCidRetired,
            Connection,
            "Non-active path has no replacement for retired CID.");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, NonActivePathCidRetired,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathActiveFallback
// [conn][%p] Path[%u] removed; falling back to Path[%u]
// QuicTraceLogConnInfo(
            PathActiveFallback,
            Connection,
            "Path[%u] removed; falling back to Path[%u]",
            Path->ID,
            PathSet->Paths[FallbackIndex].ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = PathSet->Paths[FallbackIndex].ID = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathActiveFallback,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathQeoEnabled
// [conn][%p] Path[%u] QEO enabled
// QuicTraceLogConnInfo(
                PathQeoEnabled,
                Connection,
                "Path[%u] QEO enabled",
                Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathQeoEnabled,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathQeoDisabled
// [conn][%p] Path[%u] QEO disabled
// QuicTraceLogConnInfo(
            PathQeoDisabled,
            Connection,
            "Path[%u] QEO disabled",
            Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, PathQeoDisabled,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerAddrChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
// QuicTraceLogConnVerbose(
        IndicatePeerAddrChanged,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, IndicatePeerAddrChanged,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathInitialized
// [conn][%p] Path[%u] Initialized
// QuicTraceEvent(
        ConnPathInitialized,
        "[conn][%p] Path[%u] Initialized",
        Connection,
        Path->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathInitialized,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(
            sizeof(ActivePath->Route.RemoteAddress),
            &ActivePath->Route.RemoteAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(
            sizeof(ActivePath->Route.RemoteAddress),
            &ActivePath->Route.RemoteAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnRemoteAddrAdded,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathRemoved
// [conn][%p] Path[%u] Removed
// QuicTraceEvent(
        ConnPathRemoved,
        "[conn][%p] Path[%u] Removed",
        Connection,
        Path->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathRemoved,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Active path has no replacement for retired CID");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Active path has no replacement for retired CID" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathValidated
// [conn][%p] Path[%u] Validated (%hhu)
// QuicTraceEvent(
        ConnPathValidated,
        "[conn][%p] Path[%u] Validated (%hhu)",
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
        unsigned int, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathActive
// [conn][%p] Path[%u] Set active (rebind=%hhu)
// QuicTraceEvent(
        ConnPathActive,
        "[conn][%p] Path[%u] Set active (rebind=%hhu)",
        Connection,
        ActivePath->ID,
        UdpPortChangeOnly);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = ActivePath->ID = arg3
// arg4 = arg4 = UdpPortChangeOnly = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_C, ConnPathActive,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)
