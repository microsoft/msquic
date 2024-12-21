


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "pathid hash table",
                0);
// arg2 = arg2 = "pathid hash table" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_SET_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    QuicPathIDSetGetConnection(PathIDSet),
                    "Failed to generate new path ID");
// arg2 = arg2 = QuicPathIDSetGetConnection(PathIDSet) = arg2
// arg3 = arg3 = "Failed to generate new path ID" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_SET_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPathIDCreated
// [conn][%p] New PathID %u
// QuicTraceEvent(
        ConnPathIDCreated,
        "[conn][%p] New PathID %u",
        Connection,
        PathID->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_SET_C, ConnPathIDCreated,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)
