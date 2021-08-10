


/*----------------------------------------------------------
// Decoder Ring for ConnCubic
// [conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u
// QuicTraceEvent(
        ConnCubic,
        "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Connection,
        Connection->CongestionControl.SlowStartThreshold,
        Connection->CongestionControl.KCubic,
        Connection->CongestionControl.WindowMax,
        Connection->CongestionControl.WindowLastMax);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->CongestionControl.SlowStartThreshold
// arg4 = arg4 = Connection->CongestionControl.KCubic
// arg5 = arg5 = Connection->CongestionControl.WindowMax
// arg6 = arg6 = Connection->CongestionControl.WindowLastMax
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONGESTION_CONTROL_C, ConnCubic,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnCongestion
// [conn][%p] Congestion event
// QuicTraceEvent(
        ConnCongestion,
        "[conn][%p] Congestion event",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONGESTION_CONTROL_C, ConnCongestion,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPersistentCongestion
// [conn][%p] Persistent congestion event
// QuicTraceEvent(
        ConnPersistentCongestion,
        "[conn][%p] Persistent congestion event",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONGESTION_CONTROL_C, ConnPersistentCongestion,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRecoveryExit
// [conn][%p] Recovery complete
// QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONGESTION_CONTROL_C, ConnRecoveryExit,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)
