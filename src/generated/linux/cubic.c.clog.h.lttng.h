


/*----------------------------------------------------------
// Decoder Ring for ConnCubic
// [conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u
// QuicTraceEvent(
        ConnCubic,
        "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Connection,
        Cubic->SlowStartThreshold,
        Cubic->KCubic,
        Cubic->WindowMax,
        Cubic->WindowLastMax);
// arg2 = arg2 = Connection
// arg3 = arg3 = Cubic->SlowStartThreshold
// arg4 = arg4 = Cubic->KCubic
// arg5 = arg5 = Cubic->WindowMax
// arg6 = arg6 = Cubic->WindowLastMax
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnCubic,
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
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnCongestion,
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
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnPersistentCongestion,
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
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnRecoveryExit,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnSpuriousCongestion
// [conn][%p] Spurious congestion event
// QuicTraceEvent(
        ConnSpuriousCongestion,
        "[conn][%p] Spurious congestion event",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnSpuriousCongestion,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowStats
// [conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u
// QuicTraceEvent(
        ConnOutFlowStats,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Cubic->BytesInFlight,
        Cubic->BytesInFlightMax,
        Cubic->CongestionWindow,
        Cubic->SlowStartThreshold,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Stats.Send.TotalBytes
// arg4 = arg4 = Cubic->BytesInFlight
// arg5 = arg5 = Cubic->BytesInFlightMax
// arg6 = arg6 = Cubic->CongestionWindow
// arg7 = arg7 = Cubic->SlowStartThreshold
// arg8 = arg8 = Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent
// arg9 = arg9 = Connection->SendBuffer.IdealBytes
// arg10 = arg10 = Connection->SendBuffer.PostedBytes
// arg11 = arg11 = Path->GotFirstRttSample ? Path->SmoothedRtt : 0
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnOutFlowStats,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6,
        unsigned int, arg7,
        unsigned long long, arg8,
        unsigned long long, arg9,
        unsigned long long, arg10,
        unsigned int, arg11), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
        ctf_integer(unsigned int, arg7, arg7)
        ctf_integer(uint64_t, arg8, arg8)
        ctf_integer(uint64_t, arg9, arg9)
        ctf_integer(uint64_t, arg10, arg10)
        ctf_integer(unsigned int, arg11, arg11)
    )
)
