


/*----------------------------------------------------------
// Decoder Ring for IndicateDataAcked
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]
// QuicTraceLogConnVerbose(
           IndicateDataAcked,
           Connection,
           "Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]",
           Event.NETWORK_STATISTICS.BytesInFlight,
           Event.NETWORK_STATISTICS.PostedBytes,
           Event.NETWORK_STATISTICS.IdealBytes,
           Event.NETWORK_STATISTICS.SmoothedRTT,
           Event.NETWORK_STATISTICS.CongestionWindow,
           Event.NETWORK_STATISTICS.Bandwidth);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.NETWORK_STATISTICS.BytesInFlight = arg3
// arg4 = arg4 = Event.NETWORK_STATISTICS.PostedBytes = arg4
// arg5 = arg5 = Event.NETWORK_STATISTICS.IdealBytes = arg5
// arg6 = arg6 = Event.NETWORK_STATISTICS.SmoothedRTT = arg6
// arg7 = arg7 = Event.NETWORK_STATISTICS.CongestionWindow = arg7
// arg8 = arg8 = Event.NETWORK_STATISTICS.Bandwidth = arg8
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, IndicateDataAcked,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned int, arg7,
        unsigned long long, arg8), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(unsigned int, arg7, arg7)
        ctf_integer(uint64_t, arg8, arg8)
    )
)



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
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Cubic->SlowStartThreshold = arg3
// arg4 = arg4 = Cubic->KCubic = arg4
// arg5 = arg5 = Cubic->WindowMax = arg5
// arg6 = arg6 = Cubic->WindowLastMax = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnCubic,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned int, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnHyStartStateChange
// [conn][%p] HyStart: State=%u CongestionWindow=%u SlowStartThreshold=%u
// QuicTraceEvent(
            ConnHyStartStateChange,
            "[conn][%p] HyStart: State=%u CongestionWindow=%u SlowStartThreshold=%u",
            Connection,
            NewHyStartState,
            Cubic->CongestionWindow,
            Cubic->SlowStartThreshold);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = NewHyStartState = arg3
// arg4 = arg4 = Cubic->CongestionWindow = arg4
// arg5 = arg5 = Cubic->SlowStartThreshold = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnHyStartStateChange,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnCongestionV2
// [conn][%p] Congestion event: IsEcn=%hu
// QuicTraceEvent(
        ConnCongestionV2,
        "[conn][%p] Congestion event: IsEcn=%hu",
        Connection,
        Ecn);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Ecn = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnCongestionV2,
    TP_ARGS(
        const void *, arg2,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPersistentCongestion
// [conn][%p] Persistent congestion event
// QuicTraceEvent(
            ConnPersistentCongestion,
            "[conn][%p] Persistent congestion event",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnPersistentCongestion,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnRecoveryExit
// [conn][%p] Recovery complete
// QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnRecoveryExit,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnSpuriousCongestion
// [conn][%p] Spurious congestion event
// QuicTraceEvent(
        ConnSpuriousCongestion,
        "[conn][%p] Spurious congestion event",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnSpuriousCongestion,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowStatsV2
// [conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu
// QuicTraceEvent(
        ConnOutFlowStatsV2,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Cubic->BytesInFlight,
        Cubic->CongestionWindow,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0,
        Path->OneWayDelay);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Send.TotalBytes = arg3
// arg4 = arg4 = Cubic->BytesInFlight = arg4
// arg5 = arg5 = Cubic->CongestionWindow = arg5
// arg6 = arg6 = Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent = arg6
// arg7 = arg7 = Connection->SendBuffer.IdealBytes = arg7
// arg8 = arg8 = Connection->SendBuffer.PostedBytes = arg8
// arg9 = arg9 = Path->GotFirstRttSample ? Path->SmoothedRtt : 0 = arg9
// arg10 = arg10 = Path->OneWayDelay = arg10
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CUBIC_C, ConnOutFlowStatsV2,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned int, arg4,
        unsigned int, arg5,
        unsigned long long, arg6,
        unsigned long long, arg7,
        unsigned long long, arg8,
        unsigned long long, arg9,
        unsigned long long, arg10), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
        ctf_integer(uint64_t, arg8, arg8)
        ctf_integer(uint64_t, arg9, arg9)
        ctf_integer(uint64_t, arg10, arg10)
    )
)
