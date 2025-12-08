


/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowStreamStats
// [conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu
// QuicTraceEvent(
        ConnOutFlowStreamStats,
        "[conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu",
        Connection,
        FcAvailable,
        SendWindow);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = FcAvailable = arg3
// arg4 = arg4 = SendWindow = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_H, ConnOutFlowStreamStats,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnInFlowStats
// [conn][%p] IN: BytesRecv=%llu
// QuicTraceEvent(
        ConnInFlowStats,
        "[conn][%p] IN: BytesRecv=%llu",
        Connection,
        Connection->Stats.Recv.TotalBytes);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Recv.TotalBytes = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_H, ConnInFlowStats,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowBlocked
// [conn][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            ConnOutFlowBlocked,
            "[conn][%p] Send Blocked Flags: %hhu",
            Connection,
            Connection->OutFlowBlockedReasons);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->OutFlowBlockedReasons = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONNECTION_H, ConnOutFlowBlocked,
    TP_ARGS(
        const void *, arg2,
        unsigned char, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned char, arg3, arg3)
    )
)
