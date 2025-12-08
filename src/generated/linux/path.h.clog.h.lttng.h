


/*----------------------------------------------------------
// Decoder Ring for PathInFlowStats
// [conn][%p][pathid][%u] IN: BytesRecv=%llu
// QuicTraceEvent(
        PathInFlowStats,
        "[conn][%p][pathid][%u] IN: BytesRecv=%llu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->Stats.Recv.TotalBytes);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->Stats.Recv.TotalBytes = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_H, PathInFlowStats,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned long long, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathStatsV3
// [conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u
// QuicTraceEvent(
        PathStatsV3,
        "[conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->SmoothedRtt,
        Path->Stats.Send.CongestionCount,
        Path->Stats.Send.PersistentCongestionCount,
        Path->Stats.Send.TotalBytes,
        Path->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&Path->CongestionControl),
        Path->CongestionControl.Name,
        Path->Stats.Send.EcnCongestionCount);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->SmoothedRtt = arg4
// arg5 = arg5 = Path->Stats.Send.CongestionCount = arg5
// arg6 = arg6 = Path->Stats.Send.PersistentCongestionCount = arg6
// arg7 = arg7 = Path->Stats.Send.TotalBytes = arg7
// arg8 = arg8 = Path->Stats.Recv.TotalBytes = arg8
// arg9 = arg9 = QuicCongestionControlGetCongestionWindow(&Path->CongestionControl) = arg9
// arg10 = arg10 = Path->CongestionControl.Name = arg10
// arg11 = arg11 = Path->Stats.Send.EcnCongestionCount = arg11
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_H, PathStatsV3,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned long long, arg4,
        unsigned int, arg5,
        unsigned int, arg6,
        unsigned long long, arg7,
        unsigned long long, arg8,
        unsigned int, arg9,
        const char *, arg10,
        unsigned int, arg11), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
        ctf_integer(unsigned int, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
        ctf_integer(uint64_t, arg8, arg8)
        ctf_integer(unsigned int, arg9, arg9)
        ctf_string(arg10, arg10)
        ctf_integer(unsigned int, arg11, arg11)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathPacketStats
// [conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu
// QuicTraceEvent(
        PathPacketStats,
        "[conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->Stats.Send.TotalPackets,
        Path->Stats.Send.SuspectedLostPackets,
        Path->Stats.Send.SpuriousLostPackets,
        Path->Stats.Recv.TotalPackets,
        Path->Stats.Recv.ReorderedPackets,
        Path->Stats.Recv.DuplicatePackets,
        Path->Stats.Recv.DecryptionFailures);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->Stats.Send.TotalPackets = arg4
// arg5 = arg5 = Path->Stats.Send.SuspectedLostPackets = arg5
// arg6 = arg6 = Path->Stats.Send.SpuriousLostPackets = arg6
// arg7 = arg7 = Path->Stats.Recv.TotalPackets = arg7
// arg8 = arg8 = Path->Stats.Recv.ReorderedPackets = arg8
// arg9 = arg9 = Path->Stats.Recv.DuplicatePackets = arg9
// arg10 = arg10 = Path->Stats.Recv.DecryptionFailures = arg10
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_H, PathPacketStats,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned long long, arg4,
        unsigned long long, arg5,
        unsigned long long, arg6,
        unsigned long long, arg7,
        unsigned long long, arg8,
        unsigned long long, arg9,
        unsigned long long, arg10), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(uint64_t, arg5, arg5)
        ctf_integer(uint64_t, arg6, arg6)
        ctf_integer(uint64_t, arg7, arg7)
        ctf_integer(uint64_t, arg8, arg8)
        ctf_integer(uint64_t, arg9, arg9)
        ctf_integer(uint64_t, arg10, arg10)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathOutFlowBlocked
// [conn][%p][pathid][%hhu] Send Blocked Flags: %hhu
// QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            Path->PathID->Connection,
            Path->PathID->ID,
            Path->OutFlowBlockedReasons);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->OutFlowBlockedReasons = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATH_H, PathOutFlowBlocked,
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
