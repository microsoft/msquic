


/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidRemoved
// [conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!
// QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!",
                    PathID->Connection,
                    PathID->ID,
                    SourceCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = SourceCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_H, ConnSourceCidRemoved,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned long long, arg4,
        unsigned int, arg5_len,
        const void *, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(uint64_t, arg4, arg4)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathInFlowStats
// [conn][%p][pathid][%u] IN: BytesRecv=%llu
// QuicTraceEvent(
        PathInFlowStats,
        "[conn][%p][pathid][%u] IN: BytesRecv=%llu",
        PathID->Connection,
        PathID->ID,
        PathID->Stats.Recv.TotalBytes);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->Stats.Recv.TotalBytes = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_H, PathInFlowStats,
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
        PathID->Connection,
        PathID->ID,
        PathID->Path->SmoothedRtt,
        PathID->Stats.Send.CongestionCount,
        PathID->Stats.Send.PersistentCongestionCount,
        PathID->Stats.Send.TotalBytes,
        PathID->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&PathID->CongestionControl),
        PathID->CongestionControl.Name,
        PathID->Stats.Send.EcnCongestionCount);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->Path->SmoothedRtt = arg4
// arg5 = arg5 = PathID->Stats.Send.CongestionCount = arg5
// arg6 = arg6 = PathID->Stats.Send.PersistentCongestionCount = arg6
// arg7 = arg7 = PathID->Stats.Send.TotalBytes = arg7
// arg8 = arg8 = PathID->Stats.Recv.TotalBytes = arg8
// arg9 = arg9 = QuicCongestionControlGetCongestionWindow(&PathID->CongestionControl) = arg9
// arg10 = arg10 = PathID->CongestionControl.Name = arg10
// arg11 = arg11 = PathID->Stats.Send.EcnCongestionCount = arg11
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_H, PathStatsV3,
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
        PathID->Connection,
        PathID->ID,
        PathID->Stats.Send.TotalPackets,
        PathID->Stats.Send.SuspectedLostPackets,
        PathID->Stats.Send.SpuriousLostPackets,
        PathID->Stats.Recv.TotalPackets,
        PathID->Stats.Recv.ReorderedPackets,
        PathID->Stats.Recv.DuplicatePackets,
        PathID->Stats.Recv.DecryptionFailures);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->Stats.Send.TotalPackets = arg4
// arg5 = arg5 = PathID->Stats.Send.SuspectedLostPackets = arg5
// arg6 = arg6 = PathID->Stats.Send.SpuriousLostPackets = arg6
// arg7 = arg7 = PathID->Stats.Recv.TotalPackets = arg7
// arg8 = arg8 = PathID->Stats.Recv.ReorderedPackets = arg8
// arg9 = arg9 = PathID->Stats.Recv.DuplicatePackets = arg9
// arg10 = arg10 = PathID->Stats.Recv.DecryptionFailures = arg10
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_H, PathPacketStats,
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
            PathID->Connection,
            PathID->ID,
            PathID->OutFlowBlockedReasons);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->OutFlowBlockedReasons = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_H, PathOutFlowBlocked,
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
