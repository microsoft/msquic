


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
