


/*----------------------------------------------------------
// Decoder Ring for PacketRxStatelessReset
// [S][RX][-] SR %s
// QuicTraceLogVerbose(
                PacketRxStatelessReset,
                "[S][RX][-] SR %s",
                QuicCidBufToStr(ResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg2 = arg2 = QuicCidBufToStr(ResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, PacketRxStatelessReset,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NoReplacementCidForRetire
// [conn][%p] Can't retire current CID because we don't have a replacement
// QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            PathID->Connection,
            "Can't retire current CID because we don't have a replacement");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, NoReplacementCidForRetire,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NonActivePathCidRetired
// [conn][%p] Non-active path has no replacement for retired CID.
// QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                PathID->Connection,
                "Non-active path has no replacement for retired CID.");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, NonActivePathCidRetired,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for NewSrcCidNameCollision
// [conn][%p] CID collision, trying again
// QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                PathID->Connection,
                "CID collision, trying again");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, NewSrcCidNameCollision,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ZeroLengthCidRetire
// [conn][%p] Can't retire current CID because it's zero length
// QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            PathID->Connection,
            "Can't retire current CID because it's zero length");
// arg1 = arg1 = PathID->Connection = arg1
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, ZeroLengthCidRetire,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidAdded,
        "[conn][%p][pathid][%u] (SeqNum=%llu) New Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = DestCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, ConnDestCidAdded,
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
// Decoder Ring for ConnSourceCidAdded
// [conn][%p][pathid][%u] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p][pathid][%u] (SeqNum=%llu) New Source CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = SourceCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, ConnSourceCidAdded,
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
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "new Src CID",
                sizeof(QUIC_CID_SLIST_ENTRY) + MsQuicLib.CidTotalLength);
// arg2 = arg2 = "new Src CID" = arg2
// arg3 = arg3 = sizeof(QUIC_CID_SLIST_ENTRY) + MsQuicLib.CidTotalLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, AllocFailure,
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
                    PathID->Connection,
                    "Too many CID collisions");
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = "Too many CID collisions" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidRemoved
// [conn][%p][pathid][%u] (SeqNum=%llu) Removed Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Destination CID: %!CID!",
        PathID->Connection,
        PathID->ID,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = DestCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data) = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PATHID_C, ConnDestCidRemoved,
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
