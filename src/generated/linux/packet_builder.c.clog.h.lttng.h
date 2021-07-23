


/*----------------------------------------------------------
// Decoder Ring for NoSrcCidAvailable
// [conn][%p] No src CID to send with
// QuicTraceLogConnWarning(
            NoSrcCidAvailable,
            Connection,
            "No src CID to send with");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, NoSrcCidAvailable,
    TP_ARGS(
        const void *, arg1), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
    )
)



/*----------------------------------------------------------
// Decoder Ring for GetPacketTypeFailure
// [conn][%p] Failed to get packet type for control frames, 0x%x
// QuicTraceLogConnWarning(
        GetPacketTypeFailure,
        Builder->Connection,
        "Failed to get packet type for control frames, 0x%x",
        SendFlags);
// arg1 = arg1 = Builder->Connection
// arg3 = arg3 = SendFlags
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, GetPacketTypeFailure,
    TP_ARGS(
        const void *, arg1,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PacketBuilderSendBatch
// [conn][%p] Sending batch. %hu datagrams
// QuicTraceLogConnVerbose(
        PacketBuilderSendBatch,
        Builder->Connection,
        "Sending batch. %hu datagrams",
        (uint16_t)Builder->TotalCountDatagrams);
// arg1 = arg1 = Builder->Connection
// arg3 = arg3 = (uint16_t)Builder->TotalCountDatagrams
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, PacketBuilderSendBatch,
    TP_ARGS(
        const void *, arg1,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "NULL key in builder prepare");
// arg2 = arg2 = Connection
// arg3 = arg3 = "NULL key in builder prepare"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, ConnError,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "packet send context",
                    0);
// arg2 = arg2 = "packet send context"
// arg3 = arg3 = 0
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Send-triggered key update");
// arg2 = arg2 = Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "Send-triggered key update"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, ConnErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ConnPacketSent
// [conn][%p][TX][%llu] %hhu (%hu bytes)
// QuicTraceEvent(
        ConnPacketSent,
        "[conn][%p][TX][%llu] %hhu (%hu bytes)",
        Connection,
        Builder->Metadata->PacketNumber,
        QuicPacketTraceType(Builder->Metadata),
        Builder->Metadata->PacketLength);
// arg2 = arg2 = Connection
// arg3 = arg3 = Builder->Metadata->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Builder->Metadata)
// arg5 = arg5 = Builder->Metadata->PacketLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PACKET_BUILDER_C, ConnPacketSent,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3,
        unsigned char, arg4,
        unsigned short, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
    )
)

