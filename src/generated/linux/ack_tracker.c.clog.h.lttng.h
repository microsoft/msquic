


/*----------------------------------------------------------
// Decoder Ring for PacketRxMarkedForAck
// [%c][RX][%llu] Marked for ACK (ECN=%hhu)
// QuicTraceLogVerbose(
        PacketRxMarkedForAck,
        "[%c][RX][%llu] Marked for ACK (ECN=%hhu)",
        PtkConnPre(Connection),
        PacketNumber,
        (uint8_t)ECN);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PacketNumber = arg3
// arg4 = arg4 = (uint8_t)ECN = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ACK_TRACKER_C, PacketRxMarkedForAck,
    TP_ARGS(
        unsigned char, arg2,
        unsigned long long, arg3,
        unsigned char, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned char, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
    )
)
