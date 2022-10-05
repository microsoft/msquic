


/*----------------------------------------------------------
// Decoder Ring for MtuSearchComplete
// [conn][%p] Path[%hhu] Mtu Discovery Entering Search Complete at MTU %hu
// QuicTraceLogConnInfo(
        MtuSearchComplete,
        Connection,
        "Path[%hhu] Mtu Discovery Entering Search Complete at MTU %hu",
        Path->ID,
        Path->Mtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Path->Mtu = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_MTU_DISCOVERY_C, MtuSearchComplete,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for MtuSearching
// [conn][%p] Path[%hhu] Mtu Discovery Search Packet Sending with MTU %hu
// QuicTraceLogConnInfo(
        MtuSearching,
        Connection,
        "Path[%hhu] Mtu Discovery Search Packet Sending with MTU %hu",
        Path->ID,
        MtuDiscovery->ProbeSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->ProbeSize = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_MTU_DISCOVERY_C, MtuSearching,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for MtuPathInitialized
// [conn][%p] Path[%hhu] Mtu Discovery Initialized: max_mtu=%u, cur/min_mtu=%u
// QuicTraceLogConnInfo(
        MtuPathInitialized,
        Connection,
        "Path[%hhu] Mtu Discovery Initialized: max_mtu=%u, cur/min_mtu=%u",
        Path->ID,
        MtuDiscovery->MaxMtu,
        Path->Mtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->MaxMtu = arg4
// arg5 = arg5 = Path->Mtu = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_MTU_DISCOVERY_C, MtuPathInitialized,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PathMtuUpdated
// [conn][%p] Path[%hhu] MTU updated to %hu bytes
// QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Path->Mtu = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_MTU_DISCOVERY_C, PathMtuUpdated,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned short, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for MtuDiscarded
// [conn][%p] Path[%hhu] Mtu Discovery Packet Discarded: size=%u, probe_count=%u
// QuicTraceLogConnInfo(
        MtuDiscarded,
        Connection,
        "Path[%hhu] Mtu Discovery Packet Discarded: size=%u, probe_count=%u",
        Path->ID,
        MtuDiscovery->ProbeSize,
        MtuDiscovery->ProbeCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->ProbeSize = arg4
// arg5 = arg5 = MtuDiscovery->ProbeCount = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_MTU_DISCOVERY_C, MtuDiscarded,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)



/*----------------------------------------------------------
// Decoder Ring for MtuIncorrectSize
// [conn][%p] Path[%hhu] Mtu Discovery Received Out of Order: expected=%u received=%u
// QuicTraceLogConnVerbose(
            MtuIncorrectSize,
            Connection,
            "Path[%hhu] Mtu Discovery Received Out of Order: expected=%u received=%u",
            Path->ID,
            MtuDiscovery->ProbeSize,
            PacketMtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->ProbeSize = arg4
// arg5 = arg5 = PacketMtu = arg5
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_MTU_DISCOVERY_C, MtuIncorrectSize,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned int, arg4,
        unsigned int, arg5), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_integer(unsigned int, arg5, arg5)
    )
)
