


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(CXPLAT_DATAPATH));
// arg2 = arg2 = "CXPLAT_DATAPATH"
// arg3 = arg3 = sizeof(CXPLAT_DATAPATH)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_DPDK_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathRecv
// [data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
                    DatapathRecv,
                    "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
                    Socket,
                    Packet->BufferLength,
                    Packet->BufferLength,
                    CASTED_CLOG_BYTEARRAY(sizeof(Packet->IP.LocalAddress), &Packet->IP.LocalAddress),
                    CASTED_CLOG_BYTEARRAY(sizeof(Packet->IP.RemoteAddress), &Packet->IP.RemoteAddress));
// arg2 = arg2 = Socket
// arg3 = arg3 = Packet->BufferLength
// arg4 = arg4 = Packet->BufferLength
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(Packet->IP.LocalAddress), &Packet->IP.LocalAddress)
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Packet->IP.RemoteAddress), &Packet->IP.RemoteAddress)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_DPDK_C, DatapathRecv,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned short, arg4,
        unsigned int, arg5_len,
        const void *, arg5,
        unsigned int, arg6_len,
        const void *, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned short, arg4, arg4)
        ctf_integer(unsigned int, arg5_len, arg5_len)
        ctf_sequence(char, arg5, arg5, unsigned int, arg5_len)
        ctf_integer(unsigned int, arg6_len, arg6_len)
        ctf_sequence(char, arg6, arg6, unsigned int, arg6_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
// arg2 = arg2 = Socket
// arg3 = arg3 = SendData->Buffer.Length
// arg4 = arg4 = 1
// arg5 = arg5 = (uint16_t)SendData->Buffer.Length
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress)
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_DPDK_C, DatapathSend,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned char, arg4,
        unsigned short, arg5,
        unsigned int, arg6_len,
        const void *, arg6,
        unsigned int, arg7_len,
        const void *, arg7), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
        ctf_integer(unsigned int, arg6_len, arg6_len)
        ctf_sequence(char, arg6, arg6, unsigned int, arg6_len)
        ctf_integer(unsigned int, arg7_len, arg7_len)
        ctf_sequence(char, arg7, arg7, unsigned int, arg7_len)
    )
)
