


/*----------------------------------------------------------
// Decoder Ring for DatapathTcpAuxBinding
// [data][%p] Binding TCP socket to %s
// QuicTraceLogVerbose(
            DatapathTcpAuxBinding,
            "[data][%p] Binding TCP socket to %s",
            Socket,
            LocalAddressString.Address);
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = LocalAddressString.Address = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathTcpAuxBinding,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RouteResolutionEnd
// [conn][%p] Route resolution completed on Path[%hhu] with L2 address %hhx:%hhx:%hhx:%hhx:%hhx:%hhx
// QuicTraceLogConnInfo(
        RouteResolutionEnd,
        Connection,
        "Route resolution completed on Path[%hhu] with L2 address %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        PathId,
        Route->NextHopLinkLayerAddress[0],
        Route->NextHopLinkLayerAddress[1],
        Route->NextHopLinkLayerAddress[2],
        Route->NextHopLinkLayerAddress[3],
        Route->NextHopLinkLayerAddress[4],
        Route->NextHopLinkLayerAddress[5]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = PathId = arg3
// arg4 = arg4 = Route->NextHopLinkLayerAddress[0] = arg4
// arg5 = arg5 = Route->NextHopLinkLayerAddress[1] = arg5
// arg6 = arg6 = Route->NextHopLinkLayerAddress[2] = arg6
// arg7 = arg7 = Route->NextHopLinkLayerAddress[3] = arg7
// arg8 = arg8 = Route->NextHopLinkLayerAddress[4] = arg8
// arg9 = arg9 = Route->NextHopLinkLayerAddress[5] = arg9
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, RouteResolutionEnd,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned char, arg4,
        unsigned char, arg5,
        unsigned char, arg6,
        unsigned char, arg7,
        unsigned char, arg8,
        unsigned char, arg9), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, (uint64_t)arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned char, arg5, arg5)
        ctf_integer(unsigned char, arg6, arg6)
        ctf_integer(unsigned char, arg7, arg7)
        ctf_integer(unsigned char, arg8, arg8)
        ctf_integer(unsigned char, arg9, arg9)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "closesocket");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = Error = arg3
// arg4 = arg4 = "closesocket" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathErrorStatus,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSendTcpControl
// [data][%p] Send %u bytes TCP control packet Flags=%hhu Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSendTcpControl,
        "[data][%p] Send %u bytes TCP control packet Flags=%hhu Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        (uint8_t)(TH_FIN | TH_ACK),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->Buffer.Length = arg3
// arg4 = arg4 = (uint8_t)(TH_FIN | TH_ACK) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathSendTcpControl,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned char, arg4,
        unsigned int, arg5_len,
        const void *, arg5,
        unsigned int, arg6_len,
        const void *, arg6), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
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
            CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->Buffer.Length = arg3
// arg4 = arg4 = 1 = arg4
// arg5 = arg5 = (uint16_t)SendData->Buffer.Length = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg6
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathSend,
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
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned char, arg4, arg4)
        ctf_integer(unsigned short, arg5, arg5)
        ctf_integer(unsigned int, arg6_len, arg6_len)
        ctf_sequence(char, arg6, arg6, unsigned int, arg6_len)
        ctf_integer(unsigned int, arg7_len, arg7_len)
        ctf_sequence(char, arg7, arg7, unsigned int, arg7_len)
    )
)
