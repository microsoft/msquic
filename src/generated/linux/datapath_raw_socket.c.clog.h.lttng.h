


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
        ctf_integer_hex(uint64_t, arg1, arg1)
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
// Decoder Ring for RouteResolutionStart
// [conn][%p] Starting to look up neighbor on Path[%hhu] with status %u
// QuicTraceLogConnInfo(
        RouteResolutionStart,
        Context,
        "Starting to look up neighbor on Path[%hhu] with status %u",
        PathId,
        Status);
// arg1 = arg1 = Context = arg1
// arg3 = arg3 = PathId = arg3
// arg4 = arg4 = Status = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, RouteResolutionStart,
    TP_ARGS(
        const void *, arg1,
        unsigned char, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg1, arg1)
        ctf_integer(unsigned char, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "WSAStartup");
// arg2 = arg2 = WsaError = arg2
// arg3 = arg3 = "WSAStartup" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "socket");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = WsaError = arg3
// arg4 = arg4 = "socket" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathErrorStatus,
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
// Decoder Ring for DatapathGetRouteStart
// [data][%p] Querying route, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathGetRouteStart,
        "[data][%p] Querying route, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathGetRouteStart,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathGetRouteComplete
// [data][%p] Query route result: %!ADDR!
// QuicTraceEvent(
        DatapathGetRouteComplete,
        "[data][%p] Query route result: %!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(LocalAddress), &LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(LocalAddress), &LocalAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathGetRouteComplete,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathError
// [data][%p] ERROR, %s.
// QuicTraceEvent(
            DatapathError,
            "[data][%p] ERROR, %s.",
            Socket,
            "no matching interface/queue");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = "no matching interface/queue" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, DatapathError,
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
                "CXPLAT_DATAPATH",
                sizeof(CXPLAT_ROUTE_RESOLUTION_OPERATION));
// arg2 = arg2 = "CXPLAT_DATAPATH" = arg2
// arg3 = arg3 = sizeof(CXPLAT_ROUTE_RESOLUTION_OPERATION) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_SOCKET_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
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
        ctf_integer_hex(uint64_t, arg2, arg2)
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
