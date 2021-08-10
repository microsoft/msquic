


/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailed
// [ udp] RSS helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[ udp] RSS helper socket failed to open, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathOpenTcpSocketFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssProcessorInfoFailed
// [ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssProcessorInfoFailed,
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathQueryRssProcessorInfoFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailed
// [ udp] UDP send segmentation helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[ udp] UDP send segmentation helper socket failed to open, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathOpenUdpSocketFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSendMsgFailed
// [ udp] Query for UDP_SEND_MSG_SIZE failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryUdpSendMsgFailed,
            "[ udp] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathQueryUdpSendMsgFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRecvMaxCoalescedSizeFailed
// [ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRecvMaxCoalescedSizeFailed,
            "[ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathQueryRecvMaxCoalescedSizeFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryProcessorAffinityFailed
// [ udp][%p] WSAIoctl for SIO_QUERY_RSS_PROCESSOR_INFO failed, 0x%x
// QuicTraceLogWarning(
                        DatapathQueryProcessorAffinityFailed,
                        "[ udp][%p] WSAIoctl for SIO_QUERY_RSS_PROCESSOR_INFO failed, 0x%x",
                        Binding,
                        WsaError);
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathQueryProcessorAffinityFailed,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathMissingInfo
// [ udp][%p] WSARecvMsg completion is missing IP_PKTINFO
// QuicTraceLogWarning(
                DatapathMissingInfo,
                "[ udp][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathMissingInfo,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathRecvEmpty
// [ udp][%p] Dropping datagram with empty payload.
// QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[ udp][%p] Dropping datagram with empty payload.",
                SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathRecvEmpty,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathUroPreallocExceeded
// [ udp][%p] Exceeded URO preallocation capacity.
// QuicTraceLogWarning(
                    DatapathUroPreallocExceeded,
                    "[ udp][%p] Exceeded URO preallocation capacity.",
                    SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathUroPreallocExceeded,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathWorkerThreadStart
// [ udp][%p] Worker start
// QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[ udp][%p] Worker start",
        ProcContext);
// arg2 = arg2 = ProcContext
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathWorkerThreadStart,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathWorkerThreadStop
// [ udp][%p] Worker stop
// QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[ udp][%p] Worker stop",
        ProcContext);
// arg2 = arg2 = ProcContext
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathWorkerThreadStop,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownReturn
// [ udp][%p] Shut down (return)
// QuicTraceLogVerbose(
        DatapathShutDownReturn,
        "[ udp][%p] Shut down (return)",
        Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathShutDownReturn,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownComplete
// [ udp][%p] Shut down (complete)
// QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[ udp][%p] Shut down (complete)",
            SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathShutDownComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathUnreachableWithError
// [ udp][%p] Received unreachable error (0x%x) from %!ADDR!
// QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[ udp][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketContext->Binding,
        ErrorCode,
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = ErrorCode
// arg4 = arg4 = CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathUnreachableWithError,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned int, arg4_len,
        const void *, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4_len, arg4_len)
        ctf_sequence(char, arg4, arg4, unsigned int, arg4_len)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathTooLarge
// [ udp][%p] Received larger than expected datagram from %!ADDR!
// QuicTraceLogVerbose(
            DatapathTooLarge,
            "[ udp][%p] Received larger than expected datagram from %!ADDR!",
            SocketContext->Binding,
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathTooLarge,
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
// Decoder Ring for DatapathResolveHostNameFailed
// [%p] Couldn't resolve hostname '%s' to an IP address
// QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
// arg2 = arg2 = Datapath
// arg3 = arg3 = HostName
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathResolveHostNameFailed,
    TP_ARGS(
        const void *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_string(arg3, arg3)
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
// arg2 = arg2 = WsaError
// arg3 = arg3 = "WSAStartup"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);
// arg2 = arg2 = "QUIC_DATAPATH"
// arg3 = arg3 = DatapathLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
// arg2 = arg2 = "Resolving hostname to IP"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [ udp][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[ udp][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress)
// arg4 = arg4 = CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathCreated,
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
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "WSASocketW");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "WSASocketW"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathErrorStatus,
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
// Decoder Ring for DatapathDestroyed
// [ udp][%p] Destroyed
// QuicTraceEvent(
                DatapathDestroyed,
                "[ udp][%p] Destroyed",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathRecv
// [ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
            DatapathRecv,
            "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            NumberOfBytesTransferred,
            MessageLength,
            CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = NumberOfBytesTransferred
// arg4 = arg4 = MessageLength
// arg5 = arg5 = CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr)
// arg6 = arg6 = CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathRecv,
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
// [ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        SendContext->TotalSize,
        SendContext->WsaBufferCount,
        SendContext->SegmentSize,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = SendContext->TotalSize
// arg4 = arg4 = SendContext->WsaBufferCount
// arg5 = arg5 = SendContext->SegmentSize
// arg6 = arg6 = CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress)
// arg7 = arg7 = CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINUSER_C, DatapathSend,
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
