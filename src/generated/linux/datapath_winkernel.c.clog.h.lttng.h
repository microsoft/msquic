


/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailed
// [ udp] RSS helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[ udp] RSS helper socket failed to open, 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenTcpSocketFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailedAsync
// [ udp] RSS helper socket failed to open (async), 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailedAsync,
            "[ udp] RSS helper socket failed to open (async), 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenTcpSocketFailedAsync,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssScalabilityInfoFailed
// [ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailed,
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRssScalabilityInfoFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssScalabilityInfoFailedAsync
// [ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed (async), 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailedAsync,
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed (async), 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRssScalabilityInfoFailedAsync,
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
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenUdpSocketFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailedAsync
// [ udp] UDP send segmentation helper socket failed to open (async), 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailedAsync,
            "[ udp] UDP send segmentation helper socket failed to open (async), 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenUdpSocketFailedAsync,
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
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryUdpSendMsgFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSendMsgFailedAsync
// [ udp] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x
// QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailedAsync,
                "[ udp] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x",
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryUdpSendMsgFailedAsync,
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
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRecvMaxCoalescedSizeFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRecvMaxCoalescedSizeFailedAsync
// [ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x
// QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailedAsync,
                "[ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x",
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRecvMaxCoalescedSizeFailedAsync,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathDropEmptyMdl
// [%p] Dropping datagram with empty mdl.
// QuicTraceLogWarning(
                DatapathDropEmptyMdl,
                "[%p] Dropping datagram with empty mdl.",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDropEmptyMdl,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathDropMissingInfo
// [%p] Dropping datagram missing IP_PKTINFO/IP_RECVERR.
// QuicTraceLogWarning(
                DatapathDropMissingInfo,
                "[%p] Dropping datagram missing IP_PKTINFO/IP_RECVERR.",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDropMissingInfo,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathDropTooBig
// [%p] Dropping datagram with too many bytes (%llu).
// QuicTraceLogWarning(
                    DatapathDropTooBig,
                    "[%p] Dropping datagram with too many bytes (%llu).",
                    Binding,
                    (uint64_t)DataLength);
// arg2 = arg2 = Binding
// arg3 = arg3 = (uint64_t)DataLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDropTooBig,
    TP_ARGS(
        const void *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathDropMdlMapFailure
// [%p] Failed to map MDL chain
// QuicTraceLogWarning(
                DatapathDropMdlMapFailure,
                "[%p] Failed to map MDL chain",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDropMdlMapFailure,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathFragmented
// [%p] Dropping datagram with fragmented MDL.
// QuicTraceLogWarning(
                    DatapathFragmented,
                    "[%p] Dropping datagram with fragmented MDL.",
                    Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathFragmented,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathDropAllocRecvContextFailure
// [%p] Couldn't allocate receive context.
// QuicTraceLogWarning(
                        DatapathDropAllocRecvContextFailure,
                        "[%p] Couldn't allocate receive context.",
                        Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDropAllocRecvContextFailure,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathDropAllocRecvBufferFailure
// [%p] Couldn't allocate receive buffers.
// QuicTraceLogWarning(
                            DatapathDropAllocRecvBufferFailure,
                            "[%p] Couldn't allocate receive buffers.",
                            Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDropAllocRecvBufferFailure,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathUroExceeded
// [%p] Exceeded URO preallocation capacity.
// QuicTraceLogWarning(
                    DatapathUroExceeded,
                    "[%p] Exceeded URO preallocation capacity.",
                    Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathUroExceeded,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathUnreachable
// [sock][%p] Unreachable error from %!ADDR!
// QuicTraceLogVerbose(
                DatapathUnreachable,
                "[sock][%p] Unreachable error from %!ADDR!",
                Binding,
                CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));
// arg2 = arg2 = Binding
// arg3 = arg3 = CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathUnreachable,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathResolveHostNameFailed,
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
            "QUIC_DATAPATH",
            DatapathLength);
// arg2 = arg2 = "QUIC_DATAPATH"
// arg3 = arg3 = DatapathLength
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskRegister");
// arg2 = arg2 = Status
// arg3 = arg3 = "WskRegister"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
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
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, LibraryError,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathCreated,
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
            Status,
            "WskSocket");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskSocket"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathErrorStatus,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathDestroyed,
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
            Binding,
            (uint32_t)DataLength,
            MessageLength,
            CLOG_BYTEARRAY(sizeof(LocalAddr), &LocalAddr),
            CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));
// arg2 = arg2 = Binding
// arg3 = arg3 = (uint32_t)DataLength
// arg4 = arg4 = MessageLength
// arg5 = arg5 = CLOG_BYTEARRAY(sizeof(LocalAddr), &LocalAddr)
// arg6 = arg6 = CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathRecv,
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
        SendContext->WskBufferCount,
        SendContext->SegmentSize,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = SendContext->TotalSize
// arg4 = arg4 = SendContext->WskBufferCount
// arg5 = arg5 = SendContext->SegmentSize
// arg6 = arg6 = CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress)
// arg7 = arg7 = CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress)
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_WINKERNEL_C, DatapathSend,
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
