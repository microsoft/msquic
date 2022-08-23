


/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailed
// [data] UDP send segmentation helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[data] UDP send segmentation helper socket failed to open, 0x%x",
            SockError);
// arg2 = arg2 = SockError = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathOpenUdpSocketFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSegmentFailed
// [data] Query for UDP_SEGMENT failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryUdpSegmentFailed,
            "[data] Query for UDP_SEGMENT failed, 0x%x",
            SockError);
// arg2 = arg2 = SockError = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathQueryUdpSegmentFailed,
    TP_ARGS(
        unsigned int, arg2), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathRecvEmpty
// [data][%p] Dropping datagram with empty payload.
// QuicTraceLogWarning(
            DatapathRecvEmpty,
            "[data][%p] Dropping datagram with empty payload.",
            SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathRecvEmpty,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathProcContextInitialize
// [data][%p] Proc context initialize
// QuicTraceLogVerbose(
        DatapathProcContextInitialize,
        "[data][%p] Proc context initialize",
        ProcContext);
// arg2 = arg2 = ProcContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathProcContextInitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathInitialize
// [data][%p] Datapath initialize
// QuicTraceLogVerbose(
        DatapathInitialize,
        "[data][%p] Datapath initialize",
        Datapath);
// arg2 = arg2 = Datapath = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathInitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathUninitializeComplete
// [data][%p] Datapath uninitialize complete
// QuicTraceLogVerbose(
            DatapathUninitializeComplete,
            "[data][%p] Datapath uninitialize complete",
            Datapath);
// arg2 = arg2 = Datapath = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathUninitializeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathProcContextUninitializeComplete
// [data][%p] Proc context uninitialize complete
// QuicTraceLogVerbose(
        DatapathProcContextUninitializeComplete,
        "[data][%p] Proc context uninitialize complete",
        ProcContext);
// arg2 = arg2 = ProcContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathProcContextUninitializeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathProcContextUninitialize
// [data][%p] Proc context uninitialize
// QuicTraceLogVerbose(
            DatapathProcContextUninitialize,
            "[data][%p] Proc context uninitialize",
            ProcContext);
// arg2 = arg2 = ProcContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathProcContextUninitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathUninitialize
// [data][%p] Datapath uninitialize
// QuicTraceLogVerbose(
            DatapathUninitialize,
            "[data][%p] Datapath uninitialize",
            Datapath);
// arg2 = arg2 = Datapath = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathUninitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSocketContextInitialize
// [data][%p] Socket context initialize
// QuicTraceLogVerbose(
        DatapathSocketContextInitialize,
        "[data][%p] Socket context initialize",
        SocketContext);
// arg2 = arg2 = SocketContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathSocketContextInitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSocketUninitializeComplete
// [data][%p] Socket uninitialize complete
// QuicTraceLogVerbose(
            DatapathSocketUninitializeComplete,
            "[data][%p] Socket uninitialize complete",
            Socket);
// arg2 = arg2 = Socket = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathSocketUninitializeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSocketContextUninitializeComplete
// [data][%p] Socket context uninitialize complete
// QuicTraceLogVerbose(
        DatapathSocketContextUninitializeComplete,
        "[data][%p] Socket context uninitialize complete",
        SocketContext);
// arg2 = arg2 = SocketContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathSocketContextUninitializeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSocketContextUninitialize
// [data][%p] Socket context uninitialize
// QuicTraceLogVerbose(
        DatapathSocketContextUninitialize,
        "[data][%p] Socket context uninitialize",
        SocketContext);
// arg2 = arg2 = SocketContext = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathSocketContextUninitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
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
// arg2 = arg2 = Datapath = arg2
// arg3 = arg3 = HostName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathResolveHostNameFailed,
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
            errno,
            "CxPlatSqeInitialize failed");
// arg2 = arg2 = errno = arg2
// arg3 = arg3 = "CxPlatSqeInitialize failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, LibraryErrorStatus,
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
            "CXPLAT_DATAPATH",
            DatapathLength);
// arg2 = arg2 = "CXPLAT_DATAPATH" = arg2
// arg3 = arg3 = DatapathLength = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed");
// arg2 = arg2 = SocketContext->Binding = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed" = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathErrorStatus,
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
// Decoder Ring for DatapathRecv
// [data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            (uint32_t)RecvPacket->BufferLength,
            (uint32_t)RecvPacket->BufferLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding = arg2
// arg3 = arg3 = (uint32_t)RecvPacket->BufferLength = arg3
// arg4 = arg4 = (uint32_t)RecvPacket->BufferLength = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr) = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr) = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathRecv,
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
// Decoder Ring for DatapathCreated
// [data][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress) = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathCreated,
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
// Decoder Ring for DatapathDestroyed
// [data][%p] Destroyed
// QuicTraceEvent(
        DatapathDestroyed,
        "[data][%p] Destroyed",
        Socket);
// arg2 = arg2 = Socket = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathDestroyed,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
            DatapathSend,
            "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
            Socket,
            SendData->TotalSize,
            SendData->BufferCount,
            SendData->SegmentSize,
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->TotalSize = arg3
// arg4 = arg4 = SendData->BufferCount = arg4
// arg5 = arg5 = SendData->SegmentSize = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress) = arg6
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress) = arg7
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_EPOLL_C, DatapathSend,
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
