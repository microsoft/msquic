


/*----------------------------------------------------------
// Decoder Ring for XdpFailGettingRssQueueCount
// [ xdp] Failed to get RSS queue count for %s
// QuicTraceLogVerbose(
            XdpFailGettingRssQueueCount,
            "[ xdp] Failed to get RSS queue count for %s",
            IfName);
// arg2 = arg2 = IfName = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpFailGettingRssQueueCount,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpUmemDeleteFails
// [ xdp] Failed to delete Umem
// QuicTraceLogVerbose(
            XdpUmemDeleteFails,
            "[ xdp] Failed to delete Umem");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUmemDeleteFails,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpDetachFails
// [ xdp] Failed to detach XDP program from %s. error:%s
// QuicTraceLogVerbose(
            XdpDetachFails,
            "[ xdp] Failed to detach XDP program from %s. error:%s",
            Interface->IfName,
            strerror(-err));
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = strerror(-err) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpDetachFails,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for InterfaceFree
// [ xdp][%p] Freeing Interface
// QuicTraceLogVerbose(
        InterfaceFree,
        "[ xdp][%p] Freeing Interface",
        Interface);
// arg2 = arg2 = Interface = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, InterfaceFree,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for QueueFree
// [ xdp][%p] Freeing Queue on Interface:%p
// QuicTraceLogVerbose(
            QueueFree,
            "[ xdp][%p] Freeing Queue on Interface:%p",
            Queue,
            Interface);
// arg2 = arg2 = Queue = arg2
// arg3 = arg3 = Interface = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, QueueFree,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer_hex(uint64_t, arg3, (uint64_t)arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpAllocUmem
// [ xdp] Failed to allocate umem
// QuicTraceLogVerbose(
            XdpAllocUmem,
            "[ xdp] Failed to allocate umem");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpAllocUmem,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpUmemAllocFails
// [ xdp][umem] Out of UMEM frame, OOM
// QuicTraceLogVerbose(
            XdpUmemAllocFails,
            "[ xdp][umem] Out of UMEM frame, OOM");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUmemAllocFails,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpAttachFails
// [ xdp] Failed to attach XDP program to %s. error:%s
// QuicTraceLogVerbose(
            XdpAttachFails,
            "[ xdp] Failed to attach XDP program to %s. error:%s", Interface->IfName, errmsg);
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = errmsg = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpAttachFails,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpAttachSucceeds
// [ xdp] Successfully attach XDP program to %s by mode:%d
// QuicTraceLogVerbose(
        XdpAttachSucceeds,
        "[ xdp] Successfully attach XDP program to %s by mode:%d", Interface->IfName, Interface->AttachMode);
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = Interface->AttachMode = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpAttachSucceeds,
    TP_ARGS(
        const char *, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpOpenFileError
// [ xdp] Failed to open xdp program %s. error:%s(%d)
// QuicTraceLogVerbose(
            XdpOpenFileError,
            "[ xdp] Failed to open xdp program %s. error:%s(%d)",
            FilePath,
            errmsg,
            err);
// arg2 = arg2 = FilePath = arg2
// arg3 = arg3 = errmsg = arg3
// arg4 = arg4 = err = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpOpenFileError,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3,
        int, arg4), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
        ctf_integer(int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpLoadObject
// [ xdp] Successfully loaded xdp object of %s
// QuicTraceLogVerbose(
    XdpLoadObject,
    "[ xdp] Successfully loaded xdp object of %s",
    FilePath);
// arg2 = arg2 = FilePath = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpLoadObject,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpNoXsksMap
// [ xdp] No xsks map found
// QuicTraceLogVerbose(
            XdpNoXsksMap,
            "[ xdp] No xsks map found");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpNoXsksMap,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpConfigureUmem
// [ xdp] Failed to configure Umem
// QuicTraceLogVerbose(
                XdpConfigureUmem,
                "[ xdp] Failed to configure Umem");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpConfigureUmem,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for FailXskSocketCreate
// [ xdp] Failed to create XDP socket for %s. error:%s
// QuicTraceLogVerbose(
                FailXskSocketCreate,
                "[ xdp] Failed to create XDP socket for %s. error:%s", Interface->IfName, strerror(-Ret));
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = strerror(-Ret) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailXskSocketCreate,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FailRxAlloc
// [ xdp][rx  ] OOM for Rx
// QuicTraceLogVerbose(
                    FailRxAlloc,
                    "[ xdp][rx  ] OOM for Rx");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailRxAlloc,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpInitialize
// [ xdp][%p] XDP initialized, %u procs
// QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);
// arg2 = arg2 = Xdp = arg2
// arg3 = arg3 = Xdp->PartitionCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpInitialize,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpWorkerStart
// [ xdp][%p] XDP partition start, %u queues
// QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP partition start, %u queues",
            Partition,
            QueueCount);
// arg2 = arg2 = Partition = arg2
// arg3 = arg3 = QueueCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpWorkerStart,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpRelease
// [ xdp][%p] XDP release
// QuicTraceLogVerbose(
        XdpRelease,
        "[ xdp][%p] XDP release",
        Xdp);
// arg2 = arg2 = Xdp = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpRelease,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpUninitializeComplete
// [ xdp][%p] XDP uninitialize complete
// QuicTraceLogVerbose(
            XdpUninitializeComplete,
            "[ xdp][%p] XDP uninitialize complete",
            Xdp);
// arg2 = arg2 = Xdp = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUninitializeComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpUninitialize
// [ xdp][%p] XDP uninitialize
// QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
// arg2 = arg2 = Xdp = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUninitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpSetPortFails
// [ xdp] Failed to set port %d on %s
// QuicTraceLogVerbose(
                        XdpSetPortFails,
                        "[ xdp] Failed to set port %d on %s", port, Interface->IfName);
// arg2 = arg2 = port = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpSetPortFails,
    TP_ARGS(
        int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpDeletePortFails
// [ xdp] Failed to delete port %d on %s
// QuicTraceLogVerbose(
                        XdpDeletePortFails,
                        "[ xdp] Failed to delete port %d on %s", port, Interface->IfName);
// arg2 = arg2 = port = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpDeletePortFails,
    TP_ARGS(
        int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpSetIpFails
// [ xdp] Failed to set ipv4 %s on %s
// QuicTraceLogVerbose(
                        XdpSetIpFails,
                        "[ xdp] Failed to set ipv4 %s on %s",
                        inet_ntoa(Interface->Ipv4Address),
                        Interface->IfName);
// arg2 = arg2 = inet_ntoa(Interface->Ipv4Address) = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpSetIpFails,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpSetIfnameFails
// [ xdp] Failed to set ifname %s on %s
// QuicTraceLogVerbose(
                        XdpSetIfnameFails,
                        "[ xdp] Failed to set ifname %s on %s", Interface->IfName, Interface->IfName);
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpSetIfnameFails,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FailTxAlloc
// [ xdp][tx  ] OOM for Tx
// QuicTraceLogVerbose(
            FailTxAlloc,
            "[ xdp][tx  ] OOM for Tx");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailTxAlloc,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for DoneSendTo
// [ xdp][TX  ] Done sendto.
// QuicTraceLogVerbose(
        DoneSendTo,
        "[ xdp][TX  ] Done sendto.");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, DoneSendTo,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for ReleaseCons
// [ xdp][cq  ] Release %d from completion queue
// QuicTraceLogVerbose(
            ReleaseCons,
            "[ xdp][cq  ] Release %d from completion queue", Completed);
// arg2 = arg2 = Completed = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, ReleaseCons,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FailTxReserve
// [ xdp][tx  ] Failed to reserve
// QuicTraceLogVerbose(
            FailTxReserve,
            "[ xdp][tx  ] Failed to reserve");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailTxReserve,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpPartitionShutdown
// [ xdp][%p] XDP partition shutdown
// QuicTraceLogVerbose(
            XdpPartitionShutdown,
            "[ xdp][%p] XDP partition shutdown",
            Partition);
// arg2 = arg2 = Partition = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpPartitionShutdown,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpPartitionShutdownComplete
// [ xdp][%p] XDP partition shutdown complete
// QuicTraceLogVerbose(
            XdpPartitionShutdownComplete,
            "[ xdp][%p] XDP partition shutdown complete",
            Partition);
// arg2 = arg2 = Partition = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpPartitionShutdownComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoRxComplete
// [ xdp][%p] XDP async IO complete (RX)
// QuicTraceLogVerbose(
            XdpQueueAsyncIoRxComplete,
            "[ xdp][%p] XDP async IO complete (RX)",
            Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpQueueAsyncIoRxComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpEpollErrorStatus
// [ xdp]ERROR, %u, %s.
// QuicTraceEvent(
            XdpEpollErrorStatus,
            "[ xdp]ERROR, %u, %s.",
            errno,
            "epoll_ctl failed");
// arg2 = arg2 = errno = arg2
// arg3 = arg3 = "epoll_ctl failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpEpollErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatGetInterfaceRssQueueCount");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatGetInterfaceRssQueueCount" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, LibraryErrorStatus,
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
            "XDP Queues",
            Interface->QueueCount * sizeof(*Interface->Queues));
// arg2 = arg2 = "XDP Queues" = arg2
// arg3 = arg3 = Interface->QueueCount * sizeof(*Interface->Queues) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, AllocFailure,
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
            "no XDP capable interface");
// arg2 = arg2 = "no XDP capable interface" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RxConstructPacket
// [ xdp][rx  ] Constructing Packet from Rx, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
            RxConstructPacket,
            "[ xdp][rx  ] Constructing Packet from Rx, local=%!ADDR!, remote=%!ADDR!",
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.LocalAddress), &Packet->RouteStorage.LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.RemoteAddress), &Packet->RouteStorage.RemoteAddress));
// arg2 = arg2 = CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.LocalAddress), &Packet->RouteStorage.LocalAddress) = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.RemoteAddress), &Packet->RouteStorage.RemoteAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, RxConstructPacket,
    TP_ARGS(
        unsigned int, arg2_len,
        const void *, arg2,
        unsigned int, arg3_len,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2_len, arg2_len)
        ctf_sequence(char, arg2, arg2, unsigned int, arg2_len)
        ctf_integer(unsigned int, arg3_len, arg3_len)
        ctf_sequence(char, arg3, arg3, unsigned int, arg3_len)
    )
)
