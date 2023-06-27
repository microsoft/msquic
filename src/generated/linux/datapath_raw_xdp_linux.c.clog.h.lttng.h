


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
        ctf_integer_hex(uint64_t, arg2, arg2)
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
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for QueueInit
// [ xdp][%p] Setting up Queue on Interface:%p
// QuicTraceLogVerbose(
            QueueInit,
            "[ xdp][%p] Setting up Queue on Interface:%p",
            Queue,
            Interface);
// arg2 = arg2 = Queue = arg2
// arg3 = arg3 = Interface = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, QueueInit,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for InterfaceInit
// [ xdp][%p] Interface init done
// QuicTraceLogVerbose(
        InterfaceInit,
        "[ xdp][%p] Interface init done",
        Interface);
// arg2 = arg2 = Interface = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, InterfaceInit,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpInitialize
// [ xdp][%p] XDP initialized, %u procs
// QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->WorkerCount);
// arg2 = arg2 = Xdp = arg2
// arg3 = arg3 = Xdp->WorkerCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpInitialize,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpWorkerStart
// [ xdp][%p] XDP worker start, %u queues
// QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP worker start, %u queues",
            Worker,
            QueueCount);
// arg2 = arg2 = Worker = arg2
// arg3 = arg3 = QueueCount = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpWorkerStart,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
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
        ctf_integer_hex(uint64_t, arg2, arg2)
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
        ctf_integer_hex(uint64_t, arg2, arg2)
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
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for FailSendTo
// [ xdp][tx  ] Faild sendto. errno:%d, Umem addr:%lld
// QuicTraceLogVerbose(
            FailSendTo,
            "[ xdp][tx  ] Faild sendto. errno:%d, Umem addr:%lld", er, Packet->tx_desc->addr);
// arg2 = arg2 = er = arg2
// arg3 = arg3 = Packet->tx_desc->addr = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailSendTo,
    TP_ARGS(
        int, arg2,
        long long, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_integer(int64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for DoneSendTo
// [ xdp][TX  ] Done sendto. len:%d, Umem addr:%lld
// QuicTraceLogVerbose(
            DoneSendTo,
            "[ xdp][TX  ] Done sendto. len:%d, Umem addr:%lld", SendData->Buffer.Length, Packet->tx_desc->addr);
// arg2 = arg2 = SendData->Buffer.Length = arg2
// arg3 = arg3 = Packet->tx_desc->addr = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, DoneSendTo,
    TP_ARGS(
        int, arg2,
        long long, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_integer(int64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for ReleaseCons
// [ xdp][cq  ] Release %d from completion queue
// QuicTraceLogVerbose(
            ReleaseCons,
            "[ xdp][cq  ] Release %d from completion queue", completed);
// arg2 = arg2 = completed = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, ReleaseCons,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpWorkerShutdown
// [ xdp][%p] XDP worker shutdown
// QuicTraceLogVerbose(
            XdpWorkerShutdown,
            "[ xdp][%p] XDP worker shutdown",
            Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpWorkerShutdown,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for RxConsPeekFail
// [ xdp][rx  ] Failed to peek from Rx queue
// QuicTraceLogVerbose(
            RxConsPeekFail,
            "[ xdp][rx  ] Failed to peek from Rx queue");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, RxConsPeekFail,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for RxConsPeekSucceed
// [ xdp][rx  ] Succeed peek %d from Rx queue
// QuicTraceLogVerbose(
            RxConsPeekSucceed,
            "[ xdp][rx  ] Succeed peek %d from Rx queue", rcvd);
// arg2 = arg2 = rcvd = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, RxConsPeekSucceed,
    TP_ARGS(
        int, arg2), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpRxRelease
// [ xdp][%p] Release %d from Rx queue (TODO:Check necesity here)
// QuicTraceLogVerbose(
            XdpRxRelease,
            "[ xdp][%p] Release %d from Rx queue (TODO:Check necesity here)",
            Queue, rcvd);
// arg2 = arg2 = Queue = arg2
// arg3 = arg3 = rcvd = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpRxRelease,
    TP_ARGS(
        const void *, arg2,
        int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpWorkerShutdownComplete
// [ xdp][%p] XDP worker shutdown complete
// QuicTraceLogVerbose(
            XdpWorkerShutdownComplete,
            "[ xdp][%p] XDP worker shutdown complete",
            Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpWorkerShutdownComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
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
        ctf_integer_hex(uint64_t, arg2, arg2)
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
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Status,
                    "CxPlatDpRawInterfaceInitialize");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatDpRawInterfaceInitialize" = arg3
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
