


/*----------------------------------------------------------
// Decoder Ring for FoundVF
// [ xdp][%p] Found NetSvc-VF interfaces. NetSvc IfIdx:%lu, VF IfIdx:%lu
// QuicTraceLogInfo(
                            FoundVF,
                            "[ xdp][%p] Found NetSvc-VF interfaces. NetSvc IfIdx:%lu, VF IfIdx:%lu",
                            Xdp,
                            Interface->IfIndex,
                            Interface->ActualIfIndex);
// arg2 = arg2 = Xdp = arg2
// arg3 = arg3 = Interface->IfIndex = arg3
// arg4 = arg4 = Interface->ActualIfIndex = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, FoundVF,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpInitialize,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpQueueStart
// [ xdp][%p] XDP queue start on worker %p
// QuicTraceLogVerbose(
                XdpQueueStart,
                "[ xdp][%p] XDP queue start on worker %p",
                Queue,
                Worker);
// arg2 = arg2 = Queue = arg2
// arg3 = arg3 = Worker = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueStart,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpWorkerStart,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpRelease,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpUninitializeComplete,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpUninitialize,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpWorkerShutdown,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoRx
// [ xdp][%p] XDP async IO start (RX)
// QuicTraceLogVerbose(
                    XdpQueueAsyncIoRx,
                    "[ xdp][%p] XDP async IO start (RX)",
                    Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoRx,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoTx
// [ xdp][%p] XDP async IO start (TX)
// QuicTraceLogVerbose(
                    XdpQueueAsyncIoTx,
                    "[ xdp][%p] XDP async IO start (TX)",
                    Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoTx,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoRxComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoTxComplete
// [ xdp][%p] XDP async IO complete (TX)
// QuicTraceLogVerbose(
                XdpQueueAsyncIoTxComplete,
                "[ xdp][%p] XDP async IO complete (TX)",
                Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoTxComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpWorkerShutdownComplete,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "ConvertInterfaceIndexToLuid");
// arg2 = arg2 = ret = arg2
// arg3 = arg3 = "ConvertInterfaceIndexToLuid" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, LibraryErrorStatus,
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
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, AllocFailure,
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
            "No more room for rules");
// arg2 = arg2 = "No more room for rules" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DATAPATH_RAW_XDP_WIN_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
