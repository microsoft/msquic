


/*----------------------------------------------------------
// Decoder Ring for PerfControlClientCanceledRequest
// [perf] Client %p canceled request %p
// QuicTraceLogWarning(
        PerfControlClientCanceledRequest,
        "[perf] Client %p canceled request %p",
        Client,
        Request);
// arg2 = arg2 = Client = arg2
// arg3 = arg3 = Request = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlClientCanceledRequest,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfDriverStarted
// [perf] Started
// QuicTraceLogInfo(
        PerfDriverStarted,
        "[perf] Started");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfDriverStarted,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfDriverStopped
// [perf] Stopped
// QuicTraceLogInfo(
        PerfDriverStopped,
        "[perf] Stopped");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfDriverStopped,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlClientCreated
// [perf] Client %p created
// QuicTraceLogInfo(
            PerfControlClientCreated,
            "[perf] Client %p created",
            Client);
// arg2 = arg2 = Client = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlClientCreated,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlClientCleaningUp
// [perf] Client %p cleaning up
// QuicTraceLogInfo(
            PerfControlClientCleaningUp,
            "[perf] Client %p cleaning up",
            Client);
// arg2 = arg2 = Client = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlClientCleaningUp,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerformanceStopCancelled
// [perf] Performance Stop Cancelled
// QuicTraceLogInfo(
            PerformanceStopCancelled,
            "[perf] Performance Stop Cancelled");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerformanceStopCancelled,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for PrintBufferReturn
// [perf] Print Buffer %d %s\n
// QuicTraceLogInfo(
        PrintBufferReturn,
        "[perf] Print Buffer %d %s\n",
        BufferCurrent,
        LocalBuffer);
// arg2 = arg2 = BufferCurrent = arg2
// arg3 = arg3 = LocalBuffer = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PrintBufferReturn,
    TP_ARGS(
        int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlClientIoctl
// [perf] Client %p executing write IOCTL %u
// QuicTraceLogInfo(
        PerfControlClientIoctl,
        "[perf] Client %p executing write IOCTL %u",
        Client,
        FunctionCode);
// arg2 = arg2 = Client = arg2
// arg3 = arg3 = FunctionCode = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlClientIoctl,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlClientIoctlComplete
// [perf] Client %p completing request, 0x%x
// QuicTraceLogInfo(
        PerfControlClientIoctlComplete,
        "[perf] Client %p completing request, 0x%x",
        Client,
        Status);
// arg2 = arg2 = Client = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlClientIoctlComplete,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlInitialized
// [perf] Control interface initialized
// QuicTraceLogVerbose(
        PerfControlInitialized,
        "[perf] Control interface initialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlInitialized,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlUninitializing
// [perf] Control interface uninitializing
// QuicTraceLogVerbose(
        PerfControlUninitializing,
        "[perf] Control interface uninitializing");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlUninitializing,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for PerfControlUninitialized
// [perf] Control interface uninitialized
// QuicTraceLogVerbose(
        PerfControlUninitialized,
        "[perf] Control interface uninitialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, PerfControlUninitialized,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatInitialize failed");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatInitialize failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, LibraryErrorStatus,
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
            "WdfControlDeviceInitAllocate failed");
// arg2 = arg2 = "WdfControlDeviceInitAllocate failed" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRVMAIN_CPP, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
