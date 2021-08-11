


/*----------------------------------------------------------
// Decoder Ring for WindowsKernelLoaded
// [ sys] Loaded
// QuicTraceLogInfo(
        WindowsKernelLoaded,
        "[ sys] Loaded");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelLoaded,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsKernelUnloaded
// [ sys] Unloaded
// QuicTraceLogInfo(
        WindowsKernelUnloaded,
        "[ sys] Unloaded");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelUnloaded,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsKernelInitialized
// [ sys] Initialized (PageSize = %u bytes; AvailMem = %llu bytes)
// QuicTraceLogInfo(
        WindowsKernelInitialized,
        "[ sys] Initialized (PageSize = %u bytes; AvailMem = %llu bytes)",
        Sbi.PageSize,
        QuicTotalMemory);
// arg2 = arg2 = Sbi.PageSize
// arg3 = arg3 = QuicTotalMemory
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelInitialized,
    TP_ARGS(
        unsigned int, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for WindowsKernelUninitialized
// [ sys] Uninitialized
// QuicTraceLogInfo(
        WindowsKernelUninitialized,
        "[ sys] Uninitialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelUninitialized,
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
            "BCryptOpenAlgorithmProvider (RNG)");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptOpenAlgorithmProvider (RNG)"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINKERNEL_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryAssert
// [ lib] ASSERT, %u:%s - %s.
// QuicTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
// arg2 = arg2 = (uint32_t)Line
// arg3 = arg3 = File
// arg4 = arg4 = Expr
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WINKERNEL_C, LibraryAssert,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
