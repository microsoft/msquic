


/*----------------------------------------------------------
// Decoder Ring for PlatformWorkerThreadStart
// [ lib][%p] Worker start
// QuicTraceLogInfo(
        PlatformWorkerThreadStart,
        "[ lib][%p] Worker start",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WORKER_C, PlatformWorkerThreadStart,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PlatformWorkerThreadStop
// [ lib][%p] Worker stop
// QuicTraceLogInfo(
        PlatformWorkerThreadStop,
        "[ lib][%p] Worker stop",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WORKER_C, PlatformWorkerThreadStop,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for PlatformWorkerProcessPools
// [ lib][%p] Processing pools
// QuicTraceLogVerbose(
        PlatformWorkerProcessPools,
        "[ lib][%p] Processing pools",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WORKER_C, PlatformWorkerProcessPools,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, (uint64_t)arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CxPlatEventQInitialize");
// arg2 = arg2 = "CxPlatEventQInitialize" = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WORKER_C, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER_POOL",
            WorkerPoolSize);
// arg2 = arg2 = "CXPLAT_WORKER_POOL" = arg2
// arg3 = arg3 = WorkerPoolSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_PLATFORM_WORKER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
