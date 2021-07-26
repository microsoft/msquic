


/*----------------------------------------------------------
// Decoder Ring for TestDriverStarted
// [test] Started
// QuicTraceLogInfo(
        TestDriverStarted,
        "[test] Started");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRIVER_CPP, TestDriverStarted,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestDriverStopped
// [test] Stopped
// QuicTraceLogInfo(
        TestDriverStopped,
        "[test] Stopped");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRIVER_CPP, TestDriverStopped,
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
// arg2 = arg2 = Status
// arg3 = arg3 = "CxPlatInitialize failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_DRIVER_CPP, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)

