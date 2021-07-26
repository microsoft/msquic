


/*----------------------------------------------------------
// Decoder Ring for TestControlClientCanceledRequest
// [test] Client %p canceled request %p
// QuicTraceLogWarning(
        TestControlClientCanceledRequest,
        "[test] Client %p canceled request %p",
        Client,
        Request);
// arg2 = arg2 = Client
// arg3 = arg3 = Request
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlClientCanceledRequest,
    TP_ARGS(
        const void *, arg2,
        const void *, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer_hex(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlClientCreated
// [test] Client %p created
// QuicTraceLogInfo(
            TestControlClientCreated,
            "[test] Client %p created",
            Client);
// arg2 = arg2 = Client
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlClientCreated,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlClientCleaningUp
// [test] Client %p cleaning up
// QuicTraceLogInfo(
            TestControlClientCleaningUp,
            "[test] Client %p cleaning up",
            Client);
// arg2 = arg2 = Client
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlClientCleaningUp,
    TP_ARGS(
        const void *, arg2), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlClientIoctl
// [test] Client %p executing IOCTL %u
// QuicTraceLogInfo(
        TestControlClientIoctl,
        "[test] Client %p executing IOCTL %u",
        Client,
        FunctionCode);
// arg2 = arg2 = Client
// arg3 = arg3 = FunctionCode
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlClientIoctl,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlClientIoctlComplete
// [test] Client %p completing request, 0x%x
// QuicTraceLogInfo(
        TestControlClientIoctlComplete,
        "[test] Client %p completing request, 0x%x",
        Client,
        Status);
// arg2 = arg2 = Client
// arg3 = arg3 = Status
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlClientIoctlComplete,
    TP_ARGS(
        const void *, arg2,
        unsigned int, arg3), 
    TP_FIELDS(
        ctf_integer_hex(uint64_t, arg2, arg2)
        ctf_integer(unsigned int, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlInitialized
// [test] Control interface initialized
// QuicTraceLogVerbose(
        TestControlInitialized,
        "[test] Control interface initialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlInitialized,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlUninitializing
// [test] Control interface uninitializing
// QuicTraceLogVerbose(
        TestControlUninitializing,
        "[test] Control interface uninitializing");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlUninitializing,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestControlUninitialized
// [test] Control interface uninitialized
// QuicTraceLogVerbose(
        TestControlUninitialized,
        "[test] Control interface uninitialized");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestControlUninitialized,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestDriverFailureLocation
// [test] File: %s, Function: %s, Line: %d
// QuicTraceLogError(
        TestDriverFailureLocation,
        "[test] File: %s, Function: %s, Line: %d",
        File,
        Function,
        Line);
// arg2 = arg2 = File
// arg3 = arg3 = Function
// arg4 = arg4 = Line
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestDriverFailureLocation,
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
// Decoder Ring for TestDriverFailure
// [test] FAIL: %s
// QuicTraceLogError(
        TestDriverFailure,
        "[test] FAIL: %s",
        Buffer);
// arg2 = arg2 = Buffer
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, TestDriverFailure,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            MsQuic->GetInitStatus(),
            "MsQuicOpen");
// arg2 = arg2 = MsQuic->GetInitStatus()
// arg3 = arg3 = "MsQuicOpen"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, LibraryErrorStatus,
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
// arg2 = arg2 = "WdfControlDeviceInitAllocate failed"
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_CONTROL_CPP, LibraryError,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)
