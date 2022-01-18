


/*----------------------------------------------------------
// Decoder Ring for InteropTestStart
// [ntrp] Test Start, Server: %s, Port: %hu, Tests: 0x%x.
// QuicTraceLogInfo(
        InteropTestStart,
        "[ntrp] Test Start, Server: %s, Port: %hu, Tests: 0x%x.",
        PublicEndpoints[TestContext->EndpointIndex].ServerName,
        TestContext->Port,
        (uint32_t)TestContext->Feature);
// arg2 = arg2 = PublicEndpoints[TestContext->EndpointIndex].ServerName = arg2
// arg3 = arg3 = TestContext->Port = arg3
// arg4 = arg4 = (uint32_t)TestContext->Feature = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_INTEROP_CPP, InteropTestStart,
    TP_ARGS(
        const char *, arg2,
        unsigned short, arg3,
        unsigned int, arg4), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
    )
)



/*----------------------------------------------------------
// Decoder Ring for InteropTestStop
// [ntrp] Test Stop, Server: %s, Port: %hu, Tests: 0x%x, Negotiated Alpn: %s, Passed: %s.
// QuicTraceLogInfo(
        InteropTestStop,
        "[ntrp] Test Stop, Server: %s, Port: %hu, Tests: 0x%x, Negotiated Alpn: %s, Passed: %s.",
        PublicEndpoints[TestContext->EndpointIndex].ServerName,
        TestContext->Port,
        (uint32_t)TestContext->Feature,
        Alpn,
        ThisTestFailed ? "false" : "true");
// arg2 = arg2 = PublicEndpoints[TestContext->EndpointIndex].ServerName = arg2
// arg3 = arg3 = TestContext->Port = arg3
// arg4 = arg4 = (uint32_t)TestContext->Feature = arg4
// arg5 = arg5 = Alpn = arg5
// arg6 = arg6 = ThisTestFailed ? "false" : "true" = arg6
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_INTEROP_CPP, InteropTestStop,
    TP_ARGS(
        const char *, arg2,
        unsigned short, arg3,
        unsigned int, arg4,
        const char *, arg5,
        const char *, arg6), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
        ctf_integer(unsigned int, arg4, arg4)
        ctf_string(arg5, arg5)
        ctf_string(arg6, arg6)
    )
)
