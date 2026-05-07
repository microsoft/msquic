


/*----------------------------------------------------------
// Decoder Ring for TestCaseStart
// [test] START %s
// QuicTraceLogInfo(
            TestCaseStart,
            "[test] START %s",
            TestName);
// arg2 = arg2 = TestName = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QUIC_GTEST_CPP, TestCaseStart,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestCaseEnd
// [test] END %s
// QuicTraceLogInfo(
            TestCaseEnd,
            "[test] END %s",
            TestName);
// arg2 = arg2 = TestName = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QUIC_GTEST_CPP, TestCaseEnd,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestCaseTStart
// [test] START %s, %s
// QuicTraceLogInfo(
            TestCaseTStart,
            "[test] START %s, %s",
            TestName,
            stream.str().c_str());
// arg2 = arg2 = TestName = arg2
// arg3 = arg3 = stream.str().c_str() = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QUIC_GTEST_CPP, TestCaseTStart,
    TP_ARGS(
        const char *, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestCaseTEnd
// [test] END %s
// QuicTraceLogInfo(
            TestCaseTEnd,
            "[test] END %s",
            TestName);
// arg2 = arg2 = TestName = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QUIC_GTEST_CPP, TestCaseTEnd,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestLogFailure
// [test] FAILURE - %s:%d - %s
// QuicTraceLogError(
        TestLogFailure,
        "[test] FAILURE - %s:%d - %s",
        File,
        Line,
        Buffer);
// arg2 = arg2 = File = arg2
// arg3 = arg3 = Line = arg3
// arg4 = arg4 = Buffer = arg4
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_QUIC_GTEST_CPP, TestLogFailure,
    TP_ARGS(
        const char *, arg2,
        int, arg3,
        const char *, arg4), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(int, arg3, arg3)
        ctf_string(arg4, arg4)
    )
)
