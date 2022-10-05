


/*----------------------------------------------------------
// Decoder Ring for TestScopeEntry
// [test]---> %s
// QuicTraceLogInfo(
            TestScopeEntry,
            "[test]---> %s",
            Name);
// arg2 = arg2 = Name = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestScopeEntry,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestScopeExit
// [test]<--- %s
// QuicTraceLogInfo(
            TestScopeExit,
            "[test]<--- %s",
            Name);
// arg2 = arg2 = Name = arg2
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestScopeExit,
    TP_ARGS(
        const char *, arg2), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookRegister
// [test][hook] Registering
// QuicTraceLogInfo(
            TestHookRegister,
            "[test][hook] Registering");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookRegister,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookUnregistering
// [test][hook] Unregistering
// QuicTraceLogInfo(
            TestHookUnregistering,
            "[test][hook] Unregistering");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookUnregistering,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookUnregistered
// [test][hook] Unregistered
// QuicTraceLogInfo(
            TestHookUnregistered,
            "[test][hook] Unregistered");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookUnregistered,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookDropPacketRandom
// [test][hook] Random packet drop
// QuicTraceLogVerbose(
                TestHookDropPacketRandom,
                "[test][hook] Random packet drop");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookDropPacketRandom,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookDropPacketSelective
// [test][hook] Selective packet drop
// QuicTraceLogVerbose(
            TestHookDropPacketSelective,
            "[test][hook] Selective packet drop");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookDropPacketSelective,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrRecv
// [test][hook] Recv Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrRecv,
                "[test][hook] Recv Addr :%hu => :%hu",
                QuicAddrGetPort(&Original),
                QuicAddrGetPort(&New));
// arg2 = arg2 = QuicAddrGetPort(&Original) = arg2
// arg3 = arg3 = QuicAddrGetPort(&New) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookReplaceAddrRecv,
    TP_ARGS(
        unsigned short, arg2,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrSend
// [test][hook] Send Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&New),
                QuicAddrGetPort(&Original));
// arg2 = arg2 = QuicAddrGetPort(&New) = arg2
// arg3 = arg3 = QuicAddrGetPort(&Original) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookReplaceAddrSend,
    TP_ARGS(
        unsigned short, arg2,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookDropOldAddrSend
// [test][hook] Dropping send to old addr
// QuicTraceLogVerbose(
                TestHookDropOldAddrSend,
                "[test][hook] Dropping send to old addr");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookDropOldAddrSend,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookDropLimitAddrRecv
// [test][hook] Dropping recv over limit to new addr
// QuicTraceLogVerbose(
                    TestHookDropLimitAddrRecv,
                    "[test][hook] Dropping recv over limit to new addr");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookDropLimitAddrRecv,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookDropLimitAddrSend
// [test][hook] Dropping send over limit to new addr
// QuicTraceLogVerbose(
                    TestHookDropLimitAddrSend,
                    "[test][hook] Dropping send over limit to new addr");
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookDropLimitAddrSend,
    TP_ARGS(
), 
    TP_FIELDS(
    )
)



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceCreateSend
// [test][hook] Create (remote) Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceCreateSend,
                "[test][hook] Create (remote) Addr :%hu => :%hu",
                QuicAddrGetPort(&PublicAddress),
                QuicAddrGetPort(RemoteAddress));
// arg2 = arg2 = QuicAddrGetPort(&PublicAddress) = arg2
// arg3 = arg3 = QuicAddrGetPort(RemoteAddress) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_TESTHELPERS_H, TestHookReplaceCreateSend,
    TP_ARGS(
        unsigned short, arg2,
        unsigned short, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned short, arg2, arg2)
        ctf_integer(unsigned short, arg3, arg3)
    )
)
