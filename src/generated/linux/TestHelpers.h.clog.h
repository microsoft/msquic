#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TESTHELPERS_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "TestHelpers.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_TESTHELPERS_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TESTHELPERS_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "TestHelpers.h.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_3_ARGS_TRACE_TestScopeEntry



/*----------------------------------------------------------
// Decoder Ring for TestScopeEntry
// [test]---> %s
// QuicTraceLogInfo(
            TestScopeEntry,
            "[test]---> %s",
            Name);
// arg2 = arg2 = Name
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_TestScopeEntry(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TESTHELPERS_H, TestScopeEntry , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_TestScopeExit



/*----------------------------------------------------------
// Decoder Ring for TestScopeExit
// [test]<--- %s
// QuicTraceLogInfo(
            TestScopeExit,
            "[test]<--- %s",
            Name);
// arg2 = arg2 = Name
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_TestScopeExit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TESTHELPERS_H, TestScopeExit , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookRegister



/*----------------------------------------------------------
// Decoder Ring for TestHookRegister
// [test][hook] Registering
// QuicTraceLogInfo(
            TestHookRegister,
            "[test][hook] Registering");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookRegister(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookRegister );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookUnregistering



/*----------------------------------------------------------
// Decoder Ring for TestHookUnregistering
// [test][hook] Unregistering
// QuicTraceLogInfo(
            TestHookUnregistering,
            "[test][hook] Unregistering");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookUnregistering(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookUnregistering );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookUnregistered



/*----------------------------------------------------------
// Decoder Ring for TestHookUnregistered
// [test][hook] Unregistered
// QuicTraceLogInfo(
            TestHookUnregistered,
            "[test][hook] Unregistered");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookUnregistered(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookUnregistered );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookDropPacketRandom



/*----------------------------------------------------------
// Decoder Ring for TestHookDropPacketRandom
// [test][hook] Random packet drop
// QuicTraceLogVerbose(
                TestHookDropPacketRandom,
                "[test][hook] Random packet drop");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookDropPacketRandom(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookDropPacketRandom );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookDropPacketSelective



/*----------------------------------------------------------
// Decoder Ring for TestHookDropPacketSelective
// [test][hook] Selective packet drop
// QuicTraceLogVerbose(
            TestHookDropPacketSelective,
            "[test][hook] Selective packet drop");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookDropPacketSelective(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookDropPacketSelective );\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceAddrRecv



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrRecv
// [test][hook] Recv Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrRecv,
                "[test][hook] Recv Addr :%hu => :%hu",
                QuicAddrGetPort(&Original),
                QuicAddrGetPort(&New));
// arg2 = arg2 = QuicAddrGetPort(&Original)
// arg3 = arg3 = QuicAddrGetPort(&New)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceAddrRecv(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TESTHELPERS_H, TestHookReplaceAddrRecv , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceAddrSend



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrSend
// [test][hook] Send Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&New),
                QuicAddrGetPort(&Original));
// arg2 = arg2 = QuicAddrGetPort(&New)
// arg3 = arg3 = QuicAddrGetPort(&Original)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceAddrSend(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TESTHELPERS_H, TestHookReplaceAddrSend , arg2, arg3);\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookDropOldAddrSend



/*----------------------------------------------------------
// Decoder Ring for TestHookDropOldAddrSend
// [test][hook] Dropping send to old addr
// QuicTraceLogVerbose(
                TestHookDropOldAddrSend,
                "[test][hook] Dropping send to old addr");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookDropOldAddrSend(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookDropOldAddrSend );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookDropLimitAddrRecv



/*----------------------------------------------------------
// Decoder Ring for TestHookDropLimitAddrRecv
// [test][hook] Dropping recv over limit to new addr
// QuicTraceLogVerbose(
                    TestHookDropLimitAddrRecv,
                    "[test][hook] Dropping recv over limit to new addr");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookDropLimitAddrRecv(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookDropLimitAddrRecv );\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceAddrRecv



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrRecv
// [test][hook] Recv Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrRecv,
                "[test][hook] Recv Addr :%hu => :%hu",
                QuicAddrGetPort(&Original),
                QuicAddrGetPort(&New));
// arg2 = arg2 = QuicAddrGetPort(&Original)
// arg3 = arg3 = QuicAddrGetPort(&New)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceAddrRecv(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookDropLimitAddrSend



/*----------------------------------------------------------
// Decoder Ring for TestHookDropLimitAddrSend
// [test][hook] Dropping send over limit to new addr
// QuicTraceLogVerbose(
                    TestHookDropLimitAddrSend,
                    "[test][hook] Dropping send over limit to new addr");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookDropLimitAddrSend(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTHELPERS_H, TestHookDropLimitAddrSend );\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceAddrSend



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrSend
// [test][hook] Send Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&New),
                QuicAddrGetPort(&Original));
// arg2 = arg2 = QuicAddrGetPort(&New)
// arg3 = arg3 = QuicAddrGetPort(&Original)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceAddrSend(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_2_ARGS_TRACE_TestHookDropOldAddrSend



/*----------------------------------------------------------
// Decoder Ring for TestHookDropOldAddrSend
// [test][hook] Dropping send to old addr
// QuicTraceLogVerbose(
                TestHookDropOldAddrSend,
                "[test][hook] Dropping send to old addr");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestHookDropOldAddrSend(uniqueId, encoded_arg_string)\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceCreateSend



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceCreateSend
// [test][hook] Create (remote) Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceCreateSend,
                "[test][hook] Create (remote) Addr :%hu => :%hu",
                QuicAddrGetPort(&PublicAddress),
                QuicAddrGetPort(RemoteAddress));
// arg2 = arg2 = QuicAddrGetPort(&PublicAddress)
// arg3 = arg3 = QuicAddrGetPort(RemoteAddress)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceCreateSend(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TESTHELPERS_H, TestHookReplaceCreateSend , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceAddrRecv



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrRecv
// [test][hook] Recv Addr :%hu => :%hu
// QuicTraceLogVerbose(
                    TestHookReplaceAddrRecv,
                    "[test][hook] Recv Addr :%hu => :%hu",
                    QuicAddrGetPort(&PrivateAddresses[i]),
                    QuicAddrGetPort(&PublicAddress));
// arg2 = arg2 = QuicAddrGetPort(&PrivateAddresses[i])
// arg3 = arg3 = QuicAddrGetPort(&PublicAddress)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceAddrRecv(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TestHookReplaceAddrSend



/*----------------------------------------------------------
// Decoder Ring for TestHookReplaceAddrSend
// [test][hook] Send Addr :%hu => :%hu
// QuicTraceLogVerbose(
                TestHookReplaceAddrSend,
                "[test][hook] Send Addr :%hu => :%hu",
                QuicAddrGetPort(&PublicAddress),
                QuicAddrGetPort(RemoteAddress));
// arg2 = arg2 = QuicAddrGetPort(&PublicAddress)
// arg3 = arg3 = QuicAddrGetPort(RemoteAddress)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestHookReplaceAddrSend(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_TestHelpers.h.clog.h.c"
#endif

