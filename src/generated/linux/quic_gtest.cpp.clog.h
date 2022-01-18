#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_QUIC_GTEST_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "quic_gtest.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_QUIC_GTEST_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_QUIC_GTEST_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "quic_gtest.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogError
#define _clog_MACRO_QuicTraceLogError  1
#define QuicTraceLogError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for TestCaseStart
// [test] START %s
// QuicTraceLogInfo(
            TestCaseStart,
            "[test] START %s",
            TestName);
// arg2 = arg2 = TestName = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TestCaseStart
#define _clog_3_ARGS_TRACE_TestCaseStart(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_QUIC_GTEST_CPP, TestCaseStart , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TestCaseEnd
// [test] END %s
// QuicTraceLogInfo(
            TestCaseEnd,
            "[test] END %s",
            TestName);
// arg2 = arg2 = TestName = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TestCaseEnd
#define _clog_3_ARGS_TRACE_TestCaseEnd(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_QUIC_GTEST_CPP, TestCaseEnd , arg2);\

#endif




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
#ifndef _clog_4_ARGS_TRACE_TestCaseTStart
#define _clog_4_ARGS_TRACE_TestCaseTStart(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_QUIC_GTEST_CPP, TestCaseTStart , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TestCaseTEnd
// [test] END %s
// QuicTraceLogInfo(
            TestCaseTEnd,
            "[test] END %s",
            TestName);
// arg2 = arg2 = TestName = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TestCaseTEnd
#define _clog_3_ARGS_TRACE_TestCaseTEnd(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_QUIC_GTEST_CPP, TestCaseTEnd , arg2);\

#endif




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
#ifndef _clog_5_ARGS_TRACE_TestLogFailure
#define _clog_5_ARGS_TRACE_TestLogFailure(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_QUIC_GTEST_CPP, TestLogFailure , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_quic_gtest.cpp.clog.h.c"
#endif
