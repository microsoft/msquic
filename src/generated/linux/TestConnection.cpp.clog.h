#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TESTCONNECTION_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "TestConnection.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_TESTCONNECTION_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TESTCONNECTION_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "TestConnection.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for TestIgnoreConnectionTimeout
// [test] Ignoring timeout unexpected status because of random loss
// QuicTraceLogInfo(
                    TestIgnoreConnectionTimeout,
                    "[test] Ignoring timeout unexpected status because of random loss");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_TestIgnoreConnectionTimeout
#define _clog_2_ARGS_TRACE_TestIgnoreConnectionTimeout(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TESTCONNECTION_CPP, TestIgnoreConnectionTimeout );\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_TestConnection.cpp.clog.h.c"
#endif
