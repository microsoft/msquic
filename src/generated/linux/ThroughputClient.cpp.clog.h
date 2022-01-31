#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_THROUGHPUTCLIENT_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "ThroughputClient.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_THROUGHPUTCLIENT_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_THROUGHPUTCLIENT_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "ThroughputClient.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PerfRpsStart
// [perf] RPS Client start
// QuicTraceLogVerbose(
        PerfRpsStart,
        "[perf] RPS Client start");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfRpsStart
#define _clog_2_ARGS_TRACE_PerfRpsStart(uniqueId, encoded_arg_string)\
tracepoint(CLOG_THROUGHPUTCLIENT_CPP, PerfRpsStart );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfRpsTimeout
// [perf] RPS Client timeout
// QuicTraceLogVerbose(
                PerfRpsTimeout,
                "[perf] RPS Client timeout");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfRpsTimeout
#define _clog_2_ARGS_TRACE_PerfRpsTimeout(uniqueId, encoded_arg_string)\
tracepoint(CLOG_THROUGHPUTCLIENT_CPP, PerfRpsTimeout );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfRpsComplete
// [perf] RPS Client complete
// QuicTraceLogVerbose(
        PerfRpsComplete,
        "[perf] RPS Client complete");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfRpsComplete
#define _clog_2_ARGS_TRACE_PerfRpsComplete(uniqueId, encoded_arg_string)\
tracepoint(CLOG_THROUGHPUTCLIENT_CPP, PerfRpsComplete );\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_ThroughputClient.cpp.clog.h.c"
#endif
