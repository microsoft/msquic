#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_INTEROP_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "interop.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_INTEROP_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_INTEROP_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "interop.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_5_ARGS_TRACE_InteropTestStart



/*----------------------------------------------------------
// Decoder Ring for InteropTestStart
// [ntrp] Test Start, Server: %s, Port: %hu, Tests: 0x%x.
// QuicTraceLogInfo(
        InteropTestStart,
        "[ntrp] Test Start, Server: %s, Port: %hu, Tests: 0x%x.",
        PublicEndpoints[EndpointIndex].ServerName,
        TestContext->Port,
        (uint32_t)TestContext->Feature);
// arg2 = arg2 = PublicEndpoints[EndpointIndex].ServerName
// arg3 = arg3 = TestContext->Port
// arg4 = arg4 = (uint32_t)TestContext->Feature
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_InteropTestStart(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_INTEROP_CPP, InteropTestStart , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_InteropTestStop



/*----------------------------------------------------------
// Decoder Ring for InteropTestStop
// [ntrp] Test Stop, Server: %s, Port: %hu, Tests: 0x%x, Negotiated Alpn: %s, Passed: %s.
// QuicTraceLogInfo(
        InteropTestStop,
        "[ntrp] Test Stop, Server: %s, Port: %hu, Tests: 0x%x, Negotiated Alpn: %s, Passed: %s.",
        PublicEndpoints[EndpointIndex].ServerName,
        TestContext->Port,
        (uint32_t)TestContext->Feature,
        Alpn,
        ThisTestFailed ? "false" : "true");
// arg2 = arg2 = PublicEndpoints[EndpointIndex].ServerName
// arg3 = arg3 = TestContext->Port
// arg4 = arg4 = (uint32_t)TestContext->Feature
// arg5 = arg5 = Alpn
// arg6 = arg6 = ThisTestFailed ? "false" : "true"
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_InteropTestStop(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_INTEROP_CPP, InteropTestStop , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_interop.cpp.clog.h.c"
#endif
