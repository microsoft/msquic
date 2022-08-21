#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONGESTION_CONTROL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "congestion_control.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONGESTION_CONTROL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONGESTION_CONTROL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "congestion_control.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for InvalidCongestionControlAlgorithm
// [conn][%p] Unknown congestion control algorithm: %hu, fallback to Cubic
// QuicTraceLogConnWarning(
            InvalidCongestionControlAlgorithm,
            QuicCongestionControlGetConnection(Cc),
            "Unknown congestion control algorithm: %hu, fallback to Cubic",
            Settings->CongestionControlAlgorithm);
// arg1 = arg1 = QuicCongestionControlGetConnection(Cc) = arg1
// arg3 = arg3 = Settings->CongestionControlAlgorithm = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_InvalidCongestionControlAlgorithm
#define _clog_4_ARGS_TRACE_InvalidCongestionControlAlgorithm(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONGESTION_CONTROL_C, InvalidCongestionControlAlgorithm , arg1, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_congestion_control.c.clog.h.c"
#endif
