#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_STREAM_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "stream.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_STREAM_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_STREAM_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "stream.h.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for StreamOutFlowBlocked
// [strm][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            StreamOutFlowBlocked,
            "[strm][%p] Send Blocked Flags: %hhu",
            Stream,
            Stream->OutFlowBlockedReasons);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Stream->OutFlowBlockedReasons = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StreamOutFlowBlocked
#define _clog_4_ARGS_TRACE_StreamOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_H, StreamOutFlowBlocked , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_stream.h.clog.h.c"
#endif
