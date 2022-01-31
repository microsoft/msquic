#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_SEND_BUFFER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "send_buffer.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_SEND_BUFFER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_SEND_BUFFER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "send_buffer.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogStreamVerbose
#define _clog_MACRO_QuicTraceLogStreamVerbose  1
#define QuicTraceLogStreamVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for IndicateIdealSendBuffer
// [strm][%p] Indicating QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = %llu
// QuicTraceLogStreamVerbose(
            IndicateIdealSendBuffer,
            Stream,
            "Indicating QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = %llu",
            Event.IDEAL_SEND_BUFFER_SIZE.ByteCount);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Event.IDEAL_SEND_BUFFER_SIZE.ByteCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicateIdealSendBuffer
#define _clog_4_ARGS_TRACE_IndicateIdealSendBuffer(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_BUFFER_C, IndicateIdealSendBuffer , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "sendbuffer",
            Size);
// arg2 = arg2 = "sendbuffer" = arg2
// arg3 = arg3 = Size = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SEND_BUFFER_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_send_buffer.c.clog.h.c"
#endif
