#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_OPERATION_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "operation.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_OPERATION_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_OPERATION_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "operation.h.clog.h.lttng.h"
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
// Decoder Ring for ConnExecApiOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecApiOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->API_CALL.Context->Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Oper->API_CALL.Context->Type = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnExecApiOper
#define _clog_4_ARGS_TRACE_ConnExecApiOper(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_OPERATION_H, ConnExecApiOper , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnExecTimerOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->TIMER_EXPIRED.Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Oper->TIMER_EXPIRED.Type = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnExecTimerOper
#define _clog_4_ARGS_TRACE_ConnExecTimerOper(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_OPERATION_H, ConnExecTimerOper , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnExecOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecOper,
                "[conn][%p] Execute: %u",
                Connection,
                Oper->Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Oper->Type = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnExecOper
#define _clog_4_ARGS_TRACE_ConnExecOper(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_OPERATION_H, ConnExecOper , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_operation.h.clog.h.c"
#endif
