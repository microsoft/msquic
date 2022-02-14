#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PLATFORM_WORKER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "platform_worker.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PLATFORM_WORKER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PLATFORM_WORKER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "platform_worker.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PlatformWorkerThreadStart
// [ lib][%p] Worker start
// QuicTraceLogInfo(
        PlatformWorkerThreadStart,
        "[ lib][%p] Worker start",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PlatformWorkerThreadStart
#define _clog_3_ARGS_TRACE_PlatformWorkerThreadStart(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_WORKER_C, PlatformWorkerThreadStart , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PlatformWorkerThreadStop
// [ lib][%p] Worker stop
// QuicTraceLogInfo(
        PlatformWorkerThreadStop,
        "[ lib][%p] Worker stop",
        Worker);
// arg2 = arg2 = Worker = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PlatformWorkerThreadStop
#define _clog_3_ARGS_TRACE_PlatformWorkerThreadStop(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_WORKER_C, PlatformWorkerThreadStop , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_WORKER",
            WorkersSize);
// arg2 = arg2 = "CXPLAT_WORKER" = arg2
// arg3 = arg3 = WorkersSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WORKER_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_platform_worker.c.clog.h.c"
#endif
