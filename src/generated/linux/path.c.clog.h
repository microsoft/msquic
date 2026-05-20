#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PATH_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "path.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PATH_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PATH_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "path.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PathActiveFallback
// [conn][%p] Path[%hhu] removed; falling back to Path[%hhu]
// QuicTraceLogConnInfo(
            PathActiveFallback,
            Connection,
            "Path[%hhu] removed; falling back to Path[%hhu]",
            Path->ID,
            Connection->Paths[FallbackIndex].ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Connection->Paths[FallbackIndex].ID = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathActiveFallback
#define _clog_5_ARGS_TRACE_PathActiveFallback(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_PATH_C, PathActiveFallback , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathQeoEnabled
// [conn][%p] Path[%hhu] QEO enabled
// QuicTraceLogConnInfo(
                PathQeoEnabled,
                Connection,
                "Path[%hhu] QEO enabled",
                Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathQeoEnabled
#define _clog_4_ARGS_TRACE_PathQeoEnabled(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PATH_C, PathQeoEnabled , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathQeoDisabled
// [conn][%p] Path[%hhu] QEO disabled
// QuicTraceLogConnInfo(
            PathQeoDisabled,
            Connection,
            "Path[%hhu] QEO disabled",
            Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathQeoDisabled
#define _clog_4_ARGS_TRACE_PathQeoDisabled(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PATH_C, PathQeoDisabled , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathInitialized
// [conn][%p] Path[%hhu] Initialized
// QuicTraceEvent(
        ConnPathInitialized,
        "[conn][%p] Path[%hhu] Initialized",
        Connection,
        Path->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPathInitialized
#define _clog_4_ARGS_TRACE_ConnPathInitialized(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATH_C, ConnPathInitialized , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathRemoved
// [conn][%p] Path[%hhu] Removed
// QuicTraceEvent(
        ConnPathRemoved,
        "[conn][%p] Path[%hhu] Removed",
        Connection,
        Path->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPathRemoved
#define _clog_4_ARGS_TRACE_ConnPathRemoved(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATH_C, ConnPathRemoved , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathValidated
// [conn][%p] Path[%hhu] Validated (%hhu)
// QuicTraceEvent(
        ConnPathValidated,
        "[conn][%p] Path[%hhu] Validated (%hhu)",
        Connection,
        Path->ID,
        Reason);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Reason = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnPathValidated
#define _clog_5_ARGS_TRACE_ConnPathValidated(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PATH_C, ConnPathValidated , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathActive
// [conn][%p] Path[%hhu] Set active (rebind=%hhu)
// QuicTraceEvent(
        ConnPathActive,
        "[conn][%p] Path[%hhu] Set active (rebind=%hhu)",
        Connection,
        Connection->Paths[0].ID,
        UdpPortChangeOnly);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Paths[0].ID = arg3
// arg4 = arg4 = UdpPortChangeOnly = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnPathActive
#define _clog_5_ARGS_TRACE_ConnPathActive(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PATH_C, ConnPathActive , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_path.c.clog.h.c"
#endif
