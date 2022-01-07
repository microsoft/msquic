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
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PathInitialized
// [conn][%p] Path[%hhu] Initialized
// QuicTraceLogConnInfo(
        PathInitialized,
        Connection,
        "Path[%hhu] Initialized",
        Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathInitialized
#define _clog_4_ARGS_TRACE_PathInitialized(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PATH_C, PathInitialized , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathRemoved
// [conn][%p] Path[%hhu] Removed
// QuicTraceLogConnInfo(
        PathRemoved,
        Connection,
        "Path[%hhu] Removed",
        Path->ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathRemoved
#define _clog_4_ARGS_TRACE_PathRemoved(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PATH_C, PathRemoved , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathValidated
// [conn][%p] Path[%hhu] Validated (%s)
// QuicTraceLogConnInfo(
        PathValidated,
        Connection,
        "Path[%hhu] Validated (%s)",
        Path->ID,
        ReasonStrings[Reason]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = ReasonStrings[Reason] = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathValidated
#define _clog_5_ARGS_TRACE_PathValidated(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_PATH_C, PathValidated , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathActive
// [conn][%p] Path[%hhu] Set active (rebind=%hhu)
// QuicTraceLogConnInfo(
        PathActive,
        Connection,
        "Path[%hhu] Set active (rebind=%hhu)",
        Connection->Paths[0].ID,
        UdpPortChangeOnly);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Paths[0].ID = arg3
// arg4 = arg4 = UdpPortChangeOnly = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathActive
#define _clog_5_ARGS_TRACE_PathActive(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_PATH_C, PathActive , arg1, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_path.c.clog.h.c"
#endif
