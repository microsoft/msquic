#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_RAW_SOCKET_LINUX_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_raw_socket_linux.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_RAW_SOCKET_LINUX_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_RAW_SOCKET_LINUX_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_raw_socket_linux.c.clog.h.lttng.h"
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
// Decoder Ring for DatapathGetRouteStart
// [data][%p] Querying route, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathGetRouteStart,
        "[data][%p] Querying route, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg4
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_DatapathGetRouteStart
#define _clog_7_ARGS_TRACE_DatapathGetRouteStart(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_RAW_SOCKET_LINUX_C, DatapathGetRouteStart , arg2, arg3_len, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "ResolveBestL3Route");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "ResolveBestL3Route" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_RAW_SOCKET_LINUX_C, DatapathErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathResoveShow
// [data][%p] Route resolution completed, local=%!ADDR!, remote=%!ADDR!, nexthop=%!ADDR!, iface=%d
// QuicTraceEvent(
        DatapathResoveShow,
        "[data][%p] Route resolution completed, local=%!ADDR!, remote=%!ADDR!, nexthop=%!ADDR!, iface=%d",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(NextHop), &NextHop),
        oif);
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(NextHop), &NextHop) = arg5
// arg6 = arg6 = oif = arg6
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_DatapathResoveShow
#define _clog_10_ARGS_TRACE_DatapathResoveShow(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len, arg5, arg5_len, arg6)\
tracepoint(CLOG_DATAPATH_RAW_SOCKET_LINUX_C, DatapathResoveShow , arg2, arg3_len, arg3, arg4_len, arg4, arg5_len, arg5, arg6);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_socket_linux.c.clog.h.c"
#endif
