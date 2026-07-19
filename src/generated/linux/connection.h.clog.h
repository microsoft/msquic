#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONNECTION_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "connection.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONNECTION_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONNECTION_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "connection.h.clog.h.lttng.h"
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
// Decoder Ring for ConnOutFlowStreamStats
// [conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu
// QuicTraceEvent(
        ConnOutFlowStreamStats,
        "[conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu",
        Connection,
        FcAvailable,
        SendWindow);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = FcAvailable = arg3
// arg4 = arg4 = SendWindow = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnOutFlowStreamStats
#define _clog_5_ARGS_TRACE_ConnOutFlowStreamStats(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_H, ConnOutFlowStreamStats , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnInFlowStats
// [conn][%p] IN: BytesRecv=%llu
// QuicTraceEvent(
        ConnInFlowStats,
        "[conn][%p] IN: BytesRecv=%llu",
        Connection,
        Connection->Stats.Recv.TotalBytes);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Recv.TotalBytes = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnInFlowStats
#define _clog_4_ARGS_TRACE_ConnInFlowStats(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_H, ConnInFlowStats , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowBlocked
// [conn][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            ConnOutFlowBlocked,
            "[conn][%p] Send Blocked Flags: %hhu",
            Connection,
            Connection->OutFlowBlockedReasons);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->OutFlowBlockedReasons = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnOutFlowBlocked
#define _clog_4_ARGS_TRACE_ConnOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_H, ConnOutFlowBlocked , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_connection.h.clog.h.c"
#endif
