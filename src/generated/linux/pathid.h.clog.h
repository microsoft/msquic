#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PATHID_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "pathid.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_PATHID_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PATHID_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "pathid.h.clog.h.lttng.h"
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
// Decoder Ring for ConnSourceCidRemoved
// [conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!
// QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!",
                    PathID->Connection,
                    PathID->ID,
                    SourceCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = SourceCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg5
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnSourceCidRemoved
#define _clog_7_ARGS_TRACE_ConnSourceCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len)\
tracepoint(CLOG_PATHID_H, ConnSourceCidRemoved , arg2, arg3, arg4, arg5_len, arg5);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_pathid.h.clog.h.c"
#endif
