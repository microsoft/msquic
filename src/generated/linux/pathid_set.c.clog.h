#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PATHID_SET_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "pathid_set.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PATHID_SET_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PATHID_SET_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "pathid_set.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PeerMaxPathIDUpdated
// [conn][%p] Peer updated max path id (%u).
// QuicTraceLogConnVerbose(
            PeerMaxPathIDUpdated,
            QuicPathIDSetGetConnection(PathIDSet),
            "Peer updated max path id (%u).",
            MaxPathID);
// arg1 = arg1 = QuicPathIDSetGetConnection(PathIDSet) = arg1
// arg3 = arg3 = MaxPathID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PeerMaxPathIDUpdated
#define _clog_4_ARGS_TRACE_PeerMaxPathIDUpdated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PATHID_SET_C, PeerMaxPathIDUpdated , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "pathid hash table",
                0);
// arg2 = arg2 = "pathid hash table" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_SET_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathIDRemove
// [conn][%p] Removed PathID %u
// QuicTraceEvent(
        ConnPathIDRemove,
        "[conn][%p] Removed PathID %u",
        Connection,
        PathID->ID);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPathIDRemove
#define _clog_4_ARGS_TRACE_ConnPathIDRemove(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_SET_C, ConnPathIDRemove , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    QuicPathIDSetGetConnection(PathIDSet),
                    "Failed to generate new path ID");
// arg2 = arg2 = QuicPathIDSetGetConnection(PathIDSet) = arg2
// arg3 = arg3 = "Failed to generate new path ID" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_SET_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPathIDAdd
// [conn][%p] Added New PathID %u
// QuicTraceEvent(
        ConnPathIDAdd,
        "[conn][%p] Added New PathID %u",
        QuicPathIDSetGetConnection(PathIDSet),
        PathID->ID);
// arg2 = arg2 = QuicPathIDSetGetConnection(PathIDSet) = arg2
// arg3 = arg3 = PathID->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPathIDAdd
#define _clog_4_ARGS_TRACE_ConnPathIDAdd(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PATHID_SET_C, ConnPathIDAdd , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_pathid_set.c.clog.h.c"
#endif
