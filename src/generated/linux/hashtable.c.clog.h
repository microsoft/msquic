#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_HASHTABLE_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "hashtable.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_HASHTABLE_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_HASHTABLE_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "hashtable.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "QUIC_HASHTABLE",
                sizeof(QUIC_HASHTABLE));
// arg2 = arg2 = "QUIC_HASHTABLE"
// arg3 = arg3 = sizeof(QUIC_HASHTABLE)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_HASHTABLE_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "second level dir (0)",
                QuicComputeSecondLevelDirSize(0) * sizeof(QUIC_LIST_ENTRY));
// arg2 = arg2 = "second level dir (0)"
// arg3 = arg3 = QuicComputeSecondLevelDirSize(0) * sizeof(QUIC_LIST_ENTRY)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "second level dir (i)",
                    QuicComputeSecondLevelDirSize(i) * sizeof(QUIC_LIST_ENTRY));
// arg2 = arg2 = "second level dir (i)"
// arg3 = arg3 = QuicComputeSecondLevelDirSize(i) * sizeof(QUIC_LIST_ENTRY)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_hashtable.c.clog.h.c"
#endif
