#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_RAW_DPDK_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_raw_dpdk.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_RAW_DPDK_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_RAW_DPDK_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_raw_dpdk.c.clog.h.lttng.h"
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
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatThreadCreate" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_DPDK_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No room in DPDK TX ring buffer");
// arg2 = arg2 = "No room in DPDK TX ring buffer" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_DPDK_C, LibraryError , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_dpdk.c.clog.h.c"
#endif
