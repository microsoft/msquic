#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_STORAGE_WINUSER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "storage_winuser.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_STORAGE_WINUSER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_STORAGE_WINUSER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "storage_winuser.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_3_ARGS_TRACE_StorageOpenKey



/*----------------------------------------------------------
// Decoder Ring for StorageOpenKey
// [ reg] Opening %s
// QuicTraceLogVerbose(
        StorageOpenKey,
        "[ reg] Opening %s",
        FullKeyName);
// arg2 = arg2 = FullKeyName
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StorageOpenKey(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_STORAGE_WINUSER_C, StorageOpenKey , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_storage_winuser.c.clog.h.c"
#endif
