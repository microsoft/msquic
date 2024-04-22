#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_XPLAT_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_xplat.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_XPLAT_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_XPLAT_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_xplat.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for DatapathInitFail
// [  dp] Failed to initialize datapath, status:%d
// QuicTraceLogVerbose(
            DatapathInitFail,
            "[  dp] Failed to initialize datapath, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathInitFail
#define _clog_3_ARGS_TRACE_DatapathInitFail(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_XPLAT_C, DatapathInitFail , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RawDatapathInitFail
// [ raw] Failed to initialize raw datapath, status:%d
// QuicTraceLogVerbose(
                RawDatapathInitFail,
                "[ raw] Failed to initialize raw datapath, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RawDatapathInitFail
#define _clog_3_ARGS_TRACE_RawDatapathInitFail(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_XPLAT_C, RawDatapathInitFail , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SockCreateFail
// [sock] Failed to create socket, status:%d
// QuicTraceLogVerbose(
            SockCreateFail,
            "[sock] Failed to create socket, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SockCreateFail
#define _clog_3_ARGS_TRACE_SockCreateFail(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_XPLAT_C, SockCreateFail , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RawSockCreateFail
// [sock] Failed to create raw socket, status:%d
// QuicTraceLogVerbose(
                RawSockCreateFail,
                "[sock] Failed to create raw socket, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RawSockCreateFail
#define _clog_3_ARGS_TRACE_RawSockCreateFail(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_XPLAT_C, RawSockCreateFail , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_xplat.c.clog.h.c"
#endif
