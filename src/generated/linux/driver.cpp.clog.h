#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DRIVER_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "driver.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_DRIVER_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DRIVER_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "driver.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_2_ARGS_TRACE_TestDriverStarted



/*----------------------------------------------------------
// Decoder Ring for TestDriverStarted
// [test] Started
// QuicTraceLogInfo(
        TestDriverStarted,
        "[test] Started");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestDriverStarted(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRIVER_CPP, TestDriverStarted );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestDriverStopped



/*----------------------------------------------------------
// Decoder Ring for TestDriverStopped
// [test] Stopped
// QuicTraceLogInfo(
        TestDriverStopped,
        "[test] Stopped");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestDriverStopped(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRIVER_CPP, TestDriverStopped );\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicPlatformInitialize failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "QuicPlatformInitialize failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DRIVER_CPP, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDriverCreate failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "WdfDriverCreate failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicTestCtlInitialize failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "QuicTestCtlInitialize failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_driver.cpp.clog.h.c"
#endif
