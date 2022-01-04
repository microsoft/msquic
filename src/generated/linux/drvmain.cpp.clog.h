#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DRVMAIN_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "drvmain.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_DRVMAIN_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DRVMAIN_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "drvmain.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogWarning
#define _clog_MACRO_QuicTraceLogWarning  1
#define QuicTraceLogWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PerfControlClientCanceledRequest
// [perf] Client %p canceled request %p
// QuicTraceLogWarning(
        PerfControlClientCanceledRequest,
        "[perf] Client %p canceled request %p",
        Client,
        Request);
// arg2 = arg2 = Client = arg2
// arg3 = arg3 = Request = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfControlClientCanceledRequest
#define _clog_4_ARGS_TRACE_PerfControlClientCanceledRequest(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlClientCanceledRequest , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfDriverStarted
// [perf] Started
// QuicTraceLogInfo(
        PerfDriverStarted,
        "[perf] Started");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfDriverStarted
#define _clog_2_ARGS_TRACE_PerfDriverStarted(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRVMAIN_CPP, PerfDriverStarted );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfDriverStopped
// [perf] Stopped
// QuicTraceLogInfo(
        PerfDriverStopped,
        "[perf] Stopped");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfDriverStopped
#define _clog_2_ARGS_TRACE_PerfDriverStopped(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRVMAIN_CPP, PerfDriverStopped );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlClientCreated
// [perf] Client %p created
// QuicTraceLogInfo(
            PerfControlClientCreated,
            "[perf] Client %p created",
            Client);
// arg2 = arg2 = Client = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfControlClientCreated
#define _clog_3_ARGS_TRACE_PerfControlClientCreated(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlClientCreated , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlClientCleaningUp
// [perf] Client %p cleaning up
// QuicTraceLogInfo(
            PerfControlClientCleaningUp,
            "[perf] Client %p cleaning up",
            Client);
// arg2 = arg2 = Client = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfControlClientCleaningUp
#define _clog_3_ARGS_TRACE_PerfControlClientCleaningUp(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlClientCleaningUp , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerformanceStopCancelled
// [perf] Performance Stop Cancelled
// QuicTraceLogInfo(
            PerformanceStopCancelled,
            "[perf] Performance Stop Cancelled");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerformanceStopCancelled
#define _clog_2_ARGS_TRACE_PerformanceStopCancelled(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRVMAIN_CPP, PerformanceStopCancelled );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PrintBufferReturn
// [perf] Print Buffer %d %s\n
// QuicTraceLogInfo(
        PrintBufferReturn,
        "[perf] Print Buffer %d %s\n",
        BufferCurrent,
        LocalBuffer);
// arg2 = arg2 = BufferCurrent = arg2
// arg3 = arg3 = LocalBuffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PrintBufferReturn
#define _clog_4_ARGS_TRACE_PrintBufferReturn(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DRVMAIN_CPP, PrintBufferReturn , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlClientIoctl
// [perf] Client %p executing write IOCTL %u
// QuicTraceLogInfo(
        PerfControlClientIoctl,
        "[perf] Client %p executing write IOCTL %u",
        Client,
        FunctionCode);
// arg2 = arg2 = Client = arg2
// arg3 = arg3 = FunctionCode = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfControlClientIoctl
#define _clog_4_ARGS_TRACE_PerfControlClientIoctl(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlClientIoctl , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlClientIoctlComplete
// [perf] Client %p completing request, 0x%x
// QuicTraceLogInfo(
        PerfControlClientIoctlComplete,
        "[perf] Client %p completing request, 0x%x",
        Client,
        Status);
// arg2 = arg2 = Client = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfControlClientIoctlComplete
#define _clog_4_ARGS_TRACE_PerfControlClientIoctlComplete(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlClientIoctlComplete , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlInitialized
// [perf] Control interface initialized
// QuicTraceLogVerbose(
        PerfControlInitialized,
        "[perf] Control interface initialized");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfControlInitialized
#define _clog_2_ARGS_TRACE_PerfControlInitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlInitialized );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlUninitializing
// [perf] Control interface uninitializing
// QuicTraceLogVerbose(
        PerfControlUninitializing,
        "[perf] Control interface uninitializing");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfControlUninitializing
#define _clog_2_ARGS_TRACE_PerfControlUninitializing(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlUninitializing );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfControlUninitialized
// [perf] Control interface uninitialized
// QuicTraceLogVerbose(
        PerfControlUninitialized,
        "[perf] Control interface uninitialized");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PerfControlUninitialized
#define _clog_2_ARGS_TRACE_PerfControlUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DRVMAIN_CPP, PerfControlUninitialized );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatInitialize failed");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatInitialize failed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DRVMAIN_CPP, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfControlDeviceInitAllocate failed");
// arg2 = arg2 = "WdfControlDeviceInitAllocate failed" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DRVMAIN_CPP, LibraryError , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_drvmain.cpp.clog.h.c"
#endif
