#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PLATFORM_WINKERNEL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "platform_winkernel.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PLATFORM_WINKERNEL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PLATFORM_WINKERNEL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "platform_winkernel.c.clog.h.lttng.h"
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
/*----------------------------------------------------------
// Decoder Ring for WindowsKernelLoaded
// [ sys] Loaded
// QuicTraceLogInfo(
        WindowsKernelLoaded,
        "[ sys] Loaded");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_WindowsKernelLoaded
#define _clog_2_ARGS_TRACE_WindowsKernelLoaded(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelLoaded );\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsKernelUnloaded
// [ sys] Unloaded
// QuicTraceLogInfo(
        WindowsKernelUnloaded,
        "[ sys] Unloaded");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_WindowsKernelUnloaded
#define _clog_2_ARGS_TRACE_WindowsKernelUnloaded(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelUnloaded );\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsKernelInitialized
// [ sys] Initialized (PageSize = %u bytes; AvailMem = %llu bytes)
// QuicTraceLogInfo(
        WindowsKernelInitialized,
        "[ sys] Initialized (PageSize = %u bytes; AvailMem = %llu bytes)",
        Sbi.PageSize,
        CxPlatTotalMemory);
// arg2 = arg2 = Sbi.PageSize = arg2
// arg3 = arg3 = CxPlatTotalMemory = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_WindowsKernelInitialized
#define _clog_4_ARGS_TRACE_WindowsKernelInitialized(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelInitialized , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsKernelUninitialized
// [ sys] Uninitialized
// QuicTraceLogInfo(
        WindowsKernelUninitialized,
        "[ sys] Uninitialized");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_WindowsKernelUninitialized
#define _clog_2_ARGS_TRACE_WindowsKernelUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINKERNEL_C, WindowsKernelUninitialized );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptOpenAlgorithmProvider (RNG)");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "BCryptOpenAlgorithmProvider (RNG)" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WINKERNEL_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryAssert
// [ lib] ASSERT, %u:%s - %s.
// QuicTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
// arg2 = arg2 = (uint32_t)Line = arg2
// arg3 = arg3 = File = arg3
// arg4 = arg4 = Expr = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_LibraryAssert
#define _clog_5_ARGS_TRACE_LibraryAssert(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PLATFORM_WINKERNEL_C, LibraryAssert , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_platform_winkernel.c.clog.h.c"
#endif
