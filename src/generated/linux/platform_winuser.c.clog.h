#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PLATFORM_WINUSER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "platform_winuser.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PLATFORM_WINUSER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PLATFORM_WINUSER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "platform_winuser.c.clog.h.lttng.h"
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
// Decoder Ring for WindowsUserLoaded
// [ dll] Loaded
// QuicTraceLogInfo(
        WindowsUserLoaded,
        "[ dll] Loaded");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_WindowsUserLoaded
#define _clog_2_ARGS_TRACE_WindowsUserLoaded(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserLoaded );\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsUserUnloaded
// [ dll] Unloaded
// QuicTraceLogInfo(
        WindowsUserUnloaded,
        "[ dll] Unloaded");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_WindowsUserUnloaded
#define _clog_2_ARGS_TRACE_WindowsUserUnloaded(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserUnloaded );\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsUserProcessorState
// [ dll] Processors:%u, Groups:%u, NUMA Nodes:%u
// QuicTraceLogInfo(
        WindowsUserProcessorState,
        "[ dll] Processors:%u, Groups:%u, NUMA Nodes:%u",
        ActiveProcessorCount, ProcessorGroupCount, NumaNodeCount);
// arg2 = arg2 = ActiveProcessorCount = arg2
// arg3 = arg3 = ProcessorGroupCount = arg3
// arg4 = arg4 = NumaNodeCount = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_WindowsUserProcessorState
#define _clog_5_ARGS_TRACE_WindowsUserProcessorState(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserProcessorState , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ProcessorInfo
// [ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]
// QuicTraceLogInfo(
                        ProcessorInfo,
                        "[ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]",
                        Index,
                        CxPlatProcessorInfo[Index].Group,
                        CxPlatProcessorInfo[Index].Index,
                        CxPlatProcessorInfo[Index].NumaNode);
// arg2 = arg2 = Index = arg2
// arg3 = arg3 = CxPlatProcessorInfo[Index].Group = arg3
// arg4 = arg4 = CxPlatProcessorInfo[Index].Index = arg4
// arg5 = arg5 = CxPlatProcessorInfo[Index].NumaNode = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ProcessorInfo
#define _clog_6_ARGS_TRACE_ProcessorInfo(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_PLATFORM_WINUSER_C, ProcessorInfo , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsUserInitialized2
// [ dll] Initialized (AvailMem = %llu bytes, TimerResolution = [%u, %u])
// QuicTraceLogInfo(
        WindowsUserInitialized2,
        "[ dll] Initialized (AvailMem = %llu bytes, TimerResolution = [%u, %u])",
        CxPlatTotalMemory,
        CxPlatTimerCapabilities.wPeriodMin,
        CxPlatTimerCapabilities.wPeriodMax);
// arg2 = arg2 = CxPlatTotalMemory = arg2
// arg3 = arg3 = CxPlatTimerCapabilities.wPeriodMin = arg3
// arg4 = arg4 = CxPlatTimerCapabilities.wPeriodMax = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_WindowsUserInitialized2
#define _clog_5_ARGS_TRACE_WindowsUserInitialized2(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserInitialized2 , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsUserInitialized
// [ dll] Initialized (AvailMem = %llu bytes)
// QuicTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        CxPlatTotalMemory);
// arg2 = arg2 = CxPlatTotalMemory = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_WindowsUserInitialized
#define _clog_3_ARGS_TRACE_WindowsUserInitialized(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserInitialized , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for WindowsUserUninitialized
// [ dll] Uninitialized
// QuicTraceLogInfo(
        WindowsUserUninitialized,
        "[ dll] Uninitialized");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_WindowsUserUninitialized
#define _clog_2_ARGS_TRACE_WindowsUserUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserUninitialized );\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CxPlatProcessorInfo",
            ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO));
// arg2 = arg2 = "CxPlatProcessorInfo" = arg2
// arg3 = arg3 = ActiveProcessorCount * sizeof(CXPLAT_PROCESSOR_INFO) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WINUSER_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group count");
// arg2 = arg2 = "Failed to determine processor group count" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_WINUSER_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GlobalMemoryStatusEx failed");
// arg2 = arg2 = Error = arg2
// arg3 = arg3 = "GlobalMemoryStatusEx failed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WINUSER_C, LibraryErrorStatus , arg2, arg3);\

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
tracepoint(CLOG_PLATFORM_WINUSER_C, LibraryAssert , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_platform_winuser.c.clog.h.c"
#endif
