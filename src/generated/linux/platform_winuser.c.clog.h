#include <clog.h>
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
#ifndef _clog_2_ARGS_TRACE_WindowsUserLoaded



/*----------------------------------------------------------
// Decoder Ring for WindowsUserLoaded
// [ dll] Loaded
// QuicTraceLogInfo(
        WindowsUserLoaded,
        "[ dll] Loaded");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_WindowsUserLoaded(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserLoaded );\

#endif




#ifndef _clog_2_ARGS_TRACE_WindowsUserUnloaded



/*----------------------------------------------------------
// Decoder Ring for WindowsUserUnloaded
// [ dll] Unloaded
// QuicTraceLogInfo(
        WindowsUserUnloaded,
        "[ dll] Unloaded");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_WindowsUserUnloaded(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserUnloaded );\

#endif




#ifndef _clog_5_ARGS_TRACE_WindowsUserProcessorState



/*----------------------------------------------------------
// Decoder Ring for WindowsUserProcessorState
// [ dll] Processors:%u, Groups:%u, NUMA Nodes:%u
// QuicTraceLogInfo(
        WindowsUserProcessorState,
        "[ dll] Processors:%u, Groups:%u, NUMA Nodes:%u",
        ActiveProcessorCount, ProcessorGroupCount, NumaNodeCount);
// arg2 = arg2 = ActiveProcessorCount
// arg3 = arg3 = ProcessorGroupCount
// arg4 = arg4 = NumaNodeCount
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_WindowsUserProcessorState(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserProcessorState , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_ProcessorInfo



/*----------------------------------------------------------
// Decoder Ring for ProcessorInfo
// [ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]
// QuicTraceLogInfo(
                        ProcessorInfo,
                        "[ dll] Proc[%u] Group[%hu] Index[%u] NUMA[%u]",
                        Index,
                        QuicProcessorInfo[Index].Group,
                        QuicProcessorInfo[Index].Index,
                        QuicProcessorInfo[Index].NumaNode);
// arg2 = arg2 = Index
// arg3 = arg3 = QuicProcessorInfo[Index].Group
// arg4 = arg4 = QuicProcessorInfo[Index].Index
// arg5 = arg5 = QuicProcessorInfo[Index].NumaNode
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ProcessorInfo(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_PLATFORM_WINUSER_C, ProcessorInfo , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_3_ARGS_TRACE_WindowsUserInitialized



/*----------------------------------------------------------
// Decoder Ring for WindowsUserInitialized
// [ dll] Initialized (AvailMem = %llu bytes)
// QuicTraceLogInfo(
        WindowsUserInitialized,
        "[ dll] Initialized (AvailMem = %llu bytes)",
        QuicTotalMemory);
// arg2 = arg2 = QuicTotalMemory
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_WindowsUserInitialized(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserInitialized , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_WindowsUserUninitialized



/*----------------------------------------------------------
// Decoder Ring for WindowsUserUninitialized
// [ dll] Uninitialized
// QuicTraceLogInfo(
        WindowsUserUninitialized,
        "[ dll] Uninitialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_WindowsUserUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_PLATFORM_WINUSER_C, WindowsUserUninitialized );\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QuicProcessorInfo",
            ActiveProcessorCount * sizeof(QUIC_PROCESSOR_INFO));
// arg2 = arg2 = "QuicProcessorInfo"
// arg3 = arg3 = ActiveProcessorCount * sizeof(QUIC_PROCESSOR_INFO)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WINUSER_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX size");
// arg2 = arg2 = "Failed to determine PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX size"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_WINUSER_C, LibraryError , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX",
            BufferLength);
// arg2 = arg2 = "PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX"
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "GetLogicalProcessorInformationEx failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "GetLogicalProcessorInformationEx failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_WINUSER_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group count");
// arg2 = arg2 = "Failed to determine processor group count"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processors per group count");
// arg2 = arg2 = "Failed to determine processors per group count"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node count");
// arg2 = arg2 = "Failed to determine NUMA node count"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QuicProcessorGroupOffsets",
            ProcessorGroupCount * sizeof(uint32_t));
// arg2 = arg2 = "QuicProcessorGroupOffsets"
// arg3 = arg3 = ProcessorGroupCount * sizeof(uint32_t)
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
            "QuicNumaMasks",
            NumaNodeCount * sizeof(uint64_t));
// arg2 = arg2 = "QuicNumaMasks"
// arg3 = arg3 = NumaNodeCount * sizeof(uint64_t)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine processor group");
// arg2 = arg2 = "Failed to determine processor group"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Failed to determine NUMA node");
// arg2 = arg2 = "Failed to determine NUMA node"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "QuicProcessorInfoInit failed");
// arg2 = arg2 = "QuicProcessorInfoInit failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GlobalMemoryStatusEx failed");
// arg2 = arg2 = Error
// arg3 = arg3 = "GlobalMemoryStatusEx failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_LibraryAssert



/*----------------------------------------------------------
// Decoder Ring for LibraryAssert
// [ lib] ASSERT, %u:%s - %s.
// QuicTraceEvent(
        LibraryAssert,
        "[ lib] ASSERT, %u:%s - %s.",
        (uint32_t)Line,
        File,
        Expr);
// arg2 = arg2 = (uint32_t)Line
// arg3 = arg3 = File
// arg4 = arg4 = Expr
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_LibraryAssert(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PLATFORM_WINUSER_C, LibraryAssert , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_platform_winuser.c.clog.h.c"
#endif
