#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONTROL_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "control.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONTROL_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONTROL_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "control.cpp.clog.h.lttng.h"
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
#ifndef _clog_MACRO_QuicTraceLogError
#define _clog_MACRO_QuicTraceLogError  1
#define QuicTraceLogError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_4_ARGS_TRACE_TestControlClientCanceledRequest



/*----------------------------------------------------------
// Decoder Ring for TestControlClientCanceledRequest
// [test] Client %p canceled request %p
// QuicTraceLogWarning(
        TestControlClientCanceledRequest,
        "[test] Client %p canceled request %p",
        Client,
        Request);
// arg2 = arg2 = Client
// arg3 = arg3 = Request
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestControlClientCanceledRequest(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONTROL_CPP, TestControlClientCanceledRequest , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_TestControlClientCreated



/*----------------------------------------------------------
// Decoder Ring for TestControlClientCreated
// [test] Client %p created
// QuicTraceLogInfo(
            TestControlClientCreated,
            "[test] Client %p created",
            Client);
// arg2 = arg2 = Client
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_TestControlClientCreated(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONTROL_CPP, TestControlClientCreated , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_TestControlClientCleaningUp



/*----------------------------------------------------------
// Decoder Ring for TestControlClientCleaningUp
// [test] Client %p cleaning up
// QuicTraceLogInfo(
            TestControlClientCleaningUp,
            "[test] Client %p cleaning up",
            Client);
// arg2 = arg2 = Client
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_TestControlClientCleaningUp(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONTROL_CPP, TestControlClientCleaningUp , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_TestControlClientIoctl



/*----------------------------------------------------------
// Decoder Ring for TestControlClientIoctl
// [test] Client %p executing IOCTL %u
// QuicTraceLogInfo(
        TestControlClientIoctl,
        "[test] Client %p executing IOCTL %u",
        Client,
        FunctionCode);
// arg2 = arg2 = Client
// arg3 = arg3 = FunctionCode
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestControlClientIoctl(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONTROL_CPP, TestControlClientIoctl , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TestControlClientIoctlComplete



/*----------------------------------------------------------
// Decoder Ring for TestControlClientIoctlComplete
// [test] Client %p completing request, 0x%x
// QuicTraceLogInfo(
        TestControlClientIoctlComplete,
        "[test] Client %p completing request, 0x%x",
        Client,
        Status);
// arg2 = arg2 = Client
// arg3 = arg3 = Status
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TestControlClientIoctlComplete(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONTROL_CPP, TestControlClientIoctlComplete , arg2, arg3);\

#endif




#ifndef _clog_2_ARGS_TRACE_TestControlInitialized



/*----------------------------------------------------------
// Decoder Ring for TestControlInitialized
// [test] Control interface initialized
// QuicTraceLogVerbose(
        TestControlInitialized,
        "[test] Control interface initialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestControlInitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_CONTROL_CPP, TestControlInitialized );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestControlUninitializing



/*----------------------------------------------------------
// Decoder Ring for TestControlUninitializing
// [test] Control interface uninitializing
// QuicTraceLogVerbose(
        TestControlUninitializing,
        "[test] Control interface uninitializing");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestControlUninitializing(uniqueId, encoded_arg_string)\
tracepoint(CLOG_CONTROL_CPP, TestControlUninitializing );\

#endif




#ifndef _clog_2_ARGS_TRACE_TestControlUninitialized



/*----------------------------------------------------------
// Decoder Ring for TestControlUninitialized
// [test] Control interface uninitialized
// QuicTraceLogVerbose(
        TestControlUninitialized,
        "[test] Control interface uninitialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_TestControlUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_CONTROL_CPP, TestControlUninitialized );\

#endif




#ifndef _clog_5_ARGS_TRACE_TestDriverFailureLocation



/*----------------------------------------------------------
// Decoder Ring for TestDriverFailureLocation
// [test] File: %s, Function: %s, Line: %d
// QuicTraceLogError(
        TestDriverFailureLocation,
        "[test] File: %s, Function: %s, Line: %d",
        File,
        Function,
        Line);
// arg2 = arg2 = File
// arg3 = arg3 = Function
// arg4 = arg4 = Line
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TestDriverFailureLocation(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONTROL_CPP, TestDriverFailureLocation , arg2, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_TestDriverFailure



/*----------------------------------------------------------
// Decoder Ring for TestDriverFailure
// [test] FAIL: %s
// QuicTraceLogError(
        TestDriverFailure,
        "[test] FAIL: %s",
        Buffer);
// arg2 = arg2 = Buffer
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_TestDriverFailure(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONTROL_CPP, TestDriverFailure , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            MsQuic->GetInitStatus(),
            "MsQuicOpen");
// arg2 = arg2 = MsQuic->GetInitStatus()
// arg3 = arg3 = "MsQuicOpen"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONTROL_CPP, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfControlDeviceInitAllocate failed");
// arg2 = arg2 = "WdfControlDeviceInitAllocate failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONTROL_CPP, LibraryError , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceInitAssignName failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "WdfDeviceInitAssignName failed"
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
            "WdfDeviceCreate failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "WdfDeviceCreate failed"
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
            "WdfDeviceCreateSymbolicLink failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "WdfDeviceCreateSymbolicLink failed"
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
            "WdfIoQueueCreate failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "WdfIoQueueCreate failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Already have max clients");
// arg2 = arg2 = "Already have max clients"
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
                "nullptr File context in FileCreate");
// arg2 = arg2 = "nullptr File context in FileCreate"
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
            "IOCTL not supported greater than PASSIVE_LEVEL");
// arg2 = arg2 = "IOCTL not supported greater than PASSIVE_LEVEL"
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
            "WdfRequestGetFileObject failed");
// arg2 = arg2 = "WdfRequestGetFileObject failed"
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
            "QuicTestCtlGetFileContext failed");
// arg2 = arg2 = "QuicTestCtlGetFileContext failed"
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
            FunctionCode,
            "Invalid FunctionCode");
// arg2 = arg2 = FunctionCode
// arg3 = arg3 = "Invalid FunctionCode"
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
            FunctionCode,
            "Invalid buffer size for FunctionCode");
// arg2 = arg2 = FunctionCode
// arg3 = arg3 = "Invalid buffer size for FunctionCode"
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
                "WdfRequestRetrieveInputBuffer failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "WdfRequestRetrieveInputBuffer failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "WdfRequestRetrieveInputBuffer failed to return parameter buffer");
// arg2 = arg2 = "WdfRequestRetrieveInputBuffer failed to return parameter buffer"
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
            "Client didn't set Security Config");
// arg2 = arg2 = "Client didn't set Security Config"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_control.cpp.clog.h.c"
#endif
