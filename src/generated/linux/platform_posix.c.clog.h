#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PLATFORM_POSIX_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "platform_posix.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PLATFORM_POSIX_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PLATFORM_POSIX_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "platform_posix.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "pthread_attr_init failed");
// arg2 = arg2 = errno
// arg3 = arg3 = "pthread_attr_init failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_POSIX_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "pthread_attr_setaffinity_np failed");
// arg2 = arg2 = "pthread_attr_setaffinity_np failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_PLATFORM_POSIX_C, LibraryError , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                errno,
                "pthread_attr_setschedparam failed");
// arg2 = arg2 = errno
// arg3 = arg3 = "pthread_attr_setschedparam failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Custom thread context",
            sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT));
// arg2 = arg2 = "Custom thread context"
// arg3 = arg3 = sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PLATFORM_POSIX_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "pthread_create failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "pthread_create failed"
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
            "pthread_create failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "pthread_create failed"
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
                    "pthread_setaffinity_np failed");
// arg2 = arg2 = "pthread_setaffinity_np failed"
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
            "pthread_setaffinity_np failed");
// arg2 = arg2 = "pthread_setaffinity_np failed"
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
            errno,
            "pthread_attr_init failed");
// arg2 = arg2 = errno
// arg3 = arg3 = "pthread_attr_init failed"
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
                errno,
                "pthread_attr_setschedparam failed");
// arg2 = arg2 = errno
// arg3 = arg3 = "pthread_attr_setschedparam failed"
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
            "pthread_create failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "pthread_create failed"
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
tracepoint(CLOG_PLATFORM_POSIX_C, LibraryAssert , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_platform_posix.c.clog.h.c"
#endif

