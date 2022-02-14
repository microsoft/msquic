#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_API_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "api.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_API_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_API_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "api.c.clog.h.lttng.h"
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
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_OPEN,
        RegistrationHandle);
// arg2 = arg2 = QUIC_TRACE_API_CONNECTION_OPEN = arg2
// arg3 = arg3 = RegistrationHandle = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ApiEnter
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_API_C, ApiEnter , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ApiExitStatus
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_API_C, ApiExitStatus , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiWaitOperation
// [ api] Waiting on operation
// QuicTraceEvent(
            ApiWaitOperation,
            "[ api] Waiting on operation");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_ApiWaitOperation
#define _clog_2_ARGS_TRACE_ApiWaitOperation(uniqueId, encoded_arg_string)\
tracepoint(CLOG_API_C, ApiWaitOperation );\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_ApiExit
#define _clog_2_ARGS_TRACE_ApiExit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_API_C, ApiExit );\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server name",
                ServerNameLength + 1);
// arg2 = arg2 = "Server name" = arg2
// arg3 = arg3 = ServerNameLength + 1 = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_API_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamError
// [strm][%p] ERROR, %s.
// QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Send request total length exceeds max");
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = "Send request total length exceeds max" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StreamError
#define _clog_4_ARGS_TRACE_StreamError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_API_C, StreamError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamAppSend
// [strm][%p] App queuing send [%llu bytes, %u buffers, 0x%x flags]
// QuicTraceEvent(
        StreamAppSend,
        "[strm][%p] App queuing send [%llu bytes, %u buffers, 0x%x flags]",
        Stream,
        TotalLength,
        BufferCount,
        Flags);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = TotalLength = arg3
// arg4 = arg4 = BufferCount = arg4
// arg5 = arg5 = Flags = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_StreamAppSend
#define _clog_6_ARGS_TRACE_StreamAppSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_API_C, StreamAppSend , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiError
// [ api] Error %u
// QuicTraceEvent(
            ApiError,
            "[ api] Error %u",
            (uint32_t)QUIC_STATUS_INVALID_STATE);
// arg2 = arg2 = (uint32_t)QUIC_STATUS_INVALID_STATE = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ApiError
#define _clog_3_ARGS_TRACE_ApiError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_API_C, ApiError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Send request total length exceeds max");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Send request total length exceeds max" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_API_C, ConnError , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_api.c.clog.h.c"
#endif
