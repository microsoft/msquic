#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONNECTION_POOL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "connection_pool.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONNECTION_POOL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONNECTION_POOL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "connection_pool.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
/*----------------------------------------------------------
// Decoder Ring for ConnPoolLocalAddressNotFound
// [conp] Failed to find local address, 0x%x
// QuicTraceLogError(
            ConnPoolLocalAddressNotFound,
            "[conp] Failed to find local address, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolLocalAddressNotFound
#define _clog_3_ARGS_TRACE_ConnPoolLocalAddressNotFound(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolLocalAddressNotFound , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolInvalidParam
// [conp] Invalid parameter, 0x%x
// QuicTraceLogError(
            ConnPoolInvalidParam,
            "[conp] Invalid parameter, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolInvalidParam
#define _clog_3_ARGS_TRACE_ConnPoolInvalidParam(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolInvalidParam , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolResolveAddress
// [conp] Failed to resolve address, 0x%x
// QuicTraceLogError(
                ConnPoolResolveAddress,
                "[conp] Failed to resolve address, 0x%x",
                Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolResolveAddress
#define _clog_3_ARGS_TRACE_ConnPoolResolveAddress(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolResolveAddress , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolGetLocalAddress
// [conp] Failed to get local address, 0x%x
// QuicTraceLogError(
            ConnPoolGetLocalAddress,
            "[conp] Failed to get local address, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolGetLocalAddress
#define _clog_3_ARGS_TRACE_ConnPoolGetLocalAddress(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolGetLocalAddress , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolGetRssConfig
// [conp] Failed to get RSS config, 0x%x
// QuicTraceLogError(
            ConnPoolGetRssConfig,
            "[conp] Failed to get RSS config, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolGetRssConfig
#define _clog_3_ARGS_TRACE_ConnPoolGetRssConfig(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolGetRssConfig , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolRssNotSupported
// [conp] RSS not supported for UDP, 0x%x
// QuicTraceLogError(
            ConnPoolRssNotSupported,
            "[conp] RSS not supported for UDP, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolRssNotSupported
#define _clog_3_ARGS_TRACE_ConnPoolRssNotSupported(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolRssNotSupported , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolRssSecretKeyTooLong
// [conp] RSS secret key too long, 0x%x
// QuicTraceLogError(
            ConnPoolRssSecretKeyTooLong,
            "[conp] RSS secret key too long, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPoolRssSecretKeyTooLong
#define _clog_3_ARGS_TRACE_ConnPoolRssSecretKeyTooLong(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolRssSecretKeyTooLong , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolOpenConnection
// [conp] Failed to open connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolOpenConnection,
                    "[conp] Failed to open connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPoolOpenConnection
#define _clog_4_ARGS_TRACE_ConnPoolOpenConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolOpenConnection , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolSetRemoteAddress
// [conp] Failed to set remote address on connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolSetRemoteAddress,
                    "[conp] Failed to set remote address on connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPoolSetRemoteAddress
#define _clog_4_ARGS_TRACE_ConnPoolSetRemoteAddress(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolSetRemoteAddress , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolSetLocalAddress
// [conp] Failed to set local address on connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolSetLocalAddress,
                    "[conp] Failed to set local address on connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPoolSetLocalAddress
#define _clog_4_ARGS_TRACE_ConnPoolSetLocalAddress(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolSetLocalAddress , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolStartConnection
// [conp] Failed to start connection[%u], 0x%x
// QuicTraceLogError(
                    ConnPoolStartConnection,
                    "[conp] Failed to start connection[%u], 0x%x",
                    i,
                    Status);
// arg2 = arg2 = i = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnPoolStartConnection
#define _clog_4_ARGS_TRACE_ConnPoolStartConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolStartConnection , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPoolMaxRetries
// [conp] Ran out of retries. MaxRetries %u, Iteration %u, Port %u, 0x%x
// QuicTraceLogError(
                ConnPoolMaxRetries,
                "[conp] Ran out of retries. MaxRetries %u, Iteration %u, Port %u, 0x%x",
                MaxCreationRetries,
                i,
                QuicAddrGetPort(&LocalAddress),
                Status);
// arg2 = arg2 = MaxCreationRetries = arg2
// arg3 = arg3 = i = arg3
// arg4 = arg4 = QuicAddrGetPort(&LocalAddress) = arg4
// arg5 = arg5 = Status = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnPoolMaxRetries
#define _clog_6_ARGS_TRACE_ConnPoolMaxRetries(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_CONNECTION_POOL_C, ConnPoolMaxRetries , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONNECTION_POOL_CREATE,
        Config->Registration);
// arg2 = arg2 = QUIC_TRACE_API_CONNECTION_POOL_CREATE = arg2
// arg3 = arg3 = Config->Registration = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ApiEnter
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_POOL_C, ApiEnter , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSS Processor List",
            RssConfig->RssIndirectionTableLength);
// arg2 = arg2 = "RSS Processor List" = arg2
// arg3 = arg3 = RssConfig->RssIndirectionTableLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_POOL_C, AllocFailure , arg2, arg3);\

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
tracepoint(CLOG_CONNECTION_POOL_C, ApiExitStatus , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_connection_pool.c.clog.h.c"
#endif
