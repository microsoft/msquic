#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_RAW_SOCKET_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_raw_socket.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_RAW_SOCKET_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_RAW_SOCKET_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_raw_socket.c.clog.h.lttng.h"
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
            WsaError,
            "WSAStartup");
// arg2 = arg2 = WsaError
// arg3 = arg3 = "WSAStartup"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_SOCKET_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "socket");
// arg2 = arg2 = Socket
// arg3 = arg3 = Error
// arg4 = arg4 = "socket"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_RAW_SOCKET_C, DatapathErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "Set IPV6_V6ONLY");
// arg2 = arg2 = Socket
// arg3 = arg3 = Error
// arg4 = arg4 = "Set IPV6_V6ONLY"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "bind");
// arg2 = arg2 = Socket
// arg3 = arg3 = Error
// arg4 = arg4 = "bind"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Error,
                "connect failed");
// arg2 = arg2 = Socket
// arg3 = arg3 = Error
// arg4 = arg4 = "connect failed"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "getsockname");
// arg2 = arg2 = Socket
// arg3 = arg3 = Error
// arg4 = arg4 = "getsockname"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "closesocket");
// arg2 = arg2 = Socket
// arg3 = arg3 = Error
// arg4 = arg4 = "closesocket"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            IP->Protocol,
            "unacceptable v4 transport");
// arg2 = arg2 = IP->Protocol
// arg3 = arg3 = "unacceptable v4 transport"
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
            IP->NextHeader,
            "unacceptable v6 transport");
// arg2 = arg2 = IP->NextHeader
// arg3 = arg3 = "unacceptable v6 transport"
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
            EthernetType,
            "unacceptable Ethernet type");
// arg2 = arg2 = EthernetType
// arg3 = arg3 = "unacceptable Ethernet type"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_socket.c.clog.h.c"
#endif
