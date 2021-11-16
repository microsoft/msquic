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
#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for an IPv4 header");
// arg2 = arg2 = Datapath
// arg3 = arg3 = Length
// arg4 = arg4 = "packet is too small for an IPv4 header"
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
            Datapath,
            IP->HeaderLength * sizeof(uint32_t),
            "unexpected IPv4 header size");
// arg2 = arg2 = Datapath
// arg3 = arg3 = IP->HeaderLength * sizeof(uint32_t)
// arg4 = arg4 = "unexpected IPv4 header size"
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
                Datapath,
                Length,
                "unexpected IPv4 packet size");
// arg2 = arg2 = Datapath
// arg3 = arg3 = Length
// arg4 = arg4 = "unexpected IPv4 packet size"
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
            Datapath,
            IP->Protocol,
            "unacceptable v4 transport");
// arg2 = arg2 = Datapath
// arg3 = arg3 = IP->Protocol
// arg4 = arg4 = "unacceptable v4 transport"
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
            Datapath,
            Length,
            "packet is too small for an IPv6 header");
// arg2 = arg2 = Datapath
// arg3 = arg3 = Length
// arg4 = arg4 = "packet is too small for an IPv6 header"
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
                Datapath,
                IPPayloadLength,
                "incorrect IP payload length");
// arg2 = arg2 = Datapath
// arg3 = arg3 = IPPayloadLength
// arg4 = arg4 = "incorrect IP payload length"
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
            Datapath,
            IP->NextHeader,
            "unacceptable v6 transport");
// arg2 = arg2 = Datapath
// arg3 = arg3 = IP->NextHeader
// arg4 = arg4 = "unacceptable v6 transport"
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
            Datapath,
            Length,
            "packet is too small for an ethernet header");
// arg2 = arg2 = Datapath
// arg3 = arg3 = Length
// arg4 = arg4 = "packet is too small for an ethernet header"
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
            Datapath,
            0,
            "not a unicast packet");
// arg2 = arg2 = Datapath
// arg3 = arg3 = 0
// arg4 = arg4 = "not a unicast packet"
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
            Datapath,
            EthernetType,
            "unacceptable ethernet type");
// arg2 = arg2 = Datapath
// arg3 = arg3 = EthernetType
// arg4 = arg4 = "unacceptable ethernet type"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_socket.c.clog.h.c"
#endif
