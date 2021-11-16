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
#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            Length,
            sizeof(IPV4_HEADER),
            "packet is too small for an IPv4 header");
// arg2 = arg2 = Length
// arg3 = arg3 = sizeof(IPV4_HEADER)
// arg4 = arg4 = "packet is too small for an IPv4 header"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_RAW_SOCKET_C, DataPathParserError , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            IP->HeaderLength * sizeof(uint32_t),
            sizeof(IPV4_HEADER),
            "unexpected IPv4 header size");
// arg2 = arg2 = IP->HeaderLength * sizeof(uint32_t)
// arg3 = arg3 = sizeof(IPV4_HEADER)
// arg4 = arg4 = "unexpected IPv4 header size"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
                DataPathParserError,
                "[DpParser] ERROR, %u, %u, %s.",
                Length,
                IPTotalLength,
                "unexpected IPv4 packet size");
// arg2 = arg2 = Length
// arg3 = arg3 = IPTotalLength
// arg4 = arg4 = "unexpected IPv4 packet size"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            IP->Protocol,
            IPPROTO_UDP,
            "unacceptable v4 transport");
// arg2 = arg2 = IP->Protocol
// arg3 = arg3 = IPPROTO_UDP
// arg4 = arg4 = "unacceptable v4 transport"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            Length,
            sizeof(IPV6_HEADER),
            "packet is too small for an IPv6 header");
// arg2 = arg2 = Length
// arg3 = arg3 = sizeof(IPV6_HEADER)
// arg4 = arg4 = "packet is too small for an IPv6 header"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
                DataPathParserError,
                "[DpParser] ERROR, %u, %u, %s.",
                IPPayloadLength,
                Length - sizeof(IPV6_HEADER),
                "incorrect IP payload length");
// arg2 = arg2 = IPPayloadLength
// arg3 = arg3 = Length - sizeof(IPV6_HEADER)
// arg4 = arg4 = "incorrect IP payload length"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            IP->NextHeader,
            IPPROTO_UDP,
            "unacceptable v6 transport");
// arg2 = arg2 = IP->NextHeader
// arg3 = arg3 = IPPROTO_UDP
// arg4 = arg4 = "unacceptable v6 transport"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DataPathParserError



/*----------------------------------------------------------
// Decoder Ring for DataPathParserError
// [DpParser] ERROR, %u, %u, %s.
// QuicTraceEvent(
            DataPathParserError,
            "[DpParser] ERROR, %u, %u, %s.",
            EthernetType,
            0,
            "unacceptable ethernet type");
// arg2 = arg2 = EthernetType
// arg3 = arg3 = 0
// arg4 = arg4 = "unacceptable ethernet type"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DataPathParserError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_socket.c.clog.h.c"
#endif
