#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PACKET_BUILDER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "packet_builder.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PACKET_BUILDER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PACKET_BUILDER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "packet_builder.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_3_ARGS_TRACE_NoSrcCidAvailable



/*----------------------------------------------------------
// Decoder Ring for NoSrcCidAvailable
// [conn][%p] No src CID to send with
// QuicTraceLogConnWarning(
            NoSrcCidAvailable,
            Connection,
            "No src CID to send with");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NoSrcCidAvailable(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_PACKET_BUILDER_C, NoSrcCidAvailable , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_GetPacketTypeFailure



/*----------------------------------------------------------
// Decoder Ring for GetPacketTypeFailure
// [conn][%p] Failed to get packet type for control frames, 0x%x
// QuicTraceLogConnWarning(
        GetPacketTypeFailure,
        Builder->Connection,
        "Failed to get packet type for control frames, 0x%x",
        SendFlags);
// arg1 = arg1 = Builder->Connection
// arg3 = arg3 = SendFlags
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_GetPacketTypeFailure(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PACKET_BUILDER_C, GetPacketTypeFailure , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketBuilderSendBatch



/*----------------------------------------------------------
// Decoder Ring for PacketBuilderSendBatch
// [conn][%p] Sending batch. %hu datagrams
// QuicTraceLogConnVerbose(
        PacketBuilderSendBatch,
        Builder->Connection,
        "Sending batch. %hu datagrams",
        (uint16_t)Builder->TotalCountDatagrams);
// arg1 = arg1 = Builder->Connection
// arg3 = arg3 = (uint16_t)Builder->TotalCountDatagrams
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketBuilderSendBatch(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_PACKET_BUILDER_C, PacketBuilderSendBatch , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "NULL key in builder prepare");
// arg2 = arg2 = Connection
// arg3 = arg3 = "NULL key in builder prepare"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PACKET_BUILDER_C, ConnError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "packet send context",
                    0);
// arg2 = arg2 = "packet send context"
// arg3 = arg3 = 0
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PACKET_BUILDER_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "packet datagram",
                NewDatagramLength);
// arg2 = arg2 = "packet datagram"
// arg3 = arg3 = NewDatagramLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Send-triggered key update");
// arg2 = arg2 = Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "Send-triggered key update"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PACKET_BUILDER_C, ConnErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnPacketSent



/*----------------------------------------------------------
// Decoder Ring for ConnPacketSent
// [conn][%p][TX][%llu] %hhu (%hu bytes)
// QuicTraceEvent(
        ConnPacketSent,
        "[conn][%p][TX][%llu] %hhu (%hu bytes)",
        Connection,
        Builder->Metadata->PacketNumber,
        QuicPacketTraceType(Builder->Metadata),
        Builder->Metadata->PacketLength);
// arg2 = arg2 = Connection
// arg3 = arg3 = Builder->Metadata->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Builder->Metadata)
// arg5 = arg5 = Builder->Metadata->PacketLength
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnPacketSent(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_PACKET_BUILDER_C, ConnPacketSent , arg2, arg3, arg4, arg5);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_packet_builder.c.clog.h.c"
#endif
