#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_ACK_TRACKER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "ack_tracker.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_ACK_TRACKER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_ACK_TRACKER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "ack_tracker.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PacketRxMarkedForAck
// [%c][RX][%llu] Marked for ACK (ECN=%hhu)
// QuicTraceLogVerbose(
        PacketRxMarkedForAck,
        "[%c][RX][%llu] Marked for ACK (ECN=%hhu)",
        PtkConnPre(Connection),
        PacketNumber,
        (uint8_t)ECN);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PacketNumber = arg3
// arg4 = arg4 = (uint8_t)ECN = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PacketRxMarkedForAck
#define _clog_5_ARGS_TRACE_PacketRxMarkedForAck(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_ACK_TRACKER_C, PacketRxMarkedForAck , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_ack_tracker.c.clog.h.c"
#endif
