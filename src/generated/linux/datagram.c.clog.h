#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAGRAM_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datagram.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAGRAM_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAGRAM_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datagram.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
/*----------------------------------------------------------
// Decoder Ring for DatagramSendStateChanged
// [conn][%p] Indicating DATAGRAM_SEND_STATE_CHANGED to %u
// QuicTraceLogConnVerbose(
        DatagramSendStateChanged,
        Connection,
        "Indicating DATAGRAM_SEND_STATE_CHANGED to %u",
        (uint32_t)State);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint32_t)State = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DatagramSendStateChanged
#define _clog_4_ARGS_TRACE_DatagramSendStateChanged(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_DATAGRAM_C, DatagramSendStateChanged , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatagramSendShutdown
// [conn][%p] Datagram send shutdown
// QuicTraceLogConnVerbose(
        DatagramSendShutdown,
        Connection,
        "Datagram send shutdown");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatagramSendShutdown
#define _clog_3_ARGS_TRACE_DatagramSendShutdown(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_DATAGRAM_C, DatagramSendShutdown , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateDatagramStateChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED [SendEnabled=%hhu] [MaxSendLength=%hu]
// QuicTraceLogConnVerbose(
            IndicateDatagramStateChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED [SendEnabled=%hhu] [MaxSendLength=%hu]",
            Event.DATAGRAM_STATE_CHANGED.SendEnabled,
            Event.DATAGRAM_STATE_CHANGED.MaxSendLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.DATAGRAM_STATE_CHANGED.SendEnabled = arg3
// arg4 = arg4 = Event.DATAGRAM_STATE_CHANGED.MaxSendLength = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_IndicateDatagramStateChanged
#define _clog_5_ARGS_TRACE_IndicateDatagramStateChanged(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_DATAGRAM_C, IndicateDatagramStateChanged , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatagramSendQueued
// [conn][%p] Datagram [%p] queued with %llu bytes (flags 0x%x)
// QuicTraceLogConnVerbose(
            DatagramSendQueued,
            Connection,
            "Datagram [%p] queued with %llu bytes (flags 0x%x)",
            SendRequest,
            SendRequest->TotalLength,
            SendRequest->Flags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = SendRequest = arg3
// arg4 = arg4 = SendRequest->TotalLength = arg4
// arg5 = arg5 = SendRequest->Flags = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_DatagramSendQueued
#define _clog_6_ARGS_TRACE_DatagramSendQueued(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_DATAGRAM_C, DatagramSendQueued , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateDatagramReceived
// [conn][%p] Indicating DATAGRAM_RECEIVED [len=%hu]
// QuicTraceLogConnVerbose(
        IndicateDatagramReceived,
        Connection,
        "Indicating DATAGRAM_RECEIVED [len=%hu]",
        (uint16_t)Frame.Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Frame.Length = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicateDatagramReceived
#define _clog_4_ARGS_TRACE_IndicateDatagramReceived(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_DATAGRAM_C, IndicateDatagramReceived , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Datagram send while disabled");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Datagram send while disabled" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAGRAM_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DATAGRAM_SEND operation",
                0);
// arg2 = arg2 = "DATAGRAM_SEND operation" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAGRAM_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datagram.c.clog.h.c"
#endif
