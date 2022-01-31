#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_SEND_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "send.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_SEND_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_SEND_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "send.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogStreamVerbose
#define _clog_MACRO_QuicTraceLogStreamVerbose  1
#define QuicTraceLogStreamVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
/*----------------------------------------------------------
// Decoder Ring for SetSendFlag
// [strm][%p] Setting flags 0x%x (existing flags: 0x%x)
// QuicTraceLogStreamVerbose(
            SetSendFlag,
            Stream,
            "Setting flags 0x%x (existing flags: 0x%x)",
            (SendFlags & (uint32_t)(~Stream->SendFlags)),
            Stream->SendFlags);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (SendFlags & (uint32_t)(~Stream->SendFlags)) = arg3
// arg4 = arg4 = Stream->SendFlags = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_SetSendFlag
#define _clog_5_ARGS_TRACE_SetSendFlag(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_SEND_C, SetSendFlag , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClearSendFlags
// [strm][%p] Removing flags %x
// QuicTraceLogStreamVerbose(
            ClearSendFlags,
            Stream,
            "Removing flags %x",
            (SendFlags & Stream->SendFlags));
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (SendFlags & Stream->SendFlags) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ClearSendFlags
#define _clog_4_ARGS_TRACE_ClearSendFlags(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, ClearSendFlags , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ScheduleSendFlags
// [conn][%p] Scheduling flags 0x%x to 0x%x
// QuicTraceLogConnVerbose(
            ScheduleSendFlags,
            Connection,
            "Scheduling flags 0x%x to 0x%x",
            SendFlags,
            Send->SendFlags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = SendFlags = arg3
// arg4 = arg4 = Send->SendFlags = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ScheduleSendFlags
#define _clog_5_ARGS_TRACE_ScheduleSendFlags(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_SEND_C, ScheduleSendFlags , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RemoveSendFlagsMsg
// [conn][%p] Removing flags %x
// QuicTraceLogConnVerbose(
            RemoveSendFlagsMsg,
            QuicSendGetConnection(Send),
            "Removing flags %x",
            (SendFlags & Send->SendFlags));
// arg1 = arg1 = QuicSendGetConnection(Send) = arg1
// arg3 = arg3 = (SendFlags & Send->SendFlags) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_RemoveSendFlagsMsg
#define _clog_4_ARGS_TRACE_RemoveSendFlagsMsg(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, RemoveSendFlagsMsg , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AmplificationProtectionBlocked
// [conn][%p] Cannot send any more because of amplification protection
// QuicTraceLogConnVerbose(
                AmplificationProtectionBlocked,
                Connection,
                "Cannot send any more because of amplification protection");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_AmplificationProtectionBlocked
#define _clog_3_ARGS_TRACE_AmplificationProtectionBlocked(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_SEND_C, AmplificationProtectionBlocked , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SendFlushComplete
// [conn][%p] Flush complete flags=0x%x
// QuicTraceLogConnVerbose(
        SendFlushComplete,
        Connection,
        "Flush complete flags=0x%x",
        Send->SendFlags);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Send->SendFlags = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SendFlushComplete
#define _clog_4_ARGS_TRACE_SendFlushComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, SendFlushComplete , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StartAckDelayTimer
// [conn][%p] Starting ACK_DELAY timer for %u ms
// QuicTraceLogConnVerbose(
            StartAckDelayTimer,
            Connection,
            "Starting ACK_DELAY timer for %u ms",
            Connection->Settings.MaxAckDelayMs);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Settings.MaxAckDelayMs = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StartAckDelayTimer
#define _clog_4_ARGS_TRACE_StartAckDelayTimer(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, StartAckDelayTimer , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnQueueSendFlush
// [conn][%p] Queueing send flush, reason=%u
// QuicTraceEvent(
                ConnQueueSendFlush,
                "[conn][%p] Queueing send flush, reason=%u",
                Connection,
                Reason);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Reason = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnQueueSendFlush
#define _clog_4_ARGS_TRACE_ConnQueueSendFlush(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SEND_C, ConnQueueSendFlush , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnFlushSend
// [conn][%p] Flushing Send. Allowance=%u bytes
// QuicTraceEvent(
        ConnFlushSend,
        "[conn][%p] Flushing Send. Allowance=%u bytes",
        Connection,
        Builder.SendAllowance);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Builder.SendAllowance = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnFlushSend
#define _clog_4_ARGS_TRACE_ConnFlushSend(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SEND_C, ConnFlushSend , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_send.c.clog.h.c"
#endif
