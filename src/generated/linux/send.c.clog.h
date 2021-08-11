#include <clog.h>
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
#ifndef _clog_5_ARGS_TRACE_SetSendFlag



/*----------------------------------------------------------
// Decoder Ring for SetSendFlag
// [strm][%p] Setting flags 0x%x (existing flags: 0x%x)
// QuicTraceLogStreamVerbose(
            SetSendFlag,
            Stream,
            "Setting flags 0x%x (existing flags: 0x%x)",
            (SendFlags & (uint32_t)(~Stream->SendFlags)),
            Stream->SendFlags);
// arg1 = arg1 = Stream
// arg3 = arg3 = (SendFlags & (uint32_t)(~Stream->SendFlags))
// arg4 = arg4 = Stream->SendFlags
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_SetSendFlag(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_SEND_C, SetSendFlag , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ClearSendFlags



/*----------------------------------------------------------
// Decoder Ring for ClearSendFlags
// [strm][%p] Removing flags %x
// QuicTraceLogStreamVerbose(
            ClearSendFlags,
            Stream,
            "Removing flags %x",
            (SendFlags & Stream->SendFlags));
// arg1 = arg1 = Stream
// arg3 = arg3 = (SendFlags & Stream->SendFlags)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ClearSendFlags(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, ClearSendFlags , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_CancelAckDelayTimer



/*----------------------------------------------------------
// Decoder Ring for CancelAckDelayTimer
// [conn][%p] Canceling ACK_DELAY timer
// QuicTraceLogConnVerbose(
            CancelAckDelayTimer,
            QuicSendGetConnection(Send),
            "Canceling ACK_DELAY timer");
// arg1 = arg1 = QuicSendGetConnection(Send)
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CancelAckDelayTimer(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_SEND_C, CancelAckDelayTimer , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_CancelAckDelayTimer



/*----------------------------------------------------------
// Decoder Ring for CancelAckDelayTimer
// [conn][%p] Canceling ACK_DELAY timer
// QuicTraceLogConnVerbose(
            CancelAckDelayTimer,
            Connection,
            "Canceling ACK_DELAY timer");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CancelAckDelayTimer(uniqueId, arg1, encoded_arg_string)\

#endif




#ifndef _clog_5_ARGS_TRACE_ScheduleSendFlags



/*----------------------------------------------------------
// Decoder Ring for ScheduleSendFlags
// [conn][%p] Scheduling flags 0x%x to 0x%x
// QuicTraceLogConnVerbose(
            ScheduleSendFlags,
            Connection,
            "Scheduling flags 0x%x to 0x%x",
            SendFlags,
            Send->SendFlags);
// arg1 = arg1 = Connection
// arg3 = arg3 = SendFlags
// arg4 = arg4 = Send->SendFlags
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ScheduleSendFlags(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_SEND_C, ScheduleSendFlags , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_RemoveSendFlags



/*----------------------------------------------------------
// Decoder Ring for RemoveSendFlags
// [conn][%p] Removing flags %x
// QuicTraceLogConnVerbose(
            RemoveSendFlags,
            QuicSendGetConnection(Send),
            "Removing flags %x",
            (SendFlags & Send->SendFlags));
// arg1 = arg1 = QuicSendGetConnection(Send)
// arg3 = arg3 = (SendFlags & Send->SendFlags)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_RemoveSendFlags(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, RemoveSendFlags , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_CancelAckDelayTimer



/*----------------------------------------------------------
// Decoder Ring for CancelAckDelayTimer
// [conn][%p] Canceling ACK_DELAY timer
// QuicTraceLogConnVerbose(
                CancelAckDelayTimer,
                Connection,
                "Canceling ACK_DELAY timer");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CancelAckDelayTimer(uniqueId, arg1, encoded_arg_string)\

#endif




#ifndef _clog_4_ARGS_TRACE_FlushSend



/*----------------------------------------------------------
// Decoder Ring for FlushSend
// [conn][%p] Flushing send. Allowance=%u bytes
// QuicTraceLogConnVerbose(
        FlushSend,
        Connection,
        "Flushing send. Allowance=%u bytes",
        Builder.SendAllowance);
// arg1 = arg1 = Connection
// arg3 = arg3 = Builder.SendAllowance
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_FlushSend(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, FlushSend , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_AmplificationProtectionBlocked



/*----------------------------------------------------------
// Decoder Ring for AmplificationProtectionBlocked
// [conn][%p] Cannot send any more because of amplification protection
// QuicTraceLogConnVerbose(
                AmplificationProtectionBlocked,
                Connection,
                "Cannot send any more because of amplification protection");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_AmplificationProtectionBlocked(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_SEND_C, AmplificationProtectionBlocked , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_SetPacingTimer



/*----------------------------------------------------------
// Decoder Ring for SetPacingTimer
// [conn][%p] Setting delayed send (PACING) timer for %u ms
// QuicTraceLogConnVerbose(
                        SetPacingTimer,
                        Connection,
                        "Setting delayed send (PACING) timer for %u ms",
                        QUIC_SEND_PACING_INTERVAL);
// arg1 = arg1 = Connection
// arg3 = arg3 = QUIC_SEND_PACING_INTERVAL
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SetPacingTimer(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, SetPacingTimer , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_SendFlushComplete



/*----------------------------------------------------------
// Decoder Ring for SendFlushComplete
// [conn][%p] Flush complete flags=0x%x
// QuicTraceLogConnVerbose(
        SendFlushComplete,
        Connection,
        "Flush complete flags=0x%x",
        Send->SendFlags);
// arg1 = arg1 = Connection
// arg3 = arg3 = Send->SendFlags
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SendFlushComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, SendFlushComplete , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_StartAckDelayTimer



/*----------------------------------------------------------
// Decoder Ring for StartAckDelayTimer
// [conn][%p] Starting ACK_DELAY timer for %u ms
// QuicTraceLogConnVerbose(
            StartAckDelayTimer,
            Connection,
            "Starting ACK_DELAY timer for %u ms",
            Connection->Settings.MaxAckDelayMs);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Settings.MaxAckDelayMs
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StartAckDelayTimer(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_SEND_C, StartAckDelayTimer , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnQueueSendFlush



/*----------------------------------------------------------
// Decoder Ring for ConnQueueSendFlush
// [conn][%p] Queueing send flush, reason=%u
// QuicTraceEvent(
                ConnQueueSendFlush,
                "[conn][%p] Queueing send flush, reason=%u",
                Connection,
                Reason);
// arg2 = arg2 = Connection
// arg3 = arg3 = Reason
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnQueueSendFlush(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SEND_C, ConnQueueSendFlush , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_send.c.clog.h.c"
#endif
