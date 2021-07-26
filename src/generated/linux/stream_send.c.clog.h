#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_STREAM_SEND_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "stream_send.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_STREAM_SEND_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_STREAM_SEND_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "stream_send.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogStreamVerbose
#define _clog_MACRO_QuicTraceLogStreamVerbose  1
#define QuicTraceLogStreamVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_3_ARGS_TRACE_IndicateSendShutdownComplete



/*----------------------------------------------------------
// Decoder Ring for IndicateSendShutdownComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
// QuicTraceLogStreamVerbose(
            IndicateSendShutdownComplete,
            Stream,
            "Indicating QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IndicateSendShutdownComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_SEND_C, IndicateSendShutdownComplete , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_IndicateSendCanceled



/*----------------------------------------------------------
// Decoder Ring for IndicateSendCanceled
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p] (Canceled)
// QuicTraceLogStreamVerbose(
                IndicateSendCanceled,
                Stream,
                "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p] (Canceled)",
                SendRequest);
// arg1 = arg1 = Stream
// arg3 = arg3 = SendRequest
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_IndicateSendCanceled(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_SEND_C, IndicateSendCanceled , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_IndicateSendComplete



/*----------------------------------------------------------
// Decoder Ring for IndicateSendComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]
// QuicTraceLogStreamVerbose(
                IndicateSendComplete,
                Stream,
                "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]",
                SendRequest);
// arg1 = arg1 = Stream
// arg3 = arg3 = SendRequest
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_IndicateSendComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_SEND_C, IndicateSendComplete , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_IndicateSendComplete



/*----------------------------------------------------------
// Decoder Ring for IndicateSendComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]
// QuicTraceLogStreamVerbose(
        IndicateSendComplete,
        Stream,
        "Indicating QUIC_STREAM_EVENT_SEND_COMPLETE [%p]",
        Req);
// arg1 = arg1 = Stream
// arg3 = arg3 = Req
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_IndicateSendComplete(uniqueId, arg1, encoded_arg_string, arg3)\

#endif




#ifndef _clog_7_ARGS_TRACE_SendQueued



/*----------------------------------------------------------
// Decoder Ring for SendQueued
// [strm][%p] Send Request [%p] queued with %llu bytes at offset %llu (flags 0x%x)
// QuicTraceLogStreamVerbose(
            SendQueued,
            Stream,
            "Send Request [%p] queued with %llu bytes at offset %llu (flags 0x%x)",
            SendRequest,
            SendRequest->TotalLength,
            SendRequest->StreamOffset,
            SendRequest->Flags);
// arg1 = arg1 = Stream
// arg3 = arg3 = SendRequest
// arg4 = arg4 = SendRequest->TotalLength
// arg5 = arg5 = SendRequest->StreamOffset
// arg6 = arg6 = SendRequest->Flags
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_SendQueued(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_STREAM_SEND_C, SendQueued , arg1, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_3_ARGS_TRACE_NoMoreRoom



/*----------------------------------------------------------
// Decoder Ring for NoMoreRoom
// [strm][%p] Can't squeeze in a frame (no room for header)
// QuicTraceLogStreamVerbose(
            NoMoreRoom,
            Stream,
            "Can't squeeze in a frame (no room for header)");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NoMoreRoom(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_SEND_C, NoMoreRoom , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_NoMoreFrames



/*----------------------------------------------------------
// Decoder Ring for NoMoreFrames
// [strm][%p] No more frames
// QuicTraceLogStreamVerbose(
            NoMoreFrames,
            Stream,
            "No more frames");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NoMoreFrames(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_SEND_C, NoMoreFrames , arg1);\

#endif




#ifndef _clog_6_ARGS_TRACE_AddFrame



/*----------------------------------------------------------
// Decoder Ring for AddFrame
// [strm][%p] Built stream frame, offset=%llu len=%lu fin=%hhu
// QuicTraceLogStreamVerbose(
        AddFrame,
        Stream,
        "Built stream frame, offset=%llu len=%lu fin=%hhu",
        Frame.Offset,
        (uint16_t)Frame.Length,
        Frame.Fin);
// arg1 = arg1 = Stream
// arg3 = arg3 = Frame.Offset
// arg4 = arg4 = (uint16_t)Frame.Length
// arg5 = arg5 = Frame.Fin
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_AddFrame(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_SEND_C, AddFrame , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_3_ARGS_TRACE_RecoverOpen



/*----------------------------------------------------------
// Decoder Ring for RecoverOpen
// [strm][%p] Recovering open STREAM frame
// QuicTraceLogStreamVerbose(
            RecoverOpen,
            Stream,
            "Recovering open STREAM frame");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_RecoverOpen(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_SEND_C, RecoverOpen , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_RecoverFin



/*----------------------------------------------------------
// Decoder Ring for RecoverFin
// [strm][%p] Recovering fin STREAM frame
// QuicTraceLogStreamVerbose(
            RecoverFin,
            Stream,
            "Recovering fin STREAM frame");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_RecoverFin(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_SEND_C, RecoverFin , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_RecoverRange



/*----------------------------------------------------------
// Decoder Ring for RecoverRange
// [strm][%p] Recovering offset %llu up to %llu
// QuicTraceLogStreamVerbose(
            RecoverRange,
            Stream,
            "Recovering offset %llu up to %llu",
            Start,
            End);
// arg1 = arg1 = Stream
// arg3 = arg3 = Start
// arg4 = arg4 = End
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_RecoverRange(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_STREAM_SEND_C, RecoverRange , arg1, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_AckRangeMsg



/*----------------------------------------------------------
// Decoder Ring for AckRangeMsg
// [strm][%p] Received ack for %d bytes, offset=%llu, FF=0x%hx
// QuicTraceLogStreamVerbose(
        AckRangeMsg,
        Stream,
        "Received ack for %d bytes, offset=%llu, FF=0x%hx",
        (int32_t)Length,
        Offset,
        FrameMetadata->Flags);
// arg1 = arg1 = Stream
// arg3 = arg3 = (int32_t)Length
// arg4 = arg4 = Offset
// arg5 = arg5 = FrameMetadata->Flags
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_AckRangeMsg(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_SEND_C, AckRangeMsg , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_Send0RttUpdated



/*----------------------------------------------------------
// Decoder Ring for Send0RttUpdated
// [strm][%p] Updated sent 0RTT length to %llu
// QuicTraceLogStreamVerbose(
            Send0RttUpdated,
            Stream,
            "Updated sent 0RTT length to %llu",
            FollowingOffset);
// arg1 = arg1 = Stream
// arg3 = arg3 = FollowingOffset
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_Send0RttUpdated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_SEND_C, Send0RttUpdated , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_SendQueueDrained



/*----------------------------------------------------------
// Decoder Ring for SendQueueDrained
// [strm][%p] Send queue completely drained
// QuicTraceLogStreamVerbose(
                SendQueueDrained,
                Stream,
                "Send queue completely drained");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SendQueueDrained(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_SEND_C, SendQueueDrained , arg1);\

#endif




#ifndef _clog_11_ARGS_TRACE_SendDump



/*----------------------------------------------------------
// Decoder Ring for SendDump
// [strm][%p] SF:%hX FC:%llu QS:%llu MAX:%llu UNA:%llu NXT:%llu RECOV:%llu-%llu
// QuicTraceLogStreamVerbose(
            SendDump,
            Stream,
            "SF:%hX FC:%llu QS:%llu MAX:%llu UNA:%llu NXT:%llu RECOV:%llu-%llu",
            Stream->SendFlags,
            Stream->MaxAllowedSendOffset,
            Stream->QueuedSendOffset,
            Stream->MaxSentLength,
            Stream->UnAckedOffset,
            Stream->NextSendOffset,
            Stream->Flags.InRecovery ? Stream->RecoveryNextOffset : 0,
            Stream->Flags.InRecovery ? Stream->RecoveryEndOffset : 0);
// arg1 = arg1 = Stream
// arg3 = arg3 = Stream->SendFlags
// arg4 = arg4 = Stream->MaxAllowedSendOffset
// arg5 = arg5 = Stream->QueuedSendOffset
// arg6 = arg6 = Stream->MaxSentLength
// arg7 = arg7 = Stream->UnAckedOffset
// arg8 = arg8 = Stream->NextSendOffset
// arg9 = arg9 = Stream->Flags.InRecovery ? Stream->RecoveryNextOffset : 0
// arg10 = arg10 = Stream->Flags.InRecovery ? Stream->RecoveryEndOffset : 0
----------------------------------------------------------*/
#define _clog_11_ARGS_TRACE_SendDump(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_STREAM_SEND_C, SendDump , arg1, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

#endif




#ifndef _clog_5_ARGS_TRACE_SendDumpAck



/*----------------------------------------------------------
// Decoder Ring for SendDumpAck
// [strm][%p]   unACKed: [%llu, %llu]
// QuicTraceLogStreamVerbose(
                SendDumpAck,
                Stream,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Sack->Low);
// arg1 = arg1 = Stream
// arg3 = arg3 = UnAcked
// arg4 = arg4 = Sack->Low
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_SendDumpAck(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_STREAM_SEND_C, SendDumpAck , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_SendDumpAck



/*----------------------------------------------------------
// Decoder Ring for SendDumpAck
// [strm][%p]   unACKed: [%llu, %llu]
// QuicTraceLogStreamVerbose(
                SendDumpAck,
                Stream,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Stream->MaxSentLength);
// arg1 = arg1 = Stream
// arg3 = arg3 = UnAcked
// arg4 = arg4 = Stream->MaxSentLength
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_SendDumpAck(uniqueId, arg1, encoded_arg_string, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_StreamSendState



/*----------------------------------------------------------
// Decoder Ring for StreamSendState
// [strm][%p] Send State: %hhu
// QuicTraceEvent(
        StreamSendState,
        "[strm][%p] Send State: %hhu",
        Stream,
        QuicStreamSendGetState(Stream));
// arg2 = arg2 = Stream
// arg3 = arg3 = QuicStreamSendGetState(Stream)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StreamSendState(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_SEND_C, StreamSendState , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_StreamSendState



/*----------------------------------------------------------
// Decoder Ring for StreamSendState
// [strm][%p] Send State: %hhu
// QuicTraceEvent(
                    StreamSendState,
                    "[strm][%p] Send State: %hhu",
                    Stream,
                    QuicStreamSendGetState(Stream));
// arg2 = arg2 = Stream
// arg3 = arg3 = QuicStreamSendGetState(Stream)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StreamSendState(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_StreamSendState



/*----------------------------------------------------------
// Decoder Ring for StreamSendState
// [strm][%p] Send State: %hhu
// QuicTraceEvent(
            StreamSendState,
            "[strm][%p] Send State: %hhu",
            Stream,
            QuicStreamSendGetState(Stream));
// arg2 = arg2 = Stream
// arg3 = arg3 = QuicStreamSendGetState(Stream)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StreamSendState(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_stream_send.c.clog.h.c"
#endif

