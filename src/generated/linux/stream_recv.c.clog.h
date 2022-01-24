#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_STREAM_RECV_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "stream_recv.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_STREAM_RECV_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_STREAM_RECV_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "stream_recv.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogStreamWarning
#define _clog_MACRO_QuicTraceLogStreamWarning  1
#define QuicTraceLogStreamWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogStreamInfo
#define _clog_MACRO_QuicTraceLogStreamInfo  1
#define QuicTraceLogStreamInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
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
/*----------------------------------------------------------
// Decoder Ring for ResetEarly
// [strm][%p] Tried to reset at earlier final size!
// QuicTraceLogStreamWarning(
                ResetEarly,
                Stream,
                "Tried to reset at earlier final size!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ResetEarly
#define _clog_3_ARGS_TRACE_ResetEarly(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, ResetEarly , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ResetTooBig
// [strm][%p] Tried to reset with too big final size!
// QuicTraceLogStreamWarning(
                    ResetTooBig,
                    Stream,
                    "Tried to reset with too big final size!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ResetTooBig
#define _clog_3_ARGS_TRACE_ResetTooBig(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, ResetTooBig , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ReceiveTooBig
// [strm][%p] Tried to write beyond end of buffer!
// QuicTraceLogStreamWarning(
            ReceiveTooBig,
            Stream,
            "Tried to write beyond end of buffer!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ReceiveTooBig
#define _clog_3_ARGS_TRACE_ReceiveTooBig(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, ReceiveTooBig , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ReceiveBeyondFlowControl
// [strm][%p] Tried to write beyond flow control limit!
// QuicTraceLogStreamWarning(
            ReceiveBeyondFlowControl,
            Stream,
            "Tried to write beyond flow control limit!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ReceiveBeyondFlowControl
#define _clog_3_ARGS_TRACE_ReceiveBeyondFlowControl(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, ReceiveBeyondFlowControl , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RemoteCloseReset
// [strm][%p] Closed remotely (reset)
// QuicTraceLogStreamInfo(
                RemoteCloseReset,
                Stream,
                "Closed remotely (reset)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RemoteCloseReset
#define _clog_3_ARGS_TRACE_RemoteCloseReset(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, RemoteCloseReset , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LocalCloseStopSending
// [strm][%p] Closed locally (stop sending)
// QuicTraceLogStreamInfo(
            LocalCloseStopSending,
            Stream,
            "Closed locally (stop sending)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LocalCloseStopSending
#define _clog_3_ARGS_TRACE_LocalCloseStopSending(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, LocalCloseStopSending , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TreatFinAsReset
// [strm][%p] Treating FIN after receive abort as reset
// QuicTraceLogStreamInfo(
                TreatFinAsReset,
                Stream,
                "Treating FIN after receive abort as reset");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TreatFinAsReset
#define _clog_3_ARGS_TRACE_TreatFinAsReset(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, TreatFinAsReset , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for QueueRecvFlush
// [strm][%p] Queuing recv flush
// QuicTraceLogStreamVerbose(
            QueueRecvFlush,
            Stream,
            "Queuing recv flush");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_QueueRecvFlush
#define _clog_3_ARGS_TRACE_QueueRecvFlush(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, QueueRecvFlush , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerSendAbort
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_SEND_ABORTED (0x%llX)
// QuicTraceLogStreamVerbose(
                IndicatePeerSendAbort,
                Stream,
                "Indicating QUIC_STREAM_EVENT_PEER_SEND_ABORTED (0x%llX)",
                ErrorCode);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = ErrorCode = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicatePeerSendAbort
#define _clog_4_ARGS_TRACE_IndicatePeerSendAbort(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_RECV_C, IndicatePeerSendAbort , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerReceiveAborted
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED (0x%llX)
// QuicTraceLogStreamVerbose(
            IndicatePeerReceiveAborted,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED (0x%llX)",
            ErrorCode);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = ErrorCode = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicatePeerReceiveAborted
#define _clog_4_ARGS_TRACE_IndicatePeerReceiveAborted(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_RECV_C, IndicatePeerReceiveAborted , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IgnoreRecvAfterClose
// [strm][%p] Ignoring recv after close
// QuicTraceLogStreamVerbose(
            IgnoreRecvAfterClose,
            Stream,
            "Ignoring recv after close");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IgnoreRecvAfterClose
#define _clog_3_ARGS_TRACE_IgnoreRecvAfterClose(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, IgnoreRecvAfterClose , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IgnoreRecvAfterAbort
// [strm][%p] Ignoring received frame after receive abort
// QuicTraceLogStreamVerbose(
                IgnoreRecvAfterAbort,
                Stream,
                "Ignoring received frame after receive abort");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IgnoreRecvAfterAbort
#define _clog_3_ARGS_TRACE_IgnoreRecvAfterAbort(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, IgnoreRecvAfterAbort , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FlowControlExhausted
// [strm][%p] Flow control window exhausted!
// QuicTraceLogStreamVerbose(
                FlowControlExhausted,
                Stream,
                "Flow control window exhausted!");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_FlowControlExhausted
#define _clog_3_ARGS_TRACE_FlowControlExhausted(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, FlowControlExhausted , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for Receive
// [strm][%p] Received %hu bytes, offset=%llu Ready=%hhu
// QuicTraceLogStreamVerbose(
        Receive,
        Stream,
        "Received %hu bytes, offset=%llu Ready=%hhu",
        (uint16_t)Frame->Length,
        Frame->Offset,
        ReadyToDeliver);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = (uint16_t)Frame->Length = arg3
// arg4 = arg4 = Frame->Offset = arg4
// arg5 = arg5 = ReadyToDeliver = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_Receive
#define _clog_6_ARGS_TRACE_Receive(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_RECV_C, Receive , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RemoteBlocked
// [strm][%p] Remote FC blocked (%llu)
// QuicTraceLogStreamVerbose(
            RemoteBlocked,
            Stream,
            "Remote FC blocked (%llu)",
            Frame.StreamDataLimit);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Frame.StreamDataLimit = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_RemoteBlocked
#define _clog_4_ARGS_TRACE_RemoteBlocked(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_RECV_C, RemoteBlocked , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IncreaseRxBuffer
// [strm][%p] Increasing max RX buffer size to %u (MinRtt=%u; TimeNow=%u; LastUpdate=%u)
// QuicTraceLogStreamVerbose(
                    IncreaseRxBuffer,
                    Stream,
                    "Increasing max RX buffer size to %u (MinRtt=%u; TimeNow=%u; LastUpdate=%u)",
                    Stream->RecvBuffer.VirtualBufferLength * 2,
                    Stream->Connection->Paths[0].MinRtt,
                    TimeNow,
                    Stream->RecvWindowLastUpdate);
// arg1 = arg1 = Stream = arg1
// arg3 = arg3 = Stream->RecvBuffer.VirtualBufferLength * 2 = arg3
// arg4 = arg4 = Stream->Connection->Paths[0].MinRtt = arg4
// arg5 = arg5 = TimeNow = arg5
// arg6 = arg6 = Stream->RecvWindowLastUpdate = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_IncreaseRxBuffer
#define _clog_7_ARGS_TRACE_IncreaseRxBuffer(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_STREAM_RECV_C, IncreaseRxBuffer , arg1, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UpdateFlowControl
// [strm][%p] Updating flow control window
// QuicTraceLogStreamVerbose(
        UpdateFlowControl,
        Stream,
        "Updating flow control window");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_UpdateFlowControl
#define _clog_3_ARGS_TRACE_UpdateFlowControl(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, UpdateFlowControl , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IgnoreRecvFlush
// [strm][%p] Ignoring recv flush (recv disabled)
// QuicTraceLogStreamVerbose(
            IgnoreRecvFlush,
            Stream,
            "Ignoring recv flush (recv disabled)");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IgnoreRecvFlush
#define _clog_3_ARGS_TRACE_IgnoreRecvFlush(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, IgnoreRecvFlush , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerSendShutdown
// [strm][%p] Indicating QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
// QuicTraceLogStreamVerbose(
            IndicatePeerSendShutdown,
            Stream,
            "Indicating QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN");
// arg1 = arg1 = Stream = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicatePeerSendShutdown
#define _clog_3_ARGS_TRACE_IndicatePeerSendShutdown(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_RECV_C, IndicatePeerSendShutdown , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamRecvState
// [strm][%p] Recv State: %hhu
// QuicTraceEvent(
        StreamRecvState,
        "[strm][%p] Recv State: %hhu",
        Stream,
        QuicStreamRecvGetState(Stream));
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = QuicStreamRecvGetState(Stream) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StreamRecvState
#define _clog_4_ARGS_TRACE_StreamRecvState(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_RECV_C, StreamRecvState , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Flush Stream Recv operation",
                0);
// arg2 = arg2 = "Flush Stream Recv operation" = arg2
// arg3 = arg3 = 0 = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_RECV_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamError
// [strm][%p] ERROR, %s.
// QuicTraceEvent(
            StreamError,
            "[strm][%p] ERROR, %s.",
            Stream,
            "Receive on unidirectional stream");
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = "Receive on unidirectional stream" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StreamError
#define _clog_4_ARGS_TRACE_StreamError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_RECV_C, StreamError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamReceiveFrame
// [strm][%p] Processing frame in packet %llu
// QuicTraceEvent(
        StreamReceiveFrame,
        "[strm][%p] Processing frame in packet %llu",
        Stream,
        Packet->PacketId);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Packet->PacketId = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StreamReceiveFrame
#define _clog_4_ARGS_TRACE_StreamReceiveFrame(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_RECV_C, StreamReceiveFrame , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamAppReceive
// [strm][%p] Indicating QUIC_STREAM_EVENT_RECEIVE [%llu bytes, %u buffers, 0x%x flags]
// QuicTraceEvent(
            StreamAppReceive,
            "[strm][%p] Indicating QUIC_STREAM_EVENT_RECEIVE [%llu bytes, %u buffers, 0x%x flags]",
            Stream,
            Event.RECEIVE.TotalBufferLength,
            Event.RECEIVE.BufferCount,
            Event.RECEIVE.Flags);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = Event.RECEIVE.TotalBufferLength = arg3
// arg4 = arg4 = Event.RECEIVE.BufferCount = arg4
// arg5 = arg5 = Event.RECEIVE.Flags = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_StreamAppReceive
#define _clog_6_ARGS_TRACE_StreamAppReceive(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_RECV_C, StreamAppReceive , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StreamAppReceiveComplete
// [strm][%p] Receive complete [%llu bytes]
// QuicTraceEvent(
        StreamAppReceiveComplete,
        "[strm][%p] Receive complete [%llu bytes]",
        Stream,
        BufferLength);
// arg2 = arg2 = Stream = arg2
// arg3 = arg3 = BufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_StreamAppReceiveComplete
#define _clog_4_ARGS_TRACE_StreamAppReceiveComplete(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_RECV_C, StreamAppReceiveComplete , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_stream_recv.c.clog.h.c"
#endif
