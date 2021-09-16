#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_STREAM_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "stream.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_STREAM_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_STREAM_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "stream.c.clog.h.lttng.h"
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
#ifndef _clog_3_ARGS_TRACE_CloseWithoutShutdown



/*----------------------------------------------------------
// Decoder Ring for CloseWithoutShutdown
// [strm][%p] Closing handle without fully shutting down
// QuicTraceLogStreamWarning(
                CloseWithoutShutdown,
                Stream,
                "Closing handle without fully shutting down");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CloseWithoutShutdown(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_C, CloseWithoutShutdown , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_EventSilentDiscard



/*----------------------------------------------------------
// Decoder Ring for EventSilentDiscard
// [strm][%p] Event silently discarded
// QuicTraceLogStreamWarning(
            EventSilentDiscard,
            Stream,
            "Event silently discarded");
// arg1 = arg1 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_EventSilentDiscard(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_STREAM_C, EventSilentDiscard , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdatePriority



/*----------------------------------------------------------
// Decoder Ring for UpdatePriority
// [strm][%p] New send priority = %hu
// QuicTraceLogStreamInfo(
                UpdatePriority,
                Stream,
                "New send priority = %hu",
                Stream->SendPriority);
// arg1 = arg1 = Stream
// arg3 = arg3 = Stream->SendPriority
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdatePriority(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_C, UpdatePriority , arg1, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_IndicateStartComplete



/*----------------------------------------------------------
// Decoder Ring for IndicateStartComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_START_COMPLETE [Status=0x%x ID=%llu Accepted=%hhu]
// QuicTraceLogStreamVerbose(
        IndicateStartComplete,
        Stream,
        "Indicating QUIC_STREAM_EVENT_START_COMPLETE [Status=0x%x ID=%llu Accepted=%hhu]",
        Status,
        Stream->ID,
        Event.START_COMPLETE.PeerAccepted);
// arg1 = arg1 = Stream
// arg3 = arg3 = Status
// arg4 = arg4 = Stream->ID
// arg5 = arg5 = Event.START_COMPLETE.PeerAccepted
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_IndicateStartComplete(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_C, IndicateStartComplete , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_IndicateStreamShutdownComplete



/*----------------------------------------------------------
// Decoder Ring for IndicateStreamShutdownComplete
// [strm][%p] Indicating QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE [ConnectionShutdown=%hhu]
// QuicTraceLogStreamVerbose(
            IndicateStreamShutdownComplete,
            Stream,
            "Indicating QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE [ConnectionShutdown=%hhu]",
            Event.SHUTDOWN_COMPLETE.ConnectionShutdown);
// arg1 = arg1 = Stream
// arg3 = arg3 = Event.SHUTDOWN_COMPLETE.ConnectionShutdown
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_IndicateStreamShutdownComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_C, IndicateStreamShutdownComplete , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_StreamDestroyed



/*----------------------------------------------------------
// Decoder Ring for StreamDestroyed
// [strm][%p] Destroyed
// QuicTraceEvent(
            StreamDestroyed,
            "[strm][%p] Destroyed",
            Stream);
// arg2 = arg2 = Stream
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StreamDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_STREAM_C, StreamDestroyed , arg2);\

#endif




#ifndef _clog_6_ARGS_TRACE_StreamCreated



/*----------------------------------------------------------
// Decoder Ring for StreamCreated
// [strm][%p] Created, Conn=%p ID=%llu IsLocal=%hhu
// QuicTraceEvent(
        StreamCreated,
        "[strm][%p] Created, Conn=%p ID=%llu IsLocal=%hhu",
        Stream,
        Stream->Connection,
        Stream->ID,
        !IsRemoteStream);
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->Connection
// arg4 = arg4 = Stream->ID
// arg5 = arg5 = !IsRemoteStream
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_StreamCreated(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_C, StreamCreated , arg2, arg3, arg4, arg5);\

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
tracepoint(CLOG_STREAM_C, StreamSendState , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_StreamRecvState



/*----------------------------------------------------------
// Decoder Ring for StreamRecvState
// [strm][%p] Recv State: %hhu
// QuicTraceEvent(
        StreamRecvState,
        "[strm][%p] Recv State: %hhu",
        Stream,
        QuicStreamRecvGetState(Stream));
// arg2 = arg2 = Stream
// arg3 = arg3 = QuicStreamRecvGetState(Stream)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StreamRecvState(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_C, StreamRecvState , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_StreamOutFlowBlocked



/*----------------------------------------------------------
// Decoder Ring for StreamOutFlowBlocked
// [strm][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            StreamOutFlowBlocked,
            "[strm][%p] Send Blocked Flags: %hhu",
            Stream,
            Stream->OutFlowBlockedReasons);
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->OutFlowBlockedReasons
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StreamOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_C, StreamOutFlowBlocked , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_StreamRundown



/*----------------------------------------------------------
// Decoder Ring for StreamRundown
// [strm][%p] Rundown, Conn=%p ID=%llu IsLocal=%hhu
// QuicTraceEvent(
        StreamRundown,
        "[strm][%p] Rundown, Conn=%p ID=%llu IsLocal=%hhu",
        Stream,
        Stream->Connection,
        Stream->ID,
        ((QuicConnIsClient(Stream->Connection)) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER)));
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->Connection
// arg4 = arg4 = Stream->ID
// arg5 = arg5 = ((QuicConnIsClient(Stream->Connection)) ^ (Stream->ID & STREAM_ID_FLAG_IS_SERVER))
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_StreamRundown(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_STREAM_C, StreamRundown , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_StreamOutFlowBlocked



/*----------------------------------------------------------
// Decoder Ring for StreamOutFlowBlocked
// [strm][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
        StreamOutFlowBlocked,
        "[strm][%p] Send Blocked Flags: %hhu",
        Stream,
        Stream->OutFlowBlockedReasons);
// arg2 = arg2 = Stream
// arg3 = arg3 = Stream->OutFlowBlockedReasons
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StreamOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_stream.c.clog.h.c"
#endif
