#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_STREAM_SET_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "stream_set.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_STREAM_SET_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_STREAM_SET_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "stream_set.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogStreamWarning
#define _clog_MACRO_QuicTraceLogStreamWarning  1
#define QuicTraceLogStreamWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
#ifndef _clog_4_ARGS_TRACE_NotAccepted



/*----------------------------------------------------------
// Decoder Ring for NotAccepted
// [strm][%p] New stream wasn't accepted, 0x%x
// QuicTraceLogStreamWarning(
                    NotAccepted,
                    Stream,
                    "New stream wasn't accepted, 0x%x",
                    Status);
// arg1 = arg1 = Stream
// arg3 = arg3 = Status
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_NotAccepted(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_STREAM_SET_C, NotAccepted , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_MaxStreamCountUpdated



/*----------------------------------------------------------
// Decoder Ring for MaxStreamCountUpdated
// [conn][%p] App configured max stream count of %hu (type=%hhu).
// QuicTraceLogConnInfo(
        MaxStreamCountUpdated,
        Connection,
        "App configured max stream count of %hu (type=%hhu).",
        Count,
        Type);
// arg1 = arg1 = Connection
// arg3 = arg3 = Count
// arg4 = arg4 = Type
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_MaxStreamCountUpdated(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_STREAM_SET_C, MaxStreamCountUpdated , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_IndicateStreamsAvailable



/*----------------------------------------------------------
// Decoder Ring for IndicateStreamsAvailable
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE [%hu] [%hu]
// QuicTraceLogConnVerbose(
        IndicateStreamsAvailable,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE [%hu] [%hu]",
        Event.STREAMS_AVAILABLE.BidirectionalCount,
        Event.STREAMS_AVAILABLE.UnidirectionalCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = Event.STREAMS_AVAILABLE.BidirectionalCount
// arg4 = arg4 = Event.STREAMS_AVAILABLE.UnidirectionalCount
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_IndicateStreamsAvailable(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_STREAM_SET_C, IndicateStreamsAvailable , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_PeerStreamCountsUpdated



/*----------------------------------------------------------
// Decoder Ring for PeerStreamCountsUpdated
// [conn][%p] Peer updated max stream count (%hhu, %llu).
// QuicTraceLogConnVerbose(
            PeerStreamCountsUpdated,
            Connection,
            "Peer updated max stream count (%hhu, %llu).",
            BidirectionalStreams,
            MaxStreams);
// arg1 = arg1 = Connection
// arg3 = arg3 = BidirectionalStreams
// arg4 = arg4 = MaxStreams
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_PeerStreamCountsUpdated(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_STREAM_SET_C, PeerStreamCountsUpdated , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_IndicatePeerStreamStarted



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerStreamStarted
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED [%p, 0x%x]
// QuicTraceLogConnVerbose(
                IndicatePeerStreamStarted,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED [%p, 0x%x]",
                Event.PEER_STREAM_STARTED.Stream,
                Event.PEER_STREAM_STARTED.Flags);
// arg1 = arg1 = Connection
// arg3 = arg3 = Event.PEER_STREAM_STARTED.Stream
// arg4 = arg4 = Event.PEER_STREAM_STARTED.Flags
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_IndicatePeerStreamStarted(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_STREAM_SET_C, IndicatePeerStreamStarted , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "streamset hash table",
                0);
// arg2 = arg2 = "streamset hash table"
// arg3 = arg3 = 0
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_SET_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer used more streams than allowed");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Peer used more streams than allowed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_STREAM_SET_C, ConnError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Remote tried to open stream it wasn't allowed to open.");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Remote tried to open stream it wasn't allowed to open."
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_stream_set.c.clog.h.c"
#endif
