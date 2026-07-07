#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_QMUX_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "qmux.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_QMUX_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_QMUX_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "qmux.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
/*----------------------------------------------------------
// Decoder Ring for ListenerIndicateNewConnection
// [list][%p] Indicating NEW_CONNECTION %p
// QuicTraceLogVerbose(
        ListenerIndicateNewConnection,
        "[list][%p] Indicating NEW_CONNECTION %p",
        Listener,
        Connection);
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Connection = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ListenerIndicateNewConnection
#define _clog_4_ARGS_TRACE_ListenerIndicateNewConnection(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_QMUX_C, ListenerIndicateNewConnection , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IgnoreFrameAfterClose
// [conn][%p] Ignoring frame (%hhu) for already closed stream id = %llu
// QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint8_t)FrameType = arg3
// arg4 = arg4 = // This cast is safe because of the switch cases above.
                    StreamId = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_IgnoreFrameAfterClose
#define _clog_5_ARGS_TRACE_IgnoreFrameAfterClose(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_QMUX_C, IgnoreFrameAfterClose , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TcpConnected
// [conn][%p] TCP connected
// QuicTraceLogConnInfo(
            TcpConnected,
            Connection,
            "TCP connected");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TcpConnected
#define _clog_3_ARGS_TRACE_TcpConnected(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_QMUX_C, TcpConnected , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TcpDisconnected
// [conn][%p] TCP disconnected
// QuicTraceLogConnInfo(
            TcpDisconnected,
            Connection,
            "TCP disconnected");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_TcpDisconnected
#define _clog_3_ARGS_TRACE_TcpDisconnected(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_QMUX_C, TcpDisconnected , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TcpDataReceived
// [conn][%p] TCP data received: %u bytes in %u segments
// QuicTraceLogConnInfo(
        TcpDataReceived,
        Connection,
        "TCP data received: %u bytes in %u segments",
        TotalChainByteLength,
        TotalChainLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TotalChainByteLength = arg3
// arg4 = arg4 = TotalChainLength = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_TcpDataReceived
#define _clog_5_ARGS_TRACE_TcpDataReceived(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_QMUX_C, TcpDataReceived , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TlsHandshakeData
// [conn][%p] TLS handshake data ready to send, length=%u
// QuicTraceLogConnVerbose(
                        TlsHandshakeData,
                        Connection,
                        "TLS handshake data ready to send, length=%u",
                        OutputBuffers[i].Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = OutputBuffers[i].Length = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_TlsHandshakeData
#define _clog_4_ARGS_TRACE_TlsHandshakeData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_QMUX_C, TlsHandshakeData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for QueueDatagrams
// [conn][%p] Queuing %u TCP data
// QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u TCP data",
        RecvDataChainLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = RecvDataChainLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_QueueDatagrams
#define _clog_4_ARGS_TRACE_QueueDatagrams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_QMUX_C, QueueDatagrams , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateConnected
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)
// QuicTraceLogConnVerbose(
                    IndicateConnected,
                    Connection,
                    "Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)",
                    Event.CONNECTED.SessionResumed);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.CONNECTED.SessionResumed = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicateConnected
#define _clog_4_ARGS_TRACE_IndicateConnected(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_QMUX_C, IndicateConnected , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PeerConnFCBlocked
// [conn][%p] Peer Connection FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.DataLimit = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PeerConnFCBlocked
#define _clog_4_ARGS_TRACE_PeerConnFCBlocked(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_QMUX_C, PeerConnFCBlocked , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PeerStreamFCBlocked
// [conn][%p] Peer Streams[%hu] FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.BidirectionalStreams = arg3
// arg4 = arg4 = Frame.StreamLimit = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PeerStreamFCBlocked
#define _clog_5_ARGS_TRACE_PeerStreamFCBlocked(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_QMUX_C, PeerStreamFCBlocked , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerNeedStreamsV2
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s
// QuicTraceLogConnVerbose(
                IndicatePeerNeedStreamsV2,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s",
                Frame.BidirectionalStreams ? "Bidi" : "Unidi"
                );
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.BidirectionalStreams ? "Bidi" : "Unidi" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicatePeerNeedStreamsV2
#define _clog_4_ARGS_TRACE_IndicatePeerNeedStreamsV2(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_QMUX_C, IndicatePeerNeedStreamsV2 , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection QMux",
            sizeof(QUIC_QMUX));
// arg2 = arg2 = "connection QMux" = arg2
// arg3 = arg3 = sizeof(QUIC_QMUX) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_QMUX_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "CxPlatTlsInitialize");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "CxPlatTlsInitialize" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_QMUX_C, ConnErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Frame type decode failure");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Frame type decode failure" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_QMUX_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDelayCloseApplicationError
// [conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.
// QuicTraceEvent(
                    ConnDelayCloseApplicationError,
                    "[conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.",
                    Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnDelayCloseApplicationError
#define _clog_3_ARGS_TRACE_ConnDelayCloseApplicationError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_QMUX_C, ConnDelayCloseApplicationError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnRecvTcpData
// [conn][%p] Recv %u TCP data, %u bytes
// QuicTraceEvent(
        ConnRecvTcpData,
        "[conn][%p] Recv %u TCP data, %u bytes",
        Connection,
        RecvDataChainCount,
        RecvDataChainByteCount);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = RecvDataChainCount = arg3
// arg4 = arg4 = RecvDataChainByteCount = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnRecvTcpData
#define _clog_5_ARGS_TRACE_ConnRecvTcpData(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_QMUX_C, ConnRecvTcpData , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceEvent(
                    ConnHandshakeComplete,
                    "[conn][%p] Handshake complete",
                    Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnHandshakeComplete
#define _clog_3_ARGS_TRACE_ConnHandshakeComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_QMUX_C, ConnHandshakeComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnRecvPacket
// [conn][%p][RX] %hu bytes
// QuicTraceEvent(
                        ConnRecvPacket,
                        "[conn][%p][RX] %hu bytes",
                        Connection,
                        (uint16_t)RecordLength);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint16_t)RecordLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnRecvPacket
#define _clog_4_ARGS_TRACE_ConnRecvPacket(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_QMUX_C, ConnRecvPacket , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnEarlyDataStatus
// [conn][%p] Early data %s
// QuicTraceEvent(
                ConnEarlyDataStatus,
                "[conn][%p] Early data %s",
                Connection,
                "accepted");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "accepted" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnEarlyDataStatus
#define _clog_4_ARGS_TRACE_ConnEarlyDataStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_QMUX_C, ConnEarlyDataStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerErrorStatus
// [list][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ListenerErrorStatus,
            "[list][%p] ERROR, %u, %s.",
            Listener,
            Status,
            "NEW_CONNECTION callback");
// arg2 = arg2 = Listener = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "NEW_CONNECTION callback" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ListenerErrorStatus
#define _clog_5_ARGS_TRACE_ListenerErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_QMUX_C, ListenerErrorStatus , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_qmux.c.clog.h.c"
#endif
