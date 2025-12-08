#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CUBIC_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "cubic.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CUBIC_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CUBIC_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "cubic.c.clog.h.lttng.h"
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
// Decoder Ring for IndicateDataAcked
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]
// QuicTraceLogConnVerbose(
           IndicateDataAcked,
           Connection,
           "Indicating QUIC_CONNECTION_EVENT_NETWORK_STATISTICS [BytesInFlight=%u,PostedBytes=%llu,IdealBytes=%llu,SmoothedRTT=%llu,CongestionWindow=%u,Bandwidth=%llu]",
           Event.NETWORK_STATISTICS.BytesInFlight,
           Event.NETWORK_STATISTICS.PostedBytes,
           Event.NETWORK_STATISTICS.IdealBytes,
           Event.NETWORK_STATISTICS.SmoothedRTT,
           Event.NETWORK_STATISTICS.CongestionWindow,
           Event.NETWORK_STATISTICS.Bandwidth);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.NETWORK_STATISTICS.BytesInFlight = arg3
// arg4 = arg4 = Event.NETWORK_STATISTICS.PostedBytes = arg4
// arg5 = arg5 = Event.NETWORK_STATISTICS.IdealBytes = arg5
// arg6 = arg6 = Event.NETWORK_STATISTICS.SmoothedRTT = arg6
// arg7 = arg7 = Event.NETWORK_STATISTICS.CongestionWindow = arg7
// arg8 = arg8 = Event.NETWORK_STATISTICS.Bandwidth = arg8
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_IndicateDataAcked
#define _clog_9_ARGS_TRACE_IndicateDataAcked(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6, arg7, arg8)\
tracepoint(CLOG_CUBIC_C, IndicateDataAcked , arg1, arg3, arg4, arg5, arg6, arg7, arg8);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathCubic
// [conn][%p][pathid][%hhu] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u
// QuicTraceEvent(
        PathCubic,
        "[conn][%p][pathid][%hhu] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Path->PathID->Connection,
        Path->PathID->ID,
        Cubic->SlowStartThreshold,
        Cubic->KCubic,
        Cubic->WindowMax,
        Cubic->WindowLastMax);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Cubic->SlowStartThreshold = arg4
// arg5 = arg5 = Cubic->KCubic = arg5
// arg6 = arg6 = Cubic->WindowMax = arg6
// arg7 = arg7 = Cubic->WindowLastMax = arg7
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_PathCubic
#define _clog_8_ARGS_TRACE_PathCubic(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_CUBIC_C, PathCubic , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathHyStartStateChange
// [conn][%p][pathid][%hhu] HyStart: State=%u CongestionWindow=%u SlowStartThreshold=%u
// QuicTraceEvent(
            PathHyStartStateChange,
            "[conn][%p][pathid][%hhu] HyStart: State=%u CongestionWindow=%u SlowStartThreshold=%u",
            Connection,
            Path->PathID->ID,
            NewHyStartState,
            Cubic->CongestionWindow,
            Cubic->SlowStartThreshold);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = NewHyStartState = arg4
// arg5 = arg5 = Cubic->CongestionWindow = arg5
// arg6 = arg6 = Cubic->SlowStartThreshold = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_PathHyStartStateChange
#define _clog_7_ARGS_TRACE_PathHyStartStateChange(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_CUBIC_C, PathHyStartStateChange , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathCongestionV2
// [conn][%p][pathid][%hhu] Congestion event: IsEcn=%hu
// QuicTraceEvent(
        PathCongestionV2,
        "[conn][%p][pathid][%hhu] Congestion event: IsEcn=%hu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Ecn);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Ecn = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathCongestionV2
#define _clog_5_ARGS_TRACE_PathCongestionV2(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CUBIC_C, PathCongestionV2 , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathPersistentCongestion
// [conn][%p][pathid][%hhu] Persistent congestion event
// QuicTraceEvent(
            PathPersistentCongestion,
            "[conn][%p][pathid][%hhu] Persistent congestion event",
            Path->PathID->Connection,
            Path->PathID->ID);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathPersistentCongestion
#define _clog_4_ARGS_TRACE_PathPersistentCongestion(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CUBIC_C, PathPersistentCongestion , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathRecoveryExit
// [conn][%p][pathid][%hhu] Recovery complete
// QuicTraceEvent(
                PathRecoveryExit,
                "[conn][%p][pathid][%hhu] Recovery complete",
                Path->PathID->Connection,
                Path->PathID->ID);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathRecoveryExit
#define _clog_4_ARGS_TRACE_PathRecoveryExit(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CUBIC_C, PathRecoveryExit , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathSpuriousCongestion
// [conn][%p][pathid][%hhu] Spurious congestion event
// QuicTraceEvent(
        PathSpuriousCongestion,
        "[conn][%p][pathid][%hhu] Spurious congestion event",
        Path->PathID->Connection,
        Path->PathID->ID);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathSpuriousCongestion
#define _clog_4_ARGS_TRACE_PathSpuriousCongestion(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CUBIC_C, PathSpuriousCongestion , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowStatsV2
// [conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu
// QuicTraceEvent(
        ConnOutFlowStatsV2,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Cubic->BytesInFlight,
        Cubic->CongestionWindow,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0,
        Path->OneWayDelay);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Send.TotalBytes = arg3
// arg4 = arg4 = Cubic->BytesInFlight = arg4
// arg5 = arg5 = Cubic->CongestionWindow = arg5
// arg6 = arg6 = Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent = arg6
// arg7 = arg7 = Connection->SendBuffer.IdealBytes = arg7
// arg8 = arg8 = Connection->SendBuffer.PostedBytes = arg8
// arg9 = arg9 = Path->GotFirstRttSample ? Path->SmoothedRtt : 0 = arg9
// arg10 = arg10 = Path->OneWayDelay = arg10
----------------------------------------------------------*/
#ifndef _clog_11_ARGS_TRACE_ConnOutFlowStatsV2
#define _clog_11_ARGS_TRACE_ConnOutFlowStatsV2(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_CUBIC_C, ConnOutFlowStatsV2 , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_cubic.c.clog.h.c"
#endif
