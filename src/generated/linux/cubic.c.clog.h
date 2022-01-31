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
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for ConnCubic
// [conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u
// QuicTraceEvent(
        ConnCubic,
        "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Connection,
        Cubic->SlowStartThreshold,
        Cubic->KCubic,
        Cubic->WindowMax,
        Cubic->WindowLastMax);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Cubic->SlowStartThreshold = arg3
// arg4 = arg4 = Cubic->KCubic = arg4
// arg5 = arg5 = Cubic->WindowMax = arg5
// arg6 = arg6 = Cubic->WindowLastMax = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnCubic
#define _clog_7_ARGS_TRACE_ConnCubic(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_CUBIC_C, ConnCubic , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnCongestion
// [conn][%p] Congestion event
// QuicTraceEvent(
        ConnCongestion,
        "[conn][%p] Congestion event",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnCongestion
#define _clog_3_ARGS_TRACE_ConnCongestion(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CUBIC_C, ConnCongestion , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPersistentCongestion
// [conn][%p] Persistent congestion event
// QuicTraceEvent(
            ConnPersistentCongestion,
            "[conn][%p] Persistent congestion event",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnPersistentCongestion
#define _clog_3_ARGS_TRACE_ConnPersistentCongestion(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CUBIC_C, ConnPersistentCongestion , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnRecoveryExit
// [conn][%p] Recovery complete
// QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnRecoveryExit
#define _clog_3_ARGS_TRACE_ConnRecoveryExit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CUBIC_C, ConnRecoveryExit , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnSpuriousCongestion
// [conn][%p] Spurious congestion event
// QuicTraceEvent(
        ConnSpuriousCongestion,
        "[conn][%p] Spurious congestion event",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnSpuriousCongestion
#define _clog_3_ARGS_TRACE_ConnSpuriousCongestion(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CUBIC_C, ConnSpuriousCongestion , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowStats
// [conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u
// QuicTraceEvent(
        ConnOutFlowStats,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u InFlightMax=%u CWnd=%u SSThresh=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%u",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Cubic->BytesInFlight,
        Cubic->BytesInFlightMax,
        Cubic->CongestionWindow,
        Cubic->SlowStartThreshold,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Send.TotalBytes = arg3
// arg4 = arg4 = Cubic->BytesInFlight = arg4
// arg5 = arg5 = Cubic->BytesInFlightMax = arg5
// arg6 = arg6 = Cubic->CongestionWindow = arg6
// arg7 = arg7 = Cubic->SlowStartThreshold = arg7
// arg8 = arg8 = Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent = arg8
// arg9 = arg9 = Connection->SendBuffer.IdealBytes = arg9
// arg10 = arg10 = Connection->SendBuffer.PostedBytes = arg10
// arg11 = arg11 = Path->GotFirstRttSample ? Path->SmoothedRtt : 0 = arg11
----------------------------------------------------------*/
#ifndef _clog_12_ARGS_TRACE_ConnOutFlowStats
#define _clog_12_ARGS_TRACE_ConnOutFlowStats(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11)\
tracepoint(CLOG_CUBIC_C, ConnOutFlowStats , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_cubic.c.clog.h.c"
#endif
