#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_BBR_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "bbr.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_BBR_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_BBR_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "bbr.c.clog.h.lttng.h"
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
tracepoint(CLOG_BBR_C, IndicateDataAcked , arg1, arg3, arg4, arg5, arg6, arg7, arg8);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnBbr
// [conn][%p] BBR: State=%u RState=%u CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%u
// QuicTraceEvent(
        ConnBbr,
        "[conn][%p] BBR: State=%u RState=%u CongestionWindow=%u BytesInFlight=%u BytesInFlightMax=%u MinRttEst=%lu EstBw=%lu AppLimited=%u",
        Connection,
        Bbr->BbrState,
        Bbr->RecoveryState,
        BbrCongestionControlGetCongestionWindow(Cc),
        Bbr->BytesInFlight,
        Bbr->BytesInFlightMax,
        Bbr->MinRtt,
        BbrCongestionControlGetBandwidth(Cc) / BW_UNIT,
        BbrCongestionControlIsAppLimited(Cc));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Bbr->BbrState = arg3
// arg4 = arg4 = Bbr->RecoveryState = arg4
// arg5 = arg5 = BbrCongestionControlGetCongestionWindow(Cc) = arg5
// arg6 = arg6 = Bbr->BytesInFlight = arg6
// arg7 = arg7 = Bbr->BytesInFlightMax = arg7
// arg8 = arg8 = Bbr->MinRtt = arg8
// arg9 = arg9 = BbrCongestionControlGetBandwidth(Cc) / BW_UNIT = arg9
// arg10 = arg10 = BbrCongestionControlIsAppLimited(Cc) = arg10
----------------------------------------------------------*/
#ifndef _clog_11_ARGS_TRACE_ConnBbr
#define _clog_11_ARGS_TRACE_ConnBbr(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_BBR_C, ConnBbr , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowStatsV2
// [conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu
// QuicTraceEvent(
        ConnOutFlowStatsV2,
        "[conn][%p] OUT: BytesSent=%llu InFlight=%u CWnd=%u ConnFC=%llu ISB=%llu PostedBytes=%llu SRtt=%llu 1Way=%llu",
        Connection,
        Connection->Stats.Send.TotalBytes,
        Bbr->BytesInFlight,
        Bbr->CongestionWindow,
        Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent,
        Connection->SendBuffer.IdealBytes,
        Connection->SendBuffer.PostedBytes,
        Path->GotFirstRttSample ? Path->SmoothedRtt : 0,
        Path->OneWayDelay);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Send.TotalBytes = arg3
// arg4 = arg4 = Bbr->BytesInFlight = arg4
// arg5 = arg5 = Bbr->CongestionWindow = arg5
// arg6 = arg6 = Connection->Send.PeerMaxData - Connection->Send.OrderedStreamBytesSent = arg6
// arg7 = arg7 = Connection->SendBuffer.IdealBytes = arg7
// arg8 = arg8 = Connection->SendBuffer.PostedBytes = arg8
// arg9 = arg9 = Path->GotFirstRttSample ? Path->SmoothedRtt : 0 = arg9
// arg10 = arg10 = Path->OneWayDelay = arg10
----------------------------------------------------------*/
#ifndef _clog_11_ARGS_TRACE_ConnOutFlowStatsV2
#define _clog_11_ARGS_TRACE_ConnOutFlowStatsV2(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_BBR_C, ConnOutFlowStatsV2 , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

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
tracepoint(CLOG_BBR_C, ConnRecoveryExit , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnCongestionV2
// [conn][%p] Congestion event: IsEcn=%hu
// QuicTraceEvent(
        ConnCongestionV2,
        "[conn][%p] Congestion event: IsEcn=%hu",
        Connection,
        FALSE);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = FALSE = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnCongestionV2
#define _clog_4_ARGS_TRACE_ConnCongestionV2(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_BBR_C, ConnCongestionV2 , arg2, arg3);\

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
tracepoint(CLOG_BBR_C, ConnPersistentCongestion , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_bbr.c.clog.h.c"
#endif
