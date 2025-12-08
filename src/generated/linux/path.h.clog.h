#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PATH_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "path.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_PATH_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PATH_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "path.h.clog.h.lttng.h"
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
// Decoder Ring for PathInFlowStats
// [conn][%p][pathid][%u] IN: BytesRecv=%llu
// QuicTraceEvent(
        PathInFlowStats,
        "[conn][%p][pathid][%u] IN: BytesRecv=%llu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->Stats.Recv.TotalBytes);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->Stats.Recv.TotalBytes = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathInFlowStats
#define _clog_5_ARGS_TRACE_PathInFlowStats(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PATH_H, PathInFlowStats , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathStatsV3
// [conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u
// QuicTraceEvent(
        PathStatsV3,
        "[conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->SmoothedRtt,
        Path->Stats.Send.CongestionCount,
        Path->Stats.Send.PersistentCongestionCount,
        Path->Stats.Send.TotalBytes,
        Path->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&Path->CongestionControl),
        Path->CongestionControl.Name,
        Path->Stats.Send.EcnCongestionCount);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->SmoothedRtt = arg4
// arg5 = arg5 = Path->Stats.Send.CongestionCount = arg5
// arg6 = arg6 = Path->Stats.Send.PersistentCongestionCount = arg6
// arg7 = arg7 = Path->Stats.Send.TotalBytes = arg7
// arg8 = arg8 = Path->Stats.Recv.TotalBytes = arg8
// arg9 = arg9 = QuicCongestionControlGetCongestionWindow(&Path->CongestionControl) = arg9
// arg10 = arg10 = Path->CongestionControl.Name = arg10
// arg11 = arg11 = Path->Stats.Send.EcnCongestionCount = arg11
----------------------------------------------------------*/
#ifndef _clog_12_ARGS_TRACE_PathStatsV3
#define _clog_12_ARGS_TRACE_PathStatsV3(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11)\
tracepoint(CLOG_PATH_H, PathStatsV3 , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathPacketStats
// [conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu
// QuicTraceEvent(
        PathPacketStats,
        "[conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        Path->PathID->Connection,
        Path->PathID->ID,
        Path->Stats.Send.TotalPackets,
        Path->Stats.Send.SuspectedLostPackets,
        Path->Stats.Send.SpuriousLostPackets,
        Path->Stats.Recv.TotalPackets,
        Path->Stats.Recv.ReorderedPackets,
        Path->Stats.Recv.DuplicatePackets,
        Path->Stats.Recv.DecryptionFailures);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->Stats.Send.TotalPackets = arg4
// arg5 = arg5 = Path->Stats.Send.SuspectedLostPackets = arg5
// arg6 = arg6 = Path->Stats.Send.SpuriousLostPackets = arg6
// arg7 = arg7 = Path->Stats.Recv.TotalPackets = arg7
// arg8 = arg8 = Path->Stats.Recv.ReorderedPackets = arg8
// arg9 = arg9 = Path->Stats.Recv.DuplicatePackets = arg9
// arg10 = arg10 = Path->Stats.Recv.DecryptionFailures = arg10
----------------------------------------------------------*/
#ifndef _clog_11_ARGS_TRACE_PathPacketStats
#define _clog_11_ARGS_TRACE_PathPacketStats(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_PATH_H, PathPacketStats , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathOutFlowBlocked
// [conn][%p][pathid][%hhu] Send Blocked Flags: %hhu
// QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            Path->PathID->Connection,
            Path->PathID->ID,
            Path->OutFlowBlockedReasons);
// arg2 = arg2 = Path->PathID->Connection = arg2
// arg3 = arg3 = Path->PathID->ID = arg3
// arg4 = arg4 = Path->OutFlowBlockedReasons = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathOutFlowBlocked
#define _clog_5_ARGS_TRACE_PathOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PATH_H, PathOutFlowBlocked , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_path.h.clog.h.c"
#endif
