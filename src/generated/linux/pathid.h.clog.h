#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PATHID_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "pathid.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_PATHID_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PATHID_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "pathid.h.clog.h.lttng.h"
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
// Decoder Ring for ConnSourceCidRemoved
// [conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!
// QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p][pathid][%u] (SeqNum=%llu) Removed Source CID: %!CID!",
                    PathID->Connection,
                    PathID->ID,
                    SourceCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = SourceCid->CID.SequenceNumber = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg5
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_ConnSourceCidRemoved
#define _clog_7_ARGS_TRACE_ConnSourceCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len)\
tracepoint(CLOG_PATHID_H, ConnSourceCidRemoved , arg2, arg3, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathInFlowStats
// [conn][%p][pathid][%u] IN: BytesRecv=%llu
// QuicTraceEvent(
        PathInFlowStats,
        "[conn][%p][pathid][%u] IN: BytesRecv=%llu",
        PathID->Connection,
        PathID->ID,
        PathID->Stats.Recv.TotalBytes);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->Stats.Recv.TotalBytes = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathInFlowStats
#define _clog_5_ARGS_TRACE_PathInFlowStats(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PATHID_H, PathInFlowStats , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathStatsV3
// [conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u
// QuicTraceEvent(
        PathStatsV3,
        "[conn][%p][pathid][%u] STATS: SRtt=%llu CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u Cc=%s EcnCongestionCount=%u",
        PathID->Connection,
        PathID->ID,
        PathID->Path->SmoothedRtt,
        PathID->Stats.Send.CongestionCount,
        PathID->Stats.Send.PersistentCongestionCount,
        PathID->Stats.Send.TotalBytes,
        PathID->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&PathID->CongestionControl),
        PathID->CongestionControl.Name,
        PathID->Stats.Send.EcnCongestionCount);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->Path->SmoothedRtt = arg4
// arg5 = arg5 = PathID->Stats.Send.CongestionCount = arg5
// arg6 = arg6 = PathID->Stats.Send.PersistentCongestionCount = arg6
// arg7 = arg7 = PathID->Stats.Send.TotalBytes = arg7
// arg8 = arg8 = PathID->Stats.Recv.TotalBytes = arg8
// arg9 = arg9 = QuicCongestionControlGetCongestionWindow(&PathID->CongestionControl) = arg9
// arg10 = arg10 = PathID->CongestionControl.Name = arg10
// arg11 = arg11 = PathID->Stats.Send.EcnCongestionCount = arg11
----------------------------------------------------------*/
#ifndef _clog_12_ARGS_TRACE_PathStatsV3
#define _clog_12_ARGS_TRACE_PathStatsV3(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11)\
tracepoint(CLOG_PATHID_H, PathStatsV3 , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathPacketStats
// [conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu
// QuicTraceEvent(
        PathPacketStats,
        "[conn][%p][pathid][%u] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        PathID->Connection,
        PathID->ID,
        PathID->Stats.Send.TotalPackets,
        PathID->Stats.Send.SuspectedLostPackets,
        PathID->Stats.Send.SpuriousLostPackets,
        PathID->Stats.Recv.TotalPackets,
        PathID->Stats.Recv.ReorderedPackets,
        PathID->Stats.Recv.DuplicatePackets,
        PathID->Stats.Recv.DecryptionFailures);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->Stats.Send.TotalPackets = arg4
// arg5 = arg5 = PathID->Stats.Send.SuspectedLostPackets = arg5
// arg6 = arg6 = PathID->Stats.Send.SpuriousLostPackets = arg6
// arg7 = arg7 = PathID->Stats.Recv.TotalPackets = arg7
// arg8 = arg8 = PathID->Stats.Recv.ReorderedPackets = arg8
// arg9 = arg9 = PathID->Stats.Recv.DuplicatePackets = arg9
// arg10 = arg10 = PathID->Stats.Recv.DecryptionFailures = arg10
----------------------------------------------------------*/
#ifndef _clog_11_ARGS_TRACE_PathPacketStats
#define _clog_11_ARGS_TRACE_PathPacketStats(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_PATHID_H, PathPacketStats , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathOutFlowBlocked
// [conn][%p][pathid][%hhu] Send Blocked Flags: %hhu
// QuicTraceEvent(
            PathOutFlowBlocked,
            "[conn][%p][pathid][%hhu] Send Blocked Flags: %hhu",
            PathID->Connection,
            PathID->ID,
            PathID->OutFlowBlockedReasons);
// arg2 = arg2 = PathID->Connection = arg2
// arg3 = arg3 = PathID->ID = arg3
// arg4 = arg4 = PathID->OutFlowBlockedReasons = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathOutFlowBlocked
#define _clog_5_ARGS_TRACE_PathOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PATHID_H, PathOutFlowBlocked , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_pathid.h.clog.h.c"
#endif
