#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONNECTION_H
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "connection.h.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONNECTION_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONNECTION_H
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "connection.h.clog.h.lttng.h"
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
// Decoder Ring for ConnOutFlowStreamStats
// [conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu
// QuicTraceEvent(
        ConnOutFlowStreamStats,
        "[conn][%p] OUT: StreamFC=%llu StreamSendWindow=%llu",
        Connection,
        FcAvailable,
        SendWindow);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = FcAvailable = arg3
// arg4 = arg4 = SendWindow = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnOutFlowStreamStats
#define _clog_5_ARGS_TRACE_ConnOutFlowStreamStats(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_H, ConnOutFlowStreamStats , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnInFlowStats
// [conn][%p] IN: BytesRecv=%llu
// QuicTraceEvent(
        ConnInFlowStats,
        "[conn][%p] IN: BytesRecv=%llu",
        Connection,
        Connection->Stats.Recv.TotalBytes);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Recv.TotalBytes = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnInFlowStats
#define _clog_4_ARGS_TRACE_ConnInFlowStats(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_H, ConnInFlowStats , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnStats
// [conn][%p] STATS: SRtt=%u CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u
// QuicTraceEvent(
        ConnStats,
        "[conn][%p] STATS: SRtt=%u CongestionCount=%u PersistentCongestionCount=%u SendTotalBytes=%llu RecvTotalBytes=%llu CongestionWindow=%u",
        Connection,
        Path->SmoothedRtt,
        Connection->Stats.Send.CongestionCount,
        Connection->Stats.Send.PersistentCongestionCount,
        Connection->Stats.Send.TotalBytes,
        Connection->Stats.Recv.TotalBytes,
        QuicCongestionControlGetCongestionWindow(&Connection->CongestionControl));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->SmoothedRtt = arg3
// arg4 = arg4 = Connection->Stats.Send.CongestionCount = arg4
// arg5 = arg5 = Connection->Stats.Send.PersistentCongestionCount = arg5
// arg6 = arg6 = Connection->Stats.Send.TotalBytes = arg6
// arg7 = arg7 = Connection->Stats.Recv.TotalBytes = arg7
// arg8 = arg8 = QuicCongestionControlGetCongestionWindow(&Connection->CongestionControl) = arg8
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_ConnStats
#define _clog_9_ARGS_TRACE_ConnStats(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8)\
tracepoint(CLOG_CONNECTION_H, ConnStats , arg2, arg3, arg4, arg5, arg6, arg7, arg8);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPacketStats
// [conn][%p] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu
// QuicTraceEvent(
        ConnPacketStats,
        "[conn][%p] STATS: SendTotalPackets=%llu SendSuspectedLostPackets=%llu SendSpuriousLostPackets=%llu RecvTotalPackets=%llu RecvReorderedPackets=%llu RecvDroppedPackets=%llu RecvDuplicatePackets=%llu RecvDecryptionFailures=%llu",
        Connection,
        Connection->Stats.Send.TotalPackets,
        Connection->Stats.Send.SuspectedLostPackets,
        Connection->Stats.Send.SpuriousLostPackets,
        Connection->Stats.Recv.TotalPackets,
        Connection->Stats.Recv.ReorderedPackets,
        Connection->Stats.Recv.DroppedPackets,
        Connection->Stats.Recv.DuplicatePackets,
        Connection->Stats.Recv.DecryptionFailures);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.Send.TotalPackets = arg3
// arg4 = arg4 = Connection->Stats.Send.SuspectedLostPackets = arg4
// arg5 = arg5 = Connection->Stats.Send.SpuriousLostPackets = arg5
// arg6 = arg6 = Connection->Stats.Recv.TotalPackets = arg6
// arg7 = arg7 = Connection->Stats.Recv.ReorderedPackets = arg7
// arg8 = arg8 = Connection->Stats.Recv.DroppedPackets = arg8
// arg9 = arg9 = Connection->Stats.Recv.DuplicatePackets = arg9
// arg10 = arg10 = Connection->Stats.Recv.DecryptionFailures = arg10
----------------------------------------------------------*/
#ifndef _clog_11_ARGS_TRACE_ConnPacketStats
#define _clog_11_ARGS_TRACE_ConnPacketStats(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)\
tracepoint(CLOG_CONNECTION_H, ConnPacketStats , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnOutFlowBlocked
// [conn][%p] Send Blocked Flags: %hhu
// QuicTraceEvent(
            ConnOutFlowBlocked,
            "[conn][%p] Send Blocked Flags: %hhu",
            Connection,
            Connection->OutFlowBlockedReasons);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->OutFlowBlockedReasons = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnOutFlowBlocked
#define _clog_4_ARGS_TRACE_ConnOutFlowBlocked(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_H, ConnOutFlowBlocked , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!
// QuicTraceEvent(
                    ConnSourceCidRemoved,
                    "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                    Connection,
                    SourceCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = SourceCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg4
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnSourceCidRemoved
#define _clog_6_ARGS_TRACE_ConnSourceCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_H, ConnSourceCidRemoved , arg2, arg3, arg4_len, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_connection.h.clog.h.c"
#endif
