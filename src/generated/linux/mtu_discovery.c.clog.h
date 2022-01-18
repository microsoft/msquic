#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_MTU_DISCOVERY_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "mtu_discovery.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_MTU_DISCOVERY_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_MTU_DISCOVERY_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "mtu_discovery.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for MtuSearchComplete
// [conn][%p] Path[%hhu] Mtu Discovery Entering Search Complete at MTU %hu
// QuicTraceLogConnInfo(
        MtuSearchComplete,
        Connection,
        "Path[%hhu] Mtu Discovery Entering Search Complete at MTU %hu",
        Path->ID,
        Path->Mtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Path->Mtu = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_MtuSearchComplete
#define _clog_5_ARGS_TRACE_MtuSearchComplete(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_MTU_DISCOVERY_C, MtuSearchComplete , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for MtuSearching
// [conn][%p] Path[%hhu] Mtu Discovery Search Packet Sending with MTU %hu
// QuicTraceLogConnInfo(
        MtuSearching,
        Connection,
        "Path[%hhu] Mtu Discovery Search Packet Sending with MTU %hu",
        Path->ID,
        MtuDiscovery->ProbeSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->ProbeSize = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_MtuSearching
#define _clog_5_ARGS_TRACE_MtuSearching(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_MTU_DISCOVERY_C, MtuSearching , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for MtuPathInitialized
// [conn][%p] Path[%hhu] Mtu Discovery Initialized: max_mtu=%u, cur/min_mtu=%u
// QuicTraceLogConnInfo(
        MtuPathInitialized,
        Connection,
        "Path[%hhu] Mtu Discovery Initialized: max_mtu=%u, cur/min_mtu=%u",
        Path->ID,
        MtuDiscovery->MaxMtu,
        Path->Mtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->MaxMtu = arg4
// arg5 = arg5 = Path->Mtu = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_MtuPathInitialized
#define _clog_6_ARGS_TRACE_MtuPathInitialized(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_MTU_DISCOVERY_C, MtuPathInitialized , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathMtuUpdated
// [conn][%p] Path[%hhu] MTU updated to %hu bytes
// QuicTraceLogConnInfo(
        PathMtuUpdated,
        Connection,
        "Path[%hhu] MTU updated to %hu bytes",
        Path->ID,
        Path->Mtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = Path->Mtu = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PathMtuUpdated
#define _clog_5_ARGS_TRACE_PathMtuUpdated(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_MTU_DISCOVERY_C, PathMtuUpdated , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for MtuDiscarded
// [conn][%p] Path[%hhu] Mtu Discovery Packet Discarded: size=%u, probe_count=%u
// QuicTraceLogConnInfo(
        MtuDiscarded,
        Connection,
        "Path[%hhu] Mtu Discovery Packet Discarded: size=%u, probe_count=%u",
        Path->ID,
        MtuDiscovery->ProbeSize,
        MtuDiscovery->ProbeCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->ProbeSize = arg4
// arg5 = arg5 = MtuDiscovery->ProbeCount = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_MtuDiscarded
#define _clog_6_ARGS_TRACE_MtuDiscarded(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_MTU_DISCOVERY_C, MtuDiscarded , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for MtuIncorrectSize
// [conn][%p] Path[%hhu] Mtu Discovery Received Out of Order: expected=%u received=%u
// QuicTraceLogConnVerbose(
            MtuIncorrectSize,
            Connection,
            "Path[%hhu] Mtu Discovery Received Out of Order: expected=%u received=%u",
            Path->ID,
            MtuDiscovery->ProbeSize,
            PacketMtu);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->ID = arg3
// arg4 = arg4 = MtuDiscovery->ProbeSize = arg4
// arg5 = arg5 = PacketMtu = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_MtuIncorrectSize
#define _clog_6_ARGS_TRACE_MtuIncorrectSize(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_MTU_DISCOVERY_C, MtuIncorrectSize , arg1, arg3, arg4, arg5);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_mtu_discovery.c.clog.h.c"
#endif
