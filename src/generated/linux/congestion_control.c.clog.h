#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONGESTION_CONTROL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "congestion_control.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONGESTION_CONTROL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONGESTION_CONTROL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "congestion_control.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_7_ARGS_TRACE_ConnCubic



/*----------------------------------------------------------
// Decoder Ring for ConnCubic
// [conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u
// QuicTraceEvent(
        ConnCubic,
        "[conn][%p] CUBIC: SlowStartThreshold=%u K=%u WindowMax=%u WindowLastMax=%u",
        Connection,
        Connection->CongestionControl.SlowStartThreshold,
        Connection->CongestionControl.KCubic,
        Connection->CongestionControl.WindowMax,
        Connection->CongestionControl.WindowLastMax);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->CongestionControl.SlowStartThreshold
// arg4 = arg4 = Connection->CongestionControl.KCubic
// arg5 = arg5 = Connection->CongestionControl.WindowMax
// arg6 = arg6 = Connection->CongestionControl.WindowLastMax
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_ConnCubic(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_CONGESTION_CONTROL_C, ConnCubic , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnCongestion



/*----------------------------------------------------------
// Decoder Ring for ConnCongestion
// [conn][%p] Congestion event
// QuicTraceEvent(
        ConnCongestion,
        "[conn][%p] Congestion event",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnCongestion(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONGESTION_CONTROL_C, ConnCongestion , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnPersistentCongestion



/*----------------------------------------------------------
// Decoder Ring for ConnPersistentCongestion
// [conn][%p] Persistent congestion event
// QuicTraceEvent(
        ConnPersistentCongestion,
        "[conn][%p] Persistent congestion event",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnPersistentCongestion(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONGESTION_CONTROL_C, ConnPersistentCongestion , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnRecoveryExit



/*----------------------------------------------------------
// Decoder Ring for ConnRecoveryExit
// [conn][%p] Recovery complete
// QuicTraceEvent(
                ConnRecoveryExit,
                "[conn][%p] Recovery complete",
                Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnRecoveryExit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONGESTION_CONTROL_C, ConnRecoveryExit , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnSpuriousCongestion



/*----------------------------------------------------------
// Decoder Ring for ConnSpuriousCongestion
// [conn][%p] Spurious congestion event
// QuicTraceEvent(
        ConnSpuriousCongestion,
        "[conn][%p] Spurious congestion event",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnSpuriousCongestion(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONGESTION_CONTROL_C, ConnSpuriousCongestion , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_congestion_control.c.clog.h.c"
#endif
