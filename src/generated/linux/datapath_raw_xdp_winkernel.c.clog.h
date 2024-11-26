#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_RAW_XDP_WINKERNEL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_raw_xdp_winkernel.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_RAW_XDP_WINKERNEL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_RAW_XDP_WINKERNEL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_raw_xdp_winkernel.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for XdpQueueStart
// [ xdp][%p] XDP queue start on partition %p
// QuicTraceLogVerbose(
                XdpQueueStart,
                "[ xdp][%p] XDP queue start on partition %p",
                Queue,
                Partition);
// arg2 = arg2 = Queue = arg2
// arg3 = arg3 = Partition = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpQueueStart
#define _clog_4_ARGS_TRACE_XdpQueueStart(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WINKERNEL_C, XdpQueueStart , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpWorkerStart
// [ xdp][%p] XDP partition start, %u queues
// QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP partition start, %u queues",
            Partition,
            QueueCount);
// arg2 = arg2 = Partition = arg2
// arg3 = arg3 = QueueCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpWorkerStart
#define _clog_4_ARGS_TRACE_XdpWorkerStart(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WINKERNEL_C, XdpWorkerStart , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_xdp_winkernel.c.clog.h.c"
#endif
