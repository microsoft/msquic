#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_RAW_XDP_WIN_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_raw_xdp_win.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_RAW_XDP_WIN_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_RAW_XDP_WIN_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_raw_xdp_win.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for GetTxOffloadConfig
// [ lib] %u, %u
// QuicTraceLogInfo(
        GetTxOffloadConfig,
        "[ lib] %u, %u",
        Queue->Interface->ActualIfIndex, *TxChecksumOffload);
// arg2 = arg2 = Queue->Interface->ActualIfIndex = arg2
// arg3 = arg3 = *TxChecksumOffload = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_GetTxOffloadConfig
#define _clog_4_ARGS_TRACE_GetTxOffloadConfig(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, GetTxOffloadConfig , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FoundVF
// [ xdp][%p] Found NetSvc-VF interfaces. NetSvc IfIdx:%lu, VF IfIdx:%lu
// QuicTraceLogInfo(
                            FoundVF,
                            "[ xdp][%p] Found NetSvc-VF interfaces. NetSvc IfIdx:%lu, VF IfIdx:%lu",
                            Xdp,
                            Interface->IfIndex,
                            Interface->ActualIfIndex);
// arg2 = arg2 = Xdp = arg2
// arg3 = arg3 = Interface->IfIndex = arg3
// arg4 = arg4 = Interface->ActualIfIndex = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_FoundVF
#define _clog_5_ARGS_TRACE_FoundVF(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, FoundVF , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpInterfaceQueues
// [ixdp][%p] Initializing %u queues on interface
// QuicTraceLogVerbose(
        XdpInterfaceQueues,
        "[ixdp][%p] Initializing %u queues on interface",
        Interface,
        Interface->QueueCount);
// arg2 = arg2 = Interface = arg2
// arg3 = arg3 = Interface->QueueCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpInterfaceQueues
#define _clog_4_ARGS_TRACE_XdpInterfaceQueues(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpInterfaceQueues , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpInterfaceInitialize
// [ixdp][%p] Initializing interface %u
// QuicTraceLogVerbose(
                    XdpInterfaceInitialize,
                    "[ixdp][%p] Initializing interface %u",
                    Interface,
                    Interface->ActualIfIndex);
// arg2 = arg2 = Interface = arg2
// arg3 = arg3 = Interface->ActualIfIndex = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpInterfaceInitialize
#define _clog_4_ARGS_TRACE_XdpInterfaceInitialize(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpInterfaceInitialize , arg2, arg3);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueStart , arg2, arg3);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpWorkerStart , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpInitialize
// [ xdp][%p] XDP initialized, %u procs
// QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);
// arg2 = arg2 = Xdp = arg2
// arg3 = arg3 = Xdp->PartitionCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpInitialize
#define _clog_4_ARGS_TRACE_XdpInitialize(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpInitialize , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpRelease
// [ xdp][%p] XDP release
// QuicTraceLogVerbose(
        XdpRelease,
        "[ xdp][%p] XDP release",
        Xdp);
// arg2 = arg2 = Xdp = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpRelease
#define _clog_3_ARGS_TRACE_XdpRelease(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpRelease , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpUninitializeComplete
// [ xdp][%p] XDP uninitialize complete
// QuicTraceLogVerbose(
            XdpUninitializeComplete,
            "[ xdp][%p] XDP uninitialize complete",
            Xdp);
// arg2 = arg2 = Xdp = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpUninitializeComplete
#define _clog_3_ARGS_TRACE_XdpUninitializeComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpUninitializeComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpUninitialize
// [ xdp][%p] XDP uninitialize
// QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
// arg2 = arg2 = Xdp = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpUninitialize
#define _clog_3_ARGS_TRACE_XdpUninitialize(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpUninitialize , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpPartitionShutdown
// [ xdp][%p] XDP partition shutdown
// QuicTraceLogVerbose(
            XdpPartitionShutdown,
            "[ xdp][%p] XDP partition shutdown",
            Partition);
// arg2 = arg2 = Partition = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpPartitionShutdown
#define _clog_3_ARGS_TRACE_XdpPartitionShutdown(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpPartitionShutdown , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoRx
// [ xdp][%p] XDP async IO start (RX)
// QuicTraceLogVerbose(
                    XdpQueueAsyncIoRx,
                    "[ xdp][%p] XDP async IO start (RX)",
                    Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpQueueAsyncIoRx
#define _clog_3_ARGS_TRACE_XdpQueueAsyncIoRx(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoRx , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoTx
// [ xdp][%p] XDP async IO start (TX)
// QuicTraceLogVerbose(
                    XdpQueueAsyncIoTx,
                    "[ xdp][%p] XDP async IO start (TX)",
                    Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpQueueAsyncIoTx
#define _clog_3_ARGS_TRACE_XdpQueueAsyncIoTx(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoTx , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoRxComplete
// [ xdp][%p] XDP async IO complete (RX)
// QuicTraceLogVerbose(
        XdpQueueAsyncIoRxComplete,
        "[ xdp][%p] XDP async IO complete (RX)",
        Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpQueueAsyncIoRxComplete
#define _clog_3_ARGS_TRACE_XdpQueueAsyncIoRxComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoRxComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpQueueAsyncIoTxComplete
// [ xdp][%p] XDP async IO complete (TX)
// QuicTraceLogVerbose(
        XdpQueueAsyncIoTxComplete,
        "[ xdp][%p] XDP async IO complete (TX)",
        Queue);
// arg2 = arg2 = Queue = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpQueueAsyncIoTxComplete
#define _clog_3_ARGS_TRACE_XdpQueueAsyncIoTxComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpQueueAsyncIoTxComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpPartitionShutdownComplete
// [ xdp][%p] XDP partition shutdown complete
// QuicTraceLogVerbose(
        XdpPartitionShutdownComplete,
        "[ xdp][%p] XDP partition shutdown complete",
        Partition);
// arg2 = arg2 = Partition = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpPartitionShutdownComplete
#define _clog_3_ARGS_TRACE_XdpPartitionShutdownComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, XdpPartitionShutdownComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind (GetRssQueueProcessors)");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "XskBind (GetRssQueueProcessors)" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP Queues",
            Interface->QueueCount * sizeof(*Interface->Queues));
// arg2 = arg2 = "XDP Queues" = arg2
// arg3 = arg3 = Interface->QueueCount * sizeof(*Interface->Queues) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No more room for rules");
// arg2 = arg2 = "No more room for rules" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_WIN_C, LibraryError , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_xdp_win.c.clog.h.c"
#endif
