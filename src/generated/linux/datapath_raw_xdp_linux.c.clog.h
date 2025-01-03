#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_RAW_XDP_LINUX_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_raw_xdp_linux.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_RAW_XDP_LINUX_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_RAW_XDP_LINUX_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_raw_xdp_linux.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
// Decoder Ring for XdpFailGettingRssQueueCount
// [ xdp] Failed to get RSS queue count for %s
// QuicTraceLogVerbose(
            XdpFailGettingRssQueueCount,
            "[ xdp] Failed to get RSS queue count for %s",
            IfName);
// arg2 = arg2 = IfName = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpFailGettingRssQueueCount
#define _clog_3_ARGS_TRACE_XdpFailGettingRssQueueCount(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpFailGettingRssQueueCount , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpUmemDeleteFails
// [ xdp] Failed to delete Umem
// QuicTraceLogVerbose(
            XdpUmemDeleteFails,
            "[ xdp] Failed to delete Umem");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_XdpUmemDeleteFails
#define _clog_2_ARGS_TRACE_XdpUmemDeleteFails(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUmemDeleteFails );\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpDetachFails
// [ xdp] Failed to detach XDP program from %s. error:%s
// QuicTraceLogVerbose(
            XdpDetachFails,
            "[ xdp] Failed to detach XDP program from %s. error:%s",
            Interface->IfName,
            strerror(-err));
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = strerror(-err) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpDetachFails
#define _clog_4_ARGS_TRACE_XdpDetachFails(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpDetachFails , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for InterfaceFree
// [ xdp][%p] Freeing Interface
// QuicTraceLogVerbose(
        InterfaceFree,
        "[ xdp][%p] Freeing Interface",
        Interface);
// arg2 = arg2 = Interface = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_InterfaceFree
#define _clog_3_ARGS_TRACE_InterfaceFree(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, InterfaceFree , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for QueueFree
// [ xdp][%p] Freeing Queue on Interface:%p
// QuicTraceLogVerbose(
            QueueFree,
            "[ xdp][%p] Freeing Queue on Interface:%p",
            Queue,
            Interface);
// arg2 = arg2 = Queue = arg2
// arg3 = arg3 = Interface = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_QueueFree
#define _clog_4_ARGS_TRACE_QueueFree(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, QueueFree , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpAllocUmem
// [ xdp] Failed to allocate umem
// QuicTraceLogVerbose(
            XdpAllocUmem,
            "[ xdp] Failed to allocate umem");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_XdpAllocUmem
#define _clog_2_ARGS_TRACE_XdpAllocUmem(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpAllocUmem );\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpUmemAllocFails
// [ xdp][umem] Out of UMEM frame, OOM
// QuicTraceLogVerbose(
            XdpUmemAllocFails,
            "[ xdp][umem] Out of UMEM frame, OOM");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_XdpUmemAllocFails
#define _clog_2_ARGS_TRACE_XdpUmemAllocFails(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUmemAllocFails );\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpAttachFails
// [ xdp] Failed to attach XDP program to %s. error:%s
// QuicTraceLogVerbose(
            XdpAttachFails,
            "[ xdp] Failed to attach XDP program to %s. error:%s", Interface->IfName, errmsg);
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = errmsg = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpAttachFails
#define _clog_4_ARGS_TRACE_XdpAttachFails(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpAttachFails , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpAttachSucceeds
// [ xdp] Successfully attach XDP program to %s by mode:%d
// QuicTraceLogVerbose(
        XdpAttachSucceeds,
        "[ xdp] Successfully attach XDP program to %s by mode:%d", Interface->IfName, Interface->AttachMode);
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = Interface->AttachMode = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpAttachSucceeds
#define _clog_4_ARGS_TRACE_XdpAttachSucceeds(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpAttachSucceeds , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpOpenFileError
// [ xdp] Failed to open xdp program %s. error:%s(%d)
// QuicTraceLogVerbose(
            XdpOpenFileError,
            "[ xdp] Failed to open xdp program %s. error:%s(%d)",
            FilePath,
            errmsg,
            err);
// arg2 = arg2 = FilePath = arg2
// arg3 = arg3 = errmsg = arg3
// arg4 = arg4 = err = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_XdpOpenFileError
#define _clog_5_ARGS_TRACE_XdpOpenFileError(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpOpenFileError , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpLoadObject
// [ xdp] Successfully loaded xdp object of %s
// QuicTraceLogVerbose(
    XdpLoadObject,
    "[ xdp] Successfully loaded xdp object of %s",
    FilePath);
// arg2 = arg2 = FilePath = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_XdpLoadObject
#define _clog_3_ARGS_TRACE_XdpLoadObject(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpLoadObject , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpNoXsksMap
// [ xdp] No xsks map found
// QuicTraceLogVerbose(
            XdpNoXsksMap,
            "[ xdp] No xsks map found");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_XdpNoXsksMap
#define _clog_2_ARGS_TRACE_XdpNoXsksMap(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpNoXsksMap );\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpConfigureUmem
// [ xdp] Failed to configure Umem
// QuicTraceLogVerbose(
                XdpConfigureUmem,
                "[ xdp] Failed to configure Umem");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_XdpConfigureUmem
#define _clog_2_ARGS_TRACE_XdpConfigureUmem(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpConfigureUmem );\

#endif




/*----------------------------------------------------------
// Decoder Ring for FailXskSocketCreate
// [ xdp] Failed to create XDP socket for %s. error:%s
// QuicTraceLogVerbose(
                FailXskSocketCreate,
                "[ xdp] Failed to create XDP socket for %s. error:%s", Interface->IfName, strerror(-Ret));
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = strerror(-Ret) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_FailXskSocketCreate
#define _clog_4_ARGS_TRACE_FailXskSocketCreate(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailXskSocketCreate , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FailRxAlloc
// [ xdp][rx  ] OOM for Rx
// QuicTraceLogVerbose(
                    FailRxAlloc,
                    "[ xdp][rx  ] OOM for Rx");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_FailRxAlloc
#define _clog_2_ARGS_TRACE_FailRxAlloc(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailRxAlloc );\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpInitialize , arg2, arg3);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpWorkerStart , arg2, arg3);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpRelease , arg2);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUninitializeComplete , arg2);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpUninitialize , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpSetPortFails
// [ xdp] Failed to set port %d on %s
// QuicTraceLogVerbose(
                        XdpSetPortFails,
                        "[ xdp] Failed to set port %d on %s", port, Interface->IfName);
// arg2 = arg2 = port = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpSetPortFails
#define _clog_4_ARGS_TRACE_XdpSetPortFails(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpSetPortFails , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpDeletePortFails
// [ xdp] Failed to delete port %d on %s
// QuicTraceLogVerbose(
                        XdpDeletePortFails,
                        "[ xdp] Failed to delete port %d on %s", port, Interface->IfName);
// arg2 = arg2 = port = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpDeletePortFails
#define _clog_4_ARGS_TRACE_XdpDeletePortFails(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpDeletePortFails , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpSetIpFails
// [ xdp] Failed to set ipv4 %s on %s
// QuicTraceLogVerbose(
                        XdpSetIpFails,
                        "[ xdp] Failed to set ipv4 %s on %s",
                        inet_ntoa(Interface->Ipv4Address),
                        Interface->IfName);
// arg2 = arg2 = inet_ntoa(Interface->Ipv4Address) = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpSetIpFails
#define _clog_4_ARGS_TRACE_XdpSetIpFails(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpSetIpFails , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpSetIfnameFails
// [ xdp] Failed to set ifname %s on %s
// QuicTraceLogVerbose(
                        XdpSetIfnameFails,
                        "[ xdp] Failed to set ifname %s on %s", Interface->IfName, Interface->IfName);
// arg2 = arg2 = Interface->IfName = arg2
// arg3 = arg3 = Interface->IfName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpSetIfnameFails
#define _clog_4_ARGS_TRACE_XdpSetIfnameFails(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpSetIfnameFails , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FailTxAlloc
// [ xdp][tx  ] OOM for Tx
// QuicTraceLogVerbose(
            FailTxAlloc,
            "[ xdp][tx  ] OOM for Tx");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_FailTxAlloc
#define _clog_2_ARGS_TRACE_FailTxAlloc(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailTxAlloc );\

#endif




/*----------------------------------------------------------
// Decoder Ring for DoneSendTo
// [ xdp][TX  ] Done sendto.
// QuicTraceLogVerbose(
        DoneSendTo,
        "[ xdp][TX  ] Done sendto.");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_DoneSendTo
#define _clog_2_ARGS_TRACE_DoneSendTo(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, DoneSendTo );\

#endif




/*----------------------------------------------------------
// Decoder Ring for ReleaseCons
// [ xdp][cq  ] Release %d from completion queue
// QuicTraceLogVerbose(
            ReleaseCons,
            "[ xdp][cq  ] Release %d from completion queue", Completed);
// arg2 = arg2 = Completed = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ReleaseCons
#define _clog_3_ARGS_TRACE_ReleaseCons(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, ReleaseCons , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FailTxReserve
// [ xdp][tx  ] Failed to reserve
// QuicTraceLogVerbose(
            FailTxReserve,
            "[ xdp][tx  ] Failed to reserve");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_FailTxReserve
#define _clog_2_ARGS_TRACE_FailTxReserve(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, FailTxReserve );\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpPartitionShutdown , arg2);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpPartitionShutdownComplete , arg2);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpQueueAsyncIoRxComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for XdpEpollErrorStatus
// [ xdp]ERROR, %u, %s.
// QuicTraceEvent(
            XdpEpollErrorStatus,
            "[ xdp]ERROR, %u, %s.",
            errno,
            "epoll_ctl failed");
// arg2 = arg2 = errno = arg2
// arg3 = arg3 = "epoll_ctl failed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_XdpEpollErrorStatus
#define _clog_4_ARGS_TRACE_XdpEpollErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, XdpEpollErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatGetInterfaceRssQueueCount");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatGetInterfaceRssQueueCount" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, LibraryErrorStatus , arg2, arg3);\

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
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "no XDP capable interface");
// arg2 = arg2 = "no XDP capable interface" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RxConstructPacket
// [ xdp][rx  ] Constructing Packet from Rx, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
            RxConstructPacket,
            "[ xdp][rx  ] Constructing Packet from Rx, local=%!ADDR!, remote=%!ADDR!",
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.LocalAddress), &Packet->RouteStorage.LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.RemoteAddress), &Packet->RouteStorage.RemoteAddress));
// arg2 = arg2 = CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.LocalAddress), &Packet->RouteStorage.LocalAddress) = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Packet->RouteStorage.RemoteAddress), &Packet->RouteStorage.RemoteAddress) = arg3
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_RxConstructPacket
#define _clog_6_ARGS_TRACE_RxConstructPacket(uniqueId, encoded_arg_string, arg2, arg2_len, arg3, arg3_len)\
tracepoint(CLOG_DATAPATH_RAW_XDP_LINUX_C, RxConstructPacket , arg2_len, arg2, arg3_len, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_raw_xdp_linux.c.clog.h.c"
#endif
