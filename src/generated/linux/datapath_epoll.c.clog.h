#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_EPOLL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_epoll.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_EPOLL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_EPOLL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_epoll.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogWarning
#define _clog_MACRO_QuicTraceLogWarning  1
#define QuicTraceLogWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for DatapathRecvEmpty
// [data][%p] Dropping datagram with empty payload.
// QuicTraceLogWarning(
            DatapathRecvEmpty,
            "[data][%p] Dropping datagram with empty payload.",
            SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathRecvEmpty
#define _clog_3_ARGS_TRACE_DatapathRecvEmpty(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_EPOLL_C, DatapathRecvEmpty , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
// arg2 = arg2 = "CXPLAT_DATAPATH" = arg2
// arg3 = arg3 = DatapathLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_EPOLL_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed");
// arg2 = arg2 = SocketContext->Binding = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_EPOLL_C, DatapathErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [data][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress) = arg4
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_DatapathCreated
#define _clog_7_ARGS_TRACE_DatapathCreated(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_EPOLL_C, DatapathCreated , arg2, arg3_len, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathDestroyed
// [data][%p] Destroyed
// QuicTraceEvent(
        DatapathDestroyed,
        "[data][%p] Destroyed",
        Socket);
// arg2 = arg2 = Socket = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathDestroyed
#define _clog_3_ARGS_TRACE_DatapathDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_EPOLL_C, DatapathDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathRecv
// [data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            RecvMsgHdr[CurrentMessage].msg_len,
            SegmentLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding = arg2
// arg3 = arg3 = RecvMsgHdr[CurrentMessage].msg_len = arg3
// arg4 = arg4 = SegmentLength = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr) = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr) = arg6
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_DatapathRecv
#define _clog_9_ARGS_TRACE_DatapathRecv(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len, arg6, arg6_len)\
tracepoint(CLOG_DATAPATH_EPOLL_C, DatapathRecv , arg2, arg3, arg4, arg5_len, arg5, arg6_len, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->TotalSize,
        SendData->BufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->TotalSize = arg3
// arg4 = arg4 = SendData->BufferCount = arg4
// arg5 = arg5 = SendData->SegmentSize = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg6
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg7
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_DatapathSend
#define _clog_10_ARGS_TRACE_DatapathSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg6_len, arg7, arg7_len)\
tracepoint(CLOG_DATAPATH_EPOLL_C, DatapathSend , arg2, arg3, arg4, arg5, arg6_len, arg6, arg7_len, arg7);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Disabling segmentation support globally");
// arg2 = arg2 = "Disabling segmentation support globally" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_EPOLL_C, LibraryError , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_epoll.c.clog.h.c"
#endif
