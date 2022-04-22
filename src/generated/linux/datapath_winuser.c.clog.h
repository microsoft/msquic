#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_WINUSER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_winuser.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_WINUSER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_WINUSER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_winuser.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogWarning
#define _clog_MACRO_QuicTraceLogWarning  1
#define QuicTraceLogWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogError
#define _clog_MACRO_QuicTraceLogError  1
#define QuicTraceLogError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailed
// [data] RSS helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[data] RSS helper socket failed to open, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailed
#define _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathOpenTcpSocketFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssProcessorInfoFailed
// [data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssProcessorInfoFailed,
            "[data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathQueryRssProcessorInfoFailed
#define _clog_3_ARGS_TRACE_DatapathQueryRssProcessorInfoFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryRssProcessorInfoFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailed
// [data] UDP send segmentation helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[data] UDP send segmentation helper socket failed to open, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailed
#define _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathOpenUdpSocketFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSendMsgFailed
// [data] Query for UDP_SEND_MSG_SIZE failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryUdpSendMsgFailed,
            "[data] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailed
#define _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryUdpSendMsgFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRecvMaxCoalescedSizeFailed
// [data] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRecvMaxCoalescedSizeFailed,
            "[data] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailed
#define _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryRecvMaxCoalescedSizeFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathMissingInfo
// [data][%p] WSARecvMsg completion is missing IP_PKTINFO
// QuicTraceLogWarning(
                DatapathMissingInfo,
                "[data][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketProc->Parent);
// arg2 = arg2 = SocketProc->Parent = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathMissingInfo
#define _clog_3_ARGS_TRACE_DatapathMissingInfo(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathMissingInfo , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathRecvEmpty
// [data][%p] Dropping datagram with empty payload.
// QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[data][%p] Dropping datagram with empty payload.",
                SocketProc->Parent);
// arg2 = arg2 = SocketProc->Parent = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathRecvEmpty
#define _clog_3_ARGS_TRACE_DatapathRecvEmpty(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathRecvEmpty , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathUroPreallocExceeded
// [data][%p] Exceeded URO preallocation capacity.
// QuicTraceLogWarning(
                    DatapathUroPreallocExceeded,
                    "[data][%p] Exceeded URO preallocation capacity.",
                    SocketProc->Parent);
// arg2 = arg2 = SocketProc->Parent = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathUroPreallocExceeded
#define _clog_3_ARGS_TRACE_DatapathUroPreallocExceeded(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathUroPreallocExceeded , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownReturn
// [data][%p] Shut down (return)
// QuicTraceLogVerbose(
        DatapathShutDownReturn,
        "[data][%p] Shut down (return)",
        Socket);
// arg2 = arg2 = Socket = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathShutDownReturn
#define _clog_3_ARGS_TRACE_DatapathShutDownReturn(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathShutDownReturn , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathSocketContextComplete
// [data][%p] Socket context shutdown
// QuicTraceLogVerbose(
        DatapathSocketContextComplete,
        "[data][%p] Socket context shutdown",
        SocketProc);
// arg2 = arg2 = SocketProc = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathSocketContextComplete
#define _clog_3_ARGS_TRACE_DatapathSocketContextComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathSocketContextComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownComplete
// [data][%p] Shut down (complete)
// QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            SocketProc->Parent);
// arg2 = arg2 = SocketProc->Parent = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathShutDownComplete
#define _clog_3_ARGS_TRACE_DatapathShutDownComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathShutDownComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathUnreachableWithError
// [data][%p] Received unreachable error (0x%x) from %!ADDR!
// QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[data][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketProc->Parent,
        ErrorCode,
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketProc->Parent = arg2
// arg3 = arg3 = ErrorCode = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr) = arg4
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_DatapathUnreachableWithError
#define _clog_6_ARGS_TRACE_DatapathUnreachableWithError(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathUnreachableWithError , arg2, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathTooLarge
// [data][%p] Received larger than expected datagram from %!ADDR!
// QuicTraceLogVerbose(
            DatapathTooLarge,
            "[data][%p] Received larger than expected datagram from %!ADDR!",
            SocketProc->Parent,
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketProc->Parent = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DatapathTooLarge
#define _clog_5_ARGS_TRACE_DatapathTooLarge(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathTooLarge , arg2, arg3_len, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathWakeupForShutdown
// [data][%p] Datapath wakeup for shutdown
// QuicTraceLogVerbose(
            DatapathWakeupForShutdown,
            "[data][%p] Datapath wakeup for shutdown",
            DatapathProc);
// arg2 = arg2 = DatapathProc = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathWakeupForShutdown
#define _clog_3_ARGS_TRACE_DatapathWakeupForShutdown(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathWakeupForShutdown , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathWakeupForECTimeout
// [data][%p] Datapath wakeup for EC wake or timeout
// QuicTraceLogVerbose(
            DatapathWakeupForECTimeout,
            "[data][%p] Datapath wakeup for EC wake or timeout",
            DatapathProc);
// arg2 = arg2 = DatapathProc = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathWakeupForECTimeout
#define _clog_3_ARGS_TRACE_DatapathWakeupForECTimeout(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathWakeupForECTimeout , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathResolveHostNameFailed
// [%p] Couldn't resolve hostname '%s' to an IP address
// QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
// arg2 = arg2 = Datapath = arg2
// arg3 = arg3 = HostName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DatapathResolveHostNameFailed
#define _clog_4_ARGS_TRACE_DatapathResolveHostNameFailed(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathResolveHostNameFailed , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "SIO_GET_EXTENSION_FUNCTION_POINTER (AcceptEx)");
// arg2 = arg2 = WsaError = arg2
// arg3 = arg3 = "SIO_GET_EXTENSION_FUNCTION_POINTER (AcceptEx)" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINUSER_C, LibraryErrorStatus , arg2, arg3);\

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
tracepoint(CLOG_DATAPATH_WINUSER_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No local unicast addresses found");
// arg2 = arg2 = "No local unicast addresses found" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [data][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress) = arg4
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_DatapathCreated
#define _clog_7_ARGS_TRACE_DatapathCreated(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathCreated , arg2, arg3_len, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "WSASocketW");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = WsaError = arg3
// arg4 = arg4 = "WSASocketW" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathErrorStatus , arg2, arg3, arg4);\

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
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathRecv
// [data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketProc->Parent,
            NumberOfBytesTransferred,
            MessageLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketProc->Parent = arg2
// arg3 = arg3 = NumberOfBytesTransferred = arg3
// arg4 = arg4 = MessageLength = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr) = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr) = arg6
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_DatapathRecv
#define _clog_9_ARGS_TRACE_DatapathRecv(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len, arg6, arg6_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathRecv , arg2, arg3, arg4, arg5_len, arg5, arg6_len, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->TotalSize,
        SendData->WsaBufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->TotalSize = arg3
// arg4 = arg4 = SendData->WsaBufferCount = arg4
// arg5 = arg5 = SendData->SegmentSize = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress) = arg6
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress) = arg7
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_DatapathSend
#define _clog_10_ARGS_TRACE_DatapathSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg6_len, arg7, arg7_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathSend , arg2, arg3, arg4, arg5, arg6_len, arg6, arg7_len, arg7);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_winuser.c.clog.h.c"
#endif
