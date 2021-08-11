#include <clog.h>
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
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
#ifndef _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailed
// [ udp] RSS helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[ udp] RSS helper socket failed to open, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathOpenTcpSocketFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryRssProcessorInfoFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssProcessorInfoFailed
// [ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssProcessorInfoFailed,
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryRssProcessorInfoFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryRssProcessorInfoFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailed
// [ udp] UDP send segmentation helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[ udp] UDP send segmentation helper socket failed to open, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathOpenUdpSocketFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSendMsgFailed
// [ udp] Query for UDP_SEND_MSG_SIZE failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryUdpSendMsgFailed,
            "[ udp] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryUdpSendMsgFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRecvMaxCoalescedSizeFailed
// [ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRecvMaxCoalescedSizeFailed,
            "[ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
            WsaError);
// arg2 = arg2 = WsaError
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryRecvMaxCoalescedSizeFailed , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_DatapathQueryProcessorAffinityFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryProcessorAffinityFailed
// [ udp][%p] WSAIoctl for SIO_QUERY_RSS_PROCESSOR_INFO failed, 0x%x
// QuicTraceLogWarning(
                        DatapathQueryProcessorAffinityFailed,
                        "[ udp][%p] WSAIoctl for SIO_QUERY_RSS_PROCESSOR_INFO failed, 0x%x",
                        Binding,
                        WsaError);
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_DatapathQueryProcessorAffinityFailed(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathQueryProcessorAffinityFailed , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathMissingInfo



/*----------------------------------------------------------
// Decoder Ring for DatapathMissingInfo
// [ udp][%p] WSARecvMsg completion is missing IP_PKTINFO
// QuicTraceLogWarning(
                DatapathMissingInfo,
                "[ udp][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathMissingInfo(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathMissingInfo , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathRecvEmpty



/*----------------------------------------------------------
// Decoder Ring for DatapathRecvEmpty
// [ udp][%p] Dropping datagram with empty payload.
// QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[ udp][%p] Dropping datagram with empty payload.",
                SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathRecvEmpty(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathRecvEmpty , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathUroPreallocExceeded



/*----------------------------------------------------------
// Decoder Ring for DatapathUroPreallocExceeded
// [ udp][%p] Exceeded URO preallocation capacity.
// QuicTraceLogWarning(
                    DatapathUroPreallocExceeded,
                    "[ udp][%p] Exceeded URO preallocation capacity.",
                    SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathUroPreallocExceeded(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathUroPreallocExceeded , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathWorkerThreadStart



/*----------------------------------------------------------
// Decoder Ring for DatapathWorkerThreadStart
// [ udp][%p] Worker start
// QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[ udp][%p] Worker start",
        ProcContext);
// arg2 = arg2 = ProcContext
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathWorkerThreadStart(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathWorkerThreadStart , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathWorkerThreadStop



/*----------------------------------------------------------
// Decoder Ring for DatapathWorkerThreadStop
// [ udp][%p] Worker stop
// QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[ udp][%p] Worker stop",
        ProcContext);
// arg2 = arg2 = ProcContext
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathWorkerThreadStop(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathWorkerThreadStop , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathShutDownReturn



/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownReturn
// [ udp][%p] Shut down (return)
// QuicTraceLogVerbose(
        DatapathShutDownReturn,
        "[ udp][%p] Shut down (return)",
        Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathShutDownReturn(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathShutDownReturn , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathShutDownComplete



/*----------------------------------------------------------
// Decoder Ring for DatapathShutDownComplete
// [ udp][%p] Shut down (complete)
// QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[ udp][%p] Shut down (complete)",
            SocketContext->Binding);
// arg2 = arg2 = SocketContext->Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathShutDownComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathShutDownComplete , arg2);\

#endif




#ifndef _clog_6_ARGS_TRACE_DatapathUnreachableWithError



/*----------------------------------------------------------
// Decoder Ring for DatapathUnreachableWithError
// [ udp][%p] Received unreachable error (0x%x) from %!ADDR!
// QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[ udp][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketContext->Binding,
        ErrorCode,
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = ErrorCode
// arg4 = arg4 = CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_DatapathUnreachableWithError(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathUnreachableWithError , arg2, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathTooLarge



/*----------------------------------------------------------
// Decoder Ring for DatapathTooLarge
// [ udp][%p] Received larger than expected datagram from %!ADDR!
// QuicTraceLogVerbose(
            DatapathTooLarge,
            "[ udp][%p] Received larger than expected datagram from %!ADDR!",
            SocketContext->Binding,
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathTooLarge(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathTooLarge , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_DatapathResolveHostNameFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathResolveHostNameFailed
// [%p] Couldn't resolve hostname '%s' to an IP address
// QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
// arg2 = arg2 = Datapath
// arg3 = arg3 = HostName
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_DatapathResolveHostNameFailed(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathResolveHostNameFailed , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "WSAStartup");
// arg2 = arg2 = WsaError
// arg3 = arg3 = "WSAStartup"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINUSER_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);
// arg2 = arg2 = "QUIC_DATAPATH"
// arg3 = arg3 = DatapathLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINUSER_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                LastError,
                "CreateIoCompletionPort");
// arg2 = arg2 = LastError
// arg3 = arg3 = "CreateIoCompletionPort"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                LastError,
                "CreateThread");
// arg2 = arg2 = LastError
// arg3 = arg3 = "CreateThread"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                LastError,
                "SetThreadGroupAffinity");
// arg2 = arg2 = LastError
// arg3 = arg3 = "SetThreadGroupAffinity"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                NtStatus,
                "NtSetInformationThread(name)");
// arg2 = arg2 = NtStatus
// arg3 = arg3 = "NtSetInformationThread(name)"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "Calculate hostname wchar length");
// arg2 = arg2 = LastError
// arg3 = arg3 = "Calculate hostname wchar length"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Wchar hostname",
            sizeof(WCHAR) * Result);
// arg2 = arg2 = "Wchar hostname"
// arg3 = arg3 = sizeof(WCHAR) * Result
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "Convert hostname to wchar");
// arg2 = arg2 = LastError
// arg3 = arg3 = "Convert hostname to wchar"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
// arg2 = arg2 = "Resolving hostname to IP"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, LibraryError , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_BINDING",
            BindingLength);
// arg2 = arg2 = "QUIC_DATAPATH_BINDING"
// arg3 = arg3 = BindingLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_7_ARGS_TRACE_DatapathCreated



/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [ udp][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[ udp][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress)
// arg4 = arg4 = CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress)
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_DatapathCreated(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathCreated , arg2, arg3_len, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "WSASocketW");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "WSASocketW"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    WsaError,
                    "SIO_GET_EXTENSION_FUNCTION_POINTER (WSASendMsg)");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "SIO_GET_EXTENSION_FUNCTION_POINTER (WSASendMsg)"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    WsaError,
                    "SIO_GET_EXTENSION_FUNCTION_POINTER (WSARecvMsg)");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "SIO_GET_EXTENSION_FUNCTION_POINTER (WSARecvMsg)"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    WsaError,
                    "SIO_CPU_AFFINITY");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "SIO_CPU_AFFINITY"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IPV6_V6ONLY");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IPV6_V6ONLY"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IP_DONTFRAGMENT");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IP_DONTFRAGMENT"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IPV6_DONTFRAG");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IPV6_DONTFRAG"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IPV6_PKTINFO");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IPV6_PKTINFO"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IP_PKTINFO");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IP_PKTINFO"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IPV6_ECN");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IPV6_ECN"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set IP_ECN");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set IP_ECN"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "Set SO_RCVBUF");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set SO_RCVBUF"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    WsaError,
                    "Set UDP_RECV_MAX_COALESCED_SIZE");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "Set UDP_RECV_MAX_COALESCED_SIZE"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                LastError,
                "SetFileCompletionNotificationModes");
// arg2 = arg2 = Binding
// arg3 = arg3 = LastError
// arg4 = arg4 = "SetFileCompletionNotificationModes"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                WsaError,
                "bind");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "bind"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    WsaError,
                    "connect");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "connect"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                LastError,
                "CreateIoCompletionPort");
// arg2 = arg2 = Binding
// arg3 = arg3 = LastError
// arg4 = arg4 = "CreateIoCompletionPort"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    WsaError,
                    "getsockaddress");
// arg2 = arg2 = Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "getsockaddress"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDestroyed



/*----------------------------------------------------------
// Decoder Ring for DatapathDestroyed
// [ udp][%p] Destroyed
// QuicTraceEvent(
                DatapathDestroyed,
                "[ udp][%p] Destroyed",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathDestroyed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDestroyed



/*----------------------------------------------------------
// Decoder Ring for DatapathDestroyed
// [ udp][%p] Destroyed
// QuicTraceEvent(
        DatapathDestroyed,
        "[ udp][%p] Destroyed",
        Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDestroyed(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    WsaError,
                    "WSARecvMsg");
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "WSARecvMsg"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                LastError,
                "PostQueuedCompletionStatus");
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = LastError
// arg4 = arg4 = "PostQueuedCompletionStatus"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_9_ARGS_TRACE_DatapathRecv



/*----------------------------------------------------------
// Decoder Ring for DatapathRecv
// [ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
            DatapathRecv,
            "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            NumberOfBytesTransferred,
            MessageLength,
            CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = NumberOfBytesTransferred
// arg4 = arg4 = MessageLength
// arg5 = arg5 = CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr)
// arg6 = arg6 = CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr)
----------------------------------------------------------*/
#define _clog_9_ARGS_TRACE_DatapathRecv(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len, arg6, arg6_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathRecv , arg2, arg3, arg4, arg5_len, arg5, arg6_len, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            IoResult,
            "WSARecvMsg completion");
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = IoResult
// arg4 = arg4 = "WSARecvMsg completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            IoResult,
            "WSASendMsg completion");
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = IoResult
// arg4 = arg4 = "WSASendMsg completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_10_ARGS_TRACE_DatapathSend



/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        SendContext->TotalSize,
        SendContext->WsaBufferCount,
        SendContext->SegmentSize,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = SendContext->TotalSize
// arg4 = arg4 = SendContext->WsaBufferCount
// arg5 = arg5 = SendContext->SegmentSize
// arg6 = arg6 = CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress)
// arg7 = arg7 = CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress)
----------------------------------------------------------*/
#define _clog_10_ARGS_TRACE_DatapathSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg6_len, arg7, arg7_len)\
tracepoint(CLOG_DATAPATH_WINUSER_C, DatapathSend , arg2, arg3, arg4, arg5, arg6_len, arg6, arg7_len, arg7);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [ udp][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                WsaError,
                "WSASendMsg");
// arg2 = arg2 = SocketContext->Binding
// arg3 = arg3 = WsaError
// arg4 = arg4 = "WSASendMsg"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_winuser.c.clog.h.c"
#endif
