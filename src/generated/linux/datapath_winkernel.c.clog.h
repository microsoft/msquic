#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_WINKERNEL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_winkernel.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_WINKERNEL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_WINKERNEL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_winkernel.c.clog.h.lttng.h"
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
#ifndef _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailed
// [data] RSS helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[data] RSS helper socket failed to open, 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenTcpSocketFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailedAsync



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenTcpSocketFailedAsync
// [data] RSS helper socket failed to open (async), 0x%x
// QuicTraceLogWarning(
            DatapathOpenTcpSocketFailedAsync,
            "[data] RSS helper socket failed to open (async), 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathOpenTcpSocketFailedAsync(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenTcpSocketFailedAsync , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryRssScalabilityInfoFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssScalabilityInfoFailed
// [data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailed,
            "[data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryRssScalabilityInfoFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRssScalabilityInfoFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryRssScalabilityInfoFailedAsync



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRssScalabilityInfoFailedAsync
// [data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed (async), 0x%x
// QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailedAsync,
            "[data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed (async), 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryRssScalabilityInfoFailedAsync(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRssScalabilityInfoFailedAsync , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailed
// [data] UDP send segmentation helper socket failed to open, 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[data] UDP send segmentation helper socket failed to open, 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenUdpSocketFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailedAsync



/*----------------------------------------------------------
// Decoder Ring for DatapathOpenUdpSocketFailedAsync
// [data] UDP send segmentation helper socket failed to open (async), 0x%x
// QuicTraceLogWarning(
            DatapathOpenUdpSocketFailedAsync,
            "[data] UDP send segmentation helper socket failed to open (async), 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathOpenUdpSocketFailedAsync(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathOpenUdpSocketFailedAsync , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSendMsgFailed
// [data] Query for UDP_SEND_MSG_SIZE failed, 0x%x
// QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailed,
                "[data] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryUdpSendMsgFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailedAsync



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryUdpSendMsgFailedAsync
// [data] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x
// QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailedAsync,
                "[data] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x",
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryUdpSendMsgFailedAsync(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryUdpSendMsgFailedAsync , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailed



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRecvMaxCoalescedSizeFailed
// [data] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x
// QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailed,
                "[data] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRecvMaxCoalescedSizeFailed , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailedAsync



/*----------------------------------------------------------
// Decoder Ring for DatapathQueryRecvMaxCoalescedSizeFailedAsync
// [data] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x
// QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailedAsync,
                "[data] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x",
                Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathQueryRecvMaxCoalescedSizeFailedAsync(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathQueryRecvMaxCoalescedSizeFailedAsync , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDropEmptyMdl



/*----------------------------------------------------------
// Decoder Ring for DatapathDropEmptyMdl
// [%p] Dropping datagram with empty mdl.
// QuicTraceLogWarning(
                DatapathDropEmptyMdl,
                "[%p] Dropping datagram with empty mdl.",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDropEmptyMdl(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDropEmptyMdl , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDropMissingInfo



/*----------------------------------------------------------
// Decoder Ring for DatapathDropMissingInfo
// [%p] Dropping datagram missing IP_PKTINFO/IP_RECVERR.
// QuicTraceLogWarning(
                DatapathDropMissingInfo,
                "[%p] Dropping datagram missing IP_PKTINFO/IP_RECVERR.",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDropMissingInfo(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDropMissingInfo , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_DatapathDropTooBig



/*----------------------------------------------------------
// Decoder Ring for DatapathDropTooBig
// [%p] Dropping datagram with too many bytes (%llu).
// QuicTraceLogWarning(
                    DatapathDropTooBig,
                    "[%p] Dropping datagram with too many bytes (%llu).",
                    Binding,
                    (uint64_t)DataLength);
// arg2 = arg2 = Binding
// arg3 = arg3 = (uint64_t)DataLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_DatapathDropTooBig(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDropTooBig , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDropMdlMapFailure



/*----------------------------------------------------------
// Decoder Ring for DatapathDropMdlMapFailure
// [%p] Failed to map MDL chain
// QuicTraceLogWarning(
                DatapathDropMdlMapFailure,
                "[%p] Failed to map MDL chain",
                Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDropMdlMapFailure(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDropMdlMapFailure , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathFragmented



/*----------------------------------------------------------
// Decoder Ring for DatapathFragmented
// [%p] Dropping datagram with fragmented MDL.
// QuicTraceLogWarning(
                    DatapathFragmented,
                    "[%p] Dropping datagram with fragmented MDL.",
                    Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathFragmented(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathFragmented , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDropAllocRecvContextFailure



/*----------------------------------------------------------
// Decoder Ring for DatapathDropAllocRecvContextFailure
// [%p] Couldn't allocate receive context.
// QuicTraceLogWarning(
                        DatapathDropAllocRecvContextFailure,
                        "[%p] Couldn't allocate receive context.",
                        Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDropAllocRecvContextFailure(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDropAllocRecvContextFailure , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDropAllocRecvBufferFailure



/*----------------------------------------------------------
// Decoder Ring for DatapathDropAllocRecvBufferFailure
// [%p] Couldn't allocate receive buffers.
// QuicTraceLogWarning(
                            DatapathDropAllocRecvBufferFailure,
                            "[%p] Couldn't allocate receive buffers.",
                            Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDropAllocRecvBufferFailure(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDropAllocRecvBufferFailure , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathUroExceeded



/*----------------------------------------------------------
// Decoder Ring for DatapathUroExceeded
// [%p] Exceeded URO preallocation capacity.
// QuicTraceLogWarning(
                    DatapathUroExceeded,
                    "[%p] Exceeded URO preallocation capacity.",
                    Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathUroExceeded(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathUroExceeded , arg2);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathUnreachableMsg



/*----------------------------------------------------------
// Decoder Ring for DatapathUnreachableMsg
// [sock][%p] Unreachable error from %!ADDR!
// QuicTraceLogVerbose(
                DatapathUnreachableMsg,
                "[sock][%p] Unreachable error from %!ADDR!",
                Binding,
                CASTED_CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));
// arg2 = arg2 = Binding
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathUnreachableMsg(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathUnreachableMsg , arg2, arg3_len, arg3);\

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
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathResolveHostNameFailed , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
// arg2 = arg2 = "CXPLAT_DATAPATH"
// arg3 = arg3 = DatapathLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskRegister");
// arg2 = arg2 = Status
// arg3 = arg3 = "WskRegister"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskCaptureProviderNPI");
// arg2 = arg2 = Status
// arg3 = arg3 = "WskCaptureProviderNPI"
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
            Status,
            "WskControlClient WSK_TDI_BEHAVIOR");
// arg2 = arg2 = Status
// arg3 = arg3 = "WskControlClient WSK_TDI_BEHAVIOR"
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
            Status,
            "WskControlClient WSK_SET_STATIC_EVENT_CALLBACKS");
// arg2 = arg2 = Status
// arg3 = arg3 = "WskControlClient WSK_SET_STATIC_EVENT_CALLBACKS"
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
            Status,
            "GetIpInterfaceTable");
// arg2 = arg2 = Status
// arg3 = arg3 = "GetIpInterfaceTable"
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
            Status,
            "GetUnicastIpAddressTable");
// arg2 = arg2 = Status
// arg3 = arg3 = "GetUnicastIpAddressTable"
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
            "Addresses",
            AddressTable->NumEntries * sizeof(CXPLAT_ADAPTER_ADDRESS));
// arg2 = arg2 = "Addresses"
// arg3 = arg3 = AddressTable->NumEntries * sizeof(CXPLAT_ADAPTER_ADDRESS)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Unicode Hostname",
            UniHostName.MaximumLength);
// arg2 = arg2 = "Unicode Hostname"
// arg3 = arg3 = UniHostName.MaximumLength
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
            Status,
            "Convert hostname to unicode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Convert hostname to unicode"
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
tracepoint(CLOG_DATAPATH_WINKERNEL_C, LibraryError , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            BindingSize);
// arg2 = arg2 = "CXPLAT_SOCKET"
// arg3 = arg3 = BindingSize
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_7_ARGS_TRACE_DatapathCreated



/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [data][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress)
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress)
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_DatapathCreated(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathCreated , arg2, arg3_len, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSocket");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskSocket"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSocket completion");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskSocket completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_V6ONLY");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IPV6_V6ONLY"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_DONTFRAGMENT");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IP_DONTFRAGMENT"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_DONTFRAG");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IPV6_DONTFRAG"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_PKTINFO");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IPV6_PKTINFO"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_PKTINFO");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IP_PKTINFO"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_RECVERR");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IPV6_RECVERR"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_RECVERR");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IP_RECVERR"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set UDP_RECV_MAX_COALESCED_SIZE");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set UDP_RECV_MAX_COALESCED_SIZE"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set IPV6_UNICAST_IF");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IPV6_UNICAST_IF"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set IP_UNICAST_IF");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set IP_UNICAST_IF"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskBind");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskBind"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskBind completion");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskBind completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set SIO_WSK_SET_REMOTE_ADDRESS");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "Set SIO_WSK_SET_REMOTE_ADDRESS"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskGetLocalAddress");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskGetLocalAddress"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskGetLocalAddress completion");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskGetLocalAddress completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Binding->Irp.IoStatus.Status,
                "WskCloseSocket completion");
// arg2 = arg2 = Binding
// arg3 = arg3 = Binding->Irp.IoStatus.Status
// arg4 = arg4 = "WskCloseSocket completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_3_ARGS_TRACE_DatapathDestroyed



/*----------------------------------------------------------
// Decoder Ring for DatapathDestroyed
// [data][%p] Destroyed
// QuicTraceEvent(
        DatapathDestroyed,
        "[data][%p] Destroyed",
        Binding);
// arg2 = arg2 = Binding
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DatapathDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathDestroyed , arg2);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "WskCloseSocket");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskCloseSocket"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_9_ARGS_TRACE_DatapathRecv



/*----------------------------------------------------------
// Decoder Ring for DatapathRecv
// [data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!
// QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            Binding,
            (uint32_t)DataLength,
            MessageLength,
            CASTED_CLOG_BYTEARRAY(sizeof(LocalAddr), &LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));
// arg2 = arg2 = Binding
// arg3 = arg3 = (uint32_t)DataLength
// arg4 = arg4 = MessageLength
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(LocalAddr), &LocalAddr)
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr)
----------------------------------------------------------*/
#define _clog_9_ARGS_TRACE_DatapathRecv(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg5_len, arg6, arg6_len)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathRecv , arg2, arg3, arg4, arg5_len, arg5, arg6_len, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Irp->IoStatus.Status,
            "WskSendMessages completion");
// arg2 = arg2 = Binding
// arg3 = arg3 = Irp->IoStatus.Status
// arg4 = arg4 = "WskSendMessages completion"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_10_ARGS_TRACE_DatapathSend



/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        SendData->TotalSize,
        SendData->WskBufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
// arg2 = arg2 = Binding
// arg3 = arg3 = SendData->TotalSize
// arg4 = arg4 = SendData->WskBufferCount
// arg5 = arg5 = SendData->SegmentSize
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress)
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress)
----------------------------------------------------------*/
#define _clog_10_ARGS_TRACE_DatapathSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg6_len, arg7, arg7_len)\
tracepoint(CLOG_DATAPATH_WINKERNEL_C, DatapathSend , arg2, arg3, arg4, arg5, arg6_len, arg6, arg7_len, arg7);\

#endif




#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus



/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSendMessages");
// arg2 = arg2 = Binding
// arg3 = arg3 = Status
// arg4 = arg4 = "WskSendMessages"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_winkernel.c.clog.h.c"
#endif
