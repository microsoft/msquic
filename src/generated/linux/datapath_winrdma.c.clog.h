#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_DATAPATH_WINRDMA_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "datapath_winrdma.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_DATAPATH_WINRDMA_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_DATAPATH_WINRDMA_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "datapath_winrdma.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
// Decoder Ring for DatapathShutDownComplete
// [data][%p] Shut down (complete)
// QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            Socket);
// arg2 = arg2 = Socket = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DatapathShutDownComplete
#define _clog_3_ARGS_TRACE_DatapathShutDownComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, DatapathShutDownComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedFileFailed
// [ ndspi] CreateOverlappedFile failed, status: %d
// QuicTraceLogError(
            CreateOverlappedFileFailed,
            "[ ndspi] CreateOverlappedFile failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateOverlappedFileFailed
#define _clog_3_ARGS_TRACE_CreateOverlappedFileFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedFileFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateMemoryRegionFailed
// [ ndspi] CreateMemoryRegion failed, status: %d
// QuicTraceLogError(
            CreateMemoryRegionFailed,
            "[ ndspi] CreateMemoryRegion failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateMemoryRegionFailed
#define _clog_3_ARGS_TRACE_CreateMemoryRegionFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateMemoryRegionFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RegisterMemoryFailed
// [ ndspi] RegisterMemory failed, status: %d
// QuicTraceLogError(
            RegisterMemoryFailed,
            "[ ndspi] RegisterMemory failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RegisterMemoryFailed
#define _clog_3_ARGS_TRACE_RegisterMemoryFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, RegisterMemoryFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DeRegisterMemoryFailed
// [ ndspi] DeRegisterMemory failed, status: %d
// QuicTraceLogError(
            DeRegisterMemoryFailed,
            "[ ndspi] DeRegisterMemory failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DeRegisterMemoryFailed
#define _clog_3_ARGS_TRACE_DeRegisterMemoryFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, DeRegisterMemoryFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateMemoryWindowFailed
// [ ndspi] CreateMemoryWindow failed, status: %d
// QuicTraceLogError(
            CreateMemoryWindowFailed,
            "[ ndspi] CreateMemoryWindow failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateMemoryWindowFailed
#define _clog_3_ARGS_TRACE_CreateMemoryWindowFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateMemoryWindowFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateCompletionQueueFailed
// [ ndspi] CreateCompletionQueueFailed failed, status: %d
// QuicTraceLogError(
            CreateCompletionQueueFailed,
            "[ ndspi] CreateCompletionQueueFailed failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateCompletionQueueFailed
#define _clog_3_ARGS_TRACE_CreateCompletionQueueFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateCompletionQueueFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateConnectorFailed
// [ ndspi] CreateConnector failed, status: %d
// QuicTraceLogError(
            CreateConnectorFailed,
            "[ ndspi] CreateConnector failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateConnectorFailed
#define _clog_3_ARGS_TRACE_CreateConnectorFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateConnectorFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateListenerFailed
// [ ndspi] CreateListener failed, status: %d
// QuicTraceLogError(
            CreateListenerFailed,
            "[ ndspi] CreateListener failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateListenerFailed
#define _clog_3_ARGS_TRACE_CreateListenerFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateListenerFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for StartListenerFailed
// [ ndspi] StartListener failed, status: %d
// QuicTraceLogError(
            StartListenerFailed,
            "[ ndspi] StartListener failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_StartListenerFailed
#define _clog_3_ARGS_TRACE_StartListenerFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, StartListenerFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateQueuePairFailed
// [ ndspi] CreateQueuePair failed, status: %d
// QuicTraceLogError(
            CreateQueuePairFailed,
            "[ ndspi] CreateQueuePair failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateQueuePairFailed
#define _clog_3_ARGS_TRACE_CreateQueuePairFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateQueuePairFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AcceptFailed
// [ ndspi] Accept failed, status: %d
// QuicTraceLogError(
            AcceptFailed,
            "[ ndspi] Accept failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_AcceptFailed
#define _clog_3_ARGS_TRACE_AcceptFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, AcceptFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnectorBindFailed
// [ ndspi]  Connector Bind failed, status: %d
// QuicTraceLogError(
            ConnectorBindFailed,
            "[ ndspi]  Connector Bind failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnectorBindFailed
#define _clog_3_ARGS_TRACE_ConnectorBindFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, ConnectorBindFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ListenerBindFailed
// [ ndspi]  Listener Bind failed, status: %d
// QuicTraceLogError(
            ListenerBindFailed,
            "[ ndspi]  Listener Bind failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ListenerBindFailed
#define _clog_3_ARGS_TRACE_ListenerBindFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, ListenerBindFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnectFailed
// [ ndspi] Connect failed, status: %d
// QuicTraceLogError(
            ConnectFailed,
            "[ ndspi] Connect failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnectFailed
#define _clog_3_ARGS_TRACE_ConnectFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, ConnectFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CompleteConnectFailed
// [ ndspi] CompleteConnect failed, status: %d
// QuicTraceLogError(
            CompleteConnectFailed,
            "[ ndspi] CompleteConnect failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CompleteConnectFailed
#define _clog_3_ARGS_TRACE_CompleteConnectFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CompleteConnectFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindMemoryWindowFailed
// [ ndspi] BindMemoryWindow failed, status: %d
// QuicTraceLogError(
            BindMemoryWindowFailed,
            "[ ndspi] BindMemoryWindow failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_BindMemoryWindowFailed
#define _clog_3_ARGS_TRACE_BindMemoryWindowFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, BindMemoryWindowFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for InvalidateMemoryWindowFailed
// [ ndspi] InvalidateMemoryWindow failed, status: %d
// QuicTraceLogError(
            InvalidateMemoryWindowFailed,
            "[ ndspi] InvalidateMemoryWindow failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_InvalidateMemoryWindowFailed
#define _clog_3_ARGS_TRACE_InvalidateMemoryWindowFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, InvalidateMemoryWindowFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdspiWriteFailed
// [ ndspi] NdspiWrite failed, status: %d
// QuicTraceLogError(
            NdspiWriteFailed,
            "[ ndspi] NdspiWrite failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdspiWriteFailed
#define _clog_3_ARGS_TRACE_NdspiWriteFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdspiWriteFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdspiWriteWithImmediateFailed
// [ ndspi] NdspiWriteWithImmediate failed, status: %d
// QuicTraceLogError(
            NdspiWriteWithImmediateFailed,
            "[ ndspi] NdspiWriteWithImmediate failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdspiWriteWithImmediateFailed
#define _clog_3_ARGS_TRACE_NdspiWriteWithImmediateFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdspiWriteWithImmediateFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdspiReadFailed
// [ ndspi] NdspiRead failed, status: %d
// QuicTraceLogError(
            NdspiReadFailed,
            "[ ndspi] NdspiRead failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdspiReadFailed
#define _clog_3_ARGS_TRACE_NdspiReadFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdspiReadFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdspiSendFailed
// [ ndspi] NdspiRead failed, status: %d
// QuicTraceLogError(
            NdspiSendFailed,
            "[ ndspi] NdspiRead failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdspiSendFailed
#define _clog_3_ARGS_TRACE_NdspiSendFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdspiSendFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdspiSendWithImmediateFailed
// [ ndspi] NdspiSendWithImmediate failed, status: %d
// QuicTraceLogError(
            NdspiSendWithImmediateFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdspiSendWithImmediateFailed
#define _clog_3_ARGS_TRACE_NdspiSendWithImmediateFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdspiSendWithImmediateFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdspiPostReceiveFailed
// [ ndspi] NdspiSendWithImmediate failed, status: %d
// QuicTraceLogError(
            NdspiPostReceiveFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdspiPostReceiveFailed
#define _clog_3_ARGS_TRACE_NdspiPostReceiveFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdspiPostReceiveFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NdOpenAdapterFailed
// NdOpenAdapter failed, status: %d
// QuicTraceLogError(
            NdOpenAdapterFailed,
            "NdOpenAdapter failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NdOpenAdapterFailed
#define _clog_3_ARGS_TRACE_NdOpenAdapterFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, NdOpenAdapterFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedFile
// CreateAdapterOverlappedFile failed, status: %d
// QuicTraceLogError(
            CreateOverlappedFile,
            "CreateAdapterOverlappedFile failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateOverlappedFile
#define _clog_3_ARGS_TRACE_CreateOverlappedFile(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedFile , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for QueryAdapterInfoFailed
// QueryAdapterInfo failed, status: %d
// QuicTraceLogError(
            QueryAdapterInfoFailed,
            "QueryAdapterInfo failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_QueryAdapterInfoFailed
#define _clog_3_ARGS_TRACE_QueryAdapterInfoFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, QueryAdapterInfoFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateRdmaSocketFailed
// CreateRdmaSocket failed, invalid address family
// QuicTraceLogError(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid address family");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_CreateRdmaSocketFailed
#define _clog_2_ARGS_TRACE_CreateRdmaSocketFailed(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateRdmaSocketFailed );\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedConnFileFailed
// CreateOverConnlappedFile failed, status:%d
// QuicTraceLogError(
            CreateOverlappedConnFileFailed,
            "CreateOverConnlappedFile failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateOverlappedConnFileFailed
#define _clog_3_ARGS_TRACE_CreateOverlappedConnFileFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedConnFileFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RegisterSendBufferFailed
// RegisterSendBuffer failed, status:%d
// QuicTraceLogError(
            RegisterSendBufferFailed,
            "RegisterSendBuffer failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RegisterSendBufferFailed
#define _clog_3_ARGS_TRACE_RegisterSendBufferFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, RegisterSendBufferFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SendRingBufferInitFailed
// SendRingBufferInit failed, status: %d
// QuicTraceLogError(
            SendRingBufferInitFailed,
            "SendRingBufferInit failed, status: %d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SendRingBufferInitFailed
#define _clog_3_ARGS_TRACE_SendRingBufferInitFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, SendRingBufferInitFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecvRingBufferInitFailed
// RecvRingBufferInit failed, status:%d
// QuicTraceLogError(
            RecvRingBufferInitFailed,
            "RecvRingBufferInit failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RecvRingBufferInitFailed
#define _clog_3_ARGS_TRACE_RecvRingBufferInitFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, RecvRingBufferInitFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateSharedCompletionQueueFailed
// Create CompletionQueue failed, status:%d
// QuicTraceLogError(
            CreateSharedCompletionQueueFailed,
            "Create CompletionQueue failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateSharedCompletionQueueFailed
#define _clog_3_ARGS_TRACE_CreateSharedCompletionQueueFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateSharedCompletionQueueFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateRecvMemoryWindowFailed
// Create RecvMemoryWindow failed, status:%d
// QuicTraceLogError(
                CreateRecvMemoryWindowFailed,
                "Create RecvMemoryWindow failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateRecvMemoryWindowFailed
#define _clog_3_ARGS_TRACE_CreateRecvMemoryWindowFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateRecvMemoryWindowFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateSendMemoryWindowFailed
// Create SendMemoryWindow failed, status:%d
// QuicTraceLogError(
                    CreateSendMemoryWindowFailed,
                    "Create SendMemoryWindow failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateSendMemoryWindowFailed
#define _clog_3_ARGS_TRACE_CreateSendMemoryWindowFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateSendMemoryWindowFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CreateOverlappedListenerFileFailed
// CreateOverlappedListenerFile failed, status:%d
// QuicTraceLogError(
            CreateOverlappedListenerFileFailed,
            "CreateOverlappedListenerFile failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CreateOverlappedListenerFileFailed
#define _clog_3_ARGS_TRACE_CreateOverlappedListenerFileFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, CreateOverlappedListenerFileFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ExchangeTokensFailed
// RdmaSocketPendingSend failed, invalid parameters
// QuicTraceLogError(
            ExchangeTokensFailed,
            "RdmaSocketPendingSend failed, invalid parameters");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_ExchangeTokensFailed
#define _clog_2_ARGS_TRACE_ExchangeTokensFailed(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, ExchangeTokensFailed );\

#endif




/*----------------------------------------------------------
// Decoder Ring for StartAcceptFailed
// StartAccept failed, invalid parameters
// QuicTraceLogError(
            StartAcceptFailed,
            "StartAccept failed, invalid parameters");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_StartAcceptFailed
#define _clog_2_ARGS_TRACE_StartAcceptFailed(uniqueId, encoded_arg_string)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, StartAcceptFailed );\

#endif




/*----------------------------------------------------------
// Decoder Ring for GetConnectionRequestFailed
// GetConnectionRequest failed, status:%d
// QuicTraceLogError(
                GetConnectionRequestFailed,
                "GetConnectionRequest failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_GetConnectionRequestFailed
#define _clog_3_ARGS_TRACE_GetConnectionRequestFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, GetConnectionRequestFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindRecvMemoryWindowFailed
// BindRecvMemoryWindow failed, status:%d
// QuicTraceLogError(
            BindRecvMemoryWindowFailed,
            "BindRecvMemoryWindow failed, status:%d", Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_BindRecvMemoryWindowFailed
#define _clog_3_ARGS_TRACE_BindRecvMemoryWindowFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, BindRecvMemoryWindowFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RDMA_NDSPI_ADAPTER",
            sizeof(RDMA_NDSPI_ADAPTER));
// arg2 = arg2 = "RDMA_NDSPI_ADAPTER" = arg2
// arg3 = arg3 = sizeof(RDMA_NDSPI_ADAPTER) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathCreated
// [data][%p] Created, local=%!ADDR!, remote=%!ADDR!
// QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress) = arg4
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_DatapathCreated
#define _clog_7_ARGS_TRACE_DatapathCreated(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, DatapathCreated , arg2, arg3_len, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathErrorStatus
// [data][%p] ERROR, %u, %s.
// QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "SetFileCompletionNotificationModes");
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = LastError = arg3
// arg4 = arg4 = "SetFileCompletionNotificationModes" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DatapathErrorStatus
#define _clog_5_ARGS_TRACE_DatapathErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, DatapathErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatapathSend
// [data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!
// QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
// arg2 = arg2 = Socket = arg2
// arg3 = arg3 = SendData->Buffer.Length = arg3
// arg4 = arg4 = 1 = arg4
// arg5 = arg5 = (uint16_t)SendData->Buffer.Length = arg5
// arg6 = arg6 = CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress) = arg6
// arg7 = arg7 = CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress) = arg7
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_DatapathSend
#define _clog_10_ARGS_TRACE_DatapathSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg6_len, arg7, arg7_len)\
tracepoint(CLOG_DATAPATH_WINRDMA_C, DatapathSend , arg2, arg3, arg4, arg5, arg6_len, arg6, arg7_len, arg7);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_datapath_winrdma.c.clog.h.c"
#endif
