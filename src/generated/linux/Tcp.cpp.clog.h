#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TCP_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "Tcp.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_TCP_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TCP_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "Tcp.cpp.clog.h.lttng.h"
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
// Decoder Ring for PerfTcpCreateClient
// [perf][tcp][%p] Client created
// QuicTraceLogVerbose(
        PerfTcpCreateClient,
        "[perf][tcp][%p] Client created",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpCreateClient
#define _clog_3_ARGS_TRACE_PerfTcpCreateClient(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpCreateClient , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpCreateServer
// [perf][tcp][%p] Server created
// QuicTraceLogVerbose(
        PerfTcpCreateServer,
        "[perf][tcp][%p] Server created",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpCreateServer
#define _clog_3_ARGS_TRACE_PerfTcpCreateServer(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpCreateServer , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpDestroyed
// [perf][tcp][%p] Destroyed
// QuicTraceLogVerbose(
        PerfTcpDestroyed,
        "[perf][tcp][%p] Destroyed",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpDestroyed
#define _clog_3_ARGS_TRACE_PerfTcpDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpConnectCallback
// [perf][tcp][%p] Connect callback %hhu
// QuicTraceLogVerbose(
        PerfTcpConnectCallback,
        "[perf][tcp][%p] Connect callback %hhu",
        This,
        Connected);
// arg2 = arg2 = This = arg2
// arg3 = arg3 = Connected = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfTcpConnectCallback
#define _clog_4_ARGS_TRACE_PerfTcpConnectCallback(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TCP_CPP, PerfTcpConnectCallback , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpReceiveCallback
// [perf][tcp][%p] Receive callback
// QuicTraceLogVerbose(
        PerfTcpReceiveCallback,
        "[perf][tcp][%p] Receive callback",
        This);
// arg2 = arg2 = This = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpReceiveCallback
#define _clog_3_ARGS_TRACE_PerfTcpReceiveCallback(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpReceiveCallback , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpSendCompleteCallback
// [perf][tcp][%p] SendComplete callback
// QuicTraceLogVerbose(
        PerfTcpSendCompleteCallback,
        "[perf][tcp][%p] SendComplete callback",
        This);
// arg2 = arg2 = This = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpSendCompleteCallback
#define _clog_3_ARGS_TRACE_PerfTcpSendCompleteCallback(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpSendCompleteCallback , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppAccept
// [perf][tcp][%p] App Accept
// QuicTraceLogVerbose(
            PerfTcpAppAccept,
            "[perf][tcp][%p] App Accept",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpAppAccept
#define _clog_3_ARGS_TRACE_PerfTcpAppAccept(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppAccept , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppConnect
// [perf][tcp][%p] App Connect
// QuicTraceLogVerbose(
            PerfTcpAppConnect,
            "[perf][tcp][%p] App Connect",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpAppConnect
#define _clog_3_ARGS_TRACE_PerfTcpAppConnect(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppConnect , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpStartTls
// [perf][tcp][%p] Start TLS
// QuicTraceLogVerbose(
            PerfTcpStartTls,
            "[perf][tcp][%p] Start TLS",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpStartTls
#define _clog_3_ARGS_TRACE_PerfTcpStartTls(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpStartTls , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppDisconnect
// [perf][tcp][%p] App Disconnect
// QuicTraceLogVerbose(
            PerfTcpAppDisconnect,
            "[perf][tcp][%p] App Disconnect",
            this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpAppDisconnect
#define _clog_3_ARGS_TRACE_PerfTcpAppDisconnect(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppDisconnect , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppReceive
// [perf][tcp][%p] App Receive %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu
// QuicTraceLogVerbose(
            PerfTcpAppReceive,
            "[perf][tcp][%p] App Receive %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu",
            this,
            (uint16_t)(Frame->Length - sizeof(TcpStreamFrame)),
            (uint8_t)StreamFrame->Open,
            (uint8_t)StreamFrame->Fin,
            (uint8_t)StreamFrame->Abort);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = (uint16_t)(Frame->Length - sizeof(TcpStreamFrame)) = arg3
// arg4 = arg4 = (uint8_t)StreamFrame->Open = arg4
// arg5 = arg5 = (uint8_t)StreamFrame->Fin = arg5
// arg6 = arg6 = (uint8_t)StreamFrame->Abort = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_PerfTcpAppReceive
#define _clog_7_ARGS_TRACE_PerfTcpAppReceive(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppReceive , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpSendFrame
// [perf][tcp][%p] Send frame %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu
// QuicTraceLogVerbose(
                PerfTcpSendFrame,
                "[perf][tcp][%p] Send frame %hu bytes, Open=%hhu Fin=%hhu Abort=%hhu",
                this,
                (uint16_t)StreamLength,
                (uint8_t)StreamFrame->Open,
                (uint8_t)StreamFrame->Fin,
                (uint8_t)StreamFrame->Abort);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = (uint16_t)StreamLength = arg3
// arg4 = arg4 = (uint8_t)StreamFrame->Open = arg4
// arg5 = arg5 = (uint8_t)StreamFrame->Fin = arg5
// arg6 = arg6 = (uint8_t)StreamFrame->Abort = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_PerfTcpSendFrame
#define _clog_7_ARGS_TRACE_PerfTcpSendFrame(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_TCP_CPP, PerfTcpSendFrame , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppSendComplete
// [perf][tcp][%p] App Send complete %u bytes
// QuicTraceLogVerbose(
            PerfTcpAppSendComplete,
            "[perf][tcp][%p] App Send complete %u bytes",
            this,
            Data->Length);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = Data->Length = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfTcpAppSendComplete
#define _clog_4_ARGS_TRACE_PerfTcpAppSendComplete(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppSendComplete , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppSend
// [perf][tcp][%p] App Send %u bytes, Open=%hhu Fin=%hhu Abort=%hhu
// QuicTraceLogVerbose(
        PerfTcpAppSend,
        "[perf][tcp][%p] App Send %u bytes, Open=%hhu Fin=%hhu Abort=%hhu",
        this,
        Data->Length,
        (uint8_t)Data->Open,
        (uint8_t)Data->Fin,
        (uint8_t)Data->Abort);
// arg2 = arg2 = this = arg2
// arg3 = arg3 = Data->Length = arg3
// arg4 = arg4 = (uint8_t)Data->Open = arg4
// arg5 = arg5 = (uint8_t)Data->Fin = arg5
// arg6 = arg6 = (uint8_t)Data->Abort = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_PerfTcpAppSend
#define _clog_7_ARGS_TRACE_PerfTcpAppSend(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppSend , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfTcpAppClose
// [perf][tcp][%p] App Close
// QuicTraceLogVerbose(
        PerfTcpAppClose,
        "[perf][tcp][%p] App Close",
        this);
// arg2 = arg2 = this = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PerfTcpAppClose
#define _clog_3_ARGS_TRACE_PerfTcpAppClose(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TCP_CPP, PerfTcpAppClose , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_Tcp.cpp.clog.h.c"
#endif
