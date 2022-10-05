#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TLS_SCHANNEL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tls_schannel.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_TLS_SCHANNEL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TLS_SCHANNEL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "tls_schannel.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for SchannelAchAsync
// [ tls] Calling SspiAcquireCredentialsHandleAsyncW
// QuicTraceLogVerbose(
        SchannelAchAsync,
        "[ tls] Calling SspiAcquireCredentialsHandleAsyncW");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_SchannelAchAsync
#define _clog_2_ARGS_TRACE_SchannelAchAsync(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAchAsync );\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelAchWorkerStart
// [ tls] Starting ACH worker
// QuicTraceLogVerbose(
        SchannelAchWorkerStart,
        "[ tls] Starting ACH worker");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_SchannelAchWorkerStart
#define _clog_2_ARGS_TRACE_SchannelAchWorkerStart(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAchWorkerStart );\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelAch
// [ tls] Calling AcquireCredentialsHandleW
// QuicTraceLogVerbose(
        SchannelAch,
        "[ tls] Calling AcquireCredentialsHandleW");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_SchannelAch
#define _clog_2_ARGS_TRACE_SchannelAch(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAch );\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelAchCompleteInline
// [ tls] Invoking security config completion callback inline, 0x%x
// QuicTraceLogVerbose(
        SchannelAchCompleteInline,
        "[ tls] Invoking security config completion callback inline, 0x%x",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SchannelAchCompleteInline
#define _clog_3_ARGS_TRACE_SchannelAchCompleteInline(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAchCompleteInline , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelHandshakeComplete
// [conn][%p] Handshake complete (resume=%hu)
// QuicTraceLogConnInfo(
                SchannelHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete (resume=%hu)",
                State->SessionResumed);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->SessionResumed = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelHandshakeComplete
#define _clog_4_ARGS_TRACE_SchannelHandshakeComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelHandshakeComplete , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelConsumedBytes
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnInfo(
            SchannelConsumedBytes,
            TlsContext->Connection,
            "Consumed %u bytes",
            *InBufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *InBufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelConsumedBytes
#define _clog_4_ARGS_TRACE_SchannelConsumedBytes(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelConsumedBytes , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelReadHandshakeStart
// [conn][%p] Reading Handshake data starts now
// QuicTraceLogConnInfo(
                        SchannelReadHandshakeStart,
                        TlsContext->Connection,
                        "Reading Handshake data starts now");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SchannelReadHandshakeStart
#define _clog_3_ARGS_TRACE_SchannelReadHandshakeStart(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelReadHandshakeStart , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelRead1RttStart
// [conn][%p] Reading 1-RTT data starts now
// QuicTraceLogConnInfo(
                        SchannelRead1RttStart,
                        TlsContext->Connection,
                        "Reading 1-RTT data starts now");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SchannelRead1RttStart
#define _clog_3_ARGS_TRACE_SchannelRead1RttStart(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelRead1RttStart , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelWriteHandshakeStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                        SchannelWriteHandshakeStart,
                        TlsContext->Connection,
                        "Writing Handshake data starts at %u",
                        State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->BufferOffsetHandshake = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelWriteHandshakeStart
#define _clog_4_ARGS_TRACE_SchannelWriteHandshakeStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelWriteHandshakeStart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelWrite1RttStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                            SchannelWrite1RttStart,
                            TlsContext->Connection,
                            "Writing 1-RTT data starts at %u",
                            State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = State->BufferOffset1Rtt = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelWrite1RttStart
#define _clog_4_ARGS_TRACE_SchannelWrite1RttStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelWrite1RttStart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelProducedData
// [conn][%p] Produced %u bytes
// QuicTraceLogConnInfo(
                SchannelProducedData,
                TlsContext->Connection,
                "Produced %u bytes",
                OutputTokenBuffer->cbBuffer);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = OutputTokenBuffer->cbBuffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelProducedData
#define _clog_4_ARGS_TRACE_SchannelProducedData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelProducedData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelMissingData
// [conn][%p] TLS message missing %u bytes of data
// QuicTraceLogConnInfo(
                SchannelMissingData,
                TlsContext->Connection,
                "TLS message missing %u bytes of data",
                MissingBuffer->cbBuffer);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = MissingBuffer->cbBuffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelMissingData
#define _clog_4_ARGS_TRACE_SchannelMissingData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelMissingData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelTransParamsBufferTooSmall
// [conn][%p] Peer TP too large for available buffer (%u vs. %u)
// QuicTraceLogConnInfo(
                        SchannelTransParamsBufferTooSmall,
                        TlsContext->Connection,
                        "Peer TP too large for available buffer (%u vs. %u)",
                        OutSecBufferDesc.pBuffers[i].cbBuffer,
                        (TlsContext->PeerTransportParams != NULL) ?
                            TlsContext->PeerTransportParamsLength :
                            *InBufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = OutSecBufferDesc.pBuffers[i].cbBuffer = arg3
// arg4 = arg4 = (TlsContext->PeerTransportParams != NULL) ?
                            TlsContext->PeerTransportParamsLength :
                            *InBufferLength = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_SchannelTransParamsBufferTooSmall
#define _clog_5_ARGS_TRACE_SchannelTransParamsBufferTooSmall(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelTransParamsBufferTooSmall , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        SchannelContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SchannelContextCreated
#define _clog_3_ARGS_TRACE_SchannelContextCreated(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelContextCreated , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            SchannelContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_SchannelContextCleaningUp
#define _clog_3_ARGS_TRACE_SchannelContextCleaningUp(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelContextCleaningUp , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelKeyReady
// [conn][%p] Key Ready Type, %u [%hu to %hu]
// QuicTraceLogConnVerbose(
                SchannelKeyReady,
                TlsContext->Connection,
                "Key Ready Type, %u [%hu to %hu]",
                (uint32_t)TrafficSecret->TrafficSecretType,
                TrafficSecret->MsgSequenceStart,
                TrafficSecret->MsgSequenceEnd);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)TrafficSecret->TrafficSecretType = arg3
// arg4 = arg4 = TrafficSecret->MsgSequenceStart = arg4
// arg5 = arg5 = TrafficSecret->MsgSequenceEnd = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_SchannelKeyReady
#define _clog_6_ARGS_TRACE_SchannelKeyReady(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelKeyReady , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelIgnoringTicket
// [conn][%p] Ignoring %u ticket bytes
// QuicTraceLogConnVerbose(
            SchannelIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelIgnoringTicket
#define _clog_4_ARGS_TRACE_SchannelIgnoringTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelIgnoringTicket , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SchannelProcessingData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
        SchannelProcessingData,
        TlsContext->Connection,
        "Processing %u received bytes",
        *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SchannelProcessingData
#define _clog_4_ARGS_TRACE_SchannelProcessingData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelProcessingData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Get unicode string size");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "Get unicode string size" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "unicode string",
            RequiredSize);
// arg2 = arg2 = "unicode string" = arg2
// arg3 = arg3 = RequiredSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "NULL CallbackData to CxPlatTlsSspiNotifyCallback");
// arg2 = arg2 = "NULL CallbackData to CxPlatTlsSspiNotifyCallback" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_SCHANNEL_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            Config->Connection,
            "Mismatched SEC_CONFIG IsServer state");
// arg2 = arg2 = Config->Connection = arg2
// arg3 = arg3 = "Mismatched SEC_CONFIG IsServer state" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_TlsError
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, TlsError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Convert SNI to unicode");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Convert SNI to unicode" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_SCHANNEL_C, TlsErrorStatus , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_schannel.c.clog.h.c"
#endif
