#include <clog.h>
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
#ifndef _clog_2_ARGS_TRACE_SchannelInitialized



/*----------------------------------------------------------
// Decoder Ring for SchannelInitialized
// [ tls] Library initialized
// QuicTraceLogVerbose(
        SchannelInitialized,
        "[ tls] Library initialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_SchannelInitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelInitialized );\

#endif




#ifndef _clog_2_ARGS_TRACE_SchannelInitialized



/*----------------------------------------------------------
// Decoder Ring for SchannelInitialized
// [ tls] Library initialized
// QuicTraceLogVerbose(
        SchannelInitialized,
        "[ tls] Library initialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_SchannelInitialized(uniqueId, encoded_arg_string)\

#endif




#ifndef _clog_2_ARGS_TRACE_SchannelUninitialized



/*----------------------------------------------------------
// Decoder Ring for SchannelUninitialized
// [ tls] Library uninitialized
// QuicTraceLogVerbose(
        SchannelUninitialized,
        "[ tls] Library uninitialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_SchannelUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelUninitialized );\

#endif




#ifndef _clog_2_ARGS_TRACE_SchannelAchAsync



/*----------------------------------------------------------
// Decoder Ring for SchannelAchAsync
// [ tls] Calling SspiAcquireCredentialsHandleAsyncW
// QuicTraceLogVerbose(
        SchannelAchAsync,
        "[ tls] Calling SspiAcquireCredentialsHandleAsyncW");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_SchannelAchAsync(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAchAsync );\

#endif




#ifndef _clog_2_ARGS_TRACE_SchannelAchWorkerStart



/*----------------------------------------------------------
// Decoder Ring for SchannelAchWorkerStart
// [ tls] Starting ACH worker
// QuicTraceLogVerbose(
        SchannelAchWorkerStart,
        "[ tls] Starting ACH worker");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_SchannelAchWorkerStart(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAchWorkerStart );\

#endif




#ifndef _clog_2_ARGS_TRACE_SchannelAch



/*----------------------------------------------------------
// Decoder Ring for SchannelAch
// [ tls] Calling AcquireCredentialsHandleW
// QuicTraceLogVerbose(
        SchannelAch,
        "[ tls] Calling AcquireCredentialsHandleW");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_SchannelAch(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAch );\

#endif




#ifndef _clog_3_ARGS_TRACE_SchannelAchCompleteInline



/*----------------------------------------------------------
// Decoder Ring for SchannelAchCompleteInline
// [ tls] Invoking security config completion callback inline, 0x%x
// QuicTraceLogVerbose(
        SchannelAchCompleteInline,
        "[ tls] Invoking security config completion callback inline, 0x%x",
        Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SchannelAchCompleteInline(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelAchCompleteInline , arg2);\

#endif




#ifndef _clog_5_ARGS_TRACE_SchannelLogSecret



/*----------------------------------------------------------
// Decoder Ring for SchannelLogSecret
// [ tls] %s[%u]: %s
// QuicTraceLogVerbose(
        SchannelLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
// arg2 = arg2 = Prefix
// arg3 = arg3 = Length
// arg4 = arg4 = SecretStr
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_SchannelLogSecret(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelLogSecret , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for SchannelHandshakeComplete
// [conn][%p] Handshake complete (resume=%hu)
// QuicTraceLogConnInfo(
                SchannelHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete (resume=%hu)",
                State->SessionResumed);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->SessionResumed
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelHandshakeComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelHandshakeComplete , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelConsumedBytes



/*----------------------------------------------------------
// Decoder Ring for SchannelConsumedBytes
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnInfo(
            SchannelConsumedBytes,
            TlsContext->Connection,
            "Consumed %u bytes",
            *InBufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *InBufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelConsumedBytes(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelConsumedBytes , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_SchannelReadHandshakeStart



/*----------------------------------------------------------
// Decoder Ring for SchannelReadHandshakeStart
// [conn][%p] Reading Handshake data starts now
// QuicTraceLogConnInfo(
                        SchannelReadHandshakeStart,
                        TlsContext->Connection,
                        "Reading Handshake data starts now");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SchannelReadHandshakeStart(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelReadHandshakeStart , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_SchannelRead1RttStart



/*----------------------------------------------------------
// Decoder Ring for SchannelRead1RttStart
// [conn][%p] Reading 1-RTT data starts now
// QuicTraceLogConnInfo(
                        SchannelRead1RttStart,
                        TlsContext->Connection,
                        "Reading 1-RTT data starts now");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SchannelRead1RttStart(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelRead1RttStart , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelWriteHandshakeStart



/*----------------------------------------------------------
// Decoder Ring for SchannelWriteHandshakeStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                        SchannelWriteHandshakeStart,
                        TlsContext->Connection,
                        "Writing Handshake data starts at %u",
                        State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffsetHandshake
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelWriteHandshakeStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelWriteHandshakeStart , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelWrite1RttStart



/*----------------------------------------------------------
// Decoder Ring for SchannelWrite1RttStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                            SchannelWrite1RttStart,
                            TlsContext->Connection,
                            "Writing 1-RTT data starts at %u",
                            State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffset1Rtt
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelWrite1RttStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelWrite1RttStart , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelProducedData



/*----------------------------------------------------------
// Decoder Ring for SchannelProducedData
// [conn][%p] Produced %u bytes
// QuicTraceLogConnInfo(
                SchannelProducedData,
                TlsContext->Connection,
                "Produced %u bytes",
                OutputTokenBuffer->cbBuffer);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = OutputTokenBuffer->cbBuffer
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelProducedData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelProducedData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelMissingData



/*----------------------------------------------------------
// Decoder Ring for SchannelMissingData
// [conn][%p] TLS message missing %u bytes of data
// QuicTraceLogConnInfo(
                SchannelMissingData,
                TlsContext->Connection,
                "TLS message missing %u bytes of data",
                MissingBuffer->cbBuffer);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = MissingBuffer->cbBuffer
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelMissingData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelMissingData , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_SchannelContextCreated



/*----------------------------------------------------------
// Decoder Ring for SchannelContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        SchannelContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SchannelContextCreated(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelContextCreated , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_SchannelContextCleaningUp



/*----------------------------------------------------------
// Decoder Ring for SchannelContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            SchannelContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_SchannelContextCleaningUp(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelContextCleaningUp , arg1);\

#endif




#ifndef _clog_6_ARGS_TRACE_SchannelKeyReady



/*----------------------------------------------------------
// Decoder Ring for SchannelKeyReady
// [conn][%p] Key Ready Type, %u [%hu to %hu]
// QuicTraceLogConnVerbose(
                SchannelKeyReady,
                TlsContext->Connection,
                "Key Ready Type, %u [%hu to %hu]",
                TrafficSecret->TrafficSecretType,
                TrafficSecret->MsgSequenceStart,
                TrafficSecret->MsgSequenceEnd);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TrafficSecret->TrafficSecretType
// arg4 = arg4 = TrafficSecret->MsgSequenceStart
// arg5 = arg5 = TrafficSecret->MsgSequenceEnd
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_SchannelKeyReady(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelKeyReady , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelIgnoringTicket



/*----------------------------------------------------------
// Decoder Ring for SchannelIgnoringTicket
// [conn][%p] Ignoring %u ticket bytes
// QuicTraceLogConnVerbose(
            SchannelIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelIgnoringTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelIgnoringTicket , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_SchannelProcessingData



/*----------------------------------------------------------
// Decoder Ring for SchannelProcessingData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
        SchannelProcessingData,
        TlsContext->Connection,
        "Processing %u received bytes",
        *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SchannelProcessingData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, SchannelProcessingData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "Get wchar string size");
// arg2 = arg2 = Error
// arg3 = arg3 = "Get wchar string size"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "wchar string",
            sizeof(WCHAR) * Size);
// arg2 = arg2 = "wchar string"
// arg3 = arg3 = sizeof(WCHAR) * Size
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "Convert string to wchar");
// arg2 = arg2 = Error
// arg3 = arg3 = "Convert string to wchar"
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
            "Get unicode string size");
// arg2 = arg2 = Status
// arg3 = arg3 = "Get unicode string size"
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
            "unicode string",
            RequiredSize);
// arg2 = arg2 = "unicode string"
// arg3 = arg3 = RequiredSize
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
            "Convert string to unicode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Convert string to unicode"
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
            "Open HMAC_SHA256 algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open HMAC_SHA256 algorithm"
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
            "Open HMAC_SHA384 algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open HMAC_SHA384 algorithm"
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
            "Open HMAC_SHA512 algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open HMAC_SHA512 algorithm"
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
            "Open AES algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open AES algorithm"
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
            "Set ECB chaining mode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Set ECB chaining mode"
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
            "Open AES algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open AES algorithm"
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
            "Set GCM chaining mode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Set GCM chaining mode"
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
            "Open ChaCha20-Poly1305 algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open ChaCha20-Poly1305 algorithm"
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
                "Set ChaCha20-Poly1305 chaining mode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Set ChaCha20-Poly1305 chaining mode"
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
            "Open ChaCha20-Poly1305 algorithm");
// arg2 = arg2 = Status
// arg3 = arg3 = "Open ChaCha20-Poly1305 algorithm"
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
                "Set ChaCha20-Poly1305 chaining mode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Set ChaCha20-Poly1305 chaining mode"
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
            "QUIC_ACH_CONTEXT",
            sizeof(QUIC_ACH_CONTEXT));
// arg2 = arg2 = "QUIC_ACH_CONTEXT"
// arg3 = arg3 = sizeof(QUIC_ACH_CONTEXT)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "NULL CallbackData to QuicTlsSspiNotifyCallback");
// arg2 = arg2 = "NULL CallbackData to QuicTlsSspiNotifyCallback"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_SCHANNEL_C, LibraryError , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Completion for SspiAcquireCredentialsHandleAsyncW");
// arg2 = arg2 = Status
// arg3 = arg3 = "Completion for SspiAcquireCredentialsHandleAsyncW"
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
            SecStatus,
            "SspiAcquireCredentialsHandleAsyncW");
// arg2 = arg2 = SecStatus
// arg3 = arg3 = "SspiAcquireCredentialsHandleAsyncW"
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
            "QUIC_SEC_CONFIG",
            sizeof(QUIC_SEC_CONFIG));
// arg2 = arg2 = "QUIC_SEC_CONFIG"
// arg3 = arg3 = sizeof(QUIC_SEC_CONFIG)
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
                "Convert cert store name to unicode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Convert cert store name to unicode"
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
            "Invalid flags passed in to QuicTlsSecConfigCreate");
// arg2 = arg2 = "Invalid flags passed in to QuicTlsSecConfigCreate"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Convert principal to unicode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Convert principal to unicode"
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
                "QuicCertCreate");
// arg2 = arg2 = Status
// arg3 = arg3 = "QuicCertCreate"
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
            "SspiCreateAsyncContext");
// arg2 = arg2 = "SspiCreateAsyncContext"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SspiSetAsyncNotifyCallback");
// arg2 = arg2 = SecStatus
// arg3 = arg3 = "SspiSetAsyncNotifyCallback"
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
                "PsCreateSystemThread(QuicTlsAchWorker)");
// arg2 = arg2 = Status
// arg3 = arg3 = "PsCreateSystemThread(QuicTlsAchWorker)"
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
                "ObReferenceObjectByHandle(QuicTlsAchWorker)");
// arg2 = arg2 = Status
// arg3 = arg3 = "ObReferenceObjectByHandle(QuicTlsAchWorker)"
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
            SecStatus,
            "AcquireCredentialsHandleW");
// arg2 = arg2 = SecStatus
// arg3 = arg3 = "AcquireCredentialsHandleW"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            Config->Connection,
            "Mismatched SEC_CONFIG IsServer state");
// arg2 = arg2 = Config->Connection
// arg3 = arg3 = "Mismatched SEC_CONFIG IsServer state"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_SCHANNEL_C, TlsError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS",
            sizeof(QUIC_TLS));
// arg2 = arg2 = "QUIC_TLS"
// arg3 = arg3 = sizeof(QUIC_TLS)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Convert SNI to unicode");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "Convert SNI to unicode"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_SCHANNEL_C, TlsErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "No QUIC TP received");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "No QUIC TP received"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        SecStatus,
                        "query negotiated ALPN");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = SecStatus
// arg4 = arg4 = "query negotiated ALPN"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        NegotiatedAlpn.ProtoNegoStatus,
                        "ALPN negotiation status");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = NegotiatedAlpn.ProtoNegoStatus
// arg4 = arg4 = "ALPN negotiation status"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "ALPN Mismatch");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "ALPN Mismatch"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    SecStatus,
                    "query session info");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = SecStatus
// arg4 = arg4 = "query session info"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "TLS alert message received (invalid)");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "TLS alert message received (invalid)"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    State->AlertCode,
                    "TLS alert message received");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = State->AlertCode
// arg4 = arg4 = "TLS alert message received"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "QUIC TP wasn't present");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "QUIC TP wasn't present"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Process QUIC TP");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Process QUIC TP"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "TLS alert message received (invalid)");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "TLS alert message received (invalid)"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    State->AlertCode,
                    "TLS alert message received");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = State->AlertCode
// arg4 = arg4 = "TLS alert message received"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            SecStatus,
            "Accept/InitializeSecurityContext");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = SecStatus
// arg4 = arg4 = "Accept/InitializeSecurityContext"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
// arg2 = arg2 = "QUIC_PACKET_KEY"
// arg3 = arg3 = PacketKeyLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported chaining mode");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported chaining mode"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported AES key size");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported AES key size"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Algorithm unsupported by TLS: ChaCha20-Poly1305");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Algorithm unsupported by TLS: ChaCha20-Poly1305"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported ChaCha key size");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported ChaCha key size"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported symmetric algorithm");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported symmetric algorithm"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported hash algorithm");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported hash algorithm"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            Status,
            "QuicPacketKeyDerive");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "QuicPacketKeyDerive"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptGenerateSymmetricKey");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptGenerateSymmetricKey"
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
            "QUIC_HP_KEY",
            AllocLength);
// arg2 = arg2 = "QUIC_HP_KEY"
// arg3 = arg3 = AllocLength
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
            (AeadType == QUIC_AEAD_CHACHA20_POLY1305) ?
                "BCryptGenerateSymmetricKey (ChaCha)" :
                "BCryptGenerateSymmetricKey (ECB)");
// arg2 = arg2 = Status
// arg3 = arg3 = (AeadType == QUIC_AEAD_CHACHA20_POLY1305) ?
                "BCryptGenerateSymmetricKey (ChaCha)" :
                "BCryptGenerateSymmetricKey (ECB)"
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
            "BCryptCreateHash");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptCreateHash"
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
            "BCryptHashData");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptHashData"
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
            "BCryptFinishHash");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptFinishHash"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_schannel.c.clog.h.c"
#endif
