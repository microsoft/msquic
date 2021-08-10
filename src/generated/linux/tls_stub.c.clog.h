#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TLS_STUB_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tls_stub.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_TLS_STUB_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TLS_STUB_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "tls_stub.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
#ifndef _clog_3_ARGS_TRACE_StubTlsCertValidationDisabled



/*----------------------------------------------------------
// Decoder Ring for StubTlsCertValidationDisabled
// [conn][%p] Certificate validation disabled!
// QuicTraceLogConnWarning(
                    StubTlsCertValidationDisabled,
                    TlsContext->Connection,
                    "Certificate validation disabled!");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StubTlsCertValidationDisabled(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_STUB_C, StubTlsCertValidationDisabled , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_StubTlsHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for StubTlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
                StubTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StubTlsHandshakeComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_STUB_C, StubTlsHandshakeComplete , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_StubTlsHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for StubTlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
                StubTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StubTlsHandshakeComplete(uniqueId, arg1, encoded_arg_string)\

#endif




#ifndef _clog_4_ARGS_TRACE_StubTlsProducedData



/*----------------------------------------------------------
// Decoder Ring for StubTlsProducedData
// [conn][%p] Produced %hu bytes
// QuicTraceLogConnInfo(
                StubTlsProducedData,
                TlsContext->Connection,
                "Produced %hu bytes",
                (State->BufferLength - PrevBufferLength));
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (State->BufferLength - PrevBufferLength)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StubTlsProducedData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_STUB_C, StubTlsProducedData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_StubTlsConsumedData



/*----------------------------------------------------------
// Decoder Ring for StubTlsConsumedData
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnInfo(
            StubTlsConsumedData,
            TlsContext->Connection,
            "Consumed %u bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StubTlsConsumedData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_STUB_C, StubTlsConsumedData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_StubTlsProducedData



/*----------------------------------------------------------
// Decoder Ring for StubTlsProducedData
// [conn][%p] Produced %hu bytes
// QuicTraceLogConnInfo(
                StubTlsProducedData,
                TlsContext->Connection,
                "Produced %hu bytes",
                (State->BufferLength - PrevBufferLength));
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (State->BufferLength - PrevBufferLength)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StubTlsProducedData(uniqueId, arg1, encoded_arg_string, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_StubTlsContextCreated



/*----------------------------------------------------------
// Decoder Ring for StubTlsContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        StubTlsContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StubTlsContextCreated(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_STUB_C, StubTlsContextCreated , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_StubTlsUsing0Rtt



/*----------------------------------------------------------
// Decoder Ring for StubTlsUsing0Rtt
// [conn][%p] Using 0-RTT ticket.
// QuicTraceLogConnVerbose(
            StubTlsUsing0Rtt,
            TlsContext->Connection,
            "Using 0-RTT ticket.");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StubTlsUsing0Rtt(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_STUB_C, StubTlsUsing0Rtt , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_StubTlsContextCleaningUp



/*----------------------------------------------------------
// Decoder Ring for StubTlsContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            StubTlsContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_StubTlsContextCleaningUp(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_STUB_C, StubTlsContextCleaningUp , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_StubTlsRecvNewSessionTicket



/*----------------------------------------------------------
// Decoder Ring for StubTlsRecvNewSessionTicket
// [conn][%p] Received new ticket. ticket_len:%u for %s
// QuicTraceLogConnVerbose(
            StubTlsRecvNewSessionTicket,
            TlsContext->Connection,
            "Received new ticket. ticket_len:%u for %s",
            ServerMessageLength,
            TlsContext->SNI);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = ServerMessageLength
// arg4 = arg4 = TlsContext->SNI
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_StubTlsRecvNewSessionTicket(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_STUB_C, StubTlsRecvNewSessionTicket , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_StubTlsProcessData



/*----------------------------------------------------------
// Decoder Ring for StubTlsProcessData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
            StubTlsProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_StubTlsProcessData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_STUB_C, StubTlsProcessData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
// arg2 = arg2 = "CXPLAT_TLS"
// arg3 = arg3 = sizeof(CXPLAT_TLS)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_STUB_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "SNI Too Long");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SNI Too Long"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_STUB_C, TlsError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "SNI",
                ServerNameLength + 1);
// arg2 = arg2 = "SNI"
// arg3 = arg3 = ServerNameLength + 1
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
                "CxPlatCertSelect failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "CxPlatCertSelect failed"
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
                    "Failure client finish");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Failure client finish"
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
                ClientMessage->Type,
                "Invalid message");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ClientMessage->Type
// arg4 = arg4 = "Invalid message"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_STUB_C, TlsErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            TlsContext->LastMessageType,
            "Invalid last message");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = TlsContext->LastMessageType
// arg4 = arg4 = "Invalid last message"
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




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "CxPlatCertParseChain Mismatch");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "CxPlatCertParseChain Mismatch"
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
                        "CxPlatCertValidateChain Mismatch");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "CxPlatCertValidateChain Mismatch"
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
                    "Indicate certificate received failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Indicate certificate received failed"
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
                ServerMessage->Type,
                "Invalid message");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ServerMessage->Type
// arg4 = arg4 = "Invalid message"
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
                ServerMessage->Type,
                "Invalid message");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ServerMessage->Type
// arg4 = arg4 = "Invalid message"
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
            TlsContext->LastMessageType,
            "Invalid last message");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = TlsContext->LastMessageType
// arg4 = arg4 = "Invalid last message"
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
            "Insufficient data to process header");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Insufficient data to process header"
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
            "Insufficient data to process payload");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Insufficient data to process payload"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_stub.c.clog.h.c"
#endif
