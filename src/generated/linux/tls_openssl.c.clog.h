#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TLS_OPENSSL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tls_openssl.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_TLS_OPENSSL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TLS_OPENSSL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "tls_openssl.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnError
#define _clog_MACRO_QuicTraceLogConnError  1
#define QuicTraceLogConnError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
// Decoder Ring for OpenSslAlert
// [conn][%p] Send alert = %u (Level = %u)
// QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = Alert = arg3
// arg4 = arg4 = (uint32_t)Level = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_OpenSslAlert
#define _clog_5_ARGS_TRACE_OpenSslAlert(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAlert , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslQuicDataErrorStr
// [conn][%p] SSL_provide_quic_data failed: %s
// QuicTraceLogConnError(
                OpenSslQuicDataErrorStr,
                TlsContext->Connection,
                "SSL_provide_quic_data failed: %s",
                ERR_error_string(ERR_get_error(), buf));
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = ERR_error_string(ERR_get_error(), buf) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslQuicDataErrorStr
#define _clog_4_ARGS_TRACE_OpenSslQuicDataErrorStr(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslQuicDataErrorStr , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeErrorStr
// [conn][%p] TLS handshake error: %s, file:%s:%d
// QuicTraceLogConnError(
                    OpenSslHandshakeErrorStr,
                    TlsContext->Connection,
                    "TLS handshake error: %s, file:%s:%d",
                    buf,
                    (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file),
                    line);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = buf = arg3
// arg4 = arg4 = (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file) = arg4
// arg5 = arg5 = line = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_OpenSslHandshakeErrorStr
#define _clog_6_ARGS_TRACE_OpenSslHandshakeErrorStr(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeErrorStr , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeError
// [conn][%p] TLS handshake error: %d
// QuicTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = Err = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslHandshakeError
#define _clog_4_ARGS_TRACE_OpenSslHandshakeError(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeError , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslAlpnNegotiationFailure
// [conn][%p] Failed to negotiate ALPN
// QuicTraceLogConnError(
                    OpenSslAlpnNegotiationFailure,
                    TlsContext->Connection,
                    "Failed to negotiate ALPN");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslAlpnNegotiationFailure
#define _clog_3_ARGS_TRACE_OpenSslAlpnNegotiationFailure(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAlpnNegotiationFailure , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslInvalidAlpnLength
// [conn][%p] Invalid negotiated ALPN length
// QuicTraceLogConnError(
                    OpenSslInvalidAlpnLength,
                    TlsContext->Connection,
                    "Invalid negotiated ALPN length");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslInvalidAlpnLength
#define _clog_3_ARGS_TRACE_OpenSslInvalidAlpnLength(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslInvalidAlpnLength , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslNoMatchingAlpn
// [conn][%p] Failed to find a matching ALPN
// QuicTraceLogConnError(
                    OpenSslNoMatchingAlpn,
                    TlsContext->Connection,
                    "Failed to find a matching ALPN");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslNoMatchingAlpn
#define _clog_3_ARGS_TRACE_OpenSslNoMatchingAlpn(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslNoMatchingAlpn , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslMissingTransportParameters
// [conn][%p] No transport parameters received
// QuicTraceLogConnError(
                    OpenSslMissingTransportParameters,
                    TlsContext->Connection,
                    "No transport parameters received");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslMissingTransportParameters
#define _clog_3_ARGS_TRACE_OpenSslMissingTransportParameters(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslMissingTransportParameters , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeDataStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                TlsState->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = TlsState->BufferOffsetHandshake = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslHandshakeDataStart
#define _clog_4_ARGS_TRACE_OpenSslHandshakeDataStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeDataStart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSsl1RttDataStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                TlsState->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = TlsState->BufferOffset1Rtt = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSsl1RttDataStart
#define _clog_4_ARGS_TRACE_OpenSsl1RttDataStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSsl1RttDataStart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslOnRecvTicket
// [conn][%p] Received session ticket, %u bytes
// QuicTraceLogConnInfo(
                    OpenSslOnRecvTicket,
                    TlsContext->Connection,
                    "Received session ticket, %u bytes",
                    (uint32_t)Length);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)Length = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslOnRecvTicket
#define _clog_4_ARGS_TRACE_OpenSslOnRecvTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslOnRecvTicket , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslOnSetTicket
// [conn][%p] Setting session ticket, %u bytes
// QuicTraceLogConnInfo(
                OpenSslOnSetTicket,
                TlsContext->Connection,
                "Setting session ticket, %u bytes",
                Config->ResumptionTicketLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = Config->ResumptionTicketLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslOnSetTicket
#define _clog_4_ARGS_TRACE_OpenSslOnSetTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslOnSetTicket , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeComplete
// [conn][%p] TLS Handshake complete
// QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "TLS Handshake complete");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslHandshakeComplete
#define _clog_3_ARGS_TRACE_OpenSslHandshakeComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeComplete , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeResumed
// [conn][%p] TLS Handshake resumed
// QuicTraceLogConnInfo(
                OpenSslHandshakeResumed,
                TlsContext->Connection,
                "TLS Handshake resumed");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslHandshakeResumed
#define _clog_3_ARGS_TRACE_OpenSslHandshakeResumed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeResumed , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslNewEncryptionSecrets
// [conn][%p] New encryption secrets (Level = %u)
// QuicTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)Level = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslNewEncryptionSecrets
#define _clog_4_ARGS_TRACE_OpenSslNewEncryptionSecrets(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslNewEncryptionSecrets , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslAddHandshakeData
// [conn][%p] Sending %llu handshake bytes (Level = %u)
// QuicTraceLogConnVerbose(
        OpenSslAddHandshakeData,
        TlsContext->Connection,
        "Sending %llu handshake bytes (Level = %u)",
        (uint64_t)Length,
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint64_t)Length = arg3
// arg4 = arg4 = (uint32_t)Level = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_OpenSslAddHandshakeData
#define _clog_5_ARGS_TRACE_OpenSslAddHandshakeData(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAddHandshakeData , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslTickedDecrypted
// [conn][%p] Session ticket decrypted, status %u
// QuicTraceLogConnVerbose(
        OpenSslTickedDecrypted,
        TlsContext->Connection,
        "Session ticket decrypted, status %u",
        (uint32_t)status);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslTickedDecrypted
#define _clog_4_ARGS_TRACE_OpenSslTickedDecrypted(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslTickedDecrypted , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslRecvTicketData
// [conn][%p] Received ticket data, %u bytes
// QuicTraceLogConnVerbose(
            OpenSslRecvTicketData,
            TlsContext->Connection,
            "Received ticket data, %u bytes",
            (uint32_t)Length);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = (uint32_t)Length = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslRecvTicketData
#define _clog_4_ARGS_TRACE_OpenSslRecvTicketData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslRecvTicketData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslContextCreated
#define _clog_3_ARGS_TRACE_OpenSslContextCreated(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslContextCreated , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_OpenSslContextCleaningUp
#define _clog_3_ARGS_TRACE_OpenSslContextCleaningUp(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslContextCleaningUp , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslSendTicketData
// [conn][%p] Sending ticket data, %u bytes
// QuicTraceLogConnVerbose(
            OpenSslSendTicketData,
            TlsContext->Connection,
            "Sending ticket data, %u bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslSendTicketData
#define _clog_4_ARGS_TRACE_OpenSslSendTicketData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslSendTicketData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for OpenSslProcessData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
            OpenSslProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection = arg1
// arg3 = arg3 = *BufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_OpenSslProcessData
#define _clog_4_ARGS_TRACE_OpenSslProcessData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslProcessData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "No certificate passed");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = "No certificate passed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_TlsError
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, TlsError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "i2d_X509 failed");
// arg2 = arg2 = "i2d_X509 failed" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_OPENSSL_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto buffer",
                NewBufferAllocLength);
// arg2 = arg2 = "New crypto buffer" = arg2
// arg3 = arg3 = NewBufferAllocLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "PEM_write_bio_SSL_SESSION failed");
// arg2 = arg2 = TlsContext->Connection = arg2
// arg3 = arg3 = ERR_get_error() = arg3
// arg4 = arg4 = "PEM_write_bio_SSL_SESSION failed" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, TlsErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CredConfig->AllowedCipherSuites,
            "No valid cipher suites presented");
// arg2 = arg2 = CredConfig->AllowedCipherSuites = arg2
// arg3 = arg3 = "No valid cipher suites presented" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_openssl.c.clog.h.c"
#endif
