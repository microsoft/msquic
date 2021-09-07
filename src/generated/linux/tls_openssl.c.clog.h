#include <clog.h>
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
#ifndef _clog_5_ARGS_TRACE_OpenSslAlert



/*----------------------------------------------------------
// Decoder Ring for OpenSslAlert
// [conn][%p] Send alert = %u (Level = %u)
// QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        Alert,
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Alert
// arg4 = arg4 = (uint32_t)Level
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_OpenSslAlert(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAlert , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslQuicDataErrorStr



/*----------------------------------------------------------
// Decoder Ring for OpenSslQuicDataErrorStr
// [conn][%p] SSL_provide_quic_data failed: %s
// QuicTraceLogConnError(
                OpenSslQuicDataErrorStr,
                TlsContext->Connection,
                "SSL_provide_quic_data failed: %s",
                ERR_error_string(ERR_get_error(), buf));
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = ERR_error_string(ERR_get_error(), buf)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslQuicDataErrorStr(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslQuicDataErrorStr , arg1, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_OpenSslHandshakeErrorStr



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
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = buf
// arg4 = arg4 = (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file)
// arg5 = arg5 = line
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_OpenSslHandshakeErrorStr(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeErrorStr , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslHandshakeError



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeError
// [conn][%p] TLS handshake error: %d
// QuicTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Err
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslHandshakeError(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeError , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslAlpnNegotiationFailure



/*----------------------------------------------------------
// Decoder Ring for OpenSslAlpnNegotiationFailure
// [conn][%p] Failed to negotiate ALPN
// QuicTraceLogConnError(
                    OpenSslAlpnNegotiationFailure,
                    TlsContext->Connection,
                    "Failed to negotiate ALPN");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslAlpnNegotiationFailure(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAlpnNegotiationFailure , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslInvalidAlpnLength



/*----------------------------------------------------------
// Decoder Ring for OpenSslInvalidAlpnLength
// [conn][%p] Invalid negotiated ALPN length
// QuicTraceLogConnError(
                    OpenSslInvalidAlpnLength,
                    TlsContext->Connection,
                    "Invalid negotiated ALPN length");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslInvalidAlpnLength(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslInvalidAlpnLength , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslNoMatchingAlpn



/*----------------------------------------------------------
// Decoder Ring for OpenSslNoMatchingAlpn
// [conn][%p] Failed to find a matching ALPN
// QuicTraceLogConnError(
                    OpenSslNoMatchingAlpn,
                    TlsContext->Connection,
                    "Failed to find a matching ALPN");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslNoMatchingAlpn(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslNoMatchingAlpn , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslMissingTransportParameters



/*----------------------------------------------------------
// Decoder Ring for OpenSslMissingTransportParameters
// [conn][%p] No transport parameters received
// QuicTraceLogConnError(
                    OpenSslMissingTransportParameters,
                    TlsContext->Connection,
                    "No transport parameters received");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslMissingTransportParameters(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslMissingTransportParameters , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslHandshakeDataStart



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeDataStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                TlsState->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsState->BufferOffsetHandshake
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslHandshakeDataStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeDataStart , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSsl1RttDataStart



/*----------------------------------------------------------
// Decoder Ring for OpenSsl1RttDataStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                TlsState->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsState->BufferOffset1Rtt
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSsl1RttDataStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSsl1RttDataStart , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslOnRecvTicket



/*----------------------------------------------------------
// Decoder Ring for OpenSslOnRecvTicket
// [conn][%p] Received session ticket, %u bytes
// QuicTraceLogConnInfo(
                    OpenSslOnRecvTicket,
                    TlsContext->Connection,
                    "Received session ticket, %u bytes",
                    (uint32_t)Length);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Length
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslOnRecvTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslOnRecvTicket , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslOnSetTicket



/*----------------------------------------------------------
// Decoder Ring for OpenSslOnSetTicket
// [conn][%p] Setting session ticket, %u bytes
// QuicTraceLogConnInfo(
                OpenSslOnSetTicket,
                TlsContext->Connection,
                "Setting session ticket, %u bytes",
                Config->ResumptionTicketLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Config->ResumptionTicketLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslOnSetTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslOnSetTicket , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeComplete
// [conn][%p] TLS Handshake complete
// QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "TLS Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslHandshakeComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeComplete , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslHandshakeResumed



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeResumed
// [conn][%p] TLS Handshake resumed
// QuicTraceLogConnInfo(
                OpenSslHandshakeResumed,
                TlsContext->Connection,
                "TLS Handshake resumed");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslHandshakeResumed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeResumed , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslHandshakeDataStart



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeDataStart
// [conn][%p] Writing Handshake data starts at %u
// QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffsetHandshake
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslHandshakeDataStart(uniqueId, arg1, encoded_arg_string, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSsl1RttDataStart



/*----------------------------------------------------------
// Decoder Ring for OpenSsl1RttDataStart
// [conn][%p] Writing 1-RTT data starts at %u
// QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffset1Rtt
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSsl1RttDataStart(uniqueId, arg1, encoded_arg_string, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslNewEncryptionSecrets



/*----------------------------------------------------------
// Decoder Ring for OpenSslNewEncryptionSecrets
// [conn][%p] New encryption secrets (Level = %u)
// QuicTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Level
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslNewEncryptionSecrets(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslNewEncryptionSecrets , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_OpenSslAddHandshakeData



/*----------------------------------------------------------
// Decoder Ring for OpenSslAddHandshakeData
// [conn][%p] Sending %llu handshake bytes (Level = %u)
// QuicTraceLogConnVerbose(
        OpenSslAddHandshakeData,
        TlsContext->Connection,
        "Sending %llu handshake bytes (Level = %u)",
        (uint64_t)Length,
        (uint32_t)Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint64_t)Length
// arg4 = arg4 = (uint32_t)Level
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_OpenSslAddHandshakeData(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAddHandshakeData , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslTickedDecrypted



/*----------------------------------------------------------
// Decoder Ring for OpenSslTickedDecrypted
// [conn][%p] Session ticket decrypted, status %u
// QuicTraceLogConnVerbose(
        OpenSslTickedDecrypted,
        TlsContext->Connection,
        "Session ticket decrypted, status %u",
        (uint32_t)status);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)status
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslTickedDecrypted(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslTickedDecrypted , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslRecvTicketData



/*----------------------------------------------------------
// Decoder Ring for OpenSslRecvTicketData
// [conn][%p] Received ticket data, %u bytes
// QuicTraceLogConnVerbose(
            OpenSslRecvTicketData,
            TlsContext->Connection,
            "Received ticket data, %u bytes",
            (uint32_t)Length);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Length
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslRecvTicketData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslRecvTicketData , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslContextCreated



/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCreated
// [conn][%p] TLS context Created
// QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslContextCreated(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslContextCreated , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_OpenSslContextCleaningUp



/*----------------------------------------------------------
// Decoder Ring for OpenSslContextCleaningUp
// [conn][%p] Cleaning up
// QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslContextCleaningUp(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslContextCleaningUp , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslSendTicketData



/*----------------------------------------------------------
// Decoder Ring for OpenSslSendTicketData
// [conn][%p] Sending ticket data, %u bytes
// QuicTraceLogConnVerbose(
            OpenSslSendTicketData,
            TlsContext->Connection,
            "Sending ticket data, %u bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslSendTicketData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslSendTicketData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_OpenSslProcessData



/*----------------------------------------------------------
// Decoder Ring for OpenSslProcessData
// [conn][%p] Processing %u received bytes
// QuicTraceLogConnVerbose(
            OpenSslProcessData,
            TlsContext->Connection,
            "Processing %u received bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSslProcessData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslProcessData , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "No certificate passed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "No certificate passed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, TlsError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Internal certificate validation failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Internal certificate validation failed"
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
                    "Failed to serialize certificate context");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Failed to serialize certificate context"
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
                        "Failed to allocate PKCS7 context");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Failed to allocate PKCS7 context"
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




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Too much handshake data");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Too much handshake data"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto buffer",
                NewBufferAllocLength);
// arg2 = arg2 = "New crypto buffer"
// arg3 = arg3 = NewBufferAllocLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Session data too big");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Session data too big"
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
                ERR_get_error(),
                "PEM_write_bio_SSL_SESSION failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "PEM_write_bio_SSL_SESSION failed"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TlsErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, TlsErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_TlsErrorStatus



/*----------------------------------------------------------
// Decoder Ring for TlsErrorStatus
// [ tls][%p] ERROR, %u, %s.
// QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            ERR_get_error(),
            "BIO_new_mem_buf failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "BIO_new_mem_buf failed"
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
                "Failed to generate ticket IV");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Failed to generate ticket IV"
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
                "Ticket key_name mismatch");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Ticket key_name mismatch"
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
                "ReceiveTicket failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "ReceiveTicket failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CredConfig->AllowedCipherSuites,
            "No valid cipher suites presented");
// arg2 = arg2 = CredConfig->AllowedCipherSuites
// arg3 = arg3 = "No valid cipher suites presented"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
// arg2 = arg2 = "CXPLAT_SEC_CONFIG"
// arg3 = arg3 = sizeof(CXPLAT_SEC_CONFIG)
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
            ERR_get_error(),
            "SSL_CTX_new failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_new failed"
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
            ERR_get_error(),
            "SSL_CTX_set_min_proto_version failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_min_proto_version failed"
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
            ERR_get_error(),
            "SSL_CTX_set_max_proto_version failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_max_proto_version failed"
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
                "CipherSuiteString",
                CipherSuiteStringLength);
// arg2 = arg2 = "CipherSuiteString"
// arg3 = arg3 = CipherSuiteStringLength
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
            ERR_get_error(),
            "SSL_CTX_set_ciphersuites failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_ciphersuites failed"
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
                ERR_get_error(),
                "SSL_CTX_set_default_verify_paths failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_default_verify_paths failed"
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
            ERR_get_error(),
            "SSL_CTX_set1_groups_list failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set1_groups_list failed"
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
            ERR_get_error(),
            "SSL_CTX_set_quic_method failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_quic_method failed"
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
                    ERR_get_error(),
                    "SSL_CTX_set_max_early_data failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_max_early_data failed"
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
                    ERR_get_error(),
                    "SSL_CTX_set_session_ticket_cb failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_session_ticket_cb failed"
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
                ERR_get_error(),
                "SSL_CTX_set_num_tickets failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_set_num_tickets failed"
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
                ERR_get_error(),
                "SSL_CTX_use_PrivateKey_file failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_use_PrivateKey_file failed"
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
                ERR_get_error(),
                "SSL_CTX_use_certificate_chain_file failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_use_certificate_chain_file failed"
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
                ERR_get_error(),
                "BIO_new failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "BIO_new failed"
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
                ERR_get_error(),
                "d2i_PKCS12_bio failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "d2i_PKCS12_bio failed"
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
                ERR_get_error(),
                "PKCS12_parse failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "PKCS12_parse failed"
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
                ERR_get_error(),
                "SSL_CTX_use_PrivateKey_file failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_use_PrivateKey_file failed"
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
                ERR_get_error(),
                "SSL_CTX_use_certificate failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_use_certificate failed"
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
                ERR_get_error(),
                "SSL_CTX_use_RSAPrivateKey_file failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_use_RSAPrivateKey_file failed"
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
                ERR_get_error(),
                "SSL_CTX_use_certificate failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_use_certificate failed"
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
                ERR_get_error(),
                "SSL_CTX_check_private_key failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "SSL_CTX_check_private_key failed"
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
                "QUIC_TICKET_KEY_CONFIG",
                sizeof(QUIC_TICKET_KEY_CONFIG));
// arg2 = arg2 = "QUIC_TICKET_KEY_CONFIG"
// arg3 = arg3 = sizeof(QUIC_TICKET_KEY_CONFIG)
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
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
// arg2 = arg2 = "CXPLAT_TLS"
// arg3 = arg3 = sizeof(CXPLAT_TLS)
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
                    "SNI Too Long");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SNI Too Long"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

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
            "SSL_new failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SSL_new failed"
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
                            ERR_get_error(),
                            "SSL_set_session failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "SSL_set_session failed"
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
                        ERR_get_error(),
                        "PEM_read_bio_SSL_SESSION failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "PEM_read_bio_SSL_SESSION failed"
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
                    ERR_get_error(),
                    "BIO_new_mem_buf failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "BIO_new_mem_buf failed"
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
            "SSL_set_quic_transport_params failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SSL_set_quic_transport_params failed"
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
                "SSL_get_session failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SSL_get_session failed"
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
                ERR_get_error(),
                "SSL_SESSION_set1_ticket_appdata failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "SSL_SESSION_set1_ticket_appdata failed"
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
                ERR_get_error(),
                "SSL_new_session_ticket failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "SSL_new_session_ticket failed"
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
                SSL_get_error(TlsContext->Ssl, Ret),
                "SSL_do_handshake failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = SSL_get_error(TlsContext->Ssl, Ret)
// arg4 = arg4 = "SSL_do_handshake failed"
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
                ERR_get_error(),
                "SSL_process_quic_post_handshake failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = ERR_get_error()
// arg4 = arg4 = "SSL_process_quic_post_handshake failed"
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
                    "Unable to get cipher suite");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unable to get cipher suite"
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
                    "Unable to get negotiated alpn");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unable to get negotiated alpn"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_openssl.c.clog.h.c"
#endif
