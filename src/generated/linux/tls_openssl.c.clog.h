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
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
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
#ifndef _clog_5_ARGS_TRACE_OpenSslLogSecret



/*----------------------------------------------------------
// Decoder Ring for OpenSslLogSecret
// [ tls] %s[%u]: %s
// QuicTraceLogVerbose(
        OpenSslLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
// arg2 = arg2 = Prefix
// arg3 = arg3 = Length
// arg4 = arg4 = SecretStr
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_OpenSslLogSecret(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslLogSecret , arg2, arg3, arg4);\

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
        Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Alert
// arg4 = arg4 = Level
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




#ifndef _clog_3_ARGS_TRACE_OpenSslHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for OpenSslHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnInfo(
            OpenSslHandshakeComplete,
            TlsContext->Connection,
            "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_OpenSslHandshakeComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslHandshakeComplete , arg1);\

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
        Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Level
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
        Level);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint64_t)Length
// arg4 = arg4 = Level
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_OpenSslAddHandshakeData(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSslAddHandshakeData , arg1, arg3, arg4);\

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




#ifndef _clog_4_ARGS_TRACE_OpenSsslIgnoringTicket



/*----------------------------------------------------------
// Decoder Ring for OpenSsslIgnoringTicket
// [conn][%p] Ignoring %u ticket bytes
// QuicTraceLogConnVerbose(
            OpenSsslIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_OpenSsslIgnoringTicket(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_OPENSSL_C, OpenSsslIgnoringTicket , arg1, arg3);\

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




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "OPENSSL_init_ssl failed");
// arg2 = arg2 = "OPENSSL_init_ssl failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_OPENSSL_C, LibraryError , arg2);\

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
tracepoint(CLOG_TLS_OPENSSL_C, LibraryErrorStatus , arg2, arg3);\

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




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_new failed");
// arg2 = arg2 = "EVP_CIPHER_CTX_new failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CipherInit_ex failed");
// arg2 = arg2 = "EVP_CipherInit_ex failed"
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
            ERR_get_error(),
            "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed"
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
            "EVP_EncryptInit_ex failed");
// arg2 = arg2 = "EVP_EncryptInit_ex failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate (AD) failed");
// arg2 = arg2 = "EVP_EncryptUpdate (AD) failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptUpdate (Cipher) failed");
// arg2 = arg2 = "EVP_EncryptUpdate (Cipher) failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptFinal_ex failed");
// arg2 = arg2 = "EVP_EncryptFinal_ex failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_CIPHER_CTX_ctrl (GET_TAG) failed");
// arg2 = arg2 = "EVP_CIPHER_CTX_ctrl (GET_TAG) failed"
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
            ERR_get_error(),
            "EVP_DecryptInit_ex failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "EVP_DecryptInit_ex failed"
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
            "EVP_DecryptUpdate (AD) failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "EVP_DecryptUpdate (AD) failed"
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
            "EVP_DecryptUpdate (Cipher) failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "EVP_DecryptUpdate (Cipher) failed"
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
            "EVP_CIPHER_CTX_ctrl (SET_TAG) failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "EVP_CIPHER_CTX_ctrl (SET_TAG) failed"
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
            "EVP_DecryptFinal_ex failed");
// arg2 = arg2 = ERR_get_error()
// arg3 = arg3 = "EVP_DecryptFinal_ex failed"
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
            "CXPLAT_HP_KEY",
            sizeof(CXPLAT_HP_KEY));
// arg2 = arg2 = "CXPLAT_HP_KEY"
// arg3 = arg3 = sizeof(CXPLAT_HP_KEY)
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
            "Cipherctx alloc failed");
// arg2 = arg2 = "Cipherctx alloc failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_EncryptInit_ex failed");
// arg2 = arg2 = "EVP_EncryptInit_ex failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "EVP_EncryptInit_ex (hp) failed");
// arg2 = arg2 = "EVP_EncryptInit_ex (hp) failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "EVP_EncryptUpdate (hp) failed");
// arg2 = arg2 = "EVP_EncryptUpdate (hp) failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "EVP_EncryptUpdate failed");
// arg2 = arg2 = "EVP_EncryptUpdate failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_CTX_new failed");
// arg2 = arg2 = "HMAC_CTX_new failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Init_ex failed");
// arg2 = arg2 = "HMAC_Init_ex failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Init_ex(NULL) failed");
// arg2 = arg2 = "HMAC_Init_ex(NULL) failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Update failed");
// arg2 = arg2 = "HMAC_Update failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "HMAC_Final failed");
// arg2 = arg2 = "HMAC_Final failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_openssl.c.clog.h.c"
#endif
