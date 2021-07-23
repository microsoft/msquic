#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CERT_CAPI_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "cert_capi.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CERT_CAPI_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CERT_CAPI_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "cert_capi.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_5_ARGS_TRACE_CertCapiVerifiedChain



/*----------------------------------------------------------
// Decoder Ring for CertCapiVerifiedChain
// CertVerifyChain: %S 0x%x, result=0x%x
// QuicTraceLogInfo(
        CertCapiVerifiedChain,
        "CertVerifyChain: %S 0x%x, result=0x%x",
        ServerName,
        IgnoreFlags,
        Status);
// arg2 = arg2 = ServerName
// arg3 = arg3 = IgnoreFlags
// arg4 = arg4 = Status
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_CertCapiVerifiedChain(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiVerifiedChain , arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_CertCapiParsedChain



/*----------------------------------------------------------
// Decoder Ring for CertCapiParsedChain
// [cert] Successfully parsed chain of %u certificate(s)
// QuicTraceLogVerbose(
        CertCapiParsedChain,
        "[cert] Successfully parsed chain of %u certificate(s)",
        CertNumber);
// arg2 = arg2 = CertNumber
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CertCapiParsedChain(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiParsedChain , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_CertCapiFormattedChain



/*----------------------------------------------------------
// Decoder Ring for CertCapiFormattedChain
// [cert] Successfully formatted chain of %u certificate(s)
// QuicTraceLogVerbose(
        CertCapiFormattedChain,
        "[cert] Successfully formatted chain of %u certificate(s)",
        CertNumber);
// arg2 = arg2 = CertNumber
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CertCapiFormattedChain(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiFormattedChain , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_CertCapiSign



/*----------------------------------------------------------
// Decoder Ring for CertCapiSign
// [cert] QuicCertSign alg=0x%4.4x
// QuicTraceLogVerbose(
        CertCapiSign,
        "[cert] QuicCertSign alg=0x%4.4x",
        SignatureAlgorithm);
// arg2 = arg2 = SignatureAlgorithm
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CertCapiSign(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiSign , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_CertCapiVerify



/*----------------------------------------------------------
// Decoder Ring for CertCapiVerify
// [cert] QuicCertVerify alg=0x%4.4x
// QuicTraceLogVerbose(
        CertCapiVerify,
        "[cert] QuicCertVerify alg=0x%4.4x",
        SignatureAlgorithm);
// arg2 = arg2 = SignatureAlgorithm
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CertCapiVerify(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiVerify , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "Get CERT_HASH_PROP_ID failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "Get CERT_HASH_PROP_ID failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CERT_CAPI_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CertHashLength,
            "CERT_HASH_PROP_ID incorrect size");
// arg2 = arg2 = CertHashLength
// arg3 = arg3 = "CERT_HASH_PROP_ID incorrect size"
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
            "CertOpenStore failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "CertOpenStore failed"
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
            GetLastError(),
            "CertOpenStore failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertOpenStore failed"
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
            GetLastError(),
            "CertAddEncodedCertificateToStore failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertAddEncodedCertificateToStore failed"
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
            "Not all cert bytes were processed");
// arg2 = arg2 = "Not all cert bytes were processed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, LibraryError , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Insufficient buffer to store the empty formatted chain");
// arg2 = arg2 = "Insufficient buffer to store the empty formatted chain"
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
            GetLastError(),
            "CertGetCertificateChain failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertGetCertificateChain failed"
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
                    "Insufficient buffer to store the formatted chain");
// arg2 = arg2 = "Insufficient buffer to store the formatted chain"
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
            "CertVerifyCertificateChainPolicy failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "CertVerifyCertificateChainPolicy failed"
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
            "CertVerifyCertificateChainPolicy indicated a cert error");
// arg2 = arg2 = Status
// arg3 = arg3 = "CertVerifyCertificateChainPolicy indicated a cert error"
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
            GetLastError(),
            "CertGetCertificateChain failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertGetCertificateChain failed"
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
                "Convert Host to unicode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Convert Host to unicode"
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
            GetLastError(),
            "CryptAcquireCertificatePrivateKey failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CryptAcquireCertificatePrivateKey failed"
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
            KeySpec,
            "Cert KeySpec doesn't have CERT_NCRYPT_KEY_SPEC");
// arg2 = arg2 = KeySpec
// arg3 = arg3 = "Cert KeySpec doesn't have CERT_NCRYPT_KEY_SPEC"
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
            SignatureAlgorithm,
            "Unsupported hash algorithm (HashAlg)");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported hash algorithm (HashAlg)"
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
            SignatureAlgorithm,
            "Unsupported hash algorithm");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported hash algorithm"
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
            SignatureAlgorithm,
            "Unsupported hash size");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported hash size"
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
            SignatureAlgorithm,
            "Unsupported padding scheme");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported padding scheme"
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
            "BCryptHash failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptHash failed"
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
            "NCryptSignHash failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "NCryptSignHash failed"
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
            "CertListToVerify or Signature too large");
// arg2 = arg2 = "CertListToVerify or Signature too large"
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
            SignatureAlgorithm,
            "Unsupported hash algorithm (HashAlg)");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported hash algorithm (HashAlg)"
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
            SignatureAlgorithm,
            "Unsupported padding scheme");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported padding scheme"
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
            SignatureAlgorithm,
            "Unsupported hash algorithm");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported hash algorithm"
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
            SignatureAlgorithm,
            "Unsupported hash size");
// arg2 = arg2 = SignatureAlgorithm
// arg3 = arg3 = "Unsupported hash size"
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
            "BCryptHash failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptHash failed"
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
            "CryptImportPublicKeyInfoEx2 failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "CryptImportPublicKeyInfoEx2 failed"
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
            "BCryptVerifySignature failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "BCryptVerifySignature failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_cert_capi.c.clog.h.c"
#endif

