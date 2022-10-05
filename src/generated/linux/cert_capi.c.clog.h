#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
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
/*----------------------------------------------------------
// Decoder Ring for CertCapiVerifiedChain
// CertVerifyChain: %S 0x%x, result=0x%x
// QuicTraceLogInfo(
        CertCapiVerifiedChain,
        "CertVerifyChain: %S 0x%x, result=0x%x",
        ServerName,
        CredFlags,
        Status);
// arg2 = arg2 = ServerName = arg2
// arg3 = arg3 = CredFlags = arg3
// arg4 = arg4 = Status = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CertCapiVerifiedChain
#define _clog_5_ARGS_TRACE_CertCapiVerifiedChain(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiVerifiedChain , arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCapiParsedChain
// [cert] Successfully parsed chain of %u certificate(s)
// QuicTraceLogVerbose(
        CertCapiParsedChain,
        "[cert] Successfully parsed chain of %u certificate(s)",
        CertNumber);
// arg2 = arg2 = CertNumber = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CertCapiParsedChain
#define _clog_3_ARGS_TRACE_CertCapiParsedChain(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiParsedChain , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCapiFormattedChain
// [cert] Successfully formatted chain of %u certificate(s)
// QuicTraceLogVerbose(
        CertCapiFormattedChain,
        "[cert] Successfully formatted chain of %u certificate(s)",
        CertNumber);
// arg2 = arg2 = CertNumber = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CertCapiFormattedChain
#define _clog_3_ARGS_TRACE_CertCapiFormattedChain(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiFormattedChain , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCapiSign
// [cert] QuicCertSign alg=0x%4.4x
// QuicTraceLogVerbose(
        CertCapiSign,
        "[cert] QuicCertSign alg=0x%4.4x",
        SignatureAlgorithm);
// arg2 = arg2 = SignatureAlgorithm = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CertCapiSign
#define _clog_3_ARGS_TRACE_CertCapiSign(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiSign , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCapiVerify
// [cert] QuicCertVerify alg=0x%4.4x
// QuicTraceLogVerbose(
        CertCapiVerify,
        "[cert] QuicCertVerify alg=0x%4.4x",
        SignatureAlgorithm);
// arg2 = arg2 = SignatureAlgorithm = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CertCapiVerify
#define _clog_3_ARGS_TRACE_CertCapiVerify(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, CertCapiVerify , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "Get CERT_HASH_PROP_ID failed");
// arg2 = arg2 = GetLastError() = arg2
// arg3 = arg3 = "Get CERT_HASH_PROP_ID failed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CERT_CAPI_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Not all cert bytes were processed");
// arg2 = arg2 = "Not all cert bytes were processed" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PKCS7 data",
            Blob.cbData);
// arg2 = arg2 = "PKCS7 data" = arg2
// arg3 = arg3 = Blob.cbData = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CERT_CAPI_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_cert_capi.c.clog.h.c"
#endif
