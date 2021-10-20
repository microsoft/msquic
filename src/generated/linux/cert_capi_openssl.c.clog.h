#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CERT_CAPI_OPENSSL_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "cert_capi_openssl.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CERT_CAPI_OPENSSL_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CERT_CAPI_OPENSSL_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "cert_capi_openssl.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
#ifndef _clog_3_ARGS_TRACE_TlsExportCapiCertChainVerifyResult



/*----------------------------------------------------------
// Decoder Ring for TlsExportCapiCertChainVerifyResult
// Exported chain verification result: %u
// QuicTraceLogVerbose(
        TlsExportCapiCertChainVerifyResult,
        "Exported chain verification result: %u",
        PolicyStatus.dwError);
// arg2 = arg2 = PolicyStatus.dwError
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_TlsExportCapiCertChainVerifyResult(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_OPENSSL_C, TlsExportCapiCertChainVerifyResult , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "i2d_X509 failed");
// arg2 = arg2 = "i2d_X509 failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CERT_CAPI_OPENSSL_C, LibraryError , arg2);\

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
tracepoint(CLOG_CERT_CAPI_OPENSSL_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "CertCreateCertificateChainEngine");
// arg2 = arg2 = LastError
// arg3 = arg3 = "CertCreateCertificateChainEngine"
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
            LastError,
            "CertGetCertificateChain");
// arg2 = arg2 = LastError
// arg3 = arg3 = "CertGetCertificateChain"
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
            "CertGetCertificateChain didn't build a chain");
// arg2 = arg2 = Status
// arg3 = arg3 = "CertGetCertificateChain didn't build a chain"
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
            "CertVerifyCertificateChainPolicy");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertVerifyCertificateChainPolicy"
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
            "CxPlatCertCreate");
// arg2 = arg2 = Status
// arg3 = arg3 = "CxPlatCertCreate"
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
            "NCryptGetProperty failed");
// arg2 = arg2 = Status
// arg3 = arg3 = "NCryptGetProperty failed"
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
            "Requested certificate does not support exporting. An exportable certificate is required");
// arg2 = arg2 = "Requested certificate does not support exporting. An exportable certificate is required"
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
            LastError,
            "CertOpenStore failed");
// arg2 = arg2 = LastError
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
            LastError,
            "CertAddCertificateContextToStore failed");
// arg2 = arg2 = LastError
// arg3 = arg3 = "CertAddCertificateContextToStore failed"
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
            "Convert temporary password to unicode");
// arg2 = arg2 = Status
// arg3 = arg3 = "Convert temporary password to unicode"
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
            LastError,
            "PFXExportCertStoreEx get size failed");
// arg2 = arg2 = LastError
// arg3 = arg3 = "PFXExportCertStoreEx get size failed"
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
            "PFX data",
            PfxDataBlob.cbData);
// arg2 = arg2 = "PFX data"
// arg3 = arg3 = PfxDataBlob.cbData
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CERT_CAPI_OPENSSL_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "PFXExportCertStoreEx get size failed");
// arg2 = arg2 = LastError
// arg3 = arg3 = "PFXExportCertStoreEx get size failed"
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
            Type,
            "Unsupported Type passed to CxPlatGetTestCertificate");
// arg2 = arg2 = Type
// arg3 = arg3 = "Unsupported Type passed to CxPlatGetTestCertificate"
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
            (unsigned int)QUIC_STATUS_INVALID_PARAMETER,
            "NULL CertHash passed to CxPlatGetTestCertificate");
// arg2 = arg2 = (unsigned int)QUIC_STATUS_INVALID_PARAMETER
// arg3 = arg3 = "NULL CertHash passed to CxPlatGetTestCertificate"
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
            (unsigned int)QUIC_STATUS_INVALID_PARAMETER,
            "NULL CertHashStore passed to CxPlatGetTestCertificate");
// arg2 = arg2 = (unsigned int)QUIC_STATUS_INVALID_PARAMETER
// arg3 = arg3 = "NULL CertHashStore passed to CxPlatGetTestCertificate"
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
            (unsigned int)QUIC_STATUS_INVALID_PARAMETER,
            "NULL Principal passed to CxPlatGetTestCertificate");
// arg2 = arg2 = (unsigned int)QUIC_STATUS_INVALID_PARAMETER
// arg3 = arg3 = "NULL Principal passed to CxPlatGetTestCertificate"
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
            CredType,
            "Unsupported CredType passed to CxPlatGetTestCertificate");
// arg2 = arg2 = CredType
// arg3 = arg3 = "Unsupported CredType passed to CxPlatGetTestCertificate"
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




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_cert_capi_openssl.c.clog.h.c"
#endif
