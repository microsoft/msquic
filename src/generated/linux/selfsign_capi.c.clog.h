#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_SELFSIGN_CAPI_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "selfsign_capi.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_SELFSIGN_CAPI_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_SELFSIGN_CAPI_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "selfsign_capi.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogWarning
#define _clog_MACRO_QuicTraceLogWarning  1
#define QuicTraceLogWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_2_ARGS_TRACE_CertFindCertificateFriendlyName



/*----------------------------------------------------------
// Decoder Ring for CertFindCertificateFriendlyName
// [test] No certificate found by FriendlyName
// QuicTraceLogWarning(
            CertFindCertificateFriendlyName,
            "[test] No certificate found by FriendlyName");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_CertFindCertificateFriendlyName(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertFindCertificateFriendlyName );\

#endif




#ifndef _clog_4_ARGS_TRACE_CertWaitForCreationEvent



/*----------------------------------------------------------
// Decoder Ring for CertWaitForCreationEvent
// [test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)
// QuicTraceLogWarning(
                CertWaitForCreationEvent,
                "[test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)",
                WaitResult,
                GetLastError());
// arg2 = arg2 = WaitResult
// arg3 = arg3 = GetLastError()
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_CertWaitForCreationEvent(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertWaitForCreationEvent , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_CertCleanTestCerts



/*----------------------------------------------------------
// Decoder Ring for CertCleanTestCerts
// [cert] %d test certificates found, and %d deleted
// QuicTraceLogInfo(
        CertCleanTestCerts,
        "[cert] %d test certificates found, and %d deleted",
        Found,
        Deleted);
// arg2 = arg2 = Found
// arg3 = arg3 = Deleted
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_CertCleanTestCerts(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertCleanTestCerts , arg2, arg3);\

#endif




#ifndef _clog_2_ARGS_TRACE_CertOpenRsaKeySuccess



/*----------------------------------------------------------
// Decoder Ring for CertOpenRsaKeySuccess
// [cert] Successfully opened RSA key
// QuicTraceLogInfo(
            CertOpenRsaKeySuccess,
            "[cert] Successfully opened RSA key");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_CertOpenRsaKeySuccess(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertOpenRsaKeySuccess );\

#endif




#ifndef _clog_2_ARGS_TRACE_CertCreateRsaKeySuccess



/*----------------------------------------------------------
// Decoder Ring for CertCreateRsaKeySuccess
// [cert] Successfully created key
// QuicTraceLogInfo(
        CertCreateRsaKeySuccess,
        "[cert] Successfully created key");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_CertCreateRsaKeySuccess(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertCreateRsaKeySuccess );\

#endif




#ifndef _clog_2_ARGS_TRACE_CertCreationEventAlreadyCreated



/*----------------------------------------------------------
// Decoder Ring for CertCreationEventAlreadyCreated
// [test] CreateEvent opened existing event
// QuicTraceLogInfo(
            CertCreationEventAlreadyCreated,
            "[test] CreateEvent opened existing event");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_CertCreationEventAlreadyCreated(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertCreationEventAlreadyCreated );\

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
tracepoint(CLOG_SELFSIGN_CAPI_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CryptEncodeObject failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CryptEncodeObject failed"
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
            "CryptDataBlob",
            CryptDataBlob->cbData);
// arg2 = arg2 = "CryptDataBlob"
// arg3 = arg3 = CryptDataBlob->cbData
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CryptEncodeObject failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CryptEncodeObject failed"
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
            hr,
            "AllocateAndEncodeObject X509_ENHANCED_KEY_USAGE failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "AllocateAndEncodeObject X509_ENHANCED_KEY_USAGE failed"
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
            hr,
            "AllocateAndEncodeObject X509_KEY_USAGE failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "AllocateAndEncodeObject X509_KEY_USAGE failed"
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
            hr,
            "AllocateAndEncodeObject szOID_SUBJECT_ALT_NAME failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "AllocateAndEncodeObject szOID_SUBJECT_ALT_NAME failed"
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
            hr,
            "CreateSubjectNameBlob failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateSubjectNameBlob failed"
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
            "SubjectNameBlob",
            BufferLength);
// arg2 = arg2 = "SubjectNameBlob"
// arg3 = arg3 = BufferLength
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
            hr,
            "CreateSubjectNameBlob failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateSubjectNameBlob failed"
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
            "TmpCertExtensions",
            sizeof(CERT_EXTENSION) * cTmpCertExtension);
// arg2 = arg2 = "TmpCertExtensions"
// arg3 = arg3 = sizeof(CERT_EXTENSION) * cTmpCertExtension
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
            hr,
            "CreateEnhancedKeyUsageCertExtension failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateEnhancedKeyUsageCertExtension failed"
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
            hr,
            "CreateKeyUsageCertExtension failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateKeyUsageCertExtension failed"
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
                hr,
                "CreateSubjAltNameExtension failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateSubjAltNameExtension failed"
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
            hr,
            "NCryptOpenStorageProvider failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptOpenStorageProvider failed"
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
            hr,
            "NCryptOpenKey failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptOpenKey failed"
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
            hr,
            "NCryptCreatePersistedKey failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptCreatePersistedKey failed"
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
            hr,
            "NCryptSetProperty NCRYPT_LENGTH_PROPERTY failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptSetProperty NCRYPT_LENGTH_PROPERTY failed"
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
            hr,
            "NCryptSetProperty NCRYPT_KEY_USAGE_PROPERTY failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptSetProperty NCRYPT_KEY_USAGE_PROPERTY failed"
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
            hr,
            "NCryptSetProperty NCRYPT_EXPORT_POLICY_PROPERTY failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptSetProperty NCRYPT_EXPORT_POLICY_PROPERTY failed"
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
            hr,
            "NCryptFinalizeKey failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "NCryptFinalizeKey failed"
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
            hr,
            "CreateSubjectNameBlob failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateSubjectNameBlob failed"
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
            hr,
            "GetPrivateRsaKey failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "GetPrivateRsaKey failed"
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
            hr,
            "CreateCertificateExtensions failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CreateCertificateExtensions failed"
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
            hr,
            "SystemTimeToFileTime failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "SystemTimeToFileTime failed"
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
            hr,
            "FileTimeToSystemTime failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "FileTimeToSystemTime failed"
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
            hr,
            "CertCreateSelfSignCertificate failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CertCreateSelfSignCertificate failed"
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
            hr,
            "CertSetCertificateContextProperty failed");
// arg2 = arg2 = hr
// arg3 = arg3 = "CertSetCertificateContextProperty failed"
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
                "CertAddCertificateContextToStore failed");
// arg2 = arg2 = GetLastError()
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
                GetLastError(),
                "CertGetCertificateContextProperty failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertGetCertificateContextProperty failed"
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
            "CreateEvent failed");
// arg2 = arg2 = "CreateEvent failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SELFSIGN_CAPI_C, LibraryError , arg2);\

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
            "CertAddCertificateContextToStore failed");
// arg2 = arg2 = GetLastError()
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
                GetLastError(),
                "CertGetCertificateContextProperty failed");
// arg2 = arg2 = GetLastError()
// arg3 = arg3 = "CertGetCertificateContextProperty failed"
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
#include "quic.clog_selfsign_capi.c.clog.h.c"
#endif
