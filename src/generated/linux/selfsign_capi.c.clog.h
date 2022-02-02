#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
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
/*----------------------------------------------------------
// Decoder Ring for CertFindCertificateFriendlyName
// [test] No certificate found by FriendlyName
// QuicTraceLogWarning(
            CertFindCertificateFriendlyName,
            "[test] No certificate found by FriendlyName");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_CertFindCertificateFriendlyName
#define _clog_2_ARGS_TRACE_CertFindCertificateFriendlyName(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertFindCertificateFriendlyName );\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertWaitForCreationEvent
// [test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)
// QuicTraceLogWarning(
                CertWaitForCreationEvent,
                "[test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)",
                WaitResult,
                GetLastError());
// arg2 = arg2 = WaitResult = arg2
// arg3 = arg3 = GetLastError() = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_CertWaitForCreationEvent
#define _clog_4_ARGS_TRACE_CertWaitForCreationEvent(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertWaitForCreationEvent , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCleanTestCerts
// [cert] %d test certificates found, and %d deleted
// QuicTraceLogInfo(
        CertCleanTestCerts,
        "[cert] %d test certificates found, and %d deleted",
        Found,
        Deleted);
// arg2 = arg2 = Found = arg2
// arg3 = arg3 = Deleted = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_CertCleanTestCerts
#define _clog_4_ARGS_TRACE_CertCleanTestCerts(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertCleanTestCerts , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertOpenRsaKeySuccess
// [cert] Successfully opened RSA key
// QuicTraceLogInfo(
            CertOpenRsaKeySuccess,
            "[cert] Successfully opened RSA key");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_CertOpenRsaKeySuccess
#define _clog_2_ARGS_TRACE_CertOpenRsaKeySuccess(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertOpenRsaKeySuccess );\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCreateRsaKeySuccess
// [cert] Successfully created key
// QuicTraceLogInfo(
        CertCreateRsaKeySuccess,
        "[cert] Successfully created key");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_CertCreateRsaKeySuccess
#define _clog_2_ARGS_TRACE_CertCreateRsaKeySuccess(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertCreateRsaKeySuccess );\

#endif




/*----------------------------------------------------------
// Decoder Ring for CertCreationEventAlreadyCreated
// [test] CreateEvent opened existing event
// QuicTraceLogInfo(
            CertCreationEventAlreadyCreated,
            "[test] CreateEvent opened existing event");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_CertCreationEventAlreadyCreated
#define _clog_2_ARGS_TRACE_CertCreationEventAlreadyCreated(uniqueId, encoded_arg_string)\
tracepoint(CLOG_SELFSIGN_CAPI_C, CertCreationEventAlreadyCreated );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
// arg2 = arg2 = GetLastError() = arg2
// arg3 = arg3 = "CertOpenStore failed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CryptDataBlob",
            CryptDataBlob->cbData);
// arg2 = arg2 = "CryptDataBlob" = arg2
// arg3 = arg3 = CryptDataBlob->cbData = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_SELFSIGN_CAPI_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CreateEvent failed");
// arg2 = arg2 = "CreateEvent failed" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_SELFSIGN_CAPI_C, LibraryError , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_selfsign_capi.c.clog.h.c"
#endif
