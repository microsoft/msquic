#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_REGISTRATION_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "registration.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_REGISTRATION_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_REGISTRATION_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "registration.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
// Decoder Ring for RegistrationVerifierEnabled
// [ reg][%p] Verifing enabled!
// QuicTraceLogInfo(
            RegistrationVerifierEnabled,
            "[ reg][%p] Verifing enabled!",
            Registration);
// arg2 = arg2 = Registration = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RegistrationVerifierEnabled
#define _clog_3_ARGS_TRACE_RegistrationVerifierEnabled(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_REGISTRATION_C, RegistrationVerifierEnabled , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_REGISTRATION_OPEN,
        NULL);
// arg2 = arg2 = QUIC_TRACE_API_REGISTRATION_OPEN = arg2
// arg3 = arg3 = NULL = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ApiEnter
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_REGISTRATION_C, ApiEnter , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    Status,
                    "CxPlatDataPathInitialize");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "CxPlatDataPathInitialize" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_REGISTRATION_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DataPathInitialized
// [data] Initialized, DatapathFeatures=%u
// QuicTraceEvent(
                DataPathInitialized,
                "[data] Initialized, DatapathFeatures=%u",
                CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));
// arg2 = arg2 = CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath) = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DataPathInitialized
#define _clog_3_ARGS_TRACE_DataPathInitialized(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_REGISTRATION_C, DataPathInitialized , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "registration",
            sizeof(QUIC_REGISTRATION) + AppNameLength + 1);
// arg2 = arg2 = "registration" = arg2
// arg3 = arg3 = sizeof(QUIC_REGISTRATION) + AppNameLength + 1 = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_REGISTRATION_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RegistrationCreated
// [ reg][%p] Created, AppName=%s
// QuicTraceEvent(
        RegistrationCreated,
        "[ reg][%p] Created, AppName=%s",
        Registration,
        Registration->AppName);
// arg2 = arg2 = Registration = arg2
// arg3 = arg3 = Registration->AppName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_RegistrationCreated
#define _clog_4_ARGS_TRACE_RegistrationCreated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_REGISTRATION_C, RegistrationCreated , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ApiExitStatus
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_REGISTRATION_C, ApiExitStatus , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RegistrationCleanup
// [ reg][%p] Cleaning up
// QuicTraceEvent(
            RegistrationCleanup,
            "[ reg][%p] Cleaning up",
            Registration);
// arg2 = arg2 = Registration = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RegistrationCleanup
#define _clog_3_ARGS_TRACE_RegistrationCleanup(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_REGISTRATION_C, RegistrationCleanup , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
            ApiExit,
            "[ api] Exit");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_ApiExit
#define _clog_2_ARGS_TRACE_ApiExit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_REGISTRATION_C, ApiExit );\

#endif




/*----------------------------------------------------------
// Decoder Ring for RegistrationRundown
// [ reg][%p] Rundown, AppName=%s
// QuicTraceEvent(
        RegistrationRundown,
        "[ reg][%p] Rundown, AppName=%s",
        Registration,
        Registration->AppName);
// arg2 = arg2 = Registration = arg2
// arg3 = arg3 = Registration->AppName = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_RegistrationRundown
#define _clog_4_ARGS_TRACE_RegistrationRundown(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_REGISTRATION_C, RegistrationRundown , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_registration.c.clog.h.c"
#endif
