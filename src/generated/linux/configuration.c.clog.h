#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONFIGURATION_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "configuration.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONFIGURATION_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONFIGURATION_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "configuration.c.clog.h.lttng.h"
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
#ifndef _clog_4_ARGS_TRACE_ConfigurationOpenStorageFailed



/*----------------------------------------------------------
// Decoder Ring for ConfigurationOpenStorageFailed
// [cnfg][%p] Failed to open settings, 0x%x
// QuicTraceLogWarning(
                ConfigurationOpenStorageFailed,
                "[cnfg][%p] Failed to open settings, 0x%x",
                Configuration,
                Status);
// arg2 = arg2 = Configuration
// arg3 = arg3 = Status
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConfigurationOpenStorageFailed(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationOpenStorageFailed , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConfigurationOpenAppStorageFailed



/*----------------------------------------------------------
// Decoder Ring for ConfigurationOpenAppStorageFailed
// [cnfg][%p] Failed to open app specific settings, 0x%x
// QuicTraceLogWarning(
                ConfigurationOpenAppStorageFailed,
                "[cnfg][%p] Failed to open app specific settings, 0x%x",
                Configuration,
                Status);
// arg2 = arg2 = Configuration
// arg3 = arg3 = Status
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConfigurationOpenAppStorageFailed(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationOpenAppStorageFailed , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConfigurationSettingsUpdated



/*----------------------------------------------------------
// Decoder Ring for ConfigurationSettingsUpdated
// [cnfg][%p] Settings %p Updated
// QuicTraceLogInfo(
        ConfigurationSettingsUpdated,
        "[cnfg][%p] Settings %p Updated",
        Configuration,
        &Configuration->Settings);
// arg2 = arg2 = Configuration
// arg3 = arg3 = &Configuration->Settings
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConfigurationSettingsUpdated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationSettingsUpdated , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConfigurationSetSettings



/*----------------------------------------------------------
// Decoder Ring for ConfigurationSetSettings
// [cnfg][%p] Setting new settings
// QuicTraceLogInfo(
            ConfigurationSetSettings,
            "[cnfg][%p] Setting new settings",
            Configuration);
// arg2 = arg2 = Configuration
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConfigurationSetSettings(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationSetSettings , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_OPEN,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_CONFIGURATION_OPEN
// arg3 = arg3 = Handle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, ApiEnter , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_CONFIGURATION" ,
            sizeof(QUIC_CONFIGURATION));
// arg2 = arg2 = "QUIC_CONFIGURATION"
// arg3 = arg3 = sizeof(QUIC_CONFIGURATION)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConfigurationCreated



/*----------------------------------------------------------
// Decoder Ring for ConfigurationCreated
// [cnfg][%p] Created, Registration=%p
// QuicTraceEvent(
        ConfigurationCreated,
        "[cnfg][%p] Created, Registration=%p",
        Configuration,
        Registration);
// arg2 = arg2 = Configuration
// arg3 = arg3 = Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConfigurationCreated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationCreated , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_ApiExitStatus



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONFIGURATION_C, ApiExitStatus , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConfigurationCleanup



/*----------------------------------------------------------
// Decoder Ring for ConfigurationCleanup
// [cnfg][%p] Cleaning up
// QuicTraceEvent(
        ConfigurationCleanup,
        "[cnfg][%p] Cleaning up",
        Configuration);
// arg2 = arg2 = Configuration
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConfigurationCleanup(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationCleanup , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConfigurationDestroyed



/*----------------------------------------------------------
// Decoder Ring for ConfigurationDestroyed
// [cnfg][%p] Destroyed
// QuicTraceEvent(
        ConfigurationDestroyed,
        "[cnfg][%p] Destroyed",
        Configuration);
// arg2 = arg2 = Configuration
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConfigurationDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationDestroyed , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_CLOSE,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_CONFIGURATION_CLOSE
// arg3 = arg3 = Handle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_2_ARGS_TRACE_ApiExit



/*----------------------------------------------------------
// Decoder Ring for ApiExit
// [ api] Exit
// QuicTraceEvent(
        ApiExit,
        "[ api] Exit");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_ApiExit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_CONFIGURATION_C, ApiExit );\

#endif




#ifndef _clog_4_ARGS_TRACE_ApiEnter



/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL,
        Handle);
// arg2 = arg2 = QUIC_TRACE_API_CONFIGURATION_LOAD_CREDENTIAL
// arg3 = arg3 = Handle
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ApiExitStatus



/*----------------------------------------------------------
// Decoder Ring for ApiExitStatus
// [ api] Exit %u
// QuicTraceEvent(
        ApiExitStatus,
        "[ api] Exit %u",
        Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ApiExitStatus(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConfigurationRundown



/*----------------------------------------------------------
// Decoder Ring for ConfigurationRundown
// [cnfg][%p] Rundown, Registration=%p
// QuicTraceEvent(
        ConfigurationRundown,
        "[cnfg][%p] Rundown, Registration=%p",
        Configuration,
        Configuration->Registration);
// arg2 = arg2 = Configuration
// arg3 = arg3 = Configuration->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConfigurationRundown(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONFIGURATION_C, ConfigurationRundown , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_configuration.c.clog.h.c"
#endif
