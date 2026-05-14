#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_LIBRARY_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "library.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_LIBRARY_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_LIBRARY_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "library.c.clog.h.lttng.h"
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
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogError
#define _clog_MACRO_QuicTraceLogError  1
#define QuicTraceLogError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for LibraryStorageOpenFailed
// [ lib] Failed to open global settings, 0x%x
// QuicTraceLogWarning(
            LibraryStorageOpenFailed,
            "[ lib] Failed to open global settings, 0x%x",
            Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryStorageOpenFailed
#define _clog_3_ARGS_TRACE_LibraryStorageOpenFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryStorageOpenFailed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryTestDatapathHooksSet
// [ lib] Updated test datapath hooks
// QuicTraceLogWarning(
            LibraryTestDatapathHooksSet,
            "[ lib] Updated test datapath hooks");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryTestDatapathHooksSet
#define _clog_2_ARGS_TRACE_LibraryTestDatapathHooksSet(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryTestDatapathHooksSet );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySettingsUpdated
// [ lib] Settings %p Updated
// QuicTraceLogInfo(
        LibrarySettingsUpdated,
        "[ lib] Settings %p Updated",
        &MsQuicLib.Settings);
// arg2 = arg2 = &MsQuicLib.Settings = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibrarySettingsUpdated
#define _clog_3_ARGS_TRACE_LibrarySettingsUpdated(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibrarySettingsUpdated , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryVerifierEnabledPerRegistration
// [ lib] Verifing enabled, per-registration!
// QuicTraceLogInfo(
            LibraryVerifierEnabledPerRegistration,
            "[ lib] Verifing enabled, per-registration!");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryVerifierEnabledPerRegistration
#define _clog_2_ARGS_TRACE_LibraryVerifierEnabledPerRegistration(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryVerifierEnabledPerRegistration );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryVerifierEnabled
// [ lib] Verifing enabled for all!
// QuicTraceLogInfo(
            LibraryVerifierEnabled,
            "[ lib] Verifing enabled for all!");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryVerifierEnabled
#define _clog_2_ARGS_TRACE_LibraryVerifierEnabled(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryVerifierEnabled );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryCidLengthSet
// [ lib] CID Length = %hhu
// QuicTraceLogInfo(
        LibraryCidLengthSet,
        "[ lib] CID Length = %hhu",
        MsQuicLib.CidTotalLength);
// arg2 = arg2 = MsQuicLib.CidTotalLength = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryCidLengthSet
#define _clog_3_ARGS_TRACE_LibraryCidLengthSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryCidLengthSet , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryRetryMemoryLimitSet
// [ lib] Updated retry memory limit = %hu
// QuicTraceLogInfo(
            LibraryRetryMemoryLimitSet,
            "[ lib] Updated retry memory limit = %hu",
            MsQuicLib.Settings.RetryMemoryLimit);
// arg2 = arg2 = MsQuicLib.Settings.RetryMemoryLimit = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryRetryMemoryLimitSet
#define _clog_3_ARGS_TRACE_LibraryRetryMemoryLimitSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryRetryMemoryLimitSet , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryLoadBalancingModeSet
// [ lib] Updated load balancing mode = %hu
// QuicTraceLogInfo(
            LibraryLoadBalancingModeSet,
            "[ lib] Updated load balancing mode = %hu",
            MsQuicLib.Settings.LoadBalancingMode);
// arg2 = arg2 = MsQuicLib.Settings.LoadBalancingMode = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryLoadBalancingModeSet
#define _clog_3_ARGS_TRACE_LibraryLoadBalancingModeSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryLoadBalancingModeSet , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySetSettings
// [ lib] Setting new settings
// QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibrarySetSettings
#define _clog_2_ARGS_TRACE_LibrarySetSettings(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibrarySetSettings );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryExecutionConfigSet
// [ lib] Setting execution config
// QuicTraceLogInfo(
            LibraryExecutionConfigSet,
            "[ lib] Setting execution config");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryExecutionConfigSet
#define _clog_2_ARGS_TRACE_LibraryExecutionConfigSet(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryExecutionConfigSet );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryDscpRecvEnabledSet
// [ lib] Setting Dscp on recv = %u
// QuicTraceLogInfo(
            LibraryDscpRecvEnabledSet,
            "[ lib] Setting Dscp on recv = %u", MsQuicLib.EnableDscpOnRecv);
// arg2 = arg2 = MsQuicLib.EnableDscpOnRecv = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryDscpRecvEnabledSet
#define _clog_3_ARGS_TRACE_LibraryDscpRecvEnabledSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryDscpRecvEnabledSet , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryInUse
// [ lib] Now in use.
// QuicTraceLogInfo(
                LibraryInUse,
                "[ lib] Now in use.");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryInUse
#define _clog_2_ARGS_TRACE_LibraryInUse(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryInUse );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryNotInUse
// [ lib] No longer in use.
// QuicTraceLogInfo(
                LibraryNotInUse,
                "[ lib] No longer in use.");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryNotInUse
#define _clog_2_ARGS_TRACE_LibraryNotInUse(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryNotInUse );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryRetryKeyUpdated
// [ lib] Stateless Retry Key updated. Algorithm: %d, RotationMs: %u
// QuicTraceLogInfo(
        LibraryRetryKeyUpdated,
        "[ lib] Stateless Retry Key updated. Algorithm: %d, RotationMs: %u",
        Config->Algorithm,
        Config->RotationMs);
// arg2 = arg2 = Config->Algorithm = arg2
// arg3 = arg3 = Config->RotationMs = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryRetryKeyUpdated
#define _clog_4_ARGS_TRACE_LibraryRetryKeyUpdated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, LibraryRetryKeyUpdated , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenVersionNull
// [ api] MsQuicOpenVersion, NULL
// QuicTraceLogVerbose(
            LibraryMsQuicOpenVersionNull,
            "[ api] MsQuicOpenVersion, NULL");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryMsQuicOpenVersionNull
#define _clog_2_ARGS_TRACE_LibraryMsQuicOpenVersionNull(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicOpenVersionNull );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenVersionEntry
// [ api] MsQuicOpenVersion
// QuicTraceLogVerbose(
        LibraryMsQuicOpenVersionEntry,
        "[ api] MsQuicOpenVersion");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryMsQuicOpenVersionEntry
#define _clog_2_ARGS_TRACE_LibraryMsQuicOpenVersionEntry(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicOpenVersionEntry );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenVersionExit
// [ api] MsQuicOpenVersion, status=0x%x
// QuicTraceLogVerbose(
        LibraryMsQuicOpenVersionExit,
        "[ api] MsQuicOpenVersion, status=0x%x",
        Status);
// arg2 = arg2 = Status = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryMsQuicOpenVersionExit
#define _clog_3_ARGS_TRACE_LibraryMsQuicOpenVersionExit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicOpenVersionExit , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicClose
// [ api] MsQuicClose
// QuicTraceLogVerbose(
            LibraryMsQuicClose,
            "[ api] MsQuicClose");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryMsQuicClose
#define _clog_2_ARGS_TRACE_LibraryMsQuicClose(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicClose );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryLoadBalancingModeSetAfterInUse
// [ lib] Tried to change load balancing mode after library in use!
// QuicTraceLogError(
                LibraryLoadBalancingModeSetAfterInUse,
                "[ lib] Tried to change load balancing mode after library in use!");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryLoadBalancingModeSetAfterInUse
#define _clog_2_ARGS_TRACE_LibraryLoadBalancingModeSetAfterInUse(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryLoadBalancingModeSetAfterInUse );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeySecretNull
// [ lib] Invalid retry key secret: NULL.
// QuicTraceLogError(
            LibrarySetRetryKeySecretNull,
            "[ lib] Invalid retry key secret: NULL.");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibrarySetRetryKeySecretNull
#define _clog_2_ARGS_TRACE_LibrarySetRetryKeySecretNull(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibrarySetRetryKeySecretNull );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeyAlgorithmInvalid
// [ lib] Invalid retry key algorithm: %d.
// QuicTraceLogError(
            LibrarySetRetryKeyAlgorithmInvalid,
            "[ lib] Invalid retry key algorithm: %d.",
            Config->Algorithm);
// arg2 = arg2 = Config->Algorithm = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibrarySetRetryKeyAlgorithmInvalid
#define _clog_3_ARGS_TRACE_LibrarySetRetryKeyAlgorithmInvalid(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibrarySetRetryKeyAlgorithmInvalid , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeyRotationInvalid
// [ lib] Invalid retry key rotation ms: %u.
// QuicTraceLogError(
            LibrarySetRetryKeyRotationInvalid,
            "[ lib] Invalid retry key rotation ms: %u.",
            Config->RotationMs);
// arg2 = arg2 = Config->RotationMs = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibrarySetRetryKeyRotationInvalid
#define _clog_3_ARGS_TRACE_LibrarySetRetryKeyRotationInvalid(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibrarySetRetryKeyRotationInvalid , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySetRetryKeySecretLengthInvalid
// [ lib] Invalid retry key secret length: %u. Expected %u.
// QuicTraceLogError(
            LibrarySetRetryKeySecretLengthInvalid,
            "[ lib] Invalid retry key secret length: %u. Expected %u.",
            Config->SecretLength,
            AlgSecretLen);
// arg2 = arg2 = Config->SecretLength = arg2
// arg3 = arg3 = AlgSecretLen = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibrarySetRetryKeySecretLengthInvalid
#define _clog_4_ARGS_TRACE_LibrarySetRetryKeySecretLengthInvalid(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, LibrarySetRetryKeySecretLengthInvalid , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Library Partitions",
            PartitionsSize);
// arg2 = arg2 = "Library Partitions" = arg2
// arg3 = arg3 = PartitionsSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PerfCountersRundown
// [ lib] Perf counters Rundown, Counters=%!CID!
// QuicTraceEvent(
        PerfCountersRundown,
        "[ lib] Perf counters Rundown, Counters=%!CID!",
        CASTED_CLOG_BYTEARRAY16(sizeof(PerfCounterSamples), PerfCounterSamples));
// arg2 = arg2 = CASTED_CLOG_BYTEARRAY16(sizeof(PerfCounterSamples), PerfCounterSamples) = arg2
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfCountersRundown
#define _clog_4_ARGS_TRACE_PerfCountersRundown(uniqueId, encoded_arg_string, arg2, arg2_len)\
tracepoint(CLOG_LIBRARY_C, PerfCountersRundown , arg2_len, arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryInitializedV3
// [ lib] Initialized
// QuicTraceEvent(
        LibraryInitializedV3,
        "[ lib] Initialized");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryInitializedV3
#define _clog_2_ARGS_TRACE_LibraryInitializedV3(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryInitializedV3 );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryVersion
// [ lib] Version %u.%u.%u.%u
// QuicTraceEvent(
        LibraryVersion,
        "[ lib] Version %u.%u.%u.%u",
        MsQuicLib.Version[0],
        MsQuicLib.Version[1],
        MsQuicLib.Version[2],
        MsQuicLib.Version[3]);
// arg2 = arg2 = MsQuicLib.Version[0] = arg2
// arg3 = arg3 = MsQuicLib.Version[1] = arg3
// arg4 = arg4 = MsQuicLib.Version[2] = arg4
// arg5 = arg5 = MsQuicLib.Version[3] = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_LibraryVersion
#define _clog_6_ARGS_TRACE_LibraryVersion(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_LIBRARY_C, LibraryVersion , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryUninitialized
// [ lib] Uninitialized
// QuicTraceEvent(
        LibraryUninitialized,
        "[ lib] Uninitialized");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryUninitialized
#define _clog_2_ARGS_TRACE_LibraryUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryUninitialized );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryAddRef
// [ lib] AddRef
// QuicTraceEvent(
        LibraryAddRef,
        "[ lib] AddRef");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryAddRef
#define _clog_2_ARGS_TRACE_LibraryAddRef(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryAddRef );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryRelease
// [ lib] Release
// QuicTraceEvent(
        LibraryRelease,
        "[ lib] Release");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryRelease
#define _clog_2_ARGS_TRACE_LibraryRelease(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryRelease );\

#endif




/*----------------------------------------------------------
// Decoder Ring for DataPathInitialized
// [data] Initialized, DatapathFeatures=%u
// QuicTraceEvent(
            DataPathInitialized,
            "[data] Initialized, DatapathFeatures=%u",
            QuicLibraryGetDatapathFeatures());
// arg2 = arg2 = QuicLibraryGetDatapathFeatures() = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DataPathInitialized
#define _clog_3_ARGS_TRACE_DataPathInitialized(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, DataPathInitialized , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Only v2 is supported in MsQuicOpenVersion");
// arg2 = arg2 = "Only v2 is supported in MsQuicOpenVersion" = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryError
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryError , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingError
// [bind][%p] ERROR, %s.
// QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                Binding,
                "Binding already in use");
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = "Binding already in use" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_BindingError
#define _clog_4_ARGS_TRACE_BindingError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, BindingError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryServerInit
// [ lib] Shared server state initializing
// QuicTraceEvent(
            LibraryServerInit,
            "[ lib] Shared server state initializing");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryServerInit
#define _clog_2_ARGS_TRACE_LibraryServerInit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryServerInit );\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryRundownV2
// [ lib] Rundown, PartitionCount=%u
// QuicTraceEvent(
            LibraryRundownV2,
            "[ lib] Rundown, PartitionCount=%u",
            MsQuicLib.PartitionCount);
// arg2 = arg2 = MsQuicLib.PartitionCount = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryRundownV2
#define _clog_3_ARGS_TRACE_LibraryRundownV2(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryRundownV2 , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DataPathRundown
// [data] Rundown, DatapathFeatures=%u
// QuicTraceEvent(
                DataPathRundown,
                "[data] Rundown, DatapathFeatures=%u",
                QuicLibraryGetDatapathFeatures());
// arg2 = arg2 = QuicLibraryGetDatapathFeatures() = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DataPathRundown
#define _clog_3_ARGS_TRACE_DataPathRundown(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, DataPathRundown , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibrarySendRetryStateUpdated
// [ lib] New SendRetryEnabled state, %hhu
// QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            MsQuicLib.SendRetryEnabled);
// arg2 = arg2 = MsQuicLib.SendRetryEnabled = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibrarySendRetryStateUpdated
#define _clog_3_ARGS_TRACE_LibrarySendRetryStateUpdated(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibrarySendRetryStateUpdated , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiEnter
// [ api] Enter %u (%p).
// QuicTraceEvent(
        ApiEnter,
        "[ api] Enter %u (%p).",
        QUIC_TRACE_API_EXECUTION_CREATE,
        NULL);
// arg2 = arg2 = QUIC_TRACE_API_EXECUTION_CREATE = arg2
// arg3 = arg3 = NULL = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ApiEnter
#define _clog_4_ARGS_TRACE_ApiEnter(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, ApiEnter , arg2, arg3);\

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
tracepoint(CLOG_LIBRARY_C, ApiExitStatus , arg2);\

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
tracepoint(CLOG_LIBRARY_C, ApiExit );\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_library.c.clog.h.c"
#endif
