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
// Decoder Ring for LibraryDataPathProcsSet
// [ lib] Setting datapath procs
// QuicTraceLogInfo(
            LibraryDataPathProcsSet,
            "[ lib] Setting datapath procs");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_LibraryDataPathProcsSet
#define _clog_2_ARGS_TRACE_LibraryDataPathProcsSet(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryDataPathProcsSet );\

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
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "default compatibility list",
            CompatibilityListByteLength);
// arg2 = arg2 = "default compatibility list" = arg2
// arg3 = arg3 = CompatibilityListByteLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Create reset token hash");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "Create reset token hash" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, LibraryErrorStatus , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryInitializedV2
// [ lib] Initialized, PartitionCount=%u
// QuicTraceEvent(
        LibraryInitializedV2,
        "[ lib] Initialized, PartitionCount=%u",
        MsQuicLib.PartitionCount);
// arg2 = arg2 = MsQuicLib.PartitionCount = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_LibraryInitializedV2
#define _clog_3_ARGS_TRACE_LibraryInitializedV2(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryInitializedV2 , arg2);\

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
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Tried to change raw datapath procs after datapath initialization");
// arg2 = arg2 = "Tried to change raw datapath procs after datapath initialization" = arg2
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
                CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));
// arg2 = arg2 = CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath) = arg2
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
// Decoder Ring for PerfCountersRundown
// [ lib] Perf counters Rundown, Counters=%!CID!
// QuicTraceEvent(
            PerfCountersRundown,
            "[ lib] Perf counters Rundown, Counters=%!CID!",
            CASTED_CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters));
// arg2 = arg2 = CASTED_CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters) = arg2
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PerfCountersRundown
#define _clog_4_ARGS_TRACE_PerfCountersRundown(uniqueId, encoded_arg_string, arg2, arg2_len)\
tracepoint(CLOG_LIBRARY_C, PerfCountersRundown , arg2_len, arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_library.c.clog.h.c"
#endif
