#include <clog.h>
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
#ifndef _clog_3_ARGS_TRACE_LibraryStorageOpenFailed



/*----------------------------------------------------------
// Decoder Ring for LibraryStorageOpenFailed
// [ lib] Failed to open global settings, 0x%x
// QuicTraceLogWarning(
            LibraryStorageOpenFailed,
            "[ lib] Failed to open global settings, 0x%x",
            Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryStorageOpenFailed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryStorageOpenFailed , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryTestDatapathHooksSet



/*----------------------------------------------------------
// Decoder Ring for LibraryTestDatapathHooksSet
// [ lib] Updated test datapath hooks
// QuicTraceLogWarning(
            LibraryTestDatapathHooksSet,
            "[ lib] Updated test datapath hooks");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryTestDatapathHooksSet(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryTestDatapathHooksSet );\

#endif




#ifndef _clog_3_ARGS_TRACE_LibrarySettingsUpdated



/*----------------------------------------------------------
// Decoder Ring for LibrarySettingsUpdated
// [ lib] Settings %p Updated
// QuicTraceLogInfo(
        LibrarySettingsUpdated,
        "[ lib] Settings %p Updated",
        &MsQuicLib.Settings);
// arg2 = arg2 = &MsQuicLib.Settings
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibrarySettingsUpdated(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibrarySettingsUpdated , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryVerifierEnabledPerRegistration



/*----------------------------------------------------------
// Decoder Ring for LibraryVerifierEnabledPerRegistration
// [ lib] Verifing enabled, per-registration!
// QuicTraceLogInfo(
            LibraryVerifierEnabledPerRegistration,
            "[ lib] Verifing enabled, per-registration!");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryVerifierEnabledPerRegistration(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryVerifierEnabledPerRegistration );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryVerifierEnabled



/*----------------------------------------------------------
// Decoder Ring for LibraryVerifierEnabled
// [ lib] Verifing enabled for all!
// QuicTraceLogInfo(
            LibraryVerifierEnabled,
            "[ lib] Verifing enabled for all!");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryVerifierEnabled(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryVerifierEnabled );\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryCidLengthSet



/*----------------------------------------------------------
// Decoder Ring for LibraryCidLengthSet
// [ lib] CID Length = %hhu
// QuicTraceLogInfo(
        LibraryCidLengthSet,
        "[ lib] CID Length = %hhu",
        MsQuicLib.CidTotalLength);
// arg2 = arg2 = MsQuicLib.CidTotalLength
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryCidLengthSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryCidLengthSet , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryRetryMemoryLimitSet



/*----------------------------------------------------------
// Decoder Ring for LibraryRetryMemoryLimitSet
// [ lib] Updated retry memory limit = %hu
// QuicTraceLogInfo(
            LibraryRetryMemoryLimitSet,
            "[ lib] Updated retry memory limit = %hu",
            MsQuicLib.Settings.RetryMemoryLimit);
// arg2 = arg2 = MsQuicLib.Settings.RetryMemoryLimit
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryRetryMemoryLimitSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryRetryMemoryLimitSet , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryLoadBalancingModeSet



/*----------------------------------------------------------
// Decoder Ring for LibraryLoadBalancingModeSet
// [ lib] Updated load balancing mode = %hu
// QuicTraceLogInfo(
            LibraryLoadBalancingModeSet,
            "[ lib] Updated load balancing mode = %hu",
            MsQuicLib.Settings.LoadBalancingMode);
// arg2 = arg2 = MsQuicLib.Settings.LoadBalancingMode
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryLoadBalancingModeSet(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryLoadBalancingModeSet , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_LibrarySetSettings



/*----------------------------------------------------------
// Decoder Ring for LibrarySetSettings
// [ lib] Setting new settings
// QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibrarySetSettings(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibrarySetSettings );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryInUse



/*----------------------------------------------------------
// Decoder Ring for LibraryInUse
// [ lib] Now in use.
// QuicTraceLogInfo(
                LibraryInUse,
                "[ lib] Now in use.");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryInUse(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryInUse );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryNotInUse



/*----------------------------------------------------------
// Decoder Ring for LibraryNotInUse
// [ lib] No longer in use.
// QuicTraceLogInfo(
                LibraryNotInUse,
                "[ lib] No longer in use.");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryNotInUse(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryNotInUse );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryMsQuicOpenNull



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenNull
// [ api] MsQuicOpen, NULL
// QuicTraceLogVerbose(
            LibraryMsQuicOpenNull,
            "[ api] MsQuicOpen, NULL");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryMsQuicOpenNull(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicOpenNull );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryMsQuicOpenEntry



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenEntry
// [ api] MsQuicOpen
// QuicTraceLogVerbose(
        LibraryMsQuicOpenEntry,
        "[ api] MsQuicOpen");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryMsQuicOpenEntry(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicOpenEntry );\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryMsQuicOpenExit



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicOpenExit
// [ api] MsQuicOpen, status=0x%x
// QuicTraceLogVerbose(
        LibraryMsQuicOpenExit,
        "[ api] MsQuicOpen, status=0x%x",
        Status);
// arg2 = arg2 = Status
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryMsQuicOpenExit(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicOpenExit , arg2);\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryMsQuicClose



/*----------------------------------------------------------
// Decoder Ring for LibraryMsQuicClose
// [ api] MsQuicClose
// QuicTraceLogVerbose(
            LibraryMsQuicClose,
            "[ api] MsQuicClose");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryMsQuicClose(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryMsQuicClose );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryLoadBalancingModeSetAfterInUse



/*----------------------------------------------------------
// Decoder Ring for LibraryLoadBalancingModeSetAfterInUse
// [ lib] Tried to change load balancing mode after library in use!
// QuicTraceLogError(
                LibraryLoadBalancingModeSetAfterInUse,
                "[ lib] Tried to change load balancing mode after library in use!");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryLoadBalancingModeSetAfterInUse(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryLoadBalancingModeSetAfterInUse );\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "default compatibility list",
            CompatibilityListByteLength);
// arg2 = arg2 = "default compatibility list"
// arg3 = arg3 = CompatibilityListByteLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "connection pools",
            MsQuicLib.PartitionCount * sizeof(QUIC_LIBRARY_PP));
// arg2 = arg2 = "connection pools"
// arg3 = arg3 = MsQuicLib.PartitionCount * sizeof(QUIC_LIBRARY_PP)
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
                Status,
                "Create reset token hash");
// arg2 = arg2 = Status
// arg3 = arg3 = "Create reset token hash"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatDataPathInitialize");
// arg2 = arg2 = Status
// arg3 = arg3 = "CxPlatDataPathInitialize"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryInitialized



/*----------------------------------------------------------
// Decoder Ring for LibraryInitialized
// [ lib] Initialized, PartitionCount=%u DatapathFeatures=%u
// QuicTraceEvent(
        LibraryInitialized,
        "[ lib] Initialized, PartitionCount=%u DatapathFeatures=%u",
        MsQuicLib.PartitionCount,
        CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));
// arg2 = arg2 = MsQuicLib.PartitionCount
// arg3 = arg3 = CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryInitialized(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, LibraryInitialized , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_LibraryVersion



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
// arg2 = arg2 = MsQuicLib.Version[0]
// arg3 = arg3 = MsQuicLib.Version[1]
// arg4 = arg4 = MsQuicLib.Version[2]
// arg5 = arg5 = MsQuicLib.Version[3]
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_LibraryVersion(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_LIBRARY_C, LibraryVersion , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryUninitialized



/*----------------------------------------------------------
// Decoder Ring for LibraryUninitialized
// [ lib] Uninitialized
// QuicTraceEvent(
        LibraryUninitialized,
        "[ lib] Uninitialized");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryUninitialized(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryUninitialized );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryAddRef



/*----------------------------------------------------------
// Decoder Ring for LibraryAddRef
// [ lib] AddRef
// QuicTraceEvent(
        LibraryAddRef,
        "[ lib] AddRef");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryAddRef(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryAddRef );\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryRelease



/*----------------------------------------------------------
// Decoder Ring for LibraryRelease
// [ lib] Release
// QuicTraceEvent(
        LibraryRelease,
        "[ lib] Release");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryRelease(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryRelease );\

#endif




#ifndef _clog_4_ARGS_TRACE_BindingError



/*----------------------------------------------------------
// Decoder Ring for BindingError
// [bind][%p] ERROR, %s.
// QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                Binding,
                "Binding already in use");
// arg2 = arg2 = Binding
// arg3 = arg3 = "Binding already in use"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_BindingError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, BindingError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_BindingError



/*----------------------------------------------------------
// Decoder Ring for BindingError
// [bind][%p] ERROR, %s.
// QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                *NewBinding,
                "Binding ephemeral port reuse encountered");
// arg2 = arg2 = *NewBinding
// arg3 = arg3 = "Binding ephemeral port reuse encountered"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_BindingError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_BindingError



/*----------------------------------------------------------
// Decoder Ring for BindingError
// [bind][%p] ERROR, %s.
// QuicTraceEvent(
                BindingError,
                "[bind][%p] ERROR, %s.",
                Binding,
                "Binding already in use");
// arg2 = arg2 = Binding
// arg3 = arg3 = "Binding already in use"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_BindingError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_2_ARGS_TRACE_LibraryServerInit



/*----------------------------------------------------------
// Decoder Ring for LibraryServerInit
// [ lib] Shared server state initializing
// QuicTraceEvent(
            LibraryServerInit,
            "[ lib] Shared server state initializing");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_LibraryServerInit(uniqueId, encoded_arg_string)\
tracepoint(CLOG_LIBRARY_C, LibraryServerInit );\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryRundown



/*----------------------------------------------------------
// Decoder Ring for LibraryRundown
// [ lib] Rundown, PartitionCount=%u DatapathFeatures=%u
// QuicTraceEvent(
            LibraryRundown,
            "[ lib] Rundown, PartitionCount=%u DatapathFeatures=%u",
            MsQuicLib.PartitionCount,
            CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath));
// arg2 = arg2 = MsQuicLib.PartitionCount
// arg3 = arg3 = CxPlatDataPathGetSupportedFeatures(MsQuicLib.Datapath)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryRundown(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LIBRARY_C, LibraryRundown , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_LibraryVersion



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
// arg2 = arg2 = MsQuicLib.Version[0]
// arg3 = arg3 = MsQuicLib.Version[1]
// arg4 = arg4 = MsQuicLib.Version[2]
// arg5 = arg5 = MsQuicLib.Version[3]
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_LibraryVersion(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibrarySendRetryStateUpdated



/*----------------------------------------------------------
// Decoder Ring for LibrarySendRetryStateUpdated
// [ lib] New SendRetryEnabled state, %hhu
// QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            MsQuicLib.SendRetryEnabled);
// arg2 = arg2 = MsQuicLib.SendRetryEnabled
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibrarySendRetryStateUpdated(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_LIBRARY_C, LibrarySendRetryStateUpdated , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_PerfCountersRundown



/*----------------------------------------------------------
// Decoder Ring for PerfCountersRundown
// [ lib] Perf counters Rundown, Counters=%!CID!
// QuicTraceEvent(
            PerfCountersRundown,
            "[ lib] Perf counters Rundown, Counters=%!CID!",
            CASTED_CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters));
// arg2 = arg2 = CASTED_CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PerfCountersRundown(uniqueId, encoded_arg_string, arg2, arg2_len)\
tracepoint(CLOG_LIBRARY_C, PerfCountersRundown , arg2_len, arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Create stateless retry key");
// arg2 = arg2 = Status
// arg3 = arg3 = "Create stateless retry key"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibrarySendRetryStateUpdated



/*----------------------------------------------------------
// Decoder Ring for LibrarySendRetryStateUpdated
// [ lib] New SendRetryEnabled state, %hhu
// QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            NewSendRetryState);
// arg2 = arg2 = NewSendRetryState
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibrarySendRetryStateUpdated(uniqueId, encoded_arg_string, arg2)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_library.c.clog.h.c"
#endif

