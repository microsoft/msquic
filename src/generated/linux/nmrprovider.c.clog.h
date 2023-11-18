#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_NMRPROVIDER_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "nmrprovider.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_NMRPROVIDER_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_NMRPROVIDER_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "nmrprovider.c.clog.h.lttng.h"
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
// Decoder Ring for ProviderAttachClient
// [ nmr][%p] Client attached Ver %hu Size %hu Number %u ModuleID { %x-%x-%x-%llx }
// QuicTraceLogInfo(
        ProviderAttachClient,
        "[ nmr][%p] Client attached Ver %hu Size %hu Number %u ModuleID { %x-%x-%x-%llx }",
        NmrBindingHandle,
        ClientRegistrationInstance->Version,
        ClientRegistrationInstance->Size,
        ClientRegistrationInstance->Number,
        ClientRegistrationInstance->ModuleId->Guid.Data1,
        ClientRegistrationInstance->ModuleId->Guid.Data2,
        ClientRegistrationInstance->ModuleId->Guid.Data3,
        *((uint64_t*)ClientRegistrationInstance->ModuleId->Guid.Data4));
// arg2 = arg2 = NmrBindingHandle = arg2
// arg3 = arg3 = ClientRegistrationInstance->Version = arg3
// arg4 = arg4 = ClientRegistrationInstance->Size = arg4
// arg5 = arg5 = ClientRegistrationInstance->Number = arg5
// arg6 = arg6 = ClientRegistrationInstance->ModuleId->Guid.Data1 = arg6
// arg7 = arg7 = ClientRegistrationInstance->ModuleId->Guid.Data2 = arg7
// arg8 = arg8 = ClientRegistrationInstance->ModuleId->Guid.Data3 = arg8
// arg9 = arg9 = *((uint64_t*)ClientRegistrationInstance->ModuleId->Guid.Data4) = arg9
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_ProviderAttachClient
#define _clog_10_ARGS_TRACE_ProviderAttachClient(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)\
tracepoint(CLOG_NMRPROVIDER_C, ProviderAttachClient , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ProviderDetachClient
// [ nmr][%p] Client detached
// QuicTraceLogInfo(
        ProviderDetachClient,
        "[ nmr][%p] Client detached",
        ProviderBindingContext);
// arg2 = arg2 = ProviderBindingContext = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ProviderDetachClient
#define _clog_3_ARGS_TRACE_ProviderDetachClient(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_NMRPROVIDER_C, ProviderDetachClient , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NmrRegisterProvider");
// arg2 = arg2 = Status = arg2
// arg3 = arg3 = "NmrRegisterProvider" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_NMRPROVIDER_C, LibraryErrorStatus , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_nmrprovider.c.clog.h.c"
#endif
