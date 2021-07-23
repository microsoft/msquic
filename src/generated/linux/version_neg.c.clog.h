#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_VERSION_NEG_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "version_neg.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_VERSION_NEG_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_VERSION_NEG_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "version_neg.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnError
#define _clog_MACRO_QuicTraceLogConnError  1
#define QuicTraceLogConnError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _clog_4_ARGS_TRACE_VersionInfoDecodeFailed1



/*----------------------------------------------------------
// Decoder Ring for VersionInfoDecodeFailed1
// [conn][%p] Version info too short to contain Chosen Version (%hu bytes)
// QuicTraceLogConnError(
            VersionInfoDecodeFailed1,
            Connection,
            "Version info too short to contain Chosen Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_VersionInfoDecodeFailed1(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, VersionInfoDecodeFailed1 , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_VersionInfoDecodeFailed2



/*----------------------------------------------------------
// Decoder Ring for VersionInfoDecodeFailed2
// [conn][%p] Version info too short to contain any Other Versions (%hu bytes)
// QuicTraceLogConnError(
            VersionInfoDecodeFailed2,
            Connection,
            "Version info too short to contain any Other Versions (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_VersionInfoDecodeFailed2(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, VersionInfoDecodeFailed2 , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionInfoDecodeFailed3



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoDecodeFailed3
// [conn][%p] Version info contains partial Other Version (%hu bytes vs. %u bytes)
// QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed3,
            Connection,
            "Version info contains partial Other Version (%hu bytes vs. %u bytes)",
            (unsigned)(BufferLength - Offset),
            (BufferLength - Offset) / (unsigned)sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = (unsigned)(BufferLength - Offset)
// arg4 = arg4 = (BufferLength - Offset) / (unsigned)sizeof(uint32_t)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionInfoDecodeFailed3(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionInfoDecodeFailed3 , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionInfoDecodeFailed4



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoDecodeFailed4
// [conn][%p] Version info parsed less than full buffer (%hu bytes vs. %hu bytes
// QuicTraceLogConnError(
            ServerVersionInfoDecodeFailed4,
            Connection,
            "Version info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Offset
// arg4 = arg4 = BufferLength
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionInfoDecodeFailed4(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionInfoDecodeFailed4 , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionInfoDecoded



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoDecoded
// [conn][%p] VerInfo Decoded: Chosen Ver:%x Other Ver Count:%u
// QuicTraceLogConnInfo(
        ServerVersionInfoDecoded,
        Connection,
        "VerInfo Decoded: Chosen Ver:%x Other Ver Count:%u",
        VersionInfo->ChosenVersion,
        VersionInfo->OtherVersionsCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = VersionInfo->ChosenVersion
// arg4 = arg4 = VersionInfo->OtherVersionsCount
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionInfoDecoded(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionInfoDecoded , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoEncoded



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoEncoded
// [conn][%p] Server VI Encoded: Chosen Ver:%x Other Ver Count:%u
// QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VI Encoded: Chosen Ver:%x Other Ver Count:%u",
            Connection->Stats.QuicVersion,
            DesiredVersionsListLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = DesiredVersionsListLength
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoEncoded(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoEncoded , arg1, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_ClientVersionInfoEncoded



/*----------------------------------------------------------
// Decoder Ring for ClientVersionInfoEncoded
// [conn][%p] Client VI Encoded: Current Ver:%x Prev Ver:%x Compat Ver Count:%u
// QuicTraceLogConnInfo(
            ClientVersionInfoEncoded,
            Connection,
            "Client VI Encoded: Current Ver:%x Prev Ver:%x Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = Connection->PreviousQuicVersion
// arg5 = arg5 = CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t))
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ClientVersionInfoEncoded(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionInfoEncoded , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnVNEOtherVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnVNEOtherVersionList
// [conn][%p] VerInfo Other Versions List: %!VNL!
// QuicTraceEvent(
        ConnVNEOtherVersionList,
        "[conn][%p] VerInfo Other Versions List: %!VNL!",
        Connection,
        CASTED_CLOG_BYTEARRAY(VersionInfo->OtherVersionsCount * sizeof(uint32_t), VersionInfo->OtherVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(VersionInfo->OtherVersionsCount * sizeof(uint32_t), VersionInfo->OtherVersions)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnVNEOtherVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_VERSION_NEG_C, ConnVNEOtherVersionList , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server Version Info",
                VILen);
// arg2 = arg2 = "Server Version Info"
// arg3 = arg3 = VILen
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_VERSION_NEG_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnVNEOtherVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnVNEOtherVersionList
// [conn][%p] VerInfo Other Versions List: %!VNL!
// QuicTraceEvent(
            ConnVNEOtherVersionList,
            "[conn][%p] VerInfo Other Versions List: %!VNL!",
            Connection,
            CASTED_CLOG_BYTEARRAY(DesiredVersionsListLength * sizeof(uint32_t), VIBuf));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(DesiredVersionsListLength * sizeof(uint32_t), VIBuf)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnVNEOtherVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Client Version Info",
                VILen);
// arg2 = arg2 = "Client Version Info"
// arg3 = arg3 = VILen
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnVNEOtherVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnVNEOtherVersionList
// [conn][%p] VerInfo Other Versions List: %!VNL!
// QuicTraceEvent(
            ConnVNEOtherVersionList,
            "[conn][%p] VerInfo Other Versions List: %!VNL!",
            Connection,
            CASTED_CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VIBuf));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VIBuf)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnVNEOtherVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_version_neg.c.clog.h.c"
#endif

