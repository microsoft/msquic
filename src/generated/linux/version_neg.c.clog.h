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
#ifndef _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed1



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed1
// [conn][%p] Client version negotiation info too short to contain Current Version (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed1,
            Connection,
            "Client version negotiation info too short to contain Current Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed1(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed1 , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed2



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed2
// [conn][%p] Client version negotiation info too short to contain Previous Version (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed2,
            Connection,
            "Client version negotiation info too short to contain Previous Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed2(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed2 , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed3



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed3
// [conn][%p] Client version negotiation info too short to contain Recv Negotiation Version count (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed3,
            Connection,
            "Client version negotiation info too short to contain Recv Negotiation Version count (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed3(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed3 , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed4



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed4
// [conn][%p] Client version negotiation info too short to contain Recv Negotiation Version list (%hu bytes vs. %llu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed4,
            Connection,
            "Client version negotiation info too short to contain Recv Negotiation Version list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
// arg4 = arg4 = ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed4(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed4 , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed5



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed5
// [conn][%p] Client version negotiation info too short to contain Compatible Version count (%hu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed5,
            Connection,
            "Client version negotiation info too short to contain Compatible Version count (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed5(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed5 , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed6



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed6
// [conn][%p] Client version negotiation info too short to contain Compatible Version list (%hu bytes vs. %llu bytes)
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed6,
            Connection,
            "Client version negotiation info too short to contain Compatible Version list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ClientVNI->CompatibleVersionCount * sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
// arg4 = arg4 = ClientVNI->CompatibleVersionCount * sizeof(uint32_t)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed6(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed6 , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed7



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed7
// [conn][%p] Client version negotiation info has empty Compatible Version list
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed7,
            Connection,
            "Client version negotiation info has empty Compatible Version list");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed7(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed7 , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed8



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecodeFailed8
// [conn][%p] Client version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes
// QuicTraceLogConnError(
            ClientVersionNegotiationInfoDecodeFailed8,
            Connection,
            "Client version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Offset
// arg4 = arg4 = BufferLength
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ClientVersionNegotiationInfoDecodeFailed8(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecodeFailed8 , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed1



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed1
// [conn][%p] Server version negotiation info too short to contain Negotiated Version (%hu bytes)
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed1,
            Connection,
            "Server version negotiation info too short to contain Negotiated Version (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed1(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed1 , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed2



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed2
// [conn][%p] Server version negotiation info too short to contain Supported Version count (%hu bytes)
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed2,
            Connection,
            "Server version negotiation info too short to contain Supported Version count (%hu bytes)",
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed2(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed2 , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed3



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed3
// [conn][%p] Server version negotiation info too short to contain Supported Versions list (%hu bytes vs. %llu bytes)
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed3,
            Connection,
            "Server version negotiation info too short to contain Supported Versions list (%hu bytes vs. %llu bytes)",
            BufferLength,
            ServerVNI->SupportedVersionCount * sizeof(uint32_t));
// arg1 = arg1 = Connection
// arg3 = arg3 = BufferLength
// arg4 = arg4 = ServerVNI->SupportedVersionCount * sizeof(uint32_t)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed3(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed3 , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed4



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed4
// [conn][%p] Server version negotiation info has empty Supported Versions list
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed4,
            Connection,
            "Server version negotiation info has empty Supported Versions list");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed4(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed4 , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed5



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecodeFailed5
// [conn][%p] Server version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes
// QuicTraceLogConnError(
            ServerVersionNegotiationInfoDecodeFailed5,
            Connection,
            "Server version negotiation info parsed less than full buffer (%hu bytes vs. %hu bytes",
            Offset,
            BufferLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Offset
// arg4 = arg4 = BufferLength
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoDecodeFailed5(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecodeFailed5 , arg1, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_ClientVersionNegotiationInfoDecoded



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoDecoded
// [conn][%p] Client VNI Decoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%llu Compat Ver Count:%llu
// QuicTraceLogConnInfo(
        ClientVersionNegotiationInfoDecoded,
        Connection,
        "Client VNI Decoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%llu Compat Ver Count:%llu",
        ClientVNI->CurrentVersion,
        ClientVNI->PreviousVersion,
        ClientVNI->RecvNegotiationVerCount,
        ClientVNI->CompatibleVersionCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = ClientVNI->CurrentVersion
// arg4 = arg4 = ClientVNI->PreviousVersion
// arg5 = arg5 = ClientVNI->RecvNegotiationVerCount
// arg6 = arg6 = ClientVNI->CompatibleVersionCount
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_ClientVersionNegotiationInfoDecoded(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoDecoded , arg1, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoDecoded



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoDecoded
// [conn][%p] Server VNI Decoded: Negotiated Ver:%x Supported Ver Count:%llu
// QuicTraceLogConnInfo(
        ServerVersionNegotiationInfoDecoded,
        Connection,
        "Server VNI Decoded: Negotiated Ver:%x Supported Ver Count:%llu",
        ServerVNI->NegotiatedVersion,
        ServerVNI->SupportedVersionCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = ServerVNI->NegotiatedVersion
// arg4 = arg4 = ServerVNI->SupportedVersionCount
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoDecoded(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoDecoded , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoEncoded



/*----------------------------------------------------------
// Decoder Ring for ServerVersionNegotiationInfoEncoded
// [conn][%p] Server VNI Encoded: Negotiated Ver:%x Supported Ver Count:%u
// QuicTraceLogConnInfo(
            ServerVersionNegotiationInfoEncoded,
            Connection,
            "Server VNI Encoded: Negotiated Ver:%x Supported Ver Count:%u",
            Connection->Stats.QuicVersion,
            DesiredVersionsListLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = DesiredVersionsListLength
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionNegotiationInfoEncoded(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_VERSION_NEG_C, ServerVersionNegotiationInfoEncoded , arg1, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_ClientVersionNegotiationInfoEncoded



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationInfoEncoded
// [conn][%p] Client VNI Encoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%u Compat Ver Count:%u
// QuicTraceLogConnInfo(
            ClientVersionNegotiationInfoEncoded,
            Connection,
            "Client VNI Encoded: Current Ver:%x Prev Ver:%x Recv Ver Count:%u Compat Ver Count:%u",
            Connection->Stats.QuicVersion,
            Connection->PreviousQuicVersion,
            Connection->ReceivedNegotiationVersionsLength,
            CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t)));
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = Connection->PreviousQuicVersion
// arg5 = arg5 = Connection->ReceivedNegotiationVersionsLength
// arg6 = arg6 = CompatibilityListByteLength == 0 ?
                MsQuicLib.DefaultCompatibilityListLength :
                (uint32_t)(CompatibilityListByteLength / sizeof(uint32_t))
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_ClientVersionNegotiationInfoEncoded(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_VERSION_NEG_C, ClientVersionNegotiationInfoEncoded , arg1, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnClientCompatibleVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnClientCompatibleVersionList
// [conn][%p] Client VNI Compatible Version List: %!VNL!
// QuicTraceEvent(
        ConnClientCompatibleVersionList,
        "[conn][%p] Client VNI Compatible Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ClientVNI->CompatibleVersionCount * sizeof(uint32_t), ClientVNI->CompatibleVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(ClientVNI->CompatibleVersionCount * sizeof(uint32_t), ClientVNI->CompatibleVersions)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnClientCompatibleVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_VERSION_NEG_C, ConnClientCompatibleVersionList , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnClientReceivedVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnClientReceivedVersionList
// [conn][%p] Client VNI Received Version List: %!VNL!
// QuicTraceEvent(
        ConnClientReceivedVersionList,
        "[conn][%p] Client VNI Received Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t), ClientVNI->RecvNegotiationVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(ClientVNI->RecvNegotiationVerCount * sizeof(uint32_t), ClientVNI->RecvNegotiationVersions)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnClientReceivedVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_VERSION_NEG_C, ConnClientReceivedVersionList , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnServerSupportedVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnServerSupportedVersionList
// [conn][%p] Server VNI Supported Version List: %!VNL!
// QuicTraceEvent(
        ConnServerSupportedVersionList,
        "[conn][%p] Server VNI Supported Version List: %!VNL!",
        Connection,
        CLOG_BYTEARRAY(ServerVNI->SupportedVersionCount * sizeof(uint32_t), ServerVNI->SupportedVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(ServerVNI->SupportedVersionCount * sizeof(uint32_t), ServerVNI->SupportedVersions)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnServerSupportedVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_VERSION_NEG_C, ConnServerSupportedVersionList , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server Version Negotiation Info",
                VNILen);
// arg2 = arg2 = "Server Version Negotiation Info"
// arg3 = arg3 = VNILen
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_VERSION_NEG_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnServerSupportedVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnServerSupportedVersionList
// [conn][%p] Server VNI Supported Version List: %!VNL!
// QuicTraceEvent(
            ConnServerSupportedVersionList,
            "[conn][%p] Server VNI Supported Version List: %!VNL!",
            Connection,
            CLOG_BYTEARRAY(DesiredVersionsListLength * sizeof(uint32_t), VNIBuf));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(DesiredVersionsListLength * sizeof(uint32_t), VNIBuf)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnServerSupportedVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Client Version Negotiation Info",
                VNILen);
// arg2 = arg2 = "Client Version Negotiation Info"
// arg3 = arg3 = VNILen
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnClientCompatibleVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnClientCompatibleVersionList
// [conn][%p] Client VNI Compatible Version List: %!VNL!
// QuicTraceEvent(
            ConnClientCompatibleVersionList,
            "[conn][%p] Client VNI Compatible Version List: %!VNL!",
            Connection,
            CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VNIBuf));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(
                CompatibilityListByteLength == 0 ?
                    MsQuicLib.DefaultCompatibilityListLength * sizeof(uint32_t):
                    CompatibilityListByteLength,
                VNIBuf)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnClientCompatibleVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnClientReceivedVersionList



/*----------------------------------------------------------
// Decoder Ring for ConnClientReceivedVersionList
// [conn][%p] Client VNI Received Version List: %!VNL!
// QuicTraceEvent(
            ConnClientReceivedVersionList,
            "[conn][%p] Client VNI Received Version List: %!VNL!",
            Connection,
            CLOG_BYTEARRAY(
                Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t),
                Connection->ReceivedNegotiationVersions));
// arg2 = arg2 = Connection
// arg3 = arg3 = CLOG_BYTEARRAY(
                Connection->ReceivedNegotiationVersionsLength * sizeof(uint32_t),
                Connection->ReceivedNegotiationVersions)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnClientReceivedVersionList(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_version_neg.c.clog.h.c"
#endif
