#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CONNECTION_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "connection.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CONNECTION_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CONNECTION_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "connection.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnError
#define _clog_MACRO_QuicTraceLogConnError  1
#define QuicTraceLogConnError(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnInfo
#define _clog_MACRO_QuicTraceLogConnInfo  1
#define QuicTraceLogConnInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogConnVerbose
#define _clog_MACRO_QuicTraceLogConnVerbose  1
#define QuicTraceLogConnVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for PacketRxStatelessReset
// [S][RX][-] SR %s
// QuicTraceLogVerbose(
                        PacketRxStatelessReset,
                        "[S][RX][-] SR %s",
                        QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg2 = arg2 = QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PacketRxStatelessReset
#define _clog_3_ARGS_TRACE_PacketRxStatelessReset(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, PacketRxStatelessReset , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PacketRxNotAcked
// [%c][RX][%llu] not acked (connection is closed)
// QuicTraceLogVerbose(
            PacketRxNotAcked,
            "[%c][RX][%llu] not acked (connection is closed)",
            PtkConnPre(Connection),
            Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PacketRxNotAcked
#define _clog_4_ARGS_TRACE_PacketRxNotAcked(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, PacketRxNotAcked , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClientVersionInfoVersionMismatch
// [conn][%p] Client Chosen Version doesn't match long header. 0x%x != 0x%x
// QuicTraceLogConnError(
                ClientVersionInfoVersionMismatch,
                Connection,
                "Client Chosen Version doesn't match long header. 0x%x != 0x%x",
                ClientVI.ChosenVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = ClientVI.ChosenVersion = arg3
// arg4 = arg4 = Connection->Stats.QuicVersion = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ClientVersionInfoVersionMismatch
#define _clog_5_ARGS_TRACE_ClientVersionInfoVersionMismatch(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ClientVersionInfoVersionMismatch , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoVersionMismatch
// [conn][%p] Server Chosen Version doesn't match long header. 0x%x != 0x%x
// QuicTraceLogConnError(
                ServerVersionInfoVersionMismatch,
                Connection,
                "Server Chosen Version doesn't match long header. 0x%x != 0x%x",
                ServerVI.ChosenVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = ServerVI.ChosenVersion = arg3
// arg4 = arg4 = Connection->Stats.QuicVersion = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ServerVersionInfoVersionMismatch
#define _clog_5_ARGS_TRACE_ServerVersionInfoVersionMismatch(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInfoVersionMismatch , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClientChosenVersionMismatchServerChosenVersion
// [conn][%p] Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x
// QuicTraceLogConnError(
                ClientChosenVersionMismatchServerChosenVersion,
                Connection,
                "Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x",
                ClientChosenVersion,
                ServerVI.ChosenVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = ClientChosenVersion = arg3
// arg4 = arg4 = ServerVI.ChosenVersion = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ClientChosenVersionMismatchServerChosenVersion
#define _clog_5_ARGS_TRACE_ClientChosenVersionMismatchServerChosenVersion(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ClientChosenVersionMismatchServerChosenVersion , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationPreviousVersionIsChosenVersion
// [conn][%p] Previous Client Version is Server Chosen Version: 0x%x
// QuicTraceLogConnError(
                    ServerVersionInformationPreviousVersionIsChosenVersion,
                    Connection,
                    "Previous Client Version is Server Chosen Version: 0x%x",
                    Connection->PreviousQuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->PreviousQuicVersion = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionIsChosenVersion
#define _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionIsChosenVersion(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInformationPreviousVersionIsChosenVersion , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationPreviousVersionInOtherVerList
// [conn][%p] Previous Client Version in Server Other Versions list: 0x%x
// QuicTraceLogConnError(
                            ServerVersionInformationPreviousVersionInOtherVerList,
                            Connection,
                            "Previous Client Version in Server Other Versions list: 0x%x",
                            Connection->PreviousQuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->PreviousQuicVersion = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionInOtherVerList
#define _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionInOtherVerList(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInformationPreviousVersionInOtherVerList , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionNegotiationNotCompatible
// [conn][%p] Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x
// QuicTraceLogConnError(
                    CompatibleVersionNegotiationNotCompatible,
                    Connection,
                    "Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->OriginalQuicVersion = arg3
// arg4 = arg4 = ServerVI.ChosenVersion = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CompatibleVersionNegotiationNotCompatible
#define _clog_5_ARGS_TRACE_CompatibleVersionNegotiationNotCompatible(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CompatibleVersionNegotiationNotCompatible , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionNegotiationOriginalVersionNotFound
// [conn][%p] OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x
// QuicTraceLogConnError(
                    CompatibleVersionNegotiationOriginalVersionNotFound,
                    Connection,
                    "OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->OriginalQuicVersion = arg3
// arg4 = arg4 = ServerVI.ChosenVersion = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CompatibleVersionNegotiationOriginalVersionNotFound
#define _clog_5_ARGS_TRACE_CompatibleVersionNegotiationOriginalVersionNotFound(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CompatibleVersionNegotiationOriginalVersionNotFound , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecvVerNegNoMatch
// [conn][%p] Version Negotation contained no supported versions
// QuicTraceLogConnError(
            RecvVerNegNoMatch,
            Connection,
            "Version Negotation contained no supported versions");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RecvVerNegNoMatch
#define _clog_3_ARGS_TRACE_RecvVerNegNoMatch(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvVerNegNoMatch , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecvVerNegCryptoError
// [conn][%p] Failed to update crypto on ver neg
// QuicTraceLogConnError(
            RecvVerNegCryptoError,
            Connection,
            "Failed to update crypto on ver neg");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RecvVerNegCryptoError
#define _clog_3_ARGS_TRACE_RecvVerNegCryptoError(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvVerNegCryptoError , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApiEventNoHandler
// [conn][%p] Event silently discarded (no handler).
// QuicTraceLogConnWarning(
            ApiEventNoHandler,
            Connection,
            "Event silently discarded (no handler).");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ApiEventNoHandler
#define _clog_3_ARGS_TRACE_ApiEventNoHandler(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ApiEventNoHandler , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NoReplacementCidForRetire
// [conn][%p] Can't retire current CID because we don't have a replacement
// QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            Connection,
            "Can't retire current CID because we don't have a replacement");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NoReplacementCidForRetire
#define _clog_3_ARGS_TRACE_NoReplacementCidForRetire(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NoReplacementCidForRetire , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NonActivePathCidRetired
// [conn][%p] Non-active path has no replacement for retired CID.
// QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                Connection,
                "Non-active path has no replacement for retired CID.");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NonActivePathCidRetired
#define _clog_3_ARGS_TRACE_NonActivePathCidRetired(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NonActivePathCidRetired , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IgnoreUnreachable
// [conn][%p] Ignoring received unreachable event (inline)
// QuicTraceLogConnWarning(
            IgnoreUnreachable,
            Connection,
            "Ignoring received unreachable event (inline)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IgnoreUnreachable
#define _clog_3_ARGS_TRACE_IgnoreUnreachable(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IgnoreUnreachable , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IgnoreFrameAfterClose
// [conn][%p] Ignoring frame (%hhu) for already closed stream id = %llu
// QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint8_t)FrameType = arg3
// arg4 = arg4 = // This cast is safe because of the switch cases above.
                    StreamId = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_IgnoreFrameAfterClose
#define _clog_5_ARGS_TRACE_IgnoreFrameAfterClose(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, IgnoreFrameAfterClose , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for InvalidInitialPackets
// [conn][%p] Aborting connection with invalid initial packets
// QuicTraceLogConnWarning(
            InvalidInitialPackets,
            Connection,
            "Aborting connection with invalid initial packets");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_InvalidInitialPackets
#define _clog_3_ARGS_TRACE_InvalidInitialPackets(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, InvalidInitialPackets , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UnreachableIgnore
// [conn][%p] Ignoring received unreachable event
// QuicTraceLogConnWarning(
            UnreachableIgnore,
            Connection,
            "Ignoring received unreachable event");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_UnreachableIgnore
#define _clog_3_ARGS_TRACE_UnreachableIgnore(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, UnreachableIgnore , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UnreachableInvalid
// [conn][%p] Received invalid unreachable event
// QuicTraceLogConnWarning(
            UnreachableInvalid,
            Connection,
            "Received invalid unreachable event");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_UnreachableInvalid
#define _clog_3_ARGS_TRACE_UnreachableInvalid(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, UnreachableInvalid , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CloseUserCanceled
// [conn][%p] Connection close using user canceled error
// QuicTraceLogConnInfo(
                CloseUserCanceled,
                Connection,
                "Connection close using user canceled error");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CloseUserCanceled
#define _clog_3_ARGS_TRACE_CloseUserCanceled(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CloseUserCanceled , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CloseComplete
// [conn][%p] Connection close complete
// QuicTraceLogConnInfo(
            CloseComplete,
            Connection,
            "Connection close complete");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CloseComplete
#define _clog_3_ARGS_TRACE_CloseComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CloseComplete , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for Restart
// [conn][%p] Restart (CompleteReset=%hhu)
// QuicTraceLogConnInfo(
        Restart,
        Connection,
        "Restart (CompleteReset=%hhu)",
        CompleteReset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = CompleteReset = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_Restart
#define _clog_4_ARGS_TRACE_Restart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, Restart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CryptoStateDiscard
// [conn][%p] TLS state no longer needed
// QuicTraceLogConnInfo(
            CryptoStateDiscard,
            Connection,
            "TLS state no longer needed");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CryptoStateDiscard
#define _clog_3_ARGS_TRACE_CryptoStateDiscard(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CryptoStateDiscard , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for SetConfiguration
// [conn][%p] Configuration set, %p
// QuicTraceLogConnInfo(
        SetConfiguration,
        Connection,
        "Configuration set, %p",
        Configuration);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Configuration = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_SetConfiguration
#define _clog_4_ARGS_TRACE_SetConfiguration(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, SetConfiguration , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PeerTPSet
// [conn][%p] Peer Transport Parameters Set
// QuicTraceLogConnInfo(
        PeerTPSet,
        Connection,
        "Peer Transport Parameters Set");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PeerTPSet
#define _clog_3_ARGS_TRACE_PeerTPSet(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, PeerTPSet , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PeerPreferredAddress
// [conn][%p] Peer configured preferred address %!ADDR!
// QuicTraceLogConnInfo(
                PeerPreferredAddress,
                Connection,
                "Peer configured preferred address %!ADDR!",
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PeerPreferredAddress
#define _clog_5_ARGS_TRACE_PeerPreferredAddress(uniqueId, arg1, encoded_arg_string, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, PeerPreferredAddress , arg1, arg3_len, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NegotiatedDisable1RttEncryption
// [conn][%p] Negotiated Disable 1-RTT Encryption
// QuicTraceLogConnInfo(
                NegotiatedDisable1RttEncryption,
                Connection,
                "Negotiated Disable 1-RTT Encryption");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NegotiatedDisable1RttEncryption
#define _clog_3_ARGS_TRACE_NegotiatedDisable1RttEncryption(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NegotiatedDisable1RttEncryption , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CustomCertValidationPending
// [conn][%p] Custom cert validation is pending
// QuicTraceLogConnInfo(
            CustomCertValidationPending,
            Connection,
            "Custom cert validation is pending");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CustomCertValidationPending
#define _clog_3_ARGS_TRACE_CustomCertValidationPending(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CustomCertValidationPending , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecvStatelessReset
// [conn][%p] Received stateless reset
// QuicTraceLogConnInfo(
                        RecvStatelessReset,
                        Connection,
                        "Received stateless reset");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RecvStatelessReset
#define _clog_3_ARGS_TRACE_RecvStatelessReset(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvStatelessReset , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedFrame
// [conn][%p] Handshake confirmed (frame)
// QuicTraceLogConnInfo(
                    HandshakeConfirmedFrame,
                    Connection,
                    "Handshake confirmed (frame)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_HandshakeConfirmedFrame
#define _clog_3_ARGS_TRACE_HandshakeConfirmedFrame(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, HandshakeConfirmedFrame , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UpdatePacketTolerance
// [conn][%p] Updating packet tolerance to %hhu
// QuicTraceLogConnInfo(
                UpdatePacketTolerance,
                Connection,
                "Updating packet tolerance to %hhu",
                Connection->PacketTolerance);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->PacketTolerance = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UpdatePacketTolerance
#define _clog_4_ARGS_TRACE_UpdatePacketTolerance(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdatePacketTolerance , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FirstCidUsage
// [conn][%p] First usage of SrcCid: %s
// QuicTraceLogConnInfo(
                FirstCidUsage,
                Connection,
                "First usage of SrcCid: %s",
                QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_FirstCidUsage
#define _clog_4_ARGS_TRACE_FirstCidUsage(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, FirstCidUsage , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PathDiscarded
// [conn][%p] Removing invalid path[%hhu]
// QuicTraceLogConnInfo(
                PathDiscarded,
                Connection,
                "Removing invalid path[%hhu]",
                Connection->Paths[i].ID);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Paths[i].ID = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PathDiscarded
#define _clog_4_ARGS_TRACE_PathDiscarded(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, PathDiscarded , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for Unreachable
// [conn][%p] Received unreachable event
// QuicTraceLogConnInfo(
            Unreachable,
            Connection,
            "Received unreachable event");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_Unreachable
#define _clog_3_ARGS_TRACE_Unreachable(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, Unreachable , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for FailedRouteResolution
// [conn][%p] Route resolution failed on Path[%hhu]. Switching paths...
// QuicTraceLogConnInfo(
                    FailedRouteResolution,
                    Connection,
                    "Route resolution failed on Path[%hhu]. Switching paths...",
                    PathId);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = PathId = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_FailedRouteResolution
#define _clog_4_ARGS_TRACE_FailedRouteResolution(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, FailedRouteResolution , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UpdatePeerPacketTolerance
// [conn][%p] Updating peer packet tolerance to %hhu
// QuicTraceLogConnInfo(
            UpdatePeerPacketTolerance,
            Connection,
            "Updating peer packet tolerance to %hhu",
            NewPacketTolerance);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = NewPacketTolerance = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UpdatePeerPacketTolerance
#define _clog_4_ARGS_TRACE_UpdatePeerPacketTolerance(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdatePeerPacketTolerance , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UpdateShareBinding
// [conn][%p] Updated ShareBinding = %hhu
// QuicTraceLogConnInfo(
            UpdateShareBinding,
            Connection,
            "Updated ShareBinding = %hhu",
            Connection->State.ShareBinding);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->State.ShareBinding = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UpdateShareBinding
#define _clog_4_ARGS_TRACE_UpdateShareBinding(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdateShareBinding , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UpdateStreamSchedulingScheme
// [conn][%p] Updated Stream Scheduling Scheme = %u
// QuicTraceLogConnInfo(
            UpdateStreamSchedulingScheme,
            Connection,
            "Updated Stream Scheduling Scheme = %u",
            (uint32_t)Scheme);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint32_t)Scheme = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UpdateStreamSchedulingScheme
#define _clog_4_ARGS_TRACE_UpdateStreamSchedulingScheme(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdateStreamSchedulingScheme , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LocalInterfaceSet
// [conn][%p] Local interface set to %u
// QuicTraceLogConnInfo(
            LocalInterfaceSet,
            Connection,
            "Local interface set to %u",
            Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LocalInterfaceSet
#define _clog_4_ARGS_TRACE_LocalInterfaceSet(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, LocalInterfaceSet , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CibirIdSet
// [conn][%p] CIBIR ID set (len %hhu, offset %hhu)
// QuicTraceLogConnInfo(
            CibirIdSet,
            Connection,
            "CIBIR ID set (len %hhu, offset %hhu)",
            Connection->CibirId[0],
            Connection->CibirId[1]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->CibirId[0] = arg3
// arg4 = arg4 = Connection->CibirId[1] = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CibirIdSet
#define _clog_5_ARGS_TRACE_CibirIdSet(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CibirIdSet , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ApplySettings
// [conn][%p] Applying new settings
// QuicTraceLogConnInfo(
        ApplySettings,
        Connection,
        "Applying new settings");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ApplySettings
#define _clog_3_ARGS_TRACE_ApplySettings(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ApplySettings , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RttUpdatedMsg
// [conn][%p] Updated Rtt=%u.%03u ms, Var=%u.%03u
// QuicTraceLogConnVerbose(
            RttUpdatedMsg,
            Connection,
            "Updated Rtt=%u.%03u ms, Var=%u.%03u",
            Path->SmoothedRtt / 1000, Path->SmoothedRtt % 1000,
            Path->RttVariance / 1000, Path->RttVariance % 1000);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Path->SmoothedRtt / 1000 = arg3
// arg4 = arg4 = Path->SmoothedRtt % 1000 = arg4
// arg5 = arg5 = Path->RttVariance / 1000 = arg5
// arg6 = arg6 = Path->RttVariance % 1000 = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_RttUpdatedMsg
#define _clog_7_ARGS_TRACE_RttUpdatedMsg(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_CONNECTION_C, RttUpdatedMsg , arg1, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NewSrcCidNameCollision
// [conn][%p] CID collision, trying again
// QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                Connection,
                "CID collision, trying again");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NewSrcCidNameCollision
#define _clog_3_ARGS_TRACE_NewSrcCidNameCollision(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NewSrcCidNameCollision , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ZeroLengthCidRetire
// [conn][%p] Can't retire current CID because it's zero length
// QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            Connection,
            "Can't retire current CID because it's zero length");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ZeroLengthCidRetire
#define _clog_3_ARGS_TRACE_ZeroLengthCidRetire(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ZeroLengthCidRetire , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateShutdownByPeer
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]
// QuicTraceLogConnVerbose(
            IndicateShutdownByPeer,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]",
            Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicateShutdownByPeer
#define _clog_4_ARGS_TRACE_IndicateShutdownByPeer(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, IndicateShutdownByPeer , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateShutdownByTransport
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]
// QuicTraceLogConnVerbose(
            IndicateShutdownByTransport,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]",
            Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicateShutdownByTransport
#define _clog_4_ARGS_TRACE_IndicateShutdownByTransport(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, IndicateShutdownByTransport , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateConnectionShutdownComplete
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
// QuicTraceLogConnVerbose(
            IndicateConnectionShutdownComplete,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicateConnectionShutdownComplete
#define _clog_3_ARGS_TRACE_IndicateConnectionShutdownComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicateConnectionShutdownComplete , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateResumed
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_RESUMED
// QuicTraceLogConnVerbose(
            IndicateResumed,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_RESUMED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicateResumed
#define _clog_3_ARGS_TRACE_IndicateResumed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicateResumed , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateResumptionTicketReceived
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
// QuicTraceLogConnVerbose(
                IndicateResumptionTicketReceived,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicateResumptionTicketReceived
#define _clog_3_ARGS_TRACE_IndicateResumptionTicketReceived(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicateResumptionTicketReceived , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationCompatibleVersionUpgrade
// [conn][%p] Compatible version upgrade! Old: 0x%x, New: 0x%x
// QuicTraceLogConnVerbose(
                        ClientVersionNegotiationCompatibleVersionUpgrade,
                        Connection,
                        "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                        Connection->Stats.QuicVersion,
                        SupportedVersions[ServerVersionIdx]);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Stats.QuicVersion = arg3
// arg4 = arg4 = SupportedVersions[ServerVersionIdx] = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ClientVersionNegotiationCompatibleVersionUpgrade
#define _clog_5_ARGS_TRACE_ClientVersionNegotiationCompatibleVersionUpgrade(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ClientVersionNegotiationCompatibleVersionUpgrade , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionUpgradeComplete
// [conn][%p] Compatible version upgrade! Old: 0x%x, New: 0x%x
// QuicTraceLogConnVerbose(
                CompatibleVersionUpgradeComplete,
                Connection,
                "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                Connection->OriginalQuicVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->OriginalQuicVersion = arg3
// arg4 = arg4 = Connection->Stats.QuicVersion = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CompatibleVersionUpgradeComplete
#define _clog_5_ARGS_TRACE_CompatibleVersionUpgradeComplete(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CompatibleVersionUpgradeComplete , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerCertificateReceived
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)
// QuicTraceLogConnVerbose(
        IndicatePeerCertificateReceived,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)",
        DeferredErrorFlags,
        DeferredStatus);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DeferredErrorFlags = arg3
// arg4 = arg4 = DeferredStatus = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_IndicatePeerCertificateReceived
#define _clog_5_ARGS_TRACE_IndicatePeerCertificateReceived(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, IndicatePeerCertificateReceived , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for QueueDatagrams
// [conn][%p] Queuing %u UDP datagrams
// QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u UDP datagrams",
        DatagramChainLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DatagramChainLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_QueueDatagrams
#define _clog_4_ARGS_TRACE_QueueDatagrams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, QueueDatagrams , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecvVerNeg
// [conn][%p] Received Version Negotation:
// QuicTraceLogConnVerbose(
        RecvVerNeg,
        Connection,
        "Received Version Negotation:");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_RecvVerNeg
#define _clog_3_ARGS_TRACE_RecvVerNeg(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvVerNeg , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for VerNegItem
// [conn][%p]   Ver[%d]: 0x%x
// QuicTraceLogConnVerbose(
            VerNegItem,
            Connection,
            "  Ver[%d]: 0x%x",
            (int32_t)i,
            CxPlatByteSwapUint32(ServerVersion));
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (int32_t)i = arg3
// arg4 = arg4 = CxPlatByteSwapUint32(ServerVersion) = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_VerNegItem
#define _clog_5_ARGS_TRACE_VerNegItem(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, VerNegItem , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DeferDatagram
// [conn][%p] Deferring datagram (type=%hu)
// QuicTraceLogConnVerbose(
                    DeferDatagram,
                    Connection,
                    "Deferring datagram (type=%hu)",
                    (uint16_t)Packet->KeyType);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Packet->KeyType = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DeferDatagram
#define _clog_4_ARGS_TRACE_DeferDatagram(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, DeferDatagram , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecryptOldKey
// [conn][%p] Using old key to decrypt
// QuicTraceLogConnVerbose(
                DecryptOldKey,
                Connection,
                "Using old key to decrypt");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DecryptOldKey
#define _clog_3_ARGS_TRACE_DecryptOldKey(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, DecryptOldKey , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PossiblePeerKeyUpdate
// [conn][%p] Possible peer initiated key update [packet %llu]
// QuicTraceLogConnVerbose(
                PossiblePeerKeyUpdate,
                Connection,
                "Possible peer initiated key update [packet %llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PossiblePeerKeyUpdate
#define _clog_4_ARGS_TRACE_PossiblePeerKeyUpdate(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, PossiblePeerKeyUpdate , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UpdateReadKeyPhase
// [conn][%p] Updating current read key phase and packet number[%llu]
// QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Packet->PacketNumber = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UpdateReadKeyPhase
#define _clog_4_ARGS_TRACE_UpdateReadKeyPhase(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdateReadKeyPhase , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PeerConnFCBlocked
// [conn][%p] Peer Connection FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.DataLimit = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_PeerConnFCBlocked
#define _clog_4_ARGS_TRACE_PeerConnFCBlocked(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, PeerConnFCBlocked , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PeerStreamFCBlocked
// [conn][%p] Peer Streams[%hu] FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Frame.BidirectionalStreams = arg3
// arg4 = arg4 = Frame.StreamLimit = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_PeerStreamFCBlocked
#define _clog_5_ARGS_TRACE_PeerStreamFCBlocked(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, PeerStreamFCBlocked , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerNeedStreams
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS
// QuicTraceLogConnVerbose(
                IndicatePeerNeedStreams,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicatePeerNeedStreams
#define _clog_3_ARGS_TRACE_IndicatePeerNeedStreams(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicatePeerNeedStreams , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicatePeerAddrChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
// QuicTraceLogConnVerbose(
            IndicatePeerAddrChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IndicatePeerAddrChanged
#define _clog_3_ARGS_TRACE_IndicatePeerAddrChanged(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicatePeerAddrChanged , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UdpRecvBatch
// [conn][%p] Batch Recv %u UDP datagrams
// QuicTraceLogConnVerbose(
        UdpRecvBatch,
        Connection,
        "Batch Recv %u UDP datagrams",
        BatchCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = BatchCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UdpRecvBatch
#define _clog_4_ARGS_TRACE_UdpRecvBatch(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UdpRecvBatch , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UdpRecvDeferred
// [conn][%p] Recv %u deferred UDP datagrams
// QuicTraceLogConnVerbose(
            UdpRecvDeferred,
            Connection,
            "Recv %u deferred UDP datagrams",
            DatagramChainCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DatagramChainCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UdpRecvDeferred
#define _clog_4_ARGS_TRACE_UdpRecvDeferred(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UdpRecvDeferred , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for UdpRecv
// [conn][%p] Recv %u UDP datagrams
// QuicTraceLogConnVerbose(
            UdpRecv,
            Connection,
            "Recv %u UDP datagrams",
            DatagramChainCount);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = DatagramChainCount = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_UdpRecv
#define _clog_4_ARGS_TRACE_UdpRecv(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UdpRecv , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DatagramReceiveEnableUpdated
// [conn][%p] Updated datagram receive enabled to %hhu
// QuicTraceLogConnVerbose(
            DatagramReceiveEnableUpdated,
            Connection,
            "Updated datagram receive enabled to %hhu",
            Connection->Settings.DatagramReceiveEnabled);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->Settings.DatagramReceiveEnabled = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DatagramReceiveEnableUpdated
#define _clog_4_ARGS_TRACE_DatagramReceiveEnableUpdated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, DatagramReceiveEnableUpdated , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for Disable1RttEncrytionUpdated
// [conn][%p] Updated disable 1-RTT encrytption to %hhu
// QuicTraceLogConnVerbose(
            Disable1RttEncrytionUpdated,
            Connection,
            "Updated disable 1-RTT encrytption to %hhu",
            Connection->State.Disable1RttEncrytion);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->State.Disable1RttEncrytion = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_Disable1RttEncrytionUpdated
#define _clog_4_ARGS_TRACE_Disable1RttEncrytionUpdated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, Disable1RttEncrytionUpdated , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ForceKeyUpdate
// [conn][%p] Forcing key update
// QuicTraceLogConnVerbose(
            ForceKeyUpdate,
            Connection,
            "Forcing key update");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ForceKeyUpdate
#define _clog_3_ARGS_TRACE_ForceKeyUpdate(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ForceKeyUpdate , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ForceCidUpdate
// [conn][%p] Forcing destination CID update
// QuicTraceLogConnVerbose(
            ForceCidUpdate,
            Connection,
            "Forcing destination CID update");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ForceCidUpdate
#define _clog_3_ARGS_TRACE_ForceCidUpdate(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ForceCidUpdate , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for TestTPSet
// [conn][%p] Setting Test Transport Parameter (type %hu, %hu bytes)
// QuicTraceLogConnVerbose(
            TestTPSet,
            Connection,
            "Setting Test Transport Parameter (type %hu, %hu bytes)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Connection->TestTransportParameter.Type = arg3
// arg4 = arg4 = Connection->TestTransportParameter.Length = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_TestTPSet
#define _clog_5_ARGS_TRACE_TestTPSet(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, TestTPSet , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AbandonInternallyClosed
// [conn][%p] Abandoning internal, closed connection
// QuicTraceLogConnVerbose(
            AbandonInternallyClosed,
            Connection,
            "Abandoning internal, closed connection");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_AbandonInternallyClosed
#define _clog_3_ARGS_TRACE_AbandonInternallyClosed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, AbandonInternallyClosed , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
// arg2 = arg2 = "connection" = arg2
// arg3 = arg3 = sizeof(QUIC_CONNECTION) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnCreated
// [conn][%p] Created, IsServer=%hhu, CorrelationId=%llu
// QuicTraceEvent(
        ConnCreated,
        "[conn][%p] Created, IsServer=%hhu, CorrelationId=%llu",
        Connection,
        IsServer,
        Connection->Stats.CorrelationId);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = IsServer = arg3
// arg4 = arg4 = Connection->Stats.CorrelationId = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnCreated
#define _clog_5_ARGS_TRACE_ConnCreated(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnCreated , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrAdded
#define _clog_5_ARGS_TRACE_ConnLocalAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, ConnLocalAddrAdded , arg2, arg3_len, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnRemoteAddrAdded
#define _clog_5_ARGS_TRACE_ConnRemoteAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, ConnRemoteAddrAdded , arg2, arg3_len, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Path->DestCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data) = arg4
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnDestCidAdded
#define _clog_6_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_C, ConnDestCidAdded , arg2, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
            ConnSourceCidAdded,
            "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
            Connection,
            SourceCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = SourceCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data) = arg4
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnSourceCidAdded
#define _clog_6_ARGS_TRACE_ConnSourceCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_C, ConnSourceCidAdded , arg2, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnInitializeComplete
// [conn][%p] Initialize complete
// QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnInitializeComplete
#define _clog_3_ARGS_TRACE_ConnInitializeComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnInitializeComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnUnregistered
// [conn][%p] Unregistered from %p
// QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Registration = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnUnregistered
#define _clog_4_ARGS_TRACE_ConnUnregistered(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnUnregistered , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDestroyed
// [conn][%p] Destroyed
// QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnDestroyed
#define _clog_3_ARGS_TRACE_ConnDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnHandleClosed
// [conn][%p] Handle closed
// QuicTraceEvent(
        ConnHandleClosed,
        "[conn][%p] Handle closed",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnHandleClosed
#define _clog_3_ARGS_TRACE_ConnHandleClosed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnHandleClosed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnRegistered
// [conn][%p] Registered with %p
// QuicTraceEvent(
            ConnRegistered,
            "[conn][%p] Registered with %p",
            Connection,
            Registration);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Registration = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnRegistered
#define _clog_4_ARGS_TRACE_ConnRegistered(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnRegistered , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnRundown
// [conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu
// QuicTraceEvent(
        ConnRundown,
        "[conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu",
        Connection,
        QuicConnIsServer(Connection),
        Connection->Stats.CorrelationId);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = QuicConnIsServer(Connection) = arg3
// arg4 = arg4 = Connection->Stats.CorrelationId = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnRundown
#define _clog_5_ARGS_TRACE_ConnRundown(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnRundown , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnAssignWorker
// [conn][%p] Assigned worker: %p
// QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Connection->Worker);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Worker = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnAssignWorker
#define _clog_4_ARGS_TRACE_ConnAssignWorker(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnAssignWorker , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnVersionSet
// [conn][%p] QUIC Version: %u
// QuicTraceEvent(
            ConnVersionSet,
            "[conn][%p] QUIC Version: %u",
            Connection,
            Connection->Stats.QuicVersion);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->Stats.QuicVersion = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnVersionSet
#define _clog_4_ARGS_TRACE_ConnVersionSet(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnVersionSet , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnHandshakeComplete
#define _clog_3_ARGS_TRACE_ConnHandshakeComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnHandshakeComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Too many CID collisions");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Too many CID collisions" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDestCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
        Connection,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = DestCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data) = arg4
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnDestCidRemoved
#define _clog_6_ARGS_TRACE_ConnDestCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_C, ConnDestCidRemoved , arg2, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnSetTimer
// [conn][%p] Setting %hhu, delay=%llu us
// QuicTraceEvent(
        ConnSetTimer,
        "[conn][%p] Setting %hhu, delay=%llu us",
        Connection,
        (uint8_t)Type,
        Delay);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint8_t)Type = arg3
// arg4 = arg4 = Delay = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnSetTimer
#define _clog_5_ARGS_TRACE_ConnSetTimer(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnSetTimer , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnCancelTimer
// [conn][%p] Canceling %hhu
// QuicTraceEvent(
                ConnCancelTimer,
                "[conn][%p] Canceling %hhu",
                Connection,
                (uint8_t)Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint8_t)Type = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnCancelTimer
#define _clog_4_ARGS_TRACE_ConnCancelTimer(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnCancelTimer , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnExpiredTimer
// [conn][%p] %hhu expired
// QuicTraceEvent(
            ConnExpiredTimer,
            "[conn][%p] %hhu expired",
            Connection,
            (uint8_t)Temp[j].Type);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = (uint8_t)Temp[j].Type = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnExpiredTimer
#define _clog_4_ARGS_TRACE_ConnExpiredTimer(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnExpiredTimer , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnExecTimerOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                QUIC_CONN_TIMER_ACK_DELAY);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = QUIC_CONN_TIMER_ACK_DELAY = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnExecTimerOper
#define _clog_4_ARGS_TRACE_ConnExecTimerOper(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnExecTimerOper , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnShutdownComplete
// [conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.
// QuicTraceEvent(
        ConnShutdownComplete,
        "[conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.",
        Connection,
        Connection->State.ShutdownCompleteTimedOut);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Connection->State.ShutdownCompleteTimedOut = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnShutdownComplete
#define _clog_4_ARGS_TRACE_ConnShutdownComplete(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnShutdownComplete , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnAppShutdown
// [conn][%p] App Shutdown: %llu (Remote=%hhu)
// QuicTraceEvent(
                ConnAppShutdown,
                "[conn][%p] App Shutdown: %llu (Remote=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = ErrorCode = arg3
// arg4 = arg4 = ClosedRemotely = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnAppShutdown
#define _clog_5_ARGS_TRACE_ConnAppShutdown(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnAppShutdown , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnTransportShutdown
// [conn][%p] Transport Shutdown: %llu (Remote=%hhu) (QS=%hhu)
// QuicTraceEvent(
                ConnTransportShutdown,
                "[conn][%p] Transport Shutdown: %llu (Remote=%hhu) (QS=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely,
                !!(Flags & QUIC_CLOSE_QUIC_STATUS));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = ErrorCode = arg3
// arg4 = arg4 = ClosedRemotely = arg4
// arg5 = arg5 = !!(Flags & QUIC_CLOSE_QUIC_STATUS) = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnTransportShutdown
#define _clog_6_ARGS_TRACE_ConnTransportShutdown(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_CONNECTION_C, ConnTransportShutdown , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection, Status,
                    "Set current compartment Id");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Set current compartment Id" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnServerResumeTicket
// [conn][%p] Server app accepted resumption ticket
// QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app accepted resumption ticket",
                Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnServerResumeTicket
#define _clog_3_ARGS_TRACE_ConnServerResumeTicket(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnServerResumeTicket , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeStart
// [conn][%p] Handshake start
// QuicTraceEvent(
        ConnHandshakeStart,
        "[conn][%p] Handshake start",
        Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnHandshakeStart
#define _clog_3_ARGS_TRACE_ConnHandshakeStart(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnHandshakeStart , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PacketDecrypt
// [pack][%llu] Decrypting
// QuicTraceEvent(
        PacketDecrypt,
        "[pack][%llu] Decrypting",
        Packet->PacketId);
// arg2 = arg2 = Packet->PacketId = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PacketDecrypt
#define _clog_3_ARGS_TRACE_PacketDecrypt(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, PacketDecrypt , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnPacketRecv
// [conn][%p][RX][%llu] %c (%hu bytes)
// QuicTraceEvent(
        ConnPacketRecv,
        "[conn][%p][RX][%llu] %c (%hu bytes)",
        Connection,
        Packet->PacketNumber,
        Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1),
        Packet->HeaderLength + Packet->PayloadLength);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Packet->PacketNumber = arg3
// arg4 = arg4 = Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1) = arg4
// arg5 = arg5 = Packet->HeaderLength + Packet->PayloadLength = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnPacketRecv
#define _clog_6_ARGS_TRACE_ConnPacketRecv(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_CONNECTION_C, ConnPacketRecv , arg2, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrRemoved
// [conn][%p] Removed Local IP: %!ADDR!
// QuicTraceEvent(
                ConnLocalAddrRemoved,
                "[conn][%p] Removed Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrRemoved
#define _clog_5_ARGS_TRACE_ConnLocalAddrRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, ConnLocalAddrRemoved , arg2, arg3_len, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_connection.c.clog.h.c"
#endif
