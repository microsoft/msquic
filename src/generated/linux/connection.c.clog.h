#include <clog.h>
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
#ifndef _clog_3_ARGS_TRACE_PacketRxStatelessReset



/*----------------------------------------------------------
// Decoder Ring for PacketRxStatelessReset
// [S][RX][-] SR %s
// QuicTraceLogVerbose(
                        PacketRxStatelessReset,
                        "[S][RX][-] SR %s",
                        QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg2 = arg2 = QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_PacketRxStatelessReset(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, PacketRxStatelessReset , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketRxNotAcked



/*----------------------------------------------------------
// Decoder Ring for PacketRxNotAcked
// [%c][RX][%llu] not acked (connection is closed)
// QuicTraceLogVerbose(
            PacketRxNotAcked,
            "[%c][RX][%llu] not acked (connection is closed)",
            PtkConnPre(Connection),
            Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketRxNotAcked(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, PacketRxNotAcked , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ClientVersionInfoVersionMismatch



/*----------------------------------------------------------
// Decoder Ring for ClientVersionInfoVersionMismatch
// [conn][%p] Client Chosen Version doesn't match long header. 0x%x != 0x%x
// QuicTraceLogConnError(
                ClientVersionInfoVersionMismatch,
                Connection,
                "Client Chosen Version doesn't match long header. 0x%x != 0x%x",
                ClientVI.ChosenVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = ClientVI.ChosenVersion
// arg4 = arg4 = Connection->Stats.QuicVersion
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ClientVersionInfoVersionMismatch(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ClientVersionInfoVersionMismatch , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ServerVersionInfoVersionMismatch



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInfoVersionMismatch
// [conn][%p] Server Chosen Version doesn't match long header. 0x%x != 0x%x
// QuicTraceLogConnError(
                ServerVersionInfoVersionMismatch,
                Connection,
                "Server Chosen Version doesn't match long header. 0x%x != 0x%x",
                ServerVI.ChosenVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = ServerVI.ChosenVersion
// arg4 = arg4 = Connection->Stats.QuicVersion
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ServerVersionInfoVersionMismatch(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInfoVersionMismatch , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ServerVersionInformationChosenVersionNotInOtherVerList



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationChosenVersionNotInOtherVerList
// [conn][%p] Server Chosen Version is not in Server Other Versions list: 0x%x
// QuicTraceLogConnError(
                ServerVersionInformationChosenVersionNotInOtherVerList,
                Connection,
                "Server Chosen Version is not in Server Other Versions list: 0x%x",
                ServerVI.ChosenVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = ServerVI.ChosenVersion
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ServerVersionInformationChosenVersionNotInOtherVerList(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInformationChosenVersionNotInOtherVerList , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ClientChosenVersionMismatchServerChosenVersion



/*----------------------------------------------------------
// Decoder Ring for ClientChosenVersionMismatchServerChosenVersion
// [conn][%p] Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x
// QuicTraceLogConnError(
                ClientChosenVersionMismatchServerChosenVersion,
                Connection,
                "Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x",
                ClientChosenVersion,
                ServerVI.ChosenVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = ClientChosenVersion
// arg4 = arg4 = ServerVI.ChosenVersion
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ClientChosenVersionMismatchServerChosenVersion(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ClientChosenVersionMismatchServerChosenVersion , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionIsChosenVersion



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationPreviousVersionIsChosenVersion
// [conn][%p] Previous Client Version is Server Chosen Version: 0x%x
// QuicTraceLogConnError(
                    ServerVersionInformationPreviousVersionIsChosenVersion,
                    Connection,
                    "Previous Client Version is Server Chosen Version: 0x%x",
                    Connection->PreviousQuicVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->PreviousQuicVersion
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionIsChosenVersion(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInformationPreviousVersionIsChosenVersion , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionInOtherVerList



/*----------------------------------------------------------
// Decoder Ring for ServerVersionInformationPreviousVersionInOtherVerList
// [conn][%p] Previous Client Version in Server Other Versions list: 0x%x
// QuicTraceLogConnError(
                        ServerVersionInformationPreviousVersionInOtherVerList,
                        Connection,
                        "Previous Client Version in Server Other Versions list: 0x%x",
                        Connection->PreviousQuicVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->PreviousQuicVersion
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ServerVersionInformationPreviousVersionInOtherVerList(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, ServerVersionInformationPreviousVersionInOtherVerList , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_CompatibleVersionNegotiationNotCompatible



/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionNegotiationNotCompatible
// [conn][%p] Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x
// QuicTraceLogConnError(
                    CompatibleVersionNegotiationNotCompatible,
                    Connection,
                    "Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->OriginalQuicVersion
// arg4 = arg4 = ServerVI.ChosenVersion
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_CompatibleVersionNegotiationNotCompatible(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CompatibleVersionNegotiationNotCompatible , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_CompatibleVersionNegotiationOriginalVersionNotFound



/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionNegotiationOriginalVersionNotFound
// [conn][%p] OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x
// QuicTraceLogConnError(
                    CompatibleVersionNegotiationOriginalVersionNotFound,
                    Connection,
                    "OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->OriginalQuicVersion
// arg4 = arg4 = ServerVI.ChosenVersion
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_CompatibleVersionNegotiationOriginalVersionNotFound(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CompatibleVersionNegotiationOriginalVersionNotFound , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_RecvVerNegNoMatch



/*----------------------------------------------------------
// Decoder Ring for RecvVerNegNoMatch
// [conn][%p] Version Negotation contained no supported versions
// QuicTraceLogConnError(
            RecvVerNegNoMatch,
            Connection,
            "Version Negotation contained no supported versions");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_RecvVerNegNoMatch(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvVerNegNoMatch , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_ApiEventNoHandler



/*----------------------------------------------------------
// Decoder Ring for ApiEventNoHandler
// [conn][%p] Event silently discarded (no handler).
// QuicTraceLogConnWarning(
            ApiEventNoHandler,
            Connection,
            "Event silently discarded (no handler).");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ApiEventNoHandler(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ApiEventNoHandler , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_NoReplacementCidForRetire



/*----------------------------------------------------------
// Decoder Ring for NoReplacementCidForRetire
// [conn][%p] Can't retire current CID because we don't have a replacement
// QuicTraceLogConnWarning(
            NoReplacementCidForRetire,
            Connection,
            "Can't retire current CID because we don't have a replacement");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NoReplacementCidForRetire(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NoReplacementCidForRetire , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_NonActivePathCidRetired



/*----------------------------------------------------------
// Decoder Ring for NonActivePathCidRetired
// [conn][%p] Non-active path has no replacement for retired CID.
// QuicTraceLogConnWarning(
                NonActivePathCidRetired,
                Connection,
                "Non-active path has no replacement for retired CID.");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NonActivePathCidRetired(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NonActivePathCidRetired , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_IgnoreUnreachable



/*----------------------------------------------------------
// Decoder Ring for IgnoreUnreachable
// [conn][%p] Ignoring received unreachable event (inline)
// QuicTraceLogConnWarning(
            IgnoreUnreachable,
            Connection,
            "Ignoring received unreachable event (inline)");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IgnoreUnreachable(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IgnoreUnreachable , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_IgnoreFrameAfterClose



/*----------------------------------------------------------
// Decoder Ring for IgnoreFrameAfterClose
// [conn][%p] Ignoring frame (%hhu) for already closed stream id = %llu
// QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
// arg1 = arg1 = Connection
// arg3 = arg3 = (uint8_t)FrameType
// arg4 = arg4 = // This cast is safe because of the switch cases above.
                    StreamId
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_IgnoreFrameAfterClose(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, IgnoreFrameAfterClose , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_InvalidInitialPackets



/*----------------------------------------------------------
// Decoder Ring for InvalidInitialPackets
// [conn][%p] Aborting connection with invalid initial packets
// QuicTraceLogConnWarning(
            InvalidInitialPackets,
            Connection,
            "Aborting connection with invalid initial packets");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_InvalidInitialPackets(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, InvalidInitialPackets , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_UnreachableIgnore



/*----------------------------------------------------------
// Decoder Ring for UnreachableIgnore
// [conn][%p] Ignoring received unreachable event
// QuicTraceLogConnWarning(
            UnreachableIgnore,
            Connection,
            "Ignoring received unreachable event");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_UnreachableIgnore(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, UnreachableIgnore , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_UnreachableInvalid



/*----------------------------------------------------------
// Decoder Ring for UnreachableInvalid
// [conn][%p] Received invalid unreachable event
// QuicTraceLogConnWarning(
            UnreachableInvalid,
            Connection,
            "Received invalid unreachable event");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_UnreachableInvalid(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, UnreachableInvalid , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_CloseUserCanceled



/*----------------------------------------------------------
// Decoder Ring for CloseUserCanceled
// [conn][%p] Connection close using user canceled error
// QuicTraceLogConnInfo(
                CloseUserCanceled,
                Connection,
                "Connection close using user canceled error");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CloseUserCanceled(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CloseUserCanceled , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_CloseComplete



/*----------------------------------------------------------
// Decoder Ring for CloseComplete
// [conn][%p] Connection close complete
// QuicTraceLogConnInfo(
            CloseComplete,
            Connection,
            "Connection close complete");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CloseComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CloseComplete , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_Restart



/*----------------------------------------------------------
// Decoder Ring for Restart
// [conn][%p] Restart (CompleteReset=%hhu)
// QuicTraceLogConnInfo(
        Restart,
        Connection,
        "Restart (CompleteReset=%hhu)",
        CompleteReset);
// arg1 = arg1 = Connection
// arg3 = arg3 = CompleteReset
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_Restart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, Restart , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_CryptoStateDiscard



/*----------------------------------------------------------
// Decoder Ring for CryptoStateDiscard
// [conn][%p] TLS state no longer needed
// QuicTraceLogConnInfo(
            CryptoStateDiscard,
            Connection,
            "TLS state no longer needed");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CryptoStateDiscard(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CryptoStateDiscard , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_SetConfiguration



/*----------------------------------------------------------
// Decoder Ring for SetConfiguration
// [conn][%p] Configuration set, %p
// QuicTraceLogConnInfo(
        SetConfiguration,
        Connection,
        "Configuration set, %p",
        Configuration);
// arg1 = arg1 = Connection
// arg3 = arg3 = Configuration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_SetConfiguration(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, SetConfiguration , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_PeerTPSet



/*----------------------------------------------------------
// Decoder Ring for PeerTPSet
// [conn][%p] Peer Transport Parameters Set
// QuicTraceLogConnInfo(
        PeerTPSet,
        Connection,
        "Peer Transport Parameters Set");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_PeerTPSet(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, PeerTPSet , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_PeerPreferredAddress



/*----------------------------------------------------------
// Decoder Ring for PeerPreferredAddress
// [conn][%p] Peer configured preferred address %!ADDR!
// QuicTraceLogConnInfo(
                PeerPreferredAddress,
                Connection,
                "Peer configured preferred address %!ADDR!",
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress));
// arg1 = arg1 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_PeerPreferredAddress(uniqueId, arg1, encoded_arg_string, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, PeerPreferredAddress , arg1, arg3_len, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_NegotiatedDisable1RttEncryption



/*----------------------------------------------------------
// Decoder Ring for NegotiatedDisable1RttEncryption
// [conn][%p] Negotiated Disable 1-RTT Encryption
// QuicTraceLogConnInfo(
                NegotiatedDisable1RttEncryption,
                Connection,
                "Negotiated Disable 1-RTT Encryption");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NegotiatedDisable1RttEncryption(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NegotiatedDisable1RttEncryption , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_CustomCertValidationPending



/*----------------------------------------------------------
// Decoder Ring for CustomCertValidationPending
// [conn][%p] Custom cert validation is pending
// QuicTraceLogConnInfo(
            CustomCertValidationPending,
            Connection,
            "Custom cert validation is pending");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_CustomCertValidationPending(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, CustomCertValidationPending , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_RecvStatelessReset



/*----------------------------------------------------------
// Decoder Ring for RecvStatelessReset
// [conn][%p] Received stateless reset
// QuicTraceLogConnInfo(
                        RecvStatelessReset,
                        Connection,
                        "Received stateless reset");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_RecvStatelessReset(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvStatelessReset , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_HandshakeConfirmedFrame



/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedFrame
// [conn][%p] Handshake confirmed (frame)
// QuicTraceLogConnInfo(
                    HandshakeConfirmedFrame,
                    Connection,
                    "Handshake confirmed (frame)");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_HandshakeConfirmedFrame(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, HandshakeConfirmedFrame , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdatePacketTolerance



/*----------------------------------------------------------
// Decoder Ring for UpdatePacketTolerance
// [conn][%p] Updating packet tolerance to %hhu
// QuicTraceLogConnInfo(
                UpdatePacketTolerance,
                Connection,
                "Updating packet tolerance to %hhu",
                Connection->PacketTolerance);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->PacketTolerance
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdatePacketTolerance(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdatePacketTolerance , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_FirstCidUsage



/*----------------------------------------------------------
// Decoder Ring for FirstCidUsage
// [conn][%p] First usage of SrcCid: %s
// QuicTraceLogConnInfo(
                FirstCidUsage,
                Connection,
                "First usage of SrcCid: %s",
                QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer);
// arg1 = arg1 = Connection
// arg3 = arg3 = QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_FirstCidUsage(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, FirstCidUsage , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PathDiscarded



/*----------------------------------------------------------
// Decoder Ring for PathDiscarded
// [conn][%p] Removing invalid path[%hhu]
// QuicTraceLogConnInfo(
                PathDiscarded,
                Connection,
                "Removing invalid path[%hhu]",
                Connection->Paths[i].ID);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Paths[i].ID
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PathDiscarded(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, PathDiscarded , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_Unreachable



/*----------------------------------------------------------
// Decoder Ring for Unreachable
// [conn][%p] Received unreachable event
// QuicTraceLogConnInfo(
            Unreachable,
            Connection,
            "Received unreachable event");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_Unreachable(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, Unreachable , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdatePeerPacketTolerance



/*----------------------------------------------------------
// Decoder Ring for UpdatePeerPacketTolerance
// [conn][%p] Updating peer packet tolerance to %hhu
// QuicTraceLogConnInfo(
            UpdatePeerPacketTolerance,
            Connection,
            "Updating peer packet tolerance to %hhu",
            NewPacketTolerance);
// arg1 = arg1 = Connection
// arg3 = arg3 = NewPacketTolerance
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdatePeerPacketTolerance(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdatePeerPacketTolerance , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdateShareBinding



/*----------------------------------------------------------
// Decoder Ring for UpdateShareBinding
// [conn][%p] Updated ShareBinding = %hhu
// QuicTraceLogConnInfo(
            UpdateShareBinding,
            Connection,
            "Updated ShareBinding = %hhu",
            Connection->State.ShareBinding);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->State.ShareBinding
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdateShareBinding(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdateShareBinding , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdateStreamSchedulingScheme



/*----------------------------------------------------------
// Decoder Ring for UpdateStreamSchedulingScheme
// [conn][%p] Updated Stream Scheduling Scheme = %u
// QuicTraceLogConnInfo(
            UpdateStreamSchedulingScheme,
            Connection,
            "Updated Stream Scheduling Scheme = %u",
            (uint32_t)Scheme);
// arg1 = arg1 = Connection
// arg3 = arg3 = (uint32_t)Scheme
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdateStreamSchedulingScheme(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdateStreamSchedulingScheme , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_LocalInterfaceSet



/*----------------------------------------------------------
// Decoder Ring for LocalInterfaceSet
// [conn][%p] Local interface set to %u
// QuicTraceLogConnInfo(
            LocalInterfaceSet,
            Connection,
            "Local interface set to %u",
            Connection->Paths[0].LocalAddress.Ipv6.sin6_scope_id);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Paths[0].LocalAddress.Ipv6.sin6_scope_id
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_LocalInterfaceSet(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, LocalInterfaceSet , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_ApplySettings



/*----------------------------------------------------------
// Decoder Ring for ApplySettings
// [conn][%p] Applying new settings
// QuicTraceLogConnInfo(
        ApplySettings,
        Connection,
        "Applying new settings");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ApplySettings(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ApplySettings , arg1);\

#endif




#ifndef _clog_7_ARGS_TRACE_RttUpdatedMsg



/*----------------------------------------------------------
// Decoder Ring for RttUpdatedMsg
// [conn][%p] Updated Rtt=%u.%03u ms, Var=%u.%03u
// QuicTraceLogConnVerbose(
            RttUpdatedMsg,
            Connection,
            "Updated Rtt=%u.%03u ms, Var=%u.%03u",
            Path->SmoothedRtt / 1000, Path->SmoothedRtt % 1000,
            Path->RttVariance / 1000, Path->RttVariance % 1000);
// arg1 = arg1 = Connection
// arg3 = arg3 = Path->SmoothedRtt / 1000
// arg4 = arg4 = Path->SmoothedRtt % 1000
// arg5 = arg5 = Path->RttVariance / 1000
// arg6 = arg6 = Path->RttVariance % 1000
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_RttUpdatedMsg(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_CONNECTION_C, RttUpdatedMsg , arg1, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_3_ARGS_TRACE_NewSrcCidNameCollision



/*----------------------------------------------------------
// Decoder Ring for NewSrcCidNameCollision
// [conn][%p] CID collision, trying again
// QuicTraceLogConnVerbose(
                NewSrcCidNameCollision,
                Connection,
                "CID collision, trying again");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_NewSrcCidNameCollision(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, NewSrcCidNameCollision , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_ZeroLengthCidRetire



/*----------------------------------------------------------
// Decoder Ring for ZeroLengthCidRetire
// [conn][%p] Can't retire current CID because it's zero length
// QuicTraceLogConnVerbose(
            ZeroLengthCidRetire,
            Connection,
            "Can't retire current CID because it's zero length");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ZeroLengthCidRetire(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ZeroLengthCidRetire , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_TimerExpired



/*----------------------------------------------------------
// Decoder Ring for TimerExpired
// [conn][%p] %s timer expired
// QuicTraceLogConnVerbose(
            TimerExpired,
            Connection,
            "%s timer expired",
            TimerNames[Temp[j].Type]);
// arg1 = arg1 = Connection
// arg3 = arg3 = TimerNames[Temp[j].Type]
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TimerExpired(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, TimerExpired , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_IndicateShutdownByPeer



/*----------------------------------------------------------
// Decoder Ring for IndicateShutdownByPeer
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]
// QuicTraceLogConnVerbose(
            IndicateShutdownByPeer,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]",
            Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
// arg1 = arg1 = Connection
// arg3 = arg3 = Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_IndicateShutdownByPeer(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, IndicateShutdownByPeer , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_IndicateShutdownByTransport



/*----------------------------------------------------------
// Decoder Ring for IndicateShutdownByTransport
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]
// QuicTraceLogConnVerbose(
            IndicateShutdownByTransport,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]",
            Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
// arg1 = arg1 = Connection
// arg3 = arg3 = Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_IndicateShutdownByTransport(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, IndicateShutdownByTransport , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_IndicateConnectionShutdownComplete



/*----------------------------------------------------------
// Decoder Ring for IndicateConnectionShutdownComplete
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
// QuicTraceLogConnVerbose(
            IndicateConnectionShutdownComplete,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IndicateConnectionShutdownComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicateConnectionShutdownComplete , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_IndicateResumed



/*----------------------------------------------------------
// Decoder Ring for IndicateResumed
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_RESUMED
// QuicTraceLogConnVerbose(
            IndicateResumed,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_RESUMED");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IndicateResumed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicateResumed , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_IndicateResumptionTicketReceived



/*----------------------------------------------------------
// Decoder Ring for IndicateResumptionTicketReceived
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED
// QuicTraceLogConnVerbose(
                IndicateResumptionTicketReceived,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IndicateResumptionTicketReceived(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicateResumptionTicketReceived , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_ClientVersionNegotiationCompatibleVersionUpgrade



/*----------------------------------------------------------
// Decoder Ring for ClientVersionNegotiationCompatibleVersionUpgrade
// [conn][%p] Compatible version upgrade! Old: 0x%x, New: 0x%x
// QuicTraceLogConnVerbose(
                        ClientVersionNegotiationCompatibleVersionUpgrade,
                        Connection,
                        "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                        Connection->Stats.QuicVersion,
                        SupportedVersions[ServerVersionIdx]);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
// arg4 = arg4 = SupportedVersions[ServerVersionIdx]
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ClientVersionNegotiationCompatibleVersionUpgrade(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ClientVersionNegotiationCompatibleVersionUpgrade , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_CompatibleVersionUpgradeComplete



/*----------------------------------------------------------
// Decoder Ring for CompatibleVersionUpgradeComplete
// [conn][%p] Compatible version upgrade! Old: 0x%x, New: 0x%x
// QuicTraceLogConnVerbose(
                CompatibleVersionUpgradeComplete,
                Connection,
                "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                Connection->OriginalQuicVersion,
                Connection->Stats.QuicVersion);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->OriginalQuicVersion
// arg4 = arg4 = Connection->Stats.QuicVersion
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_CompatibleVersionUpgradeComplete(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, CompatibleVersionUpgradeComplete , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_IndicatePeerCertificateReceived



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerCertificateReceived
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)
// QuicTraceLogConnVerbose(
        IndicatePeerCertificateReceived,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)",
        DeferredErrorFlags,
        DeferredStatus);
// arg1 = arg1 = Connection
// arg3 = arg3 = DeferredErrorFlags
// arg4 = arg4 = DeferredStatus
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_IndicatePeerCertificateReceived(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, IndicatePeerCertificateReceived , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_QueueDatagrams



/*----------------------------------------------------------
// Decoder Ring for QueueDatagrams
// [conn][%p] Queuing %u UDP datagrams
// QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u UDP datagrams",
        DatagramChainLength);
// arg1 = arg1 = Connection
// arg3 = arg3 = DatagramChainLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_QueueDatagrams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, QueueDatagrams , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_RecvVerNeg



/*----------------------------------------------------------
// Decoder Ring for RecvVerNeg
// [conn][%p] Received Version Negotation:
// QuicTraceLogConnVerbose(
        RecvVerNeg,
        Connection,
        "Received Version Negotation:");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_RecvVerNeg(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, RecvVerNeg , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_VerNegItem



/*----------------------------------------------------------
// Decoder Ring for VerNegItem
// [conn][%p]   Ver[%d]: 0x%x
// QuicTraceLogConnVerbose(
            VerNegItem,
            Connection,
            "  Ver[%d]: 0x%x",
            (int32_t)i,
            CxPlatByteSwapUint32(ServerVersion));
// arg1 = arg1 = Connection
// arg3 = arg3 = (int32_t)i
// arg4 = arg4 = CxPlatByteSwapUint32(ServerVersion)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_VerNegItem(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, VerNegItem , arg1, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_DeferDatagram



/*----------------------------------------------------------
// Decoder Ring for DeferDatagram
// [conn][%p] Deferring datagram (type=%hu)
// QuicTraceLogConnVerbose(
                    DeferDatagram,
                    Connection,
                    "Deferring datagram (type=%hu)",
                    (uint16_t)Packet->KeyType);
// arg1 = arg1 = Connection
// arg3 = arg3 = (uint16_t)Packet->KeyType
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_DeferDatagram(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, DeferDatagram , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_DecryptOldKey



/*----------------------------------------------------------
// Decoder Ring for DecryptOldKey
// [conn][%p] Using old key to decrypt
// QuicTraceLogConnVerbose(
                DecryptOldKey,
                Connection,
                "Using old key to decrypt");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_DecryptOldKey(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, DecryptOldKey , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_PossiblePeerKeyUpdate



/*----------------------------------------------------------
// Decoder Ring for PossiblePeerKeyUpdate
// [conn][%p] Possible peer initiated key update [packet %llu]
// QuicTraceLogConnVerbose(
                PossiblePeerKeyUpdate,
                Connection,
                "Possible peer initiated key update [packet %llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PossiblePeerKeyUpdate(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, PossiblePeerKeyUpdate , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdateReadKeyPhase



/*----------------------------------------------------------
// Decoder Ring for UpdateReadKeyPhase
// [conn][%p] Updating current read key phase and packet number[%llu]
// QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdateReadKeyPhase(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UpdateReadKeyPhase , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_UpdateReadKeyPhase



/*----------------------------------------------------------
// Decoder Ring for UpdateReadKeyPhase
// [conn][%p] Updating current read key phase and packet number[%llu]
// QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);
// arg1 = arg1 = Connection
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UpdateReadKeyPhase(uniqueId, arg1, encoded_arg_string, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_PeerConnFCBlocked



/*----------------------------------------------------------
// Decoder Ring for PeerConnFCBlocked
// [conn][%p] Peer Connection FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
// arg1 = arg1 = Connection
// arg3 = arg3 = Frame.DataLimit
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PeerConnFCBlocked(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, PeerConnFCBlocked , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_PeerStreamFCBlocked



/*----------------------------------------------------------
// Decoder Ring for PeerStreamFCBlocked
// [conn][%p] Peer Streams[%hu] FC blocked (%llu)
// QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
// arg1 = arg1 = Connection
// arg3 = arg3 = Frame.BidirectionalStreams
// arg4 = arg4 = Frame.StreamLimit
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_PeerStreamFCBlocked(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, PeerStreamFCBlocked , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_IndicatePeerNeedStreams



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerNeedStreams
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS
// QuicTraceLogConnVerbose(
                IndicatePeerNeedStreams,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IndicatePeerNeedStreams(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicatePeerNeedStreams , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_IndicatePeerAddrChanged



/*----------------------------------------------------------
// Decoder Ring for IndicatePeerAddrChanged
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED
// QuicTraceLogConnVerbose(
            IndicatePeerAddrChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_IndicatePeerAddrChanged(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, IndicatePeerAddrChanged , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_UdpRecvBatch



/*----------------------------------------------------------
// Decoder Ring for UdpRecvBatch
// [conn][%p] Batch Recv %u UDP datagrams
// QuicTraceLogConnVerbose(
        UdpRecvBatch,
        Connection,
        "Batch Recv %u UDP datagrams",
        BatchCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = BatchCount
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UdpRecvBatch(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UdpRecvBatch , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_UdpRecvDeferred



/*----------------------------------------------------------
// Decoder Ring for UdpRecvDeferred
// [conn][%p] Recv %u deferred UDP datagrams
// QuicTraceLogConnVerbose(
            UdpRecvDeferred,
            Connection,
            "Recv %u deferred UDP datagrams",
            DatagramChainCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = DatagramChainCount
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UdpRecvDeferred(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UdpRecvDeferred , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_UdpRecv



/*----------------------------------------------------------
// Decoder Ring for UdpRecv
// [conn][%p] Recv %u UDP datagrams
// QuicTraceLogConnVerbose(
            UdpRecv,
            Connection,
            "Recv %u UDP datagrams",
            DatagramChainCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = DatagramChainCount
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_UdpRecv(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, UdpRecv , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_DatagramReceiveEnableUpdated



/*----------------------------------------------------------
// Decoder Ring for DatagramReceiveEnableUpdated
// [conn][%p] Updated datagram receive enabled to %hhu
// QuicTraceLogConnVerbose(
            DatagramReceiveEnableUpdated,
            Connection,
            "Updated datagram receive enabled to %hhu",
            Connection->Settings.DatagramReceiveEnabled);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->Settings.DatagramReceiveEnabled
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_DatagramReceiveEnableUpdated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, DatagramReceiveEnableUpdated , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_Disable1RttEncrytionUpdated



/*----------------------------------------------------------
// Decoder Ring for Disable1RttEncrytionUpdated
// [conn][%p] Updated disable 1-RTT encrytption to %hhu
// QuicTraceLogConnVerbose(
            Disable1RttEncrytionUpdated,
            Connection,
            "Updated disable 1-RTT encrytption to %hhu",
            Connection->State.Disable1RttEncrytion);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->State.Disable1RttEncrytion
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_Disable1RttEncrytionUpdated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CONNECTION_C, Disable1RttEncrytionUpdated , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_ForceKeyUpdate



/*----------------------------------------------------------
// Decoder Ring for ForceKeyUpdate
// [conn][%p] Forcing key update
// QuicTraceLogConnVerbose(
            ForceKeyUpdate,
            Connection,
            "Forcing key update");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ForceKeyUpdate(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ForceKeyUpdate , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_ForceCidUpdate



/*----------------------------------------------------------
// Decoder Ring for ForceCidUpdate
// [conn][%p] Forcing destination CID update
// QuicTraceLogConnVerbose(
            ForceCidUpdate,
            Connection,
            "Forcing destination CID update");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ForceCidUpdate(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, ForceCidUpdate , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_TestTPSet



/*----------------------------------------------------------
// Decoder Ring for TestTPSet
// [conn][%p] Setting Test Transport Parameter (type %hu, %hu bytes)
// QuicTraceLogConnVerbose(
            TestTPSet,
            Connection,
            "Setting Test Transport Parameter (type %hu, %hu bytes)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);
// arg1 = arg1 = Connection
// arg3 = arg3 = Connection->TestTransportParameter.Type
// arg4 = arg4 = Connection->TestTransportParameter.Length
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_TestTPSet(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, TestTPSet , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_AbandonInternallyClosed



/*----------------------------------------------------------
// Decoder Ring for AbandonInternallyClosed
// [conn][%p] Abandoning internal, closed connection
// QuicTraceLogConnVerbose(
            AbandonInternallyClosed,
            Connection,
            "Abandoning internal, closed connection");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_AbandonInternallyClosed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CONNECTION_C, AbandonInternallyClosed , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
// arg2 = arg2 = "connection"
// arg3 = arg3 = sizeof(QUIC_CONNECTION)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnCreated



/*----------------------------------------------------------
// Decoder Ring for ConnCreated
// [conn][%p] Created, IsServer=%hhu, CorrelationId=%llu
// QuicTraceEvent(
        ConnCreated,
        "[conn][%p] Created, IsServer=%hhu, CorrelationId=%llu",
        Connection,
        IsServer,
        Connection->Stats.CorrelationId);
// arg2 = arg2 = Connection
// arg3 = arg3 = IsServer
// arg4 = arg4 = Connection->Stats.CorrelationId
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnCreated(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnCreated , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->LocalAddress), &Path->LocalAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->LocalAddress), &Path->LocalAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnLocalAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, ConnLocalAddrAdded , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnRemoteAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->RemoteAddress), &Path->RemoteAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->RemoteAddress), &Path->RemoteAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnRemoteAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, ConnRemoteAddrAdded , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = Path->DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_C, ConnDestCidAdded , arg2, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnSourceCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
            ConnSourceCidAdded,
            "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
            Connection,
            SourceCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = SourceCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnSourceCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_C, ConnSourceCidAdded , arg2, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
            ConnDestCidAdded,
            "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
            Connection,
            Path->DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = Path->DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(Path->DestCid->CID.Length, Path->DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnInitializeComplete



/*----------------------------------------------------------
// Decoder Ring for ConnInitializeComplete
// [conn][%p] Initialize complete
// QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnInitializeComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnInitializeComplete , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnUnregistered



/*----------------------------------------------------------
// Decoder Ring for ConnUnregistered
// [conn][%p] Unregistered from %p
// QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnUnregistered(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnUnregistered , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnDestroyed



/*----------------------------------------------------------
// Decoder Ring for ConnDestroyed
// [conn][%p] Destroyed
// QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnDestroyed , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnUnregistered



/*----------------------------------------------------------
// Decoder Ring for ConnUnregistered
// [conn][%p] Unregistered from %p
// QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnUnregistered(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnHandleClosed



/*----------------------------------------------------------
// Decoder Ring for ConnHandleClosed
// [conn][%p] Handle closed
// QuicTraceEvent(
        ConnHandleClosed,
        "[conn][%p] Handle closed",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnHandleClosed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnHandleClosed , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnUnregistered



/*----------------------------------------------------------
// Decoder Ring for ConnUnregistered
// [conn][%p] Unregistered from %p
// QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnUnregistered(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnRegistered



/*----------------------------------------------------------
// Decoder Ring for ConnRegistered
// [conn][%p] Registered with %p
// QuicTraceEvent(
        ConnRegistered,
        "[conn][%p] Registered with %p",
        Connection,
        Registration);
// arg2 = arg2 = Connection
// arg3 = arg3 = Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnRegistered(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnRegistered , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "trace rundown operation",
            0);
// arg2 = arg2 = "trace rundown operation"
// arg3 = arg3 = 0
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnRundown



/*----------------------------------------------------------
// Decoder Ring for ConnRundown
// [conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu
// QuicTraceEvent(
        ConnRundown,
        "[conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu",
        Connection,
        QuicConnIsServer(Connection),
        Connection->Stats.CorrelationId);
// arg2 = arg2 = Connection
// arg3 = arg3 = QuicConnIsServer(Connection)
// arg4 = arg4 = Connection->Stats.CorrelationId
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnRundown(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnRundown , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnAssignWorker



/*----------------------------------------------------------
// Decoder Ring for ConnAssignWorker
// [conn][%p] Assigned worker: %p
// QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Connection->Worker);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Worker
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnAssignWorker(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnAssignWorker , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnRegistered



/*----------------------------------------------------------
// Decoder Ring for ConnRegistered
// [conn][%p] Registered with %p
// QuicTraceEvent(
        ConnRegistered,
        "[conn][%p] Registered with %p",
        Connection,
        Connection->Registration);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Registration
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnRegistered(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnVersionSet



/*----------------------------------------------------------
// Decoder Ring for ConnVersionSet
// [conn][%p] QUIC Version: %u
// QuicTraceEvent(
            ConnVersionSet,
            "[conn][%p] QUIC Version: %u",
            Connection,
            Connection->Stats.QuicVersion);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnVersionSet(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnVersionSet , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
                    ConnLocalAddrAdded,
                     "[conn][%p] New Local IP: %!ADDR!",
                    Connection,
                    CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].LocalAddress), &Connection->Paths[i].LocalAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].LocalAddress), &Connection->Paths[i].LocalAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnLocalAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnRemoteAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
                    ConnRemoteAddrAdded,
                    "[conn][%p] New Remote IP: %!ADDR!",
                    Connection,
                    CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].RemoteAddress), &Connection->Paths[i].RemoteAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].RemoteAddress), &Connection->Paths[i].RemoteAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnRemoteAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnSourceCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
                ConnSourceCidAdded,
                "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
                Connection,
                SourceCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = SourceCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnSourceCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                Connection,
                DestCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnHandshakeComplete(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnHandshakeComplete , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnHandleClosed



/*----------------------------------------------------------
// Decoder Ring for ConnHandleClosed
// [conn][%p] Handle closed
// QuicTraceEvent(
            ConnHandleClosed,
            "[conn][%p] Handle closed",
            Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnHandleClosed(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "new Src CID",
                sizeof(QUIC_CID_HASH_ENTRY) + MsQuicLib.CidTotalLength);
// arg2 = arg2 = "new Src CID"
// arg3 = arg3 = sizeof(QUIC_CID_HASH_ENTRY) + MsQuicLib.CidTotalLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Too many CID collisions");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Too many CID collisions"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnError , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnSourceCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
        Connection,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = SourceCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnSourceCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidRemoved



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!
// QuicTraceEvent(
        ConnDestCidRemoved,
        "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
        Connection,
        DestCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CONNECTION_C, ConnDestCidRemoved , arg2, arg3, arg4_len, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Active path has no replacement for retired CID");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Active path has no replacement for retired CID"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnExecTimerOper



/*----------------------------------------------------------
// Decoder Ring for ConnExecTimerOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                QUIC_CONN_TIMER_ACK_DELAY);
// arg2 = arg2 = Connection
// arg3 = arg3 = QUIC_CONN_TIMER_ACK_DELAY
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnExecTimerOper(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnExecTimerOper , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnExecTimerOper



/*----------------------------------------------------------
// Decoder Ring for ConnExecTimerOper
// [conn][%p] Execute: %u
// QuicTraceEvent(
                ConnExecTimerOper,
                "[conn][%p] Execute: %u",
                Connection,
                QUIC_CONN_TIMER_PACING);
// arg2 = arg2 = Connection
// arg3 = arg3 = QUIC_CONN_TIMER_PACING
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnExecTimerOper(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "expired timer operation",
                    0);
// arg2 = arg2 = "expired timer operation"
// arg3 = arg3 = 0
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnShutdownComplete



/*----------------------------------------------------------
// Decoder Ring for ConnShutdownComplete
// [conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.
// QuicTraceEvent(
        ConnShutdownComplete,
        "[conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.",
        Connection,
        Connection->State.ShutdownCompleteTimedOut);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->State.ShutdownCompleteTimedOut
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnShutdownComplete(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CONNECTION_C, ConnShutdownComplete , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "close reason",
                    RemoteReasonPhraseLength + 1);
// arg2 = arg2 = "close reason"
// arg3 = arg3 = RemoteReasonPhraseLength + 1
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnAppShutdown



/*----------------------------------------------------------
// Decoder Ring for ConnAppShutdown
// [conn][%p] App Shutdown: %llu (Remote=%hhu)
// QuicTraceEvent(
                ConnAppShutdown,
                "[conn][%p] App Shutdown: %llu (Remote=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely);
// arg2 = arg2 = Connection
// arg3 = arg3 = ErrorCode
// arg4 = arg4 = ClosedRemotely
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnAppShutdown(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnAppShutdown , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnTransportShutdown



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
// arg2 = arg2 = Connection
// arg3 = arg3 = ErrorCode
// arg4 = arg4 = ClosedRemotely
// arg5 = arg5 = !!(Flags & QUIC_CLOSE_QUIC_STATUS)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnTransportShutdown(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_CONNECTION_C, ConnTransportShutdown , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnVersionSet



/*----------------------------------------------------------
// Decoder Ring for ConnVersionSet
// [conn][%p] QUIC Version: %u
// QuicTraceEvent(
        ConnVersionSet,
        "[conn][%p] QUIC Version: %u",
        Connection,
        Connection->Stats.QuicVersion);
// arg2 = arg2 = Connection
// arg3 = arg3 = Connection->Stats.QuicVersion
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnVersionSet(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection, Status,
                    "Set current compartment Id");
// arg2 = arg2 = Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "Set current compartment Id"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CONNECTION_C, ConnErrorStatus , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnRemoteAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Path->RemoteAddress), &Path->RemoteAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->RemoteAddress), &Path->RemoteAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnRemoteAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnSourceCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidAdded
// [conn][%p] (SeqNum=%llu) New Source CID: %!CID!
// QuicTraceEvent(
        ConnSourceCidAdded,
        "[conn][%p] (SeqNum=%llu) New Source CID: %!CID!",
        Connection,
        SourceCid->CID.SequenceNumber,
        CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = SourceCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(SourceCid->CID.Length, SourceCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnSourceCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
        ConnLocalAddrAdded,
        "[conn][%p] New Local IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Path->LocalAddress), &Path->LocalAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Path->LocalAddress), &Path->LocalAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnLocalAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket transport params greater than current server settings");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Resumption Ticket transport params greater than current server settings"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnServerResumeTicket



/*----------------------------------------------------------
// Decoder Ring for ConnServerResumeTicket
// [conn][%p] Server app accepted resumption ticket
// QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app accepted resumption ticket",
                Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnServerResumeTicket(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnServerResumeTicket , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket rejected by server app");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Resumption Ticket rejected by server app"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "QuicLibraryGenerateStatelessResetToken");
// arg2 = arg2 = Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "QuicLibraryGenerateStatelessResetToken"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "OrigDestCID",
                sizeof(QUIC_CID) + DestCid->CID.Length);
// arg2 = arg2 = "OrigDestCID"
// arg3 = arg3 = sizeof(QUIC_CID) + DestCid->CID.Length
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnHandshakeStart



/*----------------------------------------------------------
// Decoder Ring for ConnHandshakeStart
// [conn][%p] Handshake start
// QuicTraceEvent(
        ConnHandshakeStart,
        "[conn][%p] Handshake start",
        Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnHandshakeStart(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, ConnHandshakeStart , arg2);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer didn't provide the initial source CID in TP");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Peer didn't provide the initial source CID in TP"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Initial source CID from TP doesn't match");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Initial source CID from TP doesn't match"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Server didn't provide the original destination CID in TP");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Server didn't provide the original destination CID in TP"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Original destination CID from TP doesn't match");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Original destination CID from TP doesn't match"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server didn't provide the retry source CID in TP");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Server didn't provide the retry source CID in TP"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server incorrectly provided the retry source CID in TP");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Server incorrectly provided the retry source CID in TP"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Custom cert validation failed.");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Custom cert validation failed."
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Flush Recv operation",
                0);
// arg2 = arg2 = "Flush Recv operation"
// arg3 = arg3 = 0
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Unreachable operation",
            0);
// arg2 = arg2 = "Unreachable operation"
// arg3 = arg3 = 0
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidRemoved



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!
// QuicTraceEvent(
            ConnDestCidRemoved,
            "[conn][%p] (SeqNum=%llu) Removed Destination CID: %!CID!",
            Connection,
            DestCid->CID.SequenceNumber,
            CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
                ConnDestCidAdded,
                "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                Connection,
                DestCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "InitialToken",
            TokenLength);
// arg2 = arg2 = "InitialToken"
// arg3 = arg3 = TokenLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + Token.Encrypted.OrigConnIdLength);
// arg2 = arg2 = "OrigDestCID"
// arg3 = arg3 = sizeof(QUIC_CID) + Token.Encrypted.OrigConnIdLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + Packet->DestCidLen);
// arg2 = arg2 = "OrigDestCID"
// arg3 = arg3 = sizeof(QUIC_CID) + Packet->DestCidLen
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_PacketDecrypt



/*----------------------------------------------------------
// Decoder Ring for PacketDecrypt
// [pack][%llu] Decrypting
// QuicTraceEvent(
        PacketDecrypt,
        "[pack][%llu] Decrypting",
        Packet->PacketId);
// arg2 = arg2 = Packet->PacketId
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_PacketDecrypt(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CONNECTION_C, PacketDecrypt , arg2);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnPacketRecv



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
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1)
// arg5 = arg5 = Packet->HeaderLength + Packet->PayloadLength
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnPacketRecv(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_CONNECTION_C, ConnPacketRecv , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Frame type decode failure");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Frame type decode failure"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unknown frame type");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Unknown frame type"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    (uint32_t)FrameType,
                    "Disallowed frame type");
// arg2 = arg2 = Connection
// arg3 = arg3 = (uint32_t)FrameType
// arg4 = arg4 = "Disallowed frame type"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    (uint32_t)FrameType,
                    "Disallowed frame type");
// arg2 = arg2 = Connection
// arg3 = arg3 = (uint32_t)FrameType
// arg4 = arg4 = "Disallowed frame type"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid ACK frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Invalid ACK frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CRYPTO frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding CRYPTO frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid CRYPTO frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Invalid CRYPTO frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding NEW_TOKEN frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding NEW_TOKEN frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping closed stream frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Skipping closed stream frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding stream ID from frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding stream ID from frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid frame on unidirectional stream");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Invalid frame on unidirectional stream"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid stream frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Invalid stream frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Getting stream from ID");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Getting stream from ID"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping ignored stream frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Skipping ignored stream frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_DATA frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding MAX_DATA frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_STREAMS frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding MAX_STREAMS frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding BLOCKED frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding BLOCKED frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding STREAMS_BLOCKED frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding STREAMS_BLOCKED frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding NEW_CONNECTION_ID frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding NEW_CONNECTION_ID frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "new DestCid",
                        sizeof(QUIC_CID_LIST_ENTRY) + Frame.Length);
// arg2 = arg2 = "new DestCid"
// arg3 = arg3 = sizeof(QUIC_CID_LIST_ENTRY) + Frame.Length
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnDestCidAdded



/*----------------------------------------------------------
// Decoder Ring for ConnDestCidAdded
// [conn][%p] (SeqNum=%llu) New Destination CID: %!CID!
// QuicTraceEvent(
                    ConnDestCidAdded,
                    "[conn][%p] (SeqNum=%llu) New Destination CID: %!CID!",
                    Connection,
                    DestCid->CID.SequenceNumber,
                    CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data));
// arg2 = arg2 = Connection
// arg3 = arg3 = DestCid->CID.SequenceNumber
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(DestCid->CID.Length, DestCid->CID.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnDestCidAdded(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Peer exceeded CID limit");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Peer exceeded CID limit"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding RETIRE_CONNECTION_ID frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding RETIRE_CONNECTION_ID frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Last Source CID Retired!");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Last Source CID Retired!"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_CHALLENGE frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding PATH_CHALLENGE frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_RESPONSE frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding PATH_RESPONSE frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CONNECTION_CLOSE frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding CONNECTION_CLOSE frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Client sent HANDSHAKE_DONE frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Client sent HANDSHAKE_DONE frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received DATAGRAM frame when not negotiated");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Received DATAGRAM frame when not negotiated"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding DATAGRAM frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding DATAGRAM frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding ACK_FREQUENCY frame");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Decoding ACK_FREQUENCY frame"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "UpdateMaxAckDelay is less than TimerResolution");
// arg2 = arg2 = Connection
// arg3 = arg3 = "UpdateMaxAckDelay is less than TimerResolution"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "No unused CID for new path");
// arg2 = arg2 = Connection
// arg3 = arg3 = "No unused CID for new path"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnRemoteAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnRemoteAddrAdded
// [conn][%p] New Remote IP: %!ADDR!
// QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].RemoteAddress), &Connection->Paths[0].RemoteAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].RemoteAddress), &Connection->Paths[0].RemoteAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnRemoteAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].LocalAddress), &Connection->Paths[0].LocalAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].LocalAddress), &Connection->Paths[0].LocalAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnLocalAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrRemoved



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrRemoved
// [conn][%p] Removed Local IP: %!ADDR!
// QuicTraceEvent(
                ConnLocalAddrRemoved,
                "[conn][%p] Removed Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].LocalAddress), &Connection->Paths[0].LocalAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].LocalAddress), &Connection->Paths[0].LocalAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnLocalAddrRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_CONNECTION_C, ConnLocalAddrRemoved , arg2, arg3_len, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnLocalAddrAdded



/*----------------------------------------------------------
// Decoder Ring for ConnLocalAddrAdded
// [conn][%p] New Local IP: %!ADDR!
// QuicTraceEvent(
                ConnLocalAddrAdded,
                "[conn][%p] New Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].LocalAddress), &Connection->Paths[0].LocalAddress));
// arg2 = arg2 = Connection
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].LocalAddress), &Connection->Paths[0].LocalAddress)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnLocalAddrAdded(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus



/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "Forced key update");
// arg2 = arg2 = Connection
// arg3 = arg3 = Status
// arg4 = arg4 = "Forced key update"
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "handshake TP",
                    sizeof(*Connection->HandshakeTP));
// arg2 = arg2 = "handshake TP"
// arg3 = arg3 = sizeof(*Connection->HandshakeTP)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_3_ARGS_TRACE_ConnInitializeComplete



/*----------------------------------------------------------
// Decoder Ring for ConnInitializeComplete
// [conn][%p] Initialize complete
// QuicTraceEvent(
                ConnInitializeComplete,
                "[conn][%p] Initialize complete",
                Connection);
// arg2 = arg2 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_ConnInitializeComplete(uniqueId, encoded_arg_string, arg2)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_connection.c.clog.h.c"
#endif
