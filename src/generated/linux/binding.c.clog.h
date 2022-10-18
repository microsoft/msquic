#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_BINDING_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "binding.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_BINDING_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_BINDING_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "binding.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogWarning
#define _clog_MACRO_QuicTraceLogWarning  1
#define QuicTraceLogWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for BindingListenerAlreadyRegistered
// [bind][%p] Listener (%p) already registered on ALPN
// QuicTraceLogWarning(
                BindingListenerAlreadyRegistered,
                "[bind][%p] Listener (%p) already registered on ALPN",
                Binding, ExistingListener);
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = ExistingListener = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_BindingListenerAlreadyRegistered
#define _clog_4_ARGS_TRACE_BindingListenerAlreadyRegistered(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_BINDING_C, BindingListenerAlreadyRegistered , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingSendFailed
// [bind][%p] Send failed, 0x%x
// QuicTraceLogWarning(
                    BindingSendFailed,
                    "[bind][%p] Send failed, 0x%x",
                    Binding,
                    Status);
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Status = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_BindingSendFailed
#define _clog_4_ARGS_TRACE_BindingSendFailed(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_BINDING_C, BindingSendFailed , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PacketTxVersionNegotiation
// [S][TX][-] VN
// QuicTraceLogVerbose(
            PacketTxVersionNegotiation,
            "[S][TX][-] VN");
----------------------------------------------------------*/
#ifndef _clog_2_ARGS_TRACE_PacketTxVersionNegotiation
#define _clog_2_ARGS_TRACE_PacketTxVersionNegotiation(uniqueId, encoded_arg_string)\
tracepoint(CLOG_BINDING_C, PacketTxVersionNegotiation );\

#endif




/*----------------------------------------------------------
// Decoder Ring for PacketTxStatelessReset
// [S][TX][-] SR %s
// QuicTraceLogVerbose(
            PacketTxStatelessReset,
            "[S][TX][-] SR %s",
            QuicCidBufToStr(
                SendDatagram->Buffer + PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
                QUIC_STATELESS_RESET_TOKEN_LENGTH
            ).Buffer);
// arg2 = arg2 = QuicCidBufToStr(
                SendDatagram->Buffer + PacketLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
                QUIC_STATELESS_RESET_TOKEN_LENGTH
            ).Buffer = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PacketTxStatelessReset
#define _clog_3_ARGS_TRACE_PacketTxStatelessReset(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_BINDING_C, PacketTxStatelessReset , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PacketTxRetry
// [S][TX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R OrigDestCid:%s (Token %hu bytes)
// QuicTraceLogVerbose(
            PacketTxRetry,
            "[S][TX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R OrigDestCid:%s (Token %hu bytes)",
            RecvPacket->LH->Version,
            QuicCidBufToStr(RecvPacket->SourceCid, RecvPacket->SourceCidLen).Buffer,
            QuicCidBufToStr(NewDestCid, MsQuicLib.CidTotalLength).Buffer,
            QuicCidBufToStr(RecvPacket->DestCid, RecvPacket->DestCidLen).Buffer,
            (uint16_t)sizeof(Token));
// arg2 = arg2 = RecvPacket->LH->Version = arg2
// arg3 = arg3 = QuicCidBufToStr(RecvPacket->SourceCid, RecvPacket->SourceCidLen).Buffer = arg3
// arg4 = arg4 = QuicCidBufToStr(NewDestCid, MsQuicLib.CidTotalLength).Buffer = arg4
// arg5 = arg5 = QuicCidBufToStr(RecvPacket->DestCid, RecvPacket->DestCidLen).Buffer = arg5
// arg6 = arg6 = (uint16_t)sizeof(Token) = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_PacketTxRetry
#define _clog_7_ARGS_TRACE_PacketTxRetry(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_BINDING_C, PacketTxRetry , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingSendTestDrop
// [bind][%p] Test dropped packet
// QuicTraceLogVerbose(
                BindingSendTestDrop,
                "[bind][%p] Test dropped packet",
                Binding);
// arg2 = arg2 = Binding = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_BindingSendTestDrop
#define _clog_3_ARGS_TRACE_BindingSendTestDrop(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_BINDING_C, BindingSendTestDrop , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_BINDING",
            sizeof(QUIC_BINDING));
// arg2 = arg2 = "QUIC_BINDING" = arg2
// arg3 = arg3 = sizeof(QUIC_BINDING) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_BINDING_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingErrorStatus
// [bind][%p] ERROR, %u, %s.
// QuicTraceEvent(
                BindingErrorStatus,
                "[bind][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set current compartment Id");
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Set current compartment Id" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_BindingErrorStatus
#define _clog_5_ARGS_TRACE_BindingErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_BINDING_C, BindingErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingCreated
// [bind][%p] Created, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!
// QuicTraceEvent(
        BindingCreated,
        "[bind][%p] Created, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!",
        Binding,
        Binding->Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr));
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Binding->Socket = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr) = arg5
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_BindingCreated
#define _clog_8_ARGS_TRACE_BindingCreated(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len, arg5, arg5_len)\
tracepoint(CLOG_BINDING_C, BindingCreated , arg2, arg3, arg4_len, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingCleanup
// [bind][%p] Cleaning up
// QuicTraceEvent(
        BindingCleanup,
        "[bind][%p] Cleaning up",
        Binding);
// arg2 = arg2 = Binding = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_BindingCleanup
#define _clog_3_ARGS_TRACE_BindingCleanup(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_BINDING_C, BindingCleanup , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingDestroyed
// [bind][%p] Destroyed
// QuicTraceEvent(
        BindingDestroyed,
        "[bind][%p] Destroyed",
        Binding);
// arg2 = arg2 = Binding = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_BindingDestroyed
#define _clog_3_ARGS_TRACE_BindingDestroyed(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_BINDING_C, BindingDestroyed , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingRundown
// [bind][%p] Rundown, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!
// QuicTraceEvent(
        BindingRundown,
        "[bind][%p] Rundown, Udp=%p LocalAddr=%!ADDR! RemoteAddr=%!ADDR!",
        Binding,
        Binding->Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr));
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = Binding->Socket = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathLocalAddr), &DatapathLocalAddr) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(DatapathRemoteAddr), &DatapathRemoteAddr) = arg5
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_BindingRundown
#define _clog_8_ARGS_TRACE_BindingRundown(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len, arg5, arg5_len)\
tracepoint(CLOG_BINDING_C, BindingRundown , arg2, arg3, arg4_len, arg4, arg5_len, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnNoListenerIp
// [conn][%p] No Listener for IP address: %!ADDR!
// QuicTraceEvent(
            ConnNoListenerIp,
            "[conn][%p] No Listener for IP address: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(*Addr), Addr));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(*Addr), Addr) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnNoListenerIp
#define _clog_5_ARGS_TRACE_ConnNoListenerIp(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_BINDING_C, ConnNoListenerIp , arg2, arg3_len, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnNoListenerAlpn
// [conn][%p] No listener matching ALPN: %!ALPN!
// QuicTraceEvent(
            ConnNoListenerAlpn,
            "[conn][%p] No listener matching ALPN: %!ALPN!",
            Connection,
            CASTED_CLOG_BYTEARRAY(Info->ClientAlpnListLength, Info->ClientAlpnList));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(Info->ClientAlpnListLength, Info->ClientAlpnList) = arg3
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnNoListenerAlpn
#define _clog_5_ARGS_TRACE_ConnNoListenerAlpn(uniqueId, encoded_arg_string, arg2, arg3, arg3_len)\
tracepoint(CLOG_BINDING_C, ConnNoListenerAlpn , arg2, arg3_len, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "No listener found for connection");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "No listener found for connection" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_BINDING_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingExecOper
// [bind][%p] Execute: %u
// QuicTraceEvent(
        BindingExecOper,
        "[bind][%p] Execute: %u",
        Binding,
        OperationType);
// arg2 = arg2 = Binding = arg2
// arg3 = arg3 = OperationType = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_BindingExecOper
#define _clog_4_ARGS_TRACE_BindingExecOper(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_BINDING_C, BindingExecOper , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for PacketReceive
// [pack][%llu] Received
// QuicTraceEvent(
            PacketReceive,
            "[pack][%llu] Received",
            Packet->PacketId);
// arg2 = arg2 = Packet->PacketId = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_PacketReceive
#define _clog_3_ARGS_TRACE_PacketReceive(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_BINDING_C, PacketReceive , arg2);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_binding.c.clog.h.c"
#endif
