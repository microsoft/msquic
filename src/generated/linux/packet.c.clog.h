#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_PACKET_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "packet.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_PACKET_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_PACKET_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "packet.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
// Decoder Ring for LogPacketVersionNegotiation
// [%c][%cX][-] VerNeg DestCid:%s SrcCid:%s (Payload %hu bytes)
// QuicTraceLogVerbose(
                LogPacketVersionNegotiation,
                "[%c][%cX][-] VerNeg DestCid:%s SrcCid:%s (Payload %hu bytes)",
                PtkConnPre(Connection),
                (uint8_t)PktRxPre(Rx),
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                (uint16_t)(PacketLength - Offset));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = (uint8_t)PktRxPre(Rx) = arg3
// arg4 = arg4 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg4
// arg5 = arg5 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg5
// arg6 = arg6 = (uint16_t)(PacketLength - Offset) = arg6
----------------------------------------------------------*/
#ifndef _clog_7_ARGS_TRACE_LogPacketVersionNegotiation
#define _clog_7_ARGS_TRACE_LogPacketVersionNegotiation(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_PACKET_C, LogPacketVersionNegotiation , arg2, arg3, arg4, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LogPacketVersionNegotiationVersion
// [%c][%cX][-]   Ver:0x%x
// QuicTraceLogVerbose(
                    LogPacketVersionNegotiationVersion,
                    "[%c][%cX][-]   Ver:0x%x",
                    PtkConnPre(Connection),
                    (uint8_t)PktRxPre(Rx),
                    *(uint32_t*)(Packet + Offset));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = (uint8_t)PktRxPre(Rx) = arg3
// arg4 = arg4 = *(uint32_t*)(Packet + Offset) = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_LogPacketVersionNegotiationVersion
#define _clog_5_ARGS_TRACE_LogPacketVersionNegotiationVersion(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_PACKET_C, LogPacketVersionNegotiationVersion , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LogPacketRetry
// [%c][%cX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R (Token %hu bytes)
// QuicTraceLogVerbose(
                    LogPacketRetry,
                    "[%c][%cX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R (Token %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    (uint16_t)(PacketLength - (Offset + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1)));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = LongHdr->Version = arg4
// arg5 = arg5 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg5
// arg6 = arg6 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg6
// arg7 = arg7 = (uint16_t)(PacketLength - (Offset + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1)) = arg7
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_LogPacketRetry
#define _clog_8_ARGS_TRACE_LogPacketRetry(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_PACKET_C, LogPacketRetry , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LogPacketLongHeaderInitial
// [%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:I (Token %hu bytes) (Payload %hu bytes)
// QuicTraceLogVerbose(
                    LogPacketLongHeaderInitial,
                    "[%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:I (Token %hu bytes) (Payload %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    (uint16_t)TokenLength,
                    (uint16_t)Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = LongHdr->Version = arg5
// arg6 = arg6 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg6
// arg7 = arg7 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg7
// arg8 = arg8 = (uint16_t)TokenLength = arg8
// arg9 = arg9 = (uint16_t)Length = arg9
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_LogPacketLongHeaderInitial
#define _clog_10_ARGS_TRACE_LogPacketLongHeaderInitial(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)\
tracepoint(CLOG_PACKET_C, LogPacketLongHeaderInitial , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LogPacketLongHeader
// [%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:%s (Payload %hu bytes)
// QuicTraceLogVerbose(
                    LogPacketLongHeader,
                    "[%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:%s (Payload %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    LongHdr->Version == QUIC_VERSION_2 ?
                        QuicLongHeaderTypeToStringV2(LongHdr->Type) :
                        QuicLongHeaderTypeToStringV1(LongHdr->Type),
                    (uint16_t)Length);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = LongHdr->Version = arg5
// arg6 = arg6 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg6
// arg7 = arg7 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg7
// arg8 = arg8 = LongHdr->Version == QUIC_VERSION_2 ?
                        QuicLongHeaderTypeToStringV2(LongHdr->Type) :
                        QuicLongHeaderTypeToStringV1(LongHdr->Type) = arg8
// arg9 = arg9 = (uint16_t)Length = arg9
----------------------------------------------------------*/
#ifndef _clog_10_ARGS_TRACE_LogPacketLongHeader
#define _clog_10_ARGS_TRACE_LogPacketLongHeader(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9)\
tracepoint(CLOG_PACKET_C, LogPacketLongHeader , arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LogPacketLongHeaderUnsupported
// [%c][%cX][%llu] LH Ver:[UNSUPPORTED,0x%x] DestCid:%s SrcCid:%s
// QuicTraceLogVerbose(
                LogPacketLongHeaderUnsupported,
                "[%c][%cX][%llu] LH Ver:[UNSUPPORTED,0x%x] DestCid:%s SrcCid:%s",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Invariant->LONG_HDR.Version,
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                QuicCidBufToStr(SourceCid, SourceCidLen).Buffer);
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = Invariant->LONG_HDR.Version = arg5
// arg6 = arg6 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg6
// arg7 = arg7 = QuicCidBufToStr(SourceCid, SourceCidLen).Buffer = arg7
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_LogPacketLongHeaderUnsupported
#define _clog_8_ARGS_TRACE_LogPacketLongHeaderUnsupported(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_PACKET_C, LogPacketLongHeaderUnsupported , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




/*----------------------------------------------------------
// Decoder Ring for LogPacketShortHeader
// [%c][%cX][%llu] SH DestCid:%s KP:%hu SB:%hu (Payload %hu bytes)
// QuicTraceLogVerbose(
                LogPacketShortHeader,
                "[%c][%cX][%llu] SH DestCid:%s KP:%hu SB:%hu (Payload %hu bytes)",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                Header->KeyPhase,
                Header->SpinBit,
                (uint16_t)(PacketLength - Offset));
// arg2 = arg2 = PtkConnPre(Connection) = arg2
// arg3 = arg3 = PktRxPre(Rx) = arg3
// arg4 = arg4 = PacketNumber = arg4
// arg5 = arg5 = QuicCidBufToStr(DestCid, DestCidLen).Buffer = arg5
// arg6 = arg6 = Header->KeyPhase = arg6
// arg7 = arg7 = Header->SpinBit = arg7
// arg8 = arg8 = (uint16_t)(PacketLength - Offset) = arg8
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_LogPacketShortHeader
#define _clog_9_ARGS_TRACE_LogPacketShortHeader(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8)\
tracepoint(CLOG_PACKET_C, LogPacketShortHeader , arg2, arg3, arg4, arg5, arg6, arg7, arg8);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RetryPseudoPacket",
            RetryPseudoPacketLength);
// arg2 = arg2 = "RetryPseudoPacket" = arg2
// arg3 = arg3 = RetryPseudoPacketLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_PACKET_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDropPacket
// [conn][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.
// QuicTraceEvent(
            ConnDropPacket,
            "[conn][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg4
// arg5 = arg5 = Reason = arg5
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_ConnDropPacket
#define _clog_8_ARGS_TRACE_ConnDropPacket(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len, arg5)\
tracepoint(CLOG_PACKET_C, ConnDropPacket , arg2, arg3_len, arg3, arg4_len, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingDropPacket
// [bind][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.
// QuicTraceEvent(
            BindingDropPacket,
            "[bind][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg4
// arg5 = arg5 = Reason = arg5
----------------------------------------------------------*/
#ifndef _clog_8_ARGS_TRACE_BindingDropPacket
#define _clog_8_ARGS_TRACE_BindingDropPacket(uniqueId, encoded_arg_string, arg2, arg3, arg3_len, arg4, arg4_len, arg5)\
tracepoint(CLOG_PACKET_C, BindingDropPacket , arg2, arg3_len, arg3, arg4_len, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnDropPacketEx
// [conn][%p] DROP packet Value=%llu Dst=%!ADDR! Src=%!ADDR! Reason=%s.
// QuicTraceEvent(
            ConnDropPacketEx,
            "[conn][%p] DROP packet Value=%llu Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            Value,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = Value = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg5
// arg6 = arg6 = Reason = arg6
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_ConnDropPacketEx
#define _clog_9_ARGS_TRACE_ConnDropPacketEx(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len, arg5, arg5_len, arg6)\
tracepoint(CLOG_PACKET_C, ConnDropPacketEx , arg2, arg3, arg4_len, arg4, arg5_len, arg5, arg6);\

#endif




/*----------------------------------------------------------
// Decoder Ring for BindingDropPacketEx
// [bind][%p] DROP packet %llu. Dst=%!ADDR! Src=%!ADDR! Reason=%s
// QuicTraceEvent(
            BindingDropPacketEx,
            "[bind][%p] DROP packet %llu. Dst=%!ADDR! Src=%!ADDR! Reason=%s",
            Owner,
            Value,
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress),
            Reason);
// arg2 = arg2 = Owner = arg2
// arg3 = arg3 = Value = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->LocalAddress), &Datagram->Route->LocalAddress) = arg4
// arg5 = arg5 = CASTED_CLOG_BYTEARRAY(sizeof(Datagram->Route->RemoteAddress), &Datagram->Route->RemoteAddress) = arg5
// arg6 = arg6 = Reason = arg6
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_BindingDropPacketEx
#define _clog_9_ARGS_TRACE_BindingDropPacketEx(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len, arg5, arg5_len, arg6)\
tracepoint(CLOG_PACKET_C, BindingDropPacketEx , arg2, arg3, arg4_len, arg4, arg5_len, arg5, arg6);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_packet.c.clog.h.c"
#endif
