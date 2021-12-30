#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_LOSS_DETECTION_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "loss_detection.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_LOSS_DETECTION_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_LOSS_DETECTION_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "loss_detection.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogVerbose
#define _clog_MACRO_QuicTraceLogVerbose  1
#define QuicTraceLogVerbose(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
#ifndef _clog_4_ARGS_TRACE_PacketTxDiscarded



/*----------------------------------------------------------
// Decoder Ring for PacketTxDiscarded
// [%c][TX][%llu] Thrown away on shutdown
// QuicTraceLogVerbose(
                PacketTxDiscarded,
                "[%c][TX][%llu] Thrown away on shutdown",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxDiscarded(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxDiscarded , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTxLostDiscarded



/*----------------------------------------------------------
// Decoder Ring for PacketTxLostDiscarded
// [%c][TX][%llu] Thrown away on shutdown (lost packet)
// QuicTraceLogVerbose(
            PacketTxLostDiscarded,
            "[%c][TX][%llu] Thrown away on shutdown (lost packet)",
            PtkConnPre(Connection),
            Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxLostDiscarded(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxLostDiscarded , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTxForget



/*----------------------------------------------------------
// Decoder Ring for PacketTxForget
// [%c][TX][%llu] Forgetting
// QuicTraceLogVerbose(
                PacketTxForget,
                "[%c][TX][%llu] Forgetting",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxForget(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxForget , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_PacketTxLostFack



/*----------------------------------------------------------
// Decoder Ring for PacketTxLostFack
// [%c][TX][%llu] Lost: FACK %llu packets
// QuicTraceLogVerbose(
                        PacketTxLostFack,
                        "[%c][TX][%llu] Lost: FACK %llu packets",
                        PtkConnPre(Connection),
                        Packet->PacketNumber,
                        LossDetection->LargestAck - Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = LossDetection->LargestAck - Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_PacketTxLostFack(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxLostFack , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_PacketTxLostRack



/*----------------------------------------------------------
// Decoder Ring for PacketTxLostRack
// [%c][TX][%llu] Lost: RACK %lu ms
// QuicTraceLogVerbose(
                        PacketTxLostRack,
                        "[%c][TX][%llu] Lost: RACK %lu ms",
                        PtkConnPre(Connection),
                        Packet->PacketNumber,
                        CxPlatTimeDiff32(Packet->SentTime, TimeNow));
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = CxPlatTimeDiff32(Packet->SentTime, TimeNow)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_PacketTxLostRack(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxLostRack , arg2, arg3, arg4);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTxAckedImplicit



/*----------------------------------------------------------
// Decoder Ring for PacketTxAckedImplicit
// [%c][TX][%llu] ACKed (implicit)
// QuicTraceLogVerbose(
                PacketTxAckedImplicit,
                "[%c][TX][%llu] ACKed (implicit)",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxAckedImplicit(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxAckedImplicit , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTxAckedImplicit



/*----------------------------------------------------------
// Decoder Ring for PacketTxAckedImplicit
// [%c][TX][%llu] ACKed (implicit)
// QuicTraceLogVerbose(
                PacketTxAckedImplicit,
                "[%c][TX][%llu] ACKed (implicit)",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxAckedImplicit(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTx0RttRejected



/*----------------------------------------------------------
// Decoder Ring for PacketTx0RttRejected
// [%c][TX][%llu] Rejected
// QuicTraceLogVerbose(
                PacketTx0RttRejected,
                "[%c][TX][%llu] Rejected",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTx0RttRejected(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTx0RttRejected , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTxSpuriousLoss



/*----------------------------------------------------------
// Decoder Ring for PacketTxSpuriousLoss
// [%c][TX][%llu] Spurious loss detected
// QuicTraceLogVerbose(
                    PacketTxSpuriousLoss,
                    "[%c][TX][%llu] Spurious loss detected",
                    PtkConnPre(Connection),
                    (*End)->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = (*End)->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxSpuriousLoss(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxSpuriousLoss , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_PacketTxAcked



/*----------------------------------------------------------
// Decoder Ring for PacketTxAcked
// [%c][TX][%llu] ACKed (%u.%03u ms)
// QuicTraceLogVerbose(
            PacketTxAcked,
            "[%c][TX][%llu] ACKed (%u.%03u ms)",
            PtkConnPre(Connection),
            Packet->PacketNumber,
            PacketRtt / 1000,
            PacketRtt % 1000);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = PacketRtt / 1000
// arg5 = arg5 = PacketRtt % 1000
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_PacketTxAcked(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxAcked , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_PacketTxProbeRetransmit



/*----------------------------------------------------------
// Decoder Ring for PacketTxProbeRetransmit
// [%c][TX][%llu] Probe Retransmit
// QuicTraceLogVerbose(
                PacketTxProbeRetransmit,
                "[%c][TX][%llu] Probe Retransmit",
                PtkConnPre(Connection),
                Packet->PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = Packet->PacketNumber
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PacketTxProbeRetransmit(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PacketTxProbeRetransmit , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_HandshakeConfirmedAck



/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedAck
// [conn][%p] Handshake confirmed (ack)
// QuicTraceLogConnInfo(
            HandshakeConfirmedAck,
            Connection,
            "Handshake confirmed (ack)");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_HandshakeConfirmedAck(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_LOSS_DETECTION_C, HandshakeConfirmedAck , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_PathMinMtuValidated



/*----------------------------------------------------------
// Decoder Ring for PathMinMtuValidated
// [conn][%p] Path[%hhu] Minimum MTU validated
// QuicTraceLogConnInfo(
                PathMinMtuValidated,
                Connection,
                "Path[%hhu] Minimum MTU validated",
                Path->ID);
// arg1 = arg1 = Connection
// arg3 = arg3 = Path->ID
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PathMinMtuValidated(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PathMinMtuValidated , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_PathValidationTimeout



/*----------------------------------------------------------
// Decoder Ring for PathValidationTimeout
// [conn][%p] Path[%hhu] validation timed out
// QuicTraceLogConnInfo(
                        PathValidationTimeout,
                        Connection,
                        "Path[%hhu] validation timed out",
                        Path->ID);
// arg1 = arg1 = Connection
// arg3 = arg3 = Path->ID
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_PathValidationTimeout(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, PathValidationTimeout , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_ScheduleProbe



/*----------------------------------------------------------
// Decoder Ring for ScheduleProbe
// [conn][%p] probe round %lu
// QuicTraceLogConnInfo(
        ScheduleProbe,
        Connection,
        "probe round %lu",
        LossDetection->ProbeCount);
// arg1 = arg1 = Connection
// arg3 = arg3 = LossDetection->ProbeCount
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ScheduleProbe(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, ScheduleProbe , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_KeyChangeConfirmed



/*----------------------------------------------------------
// Decoder Ring for KeyChangeConfirmed
// [conn][%p] Key change confirmed by peer
// QuicTraceLogConnVerbose(
            KeyChangeConfirmed,
            Connection,
            "Key change confirmed by peer");
// arg1 = arg1 = Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_KeyChangeConfirmed(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_LOSS_DETECTION_C, KeyChangeConfirmed , arg1);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnLossDetectionTimerSet



/*----------------------------------------------------------
// Decoder Ring for ConnLossDetectionTimerSet
// [conn][%p] Setting loss detection %hhu timer for %u ms. (ProbeCount=%hu)
// QuicTraceEvent(
            ConnLossDetectionTimerSet,
            "[conn][%p] Setting loss detection %hhu timer for %u ms. (ProbeCount=%hu)",
            Connection,
            TimeoutType,
            Delay,
            LossDetection->ProbeCount);
// arg2 = arg2 = Connection
// arg3 = arg3 = TimeoutType
// arg4 = arg4 = Delay
// arg5 = arg5 = LossDetection->ProbeCount
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnLossDetectionTimerSet(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_LOSS_DETECTION_C, ConnLossDetectionTimerSet , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Sent packet metadata",
            SIZEOF_QUIC_SENT_PACKET_METADATA(TempSentPacket->FrameCount));
// arg2 = arg2 = "Sent packet metadata"
// arg3 = arg3 = SIZEOF_QUIC_SENT_PACKET_METADATA(TempSentPacket->FrameCount)
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnPacketLost



/*----------------------------------------------------------
// Decoder Ring for ConnPacketLost
// [conn][%p][TX][%llu] %hhu Lost: %hhu
// QuicTraceEvent(
                        ConnPacketLost,
                        "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                        Connection,
                        Packet->PacketNumber,
                        QuicPacketTraceType(Packet),
                        QUIC_TRACE_PACKET_LOSS_FACK);
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Packet)
// arg5 = arg5 = QUIC_TRACE_PACKET_LOSS_FACK
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnPacketLost(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_LOSS_DETECTION_C, ConnPacketLost , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnPacketLost



/*----------------------------------------------------------
// Decoder Ring for ConnPacketLost
// [conn][%p][TX][%llu] %hhu Lost: %hhu
// QuicTraceEvent(
                        ConnPacketLost,
                        "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                        Connection,
                        Packet->PacketNumber,
                        QuicPacketTraceType(Packet),
                        QUIC_TRACE_PACKET_LOSS_RACK);
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Packet)
// arg5 = arg5 = QUIC_TRACE_PACKET_LOSS_RACK
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnPacketLost(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnPacketACKed



/*----------------------------------------------------------
// Decoder Ring for ConnPacketACKed
// [conn][%p][TX][%llu] %hhu ACKed
// QuicTraceEvent(
                ConnPacketACKed,
                "[conn][%p][TX][%llu] %hhu ACKed",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet));
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Packet)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnPacketACKed(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_LOSS_DETECTION_C, ConnPacketACKed , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnPacketACKed



/*----------------------------------------------------------
// Decoder Ring for ConnPacketACKed
// [conn][%p][TX][%llu] %hhu ACKed
// QuicTraceEvent(
                ConnPacketACKed,
                "[conn][%p][TX][%llu] %hhu ACKed",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet));
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Packet)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnPacketACKed(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_4_ARGS_TRACE_ConnError



/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Incorrect ACK encryption level");
// arg2 = arg2 = Connection
// arg3 = arg3 = "Incorrect ACK encryption level"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_LOSS_DETECTION_C, ConnError , arg2, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_ConnPacketACKed



/*----------------------------------------------------------
// Decoder Ring for ConnPacketACKed
// [conn][%p][TX][%llu] %hhu ACKed
// QuicTraceEvent(
            ConnPacketACKed,
            "[conn][%p][TX][%llu] %hhu ACKed",
            Connection,
            Packet->PacketNumber,
            QuicPacketTraceType(Packet));
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Packet)
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_ConnPacketACKed(uniqueId, encoded_arg_string, arg2, arg3, arg4)\

#endif




#ifndef _clog_6_ARGS_TRACE_ConnPacketLost



/*----------------------------------------------------------
// Decoder Ring for ConnPacketLost
// [conn][%p][TX][%llu] %hhu Lost: %hhu
// QuicTraceEvent(
                ConnPacketLost,
                "[conn][%p][TX][%llu] %hhu Lost: %hhu",
                Connection,
                Packet->PacketNumber,
                QuicPacketTraceType(Packet),
                QUIC_TRACE_PACKET_LOSS_PROBE);
// arg2 = arg2 = Connection
// arg3 = arg3 = Packet->PacketNumber
// arg4 = arg4 = QuicPacketTraceType(Packet)
// arg5 = arg5 = QUIC_TRACE_PACKET_LOSS_PROBE
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_ConnPacketLost(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_loss_detection.c.clog.h.c"
#endif
