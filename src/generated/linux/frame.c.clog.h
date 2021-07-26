#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_FRAME_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "frame.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_FRAME_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_FRAME_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "frame.c.clog.h.lttng.h"
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
#ifndef _clog_6_ARGS_TRACE_FrameLogUnknownType



/*----------------------------------------------------------
// Decoder Ring for FrameLogUnknownType
// [%c][%cX][%llu]   unknown frame (%llu)
// QuicTraceLogVerbose(
            FrameLogUnknownType,
            "[%c][%cX][%llu]   unknown frame (%llu)",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            FrameType);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = FrameType
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogUnknownType(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogUnknownType , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogPadding



/*----------------------------------------------------------
// Decoder Ring for FrameLogPadding
// [%c][%cX][%llu]   PADDING Len:%hu
// QuicTraceLogVerbose(
            FrameLogPadding,
            "[%c][%cX][%llu]   PADDING Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            (uint16_t)((*Offset - Start) + 1));
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = (uint16_t)((*Offset - Start) + 1)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogPadding(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogPadding , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogPing



/*----------------------------------------------------------
// Decoder Ring for FrameLogPing
// [%c][%cX][%llu]   PING
// QuicTraceLogVerbose(
            FrameLogPing,
            "[%c][%cX][%llu]   PING",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogPing(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogPing , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogAckInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckInvalid
// [%c][%cX][%llu]   ACK [Invalid]
// QuicTraceLogVerbose(
                FrameLogAckInvalid,
                "[%c][%cX][%llu]   ACK [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogAckInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogAckInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogAck



/*----------------------------------------------------------
// Decoder Ring for FrameLogAck
// [%c][%cX][%llu]   ACK Largest:%llu Delay:%llu
// QuicTraceLogVerbose(
            FrameLogAck,
            "[%c][%cX][%llu]   ACK Largest:%llu Delay:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.LargestAcknowledged,
            Frame.AckDelay);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.LargestAcknowledged
// arg6 = arg6 = Frame.AckDelay
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogAck(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogAck , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogAckSingleBlock



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckSingleBlock
// [%c][%cX][%llu]     %llu
// QuicTraceLogVerbose(
                FrameLogAckSingleBlock,
                "[%c][%cX][%llu]     %llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.LargestAcknowledged);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.LargestAcknowledged
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogAckSingleBlock(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogAckSingleBlock , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogAckMultiBlock



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckMultiBlock
// [%c][%cX][%llu]     %llu - %llu
// QuicTraceLogVerbose(
                FrameLogAckMultiBlock,
                "[%c][%cX][%llu]     %llu - %llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.LargestAcknowledged - Frame.FirstAckBlock,
                Frame.LargestAcknowledged);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.LargestAcknowledged - Frame.FirstAckBlock
// arg6 = arg6 = Frame.LargestAcknowledged
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogAckMultiBlock(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogAckMultiBlock , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogAckInvalidBlock



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckInvalidBlock
// [%c][%cX][%llu]     [Invalid Block]
// QuicTraceLogVerbose(
                    FrameLogAckInvalidBlock,
                    "[%c][%cX][%llu]     [Invalid Block]",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogAckInvalidBlock(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogAckInvalidBlock , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogAckSingleBlock



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckSingleBlock
// [%c][%cX][%llu]     %llu
// QuicTraceLogVerbose(
                    FrameLogAckSingleBlock,
                    "[%c][%cX][%llu]     %llu",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    Frame.LargestAcknowledged);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.LargestAcknowledged
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogAckSingleBlock(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogAckMultiBlock



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckMultiBlock
// [%c][%cX][%llu]     %llu - %llu
// QuicTraceLogVerbose(
                    FrameLogAckMultiBlock,
                    "[%c][%cX][%llu]     %llu - %llu",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    Frame.LargestAcknowledged - Block.AckBlock,
                    Frame.LargestAcknowledged);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.LargestAcknowledged - Block.AckBlock
// arg6 = arg6 = Frame.LargestAcknowledged
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogAckMultiBlock(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogAckEcnInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckEcnInvalid
// [%c][%cX][%llu]     ECN [Invalid]
// QuicTraceLogVerbose(
                    FrameLogAckEcnInvalid,
                    "[%c][%cX][%llu]     ECN [Invalid]",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogAckEcnInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogAckEcnInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_8_ARGS_TRACE_FrameLogAckEcn



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckEcn
// [%c][%cX][%llu]     ECN [ECT0=%llu,ECT1=%llu,CE=%llu]
// QuicTraceLogVerbose(
                FrameLogAckEcn,
                "[%c][%cX][%llu]     ECN [ECT0=%llu,ECT1=%llu,CE=%llu]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Ecn.ECT_0_Count,
                Ecn.ECT_1_Count,
                Ecn.CE_Count);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Ecn.ECT_0_Count
// arg6 = arg6 = Ecn.ECT_1_Count
// arg7 = arg7 = Ecn.CE_Count
----------------------------------------------------------*/
#define _clog_8_ARGS_TRACE_FrameLogAckEcn(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_FRAME_C, FrameLogAckEcn , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogResetStreamInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogResetStreamInvalid
// [%c][%cX][%llu]   RESET_STREAM [Invalid]
// QuicTraceLogVerbose(
                FrameLogResetStreamInvalid,
                "[%c][%cX][%llu]   RESET_STREAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogResetStreamInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogResetStreamInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_8_ARGS_TRACE_FrameLogResetStream



/*----------------------------------------------------------
// Decoder Ring for FrameLogResetStream
// [%c][%cX][%llu]   RESET_STREAM ID:%llu ErrorCode:0x%llX FinalSize:%llu
// QuicTraceLogVerbose(
            FrameLogResetStream,
            "[%c][%cX][%llu]   RESET_STREAM ID:%llu ErrorCode:0x%llX FinalSize:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.ErrorCode,
            Frame.FinalSize);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.StreamID
// arg6 = arg6 = Frame.ErrorCode
// arg7 = arg7 = Frame.FinalSize
----------------------------------------------------------*/
#define _clog_8_ARGS_TRACE_FrameLogResetStream(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_FRAME_C, FrameLogResetStream , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogStopSendingInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogStopSendingInvalid
// [%c][%cX][%llu]   STOP_SENDING [Invalid]
// QuicTraceLogVerbose(
                FrameLogStopSendingInvalid,
                "[%c][%cX][%llu]   STOP_SENDING [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogStopSendingInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogStopSendingInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogStopSending



/*----------------------------------------------------------
// Decoder Ring for FrameLogStopSending
// [%c][%cX][%llu]   STOP_SENDING ID:%llu Error:0x%llX
// QuicTraceLogVerbose(
            FrameLogStopSending,
            "[%c][%cX][%llu]   STOP_SENDING ID:%llu Error:0x%llX",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.ErrorCode);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.StreamID
// arg6 = arg6 = Frame.ErrorCode
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogStopSending(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogStopSending , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogCryptoInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogCryptoInvalid
// [%c][%cX][%llu]   CRYPTO [Invalid]
// QuicTraceLogVerbose(
                FrameLogCryptoInvalid,
                "[%c][%cX][%llu]   CRYPTO [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogCryptoInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogCryptoInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogCrypto



/*----------------------------------------------------------
// Decoder Ring for FrameLogCrypto
// [%c][%cX][%llu]   CRYPTO Offset:%llu Len:%hu
// QuicTraceLogVerbose(
            FrameLogCrypto,
            "[%c][%cX][%llu]   CRYPTO Offset:%llu Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Offset,
            (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.Offset
// arg6 = arg6 = (uint16_t)Frame.Length
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogCrypto(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogCrypto , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogNewTokenInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewTokenInvalid
// [%c][%cX][%llu]   NEW_TOKEN [Invalid]
// QuicTraceLogVerbose(
                FrameLogNewTokenInvalid,
                "[%c][%cX][%llu]   NEW_TOKEN [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogNewTokenInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogNewTokenInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogNewToken



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewToken
// [%c][%cX][%llu]   NEW_TOKEN Length:%llu
// QuicTraceLogVerbose(
            FrameLogNewToken,
            "[%c][%cX][%llu]   NEW_TOKEN Length:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.TokenLength);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.TokenLength
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogNewToken(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogNewToken , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogStreamInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamInvalid
// [%c][%cX][%llu]   STREAM [Invalid]
// QuicTraceLogVerbose(
                FrameLogStreamInvalid,
                "[%c][%cX][%llu]   STREAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogStreamInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogStreamInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_8_ARGS_TRACE_FrameLogStreamFin



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamFin
// [%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu Fin
// QuicTraceLogVerbose(
                FrameLogStreamFin,
                "[%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu Fin",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.StreamID,
                Frame.Offset,
                (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.StreamID
// arg6 = arg6 = Frame.Offset
// arg7 = arg7 = (uint16_t)Frame.Length
----------------------------------------------------------*/
#define _clog_8_ARGS_TRACE_FrameLogStreamFin(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_FRAME_C, FrameLogStreamFin , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




#ifndef _clog_8_ARGS_TRACE_FrameLogStream



/*----------------------------------------------------------
// Decoder Ring for FrameLogStream
// [%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu
// QuicTraceLogVerbose(
                FrameLogStream,
                "[%c][%cX][%llu]   STREAM ID:%llu Offset:%llu Len:%hu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.StreamID,
                Frame.Offset,
                (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.StreamID
// arg6 = arg6 = Frame.Offset
// arg7 = arg7 = (uint16_t)Frame.Length
----------------------------------------------------------*/
#define _clog_8_ARGS_TRACE_FrameLogStream(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7)\
tracepoint(CLOG_FRAME_C, FrameLogStream , arg2, arg3, arg4, arg5, arg6, arg7);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogMaxDataInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxDataInvalid
// [%c][%cX][%llu]   MAX_DATA [Invalid]
// QuicTraceLogVerbose(
                FrameLogMaxDataInvalid,
                "[%c][%cX][%llu]   MAX_DATA [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogMaxDataInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogMaxDataInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogMaxData



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxData
// [%c][%cX][%llu]   MAX_DATA Max:%llu
// QuicTraceLogVerbose(
            FrameLogMaxData,
            "[%c][%cX][%llu]   MAX_DATA Max:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.MaximumData);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.MaximumData
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogMaxData(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogMaxData , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogMaxStreamDataInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreamDataInvalid
// [%c][%cX][%llu]   MAX_STREAM_DATA [Invalid]
// QuicTraceLogVerbose(
                FrameLogMaxStreamDataInvalid,
                "[%c][%cX][%llu]   MAX_STREAM_DATA [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogMaxStreamDataInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogMaxStreamDataInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogMaxStreamData



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreamData
// [%c][%cX][%llu]   MAX_STREAM_DATA ID:%llu Max:%llu
// QuicTraceLogVerbose(
            FrameLogMaxStreamData,
            "[%c][%cX][%llu]   MAX_STREAM_DATA ID:%llu Max:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.MaximumData);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.StreamID
// arg6 = arg6 = Frame.MaximumData
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogMaxStreamData(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogMaxStreamData , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogMaxStreamsInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreamsInvalid
// [%c][%cX][%llu]   MAX_STREAMS [Invalid]
// QuicTraceLogVerbose(
                FrameLogMaxStreamsInvalid,
                "[%c][%cX][%llu]   MAX_STREAMS [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogMaxStreamsInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogMaxStreamsInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogMaxStreams



/*----------------------------------------------------------
// Decoder Ring for FrameLogMaxStreams
// [%c][%cX][%llu]   MAX_STREAMS[%hu] Count:%llu
// QuicTraceLogVerbose(
            FrameLogMaxStreams,
            "[%c][%cX][%llu]   MAX_STREAMS[%hu] Count:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.BidirectionalStreams,
            Frame.MaximumStreams);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.BidirectionalStreams
// arg6 = arg6 = Frame.MaximumStreams
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogMaxStreams(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogMaxStreams , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogDataBlockedInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogDataBlockedInvalid
// [%c][%cX][%llu]   DATA_BLOCKED [Invalid]
// QuicTraceLogVerbose(
                FrameLogDataBlockedInvalid,
                "[%c][%cX][%llu]   DATA_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogDataBlockedInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogDataBlockedInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogDataBlocked



/*----------------------------------------------------------
// Decoder Ring for FrameLogDataBlocked
// [%c][%cX][%llu]   DATA_BLOCKED Limit:%llu
// QuicTraceLogVerbose(
            FrameLogDataBlocked,
            "[%c][%cX][%llu]   DATA_BLOCKED Limit:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.DataLimit);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.DataLimit
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogDataBlocked(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogDataBlocked , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogStreamDataBlockedInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamDataBlockedInvalid
// [%c][%cX][%llu]   STREAM_DATA_BLOCKED [Invalid]
// QuicTraceLogVerbose(
                FrameLogStreamDataBlockedInvalid,
                "[%c][%cX][%llu]   STREAM_DATA_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogStreamDataBlockedInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogStreamDataBlockedInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogStreamDataBlocked



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamDataBlocked
// [%c][%cX][%llu]   STREAM_DATA_BLOCKED ID:%llu Limit:%llu
// QuicTraceLogVerbose(
            FrameLogStreamDataBlocked,
            "[%c][%cX][%llu]   STREAM_DATA_BLOCKED ID:%llu Limit:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.StreamID,
            Frame.StreamDataLimit);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.StreamID
// arg6 = arg6 = Frame.StreamDataLimit
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogStreamDataBlocked(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogStreamDataBlocked , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogStreamsBlockedInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamsBlockedInvalid
// [%c][%cX][%llu]   STREAMS_BLOCKED [Invalid]
// QuicTraceLogVerbose(
                FrameLogStreamsBlockedInvalid,
                "[%c][%cX][%llu]   STREAMS_BLOCKED [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogStreamsBlockedInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogStreamsBlockedInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogStreamsBlocked



/*----------------------------------------------------------
// Decoder Ring for FrameLogStreamsBlocked
// [%c][%cX][%llu]   STREAMS_BLOCKED[%hu] ID:%llu
// QuicTraceLogVerbose(
            FrameLogStreamsBlocked,
            "[%c][%cX][%llu]   STREAMS_BLOCKED[%hu] ID:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.BidirectionalStreams,
            Frame.StreamLimit);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.BidirectionalStreams
// arg6 = arg6 = Frame.StreamLimit
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogStreamsBlocked(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogStreamsBlocked , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogNewConnectionIDInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewConnectionIDInvalid
// [%c][%cX][%llu]   NEW_CONN_ID [Invalid]
// QuicTraceLogVerbose(
                FrameLogNewConnectionIDInvalid,
                "[%c][%cX][%llu]   NEW_CONN_ID [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogNewConnectionIDInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogNewConnectionIDInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_9_ARGS_TRACE_FrameLogNewConnectionID



/*----------------------------------------------------------
// Decoder Ring for FrameLogNewConnectionID
// [%c][%cX][%llu]   NEW_CONN_ID Seq:%llu RPT:%llu CID:%s Token:%s
// QuicTraceLogVerbose(
            FrameLogNewConnectionID,
            "[%c][%cX][%llu]   NEW_CONN_ID Seq:%llu RPT:%llu CID:%s Token:%s",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Sequence,
            Frame.RetirePriorTo,
            QuicCidBufToStr(Frame.Buffer, Frame.Length).Buffer,
            QuicCidBufToStr(Frame.Buffer + Frame.Length, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.Sequence
// arg6 = arg6 = Frame.RetirePriorTo
// arg7 = arg7 = QuicCidBufToStr(Frame.Buffer, Frame.Length).Buffer
// arg8 = arg8 = QuicCidBufToStr(Frame.Buffer + Frame.Length, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer
----------------------------------------------------------*/
#define _clog_9_ARGS_TRACE_FrameLogNewConnectionID(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8)\
tracepoint(CLOG_FRAME_C, FrameLogNewConnectionID , arg2, arg3, arg4, arg5, arg6, arg7, arg8);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogRetireConnectionIDInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogRetireConnectionIDInvalid
// [%c][%cX][%llu]   RETIRE_CONN_ID [Invalid]
// QuicTraceLogVerbose(
                FrameLogRetireConnectionIDInvalid,
                "[%c][%cX][%llu]   RETIRE_CONN_ID [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogRetireConnectionIDInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogRetireConnectionIDInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogRetireConnectionID



/*----------------------------------------------------------
// Decoder Ring for FrameLogRetireConnectionID
// [%c][%cX][%llu]   RETIRE_CONN_ID Seq:%llu
// QuicTraceLogVerbose(
            FrameLogRetireConnectionID,
            "[%c][%cX][%llu]   RETIRE_CONN_ID Seq:%llu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.Sequence);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.Sequence
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogRetireConnectionID(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogRetireConnectionID , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogPathChallengeInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathChallengeInvalid
// [%c][%cX][%llu]   PATH_CHALLENGE [Invalid]
// QuicTraceLogVerbose(
                FrameLogPathChallengeInvalid,
                "[%c][%cX][%llu]   PATH_CHALLENGE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogPathChallengeInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogPathChallengeInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogPathChallenge



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathChallenge
// [%c][%cX][%llu]   PATH_CHALLENGE [%llu]
// QuicTraceLogVerbose(
            FrameLogPathChallenge,
            "[%c][%cX][%llu]   PATH_CHALLENGE [%llu]",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            CxPlatByteSwapUint64(*(uint64_t*)Frame.Data));
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = CxPlatByteSwapUint64(*(uint64_t*)Frame.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogPathChallenge(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogPathChallenge , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogPathResponseInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathResponseInvalid
// [%c][%cX][%llu]   PATH_RESPONSE [Invalid]
// QuicTraceLogVerbose(
                FrameLogPathResponseInvalid,
                "[%c][%cX][%llu]   PATH_RESPONSE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogPathResponseInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogPathResponseInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogPathResponse



/*----------------------------------------------------------
// Decoder Ring for FrameLogPathResponse
// [%c][%cX][%llu]   PATH_RESPONSE [%llu]
// QuicTraceLogVerbose(
            FrameLogPathResponse,
            "[%c][%cX][%llu]   PATH_RESPONSE [%llu]",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            CxPlatByteSwapUint64(*(uint64_t*)Frame.Data));
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = CxPlatByteSwapUint64(*(uint64_t*)Frame.Data)
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogPathResponse(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogPathResponse , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogConnectionCloseInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogConnectionCloseInvalid
// [%c][%cX][%llu]   CONN_CLOSE [Invalid]
// QuicTraceLogVerbose(
                FrameLogConnectionCloseInvalid,
                "[%c][%cX][%llu]   CONN_CLOSE [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogConnectionCloseInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogConnectionCloseInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogConnectionCloseApp



/*----------------------------------------------------------
// Decoder Ring for FrameLogConnectionCloseApp
// [%c][%cX][%llu]   CONN_CLOSE (App) ErrorCode:0x%llX
// QuicTraceLogVerbose(
                FrameLogConnectionCloseApp,
                "[%c][%cX][%llu]   CONN_CLOSE (App) ErrorCode:0x%llX",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.ErrorCode);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.ErrorCode
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogConnectionCloseApp(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogConnectionCloseApp , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_7_ARGS_TRACE_FrameLogConnectionClose



/*----------------------------------------------------------
// Decoder Ring for FrameLogConnectionClose
// [%c][%cX][%llu]   CONN_CLOSE ErrorCode:0x%llX FrameType:%llu
// QuicTraceLogVerbose(
                FrameLogConnectionClose,
                "[%c][%cX][%llu]   CONN_CLOSE ErrorCode:0x%llX FrameType:%llu",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Frame.ErrorCode,
                Frame.FrameType);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.ErrorCode
// arg6 = arg6 = Frame.FrameType
----------------------------------------------------------*/
#define _clog_7_ARGS_TRACE_FrameLogConnectionClose(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6)\
tracepoint(CLOG_FRAME_C, FrameLogConnectionClose , arg2, arg3, arg4, arg5, arg6);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogHandshakeDone



/*----------------------------------------------------------
// Decoder Ring for FrameLogHandshakeDone
// [%c][%cX][%llu]   HANDSHAKE_DONE
// QuicTraceLogVerbose(
            FrameLogHandshakeDone,
            "[%c][%cX][%llu]   HANDSHAKE_DONE",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogHandshakeDone(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogHandshakeDone , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogDatagramInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogDatagramInvalid
// [%c][%cX][%llu]   DATAGRAM [Invalid]
// QuicTraceLogVerbose(
                FrameLogDatagramInvalid,
                "[%c][%cX][%llu]   DATAGRAM [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogDatagramInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogDatagramInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_6_ARGS_TRACE_FrameLogDatagram



/*----------------------------------------------------------
// Decoder Ring for FrameLogDatagram
// [%c][%cX][%llu]   DATAGRAM Len:%hu
// QuicTraceLogVerbose(
            FrameLogDatagram,
            "[%c][%cX][%llu]   DATAGRAM Len:%hu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            (uint16_t)Frame.Length);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = (uint16_t)Frame.Length
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_FrameLogDatagram(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5)\
tracepoint(CLOG_FRAME_C, FrameLogDatagram , arg2, arg3, arg4, arg5);\

#endif




#ifndef _clog_5_ARGS_TRACE_FrameLogAckFrequencyInvalid



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckFrequencyInvalid
// [%c][%cX][%llu]   ACK_FREQUENCY [Invalid]
// QuicTraceLogVerbose(
                FrameLogAckFrequencyInvalid,
                "[%c][%cX][%llu]   ACK_FREQUENCY [Invalid]",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_FrameLogAckFrequencyInvalid(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_FRAME_C, FrameLogAckFrequencyInvalid , arg2, arg3, arg4);\

#endif




#ifndef _clog_9_ARGS_TRACE_FrameLogAckFrequency



/*----------------------------------------------------------
// Decoder Ring for FrameLogAckFrequency
// [%c][%cX][%llu]   ACK_FREQUENCY SeqNum:%llu PktTolerance:%llu MaxAckDelay:%llu IgnoreOrder:%hhu
// QuicTraceLogVerbose(
            FrameLogAckFrequency,
            "[%c][%cX][%llu]   ACK_FREQUENCY SeqNum:%llu PktTolerance:%llu MaxAckDelay:%llu IgnoreOrder:%hhu",
            PtkConnPre(Connection),
            PktRxPre(Rx),
            PacketNumber,
            Frame.SequenceNumber,
            Frame.PacketTolerance,
            Frame.UpdateMaxAckDelay,
            Frame.IgnoreOrder);
// arg2 = arg2 = PtkConnPre(Connection)
// arg3 = arg3 = PktRxPre(Rx)
// arg4 = arg4 = PacketNumber
// arg5 = arg5 = Frame.SequenceNumber
// arg6 = arg6 = Frame.PacketTolerance
// arg7 = arg7 = Frame.UpdateMaxAckDelay
// arg8 = arg8 = Frame.IgnoreOrder
----------------------------------------------------------*/
#define _clog_9_ARGS_TRACE_FrameLogAckFrequency(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg5, arg6, arg7, arg8)\
tracepoint(CLOG_FRAME_C, FrameLogAckFrequency , arg2, arg3, arg4, arg5, arg6, arg7, arg8);\

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
tracepoint(CLOG_FRAME_C, ConnError , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_frame.c.clog.h.c"
#endif

