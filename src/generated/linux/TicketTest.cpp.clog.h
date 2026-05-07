#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TICKETTEST_CPP
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "TicketTest.cpp.clog.h.lttng.h"
#if !defined(DEF_CLOG_TICKETTEST_CPP) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TICKETTEST_CPP
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "TicketTest.cpp.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogInfo
#define _clog_MACRO_QuicTraceLogInfo  1
#define QuicTraceLogInfo(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTpLengthShort
// [test] Attempting to decode Server TP with length %u (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Server TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = s = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTpLengthShort
#define _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTpLengthShort(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTpLengthShort , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTpLengthEncodedWrong
// [test] Attempting to decode Server TP length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTpLengthEncodedWrong,
            "[test] Attempting to decode Server TP length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[5],
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = InputTicketBuffer[5] = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTpLengthEncodedWrong
#define _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTpLengthEncodedWrong(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTpLengthEncodedWrong , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTicketLengthShort
// [test] Attempting to decode Server Ticket with length %u (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTicketLengthShort,
            "[test] Attempting to decode Server Ticket with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(ServerTicket));
// arg2 = arg2 = s = arg2
// arg3 = arg3 = (uint8_t)sizeof(ServerTicket) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTicketLengthShort
#define _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTicketLengthShort(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTicketLengthShort , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ClientResumptionTicketDecodeFailTicketLengthEncodedWrong
// [test] Attempting to decode Server Ticket length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ClientResumptionTicketDecodeFailTicketLengthEncodedWrong,
            "[test] Attempting to decode Server Ticket length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[6],
            (uint8_t)sizeof(ServerTicket));
// arg2 = arg2 = InputTicketBuffer[6] = arg2
// arg3 = arg3 = (uint8_t)sizeof(ServerTicket) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTicketLengthEncodedWrong
#define _clog_4_ARGS_TRACE_ClientResumptionTicketDecodeFailTicketLengthEncodedWrong(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ClientResumptionTicketDecodeFailTicketLengthEncodedWrong , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAlpnLengthShort
// [test] Attempting to decode Negotiated ALPN with length %u (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAlpnLengthShort,
            "[test] Attempting to decode Negotiated ALPN with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(Alpn));
// arg2 = arg2 = s = arg2
// arg3 = arg3 = (uint8_t)sizeof(Alpn) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAlpnLengthShort
#define _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAlpnLengthShort(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAlpnLengthShort , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong
// [test] Attempting to decode Negotiated ALPN length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong,
            "[test] Attempting to decode Negotiated ALPN length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[5],
            (uint8_t)sizeof(Alpn));
// arg2 = arg2 = InputTicketBuffer[5] = arg2
// arg3 = arg3 = (uint8_t)sizeof(Alpn) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong
#define _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAlpnLengthEncodedWrong , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailTpLengthShort
// [test] Attempting to decode Handshake TP with length %u (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthShort,
            "[test] Attempting to decode Handshake TP with length %u (Actual: %u)",
            s,
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = s = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailTpLengthShort
#define _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailTpLengthShort(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailTpLengthShort , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailTpLengthEncodedWrong
// [test] Attempting to decode Handshake TP length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailTpLengthEncodedWrong,
            "[test] Attempting to decode Handshake TP length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[6],
            EncodedTPLength - CxPlatTlsTPHeaderSize);
// arg2 = arg2 = InputTicketBuffer[6] = arg2
// arg3 = arg3 = EncodedTPLength - CxPlatTlsTPHeaderSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailTpLengthEncodedWrong
#define _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailTpLengthEncodedWrong(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailTpLengthEncodedWrong , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAppDataLengthShort
// [test] Attempting to decode App Data with length %u (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAppDataLengthShort,
            "[test] Attempting to decode App Data with length %u (Actual: %u)",
            s,
            (uint8_t)sizeof(AppData));
// arg2 = arg2 = s = arg2
// arg3 = arg3 = (uint8_t)sizeof(AppData) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAppDataLengthShort
#define _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAppDataLengthShort(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAppDataLengthShort , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong
// [test] Attempting to decode App Data length (improperly encoded) %x (Actual: %u)
// QuicTraceLogInfo(
            ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong,
            "[test] Attempting to decode App Data length (improperly encoded) %x (Actual: %u)",
            InputTicketBuffer[7],
            (uint8_t)sizeof(AppData));
// arg2 = arg2 = InputTicketBuffer[7] = arg2
// arg3 = arg3 = (uint8_t)sizeof(AppData) = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong
#define _clog_4_ARGS_TRACE_ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TICKETTEST_CPP, ServerResumptionTicketDecodeFailAppDataLengthEncodedWrong , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_TicketTest.cpp.clog.h.c"
#endif
