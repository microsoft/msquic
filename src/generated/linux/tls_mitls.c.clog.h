#include <clog.h>
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_TLS_MITLS_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "tls_mitls.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_TLS_MITLS_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_TLS_MITLS_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "tls_mitls.c.clog.h.lttng.h"
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
#ifndef _clog_2_ARGS_TRACE_miTlsInitialize



/*----------------------------------------------------------
// Decoder Ring for miTlsInitialize
// [ tls] Initializing miTLS library
// QuicTraceLogVerbose(
        miTlsInitialize,
        "[ tls] Initializing miTLS library");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_miTlsInitialize(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsInitialize );\

#endif




#ifndef _clog_2_ARGS_TRACE_miTlsUninitialize



/*----------------------------------------------------------
// Decoder Ring for miTlsUninitialize
// [ tls] Cleaning up miTLS library
// QuicTraceLogVerbose(
        miTlsUninitialize,
        "[ tls] Cleaning up miTLS library");
----------------------------------------------------------*/
#define _clog_2_ARGS_TRACE_miTlsUninitialize(uniqueId, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsUninitialize );\

#endif




#ifndef _clog_5_ARGS_TRACE_miTlsLogSecret



/*----------------------------------------------------------
// Decoder Ring for miTlsLogSecret
// [ tls] %s[%u]: %s
// QuicTraceLogVerbose(
        miTlsLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
// arg2 = arg2 = Prefix
// arg3 = arg3 = Length
// arg4 = arg4 = SecretStr
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_miTlsLogSecret(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_TLS_MITLS_C, miTlsLogSecret , arg2, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_miTlsFfiProcessFailed



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProcessFailed
// [conn][%p] FFI_mitls_quic_process failed, tls_error %hu, %s
// QuicTraceLogConnError(
                miTlsFfiProcessFailed,
                TlsContext->Connection,
                "FFI_mitls_quic_process failed, tls_error %hu, %s",
                Context.tls_error,
                Context.tls_error_desc);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = Context.tls_error
// arg4 = arg4 = Context.tls_error_desc
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_miTlsFfiProcessFailed(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_MITLS_C, miTlsFfiProcessFailed , arg1, arg3, arg4);\

#endif




#ifndef _clog_5_ARGS_TRACE_miTlsFfiGetHelloSummaryFailed



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiGetHelloSummaryFailed
// [conn][%p] FFI_mitls_get_hello_summary failed, cookie_len: %zu, ticket_len: %zu
// QuicTraceLogConnError(
                            miTlsFfiGetHelloSummaryFailed,
                            TlsContext->Connection,
                            "FFI_mitls_get_hello_summary failed, cookie_len: %zu, ticket_len: %zu",
                            CookieLen,
                            TicketLen);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = CookieLen
// arg4 = arg4 = TicketLen
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_miTlsFfiGetHelloSummaryFailed(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_MITLS_C, miTlsFfiGetHelloSummaryFailed , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsCertValidationDisabled



/*----------------------------------------------------------
// Decoder Ring for miTlsCertValidationDisabled
// [conn][%p] Certificate validation disabled!
// QuicTraceLogConnWarning(
            miTlsCertValidationDisabled,
            TlsContext->Connection,
            "Certificate validation disabled!");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsCertValidationDisabled(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsCertValidationDisabled , arg1);\

#endif




#ifndef _clog_5_ARGS_TRACE_miTlsCertSelected



/*----------------------------------------------------------
// Decoder Ring for miTlsCertSelected
// [conn][%p] Server certificate selected. SNI: %s; Algorithm: 0x%4.4x
// QuicTraceLogConnInfo(
        miTlsCertSelected,
        TlsContext->Connection,
        "Server certificate selected. SNI: %s; Algorithm: 0x%4.4x",
        TlsContext->SNI,
        *SelectedSignature);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsContext->SNI
// arg4 = arg4 = *SelectedSignature
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_miTlsCertSelected(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_MITLS_C, miTlsCertSelected , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsUsing0Rtt



/*----------------------------------------------------------
// Decoder Ring for miTlsUsing0Rtt
// [conn][%p] Using 0-RTT ticket.
// QuicTraceLogConnVerbose(
                    miTlsUsing0Rtt,
                    TlsContext->Connection,
                    "Using 0-RTT ticket.");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsUsing0Rtt(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsUsing0Rtt , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTlsProcess



/*----------------------------------------------------------
// Decoder Ring for miTlsProcess
// [conn][%p] Processing %u bytes
// QuicTraceLogConnVerbose(
                miTlsProcess,
                TlsContext->Connection,
                "Processing %u bytes",
                *BufferLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = *BufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTlsProcess(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTlsProcess , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsSend0RttTicket



/*----------------------------------------------------------
// Decoder Ring for miTlsSend0RttTicket
// [conn][%p] Sending 0-RTT ticket
// QuicTraceLogConnVerbose(
            miTlsSend0RttTicket,
            TlsContext->Connection,
            "Sending 0-RTT ticket");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsSend0RttTicket(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsSend0RttTicket , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTlsFfiProces



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProces
// [conn][%p] FFI_mitls_quic_process processing %u input bytes
// QuicTraceLogConnVerbose(
            miTlsFfiProces,
            TlsContext->Connection,
            "FFI_mitls_quic_process processing %u input bytes",
            (uint32_t)Context.input_len);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Context.input_len
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTlsFfiProces(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTlsFfiProces , arg1, arg3);\

#endif




#ifndef _clog_5_ARGS_TRACE_miTlsFfiProcessResult



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProcessResult
// [conn][%p] FFI_mitls_quic_process read %u bytes and has %u bytes ready to send
// QuicTraceLogConnVerbose(
            miTlsFfiProcessResult,
            TlsContext->Connection,
            "FFI_mitls_quic_process read %u bytes and has %u bytes ready to send",
            (uint32_t)Context.consumed_bytes,
            (uint32_t)Context.output_len);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Context.consumed_bytes
// arg4 = arg4 = (uint32_t)Context.output_len
----------------------------------------------------------*/
#define _clog_5_ARGS_TRACE_miTlsFfiProcessResult(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_TLS_MITLS_C, miTlsFfiProcessResult , arg1, arg3, arg4);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsHandshakeComplete



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeComplete
// [conn][%p] Handshake complete
// QuicTraceLogConnVerbose(
                miTlsHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsHandshakeComplete(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsHandshakeComplete , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsEarlyDataRejected



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataRejected
// [conn][%p] Early data rejected
// QuicTraceLogConnVerbose(
                miTlsEarlyDataRejected,
                TlsContext->Connection,
                "Early data rejected");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsEarlyDataRejected(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsEarlyDataRejected , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsEarlyDataAccepted



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataAccepted
// [conn][%p] Early data accepted
// QuicTraceLogConnVerbose(
                        miTlsEarlyDataAccepted,
                        TlsContext->Connection,
                        "Early data accepted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsEarlyDataAccepted(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsEarlyDataAccepted , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsEarlyDataNotAttempted



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataNotAttempted
// [conn][%p] Early data not attempted
// QuicTraceLogConnVerbose(
                            miTlsEarlyDataNotAttempted,
                            TlsContext->Connection,
                            "Early data not attempted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsEarlyDataNotAttempted(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsEarlyDataNotAttempted , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsEarlyDataAttempted



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataAttempted
// [conn][%p] Early data attempted
// QuicTraceLogConnVerbose(
                        miTlsEarlyDataAttempted,
                        TlsContext->Connection,
                        "Early data attempted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsEarlyDataAttempted(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsEarlyDataAttempted , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTlsKeySchedule



/*----------------------------------------------------------
// Decoder Ring for miTlsKeySchedule
// [conn][%p] Key schedule = %hu
// QuicTraceLogConnVerbose(
                miTlsKeySchedule,
                TlsContext->Connection,
                "Key schedule = %hu",
                TlsContext->TlsKeySchedule);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = TlsContext->TlsKeySchedule
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTlsKeySchedule(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTlsKeySchedule , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTls0RttReadKeyExported



/*----------------------------------------------------------
// Decoder Ring for miTls0RttReadKeyExported
// [conn][%p] 0-RTT read key exported
// QuicTraceLogConnVerbose(
                        miTls0RttReadKeyExported,
                        TlsContext->Connection,
                        "0-RTT read key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTls0RttReadKeyExported(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTls0RttReadKeyExported , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsHandshakeReadKeyExported



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeReadKeyExported
// [conn][%p] Handshake read key exported
// QuicTraceLogConnVerbose(
                        miTlsHandshakeReadKeyExported,
                        TlsContext->Connection,
                        "Handshake read key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsHandshakeReadKeyExported(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsHandshakeReadKeyExported , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTls1RttReadKeyExported



/*----------------------------------------------------------
// Decoder Ring for miTls1RttReadKeyExported
// [conn][%p] 1-RTT read key exported
// QuicTraceLogConnVerbose(
                        miTls1RttReadKeyExported,
                        TlsContext->Connection,
                        "1-RTT read key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTls1RttReadKeyExported(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTls1RttReadKeyExported , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsEarlyDataAccepted



/*----------------------------------------------------------
// Decoder Ring for miTlsEarlyDataAccepted
// [conn][%p] Early data accepted
// QuicTraceLogConnVerbose(
                                miTlsEarlyDataAccepted,
                                TlsContext->Connection,
                                "Early data accepted");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsEarlyDataAccepted(uniqueId, arg1, encoded_arg_string)\

#endif




#ifndef _clog_3_ARGS_TRACE_miTls0RttWriteKeyExported



/*----------------------------------------------------------
// Decoder Ring for miTls0RttWriteKeyExported
// [conn][%p] 0-RTT write key exported
// QuicTraceLogConnVerbose(
                        miTls0RttWriteKeyExported,
                        TlsContext->Connection,
                        "0-RTT write key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTls0RttWriteKeyExported(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTls0RttWriteKeyExported , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsHandshakeWriteKeyExported



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeWriteKeyExported
// [conn][%p] Handshake write key exported
// QuicTraceLogConnVerbose(
                        miTlsHandshakeWriteKeyExported,
                        TlsContext->Connection,
                        "Handshake write key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsHandshakeWriteKeyExported(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsHandshakeWriteKeyExported , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTls1RttWriteKeyExported



/*----------------------------------------------------------
// Decoder Ring for miTls1RttWriteKeyExported
// [conn][%p] 1-RTT write key exported
// QuicTraceLogConnVerbose(
                        miTls1RttWriteKeyExported,
                        TlsContext->Connection,
                        "1-RTT write key exported");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTls1RttWriteKeyExported(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTls1RttWriteKeyExported , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTlsHandshakeWriteOffsetSet



/*----------------------------------------------------------
// Decoder Ring for miTlsHandshakeWriteOffsetSet
// [conn][%p] Handshake write offset = %u
// QuicTraceLogConnVerbose(
                    miTlsHandshakeWriteOffsetSet,
                    TlsContext->Connection,
                    "Handshake write offset = %u",
                    State->BufferOffsetHandshake);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffsetHandshake
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTlsHandshakeWriteOffsetSet(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTlsHandshakeWriteOffsetSet , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTls1RttWriteOffsetSet



/*----------------------------------------------------------
// Decoder Ring for miTls1RttWriteOffsetSet
// [conn][%p] 1-RTT write offset = %u
// QuicTraceLogConnVerbose(
                    miTls1RttWriteOffsetSet,
                    TlsContext->Connection,
                    "1-RTT write offset = %u",
                    State->BufferOffset1Rtt);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = State->BufferOffset1Rtt
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTls1RttWriteOffsetSet(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTls1RttWriteOffsetSet , arg1, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTlsFfiProcesComplete



/*----------------------------------------------------------
// Decoder Ring for miTlsFfiProcesComplete
// [conn][%p] Consumed %u bytes
// QuicTraceLogConnVerbose(
        miTlsFfiProcesComplete,
        TlsContext->Connection,
        "Consumed %u bytes",
        BufferOffset);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = BufferOffset
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTlsFfiProcesComplete(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTlsFfiProcesComplete , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsOnCertSelect



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertSelect
// [conn][%p] OnCertSelect
// QuicTraceLogConnVerbose(
        miTlsOnCertSelect,
        TlsContext->Connection,
        "OnCertSelect");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsOnCertSelect(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsOnCertSelect , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsOnNegotiate



/*----------------------------------------------------------
// Decoder Ring for miTlsOnNegotiate
// [conn][%p] OnNegotiate
// QuicTraceLogConnVerbose(
        miTlsOnNegotiate,
        TlsContext->Connection,
        "OnNegotiate");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsOnNegotiate(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsOnNegotiate , arg1);\

#endif




#ifndef _clog_4_ARGS_TRACE_miTlsProcessServerAlpn



/*----------------------------------------------------------
// Decoder Ring for miTlsProcessServerAlpn
// [conn][%p] Processing server ALPN (Length=%u)
// QuicTraceLogConnVerbose(
            miTlsProcessServerAlpn,
            TlsContext->Connection,
            "Processing server ALPN (Length=%u)",
            (uint32_t)ExtensionDataLength);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)ExtensionDataLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_miTlsProcessServerAlpn(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_TLS_MITLS_C, miTlsProcessServerAlpn , arg1, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsOnCertFormat



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertFormat
// [conn][%p] OnCertFormat
// QuicTraceLogConnVerbose(
        miTlsOnCertFormat,
        TlsContext->Connection,
        "OnCertFormat");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsOnCertFormat(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsOnCertFormat , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsOnCertSign



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertSign
// [conn][%p] OnCertSign
// QuicTraceLogConnVerbose(
        miTlsOnCertSign,
        TlsContext->Connection,
        "OnCertSign");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsOnCertSign(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsOnCertSign , arg1);\

#endif




#ifndef _clog_3_ARGS_TRACE_miTlsOnCertVerify



/*----------------------------------------------------------
// Decoder Ring for miTlsOnCertVerify
// [conn][%p] OnCertVerify
// QuicTraceLogConnVerbose(
        miTlsOnCertVerify,
        TlsContext->Connection,
        "OnCertVerify");
// arg1 = arg1 = TlsContext->Connection
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_miTlsOnCertVerify(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_TLS_MITLS_C, miTlsOnCertVerify , arg1);\

#endif




#ifndef _clog_6_ARGS_TRACE_miTlsRecvNewSessionTicket



/*----------------------------------------------------------
// Decoder Ring for miTlsRecvNewSessionTicket
// [conn][%p] Received new ticket. ticket_len:%u session_len:%u for %s
// QuicTraceLogConnVerbose(
        miTlsRecvNewSessionTicket,
        TlsContext->Connection,
        "Received new ticket. ticket_len:%u session_len:%u for %s",
        (uint32_t)Ticket->ticket_len,
        (uint32_t)Ticket->session_len,
        ServerNameIndication);
// arg1 = arg1 = TlsContext->Connection
// arg3 = arg3 = (uint32_t)Ticket->ticket_len
// arg4 = arg4 = (uint32_t)Ticket->session_len
// arg5 = arg5 = ServerNameIndication
----------------------------------------------------------*/
#define _clog_6_ARGS_TRACE_miTlsRecvNewSessionTicket(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_TLS_MITLS_C, miTlsRecvNewSessionTicket , arg1, arg3, arg4, arg5);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsMessage



/*----------------------------------------------------------
// Decoder Ring for TlsMessage
// [ tls][%p] %s
// QuicTraceEvent(
        TlsMessage,
        "[ tls][%p] %s",
        TlsGetValue(miTlsCurrentConnectionIndex),
        Msg);
// arg2 = arg2 = TlsGetValue(miTlsCurrentConnectionIndex)
// arg3 = arg3 = Msg
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsMessage(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_MITLS_C, TlsMessage , arg2, arg3);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "FFI_mitls_init failed");
// arg2 = arg2 = "FFI_mitls_init failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_TLS_MITLS_C, LibraryError , arg2);\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "FFI_mitls_set_sealing_key failed");
// arg2 = arg2 = "FFI_mitls_set_sealing_key failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "FFI_mitls_set_ticket_key failed");
// arg2 = arg2 = "FFI_mitls_set_ticket_key failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "FFI_mitls_set_sealing_key failed");
// arg2 = arg2 = "FFI_mitls_set_sealing_key failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_3_ARGS_TRACE_LibraryError



/*----------------------------------------------------------
// Decoder Ring for LibraryError
// [ lib] ERROR, %s.
// QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "FFI_mitls_set_ticket_key failed");
// arg2 = arg2 = "FFI_mitls_set_ticket_key failed"
----------------------------------------------------------*/
#define _clog_3_ARGS_TRACE_LibraryError(uniqueId, encoded_arg_string, arg2)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS",
            sizeof(QUIC_TLS) + sizeof(uint16_t) + Config->AlpnBufferLength);
// arg2 = arg2 = "QUIC_TLS"
// arg3 = arg3 = sizeof(QUIC_TLS) + sizeof(uint16_t) + Config->AlpnBufferLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_MITLS_C, AllocFailure , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SNI Too Long"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_TLS_MITLS_C, TlsError , arg2, arg3);\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "SNI",
                    ServerNameLength + 1);
// arg2 = arg2 = "SNI"
// arg3 = arg3 = ServerNameLength + 1
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "0-RTT ticket is corrupt");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "0-RTT ticket is corrupt"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "FFI_mitls_quic_create failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "FFI_mitls_quic_create failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "TLS buffer too big");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "TLS buffer too big"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "FFI_mitls_quic_send_ticket failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "FFI_mitls_quic_send_ticket failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported TLS version");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported TLS version"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SNI too long");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "SNI too long"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "SNI",
                ServerNameIndicationLength + 1);
// arg2 = arg2 = "SNI"
// arg3 = arg3 = ServerNameIndicationLength + 1
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "QuicCertSelect failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "QuicCertSelect failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported TLS version");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported TLS version"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Missing ALPN extension");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Missing ALPN extension"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ALPN extension length is too short");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "ALPN extension length is too short"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ALPN list length is incorrect");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "ALPN list length is incorrect"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ALPN length is incorrect");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "ALPN length is incorrect"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Failed to find a matching ALPN");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Failed to find a matching ALPN"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Missing QUIC transport parameters");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Missing QUIC transport parameters"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Failed to process the QUIC transport parameters");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Failed to process the QUIC transport parameters"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "QuicCertParseChain failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "QuicCertParseChain failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Cert chain validation failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Cert chain validation failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS_TICKET",
            TotalSize);
// arg2 = arg2 = "QUIC_TLS_TICKET"
// arg3 = arg3 = TotalSize
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
            "QUIC_PACKET_KEY",
            PacketKeyLength);
// arg2 = arg2 = "QUIC_PACKET_KEY"
// arg3 = arg3 = PacketKeyLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "FFI_mitls_quic_get_record_key failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "FFI_mitls_quic_get_record_key failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
// arg2 = arg2 = "QUIC_PACKET_KEY"
// arg3 = arg3 = PacketKeyLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "FFI_mitls_quic_get_record_secrets failed");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "FFI_mitls_quic_get_record_secrets failed"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_TlsError



/*----------------------------------------------------------
// Decoder Ring for TlsError
// [ tls][%p] ERROR, %s.
// QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported hash type");
// arg2 = arg2 = TlsContext->Connection
// arg3 = arg3 = "Unsupported hash type"
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_TlsError(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifndef _clog_4_ARGS_TRACE_AllocFailure



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_KEY",
            sizeof(QUIC_KEY));
// arg2 = arg2 = "QUIC_KEY"
// arg3 = arg3 = sizeof(QUIC_KEY)
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
            "QUIC_HP_KEY",
            sizeof(QUIC_HP_KEY));
// arg2 = arg2 = "QUIC_HP_KEY"
// arg3 = arg3 = sizeof(QUIC_HP_KEY)
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
            "QUIC_HASH",
            sizeof(QUIC_HASH) + SaltLength);
// arg2 = arg2 = "QUIC_HASH"
// arg3 = arg3 = sizeof(QUIC_HASH) + SaltLength
----------------------------------------------------------*/
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_tls_mitls.c.clog.h.c"
#endif
