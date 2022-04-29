#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CRYPTO_TLS_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "crypto_tls.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CRYPTO_TLS_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CRYPTO_TLS_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "crypto_tls.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceLogConnWarning
#define _clog_MACRO_QuicTraceLogConnWarning  1
#define QuicTraceLogConnWarning(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
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
// Decoder Ring for NoSniPresent
// [conn][%p] No SNI extension present
// QuicTraceLogConnWarning(
            NoSniPresent,
            Connection,
            "No SNI extension present");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NoSniPresent
#define _clog_3_ARGS_TRACE_NoSniPresent(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, NoSniPresent , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPReserved
// [conn][%p] TP: Reserved ID %llu, length %hu
// QuicTraceLogConnWarning(
                    DecodeTPReserved,
                    Connection,
                    "TP: Reserved ID %llu, length %hu",
                    Id,
                    Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Id = arg3
// arg4 = arg4 = Length = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DecodeTPReserved
#define _clog_5_ARGS_TRACE_DecodeTPReserved(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPReserved , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPUnknown
// [conn][%p] TP: Unknown ID %llu, length %hu
// QuicTraceLogConnWarning(
                    DecodeTPUnknown,
                    Connection,
                    "TP: Unknown ID %llu, length %hu",
                    Id,
                    Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Id = arg3
// arg4 = arg4 = Length = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DecodeTPUnknown
#define _clog_5_ARGS_TRACE_DecodeTPUnknown(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPUnknown , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPStart
// [conn][%p] Encoding Transport Parameters (Server = %hhu)
// QuicTraceLogConnVerbose(
        EncodeTPStart,
        Connection,
        "Encoding Transport Parameters (Server = %hhu)",
        IsServerTP);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = IsServerTP = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPStart
#define _clog_4_ARGS_TRACE_EncodeTPStart(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPStart , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPOriginalDestinationCID
// [conn][%p] TP: Original Destination Connection ID (%s)
// QuicTraceLogConnVerbose(
            EncodeTPOriginalDestinationCID,
            Connection,
            "TP: Original Destination Connection ID (%s)",
            QuicCidBufToStr(
                TransportParams->OriginalDestinationConnectionID,
                TransportParams->OriginalDestinationConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->OriginalDestinationConnectionID,
                TransportParams->OriginalDestinationConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPOriginalDestinationCID
#define _clog_4_ARGS_TRACE_EncodeTPOriginalDestinationCID(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPOriginalDestinationCID , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPIdleTimeout
// [conn][%p] TP: Idle Timeout (%llu ms)
// QuicTraceLogConnVerbose(
            EncodeTPIdleTimeout,
            Connection,
            "TP: Idle Timeout (%llu ms)",
            TransportParams->IdleTimeout);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->IdleTimeout = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPIdleTimeout
#define _clog_4_ARGS_TRACE_EncodeTPIdleTimeout(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPIdleTimeout , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPStatelessResetToken
// [conn][%p] TP: Stateless Reset Token (%s)
// QuicTraceLogConnVerbose(
            EncodeTPStatelessResetToken,
            Connection,
            "TP: Stateless Reset Token (%s)",
            QuicCidBufToStr(
                TransportParams->StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPStatelessResetToken
#define _clog_4_ARGS_TRACE_EncodeTPStatelessResetToken(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPStatelessResetToken , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxUdpPayloadSize
// [conn][%p] TP: Max Udp Payload Size (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPMaxUdpPayloadSize,
            Connection,
            "TP: Max Udp Payload Size (%llu bytes)",
            TransportParams->MaxUdpPayloadSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxUdpPayloadSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPMaxUdpPayloadSize
#define _clog_4_ARGS_TRACE_EncodeTPMaxUdpPayloadSize(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPMaxUdpPayloadSize , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxData
// [conn][%p] TP: Max Data (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxData,
            Connection,
            "TP: Max Data (%llu bytes)",
            TransportParams->InitialMaxData);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxData = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPInitMaxData
#define _clog_4_ARGS_TRACE_EncodeTPInitMaxData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxStreamDataBidiLocal
// [conn][%p] TP: Max Local Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxStreamDataBidiLocal,
            Connection,
            "TP: Max Local Bidirectional Stream Data (%llu bytes)",
            TransportParams->InitialMaxStreamDataBidiLocal);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiLocal = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPInitMaxStreamDataBidiLocal
#define _clog_4_ARGS_TRACE_EncodeTPInitMaxStreamDataBidiLocal(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxStreamDataBidiLocal , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxStreamDataBidiRemote
// [conn][%p] TP: Max Remote Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxStreamDataBidiRemote,
            Connection,
            "TP: Max Remote Bidirectional Stream Data (%llu bytes)",
            TransportParams->InitialMaxStreamDataBidiRemote);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiRemote = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPInitMaxStreamDataBidiRemote
#define _clog_4_ARGS_TRACE_EncodeTPInitMaxStreamDataBidiRemote(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxStreamDataBidiRemote , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPInitMaxStreamUni
// [conn][%p] TP: Max Unidirectional Stream Data (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPInitMaxStreamUni,
            Connection,
            "TP: Max Unidirectional Stream Data (%llu)",
            TransportParams->InitialMaxStreamDataUni);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataUni = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPInitMaxStreamUni
#define _clog_4_ARGS_TRACE_EncodeTPInitMaxStreamUni(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPInitMaxStreamUni , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxBidiStreams
// [conn][%p] TP: Max Bidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPMaxBidiStreams,
            Connection,
            "TP: Max Bidirectional Streams (%llu)",
            TransportParams->InitialMaxBidiStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxBidiStreams = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPMaxBidiStreams
#define _clog_4_ARGS_TRACE_EncodeTPMaxBidiStreams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPMaxBidiStreams , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxUniStreams
// [conn][%p] TP: Max Unidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPMaxUniStreams,
            Connection,
            "TP: Max Unidirectional Streams (%llu)",
            TransportParams->InitialMaxUniStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxUniStreams = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPMaxUniStreams
#define _clog_4_ARGS_TRACE_EncodeTPMaxUniStreams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPMaxUniStreams , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPAckDelayExponent
// [conn][%p] TP: ACK Delay Exponent (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPAckDelayExponent,
            Connection,
            "TP: ACK Delay Exponent (%llu)",
            TransportParams->AckDelayExponent);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->AckDelayExponent = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPAckDelayExponent
#define _clog_4_ARGS_TRACE_EncodeTPAckDelayExponent(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPAckDelayExponent , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPMaxAckDelay
// [conn][%p] TP: Max ACK Delay (%llu ms)
// QuicTraceLogConnVerbose(
            EncodeTPMaxAckDelay,
            Connection,
            "TP: Max ACK Delay (%llu ms)",
            TransportParams->MaxAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxAckDelay = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPMaxAckDelay
#define _clog_4_ARGS_TRACE_EncodeTPMaxAckDelay(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPMaxAckDelay , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPDisableMigration
// [conn][%p] TP: Disable Active Migration
// QuicTraceLogConnVerbose(
            EncodeTPDisableMigration,
            Connection,
            "TP: Disable Active Migration");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_EncodeTPDisableMigration
#define _clog_3_ARGS_TRACE_EncodeTPDisableMigration(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPDisableMigration , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPPreferredAddress
// [conn][%p] TP: Preferred Address
// QuicTraceLogConnVerbose(
            EncodeTPPreferredAddress,
            Connection,
            "TP: Preferred Address");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_EncodeTPPreferredAddress
#define _clog_3_ARGS_TRACE_EncodeTPPreferredAddress(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPPreferredAddress , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPCIDLimit
// [conn][%p] TP: Connection ID Limit (%llu)
// QuicTraceLogConnVerbose(
            EncodeTPCIDLimit,
            Connection,
            "TP: Connection ID Limit (%llu)",
            TransportParams->ActiveConnectionIdLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->ActiveConnectionIdLimit = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPCIDLimit
#define _clog_4_ARGS_TRACE_EncodeTPCIDLimit(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPCIDLimit , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPOriginalCID
// [conn][%p] TP: Initial Source Connection ID (%s)
// QuicTraceLogConnVerbose(
            EncodeTPOriginalCID,
            Connection,
            "TP: Initial Source Connection ID (%s)",
            QuicCidBufToStr(
                TransportParams->InitialSourceConnectionID,
                TransportParams->InitialSourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->InitialSourceConnectionID,
                TransportParams->InitialSourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPOriginalCID
#define _clog_4_ARGS_TRACE_EncodeTPOriginalCID(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPOriginalCID , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPRetrySourceCID
// [conn][%p] TP: Retry Source Connection ID (%s)
// QuicTraceLogConnVerbose(
            EncodeTPRetrySourceCID,
            Connection,
            "TP: Retry Source Connection ID (%s)",
            QuicCidBufToStr(
                TransportParams->RetrySourceConnectionID,
                TransportParams->RetrySourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                TransportParams->RetrySourceConnectionID,
                TransportParams->RetrySourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPRetrySourceCID
#define _clog_4_ARGS_TRACE_EncodeTPRetrySourceCID(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPRetrySourceCID , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeMaxDatagramFrameSize
// [conn][%p] TP: Max Datagram Frame Size (%llu bytes)
// QuicTraceLogConnVerbose(
            EncodeMaxDatagramFrameSize,
            Connection,
            "TP: Max Datagram Frame Size (%llu bytes)",
            TransportParams->MaxDatagramFrameSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxDatagramFrameSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeMaxDatagramFrameSize
#define _clog_4_ARGS_TRACE_EncodeMaxDatagramFrameSize(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeMaxDatagramFrameSize , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPDisable1RttEncryption
// [conn][%p] TP: Disable 1-RTT Encryption
// QuicTraceLogConnVerbose(
            EncodeTPDisable1RttEncryption,
            Connection,
            "TP: Disable 1-RTT Encryption");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_EncodeTPDisable1RttEncryption
#define _clog_3_ARGS_TRACE_EncodeTPDisable1RttEncryption(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPDisable1RttEncryption , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPVersionNegotiationExt
// [conn][%p] TP: Version Negotiation Extension (%u bytes)
// QuicTraceLogConnVerbose(
            EncodeTPVersionNegotiationExt,
            Connection,
            "TP: Version Negotiation Extension (%u bytes)",
            TransportParams->VersionInfoLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->VersionInfoLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPVersionNegotiationExt
#define _clog_4_ARGS_TRACE_EncodeTPVersionNegotiationExt(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPVersionNegotiationExt , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPMinAckDelay
// [conn][%p] TP: Min ACK Delay (%llu us)
// QuicTraceLogConnVerbose(
            EncodeTPMinAckDelay,
            Connection,
            "TP: Min ACK Delay (%llu us)",
            TransportParams->MinAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MinAckDelay = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPMinAckDelay
#define _clog_4_ARGS_TRACE_EncodeTPMinAckDelay(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPMinAckDelay , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPCibirEncoding
// [conn][%p] TP: CIBIR Encoding (%llu length, %llu offset)
// QuicTraceLogConnVerbose(
            EncodeTPCibirEncoding,
            Connection,
            "TP: CIBIR Encoding (%llu length, %llu offset)",
            TransportParams->CibirLength,
            TransportParams->CibirOffset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->CibirLength = arg3
// arg4 = arg4 = TransportParams->CibirOffset = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_EncodeTPCibirEncoding
#define _clog_5_ARGS_TRACE_EncodeTPCibirEncoding(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPCibirEncoding , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPTest
// [conn][%p] TP: TEST TP (Type %hu, Length %hu)
// QuicTraceLogConnVerbose(
            EncodeTPTest,
            Connection,
            "TP: TEST TP (Type %hu, Length %hu)",
            TestParam->Type,
            TestParam->Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TestParam->Type = arg3
// arg4 = arg4 = TestParam->Length = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_EncodeTPTest
#define _clog_5_ARGS_TRACE_EncodeTPTest(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPTest , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for EncodeTPEnd
// [conn][%p] Encoded %hu bytes for QUIC TP
// QuicTraceLogConnVerbose(
        EncodeTPEnd,
        Connection,
        "Encoded %hu bytes for QUIC TP",
        (uint16_t)FinalTPLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)FinalTPLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_EncodeTPEnd
#define _clog_4_ARGS_TRACE_EncodeTPEnd(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, EncodeTPEnd , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPStart
// [conn][%p] Decoding Transport Parameters (Server = %hhu) (%hu bytes)
// QuicTraceLogConnVerbose(
        DecodeTPStart,
        Connection,
        "Decoding Transport Parameters (Server = %hhu) (%hu bytes)",
        IsServerTP,
        TPLen);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = IsServerTP = arg3
// arg4 = arg4 = TPLen = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DecodeTPStart
#define _clog_5_ARGS_TRACE_DecodeTPStart(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPStart , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPOriginalDestinationCID
// [conn][%p] TP: Original Connection Destination ID (%s)
// QuicTraceLogConnVerbose(
                DecodeTPOriginalDestinationCID,
                Connection,
                "TP: Original Connection Destination ID (%s)",
                QuicCidBufToStr(
                    TransportParams->OriginalDestinationConnectionID,
                    TransportParams->OriginalDestinationConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->OriginalDestinationConnectionID,
                    TransportParams->OriginalDestinationConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPOriginalDestinationCID
#define _clog_4_ARGS_TRACE_DecodeTPOriginalDestinationCID(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPOriginalDestinationCID , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPIdleTimeout
// [conn][%p] TP: Idle Timeout (%llu ms)
// QuicTraceLogConnVerbose(
                DecodeTPIdleTimeout,
                Connection,
                "TP: Idle Timeout (%llu ms)",
                TransportParams->IdleTimeout);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->IdleTimeout = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPIdleTimeout
#define _clog_4_ARGS_TRACE_DecodeTPIdleTimeout(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPIdleTimeout , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPStatelessResetToken
// [conn][%p] TP: Stateless Reset Token (%s)
// QuicTraceLogConnVerbose(
                DecodeTPStatelessResetToken,
                Connection,
                "TP: Stateless Reset Token (%s)",
                QuicCidBufToStr(
                    TransportParams->StatelessResetToken,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->StatelessResetToken,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPStatelessResetToken
#define _clog_4_ARGS_TRACE_DecodeTPStatelessResetToken(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPStatelessResetToken , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxUdpPayloadSize
// [conn][%p] TP: Max Udp Payload Size (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPMaxUdpPayloadSize,
                Connection,
                "TP: Max Udp Payload Size (%llu bytes)",
                TransportParams->MaxUdpPayloadSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxUdpPayloadSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPMaxUdpPayloadSize
#define _clog_4_ARGS_TRACE_DecodeTPMaxUdpPayloadSize(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPMaxUdpPayloadSize , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxData
// [conn][%p] TP: Max Data (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxData,
                Connection,
                "TP: Max Data (%llu bytes)",
                TransportParams->InitialMaxData);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxData = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPInitMaxData
#define _clog_4_ARGS_TRACE_DecodeTPInitMaxData(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxData , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxStreamDataBidiLocal
// [conn][%p] TP: Max Local Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxStreamDataBidiLocal,
                Connection,
                "TP: Max Local Bidirectional Stream Data (%llu bytes)",
                TransportParams->InitialMaxStreamDataBidiLocal);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiLocal = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPInitMaxStreamDataBidiLocal
#define _clog_4_ARGS_TRACE_DecodeTPInitMaxStreamDataBidiLocal(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxStreamDataBidiLocal , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxStreamDataBidiRemote
// [conn][%p] TP: Max Remote Bidirectional Stream Data (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxStreamDataBidiRemote,
                Connection,
                "TP: Max Remote Bidirectional Stream Data (%llu bytes)",
                TransportParams->InitialMaxStreamDataBidiRemote);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataBidiRemote = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPInitMaxStreamDataBidiRemote
#define _clog_4_ARGS_TRACE_DecodeTPInitMaxStreamDataBidiRemote(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxStreamDataBidiRemote , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitMaxStreamDataBidiUni
// [conn][%p] TP: Max Unidirectional Stream Data (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPInitMaxStreamDataBidiUni,
                Connection,
                "TP: Max Unidirectional Stream Data (%llu)",
                TransportParams->InitialMaxStreamDataUni);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxStreamDataUni = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPInitMaxStreamDataBidiUni
#define _clog_4_ARGS_TRACE_DecodeTPInitMaxStreamDataBidiUni(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPInitMaxStreamDataBidiUni , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxBidiStreams
// [conn][%p] TP: Max Bidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPMaxBidiStreams,
                Connection,
                "TP: Max Bidirectional Streams (%llu)",
                TransportParams->InitialMaxBidiStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxBidiStreams = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPMaxBidiStreams
#define _clog_4_ARGS_TRACE_DecodeTPMaxBidiStreams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPMaxBidiStreams , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxUniStreams
// [conn][%p] TP: Max Unidirectional Streams (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPMaxUniStreams,
                Connection,
                "TP: Max Unidirectional Streams (%llu)",
                TransportParams->InitialMaxUniStreams);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->InitialMaxUniStreams = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPMaxUniStreams
#define _clog_4_ARGS_TRACE_DecodeTPMaxUniStreams(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPMaxUniStreams , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPAckDelayExponent
// [conn][%p] TP: ACK Delay Exponent (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPAckDelayExponent,
                Connection,
                "TP: ACK Delay Exponent (%llu)",
                TransportParams->AckDelayExponent);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->AckDelayExponent = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPAckDelayExponent
#define _clog_4_ARGS_TRACE_DecodeTPAckDelayExponent(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPAckDelayExponent , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxAckDelay
// [conn][%p] TP: Max ACK Delay (%llu ms)
// QuicTraceLogConnVerbose(
                DecodeTPMaxAckDelay,
                Connection,
                "TP: Max ACK Delay (%llu ms)",
                TransportParams->MaxAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxAckDelay = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPMaxAckDelay
#define _clog_4_ARGS_TRACE_DecodeTPMaxAckDelay(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPMaxAckDelay , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPDisableActiveMigration
// [conn][%p] TP: Disable Active Migration
// QuicTraceLogConnVerbose(
                DecodeTPDisableActiveMigration,
                Connection,
                "TP: Disable Active Migration");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DecodeTPDisableActiveMigration
#define _clog_3_ARGS_TRACE_DecodeTPDisableActiveMigration(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPDisableActiveMigration , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPPreferredAddress
// [conn][%p] TP: Preferred Address
// QuicTraceLogConnVerbose(
                DecodeTPPreferredAddress,
                Connection,
                "TP: Preferred Address");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DecodeTPPreferredAddress
#define _clog_3_ARGS_TRACE_DecodeTPPreferredAddress(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPPreferredAddress , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPCIDLimit
// [conn][%p] TP: Connection ID Limit (%llu)
// QuicTraceLogConnVerbose(
                DecodeTPCIDLimit,
                Connection,
                "TP: Connection ID Limit (%llu)",
                TransportParams->ActiveConnectionIdLimit);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->ActiveConnectionIdLimit = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPCIDLimit
#define _clog_4_ARGS_TRACE_DecodeTPCIDLimit(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPCIDLimit , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPInitialSourceCID
// [conn][%p] TP: Initial Source Connection ID (%s)
// QuicTraceLogConnVerbose(
                DecodeTPInitialSourceCID,
                Connection,
                "TP: Initial Source Connection ID (%s)",
                QuicCidBufToStr(
                    TransportParams->InitialSourceConnectionID,
                    TransportParams->InitialSourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->InitialSourceConnectionID,
                    TransportParams->InitialSourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPInitialSourceCID
#define _clog_4_ARGS_TRACE_DecodeTPInitialSourceCID(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPInitialSourceCID , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPRetrySourceCID
// [conn][%p] TP: Retry Source Connection ID (%s)
// QuicTraceLogConnVerbose(
                DecodeTPRetrySourceCID,
                Connection,
                "TP: Retry Source Connection ID (%s)",
                QuicCidBufToStr(
                    TransportParams->RetrySourceConnectionID,
                    TransportParams->RetrySourceConnectionIDLength).Buffer);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = QuicCidBufToStr(
                    TransportParams->RetrySourceConnectionID,
                    TransportParams->RetrySourceConnectionIDLength).Buffer = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPRetrySourceCID
#define _clog_4_ARGS_TRACE_DecodeTPRetrySourceCID(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPRetrySourceCID , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPMaxDatagramFrameSize
// [conn][%p] TP: Max Datagram Frame Size (%llu bytes)
// QuicTraceLogConnVerbose(
                DecodeTPMaxDatagramFrameSize,
                Connection,
                "TP: Max Datagram Frame Size (%llu bytes)",
                TransportParams->MaxDatagramFrameSize);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MaxDatagramFrameSize = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPMaxDatagramFrameSize
#define _clog_4_ARGS_TRACE_DecodeTPMaxDatagramFrameSize(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPMaxDatagramFrameSize , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPCibirEncoding
// [conn][%p] TP: CIBIR Encoding (%llu length, %llu offset)
// QuicTraceLogConnVerbose(
                DecodeTPCibirEncoding,
                Connection,
                "TP: CIBIR Encoding (%llu length, %llu offset)",
                TransportParams->CibirLength,
                TransportParams->CibirOffset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->CibirLength = arg3
// arg4 = arg4 = TransportParams->CibirOffset = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_DecodeTPCibirEncoding
#define _clog_5_ARGS_TRACE_DecodeTPCibirEncoding(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPCibirEncoding , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPDisable1RttEncryption
// [conn][%p] TP: Disable 1-RTT Encryption
// QuicTraceLogConnVerbose(
                DecodeTPDisable1RttEncryption,
                Connection,
                "TP: Disable 1-RTT Encryption");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_DecodeTPDisable1RttEncryption
#define _clog_3_ARGS_TRACE_DecodeTPDisable1RttEncryption(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPDisable1RttEncryption , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPVersionNegotiationInfo
// [conn][%p] TP: Version Negotiation Info (%hu bytes)
// QuicTraceLogConnVerbose(
                    DecodeTPVersionNegotiationInfo,
                    Connection,
                    "TP: Version Negotiation Info (%hu bytes)",
                    Length);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Length = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPVersionNegotiationInfo
#define _clog_4_ARGS_TRACE_DecodeTPVersionNegotiationInfo(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPVersionNegotiationInfo , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DecodeTPMinAckDelay
// [conn][%p] TP: Min ACK Delay (%llu us)
// QuicTraceLogConnVerbose(
                DecodeTPMinAckDelay,
                Connection,
                "TP: Min ACK Delay (%llu us)",
                TransportParams->MinAckDelay);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = TransportParams->MinAckDelay = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DecodeTPMinAckDelay
#define _clog_4_ARGS_TRACE_DecodeTPMinAckDelay(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, DecodeTPMinAckDelay , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Parse error. ReadTlsSni #1");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Parse error. ReadTlsSni #1" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "TP buffer",
            CxPlatTlsTPHeaderSize + RequiredTPLen);
// arg2 = arg2 = "TP buffer" = arg2
// arg3 = arg3 = CxPlatTlsTPHeaderSize + RequiredTPLen = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_TLS_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Length,
                    "Invalid length of QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Length = arg3
// arg4 = arg4 = "Invalid length of QUIC_TP_ID_ORIGINAL_DESTINATION_CONNECTION_ID" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CRYPTO_TLS_C, ConnErrorStatus , arg2, arg3, arg4);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_crypto_tls.c.clog.h.c"
#endif
