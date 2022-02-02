#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_CRYPTO_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "crypto.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_CRYPTO_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_CRYPTO_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "crypto.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
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
// Decoder Ring for IgnoreCryptoFrame
// [conn][%p] Ignoring received crypto after cleanup
// QuicTraceLogConnWarning(
            IgnoreCryptoFrame,
            Connection,
            "Ignoring received crypto after cleanup");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_IgnoreCryptoFrame
#define _clog_3_ARGS_TRACE_IgnoreCryptoFrame(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, IgnoreCryptoFrame , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DiscardKeyType
// [conn][%p] Discarding key type = %hhu
// QuicTraceLogConnInfo(
        DiscardKeyType,
        Connection,
        "Discarding key type = %hhu",
        (uint8_t)KeyType);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint8_t)KeyType = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DiscardKeyType
#define _clog_4_ARGS_TRACE_DiscardKeyType(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_C, DiscardKeyType , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ZeroRttAccepted
// [conn][%p] 0-RTT accepted
// QuicTraceLogConnInfo(
            ZeroRttAccepted,
            Connection,
            "0-RTT accepted");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ZeroRttAccepted
#define _clog_3_ARGS_TRACE_ZeroRttAccepted(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, ZeroRttAccepted , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ZeroRttRejected
// [conn][%p] 0-RTT rejected
// QuicTraceLogConnInfo(
            ZeroRttRejected,
            Connection,
            "0-RTT rejected");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ZeroRttRejected
#define _clog_3_ARGS_TRACE_ZeroRttRejected(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, ZeroRttRejected , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for HandshakeConfirmedServer
// [conn][%p] Handshake confirmed (server)
// QuicTraceLogConnInfo(
                HandshakeConfirmedServer,
                Connection,
                "Handshake confirmed (server)");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_HandshakeConfirmedServer
#define _clog_3_ARGS_TRACE_HandshakeConfirmedServer(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, HandshakeConfirmedServer , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CustomCertValidationSuccess
// [conn][%p] Custom cert validation succeeded
// QuicTraceLogConnInfo(
            CustomCertValidationSuccess,
            QuicCryptoGetConnection(Crypto),
            "Custom cert validation succeeded");
// arg1 = arg1 = QuicCryptoGetConnection(Crypto) = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CustomCertValidationSuccess
#define _clog_3_ARGS_TRACE_CustomCertValidationSuccess(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, CustomCertValidationSuccess , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CryptoDump
// [conn][%p] QS:%u MAX:%u UNA:%u NXT:%u RECOV:%u-%u
// QuicTraceLogConnVerbose(
            CryptoDump,
            Connection,
            "QS:%u MAX:%u UNA:%u NXT:%u RECOV:%u-%u",
            Crypto->TlsState.BufferTotalLength,
            Crypto->MaxSentLength,
            Crypto->UnAckedOffset,
            Crypto->NextSendOffset,
            Crypto->InRecovery ? Crypto->RecoveryNextOffset : 0,
            Crypto->InRecovery ? Crypto->RecoveryEndOffset : 0);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Crypto->TlsState.BufferTotalLength = arg3
// arg4 = arg4 = Crypto->MaxSentLength = arg4
// arg5 = arg5 = Crypto->UnAckedOffset = arg5
// arg6 = arg6 = Crypto->NextSendOffset = arg6
// arg7 = arg7 = Crypto->InRecovery ? Crypto->RecoveryNextOffset : 0 = arg7
// arg8 = arg8 = Crypto->InRecovery ? Crypto->RecoveryEndOffset : 0 = arg8
----------------------------------------------------------*/
#ifndef _clog_9_ARGS_TRACE_CryptoDump
#define _clog_9_ARGS_TRACE_CryptoDump(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5, arg6, arg7, arg8)\
tracepoint(CLOG_CRYPTO_C, CryptoDump , arg1, arg3, arg4, arg5, arg6, arg7, arg8);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CryptoDumpUnacked
// [conn][%p]   unACKed: [%llu, %llu]
// QuicTraceLogConnVerbose(
                CryptoDumpUnacked,
                Connection,
                "  unACKed: [%llu, %llu]",
                UnAcked,
                Sack->Low);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = UnAcked = arg3
// arg4 = arg4 = Sack->Low = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CryptoDumpUnacked
#define _clog_5_ARGS_TRACE_CryptoDumpUnacked(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_C, CryptoDumpUnacked , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CryptoDumpUnacked2
// [conn][%p]   unACKed: [%llu, %u]
// QuicTraceLogConnVerbose(
                CryptoDumpUnacked2,
                Connection,
                "  unACKed: [%llu, %u]",
                UnAcked,
                Crypto->MaxSentLength);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = UnAcked = arg3
// arg4 = arg4 = Crypto->MaxSentLength = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_CryptoDumpUnacked2
#define _clog_5_ARGS_TRACE_CryptoDumpUnacked2(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_C, CryptoDumpUnacked2 , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for NoMoreRoomForCrypto
// [conn][%p] No room for CRYPTO frame
// QuicTraceLogConnVerbose(
            NoMoreRoomForCrypto,
            Connection,
            "No room for CRYPTO frame");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_NoMoreRoomForCrypto
#define _clog_3_ARGS_TRACE_NoMoreRoomForCrypto(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, NoMoreRoomForCrypto , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AddCryptoFrame
// [conn][%p] Sending %hu crypto bytes, offset=%u
// QuicTraceLogConnVerbose(
        AddCryptoFrame,
        Connection,
        "Sending %hu crypto bytes, offset=%u",
        (uint16_t)Frame.Length,
        CryptoOffset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Frame.Length = arg3
// arg4 = arg4 = CryptoOffset = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_AddCryptoFrame
#define _clog_5_ARGS_TRACE_AddCryptoFrame(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_C, AddCryptoFrame , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecoverCrypto
// [conn][%p] Recovering crypto from %llu up to %llu
// QuicTraceLogConnVerbose(
            RecoverCrypto,
            Connection,
            "Recovering crypto from %llu up to %llu",
            Start,
            End);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Start = arg3
// arg4 = arg4 = End = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_RecoverCrypto
#define _clog_5_ARGS_TRACE_RecoverCrypto(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_C, RecoverCrypto , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AckCrypto
// [conn][%p] Received ack for %u crypto bytes, offset=%u
// QuicTraceLogConnVerbose(
        AckCrypto,
        Connection,
        "Received ack for %u crypto bytes, offset=%u",
        Length,
        Offset);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Length = arg3
// arg4 = arg4 = Offset = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_AckCrypto
#define _clog_5_ARGS_TRACE_AckCrypto(uniqueId, arg1, encoded_arg_string, arg3, arg4)\
tracepoint(CLOG_CRYPTO_C, AckCrypto , arg1, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for RecvCrypto
// [conn][%p] Received %hu crypto bytes, offset=%llu Ready=%hhu
// QuicTraceLogConnVerbose(
        RecvCrypto,
        Connection,
        "Received %hu crypto bytes, offset=%llu Ready=%hhu",
        (uint16_t)Frame->Length,
        Frame->Offset,
        *DataReady);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = (uint16_t)Frame->Length = arg3
// arg4 = arg4 = Frame->Offset = arg4
// arg5 = arg5 = *DataReady = arg5
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_RecvCrypto
#define _clog_6_ARGS_TRACE_RecvCrypto(uniqueId, arg1, encoded_arg_string, arg3, arg4, arg5)\
tracepoint(CLOG_CRYPTO_C, RecvCrypto , arg1, arg3, arg4, arg5);\

#endif




/*----------------------------------------------------------
// Decoder Ring for IndicateConnected
// [conn][%p] Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)
// QuicTraceLogConnVerbose(
            IndicateConnected,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_CONNECTED (Resume=%hhu)",
            Event.CONNECTED.SessionResumed);
// arg1 = arg1 = Connection = arg1
// arg3 = arg3 = Event.CONNECTED.SessionResumed = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_IndicateConnected
#define _clog_4_ARGS_TRACE_IndicateConnected(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_C, IndicateConnected , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for DrainCrypto
// [conn][%p] Draining %u crypto bytes
// QuicTraceLogConnVerbose(
            DrainCrypto,
            QuicCryptoGetConnection(Crypto),
            "Draining %u crypto bytes",
            RecvBufferConsumed);
// arg1 = arg1 = QuicCryptoGetConnection(Crypto) = arg1
// arg3 = arg3 = RecvBufferConsumed = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_DrainCrypto
#define _clog_4_ARGS_TRACE_DrainCrypto(uniqueId, arg1, encoded_arg_string, arg3)\
tracepoint(CLOG_CRYPTO_C, DrainCrypto , arg1, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for CryptoNotReady
// [conn][%p] No complete TLS messages to process
// QuicTraceLogConnVerbose(
                CryptoNotReady,
                Connection,
                "No complete TLS messages to process");
// arg1 = arg1 = Connection = arg1
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_CryptoNotReady
#define _clog_3_ARGS_TRACE_CryptoNotReady(uniqueId, arg1, encoded_arg_string)\
tracepoint(CLOG_CRYPTO_C, CryptoNotReady , arg1);\

#endif




/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "crypto send buffer",
            SendBufferLength);
// arg2 = arg2 = "crypto send buffer" = arg2
// arg3 = arg3 = SendBufferLength = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_C, AllocFailure , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnErrorStatus
// [conn][%p] ERROR, %u, %s.
// QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "Creating initial keys");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Status = arg3
// arg4 = arg4 = "Creating initial keys" = arg4
----------------------------------------------------------*/
#ifndef _clog_5_ARGS_TRACE_ConnErrorStatus
#define _clog_5_ARGS_TRACE_ConnErrorStatus(uniqueId, encoded_arg_string, arg2, arg3, arg4)\
tracepoint(CLOG_CRYPTO_C, ConnErrorStatus , arg2, arg3, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnError
// [conn][%p] ERROR, %s.
// QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Tried to write beyond crypto flow control limit.");
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = "Tried to write beyond crypto flow control limit." = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnError
#define _clog_4_ARGS_TRACE_ConnError(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_C, ConnError , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnWriteKeyUpdated
// [conn][%p] Write Key Updated, %hhu.
// QuicTraceEvent(
            ConnWriteKeyUpdated,
            "[conn][%p] Write Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.WriteKey);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Crypto->TlsState.WriteKey = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnWriteKeyUpdated
#define _clog_4_ARGS_TRACE_ConnWriteKeyUpdated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_C, ConnWriteKeyUpdated , arg2, arg3);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnReadKeyUpdated
// [conn][%p] Read Key Updated, %hhu.
// QuicTraceEvent(
            ConnReadKeyUpdated,
            "[conn][%p] Read Key Updated, %hhu.",
            Connection,
            Crypto->TlsState.ReadKey);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = Crypto->TlsState.ReadKey = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnReadKeyUpdated
#define _clog_4_ARGS_TRACE_ConnReadKeyUpdated(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_C, ConnReadKeyUpdated , arg2, arg3);\

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
tracepoint(CLOG_CRYPTO_C, ConnHandshakeComplete , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnSourceCidRemoved
// [conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!
// QuicTraceEvent(
                ConnSourceCidRemoved,
                "[conn][%p] (SeqNum=%llu) Removed Source CID: %!CID!",
                Connection,
                InitialSourceCid->CID.SequenceNumber,
                CASTED_CLOG_BYTEARRAY(InitialSourceCid->CID.Length, InitialSourceCid->CID.Data));
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = InitialSourceCid->CID.SequenceNumber = arg3
// arg4 = arg4 = CASTED_CLOG_BYTEARRAY(InitialSourceCid->CID.Length, InitialSourceCid->CID.Data) = arg4
----------------------------------------------------------*/
#ifndef _clog_6_ARGS_TRACE_ConnSourceCidRemoved
#define _clog_6_ARGS_TRACE_ConnSourceCidRemoved(uniqueId, encoded_arg_string, arg2, arg3, arg4, arg4_len)\
tracepoint(CLOG_CRYPTO_C, ConnSourceCidRemoved , arg2, arg3, arg4_len, arg4);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnNewPacketKeys
// [conn][%p] New packet keys created successfully.
// QuicTraceEvent(
            ConnNewPacketKeys,
            "[conn][%p] New packet keys created successfully.",
            Connection);
// arg2 = arg2 = Connection = arg2
----------------------------------------------------------*/
#ifndef _clog_3_ARGS_TRACE_ConnNewPacketKeys
#define _clog_3_ARGS_TRACE_ConnNewPacketKeys(uniqueId, encoded_arg_string, arg2)\
tracepoint(CLOG_CRYPTO_C, ConnNewPacketKeys , arg2);\

#endif




/*----------------------------------------------------------
// Decoder Ring for ConnKeyPhaseChange
// [conn][%p] Key phase change (locally initiated=%hhu).
// QuicTraceEvent(
        ConnKeyPhaseChange,
        "[conn][%p] Key phase change (locally initiated=%hhu).",
        Connection,
        LocalUpdate);
// arg2 = arg2 = Connection = arg2
// arg3 = arg3 = LocalUpdate = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_ConnKeyPhaseChange
#define _clog_4_ARGS_TRACE_ConnKeyPhaseChange(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_CRYPTO_C, ConnKeyPhaseChange , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_crypto.c.clog.h.c"
#endif
