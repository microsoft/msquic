/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains all logic for processing TLS specific data structures.
    This includes the logic to decode the ALPN list and SNI from the Client
    Hello, on server, and the logic to read and write the QUIC transport
    parameter extension.

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "crypto_tls.tmh"
#endif

#define TLS1_PROTOCOL_VERSION 0x0301
#define TLS_MESSAGE_HEADER_LENGTH 4
#define TLS_RANDOM_LENGTH 32
#define TLS_SESSION_ID_LENGTH 32

typedef enum eTlsHandshakeType {
    TlsHandshake_ClientHello = 0x01
} eTlsHandshakeType;

typedef enum eTlsExtensions {
    TlsExt_ServerName               = 0x00,
    TlsExt_AppProtocolNegotiation   = 0x10,
    TlsExt_SessionTicket            = 0x23,
    TlsExt_QuicTransportParameters  = 0xffa5
} eTlsExtensions;

typedef enum eSniNameType {
    TlsExt_Sni_NameType_HostName = 0
} eSniNameType;

#define QUIC_TP_ID_ORIGINAL_CONNECTION_ID                   0   // uint8_t[]
#define QUIC_TP_ID_IDLE_TIMEOUT                             1   // varint
#define QUIC_TP_ID_STATELESS_RESET_TOKEN                    2   // uint8_t[16]
#define QUIC_TP_ID_MAX_PACKET_SIZE                          3   // varint
#define QUIC_TP_ID_INITIAL_MAX_DATA                         4   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL       5   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE      6   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI              7   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI                 8   // varint
#define QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI                  9   // varint
#define QUIC_TP_ID_ACK_DELAY_EXPONENT                       10  // varint
#define QUIC_TP_ID_MAX_ACK_DELAY                            11  // varint
#define QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION                 12  // N/A
#define QUIC_TP_ID_PREFERRED_ADDRESS                        13  // PreferredAddress
#define QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT               14  // varint

#define QUIC_TP_ID_MAX QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT

BOOLEAN
QuicTpIdIsReserved(
    _In_ QUIC_VAR_INT ID
    )
{
    //
    // Per spec: Transport parameters with an identifier of the form "31 * N + 27"
    // for integer values of N are reserved to exercise the requirement that
    // unknown transport parameters be ignored.
    //
    return (ID % 31ull) == 27ull;
}

static
uint16_t
TlsReadUint16(
    _In_reads_(2) const uint8_t* Buffer
    )
{
    return
        (((uint32_t)Buffer[0] << 8) +
          (uint32_t)Buffer[1]);
}

static
uint32_t
TlsReadUint24(
    _In_reads_(3) const uint8_t* Buffer
    )
{
    return
        (((uint32_t)Buffer[0] << 16) +
         ((uint32_t)Buffer[1] << 8) +
          (uint32_t)Buffer[2]);
}

//
// The following functions encode data in the QUIC TP format. This format
// consists of a var-int for the 'ID', a var-int for the 'Length', and then
// 'Length' bytes of data.
//

#define TlsTransportParamLength(Id, Length) \
    (QuicVarIntSize(Id) + QuicVarIntSize(Length) + Length)

static
uint8_t*
TlsWriteTransportParam(
    _In_ uint16_t Id,
    _In_ uint16_t Length,
    _In_reads_bytes_opt_(Length) const uint8_t* Param,
    _Out_writes_bytes_(_Inexpressible_("Too Dynamic"))
        uint8_t* Buffer
    )
{
    Buffer = QuicVarIntEncode(Id, Buffer);
    Buffer = QuicVarIntEncode(Length, Buffer);
    QUIC_DBG_ASSERT(Param != NULL || Length == 0);
    if (Param) {
        QuicCopyMemory(Buffer, Param, Length);
        Buffer += Length;
    }
    return Buffer;
}

static
uint8_t*
TlsWriteTransportParamVarInt(
    _In_ uint16_t Id,
    _In_ QUIC_VAR_INT Value,
    _Out_writes_bytes_(_Inexpressible_("Too Dynamic"))
        uint8_t* Buffer
    )
{
    uint8_t Length = QuicVarIntSize(Value);
    Buffer = QuicVarIntEncode(Id, Buffer);
    Buffer = QuicVarIntEncode(Length, Buffer);
    Buffer = QuicVarIntEncode(Value, Buffer);
    return Buffer;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadSniExtension(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
      struct {
          NameType name_type;
          select (name_type) {
              case host_name: HostName;
          } name;
      } ServerName;

      enum {
          host_name(0), (255)
      } NameType;

      opaque HostName<1..2^16-1>;

      struct {
          ServerName server_name_list<1..2^16-1>
      } ServerNameList;
    */

    if (BufferLength < sizeof(uint16_t)) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsSni #1");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // We need at least 3 bytes to encode NameType(1) and empty HostName(2)
    //
    if (TlsReadUint16(Buffer) < 3) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsSni #2");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    //
    // Loop through the contents of the extension to ensure it is properly
    // formatted, even though we will only return the first entry.
    //
    BOOLEAN Found = FALSE;
    while (BufferLength > 0) {

        uint8_t NameType = Buffer[0];
        BufferLength--;
        Buffer++;

        if (BufferLength < sizeof(uint16_t)) {
            QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsSni #3");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        uint16_t NameLen = TlsReadUint16(Buffer);
        BufferLength -= 2;
        Buffer += 2;
        if (BufferLength < NameLen) {
            QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsSni #4");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        //
        // Pick only the first name in the list of names
        //
        if (NameType == TlsExt_Sni_NameType_HostName && !Found) {
            Info->ServerName = (const char*)Buffer;
            Info->ServerNameLength = NameLen;
            Found = TRUE;
        }

        BufferLength -= NameLen;
        Buffer += NameLen;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadAlpnExtension(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
       enum {
           application_layer_protocol_negotiation(16), (65535)
       } ExtensionType;

       opaque ProtocolName<1..2^8-1>;

       struct {
           ProtocolName protocol_name_list<2..2^16-1>
       } ProtocolNameList;
    */

    //
    // The client-side ALPN extension contains a protocol ID list with at least
    // one protocol ID 1 to 255 bytes long, plus 1 byte of protocol ID size, plus
    // 2 bytes for protocol ID list size.
    //
    if (BufferLength < sizeof(uint16_t) + 2 * sizeof(uint8_t)) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsAlpn #1");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (BufferLength != TlsReadUint16(Buffer) + sizeof(uint16_t)) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsAlpn #2");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    Info->AlpnList = Buffer;
    Info->AlpnListLength = BufferLength;

    //
    // Loop through the contents of the extension to ensure it is properly
    // formatted, even though we will return the whole extension.
    //
    while (BufferLength > 0) {
        uint16_t Len = Buffer[0];
        BufferLength--;
        Buffer++;

        if (BufferLength < 1 ||
            BufferLength < Len) {
            QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsAlpn #3");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        BufferLength -= Len;
        Buffer += Len;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadExtensions(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
      enum {
          server_name(0), max_fragment_length(1),
          client_certificate_url(2), trusted_ca_keys(3),
          truncated_hmac(4), status_request(5), (65535)
      } ExtensionType;

      struct {
          ExtensionType extension_type;
          opaque extension_data<0..2^16-1>;
      } Extension;
    */

    while (BufferLength) {
        //
        // Each extension will have atleast 4 bytes of data. 2 to label
        // the extension type and 2 for the length.
        //
        if (BufferLength < 2 * sizeof(uint16_t)) {
            QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsExt #1");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        uint16_t ExtType = TlsReadUint16(Buffer);
        uint16_t ExtLen = TlsReadUint16(Buffer + sizeof(uint16_t));
        BufferLength -= 2 * sizeof(uint16_t);
        Buffer += 2 * sizeof(uint16_t);
        if (BufferLength < ExtLen) {
            QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsExt #2");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (ExtType == TlsExt_ServerName) {
            QUIC_STATUS Status =
                QuicCryptoTlsReadSniExtension(
                    Connection, Buffer, ExtLen, Info);
            if (QUIC_FAILED(Status)) {
                return Status;
            }

        } else if (ExtType == TlsExt_AppProtocolNegotiation) {
            QUIC_STATUS Status =
                QuicCryptoTlsReadAlpnExtension(
                    Connection, Buffer, ExtLen, Info);
            if (QUIC_FAILED(Status)) {
                return Status;
            }
        }
        
        BufferLength -= ExtLen;
        Buffer += ExtLen;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadClientHello(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    /*
      struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;
    */

    //
    // Version
    //
    if (BufferLength < sizeof(uint16_t) ||
        TlsReadUint16(Buffer) < TLS1_PROTOCOL_VERSION) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #1");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    //
    // Random
    //
    if (BufferLength < TLS_RANDOM_LENGTH) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #2");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= TLS_RANDOM_LENGTH;
    Buffer += TLS_RANDOM_LENGTH;

    //
    // SessionID
    //
    if (BufferLength < sizeof(uint8_t) ||
        Buffer[0] > TLS_SESSION_ID_LENGTH ||
        BufferLength < sizeof(uint8_t) + Buffer[0]) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #3");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint8_t) + Buffer[0];
    Buffer += sizeof(uint8_t) + Buffer[0];

    //
    // CipherSuite
    //
    if (BufferLength < sizeof(uint16_t)) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #4");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    uint16_t Len = TlsReadUint16(Buffer);
    if ((Len % 2) || BufferLength < (uint32_t)(sizeof(uint16_t) + Len)) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #5");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t) + Len;
    Buffer += sizeof(uint16_t) + Len;

    //
    // CompressionMethod
    //
    if (BufferLength < sizeof(uint8_t) ||
        Buffer[0] < 1 ||
        BufferLength < sizeof(uint8_t) + Buffer[0]) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #6");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint8_t) + Buffer[0];
    Buffer += sizeof(uint8_t) + Buffer[0];

    //
    // Extension List (optional)
    //
    if (BufferLength < sizeof(uint16_t)) {
        return QUIC_STATUS_SUCCESS; // OK to not have any more.
    }
    Len = TlsReadUint16(Buffer);
    if (BufferLength < (uint32_t)(sizeof(uint16_t) + Len)) {
        QuicTraceEvent(ConnError, Connection, "Parse error. ReadTlsClientHello #7");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    return
        QuicCryptoTlsReadExtensions(
            Connection,
            Buffer + sizeof(uint16_t),
            Len,
            Info);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicCrytpoTlsGetCompleteTlsMessagesLength(
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    uint32_t MessagesLength = 0;

    do {
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH) {
            break;
        }

        uint32_t MessageLength =
            TLS_MESSAGE_HEADER_LENGTH + TlsReadUint24(Buffer + 1);
        if (BufferLength < MessageLength) {
            break;
        }

        MessagesLength += MessageLength;
        Buffer += MessageLength;
        BufferLength -= MessageLength;

    } while (BufferLength > 0);

    return MessagesLength;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadInitial(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint32_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    do {
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH) {
            return QUIC_STATUS_PENDING;
        }

        if (Buffer[0] != TlsHandshake_ClientHello) {
            QuicTraceEvent(ConnError, Connection, "Invalid message in TlsReadInitial");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        uint32_t MessageLength = TlsReadUint24(Buffer + 1);
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH + MessageLength) {
            return QUIC_STATUS_PENDING;
        }

        QUIC_STATUS Status =
            QuicCryptoTlsReadClientHello(
                Connection,
                Buffer + TLS_MESSAGE_HEADER_LENGTH,
                MessageLength,
                Info);
        if (QUIC_FAILED(Status)) {
            return Status;
        }

        BufferLength -= MessageLength + TLS_MESSAGE_HEADER_LENGTH;
        Buffer += MessageLength + TLS_MESSAGE_HEADER_LENGTH;

    } while (BufferLength > 0);

    if (Info->AlpnList == NULL) {
        QuicTraceEvent(ConnError, Connection, "No ALPN list extension present");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Info->ServerName == NULL) {
        QuicTraceLogConnWarning(NoSniPresent, Connection, "No SNI extension present.");
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicCryptoTlsEncodeTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_TRANSPORT_PARAMETERS *TransportParams,
    _Out_ uint32_t* TPLen
    )
{
    //
    // Precompute the required size so we can allocate all at once.
    //

    QuicTraceLogConnVerbose(EncodeTPStart, Connection, "Encoding Transport Parameters");

    size_t RequiredTPLen = 0;
    if (TransportParams->Flags & QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_FRE_ASSERT(TransportParams->OriginalConnectionIDLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ORIGINAL_CONNECTION_ID,
                TransportParams->OriginalConnectionIDLength);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_IDLE_TIMEOUT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_IDLE_TIMEOUT,
                QuicVarIntSize(TransportParams->IdleTimeout));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_STATELESS_RESET_TOKEN,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_PACKET_SIZE) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_MAX_PACKET_SIZE,
                QuicVarIntSize(TransportParams->MaxPacketSize));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_DATA) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_DATA,
                QuicVarIntSize(TransportParams->InitialMaxData));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                QuicVarIntSize(TransportParams->InitialMaxStreamDataBidiLocal));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                QuicVarIntSize(TransportParams->InitialMaxStreamDataBidiRemote));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
                QuicVarIntSize(TransportParams->InitialMaxStreamDataUni));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI,
                QuicVarIntSize(TransportParams->InitialMaxBidiStreams));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI,
                QuicVarIntSize(TransportParams->InitialMaxUniStreams));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACK_DELAY_EXPONENT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ACK_DELAY_EXPONENT,
                QuicVarIntSize(TransportParams->AckDelayExponent));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_ACK_DELAY) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_MAX_ACK_DELAY,
                QuicVarIntSize(TransportParams->MaxAckDelay));
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION,
                0);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_FRE_ASSERT(FALSE); // TODO - Implement
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        RequiredTPLen +=
            TlsTransportParamLength(
                QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
                QuicVarIntSize(TransportParams->ActiveConnectionIdLimit));
    }
    if (Connection->State.TestTransportParameterSet) {
        RequiredTPLen +=
            TlsTransportParamLength(
                Connection->TestTransportParameter.Type,
                Connection->TestTransportParameter.Length);
    }

    QUIC_TEL_ASSERT(RequiredTPLen <= UINT16_MAX);
    if (RequiredTPLen > UINT16_MAX) {
        QuicTraceEvent(ConnError, Connection, "Encoding TP too big.");
        return NULL;
    }

    uint8_t* TPBufBase = QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + RequiredTPLen);
    if (TPBufBase == NULL) {
        QuicTraceEvent(AllocFailure, "TP buffer", QuicTlsTPHeaderSize + RequiredTPLen);
        return NULL;
    }

    *TPLen = (uint32_t)(QuicTlsTPHeaderSize + RequiredTPLen);
    uint8_t* TPBuf = TPBufBase + QuicTlsTPHeaderSize;

    //
    // Now that we have allocated the exact size, we can freely write to the
    // buffer without checking any more lengths.
    //

    if (TransportParams->Flags & QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_ORIGINAL_CONNECTION_ID,
                TransportParams->OriginalConnectionIDLength,
                TransportParams->OriginalConnectionID,
                TPBuf);
        QuicTraceLogConnVerbose(EncodeTPOriginalCID, Connection, "TP: Original Connection ID");
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_IDLE_TIMEOUT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_IDLE_TIMEOUT,
                TransportParams->IdleTimeout, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPIdleTimeout, Connection, "TP: Idle Timeout (%llu ms)", TransportParams->IdleTimeout);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_STATELESS_RESET_TOKEN,
                QUIC_STATELESS_RESET_TOKEN_LENGTH,
                TransportParams->StatelessResetToken,
                TPBuf);
        QuicTraceLogConnVerbose(EncodeTPStatelessResetToken, Connection, "TP: Stateless Reset Token (%s)",
            QuicCidBufToStr(
                TransportParams->StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_PACKET_SIZE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_PACKET_SIZE,
                TransportParams->MaxPacketSize, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPMaxPacketSize, Connection, "TP: Max Packet Size (%llu bytes)", TransportParams->MaxPacketSize);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_DATA) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_DATA,
                TransportParams->InitialMaxData, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPInitMaxData, Connection, "TP: Max Data (%llu bytes)", TransportParams->InitialMaxData);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                TransportParams->InitialMaxStreamDataBidiLocal, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPInitMaxStreamDataBidiLocal, Connection, "TP: Max Local Bidirectional Stream Data (%llu bytes)", TransportParams->InitialMaxStreamDataBidiLocal);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                TransportParams->InitialMaxStreamDataBidiRemote, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPInitMaxStreamDataBidiRemote, Connection, "TP: Max Remote Bidirectional Stream Data (%llu bytes)", TransportParams->InitialMaxStreamDataBidiRemote);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
                TransportParams->InitialMaxStreamDataUni, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPInitMaxStreamUni, Connection, "TP: Max Unidirectional Stream Data (%llu)", TransportParams->InitialMaxStreamDataUni);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI,
                TransportParams->InitialMaxBidiStreams, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPMaxBidiStreams, Connection, "TP: Max Bidirectional Streams (%llu)", TransportParams->InitialMaxBidiStreams);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI,
                TransportParams->InitialMaxUniStreams, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPMaxUniStreams, Connection, "TP: Max Unidirectional Streams (%llu)", TransportParams->InitialMaxUniStreams);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACK_DELAY_EXPONENT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ACK_DELAY_EXPONENT,
                TransportParams->AckDelayExponent, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPAckDelayExponent, Connection, "TP: ACK Delay Exponent (%llu)", TransportParams->AckDelayExponent);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_ACK_DELAY) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_ACK_DELAY,
                TransportParams->MaxAckDelay, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPMaxAckDelay, Connection, "TP: Max ACK Delay (%llu ms)", TransportParams->MaxAckDelay);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION,
                0,
                NULL,
                TPBuf);
        QuicTraceLogConnVerbose(EncodeTPDisableMigration, Connection, "TP: Disable Active Migration");
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_FRE_ASSERT(FALSE); // TODO - Implement
        QuicTraceLogConnVerbose(EncodeTPPreferredAddress, Connection, "TP: Preferred Address");
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
                TransportParams->ActiveConnectionIdLimit, TPBuf);
        QuicTraceLogConnVerbose(EncodeTPCIDLimit, Connection, "TP: Connection ID Limit (%llu)", TransportParams->ActiveConnectionIdLimit);
    }
    if (Connection->State.TestTransportParameterSet) {
        TPBuf =
            TlsWriteTransportParam(
                Connection->TestTransportParameter.Type,
                Connection->TestTransportParameter.Length,
                Connection->TestTransportParameter.Buffer,
                TPBuf);
        QuicTraceLogConnVerbose(EncodeTPTest, Connection, "TP: TEST TP (Type %hu, Length %hu)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);
    }

    size_t FinalTPLength = (TPBuf - (TPBufBase + QuicTlsTPHeaderSize));
    if (FinalTPLength != RequiredTPLen) {
        QuicTraceEvent(ConnError, Connection, "Encoding error! Length mismatch.");
        QUIC_TEL_ASSERT(FinalTPLength == RequiredTPLen);
        QUIC_FREE(TPBufBase);
        return NULL;
    } else {
        QuicTraceLogConnVerbose(EncodeTPEnd, Connection, "Encoded %hu bytes for QUIC TP", (uint16_t)FinalTPLength);
    }

    return TPBufBase;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoTlsDecodeTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(TPLen)
        const uint8_t* TPBuf,
    _In_ uint16_t TPLen,
    _Out_ QUIC_TRANSPORT_PARAMETERS* TransportParams
    )
{
    BOOLEAN Result = FALSE;
    uint32_t ParamsPresent = 0;
    uint16_t Offset = 0;

    QuicZeroMemory(TransportParams, sizeof(QUIC_TRANSPORT_PARAMETERS));
    TransportParams->MaxPacketSize = QUIC_TP_MAX_PACKET_SIZE_MAX;
    TransportParams->AckDelayExponent = QUIC_DEFAULT_ACK_DELAY_EXPONENT;
    TransportParams->MaxAckDelay = QUIC_TP_MAX_ACK_DELAY_DEFAULT;

    QuicTraceLogConnVerbose(DecodeTPStart, Connection, "Decoding Peer Transport Parameters (%hu bytes)", TPLen);

    while (Offset < TPLen) {

        QUIC_VAR_INT Id;
        if (!QuicVarIntDecode(TPLen, TPBuf, &Offset, &Id)) {
            QuicTraceEvent(ConnError, Connection, "No room for QUIC TP ID");
            goto Exit;
        }

        if (Id <= QUIC_TP_ID_MAX) {

            if (ParamsPresent & (1 << Id)) {
                QuicTraceEvent(ConnError, Connection, "Duplicate QUIC TP ID");
                goto Exit;
            }

            ParamsPresent |= (1 << Id);
        }

        QUIC_VAR_INT ParamLength;
        if (!QuicVarIntDecode(TPLen, TPBuf, &Offset, &ParamLength)) {
            QuicTraceEvent(ConnError, Connection, "No room for QUIC TP length");
            goto Exit;
        } else if (ParamLength + Offset > TPLen) {
            QuicTraceEvent(ConnError, Connection, "QUIC TP length too big");
            goto Exit;
        }

        uint16_t Length = (uint16_t)ParamLength;;

        uint16_t VarIntLength = 0;
    #define TRY_READ_VAR_INT(Param) \
        QuicVarIntDecode(Length, TPBuf + Offset, &VarIntLength, &Param)

        switch (Id) {

        case QUIC_TP_ID_ORIGINAL_CONNECTION_ID:
            if (Length > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_ORIGINAL_CONNECTION_ID");
                goto Exit;
            } else if (QuicConnIsServer(Connection)) {
                QuicTraceEvent(ConnError, Connection, "Client incorrectly provided original connection ID");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID;
            TransportParams->OriginalConnectionIDLength = (uint8_t)Length;
            QuicCopyMemory(
                TransportParams->OriginalConnectionID,
                TPBuf + Offset,
                Length);
            QuicTraceLogConnVerbose(DecodeTPOriginalCID, Connection, "TP: Original Connection ID");
            break;

        case QUIC_TP_ID_IDLE_TIMEOUT:
            if (!TRY_READ_VAR_INT(TransportParams->IdleTimeout)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_ORIGINAL_CONNECTION_ID");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
            QuicTraceLogConnVerbose(DecodeTPIdleTimeout, Connection, "TP: Idle Timeout (%llu ms)", TransportParams->IdleTimeout);
            break;

        case QUIC_TP_ID_STATELESS_RESET_TOKEN:
            if (Length != QUIC_STATELESS_RESET_TOKEN_LENGTH) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_ORIGINAL_CONNECTION_ID");
                goto Exit;
            } else if (QuicConnIsServer(Connection)) {
                QuicTraceEvent(ConnError, Connection, "Client incorrectly provided stateless reset token");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
            QuicCopyMemory(
                TransportParams->StatelessResetToken,
                TPBuf + Offset,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
            QuicTraceLogConnVerbose(DecodeTPStatelessResetToken, Connection, "TP: Stateless Reset Token (%s)",
                QuicCidBufToStr(
                    TransportParams->StatelessResetToken,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
            break;

        case QUIC_TP_ID_MAX_PACKET_SIZE:
            if (!TRY_READ_VAR_INT(TransportParams->MaxPacketSize)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_MAX_PACKET_SIZE");
                goto Exit;
            }
            if (TransportParams->MaxPacketSize < QUIC_TP_MAX_PACKET_SIZE_MIN) {
                QuicTraceEvent(ConnError, Connection, "TP MaxPacketSize too small");
                goto Exit;
            }
            if (TransportParams->MaxPacketSize > QUIC_TP_MAX_PACKET_SIZE_MAX) {
                QuicTraceEvent(ConnError, Connection, "TP MaxPacketSize too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_PACKET_SIZE;
            QuicTraceLogConnVerbose(DecodeTPMaxPacketSize, Connection, "TP: Max Packet Size (%llu bytes)", TransportParams->MaxPacketSize);
            break;

        case QUIC_TP_ID_INITIAL_MAX_DATA:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxData)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_DATA");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_DATA;
            QuicTraceLogConnVerbose(DecodeTPInitMaxData, Connection, "TP: Max Data (%llu bytes)", TransportParams->InitialMaxData);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataBidiLocal)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL");
                goto Exit;
            }
            if (TransportParams->InitialMaxStreamDataBidiLocal > QUIC_TP_MAX_MAX_STREAMS) {
                QuicTraceEvent(ConnError, Connection, "TP InitialMaxStreamDataBidiLocal too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL;
            QuicTraceLogConnVerbose(DecodeTPInitMaxStreamDataBidiLocal, Connection, "TP: Max Local Bidirectional Stream Data (%llu bytes)", TransportParams->InitialMaxStreamDataBidiLocal);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataBidiRemote)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE");
                goto Exit;
            }
            if (TransportParams->InitialMaxStreamDataBidiRemote > QUIC_TP_MAX_MAX_STREAMS) {
                QuicTraceEvent(ConnError, Connection, "TP InitialMaxStreamDataBidiRemote too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE;
            QuicTraceLogConnVerbose(DecodeTPInitMaxStreamDataBidiRemote, Connection, "TP: Max Remote Bidirectional Stream Data (%llu bytes)", TransportParams->InitialMaxStreamDataBidiRemote);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataUni)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI");
                goto Exit;
            }
            if (TransportParams->InitialMaxStreamDataUni > QUIC_TP_MAX_MAX_STREAMS) {
                QuicTraceEvent(ConnError, Connection, "TP InitialMaxStreamDataUni too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI;
            QuicTraceLogConnVerbose(DecodeTPInitMaxStreamDataBidiUni, Connection, "TP: Max Unidirectional Stream Data (%llu)", TransportParams->InitialMaxStreamDataUni);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxBidiStreams)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            QuicTraceLogConnVerbose(DecodeTPMaxBidiStreams, Connection, "TP: Max Bidirectional Streams (%llu)", TransportParams->InitialMaxBidiStreams);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxUniStreams)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            QuicTraceLogConnVerbose(DecodeTPMaxUniStreams, Connection, "TP: Max Unidirectional Streams (%llu)", TransportParams->InitialMaxUniStreams);
            break;

        case QUIC_TP_ID_ACK_DELAY_EXPONENT:
            if (!TRY_READ_VAR_INT(TransportParams->AckDelayExponent)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_MAX_ACK_DELAY_EXPONENT");
                goto Exit;
            }
            if (TransportParams->AckDelayExponent > QUIC_TP_MAX_ACK_DELAY_EXPONENT) {
                QuicTraceEvent(ConnError, Connection, "Invalid value of QUIC_TP_MAX_ACK_DELAY_EXPONENT");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
            QuicTraceLogConnVerbose(DecodeTPAckDelayExponent, Connection, "TP: ACK Delay Exponent (%llu)", TransportParams->AckDelayExponent);
            break;

        case QUIC_TP_ID_MAX_ACK_DELAY:
            if (!TRY_READ_VAR_INT(TransportParams->MaxAckDelay)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_MAX_MAX_ACK_DELAY");
                goto Exit;
            }
            if (TransportParams->MaxAckDelay > QUIC_TP_MAX_MAX_ACK_DELAY) {
                QuicTraceEvent(ConnError, Connection, "Invalid value of QUIC_TP_MAX_MAX_ACK_DELAY");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_ACK_DELAY;
            QuicTraceLogConnVerbose(DecodeTPMaxAckDelay, Connection, "TP: Max ACK Delay (%llu ms)", TransportParams->MaxAckDelay);
            break;

        case QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION:
            if (Length != 0) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION;
            QuicTraceLogConnVerbose(DecodeTPDisableActiveMigration, Connection, "TP: Disable Active Migration");
            break;

        case QUIC_TP_ID_PREFERRED_ADDRESS:
            if (QuicConnIsServer(Connection)) {
                QuicTraceEvent(ConnError, Connection, "Client incorrectly provided preferred address");
                goto Exit;
            }
            QuicTraceLogConnVerbose(DecodeTPPreferredAddress, Connection, "TP: Preferred Address");
            // TODO - Implement
            break;

        case QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT:
            if (!TRY_READ_VAR_INT(TransportParams->ActiveConnectionIdLimit)) {
                QuicTraceEvent(ConnErrorStatus, Connection, Length, "Invalid length of QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;
            QuicTraceLogConnVerbose(DecodeTPCIDLimit, Connection, "TP: Connection ID Limit (%llu)", TransportParams->ActiveConnectionIdLimit);
            break;

        default:
            if (QuicTpIdIsReserved(Id)) {
                QuicTraceLogConnWarning(DecodeTPReserved, Connection, "TP: Reserved ID %llu, length %hu", Id, Length);
            } else {
                QuicTraceLogConnWarning(DecodeTPUnknown, Connection, "TP: Unknown ID %llu, length %hu", Id, Length);
            }
            break;
        }

        Offset += Length;
    }

    Result = TRUE;

Exit:

    return Result;
}
