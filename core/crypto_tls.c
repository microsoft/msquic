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
    _In_ uint16_t ID
    )
{
    //
    // Per spec: Transport parameters with an identifier of the form "31 * N + 27"
    // for integer values of N are reserved to exercise the requirement that
    // unknown transport parameters be ignored.
    //
    return (ID % 31) == 27;
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
// The following functions encode data in the TLS extension format. This format
// consists of a uint16_t (network byte order) for the 'ID', a uint16_t (network
// byte order) for the 'Length', and then 'Length' bytes of data.
//

#define TLS_HDR_SIZE (sizeof(uint16_t) + sizeof(uint16_t))

static
uint8_t*
TlsWriteTransportParam(
    _In_ uint16_t Id,
    _In_ uint16_t Length,
    _In_reads_bytes_opt_(Length) const uint8_t* Param,
    _Out_writes_bytes_(TLS_HDR_SIZE + Length) uint8_t* Buffer
    )
{
    *((uint16_t*)Buffer) = QuicByteSwapUint16(Id);
    *((uint16_t*)(Buffer + sizeof(uint16_t))) = QuicByteSwapUint16(Length);
    QUIC_DBG_ASSERT(Param != NULL || Length == 0);
    if (Param) {
        QuicCopyMemory(Buffer + TLS_HDR_SIZE, Param, Length);
    }
    return Buffer + TLS_HDR_SIZE + Length;
}

static
uint8_t*
TlsWriteTransportParamVarInt(
    _In_ uint16_t Id,
    _In_ QUIC_VAR_INT Value,
    _When_(Value < 0x40, _Out_writes_bytes_(TLS_HDR_SIZE + sizeof(uint8_t)))
    _When_(Value >= 0x40 && Value < 0x4000, _Out_writes_bytes_(TLS_HDR_SIZE + sizeof(uint16_t)))
    _When_(Value >= 0x4000 && Value < 0x40000000, _Out_writes_bytes_(TLS_HDR_SIZE + sizeof(uint32_t)))
    _When_(Value >= 0x40000000, _Out_writes_bytes_(TLS_HDR_SIZE + sizeof(uint64_t)))
        uint8_t* Buffer
    )
{
    *((uint16_t*)Buffer) = QuicByteSwapUint16(Id);
    *((uint16_t*)(Buffer + sizeof(uint16_t))) =
        QuicByteSwapUint16(QuicVarIntSize(Value));
    return QuicVarIntEncode(Value, Buffer + TLS_HDR_SIZE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadSniExtension(
    _In_ PQUIC_CONNECTION Connection,
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
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsSni #1");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // We need at least 3 bytes to encode NameType(1) and empty HostName(2)
    //
    if (TlsReadUint16(Buffer) < 3) {
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsSni #2");
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
            EventWriteQuicConnError(Connection, "Parse error. ReadTlsSni #3");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        uint16_t NameLen = TlsReadUint16(Buffer);
        BufferLength -= 2;
        Buffer += 2;
        if (BufferLength < NameLen) {
            EventWriteQuicConnError(Connection, "Parse error. ReadTlsSni #4");
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
    _In_ PQUIC_CONNECTION Connection,
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
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsAlpn #1");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (BufferLength != TlsReadUint16(Buffer) + sizeof(uint16_t)) {
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsAlpn #2");
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
            EventWriteQuicConnError(Connection, "Parse error. ReadTlsAlpn #3");
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
    _In_ PQUIC_CONNECTION Connection,
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
            EventWriteQuicConnError(Connection, "Parse error. ReadTlsExt #1");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        uint16_t ExtType = TlsReadUint16(Buffer);
        uint16_t ExtLen = TlsReadUint16(Buffer + sizeof(uint16_t));
        BufferLength -= 2 * sizeof(uint16_t);
        Buffer += 2 * sizeof(uint16_t);
        if (BufferLength < ExtLen) {
            EventWriteQuicConnError(Connection, "Parse error. ReadTlsExt #2");
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
    _In_ PQUIC_CONNECTION Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
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
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #1");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint16_t);
    Buffer += sizeof(uint16_t);

    //
    // Random
    //
    if (BufferLength < TLS_RANDOM_LENGTH) {
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #2");
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
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #3");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    BufferLength -= sizeof(uint8_t) + Buffer[0];
    Buffer += sizeof(uint8_t) + Buffer[0];

    //
    // CipherSuite
    //
    if (BufferLength < sizeof(uint16_t)) {
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #4");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    uint16_t Len = TlsReadUint16(Buffer);
    if ((Len % 2) || BufferLength < sizeof(uint16_t) + Len) {
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #5");
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
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #6");
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
    if (BufferLength < sizeof(uint16_t) + Len) {
        EventWriteQuicConnError(Connection, "Parse error. ReadTlsClientHello #7");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    return
        QuicCryptoTlsReadExtensions(
            Connection,
            Buffer + sizeof(uint16_t),
            Len,
            Info);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicCryptoTlsReadInitial(
    _In_ PQUIC_CONNECTION Connection,
    _In_reads_(BufferLength)
        const uint8_t* Buffer,
    _In_ uint16_t BufferLength,
    _Inout_ QUIC_NEW_CONNECTION_INFO* Info
    )
{
    do {
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH) {
            EventWriteQuicConnError(Connection, "Parse error. ServerPreprocess #1");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (Buffer[0] != TlsHandshake_ClientHello) {
            EventWriteQuicConnError(Connection, "Parse error. ServerPreprocess #2");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        uint32_t MessageLength = TlsReadUint24(Buffer + 1);
        if (BufferLength < TLS_MESSAGE_HEADER_LENGTH + MessageLength) {
            EventWriteQuicConnError(Connection, "Parse error. ServerPreprocess #3");
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        QUIC_STATUS Status =
            QuicCryptoTlsReadClientHello(
                Connection,
                Buffer + TLS_MESSAGE_HEADER_LENGTH,
                (uint16_t)MessageLength,
                Info);
        if (QUIC_FAILED(Status)) {
            return Status;
        }

        BufferLength -= (uint16_t)MessageLength + TLS_MESSAGE_HEADER_LENGTH;
        Buffer += (uint16_t)MessageLength + TLS_MESSAGE_HEADER_LENGTH;

    } while (BufferLength > 0);

    if (Info->AlpnList == NULL) {
        EventWriteQuicConnError(Connection, "No ALPN list extension present");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Info->ServerName == NULL) {
        LogWarning("[conn][%p] No SNI extension present.", Connection);
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
const uint8_t*
QuicCryptoTlsEncodeTransportParameters(
    _In_ PQUIC_CONNECTION Connection,
    _In_ const QUIC_TRANSPORT_PARAMETERS *TransportParams,
    _Out_ uint32_t* TPLen
    )
{
    //
    // Precompute the required size so we can allocate all at once.
    //

    LogVerbose("[conn][%p] Encoding Transport Parameters", Connection);

    size_t RequiredTPLen = sizeof(uint16_t); // Parameter list length
    if (TransportParams->Flags & QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_FRE_ASSERT(TransportParams->OriginalConnectionIDLength <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
        RequiredTPLen += TLS_HDR_SIZE + TransportParams->OriginalConnectionIDLength;
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_IDLE_TIMEOUT) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->IdleTimeout);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        RequiredTPLen += TLS_HDR_SIZE + QUIC_STATELESS_RESET_TOKEN_LENGTH;
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_PACKET_SIZE) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->MaxPacketSize);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_DATA) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->InitialMaxData);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->InitialMaxStreamDataBidiLocal);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->InitialMaxStreamDataBidiRemote);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->InitialMaxStreamDataUni);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->InitialMaxBidiStreams);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->InitialMaxUniStreams);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACK_DELAY_EXPONENT) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->AckDelayExponent);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_ACK_DELAY) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->MaxAckDelay);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION) {
        RequiredTPLen += TLS_HDR_SIZE;
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_FRE_ASSERT(FALSE); // TODO - Implement
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        RequiredTPLen += TLS_HDR_SIZE + QuicVarIntSize(TransportParams->ActiveConnectionIdLimit);
    }

    QUIC_TEL_ASSERT(RequiredTPLen <= UINT16_MAX);
    if (RequiredTPLen > UINT16_MAX) {
        LogWarning("[conn][%p] Encoding TP too big! 0x%u",
            Connection, (uint32_t)RequiredTPLen);
        return NULL;
    }

    uint8_t* TPBufBase = QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + RequiredTPLen);
    if (TPBufBase == NULL) {
        EventWriteQuicAllocFailure("TP buffer", QuicTlsTPHeaderSize + RequiredTPLen);
        return NULL;
    }

    *TPLen = (uint32_t)(QuicTlsTPHeaderSize + RequiredTPLen);
    uint8_t* TPBuf = TPBufBase + QuicTlsTPHeaderSize;

    //
    // Now that we have allocated the exact size, we can freely write to the
    // buffer without checking any more lengths.
    //

    *(uint16_t*)TPBuf = QuicByteSwapUint16((uint16_t)RequiredTPLen - sizeof(uint16_t));
    TPBuf += sizeof(uint16_t); // Parameter list length

    if (TransportParams->Flags & QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_ORIGINAL_CONNECTION_ID,
                TransportParams->OriginalConnectionIDLength,
                TransportParams->OriginalConnectionID,
                TPBuf);
        LogVerbose("[conn][%p] TP: Original Connection ID", Connection);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_IDLE_TIMEOUT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_IDLE_TIMEOUT,
                TransportParams->IdleTimeout, TPBuf);
        LogVerbose("[conn][%p] TP: Idle Timeout (%llu ms)", Connection, TransportParams->IdleTimeout);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_STATELESS_RESET_TOKEN,
                QUIC_STATELESS_RESET_TOKEN_LENGTH,
                TransportParams->StatelessResetToken,
                TPBuf);
        LogVerbose("[conn][%p] TP: Stateless Reset Token (%s)", Connection,
            QuicCidBufToStr(
                TransportParams->StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_PACKET_SIZE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_PACKET_SIZE,
                TransportParams->MaxPacketSize, TPBuf);
        LogVerbose("[conn][%p] TP: Max Packet Size (%llu bytes)", Connection, TransportParams->MaxPacketSize);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_DATA) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_DATA,
                TransportParams->InitialMaxData, TPBuf);
        LogVerbose("[conn][%p] TP: Max Data (%llu bytes)", Connection, TransportParams->InitialMaxData);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                TransportParams->InitialMaxStreamDataBidiLocal, TPBuf);
        LogVerbose("[conn][%p] TP: Max Local Bidirectional Stream Data (%llu bytes)", Connection, TransportParams->InitialMaxStreamDataBidiLocal);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                TransportParams->InitialMaxStreamDataBidiRemote, TPBuf);
        LogVerbose("[conn][%p] TP: Max Remote Bidirectional Stream Data (%llu bytes)", Connection, TransportParams->InitialMaxStreamDataBidiRemote);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
                TransportParams->InitialMaxStreamDataUni, TPBuf);
        LogVerbose("[conn][%p] TP: Max Unidirectional Stream Data (%llu)", Connection, TransportParams->InitialMaxStreamDataUni);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI,
                TransportParams->InitialMaxBidiStreams, TPBuf);
        LogVerbose("[conn][%p] TP: Max Bidirectional Streams (%llu)", Connection, TransportParams->InitialMaxBidiStreams);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI,
                TransportParams->InitialMaxUniStreams, TPBuf);
        LogVerbose("[conn][%p] TP: Max Unidirectional Streams (%llu)", Connection, TransportParams->InitialMaxUniStreams);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACK_DELAY_EXPONENT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ACK_DELAY_EXPONENT,
                TransportParams->AckDelayExponent, TPBuf);
        LogVerbose("[conn][%p] TP: ACK Delay Exponent (%llu)", Connection, TransportParams->AckDelayExponent);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_MAX_ACK_DELAY) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_MAX_ACK_DELAY,
                TransportParams->MaxAckDelay, TPBuf);
        LogVerbose("[conn][%p] TP: Max ACK Delay (%llu ms)", Connection, TransportParams->MaxAckDelay);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION) {
        TPBuf =
            TlsWriteTransportParam(
                QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION,
                0,
                NULL,
                TPBuf);
        LogVerbose("[conn][%p] TP: Disable Active Migration", Connection);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
        QUIC_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_FRE_ASSERT(FALSE); // TODO - Implement
        LogVerbose("[conn][%p] TP: Preferred Address", Connection);
    }
    if (TransportParams->Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) {
        TPBuf =
            TlsWriteTransportParamVarInt(
                QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
                TransportParams->ActiveConnectionIdLimit, TPBuf);
        LogVerbose("[conn][%p] TP: Connection ID Limit (%llu)", Connection, TransportParams->ActiveConnectionIdLimit);
    }

    size_t FinalTPLength = (TPBuf - (TPBufBase + QuicTlsTPHeaderSize));
    if (FinalTPLength != RequiredTPLen) {
        LogWarning("[conn][%p] Encoding error! Length mismatch, %hu vs %hu",
            Connection, (uint16_t)FinalTPLength, (uint16_t)RequiredTPLen);
        QUIC_TEL_ASSERT(FinalTPLength == RequiredTPLen);
        QUIC_FREE(TPBufBase);
        return NULL;
    } else {
        LogVerbose("[conn][%p] Encoded %hu bytes for QUIC TP",
            Connection, (uint16_t)FinalTPLength);
    }

    return TPBufBase;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicCryptoTlsDecodeTransportParameters(
    _In_ PQUIC_CONNECTION Connection,
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

    LogVerbose("[conn][%p] Decoding Peer Transport Parameters (%hu bytes)", Connection, TPLen);

    if (TPLen < sizeof(uint16_t)) {
        EventWriteQuicConnError(Connection, "Invalid length for QUIC TP param list length");
        goto Exit;
    }
    uint16_t TPParamListLen = QuicByteSwapUint16(*(uint16_t*)(TPBuf));
    Offset += sizeof(uint16_t);

    if (Offset + TPParamListLen > TPLen) {
        EventWriteQuicConnError(Connection, "QUIC TP param list length too large");
        goto Exit;
    }

    while (Offset < TPLen) {

        //
        // Validate there is enough space to read the next ID and length.
        //
        if (Offset + TLS_HDR_SIZE > TPLen) {
            EventWriteQuicConnError(Connection, "QUIC TP params invalid leftover length");
            goto Exit;
        }

        //
        // Decode the next 2 bytes as the ID.
        //
        uint16_t Id = QuicByteSwapUint16(*(uint16_t*)(TPBuf + Offset));
        Offset += sizeof(uint16_t);

        if (Id <= QUIC_TP_ID_MAX) {

            if (ParamsPresent & (1 << Id)) {
                EventWriteQuicConnErrorStatus(Connection, Id, "Duplicate QUIC TP type");
                goto Exit;
            }

            ParamsPresent |= (1 << Id);
        }

        //
        // Decode the next 2 bytes as the length.
        //
        uint16_t Length = QuicByteSwapUint16(*(uint16_t*)(TPBuf + Offset));
        Offset += sizeof(uint16_t);

        //
        // Validate there is enough space for the actual value to be read.
        //
        if (Offset + Length > TPLen) {
            EventWriteQuicConnErrorStatus(Connection, Id, "QUIC TP value length too long");
            goto Exit;
        }

        uint16_t VarIntLength = 0;
    #define TRY_READ_VAR_INT(Param) \
        QuicVarIntDecode(Length, TPBuf + Offset, &VarIntLength, &Param)

        switch (Id) {

        case QUIC_TP_ID_ORIGINAL_CONNECTION_ID:
            if (Length > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_ORIGINAL_CONNECTION_ID");
                goto Exit;
            } else if (QuicConnIsServer(Connection)) {
                EventWriteQuicConnError(Connection, "Client incorrectly provided original connection ID");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ORIGINAL_CONNECTION_ID;
            TransportParams->OriginalConnectionIDLength = (uint8_t)Length;
            QuicCopyMemory(
                TransportParams->OriginalConnectionID,
                TPBuf + Offset,
                Length);
            LogVerbose("[conn][%p] TP: Original Connection ID", Connection);
            break;

        case QUIC_TP_ID_IDLE_TIMEOUT:
            if (!TRY_READ_VAR_INT(TransportParams->IdleTimeout)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_ORIGINAL_CONNECTION_ID");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
            LogVerbose("[conn][%p] TP: Idle Timeout (%llu ms)", Connection, TransportParams->IdleTimeout);
            break;

        case QUIC_TP_ID_STATELESS_RESET_TOKEN:
            if (Length != QUIC_STATELESS_RESET_TOKEN_LENGTH) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_ORIGINAL_CONNECTION_ID");
                goto Exit;
            } else if (QuicConnIsServer(Connection)) {
                EventWriteQuicConnError(Connection, "Client incorrectly provided stateless reset token");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
            QuicCopyMemory(
                TransportParams->StatelessResetToken,
                TPBuf + Offset,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
            LogVerbose("[conn][%p] TP: Stateless Reset Token (%s)", Connection,
                QuicCidBufToStr(
                    TransportParams->StatelessResetToken,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
            break;

        case QUIC_TP_ID_MAX_PACKET_SIZE:
            if (!TRY_READ_VAR_INT(TransportParams->MaxPacketSize)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_MAX_PACKET_SIZE");
                goto Exit;
            }
            if (TransportParams->MaxPacketSize < QUIC_TP_MAX_PACKET_SIZE_MIN) {
                EventWriteQuicConnError(Connection, "TP MaxPacketSize too small");
                goto Exit;
            }
            if (TransportParams->MaxPacketSize > QUIC_TP_MAX_PACKET_SIZE_MAX) {
                EventWriteQuicConnError(Connection, "TP MaxPacketSize too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_PACKET_SIZE;
            LogVerbose("[conn][%p] TP: Max Packet Size (%llu bytes)", Connection, TransportParams->MaxPacketSize);
            break;

        case QUIC_TP_ID_INITIAL_MAX_DATA:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxData)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_DATA");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_DATA;
            LogVerbose("[conn][%p] TP: Max Data (%llu bytes)", Connection, TransportParams->InitialMaxData);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataBidiLocal)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL");
                goto Exit;
            }
            if (TransportParams->InitialMaxStreamDataBidiLocal > QUIC_TP_MAX_MAX_STREAMS) {
                EventWriteQuicConnError(Connection, "TP InitialMaxStreamDataBidiLocal too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL;
            LogVerbose("[conn][%p] TP: Max Local Bidirectional Stream Data (%llu bytes)", Connection, TransportParams->InitialMaxStreamDataBidiLocal);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataBidiRemote)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE");
                goto Exit;
            }
            if (TransportParams->InitialMaxStreamDataBidiRemote > QUIC_TP_MAX_MAX_STREAMS) {
                EventWriteQuicConnError(Connection, "TP InitialMaxStreamDataBidiRemote too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE;
            LogVerbose("[conn][%p] TP: Max Remote Bidirectional Stream Data (%llu bytes)", Connection, TransportParams->InitialMaxStreamDataBidiRemote);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxStreamDataUni)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAM_DATA_UNI");
                goto Exit;
            }
            if (TransportParams->InitialMaxStreamDataUni > QUIC_TP_MAX_MAX_STREAMS) {
                EventWriteQuicConnError(Connection, "TP InitialMaxStreamDataUni too big");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI;
            LogVerbose("[conn][%p] TP: Max Unidirectional Stream Data (%llu)", Connection, TransportParams->InitialMaxStreamDataUni);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxBidiStreams)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAMS_BIDI");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LogVerbose("[conn][%p] TP: Max Bidirectional Streams (%llu)", Connection, TransportParams->InitialMaxBidiStreams);
            break;

        case QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI:
            if (!TRY_READ_VAR_INT(TransportParams->InitialMaxUniStreams)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_INITIAL_MAX_STREAMS_UNI");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LogVerbose("[conn][%p] TP: Max Unidirectional Streams (%llu)", Connection, TransportParams->InitialMaxUniStreams);
            break;

        case QUIC_TP_ID_ACK_DELAY_EXPONENT:
            if (!TRY_READ_VAR_INT(TransportParams->AckDelayExponent)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_MAX_ACK_DELAY_EXPONENT");
                goto Exit;
            }
            if (TransportParams->AckDelayExponent > QUIC_TP_MAX_ACK_DELAY_EXPONENT) {
                EventWriteQuicConnError(Connection, "Invalid value of QUIC_TP_MAX_ACK_DELAY_EXPONENT");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
            LogVerbose("[conn][%p] TP: ACK Delay Exponent (%llu)", Connection, TransportParams->AckDelayExponent);
            break;

        case QUIC_TP_ID_MAX_ACK_DELAY:
            if (!TRY_READ_VAR_INT(TransportParams->MaxAckDelay)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_MAX_MAX_ACK_DELAY");
                goto Exit;
            }
            if (TransportParams->MaxAckDelay > QUIC_TP_MAX_MAX_ACK_DELAY) {
                EventWriteQuicConnError(Connection, "Invalid value of QUIC_TP_MAX_MAX_ACK_DELAY");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_MAX_ACK_DELAY;
            LogVerbose("[conn][%p] TP: Max ACK Delay (%llu ms)", Connection, TransportParams->MaxAckDelay);
            break;

        case QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION:
            if (Length != 0) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_DISABLE_ACTIVE_MIGRATION");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION;
            LogVerbose("[conn][%p] TP: Disable Active Migration", Connection);
            break;

        case QUIC_TP_ID_PREFERRED_ADDRESS:
            if (QuicConnIsServer(Connection)) {
                EventWriteQuicConnError(Connection, "Client incorrectly provided preferred address");
                goto Exit;
            }
            LogVerbose("[conn][%p] TP: Preferred Address", Connection);
            // TODO - Implement
            break;

        case QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT:
            if (!TRY_READ_VAR_INT(TransportParams->ActiveConnectionIdLimit)) {
                EventWriteQuicConnErrorStatus(Connection, Length, "Invalid length of QUIC_TP_ID_ACTIVE_CONNECTION_ID_LIMIT");
                goto Exit;
            }
            TransportParams->Flags |= QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;
            LogVerbose("[conn][%p] TP: Connection ID Limit (%llu)", Connection, TransportParams->ActiveConnectionIdLimit);
            break;

        default:
            if (QuicTpIdIsReserved(Id)) {
                LogWarning("[conn][%p] TP: Reserved ID %hu, length %hu",
                    Connection, Id, Length);
            } else {
                LogWarning("[conn][%p] TP: Unknown ID %hu, length %hu",
                    Connection, Id, Length);
            }
            break;
        }

        Offset += Length;
    }

    Result = TRUE;

Exit:

    return Result;
}
