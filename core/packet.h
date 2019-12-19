/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// The list of supported QUIC version numbers, in network byte order.
//
extern const uint32_t QuicSupportedVersionList[2];

//
// Version specific salts.
//

extern const uint8_t QuicInitialSaltVersion1[20];

//
// Prefixes used in packet logging.
// First array is client/server
// Second is TX/RX
//
extern const char PacketLogPrefix[2][2];

#define PtkConnPre(Connection) \
    (Connection == NULL ? '-' : (PacketLogPrefix[0][QuicConnIsServer(Connection)]))

#define PktRxPre(IsRx) PacketLogPrefix[1][IsRx]

#pragma pack(push)
#pragma pack(1)

//
// The layout invariant (not specific to a particular version) fields
// of a QUIC packet.
//
typedef struct QUIC_HEADER_INVARIANT {

    union {
        struct {
            uint8_t VARIANT : 7;
            uint8_t IsLongHeader : 1;
        };

        struct {
            uint8_t VARIANT : 7;
            uint8_t IsLongHeader : 1;
            uint32_t Version;
            uint8_t DestCIDLength;
            uint8_t DestCID[0];
            //uint8_t SourceCIDLength;
            //uint8_t SourceCID[SourceCIDLength];

        } LONG_HDR;

        struct {
            uint8_t VARIANT : 7;
            uint8_t IsLongHeader : 1;
            uint8_t DestCID[0];

        } SHORT_HDR;
    };

} QUIC_HEADER_INVARIANT;

#define MIN_INV_LONG_HDR_LENGTH (sizeof(QUIC_HEADER_INVARIANT) + sizeof(uint8_t))
#define MIN_INV_SHORT_HDR_LENGTH sizeof(uint8_t)

//
// Validates the invariant part of the packet. If valid, updates the receive
// context's CIDs if necessary.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateInvariant(
    _In_ const void* Owner, // Binding or Connection depending on state
    _Inout_ QUIC_RECV_PACKET* Packet,
    _In_ BOOLEAN IsBindingShared
    );

//
// The layout of the Version Negotation packet.
//
typedef struct QUIC_VERSION_NEGOTIATION_PACKET {

    uint8_t Unused : 7;
    uint8_t IsLongHeader : 1;
    uint32_t Version;
    uint8_t DestCIDLength;
    uint8_t DestCID[0];
    //uint8_t SourceCIDLength;
    //uint8_t SourceCID[SourceCIDLength];
    //uint32_t SupportedVersions[0];

} QUIC_VERSION_NEGOTIATION_PACKET;

#pragma pack(pop)

//
// The following are Version Depedentant structs and functions.
//

//
// Different types of Long Header packets.
//
typedef enum QUIC_LONG_HEADER_TYPE_V1 {

    QUIC_INITIAL                = 0,
    QUIC_0_RTT_PROTECTED        = 1,
    QUIC_HANDSHAKE              = 2,
    QUIC_RETRY                  = 3,

} QUIC_LONG_HEADER_TYPE_V1;

#pragma pack(push)
#pragma pack(1)

//
// Represents the long header format. All values in Network Byte order.
// The 4 least significant bits are protected by header protection.
//

typedef struct QUIC_LONG_HEADER_V1 {

    uint8_t PnLength        : 2;
    uint8_t Reserved        : 2;    // Must be 0.
    uint8_t Type            : 2;
    uint8_t FixedBit        : 1;    // Must be 1.
    uint8_t IsLongHeader    : 1;
    uint32_t Version;
    uint8_t DestCIDLength;
    uint8_t DestCID[0];
    //uint8_t SourceCIDLength;
    //uint8_t SourceCID[SourceCIDLength];
    //  QUIC_VAR_INT TokenLength;       {Initial}
    //  uint8_t Token[0];               {Initial}
    //QUIC_VAR_INT Length;
    //uint8_t PacketNumber[PnLength];
    //uint8_t Payload[0];

} QUIC_LONG_HEADER_V1;

//
// The minimum long header, in bytes.
//
#define MIN_LONG_HEADER_LENGTH_V1 \
( \
    sizeof(QUIC_LONG_HEADER_V1) + \
    sizeof(uint8_t) + \
    sizeof(uint8_t) + \
    4 * sizeof(uint8_t) \
)

//
// Represents the long header retry packet format. All values in Network Byte
// order.
//

typedef struct QUIC_RETRY_V1 {

    uint8_t UNUSED          : 4;
    uint8_t Type            : 2;
    uint8_t FixedBit        : 1;    // Must be 1.
    uint8_t IsLongHeader    : 1;
    uint32_t Version;
    uint8_t DestCIDLength;
    uint8_t DestCID[0];
    //uint8_t SourceCIDLength;
    //uint8_t SourceCID[SourceCIDLength];
    //uint8_t OrigDestCIDLength;
    //uint8_t OrigDestCID[OrigDestCIDLength];
    //uint8_t Token[*];

} QUIC_RETRY_V1;

//
// The minimum retry packet header, in bytes.
//
#define MIN_RETRY_HEADER_LENGTH_V1 \
( \
    sizeof(QUIC_RETRY_V1) + \
    2 * sizeof(uint8_t) \
)

//
// Represents the short header format. All values in Network Byte order.
// The 5 least significant bits are protected by header protection.
//
typedef struct QUIC_SHORT_HEADER_V1 {

    uint8_t PnLength        : 2;
    uint8_t KeyPhase        : 1;
    uint8_t Reserved        : 2;    // Must be 0.
    uint8_t SpinBit         : 1;
    uint8_t FixedBit        : 1;    // Must be 1.
    uint8_t IsLongHeader    : 1;
    uint8_t DestCID[0];             // Length depends on connection.
    //uint8_t PacketNumber[PnLength];
    //uint8_t Payload[0];

} QUIC_SHORT_HEADER_V1;

//
// Helper to calculate the length of the full short header, in bytes.
//
#define SHORT_HEADER_PACKET_NUMBER_V1(Header, DestCIDLen) \
    ((Header)->ConnectionID + DestCIDLen)
//
// The minimum short header, in bytes.
//
#define MIN_SHORT_HEADER_LENGTH_V1 \
( \
    sizeof(QUIC_SHORT_HEADER_V1) + \
    4 * sizeof(uint8_t) \
)

#pragma pack(pop)

//
// Returns TRUE for a handshake packet (non-0RTT long header).
//
inline
BOOLEAN
QuicPacketIsHandshake(
    _In_ const QUIC_HEADER_INVARIANT* Packet
    )
{
    if (!Packet->IsLongHeader) {
        return FALSE;
    }

    switch (Packet->LONG_HDR.Version) {
        case QUIC_VERSION_DRAFT_24:
        case QUIC_VERSION_MS_1:
            return ((QUIC_LONG_HEADER_V1*)Packet)->Type != QUIC_0_RTT_PROTECTED;
        default:
            return TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateLongHeaderV1(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ BOOLEAN IsServer,
    _Inout_ QUIC_RECV_PACKET* Packet,
    _Outptr_result_buffer_maybenull_(*TokenLength)
        const uint8_t** Token,
    _Out_ uint16_t* TokenLength
    );

//
// Decodes the retry token from an initial packet. Only call if a previous call
// to QuicPacketValidateLongHeaderV1 has already succeeded.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketDecodeRetryTokenV1(
    _In_ const QUIC_RECV_PACKET* const Packet,
    _Outptr_result_buffer_maybenull_(*TokenLength)
        const uint8_t** Token,
    _Out_ uint16_t* TokenLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateShortHeaderV1(
    _In_ const void* Owner, // Binding or Connection depending on state
    _Inout_ QUIC_RECV_PACKET* Packet
    );

inline
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPktNumEncode(
    _In_ uint64_t PacketNumber,
    _In_range_(1, 4)
        uint8_t PacketNumberLength,
    _Out_writes_bytes_(PacketNumberLength)
        uint8_t* Buffer
    )
{
    for (uint8_t i = 0; i < PacketNumberLength; i++) {
        Buffer[PacketNumberLength - i - 1] = ((uint8_t*)&PacketNumber)[i];
    }
}

inline
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPktNumDecode(
    _In_range_(1, 4)
        uint8_t PacketNumberLength,
    _In_reads_bytes_(PacketNumberLength)
        const uint8_t* Buffer,
    _Out_ uint64_t* PacketNumber
    )
{
    for (uint8_t i = 0; i < PacketNumberLength; i++) {
        ((uint8_t*)PacketNumber)[i] = Buffer[PacketNumberLength - i - 1];
    }
}

//
// Decompress a packet number based on the expected next packet number.
// A compressed packet number is just the lowest N bytes of the full packet
// number. To decompress the packet number, we do a bit of math to find the
// closest packet number to the next expected packet number, that has the
// given low bytes.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicPktNumDecompress(
    _In_ uint64_t ExpectedPacketNumber,
    _In_ uint64_t CompressedPacketNumber,
    _In_ uint8_t CompressedPacketNumberBytes
    )
{
    QUIC_DBG_ASSERT(CompressedPacketNumberBytes < 8);
    const uint64_t Mask = 0xFFFFFFFFFFFFFFFF << (8 * CompressedPacketNumberBytes);
    const uint64_t PacketNumberInc = (~Mask) + 1;
    uint64_t PacketNumber = (Mask & ExpectedPacketNumber) | CompressedPacketNumber;

    if (PacketNumber < ExpectedPacketNumber) {

        //
        // If our intermediate packet number is less than the expected packet
        // number, then we need see if we would be closer to 'next' high bit
        // packet number.
        //

        uint64_t High = ExpectedPacketNumber - PacketNumber;
        uint64_t Low = PacketNumberInc - High;
        if (Low < High) {
            PacketNumber += PacketNumberInc;
        }

    } else {

        //
        // If our intermediate packet number is greater than or equal to the
        // expected packet number, then we need see if we would be closer to
        // 'previous' high bit packet number.
        //

        uint64_t Low = PacketNumber - ExpectedPacketNumber;
        uint64_t High = PacketNumberInc - Low;
        if (High <= Low && PacketNumber >= PacketNumberInc) {
            PacketNumber -= PacketNumberInc;
        }
    }

    return PacketNumber;
}

//
// Encodes the long header fields.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != 0)
uint16_t
QuicPacketEncodeLongHeaderV1(
    _In_ uint32_t Version, // Allows for version negotiation forcing
    _In_ QUIC_LONG_HEADER_TYPE_V1 PacketType,
    _In_ const QUIC_CID* const DestCID,
    _In_ const QUIC_CID* const SourceCID,
    _In_ uint16_t TokenLength,
    _In_reads_opt_(TokenLength)
        const uint8_t* const Token,
    _In_ uint32_t PacketNumber,   // Host Byte order
    _In_ uint16_t BufferLength,
    _Out_writes_bytes_(BufferLength)
        uint8_t* Buffer,
    _Out_ uint16_t* PayloadLengthOffset,
    _Out_ uint8_t* PacketNumberLength
    )
{
    uint16_t RequiredBufferLength =
        sizeof(QUIC_LONG_HEADER_V1) +
        DestCID->Length +
        sizeof(uint8_t) +
        SourceCID->Length +
        sizeof(uint16_t) + // We always encode 2 bytes for the length.
        sizeof(uint32_t);  // We always encode 4 bytes for the packet number.
    if (PacketType == QUIC_INITIAL) {
        RequiredBufferLength += QuicVarIntSize(TokenLength) + TokenLength; // TokenLength
    }
    if (BufferLength < RequiredBufferLength) {
        return 0;
    }

    QUIC_LONG_HEADER_V1* Header = (QUIC_LONG_HEADER_V1*)Buffer;

    Header->IsLongHeader    = TRUE;
    Header->FixedBit        = 1;
    Header->Type            = PacketType;
    Header->Reserved        = 0;
    Header->PnLength        = sizeof(uint32_t) - 1;
    Header->Version         = Version;
    Header->DestCIDLength   = DestCID->Length;

    uint8_t *HeaderBuffer = Header->DestCID;
    if (DestCID->Length != 0) {
        memcpy(HeaderBuffer, DestCID->Data, DestCID->Length);
        HeaderBuffer += DestCID->Length;
    }
    *HeaderBuffer = SourceCID->Length;
    HeaderBuffer++;
    if (SourceCID->Length != 0) {
        memcpy(HeaderBuffer, SourceCID->Data, SourceCID->Length);
        HeaderBuffer += SourceCID->Length;
    }
    if (PacketType == QUIC_INITIAL) {
        HeaderBuffer = QuicVarIntEncode(TokenLength, HeaderBuffer);
        if (TokenLength != 0) {
            _Analysis_assume_(Token != NULL);
            memcpy(HeaderBuffer, Token, TokenLength);
            HeaderBuffer += TokenLength;
        }
    }
    *PayloadLengthOffset = (uint16_t)(HeaderBuffer - Buffer);
    HeaderBuffer += sizeof(uint16_t); // Skip PayloadLength.
    *(uint32_t*)HeaderBuffer = QuicByteSwapUint32(PacketNumber);
    *PacketNumberLength = sizeof(uint32_t);

    return RequiredBufferLength;
}

#define QuicPacketMaxBufferSizeForRetryV1() \
    MIN_RETRY_HEADER_LENGTH_V1 + \
    3 * QUIC_MAX_CONNECTION_ID_LENGTH_V1 + \
    sizeof(QUIC_RETRY_TOKEN_CONTENTS)

//
// Encodes the long header fields.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != 0)
uint16_t
QuicPacketEncodeRetryV1(
    _In_ uint32_t Version,
    _In_reads_(DestCIDLength) const uint8_t* const DestCID,
    _In_ uint8_t DestCIDLength,
    _In_reads_(SourceCIDLength) const uint8_t* const SourceCID,
    _In_ uint8_t SourceCIDLength,
    _In_reads_(OrigDestCIDLength) const uint8_t* const OrigDestCID,
    _In_ uint8_t OrigDestCIDLength,
    _In_ uint16_t TokenLength,
    _In_reads_(TokenLength)
        uint8_t* Token,
    _In_ uint16_t BufferLength,
    _Out_writes_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    uint16_t RequiredBufferLength =
        MIN_RETRY_HEADER_LENGTH_V1 +
        DestCIDLength +
        SourceCIDLength +
        OrigDestCIDLength +
        TokenLength;
    if (BufferLength < RequiredBufferLength) {
        return 0;
    }

    QUIC_RETRY_V1* Header = (QUIC_RETRY_V1*)Buffer;

    Header->IsLongHeader    = TRUE;
    Header->FixedBit        = 1;
    Header->Type            = QUIC_RETRY;
    Header->UNUSED          = 0;
    Header->Version         = Version;
    Header->DestCIDLength   = DestCIDLength;

    uint8_t *HeaderBuffer = Header->DestCID;
    if (DestCIDLength != 0) {
        memcpy(HeaderBuffer, DestCID, DestCIDLength);
        HeaderBuffer += DestCIDLength;
    }
    *HeaderBuffer = SourceCIDLength;
    HeaderBuffer++;
    if (SourceCIDLength != 0) {
        memcpy(HeaderBuffer, SourceCID, SourceCIDLength);
        HeaderBuffer += SourceCIDLength;
    }
    *HeaderBuffer = OrigDestCIDLength;
    HeaderBuffer++;
    if (OrigDestCIDLength != 0) {
        memcpy(HeaderBuffer, OrigDestCID, OrigDestCIDLength);
        HeaderBuffer += OrigDestCIDLength;
    }
    if (TokenLength != 0) {
        memcpy(HeaderBuffer, Token, TokenLength);
        HeaderBuffer += TokenLength;
    }

    return RequiredBufferLength;
}

//
// Encodes the short header fields.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != 0)
uint16_t
QuicPacketEncodeShortHeaderV1(
    _In_ const QUIC_CID* const DestCID,
    _In_ uint64_t PacketNumber,
    _In_ uint8_t PacketNumberLength,
    _In_ BOOLEAN SpinBit,
    _In_ BOOLEAN KeyPhase,
    _In_ uint16_t BufferLength,
    _Out_writes_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    QUIC_DBG_ASSERT(PacketNumberLength != 0 && PacketNumberLength <= 4);

    uint16_t RequiredBufferLength =
        sizeof(QUIC_SHORT_HEADER_V1) +
        DestCID->Length +
        PacketNumberLength;
    if (BufferLength < RequiredBufferLength) {
        return 0;
    }

    QUIC_SHORT_HEADER_V1* Header = (QUIC_SHORT_HEADER_V1*)Buffer;

    Header->IsLongHeader    = FALSE;
    Header->FixedBit        = 1;
    Header->SpinBit         = SpinBit;
    Header->Reserved        = 0;
    Header->KeyPhase        = KeyPhase;
    Header->PnLength        = PacketNumberLength - 1;

    uint8_t *HeaderBuffer = Header->DestCID;
    if (DestCID->Length != 0) {
        memcpy(HeaderBuffer, DestCID->Data, DestCID->Length);
        HeaderBuffer += DestCID->Length;
    }

    QuicPktNumEncode(PacketNumber, PacketNumberLength, HeaderBuffer);

    return RequiredBufferLength;
}

//
// Logs a packet header.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketLogHeader(
    _In_opt_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN Rx,
    _In_ uint8_t CIDLength,
    _In_ uint64_t PacketNumber,
    _In_ uint16_t PacketLength,
    _In_reads_bytes_(PacketLength)
        const uint8_t * const Packet,
    _In_ uint32_t Version             // Network Byte Order. Used for Short Headers
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketLogDrop(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ const QUIC_RECV_PACKET* Packet,
    _In_z_ const char* Reason
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketLogDropWithValue(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ const QUIC_RECV_PACKET* Packet,
    _In_z_ const char* Reason,
    _In_ uint64_t Value
    );
