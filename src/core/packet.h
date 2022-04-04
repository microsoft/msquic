/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define CXPLAT_VERSION_SALT_LENGTH 20
#define QUIC_VERSION_RETRY_INTEGRITY_SECRET_LENGTH 32

typedef struct QUIC_VERSION_INFO {

    //
    // In network byte order.
    //
    uint32_t Number;

    //
    // Version specific salt.
    //
    uint8_t Salt[CXPLAT_VERSION_SALT_LENGTH];

    //
    // Version specific Retry integrity secret.
    //
    uint8_t RetryIntegritySecret[QUIC_VERSION_RETRY_INTEGRITY_SECRET_LENGTH];

    //
    // Labels used to derive different QUIC keys.
    //
    QUIC_HKDF_LABELS HkdfLabels;

} QUIC_VERSION_INFO;

//
// The list of supported QUIC versions.
//
extern const QUIC_VERSION_INFO QuicSupportedVersionList[4];

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
            uint8_t DestCidLength;
            uint8_t DestCid[0];
            //uint8_t SourceCidLength;
            //uint8_t SourceCid[SourceCidLength];

        } LONG_HDR;

        struct {
            uint8_t VARIANT : 7;
            uint8_t IsLongHeader : 1;
            uint8_t DestCid[0];

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
    _Inout_ CXPLAT_RECV_PACKET* Packet,
    _In_ BOOLEAN IsBindingShared
    );

//
// The layout of the Version Negotation packet.
//
typedef struct QUIC_VERSION_NEGOTIATION_PACKET {

    uint8_t Unused : 7;
    uint8_t IsLongHeader : 1;
    uint32_t Version;
    uint8_t DestCidLength;
    uint8_t DestCid[0];
    //uint8_t SourceCidLength;
    //uint8_t SourceCid[SourceCidLength];
    //uint32_t SupportedVersions[0];

} QUIC_VERSION_NEGOTIATION_PACKET;

#pragma pack(pop)

//
// The following are Version Depedentant structs and functions.
//

//
// Different types of Long Header packets.
// QUIC version 2 uses different values than version 1.
//
typedef enum QUIC_LONG_HEADER_TYPE_V1 {

    QUIC_INITIAL_V1             = 0,
    QUIC_0_RTT_PROTECTED_V1     = 1,
    QUIC_HANDSHAKE_V1           = 2,
    QUIC_RETRY_V1               = 3,

} QUIC_LONG_HEADER_TYPE_V1;

typedef enum QUIC_LONG_HEADER_TYPE_V2 {

    QUIC_RETRY_V2               = 0,
    QUIC_INITIAL_V2             = 1,
    QUIC_0_RTT_PROTECTED_V2     = 2,
    QUIC_HANDSHAKE_V2           = 3,

} QUIC_LONG_HEADER_TYPE_V2;

#pragma pack(push)
#pragma pack(1)

//
// Represents the long header format. All values in Network Byte order.
// The 4 least significant bits are protected by header protection.
// This structure is used for both QUIC version 1 and version 2.
//

typedef struct QUIC_LONG_HEADER_V1 {

    uint8_t PnLength        : 2;
    uint8_t Reserved        : 2;    // Must be 0.
    uint8_t Type            : 2;    // QUIC_LONG_HEADER_TYPE_V1 or _V2
    uint8_t FixedBit        : 1;    // Must be 1.
    uint8_t IsLongHeader    : 1;
    uint32_t Version;
    uint8_t DestCidLength;
    uint8_t DestCid[0];
    //uint8_t SourceCidLength;
    //uint8_t SourceCid[SourceCidLength];
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
// This structure is used for both QUIC version 1 and version 2.
//

typedef struct QUIC_RETRY_PACKET_V1 {

    uint8_t UNUSED          : 4;
    uint8_t Type            : 2;
    uint8_t FixedBit        : 1;    // Must be 1.
    uint8_t IsLongHeader    : 1;
    uint32_t Version;
    uint8_t DestCidLength;
    uint8_t DestCid[0];
    //uint8_t SourceCidLength;
    //uint8_t SourceCid[SourceCidLength];
    //uint8_t Token[*];
    //uint8_t RetryIntegrityField[16];

} QUIC_RETRY_PACKET_V1;

//
// The minimum retry packet header, in bytes.
//
#define MIN_RETRY_HEADER_LENGTH_V1 \
( \
    sizeof(QUIC_RETRY_PACKET_V1) + \
    sizeof(uint8_t) \
)

#define QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1 CXPLAT_ENCRYPTION_OVERHEAD

//
// Represents the short header format. All values in Network Byte order.
// The 5 least significant bits are protected by header protection.
// This struct is used for both QUIC versions 1 and 2.
//
typedef struct QUIC_SHORT_HEADER_V1 {

    uint8_t PnLength        : 2;
    uint8_t KeyPhase        : 1;
    uint8_t Reserved        : 2;    // Must be 0.
    uint8_t SpinBit         : 1;
    uint8_t FixedBit        : 1;    // Must be 1.
    uint8_t IsLongHeader    : 1;
    uint8_t DestCid[0];             // Length depends on connection.
    //uint8_t PacketNumber[PnLength];
    //uint8_t Payload[0];

} QUIC_SHORT_HEADER_V1;

//
// Helper to calculate the length of the full short header, in bytes.
//
#define SHORT_HEADER_PACKET_NUMBER_V1(Header, DestCidLen) \
    ((Header)->ConnectionID + DestCidLen)
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
        case QUIC_VERSION_1:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1:
            return ((QUIC_LONG_HEADER_V1*)Packet)->Type != QUIC_0_RTT_PROTECTED_V1;
        case QUIC_VERSION_2:
            return ((QUIC_LONG_HEADER_V1*)Packet)->Type != QUIC_0_RTT_PROTECTED_V2;
        default:
            return TRUE;
    }
}

//
// Validates both QUIC version 1 and version 2 long headers.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateLongHeaderV1(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ BOOLEAN IsServer,
    _Inout_ CXPLAT_RECV_PACKET* Packet,
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
    _In_ const CXPLAT_RECV_PACKET* const Packet,
    _Outptr_result_buffer_maybenull_(*TokenLength)
        const uint8_t** Token,
    _Out_ uint16_t* TokenLength
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicPacketValidateInitialToken(
    _In_ const void* const Owner,
    _In_ const CXPLAT_RECV_PACKET* const Packet,
    _In_range_(>, 0) uint16_t TokenLength,
    _In_reads_(TokenLength)
        const uint8_t* TokenBuffer,
    _Inout_ BOOLEAN* DropPacket
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateShortHeaderV1(
    _In_ const void* Owner, // Binding or Connection depending on state
    _Inout_ CXPLAT_RECV_PACKET* Packet
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
    CXPLAT_DBG_ASSERT(CompressedPacketNumberBytes < 8);
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
// Encodes the long header fields for QUIC versions 1 and 2.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != 0)
uint16_t
QuicPacketEncodeLongHeaderV1(
    _In_ uint32_t Version, // Allows for version negotiation forcing
    _In_ uint8_t PacketType,
    _In_ const QUIC_CID* const DestCid,
    _In_ const QUIC_CID* const SourceCid,
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
    const BOOLEAN IsInitial =
        (Version != QUIC_VERSION_2 && PacketType == QUIC_INITIAL_V1) ||
        (Version == QUIC_VERSION_2 && PacketType == QUIC_INITIAL_V2);
    uint16_t RequiredBufferLength =
        sizeof(QUIC_LONG_HEADER_V1) +
        DestCid->Length +
        sizeof(uint8_t) +
        SourceCid->Length +
        sizeof(uint16_t) + // We always encode 2 bytes for the length.
        sizeof(uint32_t);  // We always encode 4 bytes for the packet number.
    if (IsInitial) {
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
    Header->DestCidLength   = DestCid->Length;

    uint8_t *HeaderBuffer = Header->DestCid;
    if (DestCid->Length != 0) {
        memcpy(HeaderBuffer, DestCid->Data, DestCid->Length);
        HeaderBuffer += DestCid->Length;
    }
    *HeaderBuffer = SourceCid->Length;
    HeaderBuffer++;
    if (SourceCid->Length != 0) {
        memcpy(HeaderBuffer, SourceCid->Data, SourceCid->Length);
        HeaderBuffer += SourceCid->Length;
    }
    if (IsInitial) {
        HeaderBuffer = QuicVarIntEncode(TokenLength, HeaderBuffer);
        if (TokenLength != 0) {
            _Analysis_assume_(Token != NULL);
            memcpy(HeaderBuffer, Token, TokenLength);
            HeaderBuffer += TokenLength;
        }
    }
    *PayloadLengthOffset = (uint16_t)(HeaderBuffer - Buffer);
    HeaderBuffer += sizeof(uint16_t); // Skip PayloadLength.
    PacketNumber = CxPlatByteSwapUint32(PacketNumber);
    memcpy(HeaderBuffer, &PacketNumber, sizeof(PacketNumber));
    *PacketNumberLength = sizeof(PacketNumber);

    return RequiredBufferLength;
}

#define QuicPacketMaxBufferSizeForRetryV1() \
    MIN_RETRY_HEADER_LENGTH_V1 + \
    3 * QUIC_MAX_CONNECTION_ID_LENGTH_V1 + \
    sizeof(QUIC_TOKEN_CONTENTS)

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPacketGenerateRetryIntegrity(
    _In_ const QUIC_VERSION_INFO* Version,
    _In_ uint8_t OrigDestCidLength,
    _In_reads_(OrigDestCidLength) const uint8_t* const OrigDestCid,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _Out_writes_bytes_(QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1)
        uint8_t* IntegrityField
    );

//
// Encodes the retry packet fields for QUIC versions 1 and 2.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != 0)
uint16_t
QuicPacketEncodeRetryV1(
    _In_ uint32_t Version,
    _In_reads_(DestCidLength) const uint8_t* const DestCid,
    _In_ uint8_t DestCidLength,
    _In_reads_(SourceCidLength) const uint8_t* const SourceCid,
    _In_ uint8_t SourceCidLength,
    _In_reads_(OrigDestCidLength) const uint8_t* const OrigDestCid,
    _In_ uint8_t OrigDestCidLength,
    _In_ uint16_t TokenLength,
    _In_reads_(TokenLength)
        uint8_t* Token,
    _In_ uint16_t BufferLength,
    _Out_writes_bytes_(BufferLength)
        uint8_t* Buffer
    );

//
// Encodes the short header fields.
//
inline
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != 0)
uint16_t
QuicPacketEncodeShortHeaderV1(
    _In_ const QUIC_CID* const DestCid,
    _In_ uint64_t PacketNumber,
    _In_ uint8_t PacketNumberLength,
    _In_ BOOLEAN SpinBit,
    _In_ BOOLEAN KeyPhase,
    _In_ uint16_t BufferLength,
    _Out_writes_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    CXPLAT_DBG_ASSERT(PacketNumberLength != 0 && PacketNumberLength <= 4);

    uint16_t RequiredBufferLength =
        sizeof(QUIC_SHORT_HEADER_V1) +
        DestCid->Length +
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

    uint8_t *HeaderBuffer = Header->DestCid;
    if (DestCid->Length != 0) {
        memcpy(HeaderBuffer, DestCid->Data, DestCid->Length);
        HeaderBuffer += DestCid->Length;
    }

    QuicPktNumEncode(PacketNumber, PacketNumberLength, HeaderBuffer);

    return RequiredBufferLength;
}

inline
uint32_t
QuicPacketHash(
    _In_ const QUIC_ADDR* const RemoteAddress,
    _In_ uint8_t RemoteCidLength,
    _In_reads_(RemoteCidLength)
        const uint8_t* const RemoteCid
    )
{
    uint32_t Key = 0, Offset;
    CxPlatToeplitzHashComputeAddr(
        &MsQuicLib.ToeplitzHash,
        RemoteAddress,
        &Key,
        &Offset);
    if (RemoteCidLength != 0) {
        Key ^=
            CxPlatToeplitzHashCompute(
                &MsQuicLib.ToeplitzHash,
                RemoteCid,
                CXPLAT_MIN(RemoteCidLength, QUIC_MAX_CONNECTION_ID_LENGTH_V1),
                Offset);
    }
    return Key;
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
    _In_ const CXPLAT_RECV_PACKET* Packet,
    _In_z_ const char* Reason
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketLogDropWithValue(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ const CXPLAT_RECV_PACKET* Packet,
    _In_z_ const char* Reason,
    _In_ uint64_t Value
    );
