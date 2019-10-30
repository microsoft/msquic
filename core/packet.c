/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Packet processing helpers (validation, encoding and tracing).

--*/

#include "precomp.h"

#ifdef QUIC_LOGS_WPP
#include "packet.tmh"
#endif

//
// The list of supported QUIC version numbers, in network byte order.
// The list is in priority order (highest to lowest).
//
const uint32_t QuicSupportedVersionList[] = {
    QUIC_VERSION_DRAFT_23,
    QUIC_VERSION_MS_1
};

const uint8_t QuicInitialSaltVersion1[] =
{
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
    0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02
};

const char PacketLogPrefix[2][2] = {
    {'C', 'S'}, {'T', 'R'}
};

//
// The Long Header types that are allowed to be processed
// by a Client or Server.
//
const BOOLEAN QUIC_HEADER_TYPE_ALLOWED[2][4] = {
    //
    // Client
    //
    {
        TRUE,  // QUIC_INITIAL
        FALSE, // QUIC_0_RTT_PROTECTED
        TRUE,  // QUIC_HANDSHAKE
        TRUE,  // QUIC_RETRY
    },

    //
    // Server
    //
    {
        TRUE,  // QUIC_INITIAL
        TRUE,  // QUIC_0_RTT_PROTECTED
        TRUE,  // QUIC_HANDSHAKE
        FALSE, // QUIC_RETRY
    },
};

const uint16_t QuicMinPacketLengths[2] = { MIN_INV_SHORT_HDR_LENGTH, MIN_INV_LONG_HDR_LENGTH };

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateInvariant(
    _In_ const void* Owner, // Binding or Connection depending on state
    _Inout_ QUIC_RECV_PACKET* Packet,
    _In_ BOOLEAN IsBindingShared
    )
{
    uint8_t DestCIDLen, SourceCIDLen;
    const uint8_t* DestCID, *SourceCID;

    //
    // Ignore empty or too short packets.
    //
    if (Packet->BufferLength == 0 ||
        Packet->BufferLength < QuicMinPacketLengths[Packet->Invariant->IsLongHeader]) {
        QuicPacketLogDrop(Owner, Packet, "Too small for Packet->Invariant");
        return FALSE;
    }

    if (Packet->Invariant->IsLongHeader) {

        Packet->IsShortHeader = FALSE;

        DestCIDLen = Packet->Invariant->LONG_HDR.DestCIDLength;
        if (Packet->BufferLength < MIN_INV_LONG_HDR_LENGTH + DestCIDLen) {
            QuicPacketLogDrop(Owner, Packet, "LH no room for DestCID");
            return FALSE;
        }
        if (IsBindingShared && DestCIDLen == 0) {
            QuicPacketLogDrop(Owner, Packet, "Zero length DestCID");
            return FALSE;
        }
        DestCID = Packet->Invariant->LONG_HDR.DestCID;

        SourceCIDLen = *(DestCID + DestCIDLen);
        Packet->HeaderLength = MIN_INV_LONG_HDR_LENGTH + DestCIDLen + SourceCIDLen;
        if (Packet->BufferLength < Packet->HeaderLength) {
            QuicPacketLogDrop(Owner, Packet, "LH no room for SourceCID");
            return FALSE;
        }
        SourceCID = DestCID + sizeof(uint8_t) + DestCIDLen;

    } else {

        Packet->IsShortHeader = TRUE;
        DestCIDLen = IsBindingShared ? MSQUIC_CONNECTION_ID_LENGTH : 0;
        SourceCIDLen = 0;

        //
        // Header length so far (just Packet->Invariant part).
        //
        Packet->HeaderLength = sizeof(uint8_t) + DestCIDLen;

        if (Packet->BufferLength < Packet->HeaderLength) {
            QuicPacketLogDrop(Owner, Packet, "SH no room for DestCID");
            return FALSE;
        }

        DestCID = Packet->Invariant->SHORT_HDR.DestCID;
        SourceCID = NULL;
    }

    if (Packet->DestCID != NULL) {

        //
        // The CID(s) have already been previously set for this UDP datagram.
        // Make sure they match.
        //

        if (Packet->DestCIDLen != DestCIDLen ||
            memcmp(Packet->DestCID, DestCID, DestCIDLen) != 0) {
            QuicPacketLogDrop(Owner, Packet, "DestCID don't match");
            return FALSE;
        }

        if (!Packet->IsShortHeader) {

            QUIC_DBG_ASSERT(Packet->SourceCID != NULL);

            if (Packet->SourceCIDLen != SourceCIDLen ||
                memcmp(Packet->SourceCID, SourceCID, SourceCIDLen) != 0) {
                QuicPacketLogDrop(Owner, Packet, "SourceCID don't match");
                return FALSE;
            }
        }

    } else {

        //
        // The first QUIC packet in the datagram, save the CIDs with the receive
        // context.
        //

        Packet->DestCIDLen = DestCIDLen;
        Packet->SourceCIDLen = SourceCIDLen;

        Packet->DestCID = DestCID;
        Packet->SourceCID = SourceCID;
    }

    Packet->ValidatedHeaderInv = TRUE;

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateLongHeaderD23(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ BOOLEAN IsServer,
    _Inout_ QUIC_RECV_PACKET* Packet,
    _Outptr_result_buffer_maybenull_(*TokenLength)
        const uint8_t** Token,
    _Out_ uint16_t* TokenLength
    )
{
    //
    // The Packet->Invariant part of the header has already been validated. No need
    // to check that portion of the header again.
    //
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderInv);
    QUIC_DBG_ASSERT(Packet->BufferLength >= Packet->HeaderLength);
    QUIC_DBG_ASSERT(Packet->LH->Type != QUIC_RETRY); // Retry uses a different code path.

    if (Packet->DestCIDLen > QUIC_MAX_CONNECTION_ID_LENGTH_V1 ||
        Packet->SourceCIDLen > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
        QuicPacketLogDrop(Owner, Packet, "Greater than allowed max CID length");
        return FALSE;
    }

    //
    // Validate acceptable types.
    //
    QUIC_DBG_ASSERT(IsServer == 0 || IsServer == 1);
    if (QUIC_HEADER_TYPE_ALLOWED[IsServer][Packet->LH->Type] == FALSE) {
        QuicPacketLogDropWithValue(Owner, Packet, "Invalid client/server packet type", Packet->LH->Type);
        return FALSE;
    }

    //
    // Check the Fixed bit to ensure it is set to 1.
    //
    if (Packet->LH->FixedBit == 0) {
        QuicPacketLogDrop(Owner, Packet, "Invalid LH FixedBit bits values");
        return FALSE;
    }

    //
    // Cannot validate the PnLength and Reserved fields yet, as they are
    // protected by header protection.
    //

    uint16_t Offset = Packet->HeaderLength;

    if (Packet->LH->Type == QUIC_INITIAL) {
        QUIC_VAR_INT TokenLengthVarInt;
        if (!QuicVarIntDecode(
                Packet->BufferLength,
                Packet->Buffer,
                &Offset,
                &TokenLengthVarInt)) {
            QuicPacketLogDrop(Owner, Packet, "Long header has invalid token length");
            return FALSE;
        }

        if ((uint64_t)Packet->BufferLength < Offset + TokenLengthVarInt) {
            QuicPacketLogDropWithValue(Owner, Packet, "Long header has token length larger than buffer length", TokenLengthVarInt);
            return FALSE;
        }

        *Token = Packet->Buffer + Offset;
        *TokenLength = (uint16_t)TokenLengthVarInt;

        Offset += (uint16_t)TokenLengthVarInt;

    } else {

        *Token = NULL;
        *TokenLength = 0;
    }

    QUIC_VAR_INT LengthVarInt;
    if (!QuicVarIntDecode(
            Packet->BufferLength,
            Packet->Buffer,
            &Offset,
            &LengthVarInt)) {
        QuicPacketLogDrop(Owner, Packet, "Long header has invalid payload length");
        return FALSE;
    }

    if ((uint64_t)Packet->BufferLength < Offset + LengthVarInt) {
        QuicPacketLogDropWithValue(Owner, Packet, "Long header has length larger than buffer length", LengthVarInt);
        return FALSE;
    }

    if (Packet->BufferLength < Offset + sizeof(uint32_t)) {
        QuicPacketLogDropWithValue(Owner, Packet, "Long Header doesn't have enough room for packet number",
            Packet->BufferLength);
        return FALSE;
    }

    //
    // Packet number is still encrypted at this point, so we can't decode it
    // and therefore cannot calculate the total length of the header yet.
    // For the time being, set header length to the start of the packet
    // number and payload length to everything after that.
    //
    Packet->HeaderLength = Offset;
    Packet->PayloadLength = (uint16_t)LengthVarInt;
    Packet->BufferLength = Packet->HeaderLength + Packet->PayloadLength;
    Packet->ValidatedHeaderVer = TRUE;

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketDecodeRetryTokenD23(
    _In_ const QUIC_RECV_PACKET* const Packet,
    _Outptr_result_buffer_maybenull_(*TokenLength)
        const uint8_t** Token,
    _Out_ uint16_t* TokenLength
    )
{
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderInv);
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderVer);
    QUIC_DBG_ASSERT(Packet->Invariant->IsLongHeader);
    QUIC_DBG_ASSERT(Packet->LH->Type == QUIC_INITIAL);

    uint16_t Offset =
        sizeof(QUIC_LONG_HEADER_D23) +
        Packet->DestCIDLen +
        sizeof(uint8_t) +
        Packet->SourceCIDLen;

    QUIC_VAR_INT TokenLengthVarInt;
    BOOLEAN Success = QuicVarIntDecode(
        Packet->BufferLength, Packet->Buffer, &Offset, &TokenLengthVarInt);
    QUIC_DBG_ASSERT(Success); // Was previously validated.
    UNREFERENCED_PARAMETER(Success);

    QUIC_DBG_ASSERT(Offset + TokenLengthVarInt <= Packet->BufferLength); // Was previously validated.
    *Token = Packet->Buffer + Offset;
    *TokenLength = (uint16_t)TokenLengthVarInt;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketValidateShortHeaderD23(
    _In_ const void* Owner, // Binding or Connection depending on state
    _Inout_ QUIC_RECV_PACKET* Packet
    )
{
    //
    // The Packet->Invariant part of the header has already been validated. No need
    // to check any additional lengths as the cleartext part of the version
    // specific header isn't any larger than the Packet->Invariant.
    //
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderInv);
    QUIC_DBG_ASSERT(Packet->BufferLength >= Packet->HeaderLength);

    //
    // Check the Fixed bit to ensure it is set to 1.
    //
    if (Packet->SH->FixedBit == 0) {
        QuicPacketLogDrop(Owner, Packet, "Invalid SH FixedBit bits values");
        return FALSE;
    }

    //
    // Cannot validate the PnLength, KeyPhase and Reserved fields yet, as they
    // are protected by header protection.
    //

    //
    // Packet number is still encrypted at this point, so we can't decode it
    // and therefore cannot calculate the total length of the header yet.
    // For the time being, set header length to the start of the packet
    // number and payload length to everything after that.
    //
    Packet->PayloadLength = Packet->BufferLength - Packet->HeaderLength;
    Packet->ValidatedHeaderVer = TRUE;

    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPacketCanCreateNewConnection(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ const QUIC_RECV_PACKET* const Packet
    )
{
    BOOLEAN CreateNewConnection = FALSE;

    QUIC_DBG_ASSERT(Packet->Invariant->IsLongHeader);
    QUIC_DBG_ASSERT(QuicIsVersionSupported(Packet->Invariant->LONG_HDR.Version));

    switch (Packet->Invariant->LONG_HDR.Version) {
    case QUIC_VERSION_DRAFT_23:
    case QUIC_VERSION_MS_1: {

        if (Packet->LH->Type != QUIC_INITIAL) {
            //
            // Drop the packet because it's not allowed to create a new Connection.
            //
            QuicPacketLogDrop(Owner, Packet, "Non-initial packet not matched with a Connection");
            break;
        }

        if (Packet->BufferLength < QUIC_MIN_INITIAL_PACKET_LENGTH) {
            //
            // All initial packets need to be padded to a minimum length.
            //
            QuicPacketLogDropWithValue(Owner, Packet,
                "Long header Initial packet too short", Packet->BufferLength);
            break;
        }

        CreateNewConnection = TRUE;
        break;
    }
    }

    return CreateNewConnection;
}

_Null_terminated_ const char*
QuicLongHeaderTypeToString(uint8_t Type)
{
    switch (Type)
    {
    case QUIC_INITIAL:              return "I";
    case QUIC_0_RTT_PROTECTED:      return "0P";
    case QUIC_HANDSHAKE:            return "HS";
    case QUIC_RETRY:                return "R";
    }
    return "INVALID";
}

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
    )
{
    const QUIC_HEADER_INVARIANT* Invariant = (QUIC_HEADER_INVARIANT*)Packet;
    uint16_t Offset;

    if (Invariant->IsLongHeader) {

        uint8_t DestCIDLen = Invariant->LONG_HDR.DestCIDLength;
        const uint8_t* DestCID = Invariant->LONG_HDR.DestCID;
        uint8_t SourceCIDLen = *(DestCID + DestCIDLen);
        const uint8_t* SourceCID = DestCID + sizeof(uint8_t) + DestCIDLen;

        Offset = sizeof(QUIC_HEADER_INVARIANT) + sizeof(uint8_t) + DestCIDLen + SourceCIDLen;

        switch (Invariant->LONG_HDR.Version) {
        case QUIC_VERSION_VER_NEG: {
            LogPacketInfo(
                "[%c][%cX][-] VerNeg DestCID:%s SrcCID:%s (Payload %lu bytes)",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                QuicCidBufToStr(DestCID, DestCIDLen).Buffer,
                QuicCidBufToStr(SourceCID, SourceCIDLen).Buffer,
                PacketLength - Offset);

            while (Offset < PacketLength) {
                LogPacketInfo(
                    "[%c][%cX][-]   Ver:0x%x",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    *(uint32_t*)(Packet + Offset));
                Offset += sizeof(uint32_t);
            }
            break;
        }

        case QUIC_VERSION_DRAFT_23:
        case QUIC_VERSION_MS_1: {
            const QUIC_LONG_HEADER_D23 * const LongHdr =
                (const QUIC_LONG_HEADER_D23 * const)Packet;

            QUIC_VAR_INT TokenLength;
            QUIC_VAR_INT Length;

            if (LongHdr->Type == QUIC_INITIAL) {
                if (!QuicVarIntDecode(
                        PacketLength,
                        Packet,
                        &Offset,
                        &TokenLength)) {
                    break;
                }
                Offset += (uint16_t)TokenLength;

            } else if (LongHdr->Type == QUIC_RETRY) {

                uint8_t OrigDestCIDLen = *(SourceCID + SourceCIDLen);
                const uint8_t* OrigDestCID = SourceCID + sizeof(uint8_t) + SourceCIDLen;
                Offset += sizeof(uint8_t) + OrigDestCIDLen;

                LogPacketInfo(
                    "[%c][%cX][-] LH Ver:0x%x DestCID:%s SrcCID:%s Type:R OrigDestCID:%s (Token %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    LongHdr->Version,
                    QuicCidBufToStr(DestCID, DestCIDLen).Buffer,
                    QuicCidBufToStr(SourceCID, SourceCIDLen).Buffer,
                    QuicCidBufToStr(OrigDestCID, OrigDestCIDLen).Buffer,
                    PacketLength - Offset);
                break;

            } else {
                TokenLength = UINT64_MAX;
            }

            if (!QuicVarIntDecode(
                    PacketLength,
                    Packet,
                    &Offset,
                    &Length)) {
                break;
            }

            if (LongHdr->Type == QUIC_INITIAL) {
                LogPacketInfo(
                    "[%c][%cX][%llu] LH Ver:0x%x DestCID:%s SrcCID:%s Type:%s (Token %hu bytes) (Payload %hu bytes) (PktNum %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCID, DestCIDLen).Buffer,
                    QuicCidBufToStr(SourceCID, SourceCIDLen).Buffer,
                    QuicLongHeaderTypeToString(LongHdr->Type),
                    (uint16_t)TokenLength,
                    (uint16_t)Length,
                    LongHdr->PnLength + 1);
            } else {
                LogPacketInfo(
                    "[%c][%cX][%llu] LH Ver:0x%x DestCID:%s SrcCID:%s Type:%s (Payload %hu bytes) (PktNum %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCID, DestCIDLen).Buffer,
                    QuicCidBufToStr(SourceCID, SourceCIDLen).Buffer,
                    QuicLongHeaderTypeToString(LongHdr->Type),
                    (uint16_t)Length,
                    LongHdr->PnLength + 1);
            }
            break;
        }

        default:
            LogPacketInfo(
                "[%c][%cX][%llu] LH Ver:[UNSUPPORTED,0x%x] DestCID:%s SrcCID:%s",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Invariant->LONG_HDR.Version,
                QuicCidBufToStr(DestCID, DestCIDLen).Buffer,
                QuicCidBufToStr(SourceCID, SourceCIDLen).Buffer);
            break;
        }

    } else {

        uint8_t DestCIDLen = CIDLength;
        const uint8_t* DestCID = Invariant->SHORT_HDR.DestCID;

        switch (Version) {
        case QUIC_VERSION_DRAFT_23:
        case QUIC_VERSION_MS_1: {
            const QUIC_SHORT_HEADER_D23 * const Header =
                (const QUIC_SHORT_HEADER_D23 * const)Packet;

            Offset = sizeof(QUIC_SHORT_HEADER_D23) + DestCIDLen;

            LogPacketInfo(
                "[%c][%cX][%llu] SH DestCID:%s KP:%hu SB:%hu (Payload %hu bytes)",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                QuicCidBufToStr(DestCID, DestCIDLen).Buffer,
                Header->KeyPhase,
                Header->SpinBit,
                PacketLength - Offset);
            break;
        }

        default:
            QUIC_FRE_ASSERT(FALSE);
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketLogDrop(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ const QUIC_RECV_PACKET* Packet,
    _In_z_ const char* Reason
    )
{
    const QUIC_RECV_DATAGRAM* Datagram =
        QuicDataPathRecvPacketToRecvDatagram(Packet);

    if (Packet->AssignedToConnection) {
        EventWriteQuicConnDropPacket(
            Owner,
            Packet->PacketNumberSet ? UINT64_MAX : Packet->PacketNumber,
            LOG_ADDR_LEN(Datagram->Tuple->LocalAddress),
            LOG_ADDR_LEN(Datagram->Tuple->RemoteAddress),
            (uint8_t*)&Datagram->Tuple->LocalAddress,
            (uint8_t*)&Datagram->Tuple->RemoteAddress,
            Reason);
    } else {
        EventWriteQuicBindingDropPacket(
            Owner,
            Packet->PacketNumberSet ? UINT64_MAX : Packet->PacketNumber,
            LOG_ADDR_LEN(Datagram->Tuple->LocalAddress),
            LOG_ADDR_LEN(Datagram->Tuple->RemoteAddress),
            (uint8_t*)&Datagram->Tuple->LocalAddress,
            (uint8_t*)&Datagram->Tuple->RemoteAddress,
            Reason);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketLogDropWithValue(
    _In_ const void* Owner, // Binding or Connection depending on state
    _In_ const QUIC_RECV_PACKET* Packet,
    _In_z_ const char* Reason,
    _In_ uint64_t Value
    )
{
    const QUIC_RECV_DATAGRAM* Datagram =
        QuicDataPathRecvPacketToRecvDatagram(Packet);

    if (Packet->AssignedToConnection) {
        EventWriteQuicConnDropPacketEx(
            Owner,
            Packet->PacketNumberSet ? UINT64_MAX : Packet->PacketNumber,
            Value,
            LOG_ADDR_LEN(Datagram->Tuple->LocalAddress),
            LOG_ADDR_LEN(Datagram->Tuple->RemoteAddress),
            (uint8_t*)&Datagram->Tuple->LocalAddress,
            (uint8_t*)&Datagram->Tuple->RemoteAddress,
            Reason);
    } else {
        EventWriteQuicBindingDropPacketEx(
            Owner,
            Packet->PacketNumberSet ? UINT64_MAX : Packet->PacketNumber,
            Value,
            LOG_ADDR_LEN(Datagram->Tuple->LocalAddress),
            LOG_ADDR_LEN(Datagram->Tuple->RemoteAddress),
            (uint8_t*)&Datagram->Tuple->LocalAddress,
            (uint8_t*)&Datagram->Tuple->RemoteAddress,
            Reason);
    }
}
