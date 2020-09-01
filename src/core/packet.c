/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Packet processing helpers (validation, encoding and tracing).

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "packet.c.clog.h"
#endif

//
// The list of supported QUIC version numbers and associated salts/secrets.
// The list is in priority order (highest to lowest).
//
const QUIC_VERSION_INFO QuicSupportedVersionList[] = {
    { QUIC_VERSION_DRAFT_29,
      { 0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99 },
      { 0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2, 0x07, 0xd8, 0x0d, 0xf2,
        0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42, 0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c } },
    { QUIC_VERSION_DRAFT_28,
      { 0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
        0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02 },
      { 0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed, 0xd8, 0xd7, 0x8d, 0x46, 0x1e,
        0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a, 0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a } },
    { QUIC_VERSION_DRAFT_27,
      { 0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
        0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02 },
      { 0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed, 0xd8, 0xd7, 0x8d, 0x46, 0x1e,
        0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a, 0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a } },
    { QUIC_VERSION_MS_1,
      { 0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99 },
      { 0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2, 0x07, 0xd8, 0x0d, 0xf2,
        0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42, 0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c } }
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
    uint8_t DestCidLen, SourceCidLen;
    const uint8_t* DestCid, *SourceCid;

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

        DestCidLen = Packet->Invariant->LONG_HDR.DestCidLength;
        if (Packet->BufferLength < MIN_INV_LONG_HDR_LENGTH + DestCidLen) {
            QuicPacketLogDrop(Owner, Packet, "LH no room for DestCid");
            return FALSE;
        }
        if (IsBindingShared) {
            if (DestCidLen == 0) {
                QuicPacketLogDrop(Owner, Packet, "Zero length DestCid");
                return FALSE;
            } else if (DestCidLen < QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH) {
                QuicPacketLogDrop(Owner, Packet, "Less than min length CID on non-exclusive binding");
                return FALSE;
            }
        } else {
            if (DestCidLen != 0) {
                QuicPacketLogDrop(Owner, Packet, "Non-zero length CID on exclusive binding");
                return FALSE;
            }
        }

        DestCid = Packet->Invariant->LONG_HDR.DestCid;

        SourceCidLen = *(DestCid + DestCidLen);
        Packet->HeaderLength = MIN_INV_LONG_HDR_LENGTH + DestCidLen + SourceCidLen;
        if (Packet->BufferLength < Packet->HeaderLength) {
            QuicPacketLogDrop(Owner, Packet, "LH no room for SourceCid");
            return FALSE;
        }
        SourceCid = DestCid + sizeof(uint8_t) + DestCidLen;

    } else {

        Packet->IsShortHeader = TRUE;
        DestCidLen = IsBindingShared ? MsQuicLib.CidTotalLength : 0;
        SourceCidLen = 0;

        //
        // Header length so far (just Packet->Invariant part).
        //
        Packet->HeaderLength = sizeof(uint8_t) + DestCidLen;

        if (Packet->BufferLength < Packet->HeaderLength) {
            QuicPacketLogDrop(Owner, Packet, "SH no room for DestCid");
            return FALSE;
        }

        DestCid = Packet->Invariant->SHORT_HDR.DestCid;
        SourceCid = NULL;
    }

    if (Packet->DestCid != NULL) {

        //
        // CID(s) are cached from a previous packet in the datagram. Check that
        // they match.
        //

        if (Packet->DestCidLen != DestCidLen ||
            memcmp(Packet->DestCid, DestCid, DestCidLen) != 0) {
            QuicPacketLogDrop(Owner, Packet, "DestCid don't match");
            return FALSE;
        }

        if (!Packet->IsShortHeader) {

            QUIC_DBG_ASSERT(Packet->SourceCid != NULL);

            if (Packet->SourceCidLen != SourceCidLen ||
                memcmp(Packet->SourceCid, SourceCid, SourceCidLen) != 0) {
                QuicPacketLogDrop(Owner, Packet, "SourceCid don't match");
                return FALSE;
            }
        }

    } else {

        //
        // This is the first packet in the datagram. Cache the CIDs.
        //

        Packet->DestCidLen = DestCidLen;
        Packet->SourceCidLen = SourceCidLen;

        Packet->DestCid = DestCid;
        Packet->SourceCid = SourceCid;
    }

    Packet->ValidatedHeaderInv = TRUE;

    return TRUE;
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
    )
{
    //
    // The Packet->Invariant part of the header has already been validated. No need
    // to check that portion of the header again.
    //
    QUIC_DBG_ASSERT(Packet->ValidatedHeaderInv);
    QUIC_DBG_ASSERT(Packet->BufferLength >= Packet->HeaderLength);
    QUIC_DBG_ASSERT(Packet->LH->Type != QUIC_RETRY); // Retry uses a different code path.

    if (Packet->DestCidLen > QUIC_MAX_CONNECTION_ID_LENGTH_V1 ||
        Packet->SourceCidLen > QUIC_MAX_CONNECTION_ID_LENGTH_V1) {
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
        if (IsServer && Packet->BufferLength < QUIC_MIN_INITIAL_PACKET_LENGTH) {
            //
            // All client initial packets need to be padded to a minimum length.
            //
            QuicPacketLogDropWithValue(Owner, Packet, "Client Long header Initial packet too short", Packet->BufferLength);
            return FALSE;
        }

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

QUIC_STATUS
QuicPacketGenerateRetryIntegrity(
    _In_reads_(QUIC_VERSION_RETRY_INTEGRITY_SECRET_LENGTH)
        const uint8_t* IntegritySecret,
    _In_ uint8_t OrigDestCidLength,
    _In_reads_(OrigDestCidLength) const uint8_t* const OrigDestCid,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _Out_writes_bytes_(QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1)
        uint8_t* IntegrityField
    )
{
    QUIC_SECRET Secret;
    Secret.Hash = QUIC_HASH_SHA256;
    Secret.Aead = QUIC_AEAD_AES_128_GCM;
    QuicCopyMemory(
        Secret.Secret,
        IntegritySecret,
        QUIC_VERSION_RETRY_INTEGRITY_SECRET_LENGTH);

    uint8_t* RetryPseudoPacket = NULL;
    QUIC_PACKET_KEY* RetryIntegrityKey = NULL;
    QUIC_STATUS Status =
        QuicPacketKeyDerive(
            QUIC_PACKET_KEY_INITIAL,
            &Secret,
            "RetryIntegrity",
            FALSE,
            &RetryIntegrityKey);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    uint16_t RetryPseudoPacketLength = sizeof(uint8_t) + OrigDestCidLength + BufferLength;
    RetryPseudoPacket = (uint8_t*)QUIC_ALLOC_PAGED(RetryPseudoPacketLength);
    if (RetryPseudoPacket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RetryPseudoPacket",
            RetryPseudoPacketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    uint8_t* RetryPseudoPacketCursor = RetryPseudoPacket;

    *RetryPseudoPacketCursor = OrigDestCidLength;
    RetryPseudoPacketCursor++;
    QuicCopyMemory(RetryPseudoPacketCursor, OrigDestCid, OrigDestCidLength);
    RetryPseudoPacketCursor += OrigDestCidLength;
    QuicCopyMemory(RetryPseudoPacketCursor, Buffer, BufferLength);
    RetryPseudoPacketCursor += BufferLength;

    Status =
        QuicEncrypt(
            RetryIntegrityKey->PacketKey,
            RetryIntegrityKey->Iv,
            RetryPseudoPacketLength,
            RetryPseudoPacket,
            QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1,
            IntegrityField);

Exit:
    if (RetryPseudoPacket != NULL) {
        QUIC_FREE(RetryPseudoPacket);
    }
    QuicPacketKeyFree(RetryIntegrityKey);
    return Status;
}

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
    )
{
    uint16_t RequiredBufferLength =
        MIN_RETRY_HEADER_LENGTH_V1 +
        DestCidLength +
        SourceCidLength +
        TokenLength +
        QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1;
    if (BufferLength < RequiredBufferLength) {
        return 0;
    }

    QUIC_RETRY_V1* Header = (QUIC_RETRY_V1*)Buffer;

    uint8_t RandomBits;
    QuicRandom(sizeof(RandomBits), &RandomBits);

    Header->IsLongHeader    = TRUE;
    Header->FixedBit        = 1;
    Header->Type            = QUIC_RETRY;
    Header->UNUSED          = RandomBits;
    Header->Version         = Version;
    Header->DestCidLength   = DestCidLength;

    uint8_t *HeaderBuffer = Header->DestCid;
    if (DestCidLength != 0) {
        memcpy(HeaderBuffer, DestCid, DestCidLength);
        HeaderBuffer += DestCidLength;
    }
    *HeaderBuffer = SourceCidLength;
    HeaderBuffer++;
    if (SourceCidLength != 0) {
        memcpy(HeaderBuffer, SourceCid, SourceCidLength);
        HeaderBuffer += SourceCidLength;
    }
    if (TokenLength != 0) {
        memcpy(HeaderBuffer, Token, TokenLength);
        HeaderBuffer += TokenLength;
    }

    const QUIC_VERSION_INFO* VersionInfo = NULL;
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Version) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }
    QUIC_FRE_ASSERT(VersionInfo != NULL);

    if (QUIC_FAILED(
        QuicPacketGenerateRetryIntegrity(
            VersionInfo->RetryIntegritySecret,
            OrigDestCidLength,
            OrigDestCid,
            RequiredBufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1,
            (uint8_t*)Header,
            HeaderBuffer))) {
        return 0;
    }

    HeaderBuffer += QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1;

    return RequiredBufferLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketDecodeRetryTokenV1(
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
        sizeof(QUIC_LONG_HEADER_V1) +
        Packet->DestCidLen +
        sizeof(uint8_t) +
        Packet->SourceCidLen;

    QUIC_VAR_INT TokenLengthVarInt = 0;
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
QuicPacketValidateShortHeaderV1(
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

        uint8_t DestCidLen = Invariant->LONG_HDR.DestCidLength;
        const uint8_t* DestCid = Invariant->LONG_HDR.DestCid;
        uint8_t SourceCidLen = *(DestCid + DestCidLen);
        const uint8_t* SourceCid = DestCid + sizeof(uint8_t) + DestCidLen;

        Offset = sizeof(QUIC_HEADER_INVARIANT) + sizeof(uint8_t) + DestCidLen + SourceCidLen;

        switch (Invariant->LONG_HDR.Version) {
        case QUIC_VERSION_VER_NEG: {
            QuicTraceLogVerbose(
                LogPacketVersionNegotiation,
                "[%c][%cX][-] VerNeg DestCid:%s SrcCid:%s (Payload %lu bytes)",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                PacketLength - Offset);

            while (Offset < PacketLength) {
                QuicTraceLogVerbose(
                    LogPacketVersionNegotiationVersion,
                    "[%c][%cX][-]   Ver:0x%x",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    *(uint32_t*)(Packet + Offset));
                Offset += sizeof(uint32_t);
            }
            break;
        }

        case QUIC_VERSION_DRAFT_27:
        case QUIC_VERSION_DRAFT_28:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1: {
            const QUIC_LONG_HEADER_V1 * const LongHdr =
                (const QUIC_LONG_HEADER_V1 * const)Packet;

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

                QuicTraceLogVerbose(
                    LogPacketRetry,
                    "[%c][%cX][-] LH Ver:0x%x DestCid:%s SrcCid:%s Type:R (Token %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    PacketLength - (Offset + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1));
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
                QuicTraceLogVerbose(
                    LogPacketLongHeaderInitial,
                    "[%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:I (Token %hu bytes) (Payload %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    (uint16_t)TokenLength,
                    (uint16_t)Length);
            } else {
                QuicTraceLogVerbose(
                    LogPacketLongHeader,
                    "[%c][%cX][%llu] LH Ver:0x%x DestCid:%s SrcCid:%s Type:%s (Payload %hu bytes)",
                    PtkConnPre(Connection),
                    PktRxPre(Rx),
                    PacketNumber,
                    LongHdr->Version,
                    QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                    QuicCidBufToStr(SourceCid, SourceCidLen).Buffer,
                    QuicLongHeaderTypeToString(LongHdr->Type),
                    (uint16_t)Length);
            }
            break;
        }

        default:
            QuicTraceLogVerbose(
                LogPacketLongHeaderUnsupported,
                "[%c][%cX][%llu] LH Ver:[UNSUPPORTED,0x%x] DestCid:%s SrcCid:%s",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                Invariant->LONG_HDR.Version,
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
                QuicCidBufToStr(SourceCid, SourceCidLen).Buffer);
            break;
        }

    } else {

        uint8_t DestCidLen = CIDLength;
        const uint8_t* DestCid = Invariant->SHORT_HDR.DestCid;

        switch (Version) {
        case QUIC_VERSION_DRAFT_27:
        case QUIC_VERSION_DRAFT_28:
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_MS_1: {
            const QUIC_SHORT_HEADER_V1 * const Header =
                (const QUIC_SHORT_HEADER_V1 * const)Packet;

            Offset = sizeof(QUIC_SHORT_HEADER_V1) + DestCidLen;

            QuicTraceLogVerbose(
                LogPacketShortHeader,
                "[%c][%cX][%llu] SH DestCid:%s KP:%hu SB:%hu (Payload %hu bytes)",
                PtkConnPre(Connection),
                PktRxPre(Rx),
                PacketNumber,
                QuicCidBufToStr(DestCid, DestCidLen).Buffer,
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
        InterlockedIncrement64((int64_t*)&((QUIC_CONNECTION*)Owner)->Stats.Recv.DroppedPackets);
        QuicTraceEvent(
            ConnDropPacket,
            "[conn][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->LocalAddress), &Datagram->Tuple->LocalAddress),
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->RemoteAddress), &Datagram->Tuple->RemoteAddress),
            Reason);
    } else {
        InterlockedIncrement64((int64_t*)&((QUIC_BINDING*)Owner)->Stats.Recv.DroppedPackets);
        QuicTraceEvent(
            BindingDropPacket,
            "[bind][%p] DROP packet Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->LocalAddress), &Datagram->Tuple->LocalAddress),
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->RemoteAddress), &Datagram->Tuple->RemoteAddress),
            Reason);
    }
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_PKTS_DROPPED);
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
        InterlockedIncrement64((int64_t*)&((QUIC_CONNECTION*)Owner)->Stats.Recv.DroppedPackets);
        QuicTraceEvent(
            ConnDropPacketEx,
            "[conn][%p] DROP packet Value=%llu Dst=%!ADDR! Src=%!ADDR! Reason=%s.",
            Owner,
            Value,
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->LocalAddress), &Datagram->Tuple->LocalAddress),
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->RemoteAddress), &Datagram->Tuple->RemoteAddress),
            Reason);
    } else {
        InterlockedIncrement64((int64_t*)&((QUIC_BINDING*)Owner)->Stats.Recv.DroppedPackets);
        QuicTraceEvent(
            BindingDropPacketEx,
            "[bind][%p] DROP packet %llu. Dst=%!ADDR! Src=%!ADDR! Reason=%s",
            Owner,
            Value,
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->LocalAddress), &Datagram->Tuple->LocalAddress),
            CLOG_BYTEARRAY(sizeof(Datagram->Tuple->RemoteAddress), &Datagram->Tuple->RemoteAddress),
            Reason);
    }
    QuicPerfCounterIncrement(QUIC_PERF_COUNTER_PKTS_DROPPED);
}
