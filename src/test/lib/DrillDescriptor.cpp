/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"
#include <quic_crypt.h>
#include <msquichelper.h>

#ifdef QUIC_CLOG
#include "DrillDescriptor.cpp.clog.h"
#endif

DrillBuffer
QuicDrillEncodeQuicVarInt(
    uint64_t input,
    const DrillVarIntSize size
    )
{
    DrillBuffer result;
    uint8_t* inputPointer = ((uint8_t*)&input);

    if (size == OneByte) {
        CXPLAT_FRE_ASSERT(input < 0x40);
        result.push_back((uint8_t) input);
    } else if (size == TwoBytes) {
        CXPLAT_FRE_ASSERT(input < 0x4000);
        result.push_back(0x40 | inputPointer[1]);
        result.push_back(inputPointer[0]);
    } else if (size == FourBytes) {
        CXPLAT_FRE_ASSERT(input < 0x40000000);
        result.push_back(0x80 | inputPointer[3]);
        result.push_back(inputPointer[2]);
        result.push_back(inputPointer[1]);
        result.push_back(inputPointer[0]);
    } else if (size == EightBytes) {
        CXPLAT_FRE_ASSERT(input < 0x4000000000000000ull);
        result.push_back(0xc0 | inputPointer[7]);
        result.push_back(inputPointer[6]);
        result.push_back(inputPointer[5]);
        result.push_back(inputPointer[4]);
        result.push_back(inputPointer[3]);
        result.push_back(inputPointer[2]);
        result.push_back(inputPointer[1]);
        result.push_back(inputPointer[0]);
    } else {
        CXPLAT_FRE_ASSERTMSG(
            size == EightBytes,
            "Supplied size is not a valid  QUIC_VAR_INT size");
    }
    return result;
}

DrillBuffer
QuicDrillEncodeQuicVarInt (
    uint64_t input
    )
{
    if (input < 0x40) {
        return QuicDrillEncodeQuicVarInt(input, OneByte);
    } else if (input < 0x4000) {
        return QuicDrillEncodeQuicVarInt(input, TwoBytes);
    } else if (input < 0x40000000) {
        return QuicDrillEncodeQuicVarInt(input, FourBytes);
    } else if (input < 0x4000000000000000ull) {
        return QuicDrillEncodeQuicVarInt(input, EightBytes);
    } else {
        CXPLAT_FRE_ASSERTMSG(
            input < 0x4000000000000000ull,
            "Supplied value is larger than QUIC_VAR_INT allowed (2^62)");
        return DrillBuffer();
    }
}

DrillBuffer
DrillPacketDescriptor::write(
    ) const
{
    size_t RequiredSize = 0;

    //
    // Calculate the size required to write the packet.
    //
    RequiredSize += 1; // For the bit fields.
    RequiredSize += sizeof(Version);
    RequiredSize += 1; // For the size of DestCid.
    RequiredSize += DestCid.size();
    RequiredSize += 1; // For the size of SourceCid.
    RequiredSize += SourceCid.size();

    CXPLAT_FRE_ASSERTMSG(
        RequiredSize <= UINT16_MAX,
        "Descriptor is larger than allowed packet size");

    //
    // Create new buffer for packet.
    //
    DrillBuffer PacketBuffer;

    //
    // Build Flags
    //
    CXPLAT_STATIC_ASSERT(sizeof(Header) == 1, "Header must be 1 byte");

    PacketBuffer.push_back(Header.HeaderByte);

    //
    // Copy version.
    //
    for (size_t i = 0; i < sizeof(Version); ++i) {
        PacketBuffer.push_back((uint8_t) (Version >> (((sizeof(Version) - 1) - i) * 8)));
    }

    //
    // Copy Destination CID.
    //
    if (DestCidLen != nullptr) {
        PacketBuffer.push_back(*DestCidLen);
    } else {
        PacketBuffer.push_back((uint8_t) DestCid.size());
    }
    PacketBuffer.insert(PacketBuffer.end(), DestCid.begin(), DestCid.end());

    //
    // Copy Source CID.
    //
    if (SourceCidLen != nullptr) {
        PacketBuffer.push_back((uint8_t) *SourceCidLen);
    } else {
        PacketBuffer.push_back((uint8_t) SourceCid.size());
    }
    PacketBuffer.insert(PacketBuffer.end(), SourceCid.begin(), SourceCid.end());

    return PacketBuffer;
}

DrillBuffer
DrillVNPacketDescriptor::write(
    ) const
{
    DrillBuffer PacketBuffer = DrillPacketDescriptor::write();

    // uint32_t SupportedVersions[]
    uint32_t SupportedVer = QUIC_VERSION_2_H;
    for (size_t i = 0; i < sizeof(SupportedVer); ++i) {
        PacketBuffer.push_back((uint8_t) (SupportedVer >> (((sizeof(SupportedVer) - 1) - i) * 8)));
    }
    SupportedVer = QUIC_VERSION_1_MS_H;
    for (size_t i = 0; i < sizeof(SupportedVer); ++i) {
        PacketBuffer.push_back((uint8_t) (SupportedVer >> (((sizeof(SupportedVer) - 1) - i) * 8)));
    }

    return PacketBuffer;
}

DrillInitialPacketDescriptor::DrillInitialPacketDescriptor(uint8_t SrcCidLength)
{
    Type = Initial;
    Header.FixedBit = 1;
    Version = QUIC_VERSION_LATEST_H;

    const uint8_t CidValMax = 8;
    for (uint8_t CidVal = 0; CidVal <= CidValMax; CidVal++) {
        DestCid.push_back(CidVal);
    }

    for (uint8_t CidVal = 0; CidVal < SrcCidLength; CidVal++) {
        SourceCid.push_back(SrcCidLength - CidVal);
    }
}

DrillBuffer
DrillInitialPacketDescriptor::writeEx(
    bool EncryptPayload
    ) const
{
    DrillBuffer PacketBuffer = DrillPacketDescriptor::write();

    DrillBuffer EncodedTokenLength;
    if (TokenLen != nullptr) {
        EncodedTokenLength = QuicDrillEncodeQuicVarInt(*TokenLen);
    } else {
        EncodedTokenLength = QuicDrillEncodeQuicVarInt(Token.size());
    }
    PacketBuffer.insert(PacketBuffer.end(), EncodedTokenLength.begin(), EncodedTokenLength.end());

    if (Token.size()) {
        PacketBuffer.insert(PacketBuffer.end(), Token.begin(), Token.end());
    }

    //
    // Packet number buffer.
    //
    DrillBuffer PacketNumberBuffer;
    if (Header.PacketNumLen == 0) {
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    } else if (Header.PacketNumLen == 1) {
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 8));
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    } else if (Header.PacketNumLen == 2) {
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 16));
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 8));
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    } else {
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 24));
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 16));
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 8));
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    }

    //
    // Write packet length.
    //
    DrillBuffer PacketLengthBuffer;
    if (PacketLength != nullptr) {
        PacketLengthBuffer = QuicDrillEncodeQuicVarInt(*PacketLength);
    } else {
        size_t CalculatedPacketLength = PacketNumberBuffer.size() + Payload.size();
        if (EncryptPayload) {
            CalculatedPacketLength += CXPLAT_ENCRYPTION_OVERHEAD;
        }
        PacketLengthBuffer = QuicDrillEncodeQuicVarInt(CalculatedPacketLength);
    }
    PacketBuffer.insert(PacketBuffer.end(), PacketLengthBuffer.begin(), PacketLengthBuffer.end());

    //
    // Write packet number.
    //
    PacketBuffer.insert(PacketBuffer.end(), PacketNumberBuffer.begin(), PacketNumberBuffer.end());

    auto HeaderLength = (uint16_t)PacketBuffer.size();

    //
    // Write payload.
    //
    if (Payload.size() > 0) {
        PacketBuffer.insert(PacketBuffer.end(), Payload.begin(), Payload.end());
    }

    if (EncryptPayload) {
        for (uint8_t i = 0; i < CXPLAT_ENCRYPTION_OVERHEAD; ++i) {
            PacketBuffer.push_back(0);
        }
        encrypt(PacketBuffer, HeaderLength, (uint8_t)PacketNumberBuffer.size());
    }

    return PacketBuffer;
}

void
DrillInitialPacketDescriptor::encrypt(
    DrillBuffer& PacketBuffer,
    uint16_t HeaderLength,
    uint8_t PacketNumberLength
    ) const
{
    const QUIC_HKDF_LABELS HkdfLabels = { "quic key", "quic iv", "quic hp", "quic ku" };
    const StrBuffer InitialSalt("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    QUIC_PACKET_KEY* WriteKey;
    if(QUIC_SUCCEEDED(
        QuicPacketKeyCreateInitial(
            FALSE,
            &HkdfLabels,
            InitialSalt.Data,
            (uint8_t)DestCid.size(),
            DestCid.data(),
            nullptr,
            &WriteKey))) {

        uint8_t Iv[CXPLAT_IV_LENGTH];
        uint64_t FullPacketNumber = PacketNumber;
        QuicCryptoCombineIvAndPacketNumber(
            WriteKey->Iv, (uint8_t*)&FullPacketNumber, Iv);

        CxPlatEncrypt(
            WriteKey->PacketKey,
            Iv,
            HeaderLength,
            PacketBuffer.data(),
            (uint16_t)PacketBuffer.size() - HeaderLength,
            PacketBuffer.data() + HeaderLength);

        uint8_t HpMask[16];
        CxPlatHpComputeMask(
            WriteKey->HeaderKey,
            1,
            PacketBuffer.data() + HeaderLength,
            HpMask);

        uint16_t PacketNumberOffset = HeaderLength - PacketNumberLength;
        PacketBuffer[0] ^= HpMask[0] & 0x0F;
        for (uint8_t i = 0; i < PacketNumberLength; ++i) {
            PacketBuffer[PacketNumberOffset + i] ^= HpMask[i + 1];
        }

        QuicPacketKeyFree(WriteKey);
    }
}

union QuicShortHeader {
    uint8_t HeaderByte;
    struct {
        uint8_t PacketNumLen : 2;
        uint8_t KeyPhase : 1;
        uint8_t Reserved : 2;
        uint8_t SpinBit : 1;
        uint8_t FixedBit : 1;
        uint8_t LongHeader : 1;
    };
};

DrillBuffer
Drill1RttPacketDescriptor::write(
    ) const
{
    DrillBuffer PacketBuffer;
    QuicShortHeader Header = { 0 };
    Header.PacketNumLen = 3;
    Header.KeyPhase = KeyPhase;

    PacketBuffer.push_back(Header.HeaderByte);
    PacketBuffer.insert(PacketBuffer.end(), DestCid.begin(), DestCid.end());
    PacketBuffer.push_back((uint8_t) (PacketNumber >> 24));// TODO - different packet number sizes
    PacketBuffer.push_back((uint8_t) (PacketNumber >> 16));
    PacketBuffer.push_back((uint8_t) (PacketNumber >> 8));
    PacketBuffer.push_back((uint8_t) PacketNumber);
    PacketBuffer.insert(PacketBuffer.end(), Payload.begin(), Payload.end());

    return PacketBuffer;
}
