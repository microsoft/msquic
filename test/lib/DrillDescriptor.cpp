/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "precomp.h"

DrillBuffer
QuicDrillEncodeQuicVarInt(
    uint64_t input
    )
{
    DrillBuffer result;
    uint8_t* inputPointer = ((uint8_t*)&input);

    if (input < 0x40) {
        result.push_back((uint8_t) input);
    } else if (input < 0x4000) {
        result.push_back(0x40 | inputPointer[1]);
        result.push_back(inputPointer[0]);
    } else if (input < 0x40000000) {
        result.push_back(0x80 | inputPointer[3]);
        result.push_back(inputPointer[2]);
        result.push_back(inputPointer[1]);
        result.push_back(inputPointer[0]);
    } else if (input < 0x4000000000000000ull) {
        result.push_back(0xc0 | inputPointer[7]);
        result.push_back(inputPointer[6]);
        result.push_back(inputPointer[5]);
        result.push_back(inputPointer[4]);
        result.push_back(inputPointer[3]);
        result.push_back(inputPointer[2]);
        result.push_back(inputPointer[1]);
        result.push_back(inputPointer[0]);
    } else {
        QUIC_FRE_ASSERTMSG(
            input < 0x4000000000000000ull,
            "Supplied value is larger than QUIC_VAR_INT allowed (2^62)");
    }
    return result;
}

DrillBuffer
DrillPacketDescriptor::write(
    )
{
    size_t RequiredSize = 0;

    //
    // Calculate the size required to write the packet.
    //
    RequiredSize += 1; // For the bit fields.
    RequiredSize += sizeof(this->Version);
    RequiredSize += 1; // For the size of DestCid.
    RequiredSize += this->DestCid.size();
    RequiredSize += 1; // For the size of SourceCid.
    RequiredSize += this->SourceCid.size();

    QUIC_FRE_ASSERTMSG(
        RequiredSize <= UINT16_MAX,
        "Descriptor is larger than allowed packet size");

    //
    // Create new buffer for packet.
    //
    DrillBuffer PacketBuffer;

    //
    // Build Flags
    //
    QUIC_STATIC_ASSERT(sizeof(Header) == 1, "Header must be 1 byte");

    PacketBuffer.push_back(Header.HeaderByte);

    //
    // Copy version.
    //
    for (int i = 0; i < sizeof(this->Version); ++i) {
        PacketBuffer.push_back((uint8_t) (Version >> ((3 - i) * 8)));
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

    //
    // TODO: Do type-specific stuff here.
    //

    return PacketBuffer;
}

DrillInitialPacketDescriptor::DrillInitialPacketDescriptor(
    )
{
    this->Type = Initial;
    this->Header.LongHeader = 1;
    this->Header.FixedBit = 1;
    this->Version = 1;
}

DrillBuffer
DrillInitialPacketDescriptor::write(
    )
{
    DrillBuffer PacketBuffer = DrillPacketDescriptor::write();

    size_t CalculatedPacketLength = PacketBuffer.size();

    DrillBuffer EncodedTokenLength;
    if (TokenLen != nullptr) {
        EncodedTokenLength = QuicDrillEncodeQuicVarInt(*TokenLen);
    } else {
        EncodedTokenLength = QuicDrillEncodeQuicVarInt(Token.size());
    }
    PacketBuffer.insert(PacketBuffer.end(), EncodedTokenLength.begin(), EncodedTokenLength.end());

    CalculatedPacketLength += EncodedTokenLength.size();

    if (Token.size()) {
        PacketBuffer.insert(PacketBuffer.end(), Token.begin(), Token.end());
        CalculatedPacketLength += Token.size();
    }

    //
    // Note: this ignores the bits in the Header that specify how many bytes
    // are used. The caller must ensure these are in-sync.
    //
    DrillBuffer PacketNumberBuffer;
    if (PacketNumber < 0x100) {
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    } else if (PacketNumber < 0x10000) {
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 8));
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    } else if (PacketNumber < 0x1000000) {
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 16));
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 8));
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    } else {
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 24));
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 16));
        PacketNumberBuffer.push_back((uint8_t) (PacketNumber >> 8));
        PacketNumberBuffer.push_back((uint8_t) PacketNumber);
    }

    CalculatedPacketLength += PacketNumberBuffer.size();

    //
    // TODO: Calculate the payload length.
    //

    //
    // Write packet length.
    //
    DrillBuffer PacketLengthBuffer;
    if (PacketLength != nullptr) {
        PacketLengthBuffer = QuicDrillEncodeQuicVarInt(*PacketLength);
    } else {
        PacketLengthBuffer = QuicDrillEncodeQuicVarInt(CalculatedPacketLength);
    }
    PacketBuffer.insert(PacketBuffer.end(), PacketLengthBuffer.begin(), PacketLengthBuffer.end());

    //
    // Write packet number.
    //
    PacketBuffer.insert(PacketBuffer.end(), PacketNumberBuffer.begin(), PacketNumberBuffer.end());

    //
    // TODO: Write payload here.
    //

    return PacketBuffer;
}