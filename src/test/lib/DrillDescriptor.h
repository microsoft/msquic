/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
#pragma once

#ifdef _KERNEL_MODE
class DrillBuffer : public Rtl::KArray<uint8_t>
{
    public:
    void
    push_back(
        _In_ uint8_t value
        )
    {
        CXPLAT_FRE_ASSERT(append(value));
    }

    const uint8_t* data() const { return &(*this)[0]; }

    size_t size() const { return count(); }

    void
    insert(
        _In_ const iterator &dest,
        _In_ const const_iterator &start,
        _In_ const const_iterator &end
        )
    {
        CXPLAT_FRE_ASSERT(insertAt(dest, start, end));
    }
};
#else
using DrillBuffer = std::vector<uint8_t>;
#endif

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union

enum DrillPacketDescriptorType {
    UnknownPacketType,
    VersionNegotiation,
    LongHeader,
    Initial,
    Handshake,
    Zero_RTT,
    Retry,
    ShortHeader,
};

union QuicHeader {
    struct {
        uint8_t PacketNumLen : 2;
        uint8_t InitialReserved : 2;
        uint8_t LongHeaderType : 2;
        uint8_t FixedBit : 1;
        uint8_t LongHeader : 1;
    };
    uint8_t HeaderByte;
};

struct DrillPacketDescriptor {
    //
    // The type of datagram this describes.
    //
    DrillPacketDescriptorType Type {VersionNegotiation};

    QuicHeader Header {0};

    uint32_t Version {QUIC_VERSION_VER_NEG};

    //
    // Optional destination CID length. If not set, will use length of DestCid.
    //
    uint8_t* DestCidLen {nullptr};
    DrillBuffer DestCid;

    //
    // Optional source CID length. If not set, will use length of SourceCid.
    //
    uint8_t* SourceCidLen {nullptr};
    DrillBuffer SourceCid;

    DrillPacketDescriptor() { Header.LongHeader = TRUE; }

    //
    // Write this descriptor to a byte array to send on the wire.
    //
    virtual DrillBuffer write() const;
};

struct DrillVNPacketDescriptor : DrillPacketDescriptor {
    //
    // Write this descriptor to a byte array to send on the wire.
    //
    virtual DrillBuffer write() const;
};

struct DrillInitialPacketDescriptor : DrillPacketDescriptor {
    //
    // Optional Token length for the token. If unspecified, uses the length
    // of Token below.
    //
    uint64_t* TokenLen {nullptr};

    //
    // Token is optional. If unspecified, then it is elidded.
    //
    DrillBuffer Token;

    //
    // If unspecified, this value is auto-calculated from the fields.
    // Otherwise, this value is used regardless of actual packet length.
    //
    uint64_t* PacketLength {nullptr};

    //
    // The caller must ensure the packet number length bits in the header
    // match the magnitude of this PacketNumber.
    //
    uint32_t PacketNumber {0};

    DrillBuffer Payload;


    DrillInitialPacketDescriptor();

    //
    // Write this descriptor to a byte array to send on the wire.
    //
    virtual DrillBuffer write() const;
};

enum DrillVarIntSize {
    OneByte = 1,
    TwoBytes = 2,
    FourBytes = 4,
    EightBytes = 8
};

DrillBuffer
QuicDrillEncodeQuicVarInt (
    const uint64_t input,
    const DrillVarIntSize size
    );

DrillBuffer
QuicDrillEncodeQuicVarInt(
    uint64_t input
    );
