/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/
#pragma once

#ifdef _KERNEL_MODE
#ifdef PAGEDX
#undef PAGEDX
#endif
#ifdef INITCODE
#undef INITCODE
#endif
#include <karray.h>
#else
#include <vector>
#endif

#ifdef _KERNEL_MODE
class DrillBuffer : public Rtl::KArray<uint8_t>
{
    public:
    void
    push_back(
        _In_ uint8_t value
        )
    {
        QUIC_FRE_ASSERT(append(value));
    }

    size_t size() { return count(); }
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
    DrillPacketDescriptorType Type;

    QuicHeader Header;

    uint32_t Version;

    //
    // Optional destination CID length. If not set, will use length of DestCID.
    //
    uint8_t* DestCIDLen;
    DrillBuffer DestCID;

    //
    // Optional source CID length. If not set, will use length of SourceCID.
    //
    uint8_t* SourceCIDLen;
    DrillBuffer SourceCID;

    //
    // Write this descriptor to a byte array to send on the wire.
    //
    virtual DrillBuffer write();
};


struct DrillInitialPacketDescriptor : DrillPacketDescriptor {
    //
    // Optional Token length for the token. If unspecified, uses the length
    // of Token below.
    //
    uint64_t* TokenLen;

    //
    // Token is optional. If unspecified, then it is elidded.
    //
    DrillBuffer Token;

    //
    // If unspecified, this value is auto-calculated from the fields.
    // Otherwise, this value is used regardless of actual packet length.
    //
    uint64_t* PacketLength;

    //
    // The caller must ensure the packet number length bits in the header
    // match the magnitude of this PacketNumber.
    //
    uint32_t PacketNumber;


    DrillInitialPacketDescriptor();

    //
    // Write this descriptor to a byte array to send on the wire.
    //
    virtual DrillBuffer write();
};

DrillBuffer
QuicDrillEncodeQuicVarInt (
    uint64_t input
    );