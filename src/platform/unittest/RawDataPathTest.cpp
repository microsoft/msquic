/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath unit tests.

--*/

#include "main.h"
#include "quic_datapath.h"

namespace {

constexpr uint16_t EthernetHeaderLength = 14;
constexpr uint16_t Ipv4HeaderLength = CXPLAT_MIN_IPV4_HEADER_SIZE;
constexpr uint16_t UdpHeaderLength = CXPLAT_UDP_HEADER_SIZE;

constexpr uint8_t SourceIp[] = { 192, 0, 2, 1 };
constexpr uint8_t DestinationIp[] = { 192, 0, 2, 2 };
constexpr uint8_t Payload[] = { 0xDE, 0xAD, 0xBE, 0xEF };
constexpr uint8_t DestinationMac[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01
};
constexpr uint8_t SourceMac[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02
};

constexpr uint16_t SourcePort = 50000;
constexpr uint16_t DestinationPort = 443;
constexpr uint8_t TimeToLive = 64;
constexpr uint8_t TypeOfService = 0x2A;

constexpr uint16_t PayloadLength = sizeof(Payload);
constexpr uint16_t UdpLength = UdpHeaderLength + PayloadLength;
constexpr uint16_t IpLength = Ipv4HeaderLength + UdpLength;
constexpr uint16_t FrameLength = EthernetHeaderLength + IpLength;

constexpr uint16_t IpOffset = EthernetHeaderLength;
constexpr uint16_t UdpOffset = IpOffset + Ipv4HeaderLength;
constexpr uint16_t PayloadOffset = UdpOffset + UdpHeaderLength;

void
InitializeIpv4UdpFrame(_Out_writes_bytes_(FrameLength) uint8_t* Frame)
{
    CxPlatZeroMemory(Frame, FrameLength);

    //
    // Ethernet header.
    //
    CxPlatCopyMemory(Frame, DestinationMac, sizeof(DestinationMac));
    CxPlatCopyMemory(Frame + 6, SourceMac, sizeof(SourceMac));

    //
    // EtherType: IPv4 (0x0800).
    //
    Frame[12] = 0x08;
    Frame[13] = 0x00;

    //
    // IPv4 header.
    //
    Frame[IpOffset] = 0x45;
    Frame[IpOffset + 1] = TypeOfService;
    Frame[IpOffset + 2] = (uint8_t)(IpLength >> 8);
    Frame[IpOffset + 3] = (uint8_t)(IpLength & 0xFF);
    Frame[IpOffset + 8] = TimeToLive;
    Frame[IpOffset + 9] = IPPROTO_UDP;

    CxPlatCopyMemory(Frame + IpOffset + 12, SourceIp, sizeof(SourceIp));
    CxPlatCopyMemory(Frame + IpOffset + 16, DestinationIp, sizeof(DestinationIp));

    //
    // UDP header.
    //
    Frame[UdpOffset] = (uint8_t)(SourcePort >> 8);
    Frame[UdpOffset + 1] = (uint8_t)(SourcePort & 0xFF);
    Frame[UdpOffset + 2] = (uint8_t)(DestinationPort >> 8);
    Frame[UdpOffset + 3] = (uint8_t)(DestinationPort & 0xFF);
    Frame[UdpOffset + 4] = (uint8_t)(UdpLength >> 8);
    Frame[UdpOffset + 5] = (uint8_t)(UdpLength & 0xFF);

    CxPlatCopyMemory(Frame + PayloadOffset, Payload, sizeof(Payload));
}

//
// A successful parse of the IPv4/UDP frame updates Buffer and BufferLength.
//
void
ExpectParseRejected(
    _In_reads_bytes_(Length)
        const uint8_t* Frame,
    _In_ uint16_t Length
    )
{
    uint8_t Sentinel = 0xA5;

    CXPLAT_ROUTE Route = {};
    CXPLAT_RECV_DATA Packet = {};

    Packet.Route = &Route;
    Packet.Buffer = &Sentinel;
    Packet.BufferLength = 1;

    CxPlatDataPathTestParseEthernet(&Packet, Frame, Length);

    EXPECT_EQ(&Sentinel, Packet.Buffer);
    EXPECT_EQ(1, Packet.BufferLength);
}

TEST(RawDataPathTest, ParseIpv4Udp)
{
    uint8_t Frame[FrameLength];
    InitializeIpv4UdpFrame(Frame);

    CXPLAT_ROUTE Route = {};
    CXPLAT_RECV_DATA Packet = {};
    Packet.Route = &Route;

    CxPlatDataPathTestParseEthernet(&Packet, Frame, FrameLength);

    EXPECT_EQ(AF_INET, Route.RemoteAddress.Ipv4.sin_family);
    EXPECT_EQ(AF_INET, Route.LocalAddress.Ipv4.sin_family);

    EXPECT_EQ(0, memcmp(&Route.RemoteAddress.Ipv4.sin_addr, SourceIp, sizeof(SourceIp)));

    EXPECT_EQ(0, memcmp(&Route.LocalAddress.Ipv4.sin_addr, DestinationIp, sizeof(DestinationIp)));

    EXPECT_EQ(SourcePort, QuicAddrGetPort(&Route.RemoteAddress));

    EXPECT_EQ(DestinationPort, QuicAddrGetPort(&Route.LocalAddress));

    EXPECT_EQ(TimeToLive, Packet.HopLimitTTL);
    EXPECT_EQ(TypeOfService, Packet.TypeOfService);

    EXPECT_EQ(0, memcmp(Route.LocalLinkLayerAddress, DestinationMac, sizeof(DestinationMac)));

    EXPECT_EQ(0, memcmp(Route.NextHopLinkLayerAddress, SourceMac, sizeof(SourceMac)));

    ASSERT_EQ(sizeof(Payload), Packet.BufferLength);
    ASSERT_NE(nullptr, Packet.Buffer);

    EXPECT_EQ(Frame + PayloadOffset, Packet.Buffer);

    EXPECT_EQ(0, memcmp(Packet.Buffer, Payload, sizeof(Payload)));
}

TEST(RawDataPathTest, RejectTruncatedEthernet)
{
    uint8_t Frame[FrameLength];
    InitializeIpv4UdpFrame(Frame);

    ExpectParseRejected(Frame, EthernetHeaderLength - 1);
}

TEST(RawDataPathTest, RejectTruncatedIpv4)
{
    uint8_t Frame[FrameLength];
    InitializeIpv4UdpFrame(Frame);

    ExpectParseRejected(Frame, EthernetHeaderLength + Ipv4HeaderLength - 1);
}

TEST(RawDataPathTest, RejectIpv4LengthExceedsFrame)
{
    uint8_t Frame[FrameLength];
    InitializeIpv4UdpFrame(Frame);

    constexpr uint16_t InvalidIpLength = IpLength + 1;
    Frame[IpOffset + 2] = (uint8_t)(InvalidIpLength >> 8);
    Frame[IpOffset + 3] = (uint8_t)(InvalidIpLength & 0xFF);

    ExpectParseRejected(Frame, FrameLength);
}

TEST(RawDataPathTest, RejectUdpLengthBelowHeader)
{
    uint8_t Frame[FrameLength];
    InitializeIpv4UdpFrame(Frame);

    constexpr uint16_t InvalidUdpLength = UdpHeaderLength - 1;
    Frame[UdpOffset + 4] = (uint8_t)(InvalidUdpLength >> 8);
    Frame[UdpOffset + 5] = (uint8_t)(InvalidUdpLength & 0xFF);

    ExpectParseRejected(Frame, FrameLength);
}

TEST(RawDataPathTest, RejectUdpLengthExceedsIpPayload)
{
    uint8_t Frame[FrameLength];
    InitializeIpv4UdpFrame(Frame);

    constexpr uint16_t InvalidUdpLength = UdpLength + 1;
    Frame[UdpOffset + 4] = (uint8_t)(InvalidUdpLength >> 8);
    Frame[UdpOffset + 5] = (uint8_t)(InvalidUdpLength & 0xFF);

    ExpectParseRejected(Frame, FrameLength);
}

} // namespace
