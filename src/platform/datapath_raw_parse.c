/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath packet parsing

--*/

#include "datapath_raw.h"

#ifdef QUIC_CLOG
#include "datapath_raw_parse.c.clog.h"
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpRawParseUdp(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const UDP_HEADER* Udp,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(UDP_HEADER)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for a UDP header");
        return;
    }

    const uint16_t UdpLength = QuicNetByteSwapShort(Udp->Length);

    if (Length < UdpLength) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "UDP Length larger than IP length");
        return;
    }

    if (UdpLength < sizeof(UDP_HEADER)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            UdpLength,
            "UDP Length smaller than header size");
        return;
    }

    Packet->Reserved = L4_TYPE_UDP;

    Packet->Route->RemoteAddress.Ipv4.sin_port = Udp->SourcePort;
    Packet->Route->LocalAddress.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Buffer = (uint8_t*)Udp->Data;
    Packet->BufferLength = UdpLength - sizeof(UDP_HEADER);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpRawParseTcp(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const TCP_HEADER* Tcp,
    _In_ uint16_t Length
    )
{
    uint16_t HeaderLength;
    if (Length < sizeof(TCP_HEADER)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for a TCP header");
        return;
    }

    HeaderLength = Tcp->HeaderLength * sizeof(uint32_t);
    if (Length < HeaderLength) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for a TCP header");
        return;
    }

    Length -= HeaderLength;

    //
    // We only handle 3 types of TCP packets:
    // 1. Pure ACKs that carry at least one byte data.
    // 2. SYNs and SYN+ACKs for TCP handshake.
    // 3. FINs for graceful shutdown.
    //
    // Packets that don't match the rules above are discarded.
    //
    if (Tcp->Flags == TH_ACK && Length > 0) {
        //
        // Only data packets with only ACK flag set are indicated to QUIC core.
        //
        Packet->Reserved = L4_TYPE_TCP;
        Packet->Route->TcpState.AckNumber = Tcp->AckNumber;
        Packet->Route->TcpState.SequenceNumber = Tcp->SequenceNumber;
    } else if (Tcp->Flags & TH_SYN) {
        if (Tcp->Flags & TH_ACK) {
            Packet->Reserved = L4_TYPE_TCP_SYNACK;
        } else {
            Packet->Reserved = L4_TYPE_TCP_SYN;
        }
    } else if (Tcp->Flags & TH_FIN) {
        Packet->Reserved = L4_TYPE_TCP_FIN;
    } else {
        return;
    }

    Packet->Route->RemoteAddress.Ipv4.sin_port = Tcp->SourcePort;
    Packet->Route->LocalAddress.Ipv4.sin_port = Tcp->DestinationPort;

    Packet->Buffer = (uint8_t*)(Tcp) + HeaderLength;
    Packet->BufferLength = Length;
    Packet->ReservedEx = HeaderLength;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpRawParseIPv4(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const IPV4_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV4_HEADER)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for an IPv4 header");
        return;
    }

    if (IP->VersionAndHeaderLength != IPV4_DEFAULT_VERHLEN) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            IP->VersionAndHeaderLength,
            "unexpected IPv4 header length and version");
        return;
    }

    uint16_t IPTotalLength = CxPlatByteSwapUint16(IP->TotalLength);
    if (IPTotalLength < sizeof(IPV4_HEADER) || Length < IPTotalLength) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "unexpected IPv4 packet size");
        return;
    }

    Packet->TypeOfService = IP->TypeOfServiceAndEcnField;
    Packet->HopLimitTTL = IP->TimeToLive;
    Packet->Route->RemoteAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Route->RemoteAddress.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->Route->LocalAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Route->LocalAddress.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->Protocol == IPPROTO_UDP) {
        Packet->Route->UseQTIP = FALSE;
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, IPTotalLength - sizeof(IPV4_HEADER));
    } else if (IP->Protocol == IPPROTO_TCP) {
        Packet->Route->UseQTIP = TRUE;
        CxPlatDpRawParseTcp(Datapath, Packet, (TCP_HEADER*)IP->Data, IPTotalLength - sizeof(IPV4_HEADER));
    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            IP->Protocol,
            "unacceptable v4 transport");
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpRawParseIPv6(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const IPV6_HEADER* IP,
    _In_ uint16_t Length
    )
{

    if (Length < sizeof(IPV6_HEADER)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for an IPv6 header");
        return;
    }

    uint16_t IPPayloadLength = CxPlatByteSwapUint16(IP->PayloadLength);
    if (IPPayloadLength + sizeof(IPV6_HEADER) > Length) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            IPPayloadLength,
            "incorrect IP payload length");
        return;
    }

    //
    // IPv6 Version, Traffic Class, ECN Field and Flow Label fields in host
    // byte order.
    //
    union {
        struct {
            uint32_t Flow : 20;
            uint32_t EcnField : 2;
            uint32_t Class : 6;
            uint32_t Version : 4; // Most significant bits.
        };
        uint32_t Value;
    } VersionClassEcnFlow;
    VersionClassEcnFlow.Value = CxPlatByteSwapUint32(IP->VersionClassEcnFlow);

    Packet->TypeOfService = (uint8_t)(VersionClassEcnFlow.EcnField | (VersionClassEcnFlow.Class << 2));
    Packet->HopLimitTTL = IP->HopLimit;
    Packet->Route->RemoteAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Route->RemoteAddress.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->Route->LocalAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Route->LocalAddress.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->NextHeader == IPPROTO_UDP) {
        Packet->Route->UseQTIP = FALSE;
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, IPPayloadLength);
    } else if (IP->NextHeader == IPPROTO_TCP) {
        Packet->Route->UseQTIP = TRUE;
        CxPlatDpRawParseTcp(Datapath, Packet, (TCP_HEADER*)IP->Data, IPPayloadLength);
    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            IP->NextHeader,
            "unacceptable v6 transport");
    }
}

BOOLEAN IsEthernetBroadcast(_In_reads_(6) const uint8_t Address[6])
{
    return (Address[0] == 0xFF) && (Address[1] == 0xFF) && (Address[2] == 0xFF) && (Address[3] == 0xFF) && (Address[4] == 0xFF) && (Address[5] == 0xFF);
}

BOOLEAN IsEthernetMulticast(_In_reads_(6) const uint8_t Address[6])
{
    return (Address[0] & 0x01) == 0x01;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawParseEthernet(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(ETHERNET_HEADER)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "packet is too small for an ethernet header");
        return;
    }

    Length -= sizeof(ETHERNET_HEADER);

    const ETHERNET_HEADER* Ethernet = (const ETHERNET_HEADER*)Payload;

    if (IsEthernetBroadcast(Ethernet->Destination) || IsEthernetMulticast(Ethernet->Destination)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            0,
            "not a unicast packet");
        return;
    }

    CxPlatCopyMemory(&Packet->Route->LocalLinkLayerAddress, Ethernet->Destination, sizeof(Ethernet->Destination));
    CxPlatCopyMemory(&Packet->Route->NextHopLinkLayerAddress, Ethernet->Source, sizeof(Ethernet->Source));

    uint16_t EthernetType = Ethernet->Type;
    if (EthernetType == ETHERNET_TYPE_IPV4) {
        CxPlatDpRawParseIPv4(Datapath, Packet, (IPV4_HEADER*)Ethernet->Data, Length);
    } else if (EthernetType == ETHERNET_TYPE_IPV6) {
        CxPlatDpRawParseIPv6(Datapath, Packet, (IPV6_HEADER*)Ethernet->Data, Length);
    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            EthernetType,
            "unacceptable ethernet type");
    }
}
