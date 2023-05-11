#include "datapath_raw_framing.h"
#ifdef QUIC_CLOG
#include "datapath_raw.c.clog.h"
#endif

//
// Ethernet / IP Framing Logic
//

#pragma pack(push)
#pragma pack(1)

typedef struct ETHERNET_HEADER {
    uint8_t Destination[6];
    uint8_t Source[6];
    uint16_t Type;
    uint8_t Data[0];
} ETHERNET_HEADER;

typedef struct IPV4_HEADER {
    uint8_t VersionAndHeaderLength;
    union {
        uint8_t TypeOfServiceAndEcnField;
        struct {
            uint8_t EcnField : 2;
            uint8_t TypeOfService : 6;
        };
    };
    uint16_t TotalLength;
    uint16_t Identification;
    uint16_t FlagsAndFragmentOffset;
    uint8_t TimeToLive;
    uint8_t Protocol;
    uint16_t HeaderChecksum;
    uint8_t Source[4];
    uint8_t Destination[4];
    uint8_t Data[0];
} IPV4_HEADER;

typedef struct IPV6_HEADER {
    uint32_t VersionClassEcnFlow;
    uint16_t PayloadLength;
    uint8_t NextHeader;
    uint8_t HopLimit;
    uint8_t Source[16];
    uint8_t Destination[16];
    uint8_t Data[0];
} IPV6_HEADER;

typedef struct IPV6_EXTENSION {
    uint8_t NextHeader;
    uint8_t Length;
    uint16_t Reserved0;
    uint32_t Reserved1;
    uint8_t Data[0];
} IPV6_EXTENSION;

typedef struct UDP_HEADER {
    uint16_t SourcePort;
    uint16_t DestinationPort;
    uint16_t Length;
    uint16_t Checksum;
    uint8_t Data[0];
} UDP_HEADER;

typedef struct TCP_HEADER {
    uint16_t SourcePort;
    uint16_t DestinationPort;
    uint32_t SequenceNumber;
    uint32_t AckNumber;
    uint8_t X2           : 4;
    uint8_t HeaderLength : 4;
    uint8_t Flags;
    uint16_t Window;
    uint16_t Checksum;
    uint16_t UrgentPointer;
} TCP_HEADER;

#pragma pack(pop)

//
// Constants for headers in wire format.
//

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define IPV4_VERSION 4
#define IPV6_VERSION 6
#define IPV4_VERSION_BYTE (IPV4_VERSION << 4)
#define IPV4_DEFAULT_VERHLEN ((IPV4_VERSION_BYTE) | (sizeof(IPV4_HEADER) / sizeof(uint32_t)))

#define IP_DEFAULT_HOP_LIMIT 128

#define ETHERNET_TYPE_IPV4 0x0008
#define ETHERNET_TYPE_IPV6 0xdd86

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

    Length -= sizeof(UDP_HEADER);
    Packet->Reserved = L4_TYPE_UDP;

    Packet->Route->RemoteAddress.Ipv4.sin_port = Udp->SourcePort;
    Packet->Route->LocalAddress.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Buffer = (uint8_t*)Udp->Data;
    Packet->BufferLength = Length;
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
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "unexpected TCP packets");
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
    if (Length < IPTotalLength) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "unexpected IPv4 packet size");
        return;
    }

    Packet->TypeOfService = IP->EcnField;
    Packet->Route->RemoteAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Route->RemoteAddress.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->Route->LocalAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Route->LocalAddress.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));
    if (IP->Protocol == IPPROTO_UDP) {
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, IPTotalLength - sizeof(IPV4_HEADER));
    } else if (IP->Protocol == IPPROTO_TCP) {
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

    Packet->TypeOfService = (uint8_t)VersionClassEcnFlow.EcnField;
    Packet->Route->RemoteAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Route->RemoteAddress.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->Route->LocalAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Route->LocalAddress.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->NextHeader == IPPROTO_UDP) {
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, IPPayloadLength);
    } else if (IP->NextHeader == IPPROTO_TCP) {
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

// TODO: unify that of windows
static uint16_t csum16(uint16_t *buf, int nwords) {
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int framing_packet(size_t size,
                   const uint8_t src_mac[ETH_ALEN], const uint8_t dst_mac[ETH_ALEN],
                   QUIC_ADDR* LocalAddress, QUIC_ADDR* RemoteAddress,
                   uint16_t src_port, uint16_t dst_port,
                   CXPLAT_ECN_TYPE ECN,
                   struct ethhdr* eth) {
    QUIC_ADDR_STR LocalAddrStr;
    QUIC_ADDR_STR RemoteAddrStr;
    if (LocalAddress)
        QuicAddrToString(LocalAddress, &LocalAddrStr);
    if (RemoteAddress)
        QuicAddrToString(RemoteAddress, &RemoteAddrStr);

    //struct ethhdr *eth;
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;
    struct udphdr *udph;

    // Populate the Ethernet header
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    QUIC_ADDRESS_FAMILY FamilyL = QuicAddrGetFamily(LocalAddress);
    QUIC_ADDRESS_FAMILY FamilyR = QuicAddrGetFamily(RemoteAddress);
    fprintf(stderr, "framing_packet Local:[%d][%02x:%02x:%02x:%02x:%02x:%02x][%s], Remote:[%d][%02x:%02x:%02x:%02x:%02x:%02x][%s]\n",
            FamilyL, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
            LocalAddress ? LocalAddrStr.Address : "NULL",
            FamilyR, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
            RemoteAddress ? RemoteAddrStr.Address : "NULL");
    if (FamilyL == QUIC_ADDRESS_FAMILY_INET) {
        eth->h_proto = htons(ETH_P_IP);
        iph = (struct iphdr *)((char *)eth + sizeof(struct ethhdr));
        udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));

        // Populate the IP header
        iph->ihl = sizeof(struct iphdr) / 4;
        iph->version = 4;
        iph->tos = ECN;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + size);
        iph->id = 0;
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = ntohl(LocalAddress->Ipv4.sin_addr.s_addr);
        iph->daddr = ntohl(RemoteAddress->Ipv4.sin_addr.s_addr);
        iph->check = 0;
        iph->check = csum16((uint16_t *)iph, sizeof(struct iphdr) / 2);
    } else {
        eth->h_proto = htons(ETH_P_IPV6);
        ip6h = (struct ipv6hdr *)((char *)eth + sizeof(struct ethhdr));
        udph = (struct udphdr *)((char *)ip6h + sizeof(struct ipv6hdr));

        // Populate the IPv6 header
        ip6h->version = 6;
        ip6h->priority = (ECN >> 4) & 0x0F;
        ip6h->flow_lbl[0] = (ECN << 4) & 0xF0;
        ip6h->flow_lbl[1] = 0;
        ip6h->flow_lbl[2] = 0;
        ip6h->payload_len = htons(sizeof(struct udphdr) + size);
        ip6h->nexthdr = IPPROTO_UDP;
        ip6h->hop_limit = 64;
        memcpy(&ip6h->saddr, &LocalAddress->Ipv6.sin6_addr, sizeof(struct in6_addr));
        memcpy(&ip6h->daddr, &RemoteAddress->Ipv6.sin6_addr, sizeof(struct in6_addr));
    }

    // Populate the UDP header
    udph->source = src_port;
    udph->dest = dst_port;
    udph->len = htons(sizeof(struct udphdr) + size);
    udph->check = 0; //
    // NOTE: For simplicity UDP checksum to zero
    //      In production code, it's recommended to calculate and set the correct checksum.

    return 0;
}


// _IRQL_requires_max_(DISPATCH_LEVEL)
// uint16_t
// CxPlatFramingChecksum(
//     _In_reads_(Length) uint8_t* Data,
//     _In_ uint32_t Length,
//     _In_ uint64_t InitialChecksum
//     )
// {
//     //
//     // Add up all bytes in 3 steps:
//     // 1. Add the odd byte to the checksum if the length is odd.
//     // 2. If the length is divisible by 2 but not 4, add the last 2 bytes.
//     // 3. Sum up the rest as 32-bit words.
//     //

//     if ((Length & 1) != 0) {
//         --Length;
//         InitialChecksum += Data[Length];
//     }

//     if ((Length & 2) != 0) {
//         Length -= 2;
//         InitialChecksum += *((uint16_t*)(&Data[Length]));
//     }

//     for (uint32_t i = 0; i < Length; i += 4) {
//         InitialChecksum += *((uint32_t*)(&Data[i]));
//     }

//     //
//     // Fold all carries into the final checksum.
//     //
//     while (InitialChecksum >> 16) {
//         InitialChecksum = (InitialChecksum & 0xffff) + (InitialChecksum >> 16);
//     }

//     return (uint16_t)InitialChecksum;
// }

// _IRQL_requires_max_(DISPATCH_LEVEL)
// uint16_t
// CxPlatFramingTransportChecksum(
//     _In_reads_(AddrLength) uint8_t* SrcAddr,
//     _In_reads_(AddrLength) uint8_t* DstAddr,
//     _In_ uint32_t AddrLength,
//     _In_ uint16_t NextHeader,
//     _In_reads_(IPPayloadLength) uint8_t* IPPayload,
//     _In_ uint32_t IPPayloadLength
//     )
// {
//     uint64_t Checksum =
//         CxPlatFramingChecksum(SrcAddr, AddrLength, 0) +
//         CxPlatFramingChecksum(DstAddr, AddrLength, 0);
//     Checksum += CxPlatByteSwapUint16(NextHeader);
//     Checksum += CxPlatByteSwapUint16((uint16_t)IPPayloadLength);

//     //
//     // Pseudoheader is always in 32-bit words. So, cross 16-bit boundary adjustment isn't needed.
//     //
//     return ~CxPlatFramingChecksum(IPPayload, IPPayloadLength, Checksum);
// }

// _IRQL_requires_max_(DISPATCH_LEVEL)
// void
// CxPlatFramingWriteHeaders(
//     _In_ CXPLAT_SOCKET* Socket,
//     _In_ const CXPLAT_ROUTE* Route,
//     _Inout_ QUIC_BUFFER* Buffer,
//     _In_ CXPLAT_ECN_TYPE ECN,
//     _In_ BOOLEAN SkipNetworkLayerXsum,
//     _In_ BOOLEAN SkipTransportLayerXsum,
//     _In_ uint32_t TcpSeqNum,
//     _In_ uint32_t TcpAckNum,
//     _In_ uint8_t TcpFlags
//     )
// {
//     uint8_t* Transport;
//     uint16_t TransportLength;
//     uint8_t TransportProtocol;
//     TCP_HEADER* TCP = NULL;
//     UDP_HEADER* UDP = NULL;
//     ETHERNET_HEADER* Ethernet;
//     uint16_t EthType;
//     uint16_t IpHeaderLen;
//     QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Route->RemoteAddress);

//     CXPLAT_DBG_ASSERT(
//         Family == QUIC_ADDRESS_FAMILY_INET || Family == QUIC_ADDRESS_FAMILY_INET6);

//     if (Socket->UseTcp) {
//         //
//         // Fill TCP header.
//         //
//         TCP = (TCP_HEADER*)(Buffer->Buffer - sizeof(TCP_HEADER));
//         TCP->DestinationPort = Route->RemoteAddress.Ipv4.sin_port;
//         TCP->SourcePort = Route->LocalAddress.Ipv4.sin_port;
//         TCP->Window = 0xFFFF;
//         TCP->X2 = 0;
//         TCP->Checksum = 0;
//         TCP->UrgentPointer = 0;
//         TCP->HeaderLength = sizeof(TCP_HEADER) / sizeof(uint32_t);
//         TCP->SequenceNumber = TcpSeqNum;
//         TCP->AckNumber = TcpAckNum;
//         TCP->Flags = TcpFlags;

//         Transport = (uint8_t*)TCP;
//         TransportLength = sizeof(TCP_HEADER);
//         TransportProtocol = IPPROTO_TCP;
//     } else {
//         //
//         // Fill UDP header.
//         //
//         UDP = (UDP_HEADER*)(Buffer->Buffer - sizeof(UDP_HEADER));
//         UDP->DestinationPort = Route->RemoteAddress.Ipv4.sin_port;
//         UDP->SourcePort = Route->LocalAddress.Ipv4.sin_port;
//         UDP->Length = QuicNetByteSwapShort((uint16_t)Buffer->Length + sizeof(UDP_HEADER));
//         UDP->Checksum = 0;
//         Transport = (uint8_t*)UDP;
//         TransportLength = sizeof(UDP_HEADER);
//         TransportProtocol = IPPROTO_UDP;
//     }

//     //
//     // Fill IPv4/IPv6 header.
//     //
//     if (Family == QUIC_ADDRESS_FAMILY_INET) {
//         IPV4_HEADER* IPv4 = (IPV4_HEADER*)(Transport - sizeof(IPV4_HEADER));
//         IPv4->VersionAndHeaderLength = IPV4_DEFAULT_VERHLEN;
//         IPv4->TypeOfService = 0;
//         IPv4->EcnField = ECN;
//         IPv4->TotalLength = htons(sizeof(IPV4_HEADER) + TransportLength + (uint16_t)Buffer->Length);
//         IPv4->Identification = 0;
//         IPv4->FlagsAndFragmentOffset = 0;
//         IPv4->TimeToLive = IP_DEFAULT_HOP_LIMIT;
//         IPv4->Protocol = TransportProtocol;
//         IPv4->HeaderChecksum = 0;
//         CxPlatCopyMemory(IPv4->Source, &Route->LocalAddress.Ipv4.sin_addr, sizeof(Route->LocalAddress.Ipv4.sin_addr));
//         CxPlatCopyMemory(IPv4->Destination, &Route->RemoteAddress.Ipv4.sin_addr, sizeof(Route->RemoteAddress.Ipv4.sin_addr));
//         IPv4->HeaderChecksum = SkipNetworkLayerXsum ? 0 : ~CxPlatFramingChecksum((uint8_t*)IPv4, sizeof(IPV4_HEADER), 0);
//         EthType = ETHERNET_TYPE_IPV4;
//         Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv4) - sizeof(ETHERNET_HEADER));
//         IpHeaderLen = sizeof(IPV4_HEADER);
//         if (!SkipTransportLayerXsum) {
//             if (Socket->UseTcp) {
//                 TCP->Checksum =
//                     CxPlatFramingTransportChecksum(
//                         IPv4->Source, IPv4->Destination,
//                         sizeof(Route->LocalAddress.Ipv4.sin_addr),
//                         IPPROTO_TCP,
//                         (uint8_t*)TCP, sizeof(TCP_HEADER) + Buffer->Length);
//             } else {
//                 UDP->Checksum =
//                     CxPlatFramingTransportChecksum(
//                         IPv4->Source, IPv4->Destination,
//                         sizeof(Route->LocalAddress.Ipv4.sin_addr),
//                         IPPROTO_UDP,
//                         (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length);
//             }
//         }
//     } else {
//         IPV6_HEADER* IPv6 = (IPV6_HEADER*)(Transport - sizeof(IPV6_HEADER));
//         //
//         // IPv6 Version, Traffic Class, ECN Field and Flow Label fields in host
//         // byte order.
//         //
//         union {
//             struct {
//                 uint32_t Flow : 20;
//                 uint32_t EcnField : 2;
//                 uint32_t Class : 6;
//                 uint32_t Version : 4; // Most significant bits.
//             };
//             uint32_t Value;
//         } VersionClassEcnFlow = {0};

//         VersionClassEcnFlow.Version = IPV6_VERSION;
//         VersionClassEcnFlow.Class = 0;
//         VersionClassEcnFlow.EcnField = ECN;
//         VersionClassEcnFlow.Flow = (uint32_t)(uintptr_t)Socket;

//         IPv6->VersionClassEcnFlow = CxPlatByteSwapUint32(VersionClassEcnFlow.Value);
//         IPv6->PayloadLength = htons(TransportLength + (uint16_t)Buffer->Length);
//         IPv6->HopLimit = IP_DEFAULT_HOP_LIMIT;
//         IPv6->NextHeader = TransportProtocol;
//         CxPlatCopyMemory(IPv6->Source, &Route->LocalAddress.Ipv6.sin6_addr, sizeof(Route->LocalAddress.Ipv6.sin6_addr));
//         CxPlatCopyMemory(IPv6->Destination, &Route->RemoteAddress.Ipv6.sin6_addr, sizeof(Route->RemoteAddress.Ipv6.sin6_addr));
//         EthType = ETHERNET_TYPE_IPV6;
//         Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv6) - sizeof(ETHERNET_HEADER));
//         IpHeaderLen = sizeof(IPV6_HEADER);
//         if (!SkipTransportLayerXsum) {
//             if (Socket->UseTcp) {
//                 TCP->Checksum =
//                     CxPlatFramingTransportChecksum(
//                         IPv6->Source, IPv6->Destination,
//                         sizeof(Route->LocalAddress.Ipv6.sin6_addr),
//                         IPPROTO_TCP,
//                         (uint8_t*)TCP, sizeof(TCP_HEADER) + Buffer->Length);
//             } else {
//                 UDP->Checksum =
//                     CxPlatFramingTransportChecksum(
//                         IPv6->Source, IPv6->Destination,
//                         sizeof(Route->LocalAddress.Ipv6.sin6_addr),
//                         IPPROTO_UDP,
//                         (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length);
//             }
//         }
//     }

//     //
//     // Fill Ethernet header.
//     //
//     Ethernet->Type = EthType;
//     CxPlatCopyMemory(Ethernet->Destination, Route->NextHopLinkLayerAddress, sizeof(Route->NextHopLinkLayerAddress));
//     CxPlatCopyMemory(Ethernet->Source, Route->LocalLinkLayerAddress, sizeof(Route->LocalLinkLayerAddress));

//     Buffer->Length += TransportLength + IpHeaderLen + sizeof(ETHERNET_HEADER);
//     Buffer->Buffer -= TransportLength + IpHeaderLen + sizeof(ETHERNET_HEADER);
// }
