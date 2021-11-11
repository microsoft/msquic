/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket.c.clog.h"
#endif

#include <stdio.h>

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

//
// Socket Pool Logic
//

#define HARDCODED_SOCK_POOL_START_PORT 32768

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        return FALSE;
    }
    CxPlatRwLockInitialize(&Pool->Lock);
    Pool->NextLocalPort = HARDCODED_SOCK_POOL_START_PORT;
    return TRUE;
}

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    CxPlatRwLockUninitialize(&Pool->Lock);
    CxPlatHashtableUninitialize(&Pool->Sockets);
}

CXPLAT_SOCKET*
CxPlatGetSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    CxPlatRwLockAcquireShared(&Pool->Lock);
    Entry = CxPlatHashtableLookup(&Pool->Sockets, LocalAddress->Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (CxPlatSocketCompare(Temp, LocalAddress, RemoteAddress)) {
            if (CxPlatRundownAcquire(&Temp->Rundown)) {
                Socket = Temp;
            }
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    CxPlatRwLockReleaseShared(&Pool->Lock);
    return Socket;
}

BOOLEAN
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    BOOLEAN Success = TRUE;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;

    CxPlatRwLockAcquireExclusive(&Pool->Lock);

    if (Socket->LocalAddress.Ipv4.sin_port == 0) {
        Socket->LocalAddress.Ipv4.sin_port = CxPlatByteSwapUint16(Pool->NextLocalPort);
        Pool->NextLocalPort++;
        if (Pool->NextLocalPort == 0) {
            Pool->NextLocalPort = HARDCODED_SOCK_POOL_START_PORT;
        }
    }

    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (CxPlatSocketCompare(Temp, &Socket->LocalAddress, &Socket->RemoteAddress)) {
            Success = FALSE;
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    if (Success) {
        CxPlatHashtableInsert(&Pool->Sockets, &Socket->Entry, Socket->LocalAddress.Ipv4.sin_port, &Context);
    }
    CxPlatRwLockReleaseExclusive(&Pool->Lock);
    return Success;
}

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);
    CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

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
    uint8_t TypeOfService;
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

#pragma pack(pop)

//
// Constants for headers in wire format.
//
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
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const UDP_HEADER* Udp,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(UDP_HEADER)) {
        return;
    }
    Length -= sizeof(UDP_HEADER);
    Packet->Reserved = L4_TYPE_UDP;

    Packet->Route->RemoteAddress.Ipv4.sin_port = Udp->SourcePort;
    Packet->Route->LocalAddress.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Buffer = (uint8_t*)Udp->Data;
    Packet->BufferLength = Length;

    //const uint32_t Hash = CxPlatHashSimple(sizeof(*Packet->Route), (uint8_t*)Packet->Route);
    const uint32_t Hash = Udp->SourcePort + Udp->DestinationPort;
    Packet->PartitionIndex = Datapath->CpuTable[Hash % Datapath->CpuTableSize];
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpRawParseIPv4(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const IPV4_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV4_HEADER)) {
        return;
    }
    Length -= sizeof(IPV4_HEADER);

    Packet->Route->RemoteAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Route->RemoteAddress.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->Route->LocalAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Route->LocalAddress.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->Protocol == IPPROTO_UDP) {
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
    } else {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            IP->Protocol,
            "unacceptable tranport");
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpRawParseIPv6(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const IPV6_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV6_HEADER)) {
        return;
    }
    Length -= sizeof(IPV6_HEADER);

    Packet->Route->RemoteAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Route->RemoteAddress.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->Route->LocalAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Route->LocalAddress.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->NextHeader == IPPROTO_UDP) {
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, ntohs(IP->PayloadLength));
    } else {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            IP->NextHeader,
            "unacceptable tranport");
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
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(ETHERNET_HEADER)) {
        return;
    }
    Length -= sizeof(ETHERNET_HEADER);

    const ETHERNET_HEADER* Ethernet = (const ETHERNET_HEADER*)Payload;

    if (IsEthernetBroadcast(Ethernet->Destination) || IsEthernetMulticast(Ethernet->Destination)) {
        return;
    }

    uint16_t EthernetType = Ethernet->Type;
    if (EthernetType == ETHERNET_TYPE_IPV4) {
        CxPlatDpRawParseIPv4(Datapath, Packet, (IPV4_HEADER*)Ethernet->Data, Length);
    } else if (EthernetType == ETHERNET_TYPE_IPV6) {
        CxPlatDpRawParseIPv6(Datapath, Packet, (IPV6_HEADER*)Ethernet->Data, Length);
    } else {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            EthernetType,
            "unacceptable Ethernet type");
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
HEADER_BACKFILL
CxPlatDpRawCalculateHeaderBackFill(
    _In_ QUIC_ADDRESS_FAMILY Family
    )
{
    HEADER_BACKFILL HeaderBackFill;
    HeaderBackFill.TransportLayer = sizeof(UDP_HEADER);
    HeaderBackFill.NetworkLayer =
        Family == QUIC_ADDRESS_FAMILY_INET ? sizeof(IPV4_HEADER) : sizeof(IPV6_HEADER);
    HeaderBackFill.LinkLayer = sizeof(ETHERNET_HEADER);
    HeaderBackFill.AllLayer =
        HeaderBackFill.TransportLayer + HeaderBackFill.NetworkLayer + HeaderBackFill.LinkLayer;
    return HeaderBackFill;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
CxPlatFramingChecksum(
    _In_reads_(Length) uint8_t* Data,
    _In_ uint32_t Length,
    _In_ uint64_t InitialChecksum
    )
{
    //
    // Checksum is calculated in reverse order.
    // 1. Add the odd byte to the checksum if the length is odd.
    // 2. If the length is divisible by 2 but not 4, add the last 2 bytes.
    // 3. Sum up the rest as 32-bit words.
    //

    if ((Length & 1) != 0) {
        --Length;
        InitialChecksum += Data[Length];
    }

    if ((Length & 2) != 0) {
        Length -= 2;
        InitialChecksum += *((uint16_t*)(&Data[Length]));
    }

    while (Length != 0) {
        Length -= 4;
        InitialChecksum += *((uint32_t*)(&Data[Length]));
    }

    //
    // Fold all carries into the final checksum.
    //
    while (InitialChecksum >> 16) {
        InitialChecksum = (InitialChecksum & 0xffff) + (InitialChecksum >> 16);
    }

    return (uint16_t)InitialChecksum;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
CxPlatFramingUdpChecksum(
    _In_reads_(AddrLength) uint8_t* SrcAddr,
    _In_reads_(AddrLength) uint8_t* DstAddr,
    _In_ uint32_t AddrLength,
    _In_ uint16_t NextHeader,
    _In_reads_(IPPayloadLength) uint8_t* UDP,
    _In_ uint32_t IPPayloadLength
    )
{
    uint64_t Checksum =
        CxPlatFramingChecksum(SrcAddr, AddrLength, 0) +
        CxPlatFramingChecksum(DstAddr, AddrLength, 0);
    Checksum += CxPlatByteSwapUint16(NextHeader);
    Checksum += CxPlatByteSwapUint16((uint16_t)IPPayloadLength);

    //
    // Pseudoheader is always in 32-bit words. So, cross 16-bit boundary adjustment isn't needed.
    //
    return ~CxPlatFramingChecksum(UDP, IPPayloadLength, Checksum);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatFramingWriteHeaders(
    _In_ const CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _Inout_ QUIC_BUFFER* Buffer,
    _In_ BOOLEAN SkipNetworkLayerXsum,
    _In_ BOOLEAN SkipTransportLayerXsum
    )
{
    UDP_HEADER* UDP = (UDP_HEADER*)(Buffer->Buffer - sizeof(UDP_HEADER));
    ETHERNET_HEADER* Ethernet;
    uint16_t EthType;
    uint16_t IpHeaderLen;
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Route->RemoteAddress);

    CXPLAT_DBG_ASSERT(
        Family == QUIC_ADDRESS_FAMILY_INET || Family == QUIC_ADDRESS_FAMILY_INET6);

    //
    // Fill UDP header.
    //
    UDP->DestinationPort = Route->RemoteAddress.Ipv4.sin_port;
    UDP->SourcePort = Route->LocalAddress.Ipv4.sin_port;
    UDP->Length = QuicNetByteSwapShort((uint16_t)Buffer->Length + sizeof(UDP_HEADER));
    UDP->Checksum = 0;

    //
    // Fill IPv4/IPv6 header.
    //
    if (Family == QUIC_ADDRESS_FAMILY_INET) {
        IPV4_HEADER* IPv4 = (IPV4_HEADER*)(((uint8_t*)UDP) - sizeof(IPV4_HEADER));
        IPv4->VersionAndHeaderLength = IPV4_DEFAULT_VERHLEN;
        IPv4->TypeOfService = 0;
        IPv4->TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + (uint16_t)Buffer->Length);
        IPv4->Identification = 0;
        IPv4->FlagsAndFragmentOffset = 0;
        IPv4->TimeToLive = IP_DEFAULT_HOP_LIMIT;
        IPv4->Protocol = IPPROTO_UDP;
        IPv4->HeaderChecksum = 0;
        CxPlatCopyMemory(IPv4->Source, &Route->LocalAddress.Ipv4.sin_addr, sizeof(Route->LocalAddress.Ipv4.sin_addr));
        CxPlatCopyMemory(IPv4->Destination, &Route->RemoteAddress.Ipv4.sin_addr, sizeof(Route->RemoteAddress.Ipv4.sin_addr));
        IPv4->HeaderChecksum = SkipNetworkLayerXsum ? 0 : ~CxPlatFramingChecksum((uint8_t*)IPv4, sizeof(IPV4_HEADER), 0);
        EthType = ETHERNET_TYPE_IPV4;
        Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv4) - sizeof(ETHERNET_HEADER));
        IpHeaderLen = sizeof(IPV4_HEADER);
        UDP->Checksum =
            SkipTransportLayerXsum ?
                0 :
                CxPlatFramingUdpChecksum(
                    IPv4->Source, IPv4->Destination,
                    sizeof(Route->LocalAddress.Ipv4.sin_addr), IPPROTO_UDP, (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length);
    } else {
        IPV6_HEADER* IPv6 = (IPV6_HEADER*)(((uint8_t*)UDP) - sizeof(IPV6_HEADER));
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
        } VersionClassEcnFlow = {0};

        VersionClassEcnFlow.Version = IPV6_VERSION;
        VersionClassEcnFlow.Class = 0;
        VersionClassEcnFlow.EcnField = 0; // Not ECN capable currently.
        VersionClassEcnFlow.Flow = (uint32_t)(uintptr_t)Socket;

        IPv6->VersionClassEcnFlow = CxPlatByteSwapUint32(VersionClassEcnFlow.Value);
        IPv6->PayloadLength = htons(sizeof(UDP_HEADER) + (uint16_t)Buffer->Length);
        IPv6->HopLimit = IP_DEFAULT_HOP_LIMIT;
        IPv6->NextHeader = IPPROTO_UDP;
        CxPlatCopyMemory(IPv6->Source, &Route->LocalAddress.Ipv6.sin6_addr, sizeof(Route->LocalAddress.Ipv6.sin6_addr));
        CxPlatCopyMemory(IPv6->Destination, &Route->RemoteAddress.Ipv6.sin6_addr, sizeof(Route->RemoteAddress.Ipv6.sin6_addr));
        EthType = ETHERNET_TYPE_IPV6;
        Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv6) - sizeof(ETHERNET_HEADER));
        IpHeaderLen = sizeof(IPV6_HEADER);
        UDP->Checksum =
            SkipTransportLayerXsum ?
                0 :
                CxPlatFramingUdpChecksum(
                    IPv6->Source, IPv6->Destination,
                    sizeof(Route->LocalAddress.Ipv6.sin6_addr), IPPROTO_UDP, (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length);
    }

    //
    // Fill Ethernet header.
    //
    Ethernet->Type = EthType;

    if (Socket->Connected) {
        CxPlatCopyMemory(Ethernet->Destination, Socket->Datapath->ServerMac, sizeof(Socket->Datapath->ServerMac));
        CxPlatCopyMemory(Ethernet->Source, Socket->Datapath->ClientMac, sizeof(Socket->Datapath->ClientMac));
    } else {
        CxPlatCopyMemory(Ethernet->Destination, Socket->Datapath->ClientMac, sizeof(Socket->Datapath->ClientMac));
        CxPlatCopyMemory(Ethernet->Source, Socket->Datapath->ServerMac, sizeof(Socket->Datapath->ServerMac));
    }

    Buffer->Length += sizeof(UDP_HEADER) + IpHeaderLen + sizeof(ETHERNET_HEADER);
    Buffer->Buffer -= sizeof(UDP_HEADER) + IpHeaderLen + sizeof(ETHERNET_HEADER);
}
