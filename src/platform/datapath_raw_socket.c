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

uint16_t // Host byte order
CxPlatSockPoolGetNextLocalPort(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    uint16_t Port;
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    Port = Pool->NextLocalPort++;
    if (Pool->NextLocalPort == 0) {
        Pool->NextLocalPort = HARDCODED_SOCK_POOL_START_PORT;
    }
    CxPlatRwLockReleaseExclusive(&Pool->Lock);
    return Port;
}

CXPLAT_SOCKET*
CxPlatGetSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress
    )
{
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    CxPlatRwLockAcquireShared(&Pool->Lock);
    Entry = CxPlatHashtableLookup(&Pool->Sockets, LocalAddress->Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (QuicAddrCompareIp(&Temp->LocalAddress, LocalAddress)) {
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
    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (QuicAddrCompareIp(&Temp->LocalAddress, &Socket->LocalAddress)) {
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
CxPlatTryRemoveSocket(
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
    uint32_t VersionAndTrafficClass;
    uint16_t FlowLabel;
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

    Packet->Tuple->RemoteAddress.Ipv4.sin_port = Udp->SourcePort;
    Packet->Tuple->LocalAddress.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Buffer = (uint8_t*)Udp->Data;
    Packet->BufferLength = Length;

    //const uint32_t Hash = CxPlatHashSimple(sizeof(*Packet->Tuple), (uint8_t*)Packet->Tuple);
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

    Packet->Tuple->RemoteAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Tuple->RemoteAddress.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->Tuple->LocalAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Tuple->LocalAddress.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->Protocol == 17) {
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
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

    Packet->Tuple->RemoteAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Tuple->RemoteAddress.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->Tuple->LocalAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->Tuple->LocalAddress.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->NextHeader == 17) {
        CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
    } else if (IP->NextHeader != 59) {
        const uint8_t* Data = IP->Data;
        do {
            if (Length < sizeof(IPV6_EXTENSION)) {
                return;
            }
            const IPV6_EXTENSION* Extension = (const IPV6_EXTENSION*)Data;
            const uint16_t ExtLength = sizeof(IPV6_EXTENSION) + Extension->Length * sizeof(IPV6_EXTENSION);
            if (Length < ExtLength) {
                return;
            }
            Length -= ExtLength;
            Data += ExtLength;
            if (Extension->NextHeader == 17) {
                CxPlatDpRawParseUdp(Datapath, Packet, (UDP_HEADER*)Extension->Data, Length);
            } else if (Extension->NextHeader == 59) {
                return;
            }
        } while (TRUE);
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

    if (Ethernet->Type == 0x0008) { // IPv4
        CxPlatDpRawParseIPv4(Datapath, Packet, (IPV4_HEADER*)Ethernet->Data, Length);
    } else if (Ethernet->Type == 0xDD86) { // IPv6
        CxPlatDpRawParseIPv6(Datapath, Packet, (IPV6_HEADER*)Ethernet->Data, Length);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatFramingWriteHeaders(
    _In_ const CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _Inout_ QUIC_BUFFER* Buffer
    )
{
    UDP_HEADER* UDP = (UDP_HEADER*)(Buffer->Buffer - sizeof(UDP_HEADER));
    IPV4_HEADER* IP = (IPV4_HEADER*)(((uint8_t*)UDP) - sizeof(IPV4_HEADER));
    ETHERNET_HEADER* Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IP) - sizeof(ETHERNET_HEADER));

    Ethernet->Type = 0x0008; // IPv4

    if (Socket->Connected) {
        CxPlatCopyMemory(Ethernet->Destination, Socket->Datapath->ServerMac, sizeof(Socket->Datapath->ServerMac));
        CxPlatCopyMemory(Ethernet->Source, Socket->Datapath->ClientMac, sizeof(Socket->Datapath->ClientMac));
    } else {
        CxPlatCopyMemory(Ethernet->Destination, Socket->Datapath->ClientMac, sizeof(Socket->Datapath->ClientMac));
        CxPlatCopyMemory(Ethernet->Source, Socket->Datapath->ServerMac, sizeof(Socket->Datapath->ServerMac));
    }

    CxPlatCopyMemory(IP->Destination, &RemoteAddress->Ipv4.sin_addr, sizeof(RemoteAddress->Ipv4.sin_addr));
    CxPlatCopyMemory(IP->Source, &LocalAddress->Ipv4.sin_addr, sizeof(LocalAddress->Ipv4.sin_addr));

    IP->VersionAndHeaderLength = 0x45;
    IP->TypeOfService = 0;
    IP->TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + (uint16_t)Buffer->Length);
    IP->Identification = 0;
    IP->FlagsAndFragmentOffset = 0;
    IP->TimeToLive = 64;
    IP->Protocol = 17; // UDP
    IP->HeaderChecksum = 0;

    UDP->DestinationPort = RemoteAddress->Ipv4.sin_port;
    UDP->SourcePort = LocalAddress->Ipv4.sin_port;
    UDP->Length = htons((uint16_t)Buffer->Length);

    Buffer->Length += sizeof(UDP_HEADER) + sizeof(IPV4_HEADER) + sizeof(ETHERNET_HEADER);
    Buffer->Buffer -= sizeof(UDP_HEADER) + sizeof(IPV4_HEADER) + sizeof(ETHERNET_HEADER);
}
