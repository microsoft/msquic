/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC DPDK Datapath Implementation (User Mode)

--*/

#include "datapath_dpdk.h"
#ifdef QUIC_CLOG
#include "datapath_dpdk.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

typedef struct CXPLAT_SEND_DATA {

    uint32_t Reserved;

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_SOCKET {

    BOOLEAN Connected;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;

} CXPLAT_SOCKET;

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)
        (((PUCHAR)Context) -
            sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)
        (((PUCHAR)Datagram) +
            sizeof(CXPLAT_RECV_DATA));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    *NewDataPath = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_DATAPATH), QUIC_POOL_DATAPATH);
    if (*NewDataPath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(CXPLAT_DATAPATH));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CxPlatZeroMemory(*NewDataPath, sizeof(CXPLAT_DATAPATH));

    (*NewDataPath)->ClientRecvContextLength = ClientRecvContextLength;
    if (UdpCallbacks) {
        (*NewDataPath)->UdpHandlers = *UdpCallbacks;
    }
    if (TcpCallbacks) {
        (*NewDataPath)->TcpHandlers = *TcpCallbacks;
    }

    Status = CxPlatDpdkInitialize(*NewDataPath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatSleep(5000); // TODO - Remove

Error:

    if (QUIC_FAILED(Status)) {
        if (*NewDataPath != NULL) {
            CXPLAT_FREE(*NewDataPath, QUIC_POOL_DATAPATH);
            *NewDataPath = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }
    CxPlatDpdkUninitialize(Datapath);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));
}

void PrintPacket(_In_ const PACKET_DESCRIPTOR* Packet) {
    if (Packet->L2Type == L2_TYPE_ETHERNET) {
        if (Packet->L3Type == L3_TYPE_IPV4 || Packet->L3Type == L3_TYPE_IPV6) {
            QUIC_ADDR_STR Source; QuicAddrToString(&Packet->IP.Source, &Source);
            QUIC_ADDR_STR Destination; QuicAddrToString(&Packet->IP.Destination, &Destination);
            if (Packet->L4Type == L4_TYPE_UDP) {
                printf("[%02hu] RX [%hu] [%s:%hu->%s:%hu]\n",
                    Packet->Core, Packet->PayloadLength,
                    Source.Address, CxPlatByteSwapUint16(Packet->IP.Source.Ipv4.sin_port),
                    Destination.Address, CxPlatByteSwapUint16(Packet->IP.Destination.Ipv4.sin_port));
            }
        } else if (Packet->L3Type == L3_TYPE_QUIC) {
            printf("[%02hu] RX [%hu] QUIC\n",
                Packet->Core, Packet->PayloadLength);

        } else if (Packet->L3Type == L3_TYPE_LLDP) {
            printf("[%02hu] RX [%hu] LLDP\n",
                Packet->Core, Packet->PayloadLength);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkRx(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_reads_(Count)
        const PACKET_DESCRIPTOR* Packets,
    _In_range_(1, MAX_BURST_SIZE)
        uint16_t Count
    )
{
    for (uint16_t i = 0; i < Count; i++) {
        const PACKET_DESCRIPTOR* Packet = &Packets[i];
        PrintPacket(Packet);
        // TODO - Process packet
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketSetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketGetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ PUINT32 BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

//
// Ethernet / IP Framing Logic
//

#pragma pack(push)
#pragma pack(1)

typedef struct ETHERNET_HEADER {
    uint8_t Destination[6];
    uint8_t Source[6];
    union {
        uint16_t Type;
        uint16_t Length;
    };
    uint8_t Data[0];
} ETHERNET_HEADER;

typedef struct LLDP_HEADER {
    uint8_t ChassisIDSubtype;
    uint8_t ChassisIDLength;
    uint8_t ChassisID[0];
} LLDP_HEADER;

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
CxPlatDpdkParseUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const UDP_HEADER* Udp,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(UDP_HEADER)) {
        return;
    }
    Length -= sizeof(UDP_HEADER);
    Packet->L4Type = L4_TYPE_UDP;

    Packet->IP.Source.Ipv4.sin_port = Udp->SourcePort;
    Packet->IP.Destination.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Payload = Udp->Data;
    Packet->PayloadLength = Length;
    Packet->IsValid = TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpdkParseIPv4(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const IPV4_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV4_HEADER)) {
        return;
    }
    Length -= sizeof(IPV4_HEADER);
    Packet->L3Type = L3_TYPE_IPV4;

    Packet->IP.Source.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->IP.Source.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->IP.Destination.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->IP.Destination.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->Protocol == 17) {
        CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpdkParseIPv6(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const IPV6_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV6_HEADER)) {
        return;
    }
    Length -= sizeof(IPV6_HEADER);
    Packet->L3Type = L3_TYPE_IPV6;

    Packet->IP.Source.Ipv6.sin6_family = AF_INET;
    CxPlatCopyMemory(&Packet->IP.Source.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->IP.Destination.Ipv6.sin6_family = AF_INET;
    CxPlatCopyMemory(&Packet->IP.Destination.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->NextHeader == 17) {
        CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
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
                CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)Extension->Data, Length);
            } else if (Extension->NextHeader == 59) {
                return;
            }
        } while (TRUE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpdkParseLldp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const LLDP_HEADER* Lldp,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV4_HEADER)) {
        return;
    }
    Length -= sizeof(IPV4_HEADER);
    Packet->L3Type = L3_TYPE_LLDP;
    Packet->Payload = (uint8_t*)Lldp;
    Packet->PayloadLength = Length;
    Packet->IsValid = TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(ETHERNET_HEADER)) {
        return;
    }
    Length -= sizeof(ETHERNET_HEADER);
    Packet->L2Type = L2_TYPE_ETHERNET;

    const ETHERNET_HEADER* Ethernet = (const ETHERNET_HEADER*)Payload;

    if (Ethernet->Type == 0x0008) { // IPv4
        CxPlatDpdkParseIPv4(Datapath, Packet, (IPV4_HEADER*)Ethernet->Data, Length);
    } else if (Ethernet->Type == 0xDD86) { // IPv6
        CxPlatDpdkParseIPv6(Datapath, Packet, (IPV6_HEADER*)Ethernet->Data, Length);
    } else if (Ethernet->Type == 0xDCBA) { // QUIC (hack)
        Packet->L3Type = L3_TYPE_QUIC;
        Packet->Payload = Ethernet->Data;
        Packet->PayloadLength = Length;
        Packet->IsValid = TRUE;
    } else if (Ethernet->Type == 0xCC88) { // LLDPP
        Packet->L3Type = L3_TYPE_LLDP;
        CxPlatDpdkParseLldp(Datapath, Packet, (LLDP_HEADER*)Ethernet->Data, Length);
    }
}

static
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDpdkWritePacket(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const PACKET_DESCRIPTOR* Packet,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    )
{
    if (*Offset + sizeof(ETHERNET_HEADER) > BufferLength) {
        return FALSE;
    }

    ETHERNET_HEADER* Ethernet = (ETHERNET_HEADER*)(Buffer + *Offset);
    *Offset += sizeof(ETHERNET_HEADER);

    CxPlatZeroMemory(Ethernet->Destination, sizeof(Ethernet->Destination));
    CxPlatZeroMemory(Ethernet->Source, sizeof(Ethernet->Source));

    if (Packet->L3Type == L3_TYPE_IPV4) {
        Ethernet->Type = 0x0008;
        return FALSE; // TODO - Complete
    } else if (Packet->L3Type == L3_TYPE_IPV6) {
        Ethernet->Type = 0xDD86;
        return FALSE; // TODO - Complete
    } else if (Packet->L3Type == L3_TYPE_LLDP) {
        Ethernet->Type = 0xCC88;
        return FALSE; // TODO - Complete
    } else if (Packet->L3Type == L3_TYPE_QUIC) {
        Ethernet->Type = 0xDCBA;
        if (*Offset + Packet->PayloadLength > BufferLength) {
            return FALSE;
        }
        CxPlatCopyMemory(Ethernet->Data, Packet->Payload, Packet->PayloadLength);
        return TRUE;
    } else {
        return FALSE;
    }
}
