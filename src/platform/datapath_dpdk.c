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

const uint8_t ListenerMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x80 };
const uint8_t ConnectedMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x59 };

const uint32_t ListenerIP = 0x01FFFFFF;
const uint32_t ConnectedIP = 0x02FFFFFF;

typedef struct CXPLAT_SOCKET {

    CXPLAT_HASHTABLE_ENTRY Entry;
    CXPLAT_RUNDOWN_REF Rundown;
    CXPLAT_DATAPATH* Datapath;
    void* CallbackContext;
    uint16_t LocalPort;
    uint16_t RemotePort;

} CXPLAT_SOCKET;

static
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkPrependPacketHeaders(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    );

BOOLEAN
CxPlatCheckSocket(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t SourcePort // Socket's local port
    )
{
    BOOLEAN Found = FALSE;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CxPlatRwLockAcquireShared(&Datapath->SocketsLock);
    Found = CxPlatHashtableLookup(&Datapath->Sockets, SourcePort, &Context) != NULL;
    CxPlatRwLockReleaseShared(&Datapath->SocketsLock);
    return Found;
}

CXPLAT_SOCKET*
CxPlatGetSocket(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t SourcePort // Socket's local port
    )
{
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    CxPlatRwLockAcquireShared(&Datapath->SocketsLock);
    if ((Entry = CxPlatHashtableLookup(&Datapath->Sockets, SourcePort, &Context)) != NULL) {
        Socket = CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (!CxPlatRundownAcquire(&Socket->Rundown)) {
            Socket = NULL;
        }
    }
    CxPlatRwLockReleaseShared(&Datapath->SocketsLock);
    return Socket;
}

BOOLEAN
CxPlatTryAddSocket(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    BOOLEAN Success = FALSE;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CxPlatRwLockAcquireExclusive(&Datapath->SocketsLock);
    if (!CxPlatHashtableLookup(&Datapath->Sockets, Socket->LocalPort, &Context)) {
        CxPlatHashtableInsert(&Datapath->Sockets, &Socket->Entry, Socket->LocalPort, NULL);
        Success = TRUE;
    }
    CxPlatRwLockReleaseExclusive(&Datapath->SocketsLock);
    return Success;
}

void
CxPlatTryRemoveSocket(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Datapath->SocketsLock);
    CxPlatHashtableRemove(&Datapath->Sockets, &Socket->Entry, NULL);
    CxPlatRwLockReleaseExclusive(&Datapath->SocketsLock);
}

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(DPDK_RX_PACKET));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(DPDK_RX_PACKET));
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
    BOOLEAN CleanUpHashTable = FALSE;
    const uint32_t AdditionalBufferSize =
        sizeof(DPDK_RX_PACKET) + ClientRecvContextLength;

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

    (*NewDataPath)->CoreCount = (uint16_t)CxPlatProcMaxCount();
    if (UdpCallbacks) {
        (*NewDataPath)->UdpHandlers = *UdpCallbacks;
    }
    if (TcpCallbacks) {
        (*NewDataPath)->TcpHandlers = *TcpCallbacks;
    }
    CxPlatPoolInitialize(FALSE, AdditionalBufferSize, QUIC_POOL_DATAPATH, &(*NewDataPath)->AdditionalInfoPool);

    CxPlatLockInitialize(&(*NewDataPath)->TxLock);
    CxPlatRwLockInitialize(&(*NewDataPath)->SocketsLock);
    if (!CxPlatHashtableInitializeEx(&(*NewDataPath)->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CleanUpHashTable = TRUE;

    Status = CxPlatDpdkInitialize(*NewDataPath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (*NewDataPath != NULL) {
            if (CleanUpHashTable) {
                CxPlatHashtableUninitialize(&(*NewDataPath)->Sockets);
            }
            CxPlatRwLockUninitialize(&(*NewDataPath)->SocketsLock);
            CxPlatLockUninitialize(&(*NewDataPath)->TxLock);
            CxPlatPoolUninitialize(&(*NewDataPath)->AdditionalInfoPool);
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
    CxPlatHashtableUninitialize(&Datapath->Sockets);
    CxPlatRwLockUninitialize(&Datapath->SocketsLock);
    CxPlatLockUninitialize(&Datapath->TxLock);
    CxPlatPoolUninitialize(&Datapath->AdditionalInfoPool);
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
    Address->Ipv4.sin_family = AF_INET;
    Address->Ipv4.sin_port = 0;
    Address->Ipv4.sin_addr.S_un.S_addr = ListenerIP;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    *NewSocket = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_SOCKET), QUIC_POOL_SOCKET);
    if (*NewSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            sizeof(CXPLAT_SOCKET));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatRundownInitialize(&(*NewSocket)->Rundown);
    (*NewSocket)->Datapath = Datapath;
    (*NewSocket)->CallbackContext = Config->CallbackContext;
    if (Config->LocalAddress) {
        (*NewSocket)->LocalPort = Config->LocalAddress->Ipv4.sin_port;
    } else {
        (*NewSocket)->LocalPort = CxPlatByteSwapUint16(InterlockedIncrement16((short*)&Datapath->NextLocalPort));
    }
    if (Config->RemoteAddress) {
        (*NewSocket)->RemotePort = Config->RemoteAddress->Ipv4.sin_port;
    } else {
        (*NewSocket)->RemotePort = 0;
    }

    if (!CxPlatTryAddSocket(Datapath, *NewSocket)) {
        Status = QUIC_STATUS_ADDRESS_IN_USE;
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (*NewSocket != NULL) {
            CxPlatRundownUninitialize(&(*NewSocket)->Rundown);
            CXPLAT_FREE(*NewSocket, QUIC_POOL_SOCKET);
            *NewSocket = NULL;
        }
    }

    return Status;
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
    CxPlatTryRemoveSocket(Socket->Datapath, Socket);
    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return 1500;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    Address->Ipv4.sin_family = AF_INET;
    Address->Ipv4.sin_port = Socket->LocalPort;
    if (Socket->RemotePort != 0) {
        Address->Ipv4.sin_addr.S_un.S_addr = ConnectedIP;
    } else {
        Address->Ipv4.sin_addr.S_un.S_addr = ListenerIP;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    if (Socket->RemotePort != 0) {
        Address->Ipv4.sin_family = AF_INET;
        Address->Ipv4.sin_port = Socket->RemotePort;
        Address->Ipv4.sin_addr.S_un.S_addr = ListenerIP;
    } else {
        CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));
    }
}

BOOLEAN FilterPacket(_In_ const DPDK_RX_PACKET* Packet) {
    if (Packet->IP.RemoteAddress.Ipv4.sin_addr.S_un.S_addr == ConnectedIP ||
        Packet->IP.RemoteAddress.Ipv4.sin_addr.S_un.S_addr == ListenerIP ||
        Packet->IP.LocalAddress.Ipv4.sin_addr.S_un.S_addr == ConnectedIP ||
        Packet->IP.LocalAddress.Ipv4.sin_addr.S_un.S_addr == ListenerIP) {
        return FALSE;
    }
    return TRUE;
}

void PrintPacket(_In_ const DPDK_RX_PACKET* Packet) {
    if (Packet->Reserved == L4_TYPE_UDP) {
        QUIC_ADDR_STR Source; QuicAddrToString(&Packet->IP.RemoteAddress, &Source);
        QUIC_ADDR_STR Destination; QuicAddrToString(&Packet->IP.LocalAddress, &Destination);
        printf("[%02hu] RX [%hu] [%s:%hu->%s:%hu]\n",
            Packet->PartitionIndex, Packet->BufferLength,
            Source.Address, CxPlatByteSwapUint16(Packet->IP.RemoteAddress.Ipv4.sin_port),
            Destination.Address, CxPlatByteSwapUint16(Packet->IP.LocalAddress.Ipv4.sin_port));
    } else if (Packet->Reserved == L3_TYPE_LLDP) {
        printf("[%02hu] RX [%hu] LLDP\n",
            Packet->PartitionIndex, Packet->BufferLength);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkRx(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const DPDK_RX_PACKET* PacketChain
    )
{
    DPDK_RX_PACKET* ReturnPacketChain = NULL;
    DPDK_RX_PACKET** ReturnPacketChainTail = &ReturnPacketChain;

    while (PacketChain) {
        DPDK_RX_PACKET* Packet = (DPDK_RX_PACKET*)PacketChain;
        PacketChain = (DPDK_RX_PACKET*)PacketChain->Next;
        Packet->Next = NULL;

        if (FilterPacket(Packet)) {
            continue;
        }

        //PrintPacket(Packet);

        BOOLEAN Return = TRUE;
        if (Packet->Reserved == L4_TYPE_UDP) {
            CXPLAT_SOCKET* Socket = CxPlatGetSocket(Datapath, Packet->IP.LocalAddress.Ipv4.sin_port);
            if (Socket) {
                QuicTraceEvent(
                    DatapathRecv,
                    "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
                    Socket,
                    Packet->BufferLength,
                    Packet->BufferLength,
                    CASTED_CLOG_BYTEARRAY(sizeof(Packet->IP.LocalAddress), &Packet->IP.LocalAddress),
                    CASTED_CLOG_BYTEARRAY(sizeof(Packet->IP.RemoteAddress), &Packet->IP.RemoteAddress));
                Packet->PartitionIndex = CxPlatHashSimple(sizeof(Packet->IP), (uint8_t*)&Packet->IP) % Datapath->CoreCount;
                Datapath->UdpHandlers.Receive(Socket, Socket->CallbackContext, (CXPLAT_RECV_DATA*)Packet);
                CxPlatRundownRelease(&Socket->Rundown);
                Return = FALSE;
            }
        }

        if (Return) {
            *ReturnPacketChainTail = Packet;
            ReturnPacketChainTail = (DPDK_RX_PACKET**)&Packet->Next;
        }
    }

    CxPlatDpdkReturn(ReturnPacketChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatDpdkReturn((const DPDK_RX_PACKET*)RecvDataChain);
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
    return CxPlatDpdkAllocTx(Socket->Datapath, MaxPacketSize);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    SendData->Buffer.Length = MaxBufferLength;
    return &SendData->Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatDpdkFreeTx(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    // No-op
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
    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
    /*QUIC_ADDR_STR Source; QuicAddrToString(LocalAddress, &Source);
    QUIC_ADDR_STR Destination; QuicAddrToString(RemoteAddress, &Destination);
    printf("[%02hu] TX [%hu] [%s:%hu->%s:%hu]\n",
        (uint16_t)CxPlatProcCurrentNumber(), (uint16_t)SendData->Buffer.Length,
        Source.Address, CxPlatByteSwapUint16(LocalAddress->Ipv4.sin_port),
        Destination.Address, CxPlatByteSwapUint16(RemoteAddress->Ipv4.sin_port));*/
    CxPlatDpdkPrependPacketHeaders(Socket, LocalAddress, RemoteAddress, SendData);
    CxPlatDpdkTx(SendData);
    return QUIC_STATUS_SUCCESS;
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
    _Inout_ DPDK_RX_PACKET* Packet,
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

    Packet->IP.RemoteAddress.Ipv4.sin_port = Udp->SourcePort;
    Packet->IP.LocalAddress.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Buffer = (uint8_t*)Udp->Data;
    Packet->BufferLength = Length;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpdkParseIPv4(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ DPDK_RX_PACKET* Packet,
    _In_reads_bytes_(Length)
        const IPV4_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV4_HEADER)) {
        return;
    }
    Length -= sizeof(IPV4_HEADER);

    Packet->IP.RemoteAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->IP.RemoteAddress.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->IP.LocalAddress.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->IP.LocalAddress.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->Protocol == 17) {
        CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatDpdkParseIPv6(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ DPDK_RX_PACKET* Packet,
    _In_reads_bytes_(Length)
        const IPV6_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV6_HEADER)) {
        return;
    }
    Length -= sizeof(IPV6_HEADER);

    Packet->IP.RemoteAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->IP.RemoteAddress.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->IP.LocalAddress.Ipv6.sin6_family = AF_INET6;
    CxPlatCopyMemory(&Packet->IP.LocalAddress.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

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
    _Inout_ DPDK_RX_PACKET* Packet,
    _In_reads_bytes_(Length)
        const LLDP_HEADER* Lldp,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(LLDP_HEADER)) {
        return;
    }
    Length -= sizeof(LLDP_HEADER);
    Packet->Reserved = L3_TYPE_LLDP;
    Packet->Buffer = (uint8_t*)Lldp;
    Packet->BufferLength = Length;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ DPDK_RX_PACKET* Packet,
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

    if (Ethernet->Type == 0x0008) { // IPv4
        CxPlatDpdkParseIPv4(Datapath, Packet, (IPV4_HEADER*)Ethernet->Data, Length);
    } else if (Ethernet->Type == 0xDD86) { // IPv6
        CxPlatDpdkParseIPv6(Datapath, Packet, (IPV6_HEADER*)Ethernet->Data, Length);
    } else if (Ethernet->Type == 0xCC88) { // LLDPP
        CxPlatDpdkParseLldp(Datapath, Packet, (LLDP_HEADER*)Ethernet->Data, Length);
    }
}

static
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkPrependPacketHeaders(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UDP_HEADER* UDP = (UDP_HEADER*)(SendData->Buffer.Buffer - sizeof(UDP_HEADER));
    IPV4_HEADER* IP = (IPV4_HEADER*)(((uint8_t*)UDP) - sizeof(IPV4_HEADER));
    ETHERNET_HEADER* Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IP) - sizeof(ETHERNET_HEADER));

    Ethernet->Type = 0x0008; // IPv4

    if (Socket->RemotePort != 0) {
        CxPlatCopyMemory(Ethernet->Destination, ListenerMac, sizeof(ListenerMac));
        CxPlatCopyMemory(Ethernet->Source, ConnectedMac, sizeof(ConnectedMac));

        CxPlatCopyMemory(IP->Destination, &ListenerIP, sizeof(ListenerIP));
        CxPlatCopyMemory(IP->Source, &ConnectedIP, sizeof(ConnectedIP));

    } else {
        CxPlatCopyMemory(Ethernet->Destination, ConnectedMac, sizeof(ConnectedMac));
        CxPlatCopyMemory(Ethernet->Source, ListenerMac, sizeof(ListenerMac));

        CxPlatCopyMemory(IP->Destination, &ConnectedIP, sizeof(ConnectedIP));
        CxPlatCopyMemory(IP->Source, &ListenerIP, sizeof(ListenerIP));
    }

    IP->VersionAndHeaderLength = 0x45;
    IP->TypeOfService = 0;
    IP->TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + (uint16_t)SendData->Buffer.Length);
    IP->Identification = 0;
    IP->FlagsAndFragmentOffset = 0;
    IP->TimeToLive = 64;
    IP->Protocol = 17; // UDP
    IP->HeaderChecksum = 0;

    UDP->DestinationPort = RemoteAddress->Ipv4.sin_port;
    UDP->SourcePort = LocalAddress->Ipv4.sin_port;
    UDP->Length = htons((uint16_t)SendData->Buffer.Length);

    SendData->Buffer.Length += sizeof(UDP_HEADER) + sizeof(IPV4_HEADER) + sizeof(ETHERNET_HEADER);
    SendData->Buffer.Buffer -= sizeof(UDP_HEADER) + sizeof(IPV4_HEADER) + sizeof(ETHERNET_HEADER);
}
