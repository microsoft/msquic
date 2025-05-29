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

#if defined(CX_PLATFORM_LINUX) || defined(CX_PLATFORM_DARWIN)
#define CxPlatSocketError() errno
#define CxPlatCloseSocket(s) close(s)
#define CxPlatQuicErrorFromSocketError(e) (QUIC_STATUS)e
#define CxPlatAddressLengthType uint32_t
#elif defined(_WIN32) || defined(_KERNEL_MODE)
#define CxPlatSocketError() WSAGetLastError()
#define CxPlatCloseSocket(s) closesocket(s)
#define CxPlatQuicErrorFromSocketError(e) HRESULT_FROM_WIN32(e)
#define CxPlatAddressLengthType int
#else
#error unsupported platform
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter


uint32_t
CxPlatGetRawSocketSize(void) {
    return sizeof(CXPLAT_SOCKET_RAW);
}

CXPLAT_SOCKET*
CxPlatRawToSocket(_In_ CXPLAT_SOCKET_RAW* Socket) {
    return (CXPLAT_SOCKET*)((unsigned char*)Socket + sizeof(CXPLAT_SOCKET_RAW) - sizeof(CXPLAT_SOCKET));
}

CXPLAT_SOCKET_RAW*
CxPlatSocketToRaw(_In_ CXPLAT_SOCKET* Socket) {
    return (CXPLAT_SOCKET_RAW*)((unsigned char*)Socket - sizeof(CXPLAT_SOCKET_RAW) + sizeof(CXPLAT_SOCKET));
}

CXPLAT_SOCKET_RAW*
CxPlatGetSocket(
    _In_ const CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    CXPLAT_SOCKET_RAW* Socket = NULL;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    CxPlatRwLockAcquireShared(&((CXPLAT_SOCKET_POOL*)Pool)->Lock);
    Entry = CxPlatHashtableLookup(&Pool->Sockets, LocalAddress->Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET_RAW* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET_RAW, Entry);
        if (CxPlatSocketCompare(Temp, LocalAddress, RemoteAddress)) {
            if (CxPlatRundownAcquire(&Temp->RawRundown)) {
                Socket = Temp;
            }
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    CxPlatRwLockReleaseShared(&((CXPLAT_SOCKET_POOL*)Pool)->Lock);
    return Socket;
}

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);

    if (Socket->AuxSocket != INVALID_SOCKET &&
        CxPlatCloseSocket(Socket->AuxSocket) == SOCKET_ERROR) {
        int Error = CxPlatSocketError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "closesocket");
    }

    CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

void
RawResolveRouteComplete(
    _In_ void* Context,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    )
{
    QUIC_CONNECTION* Connection = (QUIC_CONNECTION*)Context;
    CxPlatCopyMemory(&Route->NextHopLinkLayerAddress, PhysicalAddress, sizeof(Route->NextHopLinkLayerAddress));
    Route->State = RouteResolved;
    QuicTraceLogConnInfo(
        RouteResolutionEnd,
        Connection,
        "Route resolution completed on Path[%hhu] with L2 address %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        PathId,
        Route->NextHopLinkLayerAddress[0],
        Route->NextHopLinkLayerAddress[1],
        Route->NextHopLinkLayerAddress[2],
        Route->NextHopLinkLayerAddress[3],
        Route->NextHopLinkLayerAddress[4],
        Route->NextHopLinkLayerAddress[5]);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    if (!DstRoute->TcpState.Syncd) {
        DstRoute->TcpState.Syncd = TRUE;
        //
        // The sequence number and ACK number in the source route are
        // taken from the received TCP packets.
        //
        // We are ACKing the peer's sequence number - 1 as if we never received
        // any data packets from the peer. This creates one byte sequence space
        // for the RST packet to be in-order.
        // For the sequence number, we skip one byte as it's reserved for in-order RST.
        //
        DstRoute->TcpState.AckNumber =
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(SrcRoute->TcpState.SequenceNumber) - 1);
        DstRoute->TcpState.SequenceNumber =
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(SrcRoute->TcpState.AckNumber) + 1);
    }
}

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

    if (Length < QuicNetByteSwapShort(Udp->Length)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Datapath,
            Length,
            "UDP Length larger than IP length");
        return;
    }

    Packet->Reserved = L4_TYPE_UDP;

    Packet->Route->RemoteAddress.Ipv4.sin_port = Udp->SourcePort;
    Packet->Route->LocalAddress.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Buffer = (uint8_t*)Udp->Data;
    Packet->BufferLength = QuicNetByteSwapShort(Udp->Length) - sizeof(UDP_HEADER);
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
    if (Length < IPTotalLength) {
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

_IRQL_requires_max_(DISPATCH_LEVEL)
HEADER_BACKFILL
CxPlatDpRawCalculateHeaderBackFill(
    _In_ CXPLAT_ROUTE* Route
    )
{
    HEADER_BACKFILL HeaderBackFill;
    HeaderBackFill.TransportLayer = Route->UseQTIP ? sizeof(TCP_HEADER) : sizeof(UDP_HEADER);
    HeaderBackFill.NetworkLayer =
        QuicAddrGetFamily(&Route->RemoteAddress) == QUIC_ADDRESS_FAMILY_INET ? sizeof(IPV4_HEADER) : sizeof(IPV6_HEADER);
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
    // Add up all bytes in 3 steps:
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

    for (uint32_t i = 0; i < Length; i += 4) {
        InitialChecksum += *((uint32_t*)(&Data[i]));
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
CxPlatFramingTransportChecksum(
    _In_reads_(AddrLength) uint8_t* SrcAddr,
    _In_reads_(AddrLength) uint8_t* DstAddr,
    _In_ uint32_t AddrLength,
    _In_ uint16_t NextHeader,
    _In_reads_(IPPayloadLength) uint8_t* IPPayload,
    _In_ uint32_t IPPayloadLength,
    _In_ BOOLEAN PseudoHeaderOnly
    )
{
    uint64_t Checksum =
        CxPlatByteSwapUint16(NextHeader) + CxPlatByteSwapUint16((uint16_t)IPPayloadLength);
    Checksum = CxPlatFramingChecksum(SrcAddr, AddrLength, Checksum);
    Checksum = CxPlatFramingChecksum(DstAddr, AddrLength, Checksum);

    if (!PseudoHeaderOnly) {
        //
        // Pseudoheader is always in 32-bit words. So, cross 16-bit boundary adjustment isn't
        // needed.
        //
        Checksum = ~CxPlatFramingChecksum(IPPayload, IPPayloadLength, Checksum);
    }

    return (uint16_t)Checksum;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketAckFin(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ CXPLAT_RECV_DATA* Packet
    )
{
    CXPLAT_ROUTE* Route = Packet->Route;
    CXPLAT_DBG_ASSERT(Route->UseQTIP);
    CXPLAT_SEND_CONFIG SendConfig = { Route, 0, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0 };
    CXPLAT_SEND_DATA *SendData = CxPlatSendDataAlloc(CxPlatRawToSocket(Socket), &SendConfig);
    if (SendData == NULL) {
        return;
    }

    QuicTraceEvent(
        DatapathSendTcpControl,
        "[data][%p] Send %u bytes TCP control packet Flags=%hhu Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        (uint8_t)(TH_FIN | TH_ACK),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
    CXPLAT_DBG_ASSERT(Route->State == RouteResolved);
    CXPLAT_DBG_ASSERT(Route->Queue != NULL);
    TCP_HEADER* ReceivedTcpHeader = (TCP_HEADER*)(Packet->Buffer - Packet->ReservedEx);

    CxPlatFramingWriteHeaders(
        Socket, Route, SendData, &SendData->Buffer, SendData->ECN, SendData->DSCP,
        CxPlatDpRawIsL3TxXsumOffloadedOnQueue(Route->Queue),
        CxPlatDpRawIsL4TxXsumOffloadedOnQueue(Route->Queue),
        ReceivedTcpHeader->AckNumber,
        CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
        TH_FIN | TH_ACK);
    CxPlatDpRawTxEnqueue(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketAckSyn(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ CXPLAT_RECV_DATA* Packet
    )
{
    CXPLAT_ROUTE* Route = Packet->Route;
    CXPLAT_DBG_ASSERT(Route->UseQTIP);
    CXPLAT_SEND_CONFIG SendConfig = { Route, 0, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0 };
    CXPLAT_SEND_DATA *SendData = CxPlatSendDataAlloc(CxPlatRawToSocket(Socket), &SendConfig);
    if (SendData == NULL) {
        return;
    }

    uint8_t TcpFlags = Packet->Reserved == L4_TYPE_TCP_SYN ? (TH_SYN | TH_ACK) : TH_ACK;
    CXPLAT_DBG_ASSERT(Route->State == RouteResolved);
    CXPLAT_DBG_ASSERT(Route->Queue != NULL);
    TCP_HEADER* ReceivedTcpHeader = (TCP_HEADER*)(Packet->Buffer - Packet->ReservedEx);

    QuicTraceEvent(
        DatapathSendTcpControl,
        "[data][%p] Send %u bytes TCP control packet Flags=%hhu Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        TcpFlags,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    CxPlatFramingWriteHeaders(
        Socket, Route, SendData, &SendData->Buffer, SendData->ECN, SendData->DSCP,
        CxPlatDpRawIsL3TxXsumOffloadedOnQueue(Route->Queue),
        CxPlatDpRawIsL4TxXsumOffloadedOnQueue(Route->Queue),
        ReceivedTcpHeader->AckNumber,
        CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
        TcpFlags);
    CxPlatDpRawTxEnqueue(SendData);

    SendData = InterlockedFetchAndClearPointer((void*)&Socket->PausedTcpSend);
    if (SendData) {
        CXPLAT_DBG_ASSERT(Socket->Connected);
        QuicTraceEvent(
            DatapathSendTcpControl,
            "[data][%p] Send %u bytes TCP control packet Flags=%hhu Dst=%!ADDR!, Src=%!ADDR!",
            Socket,
            SendData->Buffer.Length,
            TH_ACK,
            CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
        CxPlatFramingWriteHeaders(
            Socket, Route, SendData, &SendData->Buffer, SendData->ECN, SendData->DSCP,
            CxPlatDpRawIsL3TxXsumOffloadedOnQueue(Route->Queue),
            CxPlatDpRawIsL4TxXsumOffloadedOnQueue(Route->Queue),
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->AckNumber) + 1),
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
            TH_ACK);
        CxPlatDpRawTxEnqueue(SendData);

        SendData = CxPlatSendDataAlloc(CxPlatRawToSocket(Socket), &SendConfig);
        if (SendData == NULL) {
            return;
        }

        QuicTraceEvent(
            DatapathSend,
            "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
            Socket,
            SendData->Buffer.Length,
            1,
            (uint16_t)SendData->Buffer.Length,
            CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
        CxPlatFramingWriteHeaders(
            Socket, Route, SendData, &SendData->Buffer, SendData->ECN, SendData->DSCP,
            CxPlatDpRawIsL3TxXsumOffloadedOnQueue(Route->Queue),
            CxPlatDpRawIsL4TxXsumOffloadedOnQueue(Route->Queue),
            ReceivedTcpHeader->AckNumber,
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
            TH_RST | TH_ACK);
        Socket->CachedRstSend = SendData;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketSyn(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route
    )
{
    CXPLAT_DBG_ASSERT(Route->UseQTIP);
    CXPLAT_SEND_CONFIG SendConfig = { (CXPLAT_ROUTE*)Route, 0, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0 };
    CXPLAT_SEND_DATA *SendData = CxPlatSendDataAlloc(CxPlatRawToSocket(Socket), &SendConfig);
    if (SendData == NULL) {
        return;
    }

    QuicTraceEvent(
        DatapathSendTcpControl,
        "[data][%p] Send %u bytes TCP control packet Flags=%hhu Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        TH_SYN,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));
    CXPLAT_DBG_ASSERT(Route->State == RouteResolved);
    CXPLAT_DBG_ASSERT(Route->Queue != NULL);
    CxPlatFramingWriteHeaders(
        Socket, Route, SendData, &SendData->Buffer, SendData->ECN, SendData->DSCP,
        CxPlatDpRawIsL3TxXsumOffloadedOnQueue(Route->Queue),
        CxPlatDpRawIsL4TxXsumOffloadedOnQueue(Route->Queue),
        Route->TcpState.SequenceNumber, 0, TH_SYN);
    CxPlatDpRawTxEnqueue(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatFramingWriteHeaders(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _Inout_ CXPLAT_SEND_DATA* SendData,
    _Inout_ QUIC_BUFFER* Buffer,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint8_t DSCP,
    _In_ BOOLEAN SkipNetworkLayerXsum,
    _In_ BOOLEAN SkipTransportLayerXsum,
    _In_ uint32_t TcpSeqNum,
    _In_ uint32_t TcpAckNum,
    _In_ uint8_t TcpFlags
    )
{
    uint8_t* Transport;
    uint16_t TransportLength;
    uint8_t TransportProtocol;
    TCP_HEADER* TCP = NULL;
    UDP_HEADER* UDP = NULL;
    ETHERNET_HEADER* Ethernet;
    uint16_t EthType;
    uint16_t IpHeaderLen;
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Route->RemoteAddress);

    CXPLAT_DBG_ASSERT(
        Family == QUIC_ADDRESS_FAMILY_INET || Family == QUIC_ADDRESS_FAMILY_INET6);

    if (Route->UseQTIP) {
        //
        // Fill TCP header.
        //
        TCP = (TCP_HEADER*)(Buffer->Buffer - sizeof(TCP_HEADER));
        TCP->DestinationPort = Route->RemoteAddress.Ipv4.sin_port;
        TCP->SourcePort = Route->LocalAddress.Ipv4.sin_port;
        TCP->Window = 0xFFFF;
        TCP->X2 = 0;
        TCP->Checksum = 0;
        TCP->UrgentPointer = 0;
        TCP->HeaderLength = sizeof(TCP_HEADER) / sizeof(uint32_t);
        TCP->SequenceNumber = TcpSeqNum;
        TCP->AckNumber = TcpAckNum;
        TCP->Flags = TcpFlags;

        Transport = (uint8_t*)TCP;
        TransportLength = sizeof(TCP_HEADER);
        TransportProtocol = IPPROTO_TCP;
    } else {
        //
        // Fill UDP header.
        //
        UDP = (UDP_HEADER*)(Buffer->Buffer - sizeof(UDP_HEADER));
        UDP->DestinationPort = Route->RemoteAddress.Ipv4.sin_port;
        UDP->SourcePort = Route->LocalAddress.Ipv4.sin_port;
        UDP->Length = QuicNetByteSwapShort((uint16_t)Buffer->Length + sizeof(UDP_HEADER));
        UDP->Checksum = 0;
        Transport = (uint8_t*)UDP;
        TransportLength = sizeof(UDP_HEADER);
        TransportProtocol = IPPROTO_UDP;
    }

    //
    // Fill IPv4/IPv6 header.
    //
    if (Family == QUIC_ADDRESS_FAMILY_INET) {
        IPV4_HEADER* IPv4 = (IPV4_HEADER*)(Transport - sizeof(IPV4_HEADER));
        IPv4->VersionAndHeaderLength = IPV4_DEFAULT_VERHLEN;
        IPv4->TypeOfService = DSCP;
        IPv4->EcnField = ECN;
        IPv4->TotalLength = htons(sizeof(IPV4_HEADER) + TransportLength + (uint16_t)Buffer->Length);
        IPv4->Identification = 0;
        IPv4->FlagsAndFragmentOffset = 0;
        IPv4->TimeToLive = IP_DEFAULT_HOP_LIMIT;
        IPv4->Protocol = TransportProtocol;
        CxPlatCopyMemory(IPv4->Source, &Route->LocalAddress.Ipv4.sin_addr, sizeof(Route->LocalAddress.Ipv4.sin_addr));
        CxPlatCopyMemory(IPv4->Destination, &Route->RemoteAddress.Ipv4.sin_addr, sizeof(Route->RemoteAddress.Ipv4.sin_addr));
        if (SkipNetworkLayerXsum) {
            IPv4->HeaderChecksum = 0;
            CxPlatDpRawTxSetL3ChecksumOffload(SendData);
        } else {
            *((volatile uint16_t*)(&IPv4->HeaderChecksum)) = 0;
            IPv4->HeaderChecksum = ~CxPlatFramingChecksum((uint8_t*)IPv4, sizeof(IPV4_HEADER), 0);
        }
        EthType = ETHERNET_TYPE_IPV4;
        Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv4) - sizeof(ETHERNET_HEADER));
        IpHeaderLen = sizeof(IPV4_HEADER);
        if (Route->UseQTIP) {
            *((volatile uint16_t*)(&TCP->Checksum)) = 0;
            TCP->Checksum =
                CxPlatFramingTransportChecksum(
                    IPv4->Source, IPv4->Destination,
                    sizeof(Route->LocalAddress.Ipv4.sin_addr),
                    IPPROTO_TCP,
                    (uint8_t*)TCP, sizeof(TCP_HEADER) + Buffer->Length,
                    SkipTransportLayerXsum);
        } else {
            *((volatile uint16_t*)(&UDP->Checksum)) = 0;
            UDP->Checksum =
                CxPlatFramingTransportChecksum(
                    IPv4->Source, IPv4->Destination,
                    sizeof(Route->LocalAddress.Ipv4.sin_addr),
                    IPPROTO_UDP,
                    (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length,
                    SkipTransportLayerXsum);
        }
        if (SkipTransportLayerXsum) {
            CxPlatDpRawTxSetL4ChecksumOffload(
                SendData, FALSE, Route->UseQTIP,
                Route->UseQTIP ? sizeof(TCP_HEADER) : sizeof(UDP_HEADER));
        }
    } else {
        IPV6_HEADER* IPv6 = (IPV6_HEADER*)(Transport - sizeof(IPV6_HEADER));
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
        VersionClassEcnFlow.Class = DSCP;
        VersionClassEcnFlow.EcnField = ECN;
        VersionClassEcnFlow.Flow = (uint32_t)(uintptr_t)Socket;

        IPv6->VersionClassEcnFlow = CxPlatByteSwapUint32(VersionClassEcnFlow.Value);
        IPv6->PayloadLength = htons(TransportLength + (uint16_t)Buffer->Length);
        IPv6->HopLimit = IP_DEFAULT_HOP_LIMIT;
        IPv6->NextHeader = TransportProtocol;
        CxPlatCopyMemory(IPv6->Source, &Route->LocalAddress.Ipv6.sin6_addr, sizeof(Route->LocalAddress.Ipv6.sin6_addr));
        CxPlatCopyMemory(IPv6->Destination, &Route->RemoteAddress.Ipv6.sin6_addr, sizeof(Route->RemoteAddress.Ipv6.sin6_addr));
        EthType = ETHERNET_TYPE_IPV6;
        Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv6) - sizeof(ETHERNET_HEADER));
        IpHeaderLen = sizeof(IPV6_HEADER);
        if (Route->UseQTIP) {
            *((volatile uint16_t*)(&TCP->Checksum)) = 0;
            TCP->Checksum =
                CxPlatFramingTransportChecksum(
                    IPv6->Source, IPv6->Destination,
                    sizeof(Route->LocalAddress.Ipv6.sin6_addr),
                    IPPROTO_TCP,
                    (uint8_t*)TCP, sizeof(TCP_HEADER) + Buffer->Length,
                    SkipTransportLayerXsum);
        } else {
            *((volatile uint16_t*)(&UDP->Checksum)) = 0;
            UDP->Checksum =
                CxPlatFramingTransportChecksum(
                    IPv6->Source, IPv6->Destination,
                    sizeof(Route->LocalAddress.Ipv6.sin6_addr),
                    IPPROTO_UDP,
                    (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length,
                    SkipTransportLayerXsum);
            if (!SkipTransportLayerXsum) {
                UDP->Checksum = UDP->Checksum != 0 ? UDP->Checksum : ~0;
            }
        }
        if (SkipTransportLayerXsum) {
            CxPlatDpRawTxSetL4ChecksumOffload(
                SendData, TRUE, Route->UseQTIP,
                Route->UseQTIP ? sizeof(TCP_HEADER) : sizeof(UDP_HEADER));
        }
    }

    //
    // Fill Ethernet header.
    //
    Ethernet->Type = EthType;
    CxPlatCopyMemory(Ethernet->Destination, Route->NextHopLinkLayerAddress, sizeof(Route->NextHopLinkLayerAddress));
    CxPlatCopyMemory(Ethernet->Source, Route->LocalLinkLayerAddress, sizeof(Route->LocalLinkLayerAddress));

    Buffer->Length += TransportLength + IpHeaderLen + sizeof(ETHERNET_HEADER);
    Buffer->Buffer -= TransportLength + IpHeaderLen + sizeof(ETHERNET_HEADER);
}

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    int Option;
    QUIC_ADDR MappedAddress = {0};
    SOCKET TempUdpSocket = INVALID_SOCKET;
    CxPlatAddressLengthType AssignedLocalAddressLength;

    //
    // Get (and reserve) a transport layer port from the OS networking stack by
    // binding an auxiliary (dual stack) socket.
    //

    if (Socket->ReserveAuxTcpSock) {
        Socket->AuxSocket =
            socket(
                AF_INET6,
                SOCK_STREAM,
                IPPROTO_TCP);
        if (Socket->AuxSocket == INVALID_SOCKET) {
            int WsaError = CxPlatSocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "socket");
            Status = CxPlatQuicErrorFromSocketError(WsaError);
            goto Error;
        }

        Option = FALSE;
        Result =
            setsockopt(
                Socket->AuxSocket,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = CxPlatSocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_V6ONLY");
            Status = CxPlatQuicErrorFromSocketError(WsaError);
            goto Error;
        }

        if (Socket->CibirIdLength) {
            Option = TRUE;
            Result =
                setsockopt(
                    Socket->AuxSocket,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set SO_REUSEADDR");
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
        }

        CxPlatConvertToMappedV6(&Socket->LocalAddress, &MappedAddress);
#if QUIC_ADDRESS_FAMILY_INET6 != AF_INET6
        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }
#endif
    }

    CxPlatRwLockAcquireExclusive(&Pool->Lock);

    if (Socket->ReserveAuxTcpSock) {
        QUIC_ADDR_STR LocalAddressString = {0};
        QuicAddrToString(&MappedAddress, &LocalAddressString);
        QuicTraceLogVerbose(
            DatapathTcpAuxBinding,
            "[data][%p] Binding TCP socket to %s",
            Socket,
            LocalAddressString.Address);
        Result =
            bind(
                Socket->AuxSocket,
                (struct sockaddr*)&MappedAddress,
                sizeof(MappedAddress));
        if (Result == SOCKET_ERROR) {
            int WsaError = CxPlatSocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "bind");
            CxPlatRwLockReleaseExclusive(&Pool->Lock);
            Status = CxPlatQuicErrorFromSocketError(WsaError);
            goto Error;
        }

        if (Socket->Connected) {
            CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
            CxPlatConvertToMappedV6(&Socket->RemoteAddress, &MappedAddress);

#if QUIC_ADDRESS_FAMILY_INET6 != AF_INET6
            if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
                MappedAddress.Ipv6.sin6_family = AF_INET6;
            }
#endif
            //
            // Create a temporary UDP socket bound to a wildcard port
            // and connect this socket to the remote address.
            // By doing this, the OS will select a local address for us.
            //
            uint16_t LocalPortChosen = 0;
            QUIC_ADDR TempLocalAddress = {0};
            AssignedLocalAddressLength = sizeof(TempLocalAddress);
            Result =
                getsockname(
                    Socket->AuxSocket,
                    (struct sockaddr*)&TempLocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
            LocalPortChosen = TempLocalAddress.Ipv4.sin_port;
            TempUdpSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (TempUdpSocket == INVALID_SOCKET) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "temp udp socket");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            Option = FALSE;
            Result =
                setsockopt(
                    TempUdpSocket,
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set IPV6_V6ONLY (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            CxPlatZeroMemory(&TempLocalAddress, sizeof(TempLocalAddress));
            CxPlatConvertToMappedV6(&Socket->LocalAddress, &TempLocalAddress);
            TempLocalAddress.Ipv4.sin_port = 0;
            Result =
                bind(
                    TempUdpSocket,
                    (struct sockaddr*)&TempLocalAddress,
                    sizeof(TempLocalAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "bind (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            Result =
                connect(
                    TempUdpSocket,
                    (struct sockaddr*)&MappedAddress,
                    sizeof(MappedAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "connect failed (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }

            AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    TempUdpSocket,
                    (struct sockaddr*)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
            CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
            Socket->LocalAddress.Ipv4.sin_port = LocalPortChosen;
            CXPLAT_FRE_ASSERT(Socket->LocalAddress.Ipv4.sin_port != 0);
        } else {
            AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    Socket->AuxSocket,
                    (struct sockaddr*)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = CxPlatSocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = CxPlatQuicErrorFromSocketError(WsaError);
                goto Error;
            }
            CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
        }
    }

    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET_RAW* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET_RAW, Entry);
        if (CxPlatSocketCompare(Temp, &Socket->LocalAddress, &Socket->RemoteAddress)) {
            Status = QUIC_STATUS_ADDRESS_IN_USE;
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatHashtableInsert(&Pool->Sockets, &Socket->Entry, Socket->LocalAddress.Ipv4.sin_port, &Context);
    }

    CxPlatRwLockReleaseExclusive(&Pool->Lock);

Error:

    if (QUIC_FAILED(Status) && Socket->AuxSocket != INVALID_SOCKET) {
        CxPlatCloseSocket(Socket->AuxSocket);
    }

    if (TempUdpSocket != INVALID_SOCKET) {
        CxPlatCloseSocket(TempUdpSocket);
    }

    return Status;
}
