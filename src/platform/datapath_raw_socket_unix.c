/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw_unix.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket.c.clog.h"
#endif

#include <stdio.h>

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

#ifdef _WIN32
// #define SocketError() WSAGetLastError()
#else
// #define SocketError() errno
// #define HRESULT_FROM_WIN32 (QUIC_STATUS)
#endif // _WIN32

//
// Socket Pool Logic
//

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        return FALSE;
    }
#ifdef _WIN32
    int WsaError;
    WSADATA WsaData;
    if ((WsaError = WSAStartup(MAKEWORD(2, 2), &WsaData)) != 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "WSAStartup");
        CxPlatHashtableUninitialize(&Pool->Sockets);
        return FALSE;
    }
#endif // _WIN32
    CxPlatRwLockInitialize(&Pool->Lock);
    return TRUE;
}

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
#ifdef _WIN32
    (void)WSACleanup();
#endif // _WIN32
    CxPlatRwLockUninitialize(&Pool->Lock);
    CxPlatHashtableUninitialize(&Pool->Sockets);
}

CXPLAT_SOCKET*
CxPlatGetSocket(
    _In_ const CXPLAT_SOCKET_POOL* Pool,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    CXPLAT_SOCKET* Socket = NULL;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    CxPlatRwLockAcquireShared(&((CXPLAT_SOCKET_POOL*)Pool)->Lock);
    Entry = CxPlatHashtableLookup(&Pool->Sockets, LocalAddress->Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
        if (CxPlatSocketCompare(Temp, LocalAddress, RemoteAddress)) {
            if (CxPlatRundownAcquire(&Temp->Rundown)) {
                Socket = Temp;
            }
            break;
        }
        Entry = CxPlatHashtableLookupNext(&Pool->Sockets, &Context);
    }
    CxPlatRwLockReleaseShared(&((CXPLAT_SOCKET_POOL*)Pool)->Lock);
    return Socket;
}

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    QUIC_ADDR MappedAddress = {0};
    SOCKET TempUdpSocket = INVALID_SOCKET;
    uint32_t AssignedLocalAddressLength;

    //
    // Get (and reserve) a transport layer port from the OS networking stack by
    // binding an auxiliary (dual stack) socket.
    //

    Socket->AuxSocket =
        socket(
            AF_INET6,
            Socket->UseTcp ? SOCK_STREAM : SOCK_DGRAM,
            Socket->UseTcp ? IPPROTO_TCP : IPPROTO_UDP);
    if (Socket->AuxSocket == INVALID_SOCKET) {
        int WsaError = SocketError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "socket");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    int Option = FALSE;
    Result =
        setsockopt(
            Socket->AuxSocket,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (char*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        int WsaError = SocketError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "Set IPV6_V6ONLY");
        Status = HRESULT_FROM_WIN32(WsaError);
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
            int WsaError = SocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set SO_REUSEADDR");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }
    }

    CxPlatConvertToMappedV6(&Socket->LocalAddress, &MappedAddress);
#if QUIC_ADDRESS_FAMILY_INET6 != AF_INET6
    if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedAddress.Ipv6.sin6_family = AF_INET6;
    }
#endif

    CxPlatRwLockAcquireExclusive(&Pool->Lock);

    Result =
        bind(
            Socket->AuxSocket,
            (struct sockaddr*)&MappedAddress,
            sizeof(MappedAddress));
    if (Result == SOCKET_ERROR) {
        int WsaError = SocketError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "bind");
        CxPlatRwLockReleaseExclusive(&Pool->Lock);
        Status = HRESULT_FROM_WIN32(WsaError);
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
        if (Socket->UseTcp) {
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
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
            LocalPortChosen = TempLocalAddress.Ipv4.sin_port;
            TempUdpSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (TempUdpSocket == INVALID_SOCKET) {
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "temp udp socket");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
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
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set IPV6_V6ONLY (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
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
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "bind (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

            Result =
                connect(
                    TempUdpSocket,
                    (struct sockaddr*)&MappedAddress,
                    sizeof(MappedAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "connect failed (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

            AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    TempUdpSocket,
                    (struct sockaddr*)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname (temp udp socket)");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
            CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
            Socket->LocalAddress.Ipv4.sin_port = LocalPortChosen;
            CXPLAT_FRE_ASSERT(Socket->LocalAddress.Ipv4.sin_port != 0);
        } else {
            Result =
                connect(
                    Socket->AuxSocket,
                    (struct sockaddr*)&MappedAddress,
                    sizeof(MappedAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "connect failed");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
            AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    Socket->AuxSocket,
                    (struct sockaddr*)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = SocketError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockname");
                CxPlatRwLockReleaseExclusive(&Pool->Lock);
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
            CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
        }
    } else {
        AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
        Result =
            getsockname(
                Socket->AuxSocket,
                (struct sockaddr*)&Socket->LocalAddress,
                &AssignedLocalAddressLength);
        if (Result == SOCKET_ERROR) {
            int WsaError = SocketError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "getsockname");
            CxPlatRwLockReleaseExclusive(&Pool->Lock);
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }
        CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);
    }

    Entry = CxPlatHashtableLookup(&Pool->Sockets, Socket->LocalAddress.Ipv4.sin_port, &Context);
    while (Entry != NULL) {
        CXPLAT_SOCKET* Temp = CXPLAT_CONTAINING_RECORD(Entry, CXPLAT_SOCKET, Entry);
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
        close(Socket->AuxSocket);
    }

    if (TempUdpSocket != INVALID_SOCKET) {
        close(TempUdpSocket);
    }

    return Status;
}

// -> CxPlat? only closesocket diff
void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    UNREFERENCED_PARAMETER(Pool);
    UNREFERENCED_PARAMETER(Socket);
    // CxPlatRwLockAcquireExclusive(&Pool->Lock);
    // CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);

    // if (closesocket(Socket->AuxSocket) == SOCKET_ERROR) {
    //     int Error = SocketError();
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Socket,
    //         Error,
    //         "closesocket");
    // }

    // CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

// -> CxPlat?
void
CxPlatResolveRouteComplete(
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
CxPlatUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    if (DstRoute->State == RouteResolved &&
        DstRoute->Queue != SrcRoute->Queue) {
        DstRoute->Queue = SrcRoute->Queue;
    }

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

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatResolveRoute(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    )
{
#ifdef _WIN32
    NETIO_STATUS Status = ERROR_SUCCESS;
    MIB_IPFORWARD_ROW2 IpforwardRow = {0};
    CXPLAT_ROUTE_STATE State = Route->State;
    QUIC_ADDR LocalAddress = {0};

    CXPLAT_DBG_ASSERT(!QuicAddrIsWildCard(&Route->RemoteAddress));

    Route->State = RouteResolving;

    QuicTraceEvent(
        DatapathGetRouteStart,
        "[data][%p] Querying route, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress));

    //
    // Find the best next hop IP address.
    //
    Status =
        GetBestRoute2(
            NULL, // InterfaceLuid
            IFI_UNSPECIFIED, // InterfaceIndex
            &Route->LocalAddress, // SourceAddress
            &Route->RemoteAddress, // DestinationAddress
            0, // AddressSortOptions
            &IpforwardRow,
            &LocalAddress); // BestSourceAddress

    if (Status != ERROR_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "GetBestRoute2");
        goto Done;
    }

    QuicTraceEvent(
        DatapathGetRouteComplete,
        "[data][%p] Query route result: %!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(sizeof(LocalAddress), &LocalAddress));

    if (State == RouteSuspected && !QuicAddrCompareIp(&LocalAddress, &Route->LocalAddress)) {
        //
        // We can't handle local address change here easily due to lack of full migration support.
        //
        Status = ERROR_INVALID_STATE;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "GetBestRoute2 returned different local address for the suspected route");
        goto Done;
    } else {
        LocalAddress.Ipv4.sin_port = Route->LocalAddress.Ipv4.sin_port; // Preserve local port.
        Route->LocalAddress = LocalAddress;
    }

    //
    // Find the interface that matches the route we just looked up.
    //
    CXPLAT_LIST_ENTRY* Entry = Socket->Datapath->Interfaces.Flink;
    for (; Entry != &Socket->Datapath->Interfaces; Entry = Entry->Flink) {
        CXPLAT_INTERFACE* Interface = CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);
        if (Interface->IfIndex == IpforwardRow.InterfaceIndex) {
            CXPLAT_DBG_ASSERT(sizeof(Interface->PhysicalAddress) == sizeof(Route->LocalLinkLayerAddress));
            CxPlatCopyMemory(&Route->LocalLinkLayerAddress, Interface->PhysicalAddress, sizeof(Route->LocalLinkLayerAddress));
            CxPlatDpRawAssignQueue(Interface, Route);
            break;
        }
    }

    if (Route->Queue == NULL) {
        Status = ERROR_NOT_FOUND;
        QuicTraceEvent(
            DatapathError,
            "[data][%p] ERROR, %s.",
            Socket,
            "no matching interface/queue");
        goto Done;
    }

    //
    // Map the next hop IP address to a link-layer address.
    //
    MIB_IPNET_ROW2 IpnetRow = {0};
    IpnetRow.InterfaceLuid = IpforwardRow.InterfaceLuid;
    if (QuicAddrIsWildCard(&IpforwardRow.NextHop)) { // On-link?
        IpnetRow.Address = Route->RemoteAddress;
    } else {
        IpnetRow.Address = IpforwardRow.NextHop;
    }

    //
    // Call GetIpNetEntry2 to see if there's already a cached neighbor.
    //
    Status = GetIpNetEntry2(&IpnetRow);
    QuicTraceLogConnInfo(
        RouteResolutionStart,
        Context,
        "Starting to look up neighbor on Path[%hhu] with status %u",
        PathId,
        Status);
    //
    // We need to force neighbor solicitation (NS) if any of the following is true:
    // 1. No cached neighbor entry for the given destination address.
    // 2. The neighbor entry isn't in a usable state.
    // 3. When we are re-resolving a suspected route, the neighbor entry is the same as the existing one.
    //
    // We queue an operation on the route worker for NS because it involves network IO and
    // we don't want our connection worker queue blocked.
    //
    if ((Status != ERROR_SUCCESS || IpnetRow.State <= NlnsIncomplete) ||
        (State == RouteSuspected &&
         memcmp(
             Route->NextHopLinkLayerAddress,
             IpnetRow.PhysicalAddress,
             sizeof(Route->NextHopLinkLayerAddress)) == 0)) {
        CXPLAT_ROUTE_RESOLUTION_WORKER* Worker = Socket->Datapath->RouteResolutionWorker;
        CXPLAT_ROUTE_RESOLUTION_OPERATION* Operation = CxPlatPoolAlloc(&Worker->OperationPool);
        if (Operation == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_DATAPATH",
                sizeof(CXPLAT_ROUTE_RESOLUTION_OPERATION));
            Status = ERROR_NOT_ENOUGH_MEMORY;
            goto Done;
        }
        Operation->IpnetRow = IpnetRow;
        Operation->Context = Context;
        Operation->Callback = Callback;
        Operation->PathId = PathId;
        CxPlatDispatchLockAcquire(&Worker->Lock);
        CxPlatListInsertTail(&Worker->Operations, &Operation->WorkerLink);
        CxPlatDispatchLockRelease(&Worker->Lock);
        CxPlatEventSet(Worker->Ready);
        Status = ERROR_IO_PENDING;
    } else {
        CxPlatResolveRouteComplete(Context, Route, IpnetRow.PhysicalAddress, PathId);
    }

Done:
    if (Status != ERROR_IO_PENDING && Status != ERROR_SUCCESS) {
        Callback(Context, NULL, PathId, FALSE);
    }

    if (Status == ERROR_IO_PENDING) {
        return QUIC_STATUS_PENDING;
    } else {
        return HRESULT_FROM_WIN32(Status);
    }
#else // _WIN32
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(PathId);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Callback);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif // _WIN32
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

_IRQL_requires_max_(DISPATCH_LEVEL)
HEADER_BACKFILL
CxPlatDpRawCalculateHeaderBackFill(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ BOOLEAN UseTcp
    )
{
    HEADER_BACKFILL HeaderBackFill;
    HeaderBackFill.TransportLayer = UseTcp ? sizeof(TCP_HEADER) : sizeof(UDP_HEADER);
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
    return ~CxPlatFramingChecksum(IPPayload, IPPayloadLength, Checksum);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketAckFin(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_RECV_DATA* Packet
    )
{
    CXPLAT_DBG_ASSERT(Socket->UseTcp);

    CXPLAT_ROUTE* Route = Packet->Route;
    CXPLAT_SEND_CONFIG SendConfig = { Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    CXPLAT_SEND_DATA *SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
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
    const CXPLAT_INTERFACE* Interface = CxPlatDpRawGetInterfaceFromQueue(Route->Queue);
    TCP_HEADER* ReceivedTcpHeader = (TCP_HEADER*)(Packet->Buffer - Packet->ReservedEx);

    CxPlatFramingWriteHeaders(
        Socket, Route, &SendData->Buffer, SendData->ECN,
        Interface->OffloadStatus.Transmit.NetworkLayerXsum,
        Interface->OffloadStatus.Transmit.TransportLayerXsum,
        ReceivedTcpHeader->AckNumber,
        CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
        TH_FIN | TH_ACK);
    CxPlatDpRawTxEnqueue(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketAckSyn(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_RECV_DATA* Packet
    )
{
    CXPLAT_DBG_ASSERT(Socket->UseTcp);

    CXPLAT_ROUTE* Route = Packet->Route;
    CXPLAT_SEND_CONFIG SendConfig = { Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    CXPLAT_SEND_DATA *SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
    if (SendData == NULL) {
        return;
    }

    uint8_t TcpFlags = Packet->Reserved == L4_TYPE_TCP_SYN ? (TH_SYN | TH_ACK) : TH_ACK;
    CXPLAT_DBG_ASSERT(Route->State == RouteResolved);
    CXPLAT_DBG_ASSERT(Route->Queue != NULL);
    const CXPLAT_INTERFACE* Interface = CxPlatDpRawGetInterfaceFromQueue(Route->Queue);
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
        Socket, Route, &SendData->Buffer, SendData->ECN,
        Interface->OffloadStatus.Transmit.NetworkLayerXsum,
        Interface->OffloadStatus.Transmit.TransportLayerXsum,
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
            Socket, Route, &SendData->Buffer, SendData->ECN,
            Interface->OffloadStatus.Transmit.NetworkLayerXsum,
            Interface->OffloadStatus.Transmit.TransportLayerXsum,
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->AckNumber) + 1),
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
            TH_ACK);
        CxPlatDpRawTxEnqueue(SendData);

        SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
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
            Socket, Route, &SendData->Buffer, SendData->ECN,
            Interface->OffloadStatus.Transmit.NetworkLayerXsum,
            Interface->OffloadStatus.Transmit.TransportLayerXsum,
            ReceivedTcpHeader->AckNumber,
            CxPlatByteSwapUint32(CxPlatByteSwapUint32(ReceivedTcpHeader->SequenceNumber) + 1),
            TH_RST | TH_ACK);
        Socket->CachedRstSend = SendData;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawSocketSyn(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route
    )
{
    CXPLAT_DBG_ASSERT(Socket->UseTcp);

    CXPLAT_SEND_CONFIG SendConfig = { (CXPLAT_ROUTE*)Route, 0, CXPLAT_ECN_NON_ECT, 0 };
    CXPLAT_SEND_DATA *SendData = CxPlatSendDataAlloc(Socket, &SendConfig);
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
    const CXPLAT_INTERFACE* Interface = CxPlatDpRawGetInterfaceFromQueue(Route->Queue);
    CxPlatFramingWriteHeaders(
        Socket, Route, &SendData->Buffer, SendData->ECN,
        Interface->OffloadStatus.Transmit.NetworkLayerXsum,
        Interface->OffloadStatus.Transmit.TransportLayerXsum,
        Route->TcpState.SequenceNumber, 0, TH_SYN);
    CxPlatDpRawTxEnqueue(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatFramingWriteHeaders(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _Inout_ QUIC_BUFFER* Buffer,
    _In_ CXPLAT_ECN_TYPE ECN,
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

    if (Socket->UseTcp) {
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
        IPv4->TypeOfService = 0;
        IPv4->EcnField = ECN;
        IPv4->TotalLength = htons(sizeof(IPV4_HEADER) + TransportLength + (uint16_t)Buffer->Length);
        IPv4->Identification = 0;
        IPv4->FlagsAndFragmentOffset = 0;
        IPv4->TimeToLive = IP_DEFAULT_HOP_LIMIT;
        IPv4->Protocol = TransportProtocol;
        IPv4->HeaderChecksum = 0;
        CxPlatCopyMemory(IPv4->Source, &Route->LocalAddress.Ipv4.sin_addr, sizeof(Route->LocalAddress.Ipv4.sin_addr));
        CxPlatCopyMemory(IPv4->Destination, &Route->RemoteAddress.Ipv4.sin_addr, sizeof(Route->RemoteAddress.Ipv4.sin_addr));
        IPv4->HeaderChecksum = SkipNetworkLayerXsum ? 0 : ~CxPlatFramingChecksum((uint8_t*)IPv4, sizeof(IPV4_HEADER), 0);
        EthType = ETHERNET_TYPE_IPV4;
        Ethernet = (ETHERNET_HEADER*)(((uint8_t*)IPv4) - sizeof(ETHERNET_HEADER));
        IpHeaderLen = sizeof(IPV4_HEADER);
        if (!SkipTransportLayerXsum) {
            if (Socket->UseTcp) {
                TCP->Checksum =
                    CxPlatFramingTransportChecksum(
                        IPv4->Source, IPv4->Destination,
                        sizeof(Route->LocalAddress.Ipv4.sin_addr),
                        IPPROTO_TCP,
                        (uint8_t*)TCP, sizeof(TCP_HEADER) + Buffer->Length);
            } else {
                UDP->Checksum =
                    CxPlatFramingTransportChecksum(
                        IPv4->Source, IPv4->Destination,
                        sizeof(Route->LocalAddress.Ipv4.sin_addr),
                        IPPROTO_UDP,
                        (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length);
            }
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
        VersionClassEcnFlow.Class = 0;
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
        if (!SkipTransportLayerXsum) {
            if (Socket->UseTcp) {
                TCP->Checksum =
                    CxPlatFramingTransportChecksum(
                        IPv6->Source, IPv6->Destination,
                        sizeof(Route->LocalAddress.Ipv6.sin6_addr),
                        IPPROTO_TCP,
                        (uint8_t*)TCP, sizeof(TCP_HEADER) + Buffer->Length);
            } else {
                UDP->Checksum =
                    CxPlatFramingTransportChecksum(
                        IPv6->Source, IPv6->Destination,
                        sizeof(Route->LocalAddress.Ipv6.sin6_addr),
                        IPPROTO_UDP,
                        (uint8_t*)UDP, sizeof(UDP_HEADER) + Buffer->Length);
            }
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
