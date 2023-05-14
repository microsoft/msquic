/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw_win.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket.c.clog.h"
#endif

#define SocketError() WSAGetLastError()

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

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
    return TRUE;
}

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    (void)WSACleanup();
}

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);

    if (closesocket(Socket->AuxSocket) == SOCKET_ERROR) {
        int Error = SocketError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Error,
            "closesocket");
    }

    CxPlatRwLockReleaseExclusive(&Pool->Lock);
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
    int AssignedLocalAddressLength;

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
        closesocket(Socket->AuxSocket);
    }

    if (TempUdpSocket != INVALID_SOCKET) {
        closesocket(TempUdpSocket);
    }

    return Status;
}