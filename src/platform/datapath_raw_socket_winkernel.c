/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC raw datapath socket and IP framing abstractions

--*/

#include "datapath_raw_win.h"
#ifdef QUIC_CLOG
#include "datapath_raw_socket_winkernel.c.clog.h"
#endif

/*
typedef struct RAW_SOCKET_GLOBAL {
    //
    // The registration with WinSock Kernel.
    //
    WSK_REGISTRATION WskRegistration;
    WSK_PROVIDER_NPI WskProviderNpi;
    WSK_CLIENT_DATAGRAM_DISPATCH WskDispatch;
} RAW_SOCKET_GLOBAL;

static RAW_SOCKET_GLOBAL RawSocketGlobal;

//
// WSK Client version
//
static const WSK_CLIENT_DISPATCH WskAppDispatch = {
    MAKE_WSK_VERSION(1,0), // Use WSK version 1.0
    0,    // Reserved
    NULL  // WskClientEvent callback not required for WSK version 1.0
};
*/

//
// Socket Pool Logic
//

BOOLEAN
CxPlatSockPoolInitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    CxPlatRwLockInitialize(&Pool->Lock);
    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        return FALSE;
    }
    return TRUE;
    /*
    QUIC_STATUS Status;
    WSK_CLIENT_NPI WskClientNpi = { NULL, &WskAppDispatch };
    BOOLEAN Success = FALSE;
    BOOLEAN WskRegistered = FALSE;
    BOOLEAN HashTableInitialized = FALSE;
    ULONG NoTdi = WSK_TDI_BEHAVIOR_BYPASS_TDI;

    if (!CxPlatHashtableInitializeEx(&Pool->Sockets, CXPLAT_HASH_MIN_SIZE)) {
        goto Error;
    }
    HashTableInitialized = TRUE;

    Status = WskRegister(&WskClientNpi, &RawSocketGlobal.WskRegistration);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskRegister");
        goto Error;
    }
    WskRegistered = TRUE;

    //
    // Capture the WSK Provider NPI. If WSK subsystem is not ready yet,
    // wait until it becomes ready.
    //
    Status =
        WskCaptureProviderNPI(
            &RawSocketGlobal.WskRegistration,
            WSK_INFINITE_WAIT,
            &RawSocketGlobal.WskProviderNpi);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskCaptureProviderNPI");
        goto Error;
    }

    Status =
        RawSocketGlobal.WskProviderNpi.Dispatch->
        WskControlClient(
            RawSocketGlobal.WskProviderNpi.Client,
            WSK_TDI_BEHAVIOR,
            sizeof(NoTdi),
            &NoTdi,
            0,
            NULL,
            NULL,
            NULL);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskControlClient WSK_TDI_BEHAVIOR");
        // We don't "goto Error;" here, because MSDN says that this may be removed
        // in the future, at which point it presumably won't be needed.
    }

    CxPlatRwLockInitialize(&Pool->Lock);

    Success = TRUE;
    goto Exit;

Error:
    if (WskRegistered) {
        WskDeregister(&RawSocketGlobal.WskRegistration);
    }
    if (HashTableInitialized) {
        CxPlatHashtableUninitialize(&Pool->Sockets);
    }

Exit:
    return Success;
    */
}

void
CxPlatSockPoolUninitialize(
    _Inout_ CXPLAT_SOCKET_POOL* Pool
    )
{
    CxPlatHashtableUninitialize(&Pool->Sockets);
    CxPlatRwLockUninitialize(&Pool->Lock);
    /*
    WskDeregister(&RawSocketGlobal.WskRegistration);
    */
}

void
CxPlatRemoveSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CxPlatRwLockAcquireExclusive(&Pool->Lock);
    CxPlatHashtableRemove(&Pool->Sockets, &Socket->Entry, NULL);
    CxPlatRwLockReleaseExclusive(&Pool->Lock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawResolveRoute(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_ uint8_t PathId,
    _In_ void* Context,
    _In_ CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    NTSTATUS NtStatus = STATUS_SUCCESS;
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
    NtStatus =
        GetBestRoute2(
            NULL, // InterfaceLuid
            IFI_UNSPECIFIED, // InterfaceIndex
            &Route->LocalAddress, // SourceAddress
            &Route->RemoteAddress, // DestinationAddress
            0, // AddressSortOptions
            &IpforwardRow,
            &LocalAddress); // BestSourceAddress

    if (NtStatus != STATUS_SUCCESS) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            NtStatus,
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
        Status = QUIC_STATUS_INVALID_STATE;
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
    CXPLAT_LIST_ENTRY* Entry = Socket->RawDatapath->Interfaces.Flink;
    for (; Entry != &Socket->RawDatapath->Interfaces; Entry = Entry->Flink) {
        CXPLAT_INTERFACE* Interface = CONTAINING_RECORD(Entry, CXPLAT_INTERFACE, Link);
        if (Interface->IfIndex == IpforwardRow.InterfaceIndex) {
            CXPLAT_DBG_ASSERT(sizeof(Interface->PhysicalAddress) == sizeof(Route->LocalLinkLayerAddress));
            CxPlatCopyMemory(&Route->LocalLinkLayerAddress, Interface->PhysicalAddress, sizeof(Route->LocalLinkLayerAddress));
            CxPlatDpRawAssignQueue(Interface, Route);
            break;
        }
    }

    if (Route->Queue == NULL) {
        Status = QUIC_STATUS_NOT_FOUND;
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
    NtStatus = GetIpNetEntry2(&IpnetRow);
    QuicTraceLogConnInfo(
        RouteResolutionStart,
        Context,
        "Starting to look up neighbor on Path[%hhu] with status %u",
        PathId,
        NtStatus);
    //
    // We need to force neighbor solicitation (NS) if any of the following is true:
    // 1. No cached neighbor entry for the given destination address.
    // 2. The neighbor entry isn't in a usable state.
    // 3. When we are re-resolving a suspected route, the neighbor entry is the same as the existing one.
    //
    // We queue an operation on the route worker for NS because it involves network IO and
    // we don't want our connection worker queue blocked.
    //
    if ((NtStatus != STATUS_SUCCESS || IpnetRow.State <= NlnsIncomplete) ||
        (State == RouteSuspected &&
         memcmp(
             Route->NextHopLinkLayerAddress,
             IpnetRow.PhysicalAddress,
             sizeof(Route->NextHopLinkLayerAddress)) == 0)) {
        CXPLAT_ROUTE_RESOLUTION_WORKER* Worker = Socket->RawDatapath->RouteResolutionWorker;
        CXPLAT_ROUTE_RESOLUTION_OPERATION* Operation = CxPlatPoolAlloc(&Worker->OperationPool);
        if (Operation == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_DATAPATH",
                sizeof(CXPLAT_ROUTE_RESOLUTION_OPERATION));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
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
        Status = QUIC_STATUS_PENDING;
    } else {
        CxPlatResolveRouteComplete(Context, Route, IpnetRow.PhysicalAddress, PathId);
        Status = QUIC_STATUS_SUCCESS;
    }

Done:
    if (Status != QUIC_STATUS_PENDING && Status != QUIC_STATUS_SUCCESS) {
        Callback(Context, NULL, PathId, FALSE);
    }

    if (Status == QUIC_STATUS_PENDING) {
        return QUIC_STATUS_PENDING;
    } else {
        return Status;
    }
}

QUIC_STATUS
CxPlatTryAddSocket(
    _In_ CXPLAT_SOCKET_POOL* Pool,
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
    CXPLAT_HASHTABLE_ENTRY* Entry;

    CxPlatRwLockAcquireExclusive(&Pool->Lock);

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

    return Status;
}
