/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Raw (i.e. DPDK or XDP) Datapath Implementation (User Mode)

--*/

#include "datapath_raw_win.h"
#ifdef QUIC_CLOG
#include "datapath_raw_win.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

CXPLAT_THREAD_CALLBACK(CxPlatRouteResolutionWorkerThread, Context);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRouteWorkerUninitialize(
    _In_ CXPLAT_ROUTE_RESOLUTION_WORKER* Worker
    )
{
    Worker->Enabled = FALSE;
    CxPlatEventSet(Worker->Ready);

    //
    // Wait for the thread to finish.
    //
    if (Worker->Thread) {
        CxPlatThreadWait(&Worker->Thread);
        CxPlatThreadDelete(&Worker->Thread);
    }

    CxPlatEventUninitialize(Worker->Ready);
    CxPlatDispatchLockUninitialize(&Worker->Lock);
    CxPlatPoolUninitialize(&Worker->OperationPool);
    CXPLAT_FREE(Worker, QUIC_POOL_ROUTE_RESOLUTION_WORKER);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathRouteWorkerInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* DataPath
    )
{
    QUIC_STATUS Status;
    CXPLAT_ROUTE_RESOLUTION_WORKER* Worker =
        CXPLAT_ALLOC_NONPAGED(
            sizeof(CXPLAT_ROUTE_RESOLUTION_WORKER), QUIC_POOL_ROUTE_RESOLUTION_WORKER);
    if (Worker == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(CXPLAT_ROUTE_RESOLUTION_WORKER));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Worker->Enabled = TRUE;
    CxPlatEventInitialize(&Worker->Ready, FALSE, FALSE);
    CxPlatDispatchLockInitialize(&Worker->Lock);
    CxPlatListInitializeHead(&Worker->Operations);

    CxPlatPoolInitialize(
        FALSE,
        sizeof(CXPLAT_ROUTE_RESOLUTION_OPERATION),
        QUIC_POOL_ROUTE_RESOLUTION_OPER,
        &Worker->OperationPool);

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        CXPLAT_THREAD_FLAG_NONE,
        0,
        "RouteResolutionWorkerThread",
        CxPlatRouteResolutionWorkerThread,
        Worker
    };

    Status = CxPlatThreadCreate(&ThreadConfig, &Worker->Thread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }

    DataPath->RouteResolutionWorker = Worker;

Error:
    if (QUIC_FAILED(Status)) {
        if (Worker != NULL) {
            CxPlatDataPathRouteWorkerUninitialize(Worker);
        }
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketCreateUdp(
    _In_ CXPLAT_DATAPATH_RAW* Raw,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Inout_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatRundownInitialize(&Socket->RawRundown);
    Socket->RawDatapath = Raw;
    Socket->CibirIdLength = Config->CibirIdLength;
    Socket->CibirIdOffsetSrc = Config->CibirIdOffsetSrc;
    Socket->CibirIdOffsetDst = Config->CibirIdOffsetDst;
    Socket->AuxSocket = INVALID_SOCKET;
    if (Config->CibirIdLength) {
        memcpy(Socket->CibirId, Config->CibirId, Config->CibirIdLength);
    }

    //
    // Key assumptions by MsQuic core code:
    //      - A non-NULL remote address specified by the config means this Cxplat socket MUST be part of a client connection.
    //      - A remote address MUST not be a wildcard address.
    //      - A client connection either passes down a NULL local address, or a SPECIFIC ip/port local address.
    //      - A server listener MUST specify a wildcard local address AND a NULL remote address.
    //

    if (Config->RemoteAddress) {
        //
        // This CxPlatSocket is part of a client connection.
        //
        CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(Config->RemoteAddress));  // No wildcard remote addresses allowed.
        if (Socket->ReserveAuxTcpSock) {
            //
            // TODO: Not sure what's special about QTIP. We always set Socket->RemoteAddress in SocketCreateUdp()
            //       earlier and why don't we always set Socket->LocalAddress if LocalAddress is specified
            //       regardless of if we're using QTIP or not? Also if LocalAddress was not specified why do we
            //       need to set Socket->LocalAddress to IPv6 if we're using QTIP?
            //
            Socket->RemoteAddress = *Config->RemoteAddress;
            if (Config->LocalAddress != NULL) {
                CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(Config->LocalAddress));
                Socket->LocalAddress = *Config->LocalAddress;
            } else {
                QuicAddrSetFamily(&Socket->LocalAddress, QUIC_ADDRESS_FAMILY_INET6);
            }
        }
        Socket->Connected = TRUE;
    } else {
        //
        // This CxPlatSocket is part of a server listener.
        //
        CXPLAT_FRE_ASSERT(Config->LocalAddress != NULL);
        if (!QuicAddrIsWildCard(Config->LocalAddress)) {
            Status = QUIC_STATUS_INVALID_STATE;
            goto Error;
        }
        Socket->Wildcard = TRUE;
    }

    CXPLAT_FRE_ASSERT(Socket->Wildcard ^ Socket->Connected); // Assumes either a pure wildcard listener or a
                                                                         // connected socket; not both.

    Status = CxPlatTryAddSocket(&Raw->SocketPool, Socket);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatDpRawPlumbRulesOnSocket(Socket, TRUE);

Error:

    if (QUIC_FAILED(Status)) {
        if (Socket != NULL) {
            CxPlatRundownUninitialize(&Socket->RawRundown);
            CxPlatZeroMemory(Socket, sizeof(CXPLAT_SOCKET_RAW) - sizeof(CXPLAT_SOCKET));
            Socket = NULL;
        }
    }

    return Status;
}

CXPLAT_THREAD_CALLBACK(CxPlatRouteResolutionWorkerThread, Context)
{
    CXPLAT_ROUTE_RESOLUTION_WORKER* Worker = (CXPLAT_ROUTE_RESOLUTION_WORKER*)Context;

    while (Worker->Enabled) {
        CxPlatEventWaitForever(Worker->Ready);
        CXPLAT_LIST_ENTRY Operations;
        CxPlatListInitializeHead(&Operations);

        CxPlatDispatchLockAcquire(&Worker->Lock);
        if (!CxPlatListIsEmpty(&Worker->Operations)) {
            CxPlatListMoveItems(&Worker->Operations, &Operations);
        }
        CxPlatDispatchLockRelease(&Worker->Lock);

        while (!CxPlatListIsEmpty(&Operations)) {
            CXPLAT_ROUTE_RESOLUTION_OPERATION* Operation =
                CXPLAT_CONTAINING_RECORD(
                    CxPlatListRemoveHead(&Operations), CXPLAT_ROUTE_RESOLUTION_OPERATION, WorkerLink);
            NETIO_STATUS Status =
            Status = GetIpNetEntry2(&Operation->IpnetRow);
            if (Status != ERROR_SUCCESS || Operation->IpnetRow.State <= NlnsIncomplete) {
                Status =
                    ResolveIpNetEntry2(&Operation->IpnetRow, NULL);
                if (Status != 0) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Operation,
                        Status,
                        "ResolveIpNetEntry2");
                    Operation->Callback(
                        Operation->Context, NULL, Operation->PathId, FALSE);
                } else {
                    Operation->Callback(
                        Operation->Context, Operation->IpnetRow.PhysicalAddress, Operation->PathId, TRUE);
                }
            } else {
                Operation->Callback(
                    Operation->Context, Operation->IpnetRow.PhysicalAddress, Operation->PathId, TRUE);
            }

            CxPlatPoolFree(Operation);
        }
    }

    //
    // Clean up leftover work.
    //
    CXPLAT_LIST_ENTRY Operations;
    CxPlatListInitializeHead(&Operations);

    CxPlatDispatchLockAcquire(&Worker->Lock);
    if (!CxPlatListIsEmpty(&Worker->Operations)) {
        CxPlatListMoveItems(&Worker->Operations, &Operations);
    }
    CxPlatDispatchLockRelease(&Worker->Lock);

    while (!CxPlatListIsEmpty(&Operations)) {
        CXPLAT_ROUTE_RESOLUTION_OPERATION* Operation =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Operations), CXPLAT_ROUTE_RESOLUTION_OPERATION, WorkerLink);
        Operation->Callback(Operation->Context, NULL, Operation->PathId, FALSE);
        CXPLAT_FREE(Operation, QUIC_POOL_ROUTE_RESOLUTION_OPER);
    }

    return 0;
}
