/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Raw (e.g., XDP) Datapath Implementation (User Mode)

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
    // The socket addresses have been set in the SocketCreateUdp call earlier,
    // either form the config or assigned by the OS (for unspecified ports).
    // Do no override them from the config here: we need to keep the same OS assigned ports if the
    // config doesn't specify them.
    //
    CXPLAT_DBG_ASSERT(
        Config->RemoteAddress == NULL ||
        QuicAddrCompare(&Socket->RemoteAddress, Config->RemoteAddress));
    CXPLAT_DBG_ASSERT(
        Config->LocalAddress == NULL ||
        QuicAddrGetPort(Config->LocalAddress) == 0 ||
        QuicAddrGetPort(&Socket->LocalAddress) == QuicAddrGetPort(Config->LocalAddress));

    if (Config->RemoteAddress) {
        //
        // This CxPlatSocket is part of a client connection.
        //
        CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(Config->RemoteAddress));  // No wildcard remote addresses allowed.

        Socket->Connected = TRUE;
    } else {
        //
        // This CxPlatSocket is part of a server listener.
        //
        CXPLAT_FRE_ASSERT(Config->LocalAddress != NULL);

        if (!QuicAddrIsWildCard(Config->LocalAddress)) { // For server listeners, the local address MUST be a wildcard address.
            Status = QUIC_STATUS_INVALID_STATE;
            goto Error;
        }
        Socket->Wildcard = TRUE;
    }

    //
    // Note here that the socket COULD have local address be a wildcard AND Socket->Wildcard == FALSE.
    // Socket->Wildcard is TRUE if and only if the socket is part of a server listener (which implies it has a wildcard local address).
    //

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
