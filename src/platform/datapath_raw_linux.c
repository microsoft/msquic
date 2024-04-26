/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Raw (i.e. DPDK or XDP) Datapath Implementation (User Mode)

--*/

#include "datapath_raw_linux.h"
#ifdef QUIC_CLOG
#include "datapath_raw_linux.c.clog.h"
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
    _Inout_ CXPLAT_SOCKET_RAW* NewSocket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatRundownInitialize(&NewSocket->Rundown);
    NewSocket->RawDatapath = Raw;
    NewSocket->CibirIdLength = Config->CibirIdLength;
    NewSocket->CibirIdOffsetSrc = Config->CibirIdOffsetSrc;
    NewSocket->CibirIdOffsetDst = Config->CibirIdOffsetDst;
    NewSocket->AuxSocket = INVALID_SOCKET;
    NewSocket->UseTcp = Raw->UseTcp;
    if (Config->CibirIdLength) {
        memcpy(NewSocket->CibirId, Config->CibirId, Config->CibirIdLength);
    }

    if (Config->RemoteAddress) {
        CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(Config->RemoteAddress));  // No wildcard remote addresses allowed.
        if (NewSocket->UseTcp) {
            NewSocket->RemoteAddress = *Config->RemoteAddress;
        }
        NewSocket->Connected = TRUE;
    }

    if (Config->LocalAddress) {
        if (NewSocket->UseTcp) {
            NewSocket->LocalAddress = *Config->LocalAddress;
        }
        if (QuicAddrIsWildCard(Config->LocalAddress)) {
            if (!NewSocket->Connected) {
                NewSocket->Wildcard = TRUE;
            }
        } else if (!NewSocket->Connected) {
            // Assumes only connected sockets fully specify local address
            Status = QUIC_STATUS_INVALID_STATE;
            goto Error;
        }
    } else {
        if (NewSocket->UseTcp) {
            QuicAddrSetFamily(&NewSocket->LocalAddress, QUIC_ADDRESS_FAMILY_INET6);
        }
        if (!NewSocket->Connected) {
            NewSocket->Wildcard = TRUE;
        } else {
            int oif = -1;
            NewSocket->LocalAddress.Ip.sa_family = NewSocket->RemoteAddress.Ip.sa_family;
            ResolveBestL3Route(&NewSocket->RemoteAddress, &NewSocket->LocalAddress, NULL, &oif);
        }
    }

    CXPLAT_FRE_ASSERT(NewSocket->Wildcard ^ NewSocket->Connected); // Assumes either a pure wildcard listener or a
                                                                         // connected socket; not both.
    Status = CxPlatTryAddSocket(&Raw->SocketPool, NewSocket);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    CxPlatDpRawPlumbRulesOnSocket(NewSocket, TRUE);
Error:

    if (QUIC_FAILED(Status)) {
        if (NewSocket != NULL) {
            CxPlatRundownUninitialize(&NewSocket->Rundown);
            CxPlatZeroMemory(NewSocket, sizeof(CXPLAT_SOCKET_RAW) - sizeof(CXPLAT_SOCKET));
            NewSocket = NULL;
        }
    }

    return Status;
}

CXPLAT_THREAD_CALLBACK(CxPlatRouteResolutionWorkerThread, Context)
{
    UNREFERENCED_PARAMETER(Context);
    return 0;
}
