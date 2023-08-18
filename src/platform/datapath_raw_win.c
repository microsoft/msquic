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
    _Inout_  CXPLAT_DATAPATH_RAW* DataPath
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
CxPlatInitRawDataPath(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _In_opt_ const CXPLAT_DATAPATH* ParentDataPath,
    _Out_  CXPLAT_DATAPATH_RAW* DataPath
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    // const size_t DatapathSize = CxPlatDpRawGetDatapathSize(Config);
    BOOLEAN DpRawInitialized = FALSE;
    BOOLEAN SockPoolInitialized = FALSE;
    // CXPLAT_FRE_ASSERT(DatapathSize > sizeof(CXPLAT_DATAPATH));

    if (DataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    CXPLAT_FRE_ASSERT(CxPlatRundownAcquire(&CxPlatWorkerRundown));

    if (Config && (Config->Flags & QUIC_EXECUTION_CONFIG_FLAG_QTIP)) {
        DataPath->UseTcp = TRUE;
    }

    if (!CxPlatSockPoolInitialize(&DataPath->SocketPool)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    SockPoolInitialized = TRUE;

    Status = CxPlatDpRawInitialize(DataPath, ClientRecvContextLength, Config);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    DpRawInitialized = TRUE;

    Status = CxPlatDataPathRouteWorkerInitialize(DataPath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    DataPath->ParentDataPath = ParentDataPath;

Error:

    if (QUIC_FAILED(Status)) {
#if DEBUG
        DataPath->Uninitialized = TRUE;
#endif
        if (DpRawInitialized) {
            CxPlatDpRawUninitialize(DataPath);
        } else {
            if (SockPoolInitialized) {
                CxPlatSockPoolUninitialize(&DataPath->SocketPool);
            }
            // CXPLAT_FREE(DataPath, QUIC_POOL_DATAPATH);
            CxPlatRundownRelease(&CxPlatWorkerRundown);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MANGLE(CxPlatDataPathUninitialize)(
    _In_  CXPLAT_DATAPATH_RAW* Datapath
    )
{
    if (Datapath != NULL) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Datapath->Freed);
        CXPLAT_DBG_ASSERT(!Datapath->Uninitialized);
        Datapath->Uninitialized = TRUE;
#endif
        CxPlatDataPathRouteWorkerUninitialize(Datapath->RouteResolutionWorker);
        CxPlatDpRawUninitialize(Datapath);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitializeComplete(
    _In_  CXPLAT_DATAPATH_RAW* Datapath
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!Datapath->Freed);
    CXPLAT_DBG_ASSERT(Datapath->Uninitialized);
    Datapath->Freed = TRUE;
#endif
    CxPlatSockPoolUninitialize(&Datapath->SocketPool);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
    CxPlatRundownRelease(&CxPlatWorkerRundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MANGLE(CxPlatDataPathUpdateConfig)(
    _In_  CXPLAT_DATAPATH_RAW* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    CxPlatDpRawUpdateConfig(Datapath, Config);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
MANGLE(CxPlatDataPathGetSupportedFeatures)(
    _In_  CXPLAT_DATAPATH_RAW* Datapath
    )
{
    return CXPLAT_DATAPATH_FEATURE_RAW;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MANGLE(CxPlatDataPathIsPaddingPreferred)(
    _In_  CXPLAT_DATAPATH* Datapath
    )
{
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
MANGLE(CxPlatDataPathGetLocalAddresses)(
    _In_  CXPLAT_DATAPATH* Datapath,
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
MANGLE(CxPlatDataPathGetGatewayAddresses)(
    _In_  CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

// void
// CxPlatDataPathPopulateTargetAddress(
//     _In_ ADDRESS_FAMILY Family,
//     _In_ ADDRINFOW *Ai,
//     _Out_ SOCKADDR_INET* Address
//     )
// {
//     if (Ai->ai_addr->sa_family == QUIC_ADDRESS_FAMILY_INET6) {
//         //
//         // Is this a mapped ipv4 one?
//         //
//         PSOCKADDR_IN6 SockAddr6 = (PSOCKADDR_IN6)Ai->ai_addr;

//         if (Family == QUIC_ADDRESS_FAMILY_UNSPEC && IN6ADDR_ISV4MAPPED(SockAddr6))
//         {
//             PSOCKADDR_IN SockAddr4 = &Address->Ipv4;
//             //
//             // Get the ipv4 address from the mapped address.
//             //
//             SockAddr4->sin_family = QUIC_ADDRESS_FAMILY_INET;
//             SockAddr4->sin_addr =
//                 *(IN_ADDR UNALIGNED *)
//                     IN6_GET_ADDR_V4MAPPED(&SockAddr6->sin6_addr);
//             SockAddr4->sin_port = SockAddr6->sin6_port;
//             return;
//         }
//     }

//     CxPlatCopyMemory(Address, Ai->ai_addr, Ai->ai_addrlen);
// }

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatInitRawSocket(
    _In_  CXPLAT_DATAPATH_RAW* Raw,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    // _Out_ CXPLAT_SOCKET_BASE** NewSocket
    _Out_ CXPLAT_SOCKET_RAW* Socket
    )
{
    // TODO: remove Socket->Remote/LocalAddress. Use (*NewSocket)->Remote/LocalAddress instead.
    #pragma warning(push)
    #pragma warning(disable:6001) // Using uninitialized memory
    CXPLAT_DBG_ASSERT(Socket != NULL);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    // CxPlatZeroMemory(Socket, sizeof(CXPLAT_SOCKET_RAW));
    CxPlatRundownInitialize(&Socket->Rundown);
    Socket->RawDatapath = Raw;
    Socket->CallbackContext = Config->CallbackContext;
    Socket->CibirIdLength = Config->CibirIdLength;
    Socket->CibirIdOffsetSrc = Config->CibirIdOffsetSrc;
    Socket->CibirIdOffsetDst = Config->CibirIdOffsetDst;
    Socket->UseTcp = Raw->UseTcp;
    if (Config->CibirIdLength) {
        memcpy(Socket->CibirId, Config->CibirId, Config->CibirIdLength);
    }

    // TODO: remove Socket address settings
    if (Config->RemoteAddress) {
        CXPLAT_FRE_ASSERT(!QuicAddrIsWildCard(Config->RemoteAddress));  // No wildcard remote addresses allowed.
        Socket->Connected = TRUE;
    }

    if (Config->LocalAddress) {
        if (QuicAddrIsWildCard(Config->LocalAddress)) {
            if (!Socket->Connected) {
                Socket->Wildcard = TRUE;
            }
        } else if (!Socket->Connected) {
            // Assumes only connected sockets fully specify local address
            Status = QUIC_STATUS_INVALID_STATE;
            goto Error;
        }
    } else {
        if (!Socket->Connected) {
            Socket->Wildcard = TRUE;
        }
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
            CxPlatRundownUninitialize(&Socket->Rundown);
            CxPlatZeroMemory(Socket, sizeof(CXPLAT_SOCKET_RAW) - sizeof(CXPLAT_SOCKET));
            Socket = NULL;
        }
    }
    #pragma warning(pop)

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MANGLE(CxPlatSocketCreateTcp)(
    _In_  CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET_RAW** Socket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MANGLE(CxPlatSocketCreateTcpListener)(
    _In_  CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET_RAW** NewSocket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatRawSocketDelete(
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    if (!Socket->RawDatapath) {
        // Raw socket was not initialized.
        return;
    }
    CxPlatDpRawPlumbRulesOnSocket(Socket, FALSE);
    CxPlatRemoveSocket(&Socket->RawDatapath->SocketPool, Socket);
    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    if (Socket->PausedTcpSend) {
        CxPlatDpRawTxFree(Socket->PausedTcpSend);
    }

    if (Socket->CachedRstSend) {
        CxPlatDpRawTxEnqueue(Socket->CachedRstSend);
    }

    // CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MANGLE(CxPlatSocketDelete)(
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CxPlatDpRawPlumbRulesOnSocket(Socket, FALSE);
    CxPlatRemoveSocket(&Socket->RawDatapath->SocketPool, Socket);
    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    if (Socket->PausedTcpSend) {
        CxPlatDpRawTxFree(Socket->PausedTcpSend);
    }

    if (Socket->CachedRstSend) {
        CxPlatDpRawTxEnqueue(Socket->CachedRstSend);
    }

    CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
MANGLE(CxPlatSocketGetLocalMtu)(
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    if (Socket->UseTcp) {
        return 1488; // Reserve space for TCP header.
    } else {
        return 1500;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxEthernet(
    _In_ const  CXPLAT_DATAPATH_RAW* Datapath,
    _In_reads_(PacketCount)
        CXPLAT_RECV_DATA** Packets,
    _In_ uint16_t PacketCount
    )
{
    for (uint16_t i = 0; i < PacketCount; i++) {
        CXPLAT_SOCKET_RAW* Socket = NULL;
        CXPLAT_RECV_DATA* PacketChain = Packets[i];
        CXPLAT_DBG_ASSERT(PacketChain->Next == NULL);

        if (PacketChain->Reserved >= L4_TYPE_UDP) {
            Socket =
                CxPlatGetSocket(
                    &Datapath->SocketPool,
                    &PacketChain->Route->LocalAddress,
                    &PacketChain->Route->RemoteAddress);
        }

        if (Socket) {
            if (PacketChain->Reserved == L4_TYPE_UDP || PacketChain->Reserved == L4_TYPE_TCP) {
                uint8_t SocketType = Socket->UseTcp ? L4_TYPE_TCP : L4_TYPE_UDP;

                //
                // Found a match. Chain and deliver contiguous packets with the same 4-tuple.
                //
                while (i < PacketCount) {
                    QuicTraceEvent(
                        DatapathRecv,
                        "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
                        Socket,
                        Packets[i]->BufferLength,
                        Packets[i]->BufferLength,
                        CASTED_CLOG_BYTEARRAY(sizeof(Packets[i]->Route->LocalAddress), &Packets[i]->Route->LocalAddress),
                        CASTED_CLOG_BYTEARRAY(sizeof(Packets[i]->Route->RemoteAddress), &Packets[i]->Route->RemoteAddress));
                    if (i == PacketCount - 1 ||
                        Packets[i+1]->Reserved != SocketType ||
                        Packets[i+1]->Route->LocalAddress.Ipv4.sin_port != Socket->LocalAddress.Ipv4.sin_port ||
                        !CxPlatSocketCompare(Socket, &Packets[i+1]->Route->LocalAddress, &Packets[i+1]->Route->RemoteAddress)) {
                        break;
                    }
                    Packets[i]->Next = Packets[i+1];
                    CXPLAT_DBG_ASSERT(Packets[i+1]->Next == NULL);
                    i++;
                }
                Datapath->ParentDataPath->UdpHandlers.Receive(CxPlatRawToSocket(Socket), Socket->CallbackContext, (CXPLAT_RECV_DATA*)PacketChain);
            } else if (PacketChain->Reserved == L4_TYPE_TCP_SYN || PacketChain->Reserved == L4_TYPE_TCP_SYNACK) {
                CxPlatDpRawSocketAckSyn(Socket, PacketChain);
                CxPlatDpRawRxFree(PacketChain);
            } else if (PacketChain->Reserved == L4_TYPE_TCP_FIN) {
                CxPlatDpRawSocketAckFin(Socket, PacketChain);
                CxPlatDpRawRxFree(PacketChain);
            } else {
                CxPlatDpRawRxFree(PacketChain);
            }

            CxPlatRundownRelease(&Socket->Rundown);
        } else {
            CxPlatDpRawRxFree(PacketChain);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
MANGLE(CxPlatRecvDataReturn)(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatDpRawRxFree((const CXPLAT_RECV_DATA*)RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
MANGLE(CxPlatSendDataAlloc)(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    return CxPlatDpRawTxAlloc(Socket, Config);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
MANGLE(CxPlatSendDataAllocBuffer)(
    _In_ CXPLAT_SEND_DATA_INTERNAL* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    SendData->Buffer.Length = MaxBufferLength;
    return &SendData->Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
MANGLE(CxPlatSendDataFree)(
    _In_ CXPLAT_SEND_DATA_INTERNAL* SendData
    )
{
    CxPlatDpRawTxFree(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
MANGLE(CxPlatSendDataFreeBuffer)(
    _In_ CXPLAT_SEND_DATA_INTERNAL* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    // No-op
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
MANGLE(CxPlatSendDataIsFull)(
    _In_ CXPLAT_SEND_DATA_INTERNAL* SendData
    )
{
    return TRUE;
}

#define TH_ACK 0x10

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
MANGLE(CxPlatSocketSend)(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA_INTERNAL* SendData
    )
{
    if (Socket->UseTcp &&
        Socket->Connected &&
        Route->TcpState.Syncd == FALSE) {
        Socket->PausedTcpSend = SendData;
        CxPlatDpRawSocketSyn(Socket, Route);
        return QUIC_STATUS_SUCCESS;
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
    CXPLAT_DBG_ASSERT(Route->State == RouteResolved);
    CXPLAT_DBG_ASSERT(Route->Queue != NULL);
    const CXPLAT_INTERFACE* Interface = CxPlatDpRawGetInterfaceFromQueue(Route->Queue);

    CxPlatFramingWriteHeaders(
        Socket, Route, &SendData->Buffer, SendData->ECN,
        Interface->OffloadStatus.Transmit.NetworkLayerXsum,
        Interface->OffloadStatus.Transmit.TransportLayerXsum,
        Route->TcpState.SequenceNumber,
        Route->TcpState.AckNumber,
        TH_ACK);
    CxPlatDpRawTxEnqueue(SendData);
    return QUIC_STATUS_SUCCESS;
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

            CxPlatPoolFree(&Worker->OperationPool, Operation);
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

CXPLAT_RECV_DATA*
MANGLE(CxPlatDataPathRecvPacketToRecvData)(
    _In_ const CXPLAT_RECV_PACKET* const RecvPacket
    );

CXPLAT_RECV_PACKET*
MANGLE(CxPlatDataPathRecvDataToRecvPacket)(
    _In_ const CXPLAT_RECV_DATA* const RecvData
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MANGLE(CxPlatSocketUpdateQeo)(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    );

void
MANGLE(CxPlatDataPathProcessCqe)(
    _In_ CXPLAT_CQE* Cqe
    );
