/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Raw (i.e. DPDK or XDP) Datapath Implementation (User Mode)

--*/

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter


_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_DATAPATH* ParentDataPath,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Outptr_result_maybenull_ CXPLAT_DATAPATH_RAW** NewDataPath
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const size_t DatapathSize = CxPlatDpRawGetDatapathSize(WorkerPool);
    BOOLEAN DpRawInitialized = FALSE;
    BOOLEAN SockPoolInitialized = FALSE;

    *NewDataPath = NULL;

    CXPLAT_DATAPATH_RAW* DataPath = CXPLAT_ALLOC_PAGED(DatapathSize, QUIC_POOL_DATAPATH);
    if (DataPath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathSize);
        return;
    }
    CxPlatZeroMemory(DataPath, DatapathSize);
    CXPLAT_FRE_ASSERT(CxPlatWorkerPoolAddRef(WorkerPool));

    DataPath->WorkerPool = WorkerPool;

    if (!CxPlatSockPoolInitialize(&DataPath->SocketPool)) {
        goto Error;
    }
    SockPoolInitialized = TRUE;

    Status = CxPlatDpRawInitialize(DataPath, ClientRecvContextLength, WorkerPool);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }
    DpRawInitialized = TRUE;

    Status = CxPlatDataPathRouteWorkerInitialize(DataPath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    *NewDataPath = DataPath;
    DataPath->ParentDataPath = ParentDataPath;
    DataPath = NULL;

Error:

    if (DataPath != NULL) {
#if DEBUG
        DataPath->Uninitialized = TRUE;
#endif
        if (DpRawInitialized) {
            CxPlatDpRawUninitialize(DataPath);
        } else {
            if (SockPoolInitialized) {
                CxPlatSockPoolUninitialize(&DataPath->SocketPool);
            }
            CXPLAT_FREE(DataPath, QUIC_POOL_DATAPATH);
            CxPlatWorkerPoolRelease(WorkerPool);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
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
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!Datapath->Freed);
    CXPLAT_DBG_ASSERT(Datapath->Uninitialized);
    Datapath->Freed = TRUE;
#endif
    CxPlatSockPoolUninitialize(&Datapath->SocketPool);
    CxPlatWorkerPoolRelease(Datapath->WorkerPool);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawDataPathUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    )
{
    CxPlatDpRawUpdatePollingIdleTimeout(Datapath, PollingIdleTimeoutUs);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_FEATURES
RawDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return CXPLAT_DATAPATH_FEATURE_RAW | CXPLAT_DATAPATH_FEATURE_TTL | CXPLAT_DATAPATH_FEATURE_SEND_DSCP;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RawDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
RawSocketDelete(
    _In_ CXPLAT_SOCKET_RAW* Socket
    )
{
    CxPlatDpRawPlumbRulesOnSocket(Socket, FALSE);
    CxPlatRemoveSocket(&Socket->RawDatapath->SocketPool, Socket);
    CxPlatRundownReleaseAndWait(&Socket->RawRundown);
    if (Socket->PausedTcpSend) {
        CxPlatDpRawTxFree(Socket->PausedTcpSend);
    }

    if (Socket->CachedRstSend) {
        CxPlatDpRawTxEnqueue(Socket->CachedRstSend);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
RawSocketGetLocalMtu(
    _In_ CXPLAT_ROUTE* Route
    )
{
    // Reserve space for TCP header.
    return Route->UseQTIP ? 1488 : 1500;

}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxEthernet(
    _In_ const CXPLAT_DATAPATH_RAW* Datapath,
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
            CXPLAT_DBG_ASSERT(!Socket->HasFixedRemoteAddress || Socket->ReserveAuxTcpSock == PacketChain->Route->UseQTIP);
            if (PacketChain->Reserved == L4_TYPE_UDP || PacketChain->Reserved == L4_TYPE_TCP) {
                uint8_t SocketType = PacketChain->Route->UseQTIP ? L4_TYPE_TCP : L4_TYPE_UDP;
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
                Datapath->ParentDataPath->UdpHandlers.Receive(CxPlatRawToSocket(Socket), Socket->ClientContext, PacketChain);
            } else if (PacketChain->Reserved == L4_TYPE_TCP_SYN || PacketChain->Reserved == L4_TYPE_TCP_SYNACK) {
                CxPlatDpRawSocketAckSyn(Socket, PacketChain);
                CxPlatDpRawRxFree(PacketChain);
            } else if (PacketChain->Reserved == L4_TYPE_TCP_FIN) {
                CxPlatDpRawSocketAckFin(Socket, PacketChain);
                CxPlatDpRawRxFree(PacketChain);
            } else {
                CxPlatDpRawRxFree(PacketChain);
            }

            CxPlatRundownRelease(&Socket->RawRundown);
        } else {
            CxPlatDpRawRxFree(PacketChain);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawRecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CxPlatDpRawRxFree((const CXPLAT_RECV_DATA*)RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
RawSendDataAlloc(
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    return CxPlatDpRawTxAlloc(Config);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
RawSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    SendData->Buffer.Length = MaxBufferLength;
    return &SendData->Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatDpRawTxFree(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RawSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    UNREFERENCED_PARAMETER(SendData);
    UNREFERENCED_PARAMETER(Buffer);
    // No-op
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RawSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
    return TRUE;
}

#define TH_ACK 0x10

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
RawSocketSend(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(!Socket->HasFixedRemoteAddress || Route->UseQTIP == Socket->ReserveAuxTcpSock);
    if (Route->UseQTIP &&
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

    CxPlatFramingWriteHeaders(
        Socket, Route, SendData, &SendData->Buffer, SendData->ECN, SendData->DSCP,
        CxPlatDpRawIsL3TxXsumOffloadedOnQueue(Route->Queue),
        CxPlatDpRawIsL4TxXsumOffloadedOnQueue(Route->Queue),
        Route->TcpState.SequenceNumber,
        Route->TcpState.AckNumber,
        TH_ACK);
    CxPlatDpRawTxEnqueue(SendData);
    return QUIC_STATUS_SUCCESS;
}
