/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"

#ifdef QUIC_CLOG
#include "datapath_winuser.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses

#pragma warning(disable:4100) // unreferenced
#pragma warning(disable:6101) // uninitialized
#pragma warning(disable:6386) // buffer overrun

#define IS_LOOPBACK(Address) ((Address.si_family == QUIC_ADDRESS_FAMILY_INET &&                \
                               Address.Ipv4.sin_addr.S_un.S_addr == CxPlatByteSwapUint32(INADDR_LOOPBACK)) || \
                              (Address.si_family == QUIC_ADDRESS_FAMILY_INET6 &&               \
                               IN6_IS_ADDR_LOOPBACK(&Address.Ipv6.sin6_addr)))

#define DatapathType(SendData) ((CXPLAT_SEND_DATA_COMMON*)(SendData))->DatapathType

volatile DWORD EnableRawDatapath = 1;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Status =
        DataPathInitialize(
            ClientRecvContextLength,
            UdpCallbacks,
            TcpCallbacks,
            Config,
            NewDataPath);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogVerbose(
            DatapathInitFail,
            "[  dp] Failed to initialize datapath, status:%d", Status);
        goto Error;
    }

    if (EnableRawDatapath) {
        Status =
            RawDataPathInitialize(
                ClientRecvContextLength,
                Config,
                (*NewDataPath),
                &((*NewDataPath)->RawDataPath));
        if (QUIC_FAILED(Status)) {
            QuicTraceLogVerbose(
                RawDatapathInitFail,
                "[ raw] Failed to initialize raw datapath, status:%d", Status);
            Status = QUIC_STATUS_SUCCESS;
            (*NewDataPath)->RawDataPath = NULL;
        }
    } else {
        (*NewDataPath)->RawDataPath = NULL;
    }


Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath->RawDataPath) {
        RawDataPathUninitialize(Datapath->RawDataPath);
    }
    DataPathUninitialize(Datapath);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    DataPathUpdateConfig(Datapath, Config);
    if (Datapath->RawDataPath) {
        RawDataPathUpdateConfig(Datapath->RawDataPath, Config);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath->RawDataPath) {
        return DataPathGetSupportedFeatures(Datapath) |
               RawDataPathGetSupportedFeatures(Datapath->RawDataPath);
    }
    return DataPathGetSupportedFeatures(Datapath);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ?
            DataPathIsPaddingPreferred(Datapath) : RawDataPathIsPaddingPreferred(Datapath);
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

    Status =
        SocketCreateUdp(
            Datapath,
            Config,
            NewSocket);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogVerbose(
            SockCreateFail,
            "[sock] Failed to create socket, status:%d", Status);
        goto Error;
    }

    if (Datapath->RawDataPath) {
        Status =
            RawSocketCreateUdp(
                Datapath->RawDataPath,
                Config,
                CxPlatSocketToRaw(*NewSocket));
        (*NewSocket)->RawSocketAvailable = QUIC_SUCCEEDED(Status);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogVerbose(
                RawSockCreateFail,
                "[sock] Failed to create raw socket, status:%d", Status);
            if (Datapath->UseTcp) {
                CxPlatSocketDelete(*NewSocket);
                goto Error;
            }
            Status = QUIC_STATUS_SUCCESS;
        }
    }

Error:
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return SocketCreateTcp(
        Datapath,
        LocalAddress,
        RemoteAddress,
        CallbackContext,
        NewSocket);
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
    return SocketCreateTcpListener(
        Datapath,
        LocalAddress,
        RecvCallbackContext,
        NewSocket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (Socket->RawSocketAvailable) {
        RawSocketDelete(CxPlatSocketToRaw(Socket));
    }
    SocketDelete(Socket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketUpdateQeo(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    if (Socket->UseTcp || (Socket->RawSocketAvailable &&
        !IS_LOOPBACK(Offloads[0].Address))) {
        return RawSocketUpdateQeo(CxPlatSocketToRaw(Socket), Offloads, OffloadCount);
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    if (Socket->UseTcp || (Socket->RawSocketAvailable &&
        !IS_LOOPBACK(Socket->RemoteAddress))) {
        return RawSocketGetLocalMtu(CxPlatSocketToRaw(Socket));
    }
    return Socket->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    if (RecvDataChain == NULL) {
        return;
    }
    CXPLAT_DBG_ASSERT(
        RecvDataChain->DatapathType == CXPLAT_DATAPATH_TYPE_USER ||
        RecvDataChain->DatapathType == CXPLAT_DATAPATH_TYPE_RAW);
    RecvDataChain->DatapathType == CXPLAT_DATAPATH_TYPE_USER ?
        RecvDataReturn(RecvDataChain) : RawRecvDataReturn(RecvDataChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    CXPLAT_SEND_DATA* SendData = NULL;
    // TODO: fallback?
    if (Socket->UseTcp || Config->Route->DatapathType == CXPLAT_DATAPATH_TYPE_RAW ||
        (Config->Route->DatapathType == CXPLAT_DATAPATH_TYPE_UNKNOWN &&
        Socket->RawSocketAvailable && !IS_LOOPBACK(Config->Route->RemoteAddress))) {
        SendData = RawSendDataAlloc(CxPlatSocketToRaw(Socket), Config);
    } else {
        SendData = SendDataAlloc(Socket, Config);
    }
    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ?
    SendDataFree(SendData) : RawSendDataFree(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ?
        SendDataAllocBuffer(SendData, MaxBufferLength) : RawSendDataAllocBuffer(SendData, MaxBufferLength);        
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ?
    SendDataFreeBuffer(SendData, Buffer) : RawSendDataFreeBuffer(SendData, Buffer);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ?
        SendDataIsFull(SendData) : RawSendDataIsFull(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_USER ?
        SocketSend(Socket, Route, SendData) : RawSocketSend(CxPlatSocketToRaw(Socket), Route, SendData);
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        DATAPATH_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_IO_SQE, DatapathSqe);
        if (Sqe->IoType == DATAPATH_XDP_IO_RECV || Sqe->IoType == DATAPATH_XDP_IO_SEND) {
            // if (Sqe->IoType == DATAPATH_XDP_IO_RECV) {
            //     QuicTraceLogInfo(
            //         LogInfo,
            //         "[ xdp] INFO, Dequeueing RX IO.");
            // } else {
            //     QuicTraceLogInfo(
            //         LogInfo,
            //         "[ xdp] INFO, Dequeueing TX IO.");
            // }
            RawDataPathProcessCqe(Cqe);
        } else {
            DataPathProcessCqe(Cqe);
        }
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        // QuicTraceLogInfo(
        //     LogInfo,
        //     "[ xdp] INFO, Dequeueing socket shutdown.");
        RawDataPathProcessCqe(Cqe);
        break;
    }
    default: CXPLAT_DBG_ASSERT(FALSE); break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCopyRouteInfo(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_RAW) {
        CxPlatCopyMemory(DstRoute, SrcRoute, (uint8_t*)&SrcRoute->State - (uint8_t*)SrcRoute);
        CxPlatUpdateRoute(DstRoute, SrcRoute);
    } else if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_USER) {
        *DstRoute = *SrcRoute;
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
}

void
CxPlatResolveRouteComplete(
    _In_ void* Connection,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    )
{
    CXPLAT_DBG_ASSERT(Route->DatapathType != CXPLAT_DATAPATH_TYPE_USER);
    if (Route->State != RouteResolved) {
        RawResolveRouteComplete(Connection, Route, PhysicalAddress, PathId);
    }
}

//
// Tries to resolve route and neighbor for the given destination address.
//
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
    if (Socket->UseTcp || Route->DatapathType == CXPLAT_DATAPATH_TYPE_RAW ||
        (Route->DatapathType == CXPLAT_DATAPATH_TYPE_UNKNOWN &&
        Socket->RawSocketAvailable && !IS_LOOPBACK(Route->RemoteAddress))) {
        return RawResolveRoute(CxPlatSocketToRaw(Socket), Route, PathId, Context, Callback);
    }
    Route->State = RouteResolved;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUpdateRoute(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_RAW) {
        RawUpdateRoute(DstRoute, SrcRoute);
    }
    if (DstRoute->DatapathType != SrcRoute->DatapathType ||
        (DstRoute->State == RouteResolved &&
         DstRoute->Queue != SrcRoute->Queue)) {
        DstRoute->Queue = SrcRoute->Queue;
        DstRoute->DatapathType = SrcRoute->DatapathType;
    }
}

void
CxPlatDatapathSqeInitialize(
    _Out_ DATAPATH_SQE* DatapathSqe,
    _In_ uint32_t CqeType
    )
{
    RtlZeroMemory(DatapathSqe, sizeof(*DatapathSqe));
    DatapathSqe->CqeType = CqeType;
    DatapathSqe->Sqe.UserData = DatapathSqe;
}
