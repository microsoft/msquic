/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"

#ifdef QUIC_CLOG
#include "datapath_xplat.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ CXPLAT_DATAPATH_INIT_CONFIG* InitConfig,
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
            WorkerPool,
            InitConfig,
            NewDataPath);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogVerbose(
            DatapathInitFail,
            "[  dp] Failed to initialize datapath, status:%d", Status);
        goto Error;
    }

    //
    // Best effort try to initialize the raw datapath.
    //
    RawDataPathInitialize(
        ClientRecvContextLength,
        *NewDataPath,
        WorkerPool,
        &((*NewDataPath)->RawDataPath));

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
CxPlatDataPathUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    )
{
    DataPathUpdatePollingIdleTimeout(Datapath, PollingIdleTimeoutUs);
    if (Datapath->RawDataPath) {
        RawDataPathUpdatePollingIdleTimeout(
            Datapath->RawDataPath, PollingIdleTimeoutUs);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_FEATURES
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_FLAGS SocketFlags
    )
{
    if (Datapath->RawDataPath && (SocketFlags & CXPLAT_SOCKET_FLAG_XDP)) {
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
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ?
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
    BOOLEAN CreateRaw = Config->Flags & CXPLAT_SOCKET_FLAG_XDP;

    //
    // In a real production (XDP/QTIP+XDP) scenario, we never have to loop more than once
    // because server admins will ensure whatever port they are binding to is available.
    // The reason we have this loop is to eliminate test flakiness. The tests treat server
    // sockets the same as client sockets, in that they bind to some random free UDP port.
    // However, what's free in UDP may not be free in TCP. So we loop until we find a free port.
    //
    for (uint32_t TryCount = 0; TryCount < 1000; TryCount++) {
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

        (*NewSocket)->RawSocketAvailable = 0;
        if (CreateRaw && Datapath->RawDataPath) {
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
                BOOLEAN IsWildcardAddr = Config->LocalAddress == NULL || QuicAddrIsWildCard(Config->LocalAddress);
                if (IsWildcardAddr && (Config->Flags & CXPLAT_SOCKET_FLAG_QTIP)) {
                    CxPlatSocketDelete(*NewSocket);
                    continue;
                }
                if (!(Config->Flags & CXPLAT_SOCKET_FLAG_QTIP)) {
                    Status = QUIC_STATUS_SUCCESS; // Silently fail non-QTIP raw socket creation.
                } else {
                    CxPlatSocketDelete(*NewSocket);
                }
                goto Error;
            }
        }
        break;
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

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ROUTE* Route
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    if (Route->UseQTIP || (Socket->RawSocketAvailable &&
        !IS_LOOPBACK(Socket->RemoteAddress))) {
        return RawSocketGetLocalMtu(Route);
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
BOOLEAN
CxPlatSocketRawSocketAvailable(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return Socket->RawSocketAvailable;
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
        RecvDataChain->DatapathType == CXPLAT_DATAPATH_TYPE_NORMAL ||
        RecvDataChain->DatapathType == CXPLAT_DATAPATH_TYPE_RAW);
    RecvDataChain->DatapathType == CXPLAT_DATAPATH_TYPE_NORMAL ?
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
    if (Config->Route->DatapathType == CXPLAT_DATAPATH_TYPE_RAW ||
        (Config->Route->DatapathType == CXPLAT_DATAPATH_TYPE_UNKNOWN &&
        Socket->RawSocketAvailable && !IS_LOOPBACK(Config->Route->RemoteAddress))) {
        SendData = RawSendDataAlloc(Config);
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
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ?
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
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ?
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
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ?
    SendDataFreeBuffer(SendData, Buffer) : RawSendDataFreeBuffer(SendData, Buffer);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ||
        DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
    return DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL ?
        SendDataIsFull(SendData) : RawSendDataIsFull(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_NORMAL) {
        SocketSend(Socket, Route, SendData);
     } else {
        CXPLAT_DBG_ASSERT(DatapathType(SendData) == CXPLAT_DATAPATH_TYPE_RAW);
        RawSocketSend(CxPlatSocketToRaw(Socket), Route, SendData);
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
    } else if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_NORMAL) {
        *DstRoute = *SrcRoute;
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
}

void
CxPlatResolveRouteComplete(
    _In_ void* Context,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    )
{
    CXPLAT_DBG_ASSERT(Route->DatapathType != CXPLAT_DATAPATH_TYPE_NORMAL);
    if (Route->State != RouteResolved) {
        RawResolveRouteComplete(Context, Route, PhysicalAddress, PathId);
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
    if (Socket->HasFixedRemoteAddress) {
        //
        // For clients,
        // It must be true that Route->UseQTIP == Socket->ReserveAuxTcpSock because client
        // connections can only send/recv either UDP or TCP traffic.
        //
        // For servers,
        // It could be the case that Route->UseQTIP != Socket->ReserveAuxTcpSock. The state of
        // Socket->ReserveAuxTcpSock simply determines whether or not we initialize an auxiliary TCP socket
        // to prevent XDP from hijacking traffic from other processes. Therefore, servers rely
        // on the receive path to set Route->UseQTIP, depending on the type of XDP traffic it sees.
        //
        Route->UseQTIP = Socket->ReserveAuxTcpSock;
    }

    #if defined(_KERNEL_MODE) || defined(CX_PLATFORM_LINUX) || defined(CX_PLATFORM_DARWIN)
    CXPLAT_DBG_ASSERT(Route->UseQTIP == FALSE);
    #endif

    if (Route->UseQTIP || Route->DatapathType == CXPLAT_DATAPATH_TYPE_RAW ||
        (Route->DatapathType == CXPLAT_DATAPATH_TYPE_UNKNOWN &&
        Socket->RawSocketAvailable && !IS_LOOPBACK(Route->RemoteAddress))) {
        return RawResolveRoute(CxPlatSocketToRaw(Socket), Route, PathId, Context, Callback);
    }
    Route->State = RouteResolved;
    return QUIC_STATUS_SUCCESS;
}
