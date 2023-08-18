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

#define IS_LOOPBACK(RemoteAddress) ((RemoteAddress.si_family == QUIC_ADDRESS_FAMILY_INET &&                \
                                     RemoteAddress.Ipv4.sin_addr.S_un.S_addr == htonl(INADDR_LOOPBACK)) || \
                                    (RemoteAddress.si_family == QUIC_ADDRESS_FAMILY_INET6 &&               \
                                     IN6_IS_ADDR_LOOPBACK(&RemoteAddress.Ipv6.sin6_addr)))

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context,
    _In_ uint16_t BufferFrom
    )
{
    if (BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        return DataPathUserFuncs.CxPlatDataPathRecvPacketToRecvData(Context);
    } else if (BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        return XDP_CxPlatDataPathRecvPacketToRecvData(Context);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return NULL;
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    if (Datagram->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        return DataPathUserFuncs.CxPlatDataPathRecvDataToRecvPacket(Datagram);
    } else if (Datagram->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        return XDP_CxPlatDataPathRecvDataToRecvPacket(Datagram);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatRawDataPathAvailable(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return Datapath->RawDataPath != NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatRawSocketAvailable(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return Socket->Datapath && CxPlatRawDataPathAvailable(Socket->Datapath);
}

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

    // 
    // Init all Datapath
    //
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
    }
    if (TcpCallbacks != NULL) {
        if (TcpCallbacks->Accept == NULL ||
            TcpCallbacks->Connect == NULL ||
            TcpCallbacks->Receive == NULL ||
            TcpCallbacks->SendComplete == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
    }
    if (!CxPlatWorkersLazyStart(Config)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    uint32_t ProcessorCount;
    if (Config && Config->ProcessorCount) {
        ProcessorCount = Config->ProcessorCount;
    } else {
        ProcessorCount = CxPlatProcMaxCount();
    }    
    uint32_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        ProcessorCount * sizeof(CXPLAT_DATAPATH_PROC);
    CXPLAT_DATAPATH* DataPath = (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (DataPath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CxPlatZeroMemory(DataPath, DatapathLength);
    if (UdpCallbacks) {
        DataPath->UdpHandlers = *UdpCallbacks;
    }
    if (TcpCallbacks) {
        DataPath->TcpHandlers = *TcpCallbacks;
    }
    DataPath->ProcCount = (uint16_t)ProcessorCount;
    Status = DataPathUserFuncs.CxPlatDataPathInitialize(
        ClientRecvContextLength,
        Config,
        DataPath);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogVerbose(
            DatapathInitFail,
            "[  dp] Failed to initialize datapath, status:%d", Status);
        goto Error;
    }

    const size_t RawDatapathSize = CxPlatDpRawGetDatapathSize(Config);
    CXPLAT_DATAPATH_RAW* RawDataPath = CXPLAT_ALLOC_PAGED(RawDatapathSize, QUIC_POOL_DATAPATH);
    if (RawDataPath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            RawDatapathSize);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(RawDataPath, RawDatapathSize);

    // Status = QUIC_STATUS_INVALID_PARAMETER;
    Status = CxPlatInitRawDataPath(
        ClientRecvContextLength,
        Config,
        DataPath,
        RawDataPath);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogVerbose(
            RawDatapathInitFail,
            "[ raw] Failed to initialize raw datapath, status:%d", Status);
        Status = QUIC_STATUS_SUCCESS;
        CXPLAT_FREE(RawDataPath, QUIC_POOL_DATAPATH);
        RawDataPath = NULL;
    }

    DataPath->RawDataPath = RawDataPath;
    *NewDataPath = DataPath;
Error:
    // TODO: error handling

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath->RawDataPath) {
        XDP_CxPlatDataPathUninitialize(Datapath->RawDataPath);
    }   
    DataPathUserFuncs.CxPlatDataPathUninitialize(Datapath);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    DataPathUserFuncs.CxPlatDataPathUpdateConfig(Datapath, Config);
    if (Datapath->RawDataPath) {
        XDP_CxPlatDataPathUpdateConfig(Datapath->RawDataPath, Config);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath->RawDataPath) {
        return DataPathUserFuncs.CxPlatDataPathGetSupportedFeatures(Datapath) |
               XDP_CxPlatDataPathGetSupportedFeatures(Datapath->RawDataPath);
    }
    return DataPathUserFuncs.CxPlatDataPathGetSupportedFeatures(Datapath);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    // FIXME: Which flag should be taken?
    // return DataPathUserFuncs.CxPlatDataPathIsPaddingPreferred(Datapath);
    return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    // TODO: XDP doesn't support, could be inlined here
    return DataPathUserFuncs.CxPlatDataPathGetLocalAddresses(
        Datapath,
        Addresses,
        AddressesCount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    // TODO: XDP doesn't support, Could be inlined here.
    return DataPathUserFuncs.CxPlatDataPathGetGatewayAddresses(
        Datapath,
        GatewayAddresses,
        GatewayAddressesCount);
}

// private func
void
CxPlatDataPathPopulateTargetAddress(
    _In_ ADDRESS_FAMILY Family,
    _In_ ADDRINFOW *Ai,
    _Out_ SOCKADDR_INET* Address
    )
{
    if (Ai->ai_addr->sa_family == QUIC_ADDRESS_FAMILY_INET6) {
        //
        // Is this a mapped ipv4 one?
        //
        PSOCKADDR_IN6 SockAddr6 = (PSOCKADDR_IN6)Ai->ai_addr;

        if (Family == QUIC_ADDRESS_FAMILY_UNSPEC && IN6ADDR_ISV4MAPPED(SockAddr6))
        {
            PSOCKADDR_IN SockAddr4 = &Address->Ipv4;
            //
            // Get the ipv4 address from the mapped address.
            //
            SockAddr4->sin_family = QUIC_ADDRESS_FAMILY_INET;
            SockAddr4->sin_addr =
                *(IN_ADDR UNALIGNED *)
                    IN6_GET_ADDR_V4MAPPED(&SockAddr6->sin6_addr);
            SockAddr4->sin_port = SockAddr6->sin6_port;
            return;
        }
    }

    CxPlatCopyMemory(Address, Ai->ai_addr, Ai->ai_addrlen);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    QUIC_STATUS Status;
    PWSTR HostNameW = NULL;
    ADDRINFOW Hints = { 0 };
    ADDRINFOW *Ai;

    Status =
        CxPlatUtf8ToWideChar(
            HostName,
            QUIC_POOL_PLATFORM_TMP_ALLOC,
            &HostNameW);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Convert HostName to unicode");
        goto Exit;
    }

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->si_family;

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    if (GetAddrInfoW(HostNameW, NULL, &Hints, &Ai) == 0) {
        CxPlatDataPathPopulateTargetAddress((ADDRESS_FAMILY)Hints.ai_family, Ai, Address);
        FreeAddrInfoW(Ai);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    if (GetAddrInfoW(HostNameW, NULL, &Hints, &Ai) == 0) {
        CxPlatDataPathPopulateTargetAddress((ADDRESS_FAMILY)Hints.ai_family, Ai, Address);
        FreeAddrInfoW(Ai);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = HRESULT_FROM_WIN32(WSAHOST_NOT_FOUND);

Exit:

    if (HostNameW != NULL) {
        CXPLAT_FREE(HostNameW, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

    return Status;
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

    Status = DataPathUserFuncs.CxPlatSocketCreateUdp(
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
        Status = CxPlatInitRawSocket(
            Datapath->RawDataPath,
            Config,
            CxPlatSocketToRaw(*NewSocket));
        if (QUIC_FAILED(Status)) {
            QuicTraceLogVerbose(
                RawSockCreateFail,
                "[sock] Failed to create raw socket, status:%d", Status);
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
    return DataPathUserFuncs.CxPlatSocketCreateTcp(
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
    return DataPathUserFuncs.CxPlatSocketCreateTcpListener(
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
    if (Socket->Datapath && Socket->Datapath->RawDataPath) {
        CxPlatRawSocketDelete(CxPlatSocketToRaw(Socket));
    }
    DataPathUserFuncs.CxPlatSocketDelete(Socket);
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
    if (Socket->Datapath && Socket->Datapath->RawDataPath &&
        !IS_LOOPBACK(Offloads[0].Address)) {
        return XDP_CxPlatSocketUpdateQeo(CxPlatSocketToRaw(Socket), Offloads, OffloadCount);
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
    if (Socket->Datapath && Socket->Datapath->RawDataPath &&
        !IS_LOOPBACK(Socket->RemoteAddress)) {
        XDP_CxPlatSocketGetLocalMtu(CxPlatSocketToRaw(Socket));
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
    CXPLAT_DBG_ASSERT(RecvDataChain != NULL);
    if (RecvDataChain->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        DataPathUserFuncs.CxPlatRecvDataReturn(RecvDataChain);
    } else if (RecvDataChain->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        XDP_CxPlatRecvDataReturn(RecvDataChain);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
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
    if (Socket->Type == 0 && // CXPLAT_SOCKET_UDP
        Socket->Datapath && Socket->Datapath->RawDataPath &&
        !IS_LOOPBACK(Config->Route->RemoteAddress)) {
        SendData = XDP_CxPlatSendDataAlloc(CxPlatSocketToRaw(Socket), Config);
        if (SendData) {
            SendData->BufferFrom = CXPLAT_BUFFER_FROM_XDP;
        }
    } else {
        SendData = DataPathUserFuncs.CxPlatSendDataAlloc(Socket, Config);
        if (SendData) {
            SendData->BufferFrom = CXPLAT_BUFFER_FROM_USER;
        }
    }
    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        DataPathUserFuncs.CxPlatSendDataFree((CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        XDP_CxPlatSendDataFree((CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        return DataPathUserFuncs.CxPlatSendDataAllocBuffer((CXPLAT_SEND_DATA_INTERNAL*)SendData, MaxBufferLength);
    } else if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        return XDP_CxPlatSendDataAllocBuffer((CXPLAT_SEND_DATA_INTERNAL*)SendData, MaxBufferLength);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        DataPathUserFuncs.CxPlatSendDataFreeBuffer((CXPLAT_SEND_DATA_INTERNAL*)SendData, Buffer);
    } else if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        XDP_CxPlatSendDataFreeBuffer((CXPLAT_SEND_DATA_INTERNAL*)SendData, Buffer);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        return DataPathUserFuncs.CxPlatSendDataIsFull((CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        return XDP_CxPlatSendDataIsFull((CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return FALSE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_USER) {
        return DataPathUserFuncs.CxPlatSocketSend(Socket, Route, (CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else if (SendData->BufferFrom == CXPLAT_BUFFER_FROM_XDP) {
        return XDP_CxPlatSocketSend(CxPlatSocketToRaw(Socket), Route, (CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    // TODO: refactoring
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        DATAPATH_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_IO_SQE, DatapathSqe);
        if (Sqe->IoType == 1480872005 || Sqe->IoType == 1480872006) {
            XDP_CxPlatDataPathProcessCqe(Cqe);
        } else {
            DataPathUserFuncs.CxPlatDataPathProcessCqe(Cqe);
        }
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        XDP_CxPlatDataPathProcessCqe(Cqe);
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
    if (!IS_LOOPBACK(SrcRoute->RemoteAddress)) {
        CxPlatCopyMemory(DstRoute, SrcRoute, (uint8_t*)&SrcRoute->State - (uint8_t*)SrcRoute);
        CxPlatUpdateRoute(DstRoute, SrcRoute);
    } else {
        *DstRoute = *SrcRoute;
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
    if (Route->State != RouteResolved) {
        XDP_CxPlatResolveRouteComplete(Connection, Route, PhysicalAddress, PathId);
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
    if (Socket->Datapath && Socket->Datapath->RawDataPath &&
        !IS_LOOPBACK(Route->RemoteAddress)) {
        return XDP_CxPlatResolveRoute(Socket, Route, PathId, Context, Callback);
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
    if (!IS_LOOPBACK(SrcRoute->RemoteAddress)) {
        XDP_CxPlatUpdateRoute(DstRoute, SrcRoute);
    }
}

