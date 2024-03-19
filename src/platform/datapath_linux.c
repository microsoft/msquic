/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"

#ifdef QUIC_CLOG
#include "datapath_linux.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses

#pragma warning(disable:4100) // unreferenced
#pragma warning(disable:6101) // uninitialized
#pragma warning(disable:6386) // buffer overrun

#define IS_LOOPBACK(Address) ((Address.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET &&        \
                               Address.Ipv4.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) || \
                              (Address.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6 &&       \
                               IN6_IS_ADDR_LOOPBACK(&Address.Ipv6.sin6_addr)))

#define DatapathType(SendData) ((CXPLAT_SEND_DATA_COMMON*)(SendData))->DatapathType

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

    // temporally disable XDP by default
    if (getenv("QUIC_ENABLE_XDP") != NULL &&
        getenv("QUIC_ENABLE_XDP")[0] == '1') {
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
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Addresses);
    UNREFERENCED_PARAMETER(AddressesCount);
    return QUIC_STATUS_NOT_SUPPORTED;
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
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(GatewayAddresses);
    UNREFERENCED_PARAMETER(GatewayAddressesCount);
    return QUIC_STATUS_NOT_SUPPORTED;
}

// private func
void
CxPlatDataPathPopulateTargetAddress(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ QUIC_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //
        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;
        if (Family == QUIC_ADDRESS_FAMILY_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //
            SockAddrIn->sin_family = QUIC_ADDRESS_FAMILY_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        }
        Address->Ipv6 = *SockAddrIn6;
        Address->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        return;
    }

    if (AddrInfo->ai_addr->sa_family == AF_INET) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        Address->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
        return;
    }

    CXPLAT_FRE_ASSERT(FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;
    if (Hints.ai_family == QUIC_ADDRESS_FAMILY_INET6) {
        Hints.ai_family = AF_INET6;
    }

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    QuicTraceEvent(
        LibraryErrorStatus,
        "[ lib] ERROR, %u, %s.",
        (uint32_t)Result,
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = (QUIC_STATUS)Result;

Exit:

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

QUIC_STATUS
CxPlatSocketUpdateQeo(
    _In_ CXPLAT_SOCKET* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Offloads);
    UNREFERENCED_PARAMETER(OffloadCount);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
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

void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

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
    if (CXPLAT_CQE_TYPE_XDP_SHUTDOWN <= CxPlatCqeType(Cqe)) {
        RawDataPathProcessCqe(Cqe);
    } else {
        DataPathProcessCqe(Cqe);
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
    if (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_RAW ||
        (SrcRoute->DatapathType == CXPLAT_DATAPATH_TYPE_UNKNOWN &&
        !IS_LOOPBACK(SrcRoute->RemoteAddress))) {
        RawUpdateRoute(DstRoute, SrcRoute);
    }
}

