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
                               Address.Ipv4.sin_addr.S_un.S_addr == htonl(INADDR_LOOPBACK)) || \
                              (Address.si_family == QUIC_ADDRESS_FAMILY_INET6 &&               \
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
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    const ULONG Flags =
        GAA_FLAG_INCLUDE_ALL_INTERFACES |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME |
        GAA_FLAG_SKIP_DNS_INFO;

    UNREFERENCED_PARAMETER(Datapath);

    ULONG AdapterAddressesSize = 0;
    PIP_ADAPTER_ADDRESSES AdapterAddresses = NULL;
    uint32_t Index = 0;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ULONG Error;
    do {
        Error =
            GetAdaptersAddresses(
                AF_UNSPEC,
                Flags,
                NULL,
                AdapterAddresses,
                &AdapterAddressesSize);
        if (Error == ERROR_BUFFER_OVERFLOW) {
            if (AdapterAddresses) {
                CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
            }
            AdapterAddresses = CXPLAT_ALLOC_NONPAGED(AdapterAddressesSize, QUIC_POOL_DATAPATH_ADDRESSES);
            if (!AdapterAddresses) {
                Error = ERROR_NOT_ENOUGH_MEMORY;
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "PIP_ADAPTER_ADDRESSES",
                    AdapterAddressesSize);
            }
        }
    } while (Error == ERROR_BUFFER_OVERFLOW);

    if (Error != ERROR_SUCCESS) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GetAdaptersAddresses");
        Status = HRESULT_FROM_WIN32(Error);
        goto Exit;
    }

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS_LH Iter2 = Iter->FirstUnicastAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            Index++;
        }
    }

    if (Index == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No local unicast addresses found");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    *Addresses = CXPLAT_ALLOC_NONPAGED(Index * sizeof(CXPLAT_ADAPTER_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
    if (*Addresses == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Addresses",
            Index * sizeof(CXPLAT_ADAPTER_ADDRESS));
        goto Exit;
    }

    CxPlatZeroMemory(*Addresses, Index * sizeof(CXPLAT_ADAPTER_ADDRESS));
    *AddressesCount = Index;
    Index = 0;

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS_LH Iter2 = Iter->FirstUnicastAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            CxPlatCopyMemory(
                &(*Addresses)[Index].Address,
                Iter2->Address.lpSockaddr,
                sizeof(QUIC_ADDR));
            (*Addresses)[Index].InterfaceIndex =
                Iter2->Address.lpSockaddr->sa_family == AF_INET ?
                    (uint32_t)Iter->IfIndex : (uint32_t)Iter->Ipv6IfIndex;
            (*Addresses)[Index].InterfaceType = (uint16_t)Iter->IfType;
            (*Addresses)[Index].OperationStatus = (CXPLAT_OPERATION_STATUS)Iter->OperStatus;
            Index++;
        }
    }

Exit:

    if (AdapterAddresses) {
        CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
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
    const ULONG Flags =
        GAA_FLAG_INCLUDE_GATEWAYS |
        GAA_FLAG_INCLUDE_ALL_INTERFACES |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_MULTICAST;

    UNREFERENCED_PARAMETER(Datapath);

    ULONG AdapterAddressesSize = 0;
    PIP_ADAPTER_ADDRESSES AdapterAddresses = NULL;
    uint32_t Index = 0;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ULONG Error;
    do {
        Error =
            GetAdaptersAddresses(
                AF_UNSPEC,
                Flags,
                NULL,
                AdapterAddresses,
                &AdapterAddressesSize);
        if (Error == ERROR_BUFFER_OVERFLOW) {
            if (AdapterAddresses) {
                CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
            }
            AdapterAddresses = CXPLAT_ALLOC_NONPAGED(AdapterAddressesSize, QUIC_POOL_DATAPATH_ADDRESSES);
            if (!AdapterAddresses) {
                Error = ERROR_NOT_ENOUGH_MEMORY;
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "PIP_ADAPTER_ADDRESSES",
                    AdapterAddressesSize);
            }
        }
    } while (Error == ERROR_BUFFER_OVERFLOW);

    if (Error != ERROR_SUCCESS) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GetAdaptersAddresses");
        Status = HRESULT_FROM_WIN32(Error);
        goto Exit;
    }

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_GATEWAY_ADDRESS_LH Iter2 = Iter->FirstGatewayAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            Index++;
        }
    }

    if (Index == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No gateway server addresses found");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    *GatewayAddresses = CXPLAT_ALLOC_NONPAGED(Index * sizeof(QUIC_ADDR), QUIC_POOL_DATAPATH_ADDRESSES);
    if (*GatewayAddresses == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "GatewayAddresses",
            Index * sizeof(QUIC_ADDR));
        goto Exit;
    }

    CxPlatZeroMemory(*GatewayAddresses, Index * sizeof(QUIC_ADDR));
    *GatewayAddressesCount = Index;
    Index = 0;

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_GATEWAY_ADDRESS_LH Iter2 = Iter->FirstGatewayAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            CxPlatCopyMemory(
                &(*GatewayAddresses)[Index],
                Iter2->Address.lpSockaddr,
                sizeof(QUIC_ADDR));
            Index++;
        }
    }

Exit:

    if (AdapterAddresses) {
        CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
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
            RawDataPathProcessCqe(Cqe);
        } else {
            DataPathProcessCqe(Cqe);
        }
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
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

