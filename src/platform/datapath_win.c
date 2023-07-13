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

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return DataPathUserFuncs.CxPlatDataPathRecvPacketToRecvData(Context);
    // TODO: xdp
    // Or inline the function
    // use global variable to store the offset? set at init phase
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return DataPathUserFuncs.CxPlatDataPathRecvDataToRecvPacket(Datagram);
    // TODO: xdp
    // Or inline the function
    // use global variable to store the offset? set at init phase
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
    // Init all Datapath
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_DATAPATH* DataPath = (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_DATAPATH), QUIC_POOL_DATAPATH);
    if (DataPath == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CxPlatZeroMemory(DataPath, sizeof(CXPLAT_DATAPATH));
    Status = DataPathUserFuncs.CxPlatDataPathInitialize(
        ClientRecvContextLength,
        UdpCallbacks,
        TcpCallbacks,
        Config,
        &DataPath->User);

    // TODO: xdp

    *NewDataPath = DataPath;

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    DataPathUserFuncs.CxPlatDataPathUninitialize(Datapath->User);
    if (Datapath->Xdp) {
        // DataPathXdpFuncs.CxPlatDataPathUninitialize(Datapath->User);
    }
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    DataPathUserFuncs.CxPlatDataPathUpdateConfig(Datapath->User, Config);
    if (Datapath->Xdp) {
        // DataPathXdpFuncs.CxPlatDataPathUpdateConfig(Datapath->Xdp, Config);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    // Which feature should be taken?
    return DataPathUserFuncs.CxPlatDataPathGetSupportedFeatures(Datapath->User);
    // TODO: xdp
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    // Which flag should be taken?
    return DataPathUserFuncs.CxPlatDataPathIsPaddingPreferred(Datapath->User);
    // TODO: xdp

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
    // which datapath should be used?
    return DataPathUserFuncs.CxPlatDataPathGetLocalAddresses(
        Datapath->User,
        Addresses,
        AddressesCount);
    // TODO: xdp
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
    // which datapath should be used?
    return DataPathUserFuncs.CxPlatDataPathGetGatewayAddresses(
        Datapath->User,
        GatewayAddresses,
        GatewayAddressesCount);
    // TODO: xdp
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    // TODO: both datapath adopt same procedure
    //       can be flatten here and may no need for calling into internal datapath
    return DataPathUserFuncs.CxPlatDataPathResolveAddress(
        Datapath->User,
        HostName,
        Address);
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

    // - if client, use one out of 2 datapath
    //   - if Config->RemoteAddress is loopback, use user
    //   - if not, use xdp
    // - if server, init socket, then share info to xdp?

    if (FALSE /*(server && xdp) || (client && remote is not loopback)*/) {
        // use XDP
    } else {
        Status = DataPathUserFuncs.CxPlatSocketCreateUdp(
            Datapath->User,
            Config,
            NewSocket);
        (*NewSocket)->DataPathType = DATAPATH_TYPE_USER;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
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
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (Socket->DataPathType == DATAPATH_TYPE_USER) {
        DataPathUserFuncs.CxPlatSocketDelete((CXPLAT_SOCKET_INTERNAL*)Socket);
    } else if (Socket->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
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
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Offloads);
    UNREFERENCED_PARAMETER(OffloadCount);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (Socket->DataPathType == DATAPATH_TYPE_USER) {
        return DataPathUserFuncs.CxPlatSocketGetLocalMtu((CXPLAT_SOCKET_INTERNAL*)Socket);
    } else if (Socket->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    // TODO: inline
    DataPathUserFuncs.CxPlatSocketGetLocalAddress(
        (CXPLAT_SOCKET_INTERNAL*)Socket,
        Address);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    // TODO: inline
    DataPathUserFuncs.CxPlatSocketGetRemoteAddress(
        (CXPLAT_SOCKET_INTERNAL*)Socket,
        Address);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    // TODO: CXPLAT_RECV_DATA to have flag to indicate which datapath it belongs to
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
    if (Socket->DataPathType == DATAPATH_TYPE_USER) {
        SendData = DataPathUserFuncs.CxPlatSendDataAlloc(
            (CXPLAT_SOCKET_INTERNAL*)Socket,
            Config);
        SendData->DataPathType = DATAPATH_TYPE_USER;
    } else if (Socket->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
        // SendData->DataPathType = DATAPATH_TYPE_USER;
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->DataPathType == DATAPATH_TYPE_USER) {
        DataPathUserFuncs.CxPlatSendDataFree(
            (CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else if (SendData->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
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
    if (SendData->DataPathType == DATAPATH_TYPE_USER) {
        return DataPathUserFuncs.CxPlatSendDataAllocBuffer(
            (CXPLAT_SEND_DATA_INTERNAL*)SendData,
            MaxBufferLength);
    } else if (SendData->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
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
    if (SendData->DataPathType == DATAPATH_TYPE_USER) {
        DataPathUserFuncs.CxPlatSendDataFreeBuffer(
            (CXPLAT_SEND_DATA_INTERNAL*)SendData,
            Buffer);
    } else if (SendData->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
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
    if (SendData->DataPathType == DATAPATH_TYPE_USER) {
        return DataPathUserFuncs.CxPlatSendDataIsFull(
            (CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else if (SendData->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
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
    if (Socket->DataPathType == DATAPATH_TYPE_USER) {
        return DataPathUserFuncs.CxPlatSocketSend(
            (CXPLAT_SOCKET_INTERNAL*)Socket,
            Route,
            (CXPLAT_SEND_DATA_INTERNAL*)SendData);
    } else if (Socket->DataPathType == DATAPATH_TYPE_XDP) {
        // use XDP
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
    // what is the difference between datapath?
    DataPathUserFuncs.CxPlatDataPathProcessCqe(Cqe);
}
