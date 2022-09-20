/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Demikernel Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"
#include <demi/libos.h>
#include <demi/wait.h>
#include <demi/sga.h>

#ifdef QUIC_CLOG
#include "datapath_demikernel.c.clog.h"
#endif

#pragma warning(disable:4100) // unreferenced formal parameter

// Demikernel's datapath data.
typedef struct CXPLAT_DATAPATH {
    uint32_t ClientRecvContextLength;
    CXPLAT_SOCKET* Socket;
    CXPLAT_THREAD Thread;
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpCallbacks;
    CXPLAT_LOCK Lock;
    BOOLEAN IsRunning;
} CXPLAT_DATAPATH;

typedef struct CXPLAT_SOCKET {
    int sockqd;
    void* CallbackContext;
    demi_qtoken_t popqt;
    CXPLAT_DATAPATH* Datapath;
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;
    CXPLAT_RUNDOWN_REF Rundown;
    BOOLEAN popqt_set;
} CXPLAT_SOCKET;

typedef struct CXPLAT_SEND_DATA {
    demi_sgarray_t sga;
    QUIC_BUFFER Buffer;
    CXPLAT_DATAPATH* Datapath;
} CXPLAT_SEND_DATA;

// Demikernel receive data.
typedef struct DEMI_RECEIVE_DATA {
    CXPLAT_RECV_DATA RecvData;
    demi_sgarray_t sga;
    CXPLAT_ROUTE Route;
    CXPLAT_DATAPATH* Datapath;
} DEMI_RECEIVE_DATA;

CXPLAT_THREAD_CALLBACK(DemiWorkLoop, Context);

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(DEMI_RECEIVE_DATA));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(void*)(Datagram + 1);
}

// Initializes Demikernel datapath.
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ CXPLAT_DATAPATH_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;


    // Validate input args.
    UNREFERENCED_PARAMETER(TcpCallbacks);
    if (NewDataPath == NULL || UdpCallbacks == NULL ||
        UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    // Allocate datapath data structure.
    CXPLAT_DATAPATH* Datapath = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_DATAPATH), QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(CXPLAT_DATAPATH));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    // Initialize datapath's data structure.
    CxPlatZeroMemory(Datapath, sizeof(*Datapath));
    Datapath->IsRunning = TRUE;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    memcpy(&Datapath->UdpCallbacks, UdpCallbacks, sizeof(CXPLAT_UDP_DATAPATH_CALLBACKS));
    CxPlatLockInitialize(&Datapath->Lock);

    // Initialize Demikernel.
    // FIXME: Pass down right arguments.
    int argc = 1;
    char* argv[] = { "foobar" };
    if (demi_init(argc, argv) != 0) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error0;
    }

    // Spawn Demikernel's work loop thread.
    CXPLAT_THREAD_CONFIG config = {0, 0, NULL, DemiWorkLoop, Datapath};
    Status = CxPlatThreadCreate(&config, &Datapath->Thread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error1;
    }

    // Set output values.
    *NewDataPath = Datapath;

    return QUIC_STATUS_SUCCESS;

Error1:
    // TODO: Enable the following code when Demikernel features an exit function.
#ifdef __DEMIKERNEL_HAS_EXIT__
    demi_exit(-1);
#endif
Error0:
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    Datapath->IsRunning = FALSE;
    CxPlatThreadWait(&Datapath->Thread);
    CxPlatThreadDelete(&Datapath->Thread);
    // TODO: Cleanup demikernel?
    CxPlatLockUninitialize(&Datapath->Lock);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return FALSE;
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
    return QUIC_STATUS_NOT_SUPPORTED;
}

#ifdef _WIN32

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

#else

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

#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;


    assert(Datapath->Socket == NULL); // Don't support more than 1 right now

    CXPLAT_SOCKET* Socket =
        (CXPLAT_SOCKET*)CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SOCKET), QUIC_POOL_SOCKET);
    if (Socket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            sizeof(CXPLAT_SOCKET));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Socket, sizeof(*Socket));
    Socket->Datapath = Datapath;
    if (Config->LocalAddress) {
        memcpy(&Socket->LocalAddress, Config->LocalAddress, sizeof(Socket->LocalAddress));
    }
    if (Config->RemoteAddress) {
        memcpy(&Socket->RemoteAddress, Config->RemoteAddress, sizeof(Socket->RemoteAddress));
    }
    CxPlatRundownInitialize(&Socket->Rundown);

    CxPlatLockAcquire(&Datapath->Lock);

    if (demi_socket(&Socket->sockqd, AF_INET, SOCK_DGRAM, 0) != 0) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit0;
    }

    if (Config->LocalAddress) {
    if (demi_bind(Socket->sockqd, (const struct sockaddr*)&Socket->LocalAddress, sizeof(QUIC_ADDR)) != 0) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit1;
    }
    }

// TODO: Enable the following block when Demikernel features connected UDP sockets.
#if _DEMIKERNEL_HAS_UDP_CONNECT_
    if (Config->RemoteAddress) {
        demi_qtoken_t qt = -1;
        assert (demi_connect(&qt, Socket->sockqd, (const struct sockaddr*)&Config->RemoteAddress, sizeof(QUIC_ADDR)) == 0);
    }
#endif

    CxPlatLockRelease(&Datapath->Lock);

    Datapath->Socket = Socket;
    *NewSocket = Socket;

    return QUIC_STATUS_SUCCESS;

Exit1:
    demi_close(Socket->sockqd);
Exit0:
    CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
    CxPlatLockRelease(&Datapath->Lock);
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
    CXPLAT_DATAPATH* Datapath = Socket->Datapath;
    Datapath->Socket = NULL;
    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    CxPlatLockAcquire(&Socket->Datapath->Lock);
    demi_close(Socket->sockqd);
    CxPlatLockRelease(&Socket->Datapath->Lock);
    CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return 1500;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    memcpy(Address, &Socket->LocalAddress, sizeof(Socket->LocalAddress));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    memcpy(Address, &Socket->RemoteAddress, sizeof(Socket->RemoteAddress));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketRecv(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET* Socket,
    _In_ demi_qresult_t* qr
    )
{
    demi_sgarray_t sga = qr->qr_value.sga;
    DEMI_RECEIVE_DATA* DemiRecvData =
        CXPLAT_ALLOC_NONPAGED(sizeof(DEMI_RECEIVE_DATA) + Datapath->ClientRecvContextLength, QUIC_POOL_DATA);
    assert(DemiRecvData != NULL);

    memset(DemiRecvData, 0, sizeof(DEMI_RECEIVE_DATA));
    DemiRecvData->Datapath = Datapath;
    DemiRecvData->RecvData.Route = &DemiRecvData->Route;
    DemiRecvData->RecvData.Buffer = sga.sga_segs[0].sgaseg_buf;
    DemiRecvData->RecvData.BufferLength = sga.sga_segs[0].sgaseg_len;
    memcpy(&DemiRecvData->sga, &sga, sizeof(demi_sgarray_t));
    memcpy(&DemiRecvData->Route.LocalAddress, &Socket->LocalAddress, sizeof(struct sockaddr));
    memcpy(&DemiRecvData->Route.RemoteAddress, &qr->qr_value.sga.sga_addr, sizeof(struct sockaddr));

    QuicTraceEvent(
        DatapathRecv,
        "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
        Socket,
        (uint32_t)DemiRecvData->RecvData.BufferLength,
        (uint32_t)DemiRecvData->RecvData.BufferLength,
        CASTED_CLOG_BYTEARRAY(sizeof(Socket->LocalAddress), &Socket->LocalAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(qr->qr_value.sga.sga_addr), &qr->qr_value.sga.sga_addr));

    // Tell QUIC that there is data read to be read.
    Datapath->UdpCallbacks.Receive(Socket, Socket->CallbackContext, &DemiRecvData->RecvData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{

    while (RecvDataChain != NULL) {
        DEMI_RECEIVE_DATA* DemiRecvData = (DEMI_RECEIVE_DATA*)RecvDataChain;
        CxPlatLockAcquire(&DemiRecvData->Datapath->Lock);
        assert(demi_sgafree(&DemiRecvData->sga) == 0);
        CxPlatLockRelease(&DemiRecvData->Datapath->Lock);
        RecvDataChain = RecvDataChain->Next;
        CXPLAT_FREE(DemiRecvData, QUIC_POOL_DATA);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    CXPLAT_SEND_DATA* SendData = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEND_DATA), QUIC_POOL_PLATFORM_SENDCTX);
    assert(SendData != NULL);

    CxPlatLockAcquire(&Socket->Datapath->Lock);
    SendData->sga = demi_sgaalloc(MaxPacketSize);
    CxPlatLockRelease(&Socket->Datapath->Lock);
    assert(SendData->sga.sga_numsegs != 0);

    SendData->Buffer.Buffer = SendData->sga.sga_segs[0].sgaseg_buf;
    SendData->Buffer.Length = SendData->sga.sga_segs[0].sgaseg_len;
    SendData->Datapath = Socket->Datapath;

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    SendData->Buffer.Length = MaxBufferLength;
    return &SendData->Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatLockAcquire(&SendData->Datapath->Lock);
    assert(demi_sgafree(&SendData->sga) == 0);
    CxPlatLockRelease(&SendData->Datapath->Lock);
    CXPLAT_FREE(SendData, QUIC_POOL_PLATFORM_SENDCTX);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    // Nothing to be done.
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    demi_qtoken_t qt = -1;
    demi_qresult_t qr = {};


    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    // TODO: check the following code.
    demi_sgarray_t sga = {};
    memcpy(&sga, &SendData->sga, sizeof(demi_sgarray_t));
    sga.sga_segs[0].sgaseg_len = SendData->Buffer.Length;

    CxPlatLockAcquire(&Socket->Datapath->Lock);
    assert(demi_pushto(&qt, Socket->sockqd, &sga, (const struct sockaddr*)&Route->RemoteAddress, sizeof(struct sockaddr_in)) == 0);

    memset(&qr, 0, sizeof(demi_qresult_t()));
    assert(demi_wait(&qr, qt) == 0);
    CxPlatLockRelease(&Socket->Datapath->Lock);

    switch (qr.qr_opcode)
    {
    case DEMI_OPC_PUSH:
        break;
    default: // TODO: log this.
        break;
    }

    CxPlatSendDataFree(SendData);

    return QUIC_STATUS_SUCCESS;
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    // No events (yet)
    UNREFERENCED_PARAMETER(Cqe);
}

CXPLAT_THREAD_CALLBACK(DemiWorkLoop, Context) {
    CXPLAT_DATAPATH* Datapath = Context;
    while (Datapath->IsRunning) {
        CXPLAT_SOCKET* Socket = Datapath->Socket;
        if (Socket != NULL && CxPlatRundownAcquire(&Socket->Rundown)) {
            demi_qresult_t qr = {0};
            int result;

            CxPlatLockAcquire(&Datapath->Lock);
            if (!Socket->popqt_set) {
                assert(demi_pop(&Socket->popqt, Socket->sockqd) == 0);
                Socket->popqt_set = TRUE;
            }
            result = demi_wait_timeout(&qr, Socket->popqt, 0) == 0;
            CxPlatLockRelease(&Datapath->Lock);

            if (result != ETIMEDOUT) {
                switch (qr.qr_opcode) {
                case DEMI_OPC_POP:
                    CxPlatSocketRecv(Datapath, Socket, &qr);
                    break;
                default:
                    break;
                }
                Socket->popqt_set = FALSE;
            }
            CxPlatRundownRelease(&Socket->Rundown);
        }
    }
    CXPLAT_THREAD_RETURN(0);
}
