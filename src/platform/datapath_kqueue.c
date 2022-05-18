/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#define __APPLE_USE_RFC_3542 1
// See netinet6/in6.h:46 for an explanation
#include "platform_internal.h"
#include <fcntl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef QUIC_CLOG
#include "datapath_kqueue.c.clog.h"
#endif

CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be TRUE.");
CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

//
// TODO: Support batching.
//
#define CXPLAT_MAX_BATCH_SEND 1

//
// The maximum single buffer size for sending coalesced payloads.
//
#define CXPLAT_LARGE_SEND_BUFFER_SIZE         0xFFFF

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct CXPLAT_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    CXPLAT_POOL* OwningPool;

    //
    // The recv buffer used by MsQuic.
    //
    CXPLAT_RECV_DATA RecvPacket;

    //
    // Represents the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // Buffer that actually stores the UDP payload.
    //
    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // This follows the recv block.
    //
    // CXPLAT_RECV_PACKET RecvContext;

} CXPLAT_DATAPATH_RECV_BLOCK;

//
// Send context.
//

typedef struct CXPLAT_SEND_DATA {
    //
    // Indicates if the send should be bound to a local address.
    //
    BOOLEAN Bind;

    //
    // The local address to bind to.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address to send to.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Linkage to pending send list.
    //
    CXPLAT_LIST_ENTRY PendingSendLinkage;

    //
    // The type of ECN markings needed for send.
    //
    CXPLAT_ECN_TYPE ECN;

    //
    // The proc context owning this send context.
    //
    struct CXPLAT_DATAPATH_PROC_CONTEXT *Owner;

    //
    // The send segmentation size; zero if segmentation is not performed.
    //
    uint16_t SegmentSize;

    //
    // The total buffer size for Buffers.
    //
    uint32_t TotalSize;

    //
    // BufferCount - The buffer count in use.
    //
    // CurrentIndex - The current index of the Buffers to be sent.
    //
    // Buffers - Send buffers.
    //
    // Iovs - IO vectors used for doing sends on the socket.
    //
    // TODO: Better way to reconcile layout difference
    // between QUIC_BUFFER and struct iovec?
    //
    size_t BufferCount;
    size_t CurrentIndex;
    QUIC_BUFFER Buffers[CXPLAT_MAX_BATCH_SEND];
    struct iovec Iovs[CXPLAT_MAX_BATCH_SEND];

    //
    // The QUIC_BUFFER returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_DATAPATH_PROC_CONTEXT CXPLAT_DATAPATH_PROC_CONTEXT;

//
// Socket context.
//
typedef struct CXPLAT_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    CXPLAT_SOCKET* Binding;

    //
    // The datapath proc context this socket belongs to.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // The I/O vector for receive datagrams.
    //
    struct iovec RecvIov;

    //
    // The control buffer used in RecvMsgHdr.
    //
    char RecvMsgControl[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                        CMSG_SPACE(sizeof(struct in_pktinfo)) +
                        2 * CMSG_SPACE(sizeof(int))];

    //
    // The buffer used to receive msg headers on socket.
    //
    struct msghdr RecvMsgHdr;

    //
    // The receive block currently being used for receives on this socket.
    //
    CXPLAT_DATAPATH_RECV_BLOCK* CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //
    CXPLAT_LIST_ENTRY PendingSendDataHead;

    //
    // Lock around the PendingSendData list.
    //
    CXPLAT_LOCK PendingSendDataLock;

} CXPLAT_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct CXPLAT_SOCKET {

    //
    // Synchronization mechanism for cleanup.
    // Make sure events are in front for cache alignment.
    //
    CXPLAT_RUNDOWN_REF Rundown;

    //
    // A pointer to datapath object.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The client context for this binding.
    //
    void *ClientContext;

    //
    // The local address for the binding.
    //
    QUIC_ADDR LocalAddress;

    //
    //  The remote address for the binding.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Indicates the binding is shut down.
    //
    BOOLEAN Shutdown : 1;

    //
    // Flag indicates the socket has a default remote destination.
    //
    BOOLEAN HasFixedRemoteAddress : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    BOOLEAN PcpBinding : 1;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Set of socket contexts one per proc.
    //
    CXPLAT_SOCKET_CONTEXT SocketContexts[];

} CXPLAT_SOCKET;

//
// A per processor datapath context.
//
typedef struct CXPLAT_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The Kqueue FD for this proc context.
    //
    int KqueueFd;

    //
    // The index of the context in the datapath's array.
    //
    uint32_t Index;

    //
    // Thread ID of the worker thread that drives execution.
    //
    CXPLAT_THREAD_ID ThreadId;

    //
    // Completion event to indicate the worker has cleaned up.
    //
    CXPLAT_EVENT CompletionEvent;

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvBlockPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendBufferPool;

    //
    // Pool of large segmented send buffers to be shared by all sockets on this
    // core.
    //
    CXPLAT_POOL LargeSendBufferPool;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendDataPool;

} CXPLAT_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {

    //
    // A reference rundown on the datapath binding.
    // Make sure events are in front for cache alignment.
    //
    CXPLAT_RUNDOWN_REF BindingsRundown;

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // If datapath is shutting down.
    //
    BOOLEAN volatile Shutdown;

    //
    // The max send batch size.
    // TODO: See how send batching can be enabled.
    //
    uint8_t MaxSendBatchSize;

    //
    // UDP handlers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    // The length of recv context used by MsQuic.
    //
    size_t ClientRecvContextLength;

    //
    // The proc count to create per proc datapath state.
    //
    uint32_t ProcCount;

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT ProcContexts[];

} CXPLAT_DATAPATH;

void*
CxPlatDataPathWorkerThread(
    _In_ void* Context
    );

QUIC_STATUS
CxPlatSocketSendInternal(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN IsPendedSend
    );

void
CxPlatProcessorContextUninitialize(
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    struct kevent Event = {0};
    EV_SET(&Event, ProcContext->KqueueFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, NULL);
    kevent(ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);
    CxPlatEventWaitForever(ProcContext->CompletionEvent);
    CxPlatEventUninitialize(ProcContext->CompletionEvent);

    close(ProcContext->KqueueFd);

    CxPlatPoolUninitialize(&ProcContext->RecvBlockPool);
    CxPlatPoolUninitialize(&ProcContext->LargeSendBufferPool);
    CxPlatPoolUninitialize(&ProcContext->SendBufferPool);
    CxPlatPoolUninitialize(&ProcContext->SendDataPool);
}

QUIC_STATUS
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t Index,
    _Out_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int KqueueFd = INVALID_SOCKET;
    uint32_t RecvPacketLength = 0;

    CXPLAT_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(CXPLAT_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    ProcContext->Index = Index;
    CxPlatPoolInitialize(
        TRUE,
        RecvPacketLength,
        QUIC_POOL_DATA,
        &ProcContext->RecvBlockPool);
    CxPlatPoolInitialize(
        TRUE,
        MAX_UDP_PAYLOAD_LENGTH,
        QUIC_POOL_DATA,
        &ProcContext->SendBufferPool);
    CxPlatPoolInitialize(
        TRUE,
        CXPLAT_LARGE_SEND_BUFFER_SIZE,
        QUIC_POOL_DATA,
        &ProcContext->LargeSendBufferPool);
    CxPlatPoolInitialize(
        TRUE,
        sizeof(CXPLAT_SEND_DATA),
        QUIC_POOL_PLATFORM_SENDCTX,
        &ProcContext->SendDataPool);

    KqueueFd = kqueue();
    if (KqueueFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "kqueue() failed");
        goto Exit;
    }

    ProcContext->Datapath = Datapath;
    ProcContext->KqueueFd = KqueueFd;
    ProcContext->ThreadId = 0;

    //
    // Starting the thread must be done after the rest of the ProcContext
    // members have been initialized. Because the thread start routine accesses
    // ProcContext members.
    //

    CxPlatEventInitialize(&ProcContext->CompletionEvent, TRUE, FALSE);
    CxPlatWorkerRegisterDataPath((uint16_t)Index, ProcContext);

Exit:

    if (QUIC_FAILED(Status)) {
        if (KqueueFd != INVALID_SOCKET) {
            close(KqueueFd);
        }
        CxPlatPoolUninitialize(&ProcContext->RecvBlockPool);
        CxPlatPoolUninitialize(&ProcContext->LargeSendBufferPool);
        CxPlatPoolUninitialize(&ProcContext->SendBufferPool);
        CxPlatPoolUninitialize(&ProcContext->SendDataPool);
    }

    return Status;
}

QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ CXPLAT_DATAPATH_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    UNREFERENCED_PARAMETER(TcpCallbacks);
    UNREFERENCED_PARAMETER(Config);
    if (NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    size_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
            CxPlatProcMaxCount() * sizeof(CXPLAT_DATAPATH_PROC_CONTEXT);

    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(Datapath, DatapathLength);
    if (UdpCallbacks) {
        Datapath->UdpHandlers = *UdpCallbacks;
    }
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = 1; //CxPlatProcMaxCount(); // Darwin only supports a single receiver
    Datapath->MaxSendBatchSize = CXPLAT_MAX_BATCH_SEND;
    CxPlatRundownInitialize(&Datapath->BindingsRundown);

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        Status = CxPlatProcessorContextInitialize(Datapath, i, &Datapath->ProcContexts[i]);
        if (QUIC_FAILED(Status)) {
            Datapath->Shutdown = TRUE;
            for (uint32_t j = 0; j < i; j++) {
                CxPlatProcessorContextUninitialize(&Datapath->ProcContexts[j]);
            }
            goto Exit;
        }
    }

    *NewDataPath = Datapath;
    Datapath = NULL;

Exit:

    if (Datapath != NULL) {
        CxPlatRundownUninitialize(&Datapath->BindingsRundown);
        CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
    }

    return Status;
}

void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

    CxPlatRundownReleaseAndWait(&Datapath->BindingsRundown);

    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatProcessorContextUninitialize(&Datapath->ProcContexts[i]);
    }

    CxPlatRundownUninitialize(&Datapath->BindingsRundown);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return Datapath->Features;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

CXPLAT_DATAPATH_RECV_BLOCK*
CxPlatDataPathAllocRecvBlock(
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* DatapathProc
    )
{
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        CxPlatPoolAlloc(&DatapathProc->RecvBlockPool);
    if (RecvBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH_RECV_BLOCK",
            0);
    } else {
        CxPlatZeroMemory(RecvBlock, sizeof(*RecvBlock));
        RecvBlock->OwningPool = &DatapathProc->RecvBlockPool;
        RecvBlock->RecvPacket.Buffer = RecvBlock->Buffer;
        RecvBlock->RecvPacket.Allocated = TRUE;
    }
    return RecvBlock;
}

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
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *Addresses = NULL;
    *AddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *GatewayAddresses = NULL;
    *GatewayAddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
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

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//

QUIC_STATUS
CxPlatSocketContextInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    int Flags = 0;
    int ForceIpv4 = RemoteAddress && RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET;
    QUIC_ADDR MappedAddress = {0};
    socklen_t AssignedLocalAddressLength = 0;

    CXPLAT_SOCKET* Binding = SocketContext->Binding;

    //
    // Create datagram socket. We will use dual-mode sockets everywhere when we can.
    // There is problem with receiving PKTINFO on dual-mode when binded and connect to IP4 endpoints.
    // For that case we use AF_INET.
    //
    SocketContext->SocketFd =
        socket(
            ForceIpv4 ? AF_INET : AF_INET6,
            SOCK_DGRAM,
            IPPROTO_UDP);
    if (SocketContext->SocketFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket() failed");
        goto Exit;
    }

    //
    // Set dual (IPv4 & IPv6) socket mode unless we operate in pure IPv4 mode
    //
    if (!ForceIpv4) {
        Option = FALSE;
        Result =
            setsockopt(
                SocketContext->SocketFd,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (const void*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(IPV6_V6ONLY) failed");
            goto Exit;
        }
    }

    //
    // Set non blocking mode
    //
    Flags =
        fcntl(
            SocketContext->SocketFd,
            F_GETFL,
            NULL);
    if (Flags < 0) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "fcntl(F_GETFL) failed");
        goto Exit;
    }

    Flags |= O_NONBLOCK;
    Result =
        fcntl(
            SocketContext->SocketFd,
            F_SETFL,
            Flags);
    if (Result < 0) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "fcntl(F_SETFL) failed");
        goto Exit;
    }

    //
    // Set DON'T FRAG socket option.
    //
    // IP_DONTFRAG is not supported on macOS.
    // This may be re-visited on other kqueue systems like FreeBSD.
    // IPv6 does not support fragmentation so no work there.
    //

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            ForceIpv4 ? IPPROTO_IP : IPPROTO_IPV6,
            ForceIpv4 ? IP_RECVPKTINFO : IPV6_RECVPKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVPKTINFO) failed");
        goto Exit;
    }

    //
    // Set socket option to receive TOS (= DSCP + ECN) information from the
    // incoming packet.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            ForceIpv4 ? IPPROTO_IP : IPPROTO_IPV6,
            ForceIpv4 ? IP_RECVTOS :IPV6_RECVTCLASS,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_RECVTCLASS) failed");
        goto Exit;
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //
    // Option = INT32_MAX;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         SOL_SOCKET,
    //         SO_RCVBUF,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTracgdfgfdeEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(SO_RCVBUF) failed");
    //     goto Exit;
    // }

    //
    // bind() to local port if we need to. This is not necessary if we call connect
    // afterward and there is no ask for particular source address or port.
    // connect() will resolve that together in single system call.
    //
    if (!RemoteAddress || Binding->LocalAddress.Ipv6.sin6_port || !QuicAddrIsWildCard(&Binding->LocalAddress)) {
        CxPlatCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }

        // If we're going to be connecting, we need to bind to the correct local address family.
        if ((RemoteAddress && LocalAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) || ForceIpv4) {
            MappedAddress.Ipv4.sin_family = AF_INET;
            MappedAddress.Ipv4.sin_port = Binding->LocalAddress.Ipv4.sin_port;
            // For Wildcard address we only need to copy port.
            // If address is (unlikely) specified it needs to be IPv4 or mappedV4 since destination is IPv4.
            if (!QuicAddrIsWildCard(&Binding->LocalAddress)) {
                if (Binding->LocalAddress.Ip.sa_family == QUIC_ADDRESS_FAMILY_INET6) {
                    CXPLAT_DBG_ASSERT(IN6_IS_ADDR_V4MAPPED(&Binding->LocalAddress.Ipv6.sin6_addr));
                    CxPlatConvertFromMappedV6( &Binding->LocalAddress, &MappedAddress);
                }
            }
        }

        Result =
            bind(
                SocketContext->SocketFd,
                &MappedAddress.Ip,
                ForceIpv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "bind failed");
            goto Exit;
        }
    }

    //
    // connect to RemoteAddress if provided.
    //
    if (RemoteAddress != NULL) {
        CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
        CxPlatConvertToMappedV6(RemoteAddress, &MappedAddress);

        if (ForceIpv4) {
            CxPlatConvertFromMappedV6(&MappedAddress, &MappedAddress);
        } else if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }

        Result =
            connect(
                SocketContext->SocketFd,
                &MappedAddress.Ip,
                ForceIpv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "connect failed");
            goto Exit;
        }

        Binding->Connected = TRUE;
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
    Result =
        getsockname(
            SocketContext->SocketFd,
            (struct sockaddr *)&MappedAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }
    CxPlatConvertToMappedV6(&MappedAddress, &Binding->LocalAddress);

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
        Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
    }

    return Status;
}

void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock != NULL) {
        CxPlatRecvDataReturn(&SocketContext->CurrentRecvBlock->RecvPacket);
    }

    while (!CxPlatListIsEmpty(&SocketContext->PendingSendDataHead)) {
        CxPlatSendDataFree(
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&SocketContext->PendingSendDataHead),
                CXPLAT_SEND_DATA,
                PendingSendLinkage));
    }

    close(SocketContext->SocketFd);

    CxPlatRundownRelease(&SocketContext->Binding->Rundown);
}

void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    struct kevent DeleteEvent = {0};
    EV_SET(&DeleteEvent, SocketContext->SocketFd, EVFILT_READ, EV_DELETE, 0, 0, (void*)SocketContext);
    kevent(SocketContext->ProcContext->KqueueFd, &DeleteEvent, 1, NULL, 0, NULL);

    if (CxPlatCurThreadID() != SocketContext->ProcContext->ThreadId) {
        struct kevent Event = {0};
        EV_SET(&Event, SocketContext->SocketFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, (void*)SocketContext);
        kevent(SocketContext->ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);
    } else {
        CxPlatSocketContextUninitializeComplete(SocketContext);
    }
}

QUIC_STATUS
CxPlatSocketContextPrepareReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            CxPlatDataPathAllocRecvBlock(SocketContext->ProcContext);
        if (SocketContext->CurrentRecvBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_DATAPATH_RECV_BLOCK",
                0);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.BufferLength = SocketContext->RecvIov.iov_len;
    SocketContext->CurrentRecvBlock->RecvPacket.Route = &SocketContext->CurrentRecvBlock->Route;

    CxPlatZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    CxPlatZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvBlock->RecvPacket.Route->RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvBlock->RecvPacket.Route->RemoteAddress);
    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;
    SocketContext->RecvMsgHdr.msg_control = SocketContext->RecvMsgControl;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControl);
    SocketContext->RecvMsgHdr.msg_flags = 0;

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatSocketContextStartReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = CxPlatSocketContextPrepareReceive(SocketContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    struct kevent Event = {0};
    EV_SET(
        &Event, SocketContext->SocketFd,
        EVFILT_READ, EV_ADD | EV_ENABLE,
        0,
        0,
        (void*)SocketContext);
    int Ret =
        kevent(
            SocketContext->ProcContext->KqueueFd,
            &Event,
            1,
            NULL,
            0,
            NULL);
    if (Ret < 0) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "kevent failed");

        //
        // Return any allocations
        //
        if (SocketContext->CurrentRecvBlock != NULL) {
            CxPlatRecvDataReturn(&SocketContext->CurrentRecvBlock->RecvPacket);
        }

        goto Error;
    }

Error:

    return Status;
}

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ ssize_t BytesTransferred
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);
    CXPLAT_RECV_DATA* RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;

    BOOLEAN FoundLocalAddr = FALSE;
    BOOLEAN FoundTOS = FALSE;
    QUIC_ADDR* LocalAddr = &RecvPacket->Route->LocalAddress;
    if (LocalAddr->Ipv6.sin6_family == AF_INET6) {
        LocalAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    QUIC_ADDR* RemoteAddr = &RecvPacket->Route->RemoteAddress;
    if (RemoteAddr->Ipv6.sin6_family == AF_INET6) {
        RemoteAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);
    }

    RecvPacket->TypeOfService = 0;

    struct cmsghdr *CMsg;
    for (CMsg = CMSG_FIRSTHDR(&SocketContext->RecvMsgHdr);
         CMsg != NULL;
         CMsg = CMSG_NXTHDR(&SocketContext->RecvMsgHdr, CMsg)) {

        if (CMsg->cmsg_level == IPPROTO_IPV6) {
            if (CMsg->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
                LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
                LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                CxPlatConvertFromMappedV6(LocalAddr, LocalAddr);

                LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                FoundLocalAddr = TRUE;
            } else if (CMsg->cmsg_type == IPV6_TCLASS) {
                RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                FoundTOS = TRUE;
            }
        } else if (CMsg->cmsg_level == IPPROTO_IP) {
            if (CMsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
                LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
                LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
                LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                FoundLocalAddr = TRUE;
            } else if (CMsg->cmsg_type == IP_TOS || CMsg->cmsg_type == IP_RECVTOS) {
                RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                FoundTOS = TRUE;
            }
        }
    }

    CXPLAT_FRE_ASSERT(FoundLocalAddr);
    CXPLAT_FRE_ASSERT(FoundTOS);

    QuicTraceEvent(
        DatapathRecv,
        "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
        SocketContext->Binding,
        (uint32_t)BytesTransferred,
        (uint32_t)BytesTransferred,
        CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

    CXPLAT_DBG_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    RecvPacket->PartitionIndex = SocketContext->ProcContext->Index;

    if (!SocketContext->Binding->PcpBinding) {
        CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath->UdpHandlers.Receive);
        SocketContext->Binding->Datapath->UdpHandlers.Receive(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            RecvPacket);
    } else {
        CxPlatPcpRecvCallback(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            RecvPacket);
    }

    int32_t RetryCount = 0;
    do {
        Status = CxPlatSocketContextPrepareReceive(SocketContext);
    } while (!QUIC_SUCCEEDED(Status) && ++RetryCount < 10);

    if (!QUIC_SUCCEEDED(Status)) {
        CXPLAT_DBG_ASSERT(Status == QUIC_STATUS_OUT_OF_MEMORY);
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "CxPlatSocketContextPrepareReceive failed multiple times. Receive will no longer work.");
    }
}

//
// N.B Requires SocketContext->PendingSendDataLock to be locked.
//
void
CxPlatSocketContextPendSend(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (LocalAddress != NULL) {
        CxPlatCopyMemory(
            &SendData->LocalAddress,
            LocalAddress,
            sizeof(*LocalAddress));
        SendData->Bind = TRUE;
    }

    CxPlatCopyMemory(
        &SendData->RemoteAddress,
        RemoteAddress,
        sizeof(*RemoteAddress));

    //
    // This is a new send that wasn't previously pended. Add it to the end
    // of the queue.
    //
    CxPlatListInsertTail(
        &SocketContext->PendingSendDataHead,
        &SendData->PendingSendLinkage);
}

QUIC_STATUS
CxPlatSocketContextSendComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SEND_DATA* SendData = NULL;

    // Disable kqueue already disables events

    CxPlatLockAcquire(&SocketContext->PendingSendDataLock);
    if (!CxPlatListIsEmpty(&SocketContext->PendingSendDataHead)) {
        SendData =
            CXPLAT_CONTAINING_RECORD(
                SocketContext->PendingSendDataHead.Flink,
                CXPLAT_SEND_DATA,
                PendingSendLinkage);
    }
    CxPlatLockRelease(&SocketContext->PendingSendDataLock);
    if (SendData == NULL) {
        return Status;
    }

    do {
        Status =
            CxPlatSocketSendInternal(
                SocketContext->Binding,
                SendData->Bind ? &SendData->LocalAddress : NULL,
                &SendData->RemoteAddress,
                SendData,
                TRUE);
        CxPlatLockAcquire(&SocketContext->PendingSendDataLock);
        if (Status != QUIC_STATUS_PENDING) {
            CxPlatListRemoveHead(&SocketContext->PendingSendDataHead);
            CxPlatSendDataFree(SendData);
            if (!CxPlatListIsEmpty(&SocketContext->PendingSendDataHead)) {
                SendData =
                    CXPLAT_CONTAINING_RECORD(
                        SocketContext->PendingSendDataHead.Flink,
                        CXPLAT_SEND_DATA,
                        PendingSendLinkage);
            } else {
                SendData = NULL;
            }
        }
        CxPlatLockRelease(&SocketContext->PendingSendDataLock);
    } while (Status == QUIC_STATUS_SUCCESS && SendData != NULL);

    return Status;
}

void
CxPlatSocketContextProcessEvents(
    _In_ struct kevent* Event
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext = (CXPLAT_SOCKET_CONTEXT*)Event->udata;
    CXPLAT_DBG_ASSERT(Event->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));
    if (Event->filter == EVFILT_USER) {
        CXPLAT_DBG_ASSERT(SocketContext->Binding->Shutdown);
        CxPlatSocketContextUninitializeComplete(SocketContext);
        return;
    }

    if (Event->filter == EVFILT_READ) {
        //
        // Read up to 4 receives before moving to another event.
        //
        for (int i = 0; i < 4; i++) {
            CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);

            ssize_t Ret =
                recvmsg(
                    SocketContext->SocketFd,
                    &SocketContext->RecvMsgHdr,
                    0);
            if (Ret < 0) {
                int ErrNum = errno;
                if (ErrNum != EAGAIN && ErrNum != EWOULDBLOCK) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "recvmsg failed");

                    //
                    // The read can also return unreachable events. There is no
                    // flag to detect this state other then to call recvmsg.
                    // Send unreachable notification to MsQuic if any related
                    // errors were received.
                    //
                    if (ErrNum == ECONNREFUSED ||
                        ErrNum == EHOSTUNREACH ||
                        ErrNum == ENETUNREACH) {
                        if (!SocketContext->Binding->PcpBinding) {
                            SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                                SocketContext->Binding,
                                SocketContext->Binding->ClientContext,
                                &SocketContext->Binding->RemoteAddress);
                        }
                    }
                }
                break;
            }
            CxPlatSocketContextRecvComplete(SocketContext, Ret);
        }
    }

    if (Event->filter == EVFILT_WRITE) {
        CxPlatSocketContextSendComplete(SocketContext);
    }
}

//
// Datapath binding interface.
//

QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;
    int32_t SuccessfulStartReceives = -1;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & CXPLAT_SOCKET_FLAG_PCP);

    uint32_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;
    uint32_t CurrentProc = CxPlatProcCurrentNumber() % Datapath->ProcCount;
    CXPLAT_FRE_ASSERT(SocketCount > 0);
    size_t BindingLength =
        sizeof(CXPLAT_SOCKET) +
        SocketCount * sizeof(CXPLAT_SOCKET_CONTEXT);

    CXPLAT_SOCKET* Binding =
        (CXPLAT_SOCKET*)CXPLAT_ALLOC_PAGED(BindingLength, QUIC_POOL_SOCKET);
    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            BindingLength);
        goto Exit;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    CxPlatZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = Config->CallbackContext;
    Binding->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    Binding->Mtu = CXPLAT_MAX_MTU;
    CxPlatRundownInitialize(&Binding->Rundown);
    if (Config->LocalAddress) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET;
        Binding->SocketContexts[i].RecvIov.iov_len =
            Binding->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
        Binding->SocketContexts[i].ProcContext = &Datapath->ProcContexts[IsServerSocket ? i : CurrentProc];
        CxPlatListInitializeHead(&Binding->SocketContexts[i].PendingSendDataHead);
        CxPlatLockInitialize(&Binding->SocketContexts[i].PendingSendDataLock);
        CxPlatRundownAcquire(&Binding->Rundown);
    }

    CxPlatRundownAcquire(&Datapath->BindingsRundown);
    if (Config->Flags & CXPLAT_SOCKET_FLAG_PCP) {
        Binding->PcpBinding = TRUE;
    }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextInitialize(
                &Binding->SocketContexts[i],
                Config->LocalAddress,
                Config->RemoteAddress);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    CxPlatConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (Config->RemoteAddress != NULL) {
        Binding->RemoteAddress = *Config->RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    SuccessfulStartReceives = 0;
    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextStartReceive(
                &Binding->SocketContexts[i]);
        if (QUIC_FAILED(Status)) {
            SuccessfulStartReceives = (int32_t)i;
            goto Exit;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            QuicTraceEvent(
                DatapathDestroyed,
                "[data][%p] Destroyed",
                Binding);

            if (SuccessfulStartReceives >= 0) {
                uint32_t CurrentSocket = 0;
                Binding->Shutdown = TRUE;

                //
                // First shutdown any sockets that fully started
                //
                for (; CurrentSocket < (uint32_t)SuccessfulStartReceives; CurrentSocket++) {
                    CxPlatSocketContextUninitialize(&Binding->SocketContexts[CurrentSocket]);
                }
                //
                // Then shutdown any sockets that failed to start
                //
                for (; CurrentSocket < SocketCount; CurrentSocket++) {
                    CxPlatSocketContextUninitializeComplete(&Binding->SocketContexts[CurrentSocket]);
                }
            } else {
                //
                // No sockets fully started. Only uninitialize static things
                //
                for (uint32_t i = 0; i < SocketCount; i++) {
                    CXPLAT_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];
                    if (SocketContext->SocketFd != INVALID_SOCKET) {
                        close(SocketContext->SocketFd);
                    }
                    CxPlatRundownRelease(&Binding->Rundown);
                }
            }
            CxPlatRundownReleaseAndWait(&Binding->Rundown);
            CxPlatRundownRelease(&Datapath->BindingsRundown);
            CxPlatRundownUninitialize(&Binding->Rundown);
            for (uint32_t i = 0; i < SocketCount; i++) {
                CxPlatLockUninitialize(&Binding->SocketContexts[i].PendingSendDataLock);
            }
            CXPLAT_FREE(Binding, QUIC_POOL_SOCKET);
            Binding = NULL;
        }
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
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Socket);
    return QUIC_STATUS_NOT_SUPPORTED;
}

void
CxPlatSocketDelete(
    _Inout_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    QuicTraceEvent(
        DatapathDestroyed,
        "[data][%p] Destroyed",
        Socket);

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    Socket->Shutdown = TRUE;
    uint32_t SocketCount = Socket->HasFixedRemoteAddress ? 1 : Socket->Datapath->ProcCount;
    for (uint32_t i = 0; i < SocketCount; ++i) {
        CxPlatSocketContextUninitialize(
            &Socket->SocketContexts[i]);
    }

    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    CxPlatRundownRelease(&Socket->Datapath->BindingsRundown);

    CxPlatRundownUninitialize(&Socket->Rundown);
    for (uint32_t i = 0; i < SocketCount; i++) {
        CxPlatLockUninitialize(&Socket->SocketContexts[i].PendingSendDataLock);
    }
    CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
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

QUIC_STATUS
CxPlatSocketSetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatSocketGetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Packet
    )
{
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        (CXPLAT_DATAPATH_RECV_BLOCK*)
            ((char *)Packet - sizeof(CXPLAT_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const RecvData
    )
{
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        CXPLAT_CONTAINING_RECORD(RecvData, CXPLAT_DATAPATH_RECV_BLOCK, RecvPacket);

    return (CXPLAT_RECV_PACKET*)(RecvBlock + 1);
}

void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;
        CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
            CXPLAT_CONTAINING_RECORD(Datagram, CXPLAT_DATAPATH_RECV_BLOCK, RecvPacket);
        CxPlatPoolFree(RecvBlock->OwningPool, RecvBlock);
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
    UNREFERENCED_PARAMETER(Route);
    CXPLAT_DBG_ASSERT(Socket != NULL);

    CXPLAT_DATAPATH_PROC_CONTEXT* DatapathProc =
        &Socket->Datapath->ProcContexts[CxPlatProcCurrentNumber() % Socket->Datapath->ProcCount];

    CXPLAT_SEND_DATA* SendData =
        CxPlatPoolAlloc(&DatapathProc->SendDataPool);

    if (SendData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEND_DATA",
            0);
        goto Exit;
    }

    CxPlatZeroMemory(SendData, sizeof(*SendData));

    SendData->Owner = DatapathProc;
    SendData->ECN = ECN;
    SendData->SegmentSize =
        (Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)
            ? MaxPacketSize : 0;

Exit:
    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* DatapathProc = SendData->Owner;
    CXPLAT_POOL* BufferPool =
        SendData->SegmentSize > 0 ?
            &DatapathProc->LargeSendBufferPool : &DatapathProc->SendBufferPool;

    for (size_t i = 0; i < SendData->BufferCount; ++i) {
        CxPlatPoolFree(BufferPool, SendData->Buffers[i].Buffer);
    }

    CxPlatPoolFree(&DatapathProc->SendDataPool, SendData);
}

static
BOOLEAN
CxPlatSendDataCanAllocSendSegment(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    if (!SendData->ClientBuffer.Buffer) {
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(SendData->BufferCount > 0);

    uint64_t BytesAvailable =
        CXPLAT_LARGE_SEND_BUFFER_SIZE -
            SendData->Buffers[SendData->BufferCount - 1].Length -
            SendData->ClientBuffer.Length;

    return MaxBufferLength <= BytesAvailable;
}

static
BOOLEAN
CxPlatSendDataCanAllocSend(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    return
        (SendData->BufferCount < SendData->Owner->Datapath->MaxSendBatchSize) ||
        ((SendData->SegmentSize > 0) &&
            CxPlatSendDataCanAllocSendSegment(SendData, MaxBufferLength));
}

static
void
CxPlatSendDataFinalizeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->ClientBuffer.Length == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendData->BufferCount > 0) {
            CXPLAT_DBG_ASSERT(SendData->Buffers[SendData->BufferCount - 1].Length < UINT16_MAX);
            SendData->TotalSize +=
                SendData->Buffers[SendData->BufferCount - 1].Length;
        }
        return;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0 && SendData->BufferCount > 0);
    CXPLAT_DBG_ASSERT(SendData->ClientBuffer.Length > 0 && SendData->ClientBuffer.Length <= SendData->SegmentSize);
    CXPLAT_DBG_ASSERT(CxPlatSendDataCanAllocSendSegment(SendData, 0));

    //
    // Append the client's buffer segment to our internal send buffer.
    //
    SendData->Buffers[SendData->BufferCount - 1].Length +=
        SendData->ClientBuffer.Length;
    SendData->TotalSize += SendData->ClientBuffer.Length;

    if (SendData->ClientBuffer.Length == SendData->SegmentSize) {
        SendData->ClientBuffer.Buffer += SendData->SegmentSize;
        SendData->ClientBuffer.Length = 0;
    } else {
        //
        // The next segment allocation must create a new backing buffer.
        //
        SendData->ClientBuffer.Buffer = NULL;
        SendData->ClientBuffer.Length = 0;
    }
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendDataAllocDataBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ CXPLAT_POOL* BufferPool
    )
{
    CXPLAT_DBG_ASSERT(SendData->BufferCount < SendData->Owner->Datapath->MaxSendBatchSize);

    QUIC_BUFFER* Buffer = &SendData->Buffers[SendData->BufferCount];
    Buffer->Buffer = CxPlatPoolAlloc(BufferPool);
    if (Buffer->Buffer == NULL) {
        return NULL;
    }
    ++SendData->BufferCount;

    return Buffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendDataAllocPacketBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_BUFFER* Buffer =
        CxPlatSendDataAllocDataBuffer(SendData, &SendData->Owner->SendBufferPool);
    if (Buffer != NULL) {
        Buffer->Length = MaxBufferLength;
    }
    return Buffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendDataAllocSegmentBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= SendData->SegmentSize);

    if (CxPlatSendDataCanAllocSendSegment(SendData, MaxBufferLength)) {

        //
        // All clear to return the next segment of our contiguous buffer.
        //
        SendData->ClientBuffer.Length = MaxBufferLength;
        return &SendData->ClientBuffer;
    }

    QUIC_BUFFER* Buffer = CxPlatSendDataAllocDataBuffer(SendData, &SendData->Owner->LargeSendBufferPool);
    if (Buffer == NULL) {
        return NULL;
    }

    //
    // Provide a virtual QUIC_BUFFER to the client. Once the client has committed
    // to a final send size, we'll append it to our internal backing buffer.
    //
    Buffer->Length = 0;
    SendData->ClientBuffer.Buffer = Buffer->Buffer;
    SendData->ClientBuffer.Length = MaxBufferLength;

    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
    //CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

    CxPlatSendDataFinalizeSendBuffer(SendData);

    if (!CxPlatSendDataCanAllocSend(SendData, MaxBufferLength)) {
        return NULL;
    }

    if (SendData->SegmentSize == 0) {
        return CxPlatSendDataAllocPacketBuffer(SendData, MaxBufferLength);
    }
    return CxPlatSendDataAllocSegmentBuffer(SendData, MaxBufferLength);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    //
    // This must be the final send buffer; intermediate buffers cannot be freed.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT* DatapathProc = SendData->Owner;
#ifdef DEBUG
    uint8_t* TailBuffer = SendData->Buffers[SendData->BufferCount - 1].Buffer;
#endif

    if (SendData->SegmentSize == 0) {
#ifdef DEBUG
        CXPLAT_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);
#endif

        CxPlatPoolFree(&DatapathProc->SendBufferPool, Buffer->Buffer);
        --SendData->BufferCount;
    } else {
#ifdef DEBUG
        TailBuffer += SendData->Buffers[SendData->BufferCount - 1].Length;
        CXPLAT_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);
#endif

        if (SendData->Buffers[SendData->BufferCount - 1].Length == 0) {
            CxPlatPoolFree(&DatapathProc->LargeSendBufferPool, Buffer->Buffer);
            --SendData->BufferCount;
        }

        SendData->ClientBuffer.Buffer = NULL;
        SendData->ClientBuffer.Length = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return !CxPlatSendDataCanAllocSend(SendData, SendData->SegmentSize);
}

void
CxPlatSendDataComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketProc,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint64_t IoResult
    )
{
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Binding,
            IoResult,
            "sendmmsg completion");
    }

    // TODO to add TCP
    // if (SocketProc->Parent->Type != CXPLAT_SOCKET_UDP) {
    //     SocketProc->Parent->Datapath->TcpHandlers.SendComplete(
    //         SocketProc->Parent,
    //         SocketProc->Parent->ClientContext,
    //         IoResult,
    //         SendData->TotalSize);
    // }

    CxPlatSendDataFree(SendData);
}

QUIC_STATUS
CxPlatSocketSendInternal(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN IsPendedSend
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = NULL;
    ssize_t SentByteCount = 0;
    QUIC_ADDR MappedRemoteAddress = {0};
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;

    CXPLAT_STATIC_ASSERT(
        sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo),
        "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");

    char ControlBuffer[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))] = {0};

    CXPLAT_DBG_ASSERT(Socket != NULL && RemoteAddress != NULL && SendData != NULL);

    if (Socket->HasFixedRemoteAddress) {
        SocketContext = &Socket->SocketContexts[0];
    } else {
        uint32_t ProcNumber = CxPlatProcCurrentNumber() % Socket->Datapath->ProcCount;
        SocketContext = &Socket->SocketContexts[ProcNumber];
    }

    if (!IsPendedSend) {
        CxPlatSendDataFinalizeSendBuffer(SendData);
        for (size_t i = 0; i < SendData->BufferCount; ++i) {
            SendData->Iovs[i].iov_base = SendData->Buffers[i].Buffer;
            SendData->Iovs[i].iov_len = SendData->Buffers[i].Length;
        }
        QuicTraceEvent(
            DatapathSend,
            "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
            Socket,
            SendData->TotalSize,
            SendData->BufferCount,
            SendData->SegmentSize,
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

        //
        // Check to see if we need to pend.
        //
        CxPlatLockAcquire(&SocketContext->PendingSendDataLock);
        if (!CxPlatListIsEmpty(&SocketContext->PendingSendDataHead)) {
            CxPlatSocketContextPendSend(
                SocketContext,
                SendData,
                LocalAddress,
                RemoteAddress);
            SendPending = TRUE;
        }
        CxPlatLockRelease(&SocketContext->PendingSendDataLock);
        if (SendPending) {
            Status = QUIC_STATUS_PENDING;
            goto Exit;
        }
    }
    //
    // Map V4 address to dual-stack socket format.
    //
    CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

    if (MappedRemoteAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedRemoteAddress.Ipv6.sin6_family = AF_INET6;
    }

    struct msghdr Mhdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = SendData->Iovs,
        .msg_iovlen = SendData->BufferCount,
        .msg_control = ControlBuffer,
        .msg_controllen = CMSG_SPACE(sizeof(int)),
        .msg_flags = 0
    };

    CMsg = CMSG_FIRSTHDR(&Mhdr);
    CMsg->cmsg_level = RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET ? IPPROTO_IP : IPPROTO_IPV6;
    CMsg->cmsg_type = RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET ? IP_TOS : IPV6_TCLASS;
    CMsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(CMsg) = SendData->ECN;

    if (!Socket->Connected) {
        Mhdr.msg_name = &MappedRemoteAddress;
        Mhdr.msg_namelen = sizeof(MappedRemoteAddress);
        Mhdr.msg_controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
        CMsg = CMSG_NXTHDR(&Mhdr, CMsg);
        CXPLAT_DBG_ASSERT(LocalAddress != NULL);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        if (RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
            // TODO: Use Ipv4 instead of Ipv6.
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
        } else {
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
        }
    }

    SentByteCount = sendmsg(SocketContext->SocketFd, &Mhdr, 0);

    if (SentByteCount < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!IsPendedSend) {
                CxPlatLockAcquire(&SocketContext->PendingSendDataLock);
                CxPlatSocketContextPendSend(
                    SocketContext,
                    SendData,
                    LocalAddress,
                    RemoteAddress);
                CxPlatLockRelease(&SocketContext->PendingSendDataLock);
            }
            SendPending = TRUE;
            struct kevent Event = {0};
            EV_SET(&Event, SocketContext->SocketFd, EVFILT_WRITE, EV_ADD | EV_ONESHOT | EV_CLEAR, 0, 0, (void *)SocketContext);
            int Ret =
                kevent(
                    SocketContext->ProcContext->KqueueFd,
                    &Event,
                    1,
                    NULL,
                    0,
                    NULL);
            if (Ret < 1) {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "kevent failed");
                goto Exit;
            }
            Status = QUIC_STATUS_PENDING;
            goto Exit;
        } else {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                Status,
                "sendmsg failed");

            //
            // Unreachable events can sometimes come synchronously.
            // Send unreachable notification to MsQuic if any related
            // errors were received.
            //
            if (Status == ECONNREFUSED ||
                Status == EHOSTUNREACH ||
                Status == ENETUNREACH) {
                if (!SocketContext->Binding->PcpBinding) {
                    SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                        SocketContext->Binding,
                        SocketContext->Binding->ClientContext,
                        &SocketContext->Binding->RemoteAddress);
                }
            }
            goto Exit;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (!SendPending && !IsPendedSend) {
        // TODO Add TCP when necessary
        CxPlatSendDataComplete(SocketContext, SendData, Status);
    }

    return Status;
}

QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    UNREFERENCED_PARAMETER(IdealProcessor);
    QUIC_STATUS Status =
        CxPlatSocketSendInternal(
            Socket,
            &Route->LocalAddress,
            &Route->RemoteAddress,
            SendData,
            FALSE);
    if (Status == QUIC_STATUS_PENDING) {
        Status = QUIC_STATUS_SUCCESS;
    }
    return Status;
}

uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
}

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)                              \
    ({                                                              \
        long int FailureRetryResult = 0;                            \
        do {                                                        \
            FailureRetryResult = (long int)(expression);            \
        } while ((FailureRetryResult == -1L) && (errno == EINTR));  \
        FailureRetryResult;                                         \
    })
#endif

void
CxPlatDataPathWake(
    _In_ void* Context
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = (CXPLAT_DATAPATH_PROC_CONTEXT*)Context;
    struct kevent Event = {0};
    EV_SET(&Event, ProcContext->KqueueFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, NULL);
    kevent(ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);
}

void
CxPlatDataPathRunEC(
    _In_ void** Context,
    _In_ CXPLAT_THREAD_ID CurThreadId,
    _In_ uint32_t WaitTime
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT** EcProcContext = (CXPLAT_DATAPATH_PROC_CONTEXT**)Context;
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = *EcProcContext;
    CXPLAT_DBG_ASSERT(ProcContext->Datapath != NULL);

    int Kqueue = ProcContext->KqueueFd;
    const size_t EventListMax = 16; // TODO: Experiment.
    struct kevent EventList[EventListMax];

    ProcContext->ThreadId = CurThreadId;

    struct timespec Timeout = {0, 0};
    if (WaitTime != UINT32_MAX) {
        Timeout.tv_sec += (WaitTime / CXPLAT_MS_PER_SECOND);
        Timeout.tv_nsec += ((WaitTime % CXPLAT_MS_PER_SECOND) * CXPLAT_NANOSEC_PER_MS);
    }

    int ReadyEventCount =
        TEMP_FAILURE_RETRY(
            kevent(
                Kqueue,
                NULL,
                0,
                EventList,
                EventListMax,
                WaitTime == UINT32_MAX ? NULL : &Timeout));

    if (ProcContext->Datapath->Shutdown) {
        *Context = NULL;
        CxPlatEventSet(ProcContext->CompletionEvent);
        return;
    }

    if (ReadyEventCount == 0) {
        return; // Wake for timeout.
    }

    CXPLAT_FRE_ASSERT(ReadyEventCount >= 0);
    for (int i = 0; i < ReadyEventCount; i++) {
        if (EventList[i].udata != NULL) {
            CxPlatSocketContextProcessEvents(&EventList[i]);
        }
    }
}
