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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/time.h>
#include <fcntl.h>
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
    // Represents the address (source and destination) information of the
    // packet.
    //
    CXPLAT_TUPLE Tuple;

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

} CXPLAT_SEND_DATA;

//
// Socket context.
//
typedef struct CXPLAT_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    CXPLAT_SOCKET* Binding;

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
    CXPLAT_LIST_ENTRY PendingSendContextHead;

    //
    // Lock around the PendingSendContext list.
    //
    CXPLAT_LOCK PendingSendContextLock;

} CXPLAT_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct CXPLAT_SOCKET {

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
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_RUNDOWN_REF Rundown;

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
    // The kqueue wait thread.
    //
    CXPLAT_THREAD KqueueWaitThread;

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
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendContextPool;

} CXPLAT_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {
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
    // A reference rundown on the datapath binding.
    //
    CXPLAT_RUNDOWN_REF BindingsRundown;

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
        sizeof(CXPLAT_SEND_DATA),
        QUIC_POOL_PLATFORM_SENDCTX,
        &ProcContext->SendContextPool);

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

    //
    // Starting the thread must be done after the rest of the ProcContext
    // members have been initialized. Because the thread start routine accesses
    // ProcContext members.
    //

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        CXPLAT_THREAD_FLAG_SET_AFFINITIZE,
        (uint16_t)Index,
        NULL,
        CxPlatDataPathWorkerThread,
        ProcContext
    };

    Status = CxPlatThreadCreate(&ThreadConfig, &ProcContext->KqueueWaitThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate failed");
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {
        if (KqueueFd != INVALID_SOCKET) {
            close(KqueueFd);
        }
        CxPlatPoolUninitialize(&ProcContext->RecvBlockPool);
        CxPlatPoolUninitialize(&ProcContext->SendBufferPool);
        CxPlatPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}

void
CxPlatProcessorContextUninitialize(
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    struct kevent Event = {0};
    EV_SET(&Event, ProcContext->KqueueFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, NULL);
    kevent(ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);
    CxPlatThreadWait(&ProcContext->KqueueWaitThread);
    CxPlatThreadDelete(&ProcContext->KqueueWaitThread);

    close(ProcContext->KqueueFd);

    CxPlatPoolUninitialize(&ProcContext->RecvBlockPool);
    CxPlatPoolUninitialize(&ProcContext->SendBufferPool);
    CxPlatPoolUninitialize(&ProcContext->SendContextPool);
}

QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    UNREFERENCED_PARAMETER(TcpCallbacks);
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
    UNREFERENCED_PARAMETER(Datapath);
    return 0;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    //
    // The windows implementation returns TRUE only if GSO is supported and
    // this DAL implementation doesn't support GSO currently.
    //
    return FALSE;
}

CXPLAT_DATAPATH_RECV_BLOCK*
CxPlatDataPathAllocRecvBlock(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ProcIndex
    )
{
    CXPLAT_DATAPATH_RECV_BLOCK* RecvBlock =
        CxPlatPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvBlockPool);
    if (RecvBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH_RECV_BLOCK",
            0);
    } else {
        CxPlatZeroMemory(RecvBlock, sizeof(*RecvBlock));
        RecvBlock->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvBlockPool;
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
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = QUIC_STATUS_DNS_RESOLUTION_ERROR;

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
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
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

    UNREFERENCED_PARAMETER(ProcContext);

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
    // The port may be shared across processors.
    // Even if not, this is probably cheap.
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_REUSEADDR) failed");
        goto Exit;
    }


    //
    // bind() to local port if we need to. This is not necessary if we call connect afterward and there is no ask for particular
    // source address or port. connect() will resolve that together in single system call.
    if (!RemoteAddress || Binding->LocalAddress.Ipv6.sin6_port || !QuicAddrIsWildCard(&Binding->LocalAddress)) {
        CxPlatCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }

        if (ForceIpv4) { // remote exists
            MappedAddress.Ipv4.sin_family = AF_INET;
        // TBD assume wildcard for now!
            MappedAddress.Ipv4.sin_port = Binding->LocalAddress.Ipv4.sin_port;
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

        if (ForceIpv4)
        {
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
//printf("%s:%d: connect failed with %s %s : %d\n" , __func__, __LINE__,  strerror(errno), inet_ntop(MappedAddress.Ip.sa_family, &MappedAddress.Ipv4.sin_addr, (char*)(&bu2), sizeof(bu2)), ntohs(MappedAddress.Ipv4.sin_port));
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
            (struct sockaddr *)&Binding->LocalAddress,
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
// TBD flip this with the call above!!!!!
    CxPlatConvertToMappedV6(&Binding->LocalAddress, &MappedAddress);
    Binding->LocalAddress = MappedAddress;

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
        Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }

    //
    // We have socket with endpoints set. Let's set options we need.
    //

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
    if (Flags < 0) {
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

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
    }

    return Status;
}

void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    struct kevent Event = {0};
    EV_SET(&Event, SocketContext->SocketFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, (void*)SocketContext);
    kevent(ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);
}

void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    UNREFERENCED_PARAMETER(ProcContext);
    if (SocketContext->CurrentRecvBlock != NULL) {
        CxPlatRecvDataReturn(&SocketContext->CurrentRecvBlock->RecvPacket);
    }

    while (!CxPlatListIsEmpty(&SocketContext->PendingSendContextHead)) {
        CxPlatSendDataFree(
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&SocketContext->PendingSendContextHead),
                CXPLAT_SEND_DATA,
                PendingSendLinkage));
    }

    close(SocketContext->SocketFd);

    CxPlatRundownRelease(&SocketContext->Binding->Rundown);
}

QUIC_STATUS
CxPlatSocketContextPrepareReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            CxPlatDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                CxPlatProcCurrentNumber() % SocketContext->Binding->Datapath->ProcCount);
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
    SocketContext->CurrentRecvBlock->RecvPacket.Tuple = &SocketContext->CurrentRecvBlock->Tuple;

    CxPlatZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    CxPlatZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress);
    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;
    SocketContext->RecvMsgHdr.msg_control = SocketContext->RecvMsgControl;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControl);
    SocketContext->RecvMsgHdr.msg_flags = 0;

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatSocketContextStartReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ int KqueueFd
    )
{
    QUIC_STATUS Status = CxPlatSocketContextPrepareReceive(SocketContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    struct kevent Event = {0};
    EV_SET(
        &Event, SocketContext->SocketFd,
        EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR,
        0,
        0,
        (void*)SocketContext);
    int Ret =
        kevent(
            KqueueFd,
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
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
    }

    return Status;
}

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ ssize_t BytesTransferred
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);
    CXPLAT_RECV_DATA* RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;

    BOOLEAN FoundLocalAddr = FALSE;
    BOOLEAN FoundTOS = FALSE;
    QUIC_ADDR* LocalAddr = &RecvPacket->Tuple->LocalAddress;
    if (LocalAddr->Ipv6.sin6_family == AF_INET6) {
        LocalAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    QUIC_ADDR* RemoteAddr = &RecvPacket->Tuple->RemoteAddress;
    if (RemoteAddr->Ipv6.sin6_family == AF_INET6) {
        RemoteAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    //CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

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
                //CxPlatConvertFromMappedV6(LocalAddr, LocalAddr);

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
        CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

    CXPLAT_DBG_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    RecvPacket->PartitionIndex = ProcContext->Index;

    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath->UdpHandlers.Receive);
    SocketContext->Binding->Datapath->UdpHandlers.Receive(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RecvPacket);

    Status = CxPlatSocketContextPrepareReceive(SocketContext);

    //
    // Prepare can only fail under low memory condition. Treat it as a fatal
    // error.
    //
    CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(Status));
}

//
// N.B Requires SocketContext->PendingSendContextLock to be locked.
//
void
CxPlatSocketContextPendSend(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (LocalAddress != NULL) {
        CxPlatCopyMemory(
            &SendContext->LocalAddress,
            LocalAddress,
            sizeof(*LocalAddress));
        SendContext->Bind = TRUE;
    }

    CxPlatCopyMemory(
        &SendContext->RemoteAddress,
        RemoteAddress,
        sizeof(*RemoteAddress));

    //
    // This is a new send that wasn't previously pended. Add it to the end
    // of the queue.
    //
    CxPlatListInsertTail(
        &SocketContext->PendingSendContextHead,
        &SendContext->PendingSendLinkage);
}

QUIC_STATUS
CxPlatSocketContextSendComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SEND_DATA* SendContext = NULL;
    UNREFERENCED_PARAMETER(ProcContext);

    // Disable kqueue already disables events

    CxPlatLockAcquire(&SocketContext->PendingSendContextLock);
    if (!CxPlatListIsEmpty(&SocketContext->PendingSendContextHead)) {
        SendContext =
            CXPLAT_CONTAINING_RECORD(
                SocketContext->PendingSendContextHead.Flink,
                CXPLAT_SEND_DATA,
                PendingSendLinkage);
    }
    CxPlatLockRelease(&SocketContext->PendingSendContextLock);
    if (SendContext == NULL) {
        return Status;
    }

    do {
        Status =
            CxPlatSocketSendInternal(
                SocketContext->Binding,
                SendContext->Bind ? &SendContext->LocalAddress : NULL,
                &SendContext->RemoteAddress,
                SendContext,
                TRUE);
        CxPlatLockAcquire(&SocketContext->PendingSendContextLock);
        if (Status != QUIC_STATUS_PENDING) {
            CxPlatListRemoveHead(&SocketContext->PendingSendContextHead);
            CxPlatSendDataFree(SendContext);
            if (!CxPlatListIsEmpty(&SocketContext->PendingSendContextHead)) {
                SendContext =
                    CXPLAT_CONTAINING_RECORD(
                        SocketContext->PendingSendContextHead.Flink,
                        CXPLAT_SEND_DATA,
                        PendingSendLinkage);
            } else {
                SendContext = NULL;
            }
        }
        CxPlatLockRelease(&SocketContext->PendingSendContextLock);
    } while (Status == QUIC_STATUS_SUCCESS && SendContext != NULL);

    return Status;
}

void
CxPlatSocketContextProcessEvents(
    _In_ struct kevent* Event,
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext = (CXPLAT_SOCKET_CONTEXT*)Event->udata;
    CXPLAT_DBG_ASSERT(Event->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));
    if (Event->filter == EVFILT_USER) {
        CXPLAT_DBG_ASSERT(SocketContext->Binding->Shutdown);
        CxPlatSocketContextUninitializeComplete(SocketContext, ProcContext);
        return;
    }

    // TODO figure out what these mean
    // if (EPOLLERR & Events) {
    //     int ErrNum = 0;
    //     socklen_t OptLen = sizeof(ErrNum);
    //     ssize_t Ret =
    //         getsockopt(
    //             SocketContext->SocketFd,
    //             SOL_SOCKET,
    //             SO_ERROR,
    //             &ErrNum,
    //             &OptLen);
    //     if (Ret < 0) {
    //         QuicTracgdfgfdeEvent(
    //             DatapathErrorStatus,
    //             "[data][%p] ERROR, %u, %s.",
    //             SocketContext->Binding,
    //             errno,
    //             "getsockopt(SO_ERROR) failed");
    //     } else {
    //         QuicTracgdfgfdeEvent(
    //             DatapathErrorStatus,
    //             "[data][%p] ERROR, %u, %s.",
    //             SocketContext->Binding,
    //             ErrNum,
    //             "Socket error event");

    //         //
    //         // Send unreachable notification to MsQuic if any related
    //         // errors were received.
    //         //
    //         if (ErrNum == ECONNREFUSED ||
    //             ErrNum == EHOSTUNREACH ||
    //             ErrNum == ENETUNREACH) {
    //             SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
    //                 SocketContext->Binding,
    //                 SocketContext->Binding->ClientContext,
    //                 &SocketContext->Binding->RemoteAddress);
    //         }
    //     }
    // }

    if (Event->filter == EVFILT_READ) {
        while (TRUE) {
            CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);

            ssize_t Ret =
                recvmsg(
                    SocketContext->SocketFd,
                    &SocketContext->RecvMsgHdr,
                    0);
            if (Ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "recvmsg failed");
                }
                break;
            }
            CxPlatSocketContextRecvComplete(SocketContext, ProcContext, Ret);
        }
    }

    if (Event->filter == EVFILT_WRITE) {
        CxPlatSocketContextSendComplete(SocketContext, ProcContext);
    }
}

//
// Datapath binding interface.
//

QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsServerSocket = RemoteAddress == NULL;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL);

    uint32_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;
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
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    CxPlatZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->HasFixedRemoteAddress = (RemoteAddress != NULL);
    Binding->Mtu = CXPLAT_MAX_MTU;
    CxPlatRundownInitialize(&Binding->Rundown);
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET;
        Binding->SocketContexts[i].RecvIov.iov_len =
            Binding->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
        CxPlatListInitializeHead(&Binding->SocketContexts[i].PendingSendContextHead);
        CxPlatLockInitialize(&Binding->SocketContexts[i].PendingSendContextLock);
        CxPlatRundownAcquire(&Binding->Rundown);
    }

    CxPlatRundownAcquire(&Datapath->BindingsRundown);

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextInitialize(
                &Binding->SocketContexts[i],
                &Datapath->ProcContexts[i],
                LocalAddress,
                RemoteAddress);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    CxPlatConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextStartReceive(
                &Binding->SocketContexts[i],
                Datapath->ProcContexts[i].KqueueFd);
        if (QUIC_FAILED(Status)) {
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
            // TODO - Clean up socket contexts
            CxPlatRundownRelease(&Datapath->BindingsRundown);
            CxPlatRundownUninitialize(&Binding->Rundown);
            for (uint32_t i = 0; i < SocketCount; i++) {
                CxPlatLockUninitialize(&Binding->SocketContexts[i].PendingSendContextLock);
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
            &Socket->SocketContexts[i],
            &Socket->Datapath->ProcContexts[i]);
    }

    CxPlatRundownReleaseAndWait(&Socket->Rundown);
    CxPlatRundownRelease(&Socket->Datapath->BindingsRundown);

    CxPlatRundownUninitialize(&Socket->Rundown);
    for (uint32_t i = 0; i < SocketCount; i++) {
        CxPlatLockUninitialize(&Socket->SocketContexts[i].PendingSendContextLock);
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

CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
    UNREFERENCED_PARAMETER(MaxPacketSize);
    CXPLAT_DBG_ASSERT(Socket != NULL);

    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext =
        &Socket->Datapath->ProcContexts[CxPlatProcCurrentNumber() % Socket->Datapath->ProcCount];
    CXPLAT_SEND_DATA* SendContext =
        CxPlatPoolAlloc(&ProcContext->SendContextPool);
    if (SendContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEND_DATA",
            0);
        goto Exit;
    }

    CxPlatZeroMemory(SendContext, sizeof(*SendContext));
    SendContext->Owner = ProcContext;
    SendContext->ECN = ECN;

Exit:

    return SendContext;
}

void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    size_t i = 0;
    for (i = 0; i < SendData->BufferCount; ++i) {
        CxPlatPoolFree(
            &SendData->Owner->SendBufferPool,
            SendData->Buffers[i].Buffer);
        SendData->Buffers[i].Buffer = NULL;
    }

    CxPlatPoolFree(&SendData->Owner->SendContextPool, SendData);
}

QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_BUFFER* Buffer = NULL;

    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

    if (SendData->BufferCount ==
            SendData->Owner->Datapath->MaxSendBatchSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Max batch size limit hit");
        goto Exit;
    }

    Buffer = &SendData->Buffers[SendData->BufferCount];
    CxPlatZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = CxPlatPoolAlloc(&SendData->Owner->SendBufferPool);
    if (Buffer->Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Send Buffer",
            0);
        Buffer = NULL;
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    SendData->Iovs[SendData->BufferCount].iov_base = Buffer->Buffer;
    SendData->Iovs[SendData->BufferCount].iov_len = Buffer->Length;

    ++SendData->BufferCount;

Exit:

    return Buffer;
}

void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    CxPlatPoolFree(&SendData->Owner->SendBufferPool, Buffer->Buffer);
    Buffer->Buffer = NULL;

    CXPLAT_DBG_ASSERT(Buffer == &SendData->Buffers[SendData->BufferCount - 1]);

    --SendData->BufferCount;
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
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = NULL;
    ssize_t SentByteCount = 0;
    QUIC_ADDR MappedRemoteAddress = {0};
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;
    uint32_t ProcNumber;

    static_assert(CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)), "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");
    char ControlBuffer[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))] = {0};

    CXPLAT_DBG_ASSERT(Socket != NULL && RemoteAddress != NULL && SendData != NULL);

    ProcNumber = CxPlatProcCurrentNumber() % Socket->Datapath->ProcCount;
    SocketContext = &Socket->SocketContexts[Socket->HasFixedRemoteAddress ? 0 : ProcNumber];
    ProcContext = &Socket->Datapath->ProcContexts[ProcNumber];

    uint32_t TotalSize = 0;
    for (size_t i = 0; i < SendData->BufferCount; ++i) {
        SendData->Iovs[i].iov_base = SendData->Buffers[i].Buffer;
        SendData->Iovs[i].iov_len = SendData->Buffers[i].Length;
        TotalSize += SendData->Buffers[i].Length;
    }

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        TotalSize,
        SendData->BufferCount,
        SendData->Buffers[0].Length,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

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

    //
    // Check to see if we need to pend.
    //
    if (!IsPendedSend) {
        CxPlatLockAcquire(&SocketContext->PendingSendContextLock);
        if (!CxPlatListIsEmpty(&SocketContext->PendingSendContextHead)) {
            CxPlatSocketContextPendSend(
                SocketContext,
                SendData,
                LocalAddress,
                RemoteAddress);
            SendPending = TRUE;
        }
        CxPlatLockRelease(&SocketContext->PendingSendContextLock);
        if (SendPending) {
            Status = QUIC_STATUS_PENDING;
            goto Exit;
        }
    }

    SentByteCount = sendmsg(SocketContext->SocketFd, &Mhdr, 0);

    if (SentByteCount < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!IsPendedSend) {
                CxPlatLockAcquire(&SocketContext->PendingSendContextLock);
                CxPlatSocketContextPendSend(
                    SocketContext,
                    SendData,
                    LocalAddress,
                    RemoteAddress);
                CxPlatLockRelease(&SocketContext->PendingSendContextLock);
            }
            SendPending = TRUE;
            struct kevent Event = {0};
            EV_SET(&Event, SocketContext->SocketFd, EVFILT_WRITE, EV_ADD | EV_ONESHOT | EV_CLEAR, 0, 0, (void *)SocketContext);
            int Ret =
                kevent(
                    ProcContext->KqueueFd,
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
            goto Exit;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (!SendPending && !IsPendedSend) {
        CxPlatSendDataFree(SendData);
    }

    return Status;
}

QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    QUIC_STATUS Status =
        CxPlatSocketSendInternal(
            Socket,
            LocalAddress,
            RemoteAddress,
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

void*
CxPlatDataPathWorkerThread(
    _In_ void* Context
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = (CXPLAT_DATAPATH_PROC_CONTEXT*)Context;
    CXPLAT_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);

    QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[data][%p] Worker start",
        ProcContext);

    int Kqueue = ProcContext->KqueueFd;
    const size_t EventListMax = 16; // TODO: Experiment.
    struct kevent EventList[EventListMax];

    while (!ProcContext->Datapath->Shutdown) {
        int ReadyEventCount =
            TEMP_FAILURE_RETRY(
                kevent(
                    Kqueue,
                    NULL,
                    0,
                    EventList,
                    EventListMax,
                    NULL));

        CXPLAT_FRE_ASSERT(ReadyEventCount >= 0);
        for (int i = 0; i < ReadyEventCount; i++) {
            if (EventList[i].udata == NULL) {
                //
                // The processor context is shutting down and the worker thread
                // needs to clean up.
                //
                CXPLAT_DBG_ASSERT(ProcContext->Datapath->Shutdown);
                break;
            }

            CxPlatSocketContextProcessEvents(
                &EventList[i],
                ProcContext);
        }
    }

    QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[data][%p] Worker stop",
        ProcContext);

    return NO_ERROR;
}

BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return SendData->BufferCount == SendData->Owner->Datapath->MaxSendBatchSize;
}
