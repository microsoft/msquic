/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Darwin

--*/

#define __APPLE_USE_RFC_3542 1
// See netinet6/in6.h:46 for an explanation

#include "platform_internal.h"
#include "quic_platform_dispatch.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/time.h>

#ifdef QUIC_CLOG
#include "datapath_kqueue.c.clog.h"
#endif

#define QUIC_MAX_BATCH_SEND                 10

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct QUIC_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    QUIC_POOL* OwningPool;

    //
    // The recv buffer used by MsQuic.
    //
    QUIC_RECV_DATAGRAM RecvPacket;

    //
    // Represents the address (source and destination) information of the
    // packet.
    //
    QUIC_TUPLE Tuple;

    //
    // Buffer that actually stores the UDP payload.
    //
    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // This follows the recv block.
    //
    // QUIC_RECV_PACKET RecvContext;

} QUIC_DATAPATH_RECV_BLOCK;

//
// Send context.
//

typedef struct QUIC_DATAPATH_SEND_CONTEXT {
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
    QUIC_LIST_ENTRY PendingSendLinkage;

    //
    // Indicates if the send is pending.
    //
    BOOLEAN Pending;

    //
    // The proc context owning this send context.
    //
    struct QUIC_DATAPATH_PROC_CONTEXT *Owner;

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
    QUIC_BUFFER Buffers[QUIC_MAX_BATCH_SEND];
    struct iovec Iovs[QUIC_MAX_BATCH_SEND];

} QUIC_DATAPATH_SEND_CONTEXT;

//
// Socket context.
//
typedef struct QUIC_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    QUIC_DATAPATH_BINDING* Binding;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // Indicates if sends are waiting for the socket to be write ready.
    //
    BOOLEAN SendWaiting;

    //
    // The I/O vector for receive datagrams.
    //
    struct iovec RecvIov;

    //
    // The control buffer used in RecvMsgHdr.
    //
    char RecvMsgControl[CMSG_SPACE(8192)]; //CMSG_SPACE(sizeof(struct in6_pktinfo))];

    //
    // The buffer used to receive msg headers on socket.
    //
    struct msghdr RecvMsgHdr;

    //
    // The receive block currently being used for receives on this socket.
    //
    QUIC_DATAPATH_RECV_BLOCK* CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //
    QUIC_LIST_ENTRY PendingSendContextHead;

} QUIC_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct QUIC_DATAPATH_BINDING {

    //
    // A pointer to datapath object.
    //
    QUIC_DATAPATH* Datapath;

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
    QUIC_RUNDOWN_REF Rundown;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Indicates the binding is shut down.
    //
    BOOLEAN Shutdown : 1;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Set of socket contexts one per proc.
    //
    QUIC_SOCKET_CONTEXT SocketContexts[];

} QUIC_DATAPATH_BINDING;

//
// A per processor datapath context.
//
typedef struct QUIC_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //
    QUIC_DATAPATH* Datapath;

    //
    // The Kqueue FD for this proc context.
    //
    int KqueueFd;

    //
    // The index of the context in the datapath's array.
    //
    uint32_t Index;

    //
    // The epoll wait thread.
    //
    QUIC_THREAD KqueueThread;

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    QUIC_POOL RecvBlockPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //
    QUIC_POOL SendBufferPool;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    QUIC_POOL SendContextPool;

} QUIC_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct QUIC_DATAPATH {
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
    QUIC_RUNDOWN_REF BindingsRundown;

    //
    // The MsQuic receive handler.
    //
    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvHandler;

    //
    // The MsQuic unreachable handler.
    //
    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableHandler;

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
    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[];

} QUIC_DATAPATH;

QUIC_STATUS
QuicSocketContextPrepareReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    );

QUIC_STATUS
QuicDataPathBindingSend(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ BOOLEAN IsServer
    );

//
// Gets the corresponding recv datagram from its context pointer.
//
QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const Packet
    ) {
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        (QUIC_DATAPATH_RECV_BLOCK*)
            ((char *)Packet - sizeof(QUIC_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
}

//
// Gets the corresponding client context from its recv datagram pointer.
//
QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const RecvPacket
    ) {
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QUIC_CONTAINING_RECORD(RecvPacket, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

    return (QUIC_RECV_PACKET*)(RecvBlock + 1);
}

uint32_t QuicGetNumLogicalCores(void) {
    int num_cores = 0;
    size_t param_size = sizeof(num_cores);
    QUIC_FRE_ASSERT(sysctlbyname("hw.logicalcpu", &num_cores, &param_size, NULL, 0) == 0);
    return num_cores;
}

void
QuicSocketContextRecvComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ ssize_t BytesTransferred
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QUIC_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);
    QUIC_RECV_DATAGRAM* RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;

    BOOLEAN FoundLocalAddr = FALSE;
    QUIC_ADDR* LocalAddr = &RecvPacket->Tuple->LocalAddress;
    QUIC_ADDR* RemoteAddr = &RecvPacket->Tuple->RemoteAddress;
   // QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

    //LocalAddr->Ip.sa_family = AF_INET6;

    struct cmsghdr *CMsg;
    for (CMsg = CMSG_FIRSTHDR(&SocketContext->RecvMsgHdr);
         CMsg != NULL;
         CMsg = CMSG_NXTHDR(&SocketContext->RecvMsgHdr, CMsg)) {

        if (CMsg->cmsg_level == IPPROTO_IPV6 &&
            CMsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            LocalAddr->Ip.sa_family = AF_INET6;
            LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
            LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
            QuicConvertFromMappedV6(LocalAddr, LocalAddr);

            LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
            FoundLocalAddr = TRUE;
            break;
        }

        if (CMsg->cmsg_level == IPPROTO_IP && CMsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
            LocalAddr->Ip.sa_family = AF_INET;
            LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
            LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
            LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
            FoundLocalAddr = TRUE;
            break;
        }
    }

    QUIC_FRE_ASSERT(FoundLocalAddr);

    QuicTraceEvent(
        DatapathRecv,
        "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!SOCK! Dst=%!SOCK!",
        SocketContext->Binding,
        (uint32_t)BytesTransferred,
        (uint32_t)BytesTransferred,
        CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

    QUIC_DBG_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    RecvPacket->PartitionIndex = ProcContext->Index;

    QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->RecvHandler);
    SocketContext->Binding->Datapath->RecvHandler(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RecvPacket);

    Status = QuicSocketContextPrepareReceive(SocketContext);

    //
    // Prepare can only fail under low memory condition. Treat it as a fatal
    // error.
    //
    QUIC_FRE_ASSERT(QUIC_SUCCEEDED(Status));
}

void
QuicSocketContextUninitializeComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    if (SocketContext->CurrentRecvBlock != NULL) {
        QuicDataPathBindingReturnRecvDatagrams(&SocketContext->CurrentRecvBlock->RecvPacket);
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendContextHead)) {
        QuicDataPathBindingFreeSendContext(
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendContextHead),
                QUIC_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage));
    }

    close(SocketContext->SocketFd);

    QuicRundownRelease(&SocketContext->Binding->Rundown);
}

void QuicSocketContextSendPending(
    _In_ QUIC_SOCKET_CONTEXT *SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT *ProcContext) {

    if (SocketContext->SendWaiting) {
        SocketContext->SendWaiting = FALSE;
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendContextHead)) {
        QUIC_DATAPATH_SEND_CONTEXT* SendContext =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendContextHead),
                QUIC_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage);

        QUIC_STATUS Status =
            QuicDataPathBindingSend(
                SocketContext->Binding,
                SendContext->Bind ? &SendContext->LocalAddress : NULL,
                &SendContext->RemoteAddress,
                SendContext,
                !SocketContext->Binding->Connected);

        if (QUIC_FAILED(Status)) {
            break;
        }

        if (SocketContext->SendWaiting) {
            break;
        }
    }
}

void
QuicSocketContextProcessEvent(
    _In_ QUIC_DATAPATH_PROC_CONTEXT *ProcContext,
    _In_ struct kevent *Event)
{
    QUIC_DBG_ASSERT(Event->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));

    QUIC_SOCKET_CONTEXT *SocketContext = (QUIC_SOCKET_CONTEXT *)Event->udata;

    if (Event->filter == EVFILT_USER || Event->flags & EV_EOF) {
        QUIC_DBG_ASSERT(SocketContext->Binding->Shutdown);
        QuicSocketContextUninitializeComplete(SocketContext, ProcContext);
        return;
    }

    else if (Event->filter == EVFILT_READ) {
        int Ret = recvmsg(SocketContext->SocketFd, &SocketContext->RecvMsgHdr, 0);
        if (Ret != -1)
            QuicSocketContextRecvComplete(SocketContext, ProcContext, Ret);
    }

    else if (Event->filter == EVFILT_WRITE) {
        QuicSocketContextSendPending(SocketContext, ProcContext);
    }
}

void*
QuicDataPathWorkerThread(
    _In_ void* Context
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*)Context;
    QUIC_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);
    struct kevent EventList[32];
    int Kqueue = ProcContext->KqueueFd;

    while (TRUE) {
        int EventCount = kevent(Kqueue, NULL, 0, EventList, 32, NULL);

        if (ProcContext->Datapath->Shutdown) break;

        QUIC_DBG_ASSERT(EventCount > 0);

        for (int i = 0; i < EventCount; i++) {
            QuicSocketContextProcessEvent(ProcContext, &EventList[i]);
        }
    }

    return NO_ERROR;
}

QUIC_STATUS
QuicProcessorContextInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t Index,
    _Out_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    uint32_t RecvPacketLength = 0;

    QUIC_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(QUIC_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    ProcContext->Index = Index;
    QuicPoolInitialize(TRUE, RecvPacketLength, QUIC_POOL_DATA, &ProcContext->RecvBlockPool);
    QuicPoolInitialize(TRUE, MAX_UDP_PAYLOAD_LENGTH, QUIC_POOL_DATA, &ProcContext->SendBufferPool);
    QuicPoolInitialize(TRUE, sizeof(QUIC_DATAPATH_SEND_CONTEXT), QUIC_POOL_GENERIC, &ProcContext->SendContextPool);

    int KqueueFd = kqueue();

    if (KqueueFd == INVALID_SOCKET_FD) {
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

    QUIC_THREAD_CONFIG ThreadConfig = {
        0,
        0,
        NULL,
        QuicDataPathWorkerThread,
        ProcContext
    };

    Status = QuicThreadCreate(&ThreadConfig, &ProcContext->KqueueThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicThreadCreate failed");
        goto Exit;
    }

Exit:
    if (QUIC_FAILED(Status)) {
        if (KqueueFd != INVALID_SOCKET_FD) {
            close(KqueueFd);
        }
        QuicPoolUninitialize(&ProcContext->RecvBlockPool);
        QuicPoolUninitialize(&ProcContext->SendBufferPool);
        QuicPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}

//
// Opens a new handle to the QUIC Datapath library.
//
QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDataPath
    ) {

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (RecvCallback == NULL ||
        UnreachableCallback == NULL ||
        NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t DatapathObjectSize = sizeof(QUIC_DATAPATH) + sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    QUIC_DATAPATH *Datapath = (QUIC_DATAPATH *)QUIC_ALLOC_PAGED(DatapathObjectSize);
    // Should this be QUIC_ALLOC_PAGED? this is usermode? QUIC_ALLOC instead?

    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathObjectSize);

        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(Datapath, DatapathObjectSize);
    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachableHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = 1;

    // Using kqueue so batch UDP sending is enabled
    Datapath->MaxSendBatchSize = QUIC_MAX_BATCH_SEND;
    QuicRundownInitialize(&Datapath->BindingsRundown);

    // XXX: Should we spawn one of these per core?
    Status = QuicProcessorContextInitialize(Datapath, 0, &Datapath->ProcContexts[0]);
    if (QUIC_FAILED(Status)) {
        Datapath->Shutdown = TRUE;
        goto Exit;
    }

    // As far as I can tell, there's no way to enable RSS in macOS.
    *NewDataPath = Datapath;
    Datapath = NULL;
Exit:
    if (Datapath != NULL) {
        QuicRundownUninitialize(&Datapath->BindingsRundown);
        QUIC_FREE(Datapath);
    }

    return Status;
}

void
QuicProcessorContextUninitialize(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    // TOOD: wait till the worker thread shuts down
    close(ProcContext->KqueueFd);

    QuicPoolUninitialize(&ProcContext->RecvBlockPool);
    QuicPoolUninitialize(&ProcContext->SendBufferPool);
    QuicPoolUninitialize(&ProcContext->SendContextPool);
}

//
// Closes a QUIC Datapath library handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

    QuicRundownReleaseAndWait(&Datapath->BindingsRundown);

    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        QuicProcessorContextUninitialize(&Datapath->ProcContexts[i]);
    }

    QuicRundownUninitialize(&Datapath->BindingsRundown);
    QUIC_FREE(Datapath);
}

//
// Queries the currently supported features of the datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    return 0;
}

void
QuicDataPathPopulateTargetAddress(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ QUIC_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    QuicZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //

        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;

        if (Family == AF_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //

            SockAddrIn->sin_family = AF_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        } else {
            Address->Ipv6 = *SockAddrIn6;
            return;
        }
    } else if (AddrInfo->ai_addr->sa_family == AF_INET) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        QUIC_FRE_ASSERT(FALSE);
    }
}

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    //
    // The windows implementation returns TRUE only if GSO is supported and
    // this DAL implementation doesn't support GSO currently.
    //
    return FALSE;
}

//
// Resolves a hostname to an IP address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    ) {
    UNREFERENCED_PARAMETER(Datapath);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = AF_UNSPEC;

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
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
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
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

QUIC_STATUS
QuicSocketContextInitialize(
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    QUIC_ADDR MappedRemoteAddress = { };
    socklen_t AssignedLocalAddressLength = 0;

    QUIC_DATAPATH_BINDING* Binding = SocketContext->Binding;

    //
    // Create datagram socket.
    //

    sa_family_t af_family = Binding->LocalAddress.Ip.sa_family;

    SocketContext->SocketFd = socket(af_family, SOCK_DGRAM, 0);

    if (SocketContext->SocketFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }

    socklen_t AddrSize = 0;

    if (af_family == AF_INET) {
        AddrSize = sizeof(struct sockaddr_in);

        Option = TRUE;
        Result =
            setsockopt(SocketContext->SocketFd, IPPROTO_IP, IP_PKTINFO, &Option, sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Binding,
                    Status,
                    "setsockopt(IP_PKTINFO) failed");
            goto Exit;
        }
    }
    else {
        AddrSize = sizeof(struct sockaddr_in6);

        Option = TRUE;
        Result =
            setsockopt(SocketContext->SocketFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &Option, sizeof(Option));

        Option = TRUE;
        Result =
            setsockopt(SocketContext->SocketFd, IPPROTO_IPV6, IPV6_PKTINFO, &Option, sizeof(Option));
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //

    Option = INT32_MAX / 400;
    // This is the largest value that actually works. I don't know why.

    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_RCVBUF,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(SO_RCVBUF) failed");
        goto Exit;
    }

    //
    // The port is shared across processors.
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
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_REUSEADDR) failed");
        goto Exit;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            (const struct sockaddr *)&Binding->LocalAddress,
            AddrSize);

    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "bind() failed");
        goto Exit;
    }

    if (RemoteAddress != NULL) {
        // XXX: Don't map v4-to-v6 addresses for now.
        // QuicZeroMemory(&MappedRemoteAddress, sizeof(MappedRemoteAddress));
        // QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        Result =
            connect(
                SocketContext->SocketFd,
                (const struct sockaddr *)RemoteAddress,
                AddrSize);

        if (Result == SOCKET_ERROR) {
            __asm__("int3");
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
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
    AssignedLocalAddressLength = sizeof(struct sockaddr);
    Result =
        getsockname(
            SocketContext->SocketFd,
            (struct sockaddr *)&Binding->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "getsockname failed");
        goto Exit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

QUIC_DATAPATH_RECV_BLOCK*
QuicDataPathAllocRecvBlock(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t ProcIndex
    )
{
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QuicPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvBlockPool);
    if (RecvBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_RECV_BLOCK",
            0);
    } else {
        QuicZeroMemory(RecvBlock, sizeof(*RecvBlock));
        RecvBlock->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvBlockPool;
        RecvBlock->RecvPacket.Buffer = RecvBlock->Buffer;
        RecvBlock->RecvPacket.Allocated = TRUE;
    }
    return RecvBlock;
}

QUIC_STATUS
QuicSocketContextPrepareReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            QuicDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                0);
        if (SocketContext->CurrentRecvBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "QUIC_DATAPATH_RECV_BLOCK",
                0);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.BufferLength = SocketContext->RecvIov.iov_len;
    SocketContext->CurrentRecvBlock->RecvPacket.Tuple = (QUIC_TUPLE*)&SocketContext->CurrentRecvBlock->Tuple;

    QuicZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    QuicZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress);
    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;
    SocketContext->RecvMsgHdr.msg_control = &SocketContext->RecvMsgControl;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControl);
    SocketContext->RecvMsgHdr.msg_flags = 0;

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicSocketContextStartReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ int KqueueFd
    )
{
    QUIC_STATUS Status = QuicSocketContextPrepareReceive(SocketContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    struct kevent evSet = { };
    EV_SET(&evSet, SocketContext->SocketFd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, (void *)SocketContext);
    if (kevent(KqueueFd, &evSet, 1, NULL, 0, NULL) < 0)  {
        // Should be QUIC_STATUS_KQUEUE_ERROR
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "kevent(..., sockfd EV_ADD, ...) failed");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}

//
// Creates a datapath binding handle for the given local address and/or remote
// address. This function immediately registers for receive upcalls from the
// UDP layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** NewBinding
    ) {

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    uint32_t SocketCount = Datapath->ProcCount; // TODO - Only use 1 for client (RemoteAddress != NULL) bindings?
    size_t BindingLength =
        sizeof(QUIC_DATAPATH_BINDING) +
        SocketCount * sizeof(QUIC_SOCKET_CONTEXT);

    QUIC_DATAPATH_BINDING* Binding =
        (QUIC_DATAPATH_BINDING *)QUIC_ALLOC_PAGED(BindingLength);

    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_BINDING",
            BindingLength);
        goto Exit;
    }

    QuicTraceLogInfo(
        DatapathCreate,
        "[ udp][%p] Created.",
        Binding);

    QuicZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->Mtu = QUIC_MAX_MTU;
    QuicRundownInitialize(&Binding->Rundown);

    if (LocalAddress) {
        memcpy(&Binding->LocalAddress, LocalAddress, sizeof(QUIC_ADDR));
        //QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else if (RemoteAddress) {
        // We have no local address, but we have a remote address.
        // Let's match up AF types with the remote.
        Binding->LocalAddress.Ip.sa_family = RemoteAddress->Ip.sa_family;
    } else {
        // This indicates likely that the application wants a listener with a random port.
        // Since we can't dual-stack socket, fall back to AF_INET6
        Binding->LocalAddress.Ip.sa_family = AF_INET6;
    }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET_FD;
        Binding->SocketContexts[i].RecvIov.iov_len =
            Binding->Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
        QuicListInitializeHead(&Binding->SocketContexts[i].PendingSendContextHead);
        QuicRundownAcquire(&Binding->Rundown);
    }

    QuicRundownAcquire(&Datapath->BindingsRundown);

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            QuicSocketContextInitialize(
                &Binding->SocketContexts[i],
                &Datapath->ProcContexts[i],
                LocalAddress,
                RemoteAddress);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    //QuicConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    //Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
    //    Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    for (uint32_t i = 0; i < Binding->Datapath->ProcCount; i++) {
        Status =
            QuicSocketContextStartReceive(
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
            // TODO - Clean up socket contexts
            QuicRundownRelease(&Datapath->BindingsRundown);
            QuicRundownUninitialize(&Binding->Rundown);
            QUIC_FREE(Binding);
            Binding = NULL;
        }
    }

    return Status;
}

void QuicSocketContextUninitialize(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    // XXX: Documentation says shutdown(Sockfd, SHUT_RD) is enough to wake up the kqueue
    // However, this seems to only happen after we've recieved some data..
    // So we use EVFILT_USER to indicate that we want to destroy this socket
    // context, and to wake up the worker thread. Perhaps we should pass an
    // explicit CLOSE message to the worker thread, but for now, any
    // EVFILT_USER event is a shutdown.
    // shutdown(SocketContext->SocketFd, SHUT_RDWR);

    struct kevent EvSet[2] = { };
    EV_SET(&EvSet[0], SocketContext->SocketFd, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, (void *)SocketContext);
    EV_SET(&EvSet[1], SocketContext->SocketFd, EVFILT_READ, EV_DELETE, 0, 0, (void *)SocketContext);
    kevent(ProcContext->KqueueFd, EvSet, 2, NULL, 0, NULL);
}

//
// Deletes a UDP binding. This function blocks on all outstandind upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDelete(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    Binding->Shutdown = TRUE;
    for (uint32_t i = 0; i < Binding->Datapath->ProcCount; ++i) {
        QuicSocketContextUninitialize(
            &Binding->SocketContexts[i],
            &Binding->Datapath->ProcContexts[i]);
    }

    QuicRundownReleaseAndWait(&Binding->Rundown);
    QuicRundownRelease(&Binding->Datapath->BindingsRundown);

    QuicRundownUninitialize(&Binding->Rundown);
    QuicFree(Binding);
}

//
// Queries the locally bound interface's MTU. Returns QUIC_MIN_MTU if not
// already bound.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicDataPathBindingGetLocalMtu(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
}

//
// Queries the locally bound IP address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetLocalAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
}

//
// Queries the connected remote IP address. Only valid if the binding was
// initially created with a remote address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetRemoteAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
}

//
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{
    QUIC_RECV_DATAGRAM* Datagram;
    while ((Datagram = DatagramChain) != NULL) {
        DatagramChain = DatagramChain->Next;
        QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
            QUIC_CONTAINING_RECORD(Datagram, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);
        QuicPoolFree(RecvBlock->OwningPool, RecvBlock);
    }
}

//
// Allocates a new send context to be used to call QuicDataPathBindingSendTo. It
// can be freed with QuicDataPathBindingFreeSendContext too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    )
{
    UNREFERENCED_PARAMETER(MaxPacketSize);
    QUIC_DBG_ASSERT(Binding != NULL);

    QUIC_DATAPATH_PROC_CONTEXT* ProcContext =
        &Binding->Datapath->ProcContexts[0];
    QUIC_DATAPATH_SEND_CONTEXT* SendContext =
        QuicPoolAlloc(&ProcContext->SendContextPool);
    if (SendContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_SEND_CONTEXT",
            0);
        goto Exit;
    }

    QuicZeroMemory(SendContext, sizeof(*SendContext));
    SendContext->Owner = ProcContext;

Exit:
    return SendContext;
}

//
// Frees a send context returned from a previous call to
// QuicDataPathBindingAllocSendContext.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    size_t i = 0;
    for (i = 0; i < SendContext->BufferCount; ++i) {
        QuicPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    QuicPoolFree(&SendContext->Owner->SendContextPool, SendContext);
}

//
// Allocates a new UDP datagram buffer for sending.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_BUFFER* Buffer = NULL;

    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Max batch size limit hit");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    QuicZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = QuicPoolAlloc(&SendContext->Owner->SendBufferPool);
    if (Buffer->Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Send Buffer",
            0);
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    SendContext->Iovs[SendContext->BufferCount].iov_base = Buffer->Buffer;
    SendContext->Iovs[SendContext->BufferCount].iov_len = Buffer->Length;

    ++SendContext->BufferCount;

Exit:
    return Buffer;
}

//
// Frees a datagram buffer returned from a previous call to
// QuicDataPathBindingAllocSendDatagram.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* SendDatagram
    )
{
    QUIC_FRE_ASSERT(FALSE);
}

//
// Returns whether the send context buffer limit has been reached.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
}

QUIC_STATUS
QuicSocketContextPendSend(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (!SocketContext->SendWaiting) {
        // We have to enable EVFILT_WRITE notifications here, since there's
        // basically nowhere else to try and empty the send queue except the
        // worker thread, and there's the possibility that the worker thread
        // won't wake up fast enough.

        // We can try to EV_ONESHOT this, s.t. we only get woken up for this
        // once, attempt to empty the sendqueue, and if it fails, then add it
        // again as oneshot.
        //
        // The alternate option is to add it normally, so we constantly get
        // woken up for it, and after N missed writes (i.e. the kernel had room
        // and we had nothing to write), we can turn it off.
        //
        // Or we could do some mix of both, and try to recognize how often
        // we're missing writes or re-pending writes.

        // For now, we'll do the most naïve thing, and oneshot it everytime we
        // hit this function.

        struct kevent Event = { };
        EV_SET(&Event, SocketContext->SocketFd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, (void *)SocketContext);
        kevent(ProcContext->KqueueFd, &Event, 1, NULL, 0, NULL);

        if (LocalAddress != NULL) {
            QuicCopyMemory(
                &SendContext->LocalAddress,
                LocalAddress,
                sizeof(*LocalAddress));
            SendContext->Bind = TRUE;
        }

        QuicCopyMemory(
            &SendContext->RemoteAddress,
            RemoteAddress,
            sizeof(*RemoteAddress));

        SocketContext->SendWaiting = TRUE;
    }

    if (SendContext->Pending) {
        //
        // This was a send that was already pending, so we need to add it back
        // to the head of the queue.
        //
        QuicListInsertHead(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
    } else {
        //
        // This is a new send that wasn't previously pended. Add it to the end
        // of the queue.
        //
        QuicListInsertTail(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
        SendContext->Pending = TRUE;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
QuicDataPathBindingSend(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ BOOLEAN IsServer
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = NULL;
    ssize_t SentByteCount = 0;
    size_t i = 0;
    socklen_t RemoteAddrLen = 0;
    QUIC_ADDR MappedRemoteAddress = { };
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;

    // static_assert(CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)), "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");
    // XXX: On macOS, this isn't computable as a constexpr;
    const size_t ControlSize = MAX(sizeof(struct in6_pktinfo), sizeof(struct in_pktinfo));
    char ControlBuffer[CMSG_SPACE(ControlSize)] = {0};

    QUIC_DBG_ASSERT(Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    SocketContext = &Binding->SocketContexts[0];
    ProcContext = &Binding->Datapath->ProcContexts[0];

    RemoteAddrLen =
        (AF_INET == RemoteAddress->Ip.sa_family) ?
            sizeof(RemoteAddress->Ipv4) : sizeof(RemoteAddress->Ipv6);

    if (LocalAddress == NULL) {
        QUIC_DBG_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

        for (i = SendContext->CurrentIndex;
             i < SendContext->BufferCount;
             ++i, SendContext->CurrentIndex++) {

            QuicTraceEvent(
                DatapathSendTo,
                "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!SOCK!",
                Binding,
                SendContext->Buffers[i].Length,
                1,
                SendContext->Buffers[i].Length,
                CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress));

            if (IsServer) {
                SentByteCount =
                    sendto(
                        SocketContext->SocketFd,
                        SendContext->Buffers[i].Buffer,
                        SendContext->Buffers[i].Length,
                        0,
                        (struct sockaddr *)RemoteAddress,
                        RemoteAddrLen);
            }
            else {
                SentByteCount =
                    sendto(
                        SocketContext->SocketFd,
                        SendContext->Buffers[i].Buffer,
                        SendContext->Buffers[i].Length,
                        0,
                        NULL, 0);
            }

            if (SentByteCount < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                    Status =
                        QuicSocketContextPendSend(
                            SocketContext,
                            SendContext,
                            ProcContext,
                            LocalAddress,
                            RemoteAddress);

                    if (QUIC_FAILED(Status)) {
                        goto Exit;
                    }

                    SendPending = TRUE;
                    goto Exit;
                } else {
                    //
                    // Completed with error.
                    //

                    // We get ECONNREFUSED here often. Need to invoke the UnreachHandler
                    printf("COULDN'T SEND FRAME...%d\n", errno);

                    Status = errno;
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[ udp][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        Status,
                        "sendto failed");
                    goto Exit;
                }
            } else {
                //
                // Completed synchronously.
                //
                QuicTraceLogVerbose(
                    DatapathSendToCompleted,
                    "[ udp][%p] sendto succeeded, bytes transferred %d",
                    SocketContext->Binding,
                    SentByteCount);
            }
        }
    } else {

        uint32_t TotalSize = 0;
        for (i = 0; i < SendContext->BufferCount; ++i) {
            SendContext->Iovs[i].iov_base = SendContext->Buffers[i].Buffer;
            SendContext->Iovs[i].iov_len = SendContext->Buffers[i].Length;
            TotalSize += SendContext->Buffers[i].Length;
        }

        QuicTraceEvent(
            DatapathSendFromTo,
            "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!SOCK!, Src=%!SOCK!",
            Binding,
            TotalSize,
            SendContext->BufferCount,
            SendContext->Buffers[0].Length,
            CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
            CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

        //
        // Map V4 address to dual-stack socket format.
        //
        //QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        struct msghdr Mhdr = {
            .msg_name = &MappedRemoteAddress,
            .msg_namelen = sizeof(MappedRemoteAddress),
            .msg_iov = SendContext->Iovs,
            .msg_iovlen = SendContext->BufferCount,
            .msg_flags = 0
        };

        // TODO: Avoid allocating both.

        if (LocalAddress->Ip.sa_family == AF_INET) {
            Mhdr.msg_control = ControlBuffer;
            Mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

            CMsg = CMSG_FIRSTHDR(&Mhdr);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

            PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
            // TODO: Use Ipv4 instead of Ipv6.
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
        } else {
            Mhdr.msg_control = ControlBuffer;
            Mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

            CMsg = CMSG_FIRSTHDR(&Mhdr);
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

            PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
        }

        SentByteCount = sendmsg(SocketContext->SocketFd, &Mhdr, 0);

        if (SentByteCount < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
                Status =
                    QuicSocketContextPendSend(
                        SocketContext,
                        SendContext,
                        ProcContext,
                        LocalAddress,
                        RemoteAddress);

                if (QUIC_FAILED(Status)) {
                    goto Exit;
                }

                SendPending = TRUE;
                goto Exit;
            } else {
                printf("COULDN'T SEND FRAME...%d\n", errno);
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "sendmsg failed");
                goto Exit;
            }
        } else {
            //
            // Completed synchronously.
            //
            QuicTraceLogVerbose(
                DatapathSendMsgCompleted,
                "[ udp][%p] sendmsg succeeded, bytes transferred %d",
                SocketContext->Binding,
                SentByteCount);
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (!SendPending) {
        QuicDataPathBindingFreeSendContext(SendContext);
    }

    return Status;
}

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_DBG_ASSERT(
        Binding != NULL &&
        RemoteAddress != NULL &&
        RemoteAddress->Ipv4.sin_port != 0 &&
        SendContext != NULL);

    return
        QuicDataPathBindingSend(
            Binding,
            NULL,
            RemoteAddress,
            SendContext,
            FALSE);
}

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_DBG_ASSERT(
        Binding != NULL &&
        LocalAddress != NULL &&
        RemoteAddress != NULL &&
        SendContext != NULL &&
        SendContext->BufferCount != 0);

    return
        QuicDataPathBindingSend(
            Binding,
            LocalAddress,
            RemoteAddress,
            SendContext,
            TRUE);
}

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingGetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

