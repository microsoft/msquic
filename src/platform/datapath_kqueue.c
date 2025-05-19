/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

// For FreeBSD
#if defined(__FreeBSD__)
#include <netinet/in.h>
struct in_pktinfo {
	struct in_addr ipi_addr;        // the source or destination address
	unsigned int ipi_ifindex;       // the interface index
};
#endif

#define __APPLE_USE_RFC_3542 1
// See netinet6/in6.h:46 for an explanation
#include "platform_internal.h"
#include <sys/sysctl.h>

#ifdef QUIC_CLOG
#include "datapath_kqueue.c.clog.h"
#endif

// Check options
#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR)
#error "No socket option specified"
#endif
#if defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
#include <net/if_dl.h>
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
// Contains all the info for a single RX IO operation.
//
typedef struct DATAPATH_RX_IO_BLOCK {
    //
    // The pool owning this recv block.
    //
    CXPLAT_POOL* OwningPool;

    //
    // Represents the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // Buffer that actually stores the UDP payload.
    //
    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // Publicly visible receive data.
    //
    CXPLAT_RECV_DATA RecvPacket;

} DATAPATH_RX_IO_BLOCK;

//
// Send context.
//

typedef struct CXPLAT_SEND_DATA {
    CXPLAT_SEND_DATA_COMMON;

    //
    // The proc context owning this send context.
    //
    struct CXPLAT_DATAPATH_PARTITION *Owner;

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
    // Total number of Buffers currently in use.
    //
    uint32_t BufferCount;

    //
    // The current index of the Buffers to be sent.
    //
    uint32_t CurrentIndex;

    //
    // The QUIC_BUFFER returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

    //
    // Cache of send buffers.
    //
    QUIC_BUFFER Buffers[CXPLAT_MAX_BATCH_SEND];

    //
    // IO vectors used for sends on the socket.
    //
    struct iovec Iovs[CXPLAT_MAX_BATCH_SEND];

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_DATAPATH_PARTITION CXPLAT_DATAPATH_PARTITION;

//
// Socket context.
//
typedef struct QUIC_CACHEALIGN CXPLAT_SOCKET_CONTEXT {

    //
    // The datapath binding this socket context belongs to.
    //
    CXPLAT_SOCKET* Binding;

    //
    // The datapath proc context this socket belongs to.
    //
    CXPLAT_DATAPATH_PARTITION* DatapathPartition;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // The event for the shutdown event.
    //
    CXPLAT_SQE ShutdownSqe;

    //
    // The event for the IO event.
    //
    CXPLAT_SQE IoSqe;

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
    DATAPATH_RX_IO_BLOCK* CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //
    CXPLAT_LIST_ENTRY PendingSendDataHead;

    //
    // Lock around the PendingSendData list.
    //
    CXPLAT_LOCK PendingSendDataLock;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    CXPLAT_RUNDOWN_REF UpcallRundown;

    //
    // Inidicates if the socket has started IO processing.
    //
    BOOLEAN IoStarted : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

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
    CXPLAT_REF_COUNT RefCount;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Flag indicates the socket has a default remote destination.
    //
    BOOLEAN HasFixedRemoteAddress : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    BOOLEAN PcpBinding : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // Set of socket contexts one per proc.
    //
    CXPLAT_SOCKET_CONTEXT SocketContexts[];

} CXPLAT_SOCKET;

//
// A per processor datapath context.
//
typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PARTITION {

    //
    // A pointer to the datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The event queue for this proc context.
    //
    CXPLAT_EVENTQ* EventQ;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The index of the partition.
    //
    uint16_t PartitionIndex;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

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

} CXPLAT_DATAPATH_PARTITION;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {

    //
    // UDP handlers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    // The Worker pool
    //
    CXPLAT_WORKER_POOL* WorkerPool;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // The proc count to create per proc datapath state.
    //
    uint32_t PartitionCount;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PARTITION Partitions[];

} CXPLAT_DATAPATH;

CXPLAT_EVENT_COMPLETION CxPlatSocketContextUninitializeEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatSocketContextIoEventComplete;

QUIC_STATUS
CxPlatSocketSendInternal(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN IsPendedSend
    );

void
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t PartitionIndex,
    _In_ uint32_t ClientRecvDataLength,
    _Out_ CXPLAT_DATAPATH_PARTITION* DatapathPartition
    )
{
    const uint32_t RecvPacketLength =
        sizeof(DATAPATH_RX_IO_BLOCK) + ClientRecvDataLength;

    CXPLAT_DBG_ASSERT(Datapath != NULL);
    DatapathPartition->Datapath = Datapath;
    DatapathPartition->PartitionIndex = PartitionIndex;
    DatapathPartition->EventQ = CxPlatWorkerPoolGetEventQ(Datapath->WorkerPool, PartitionIndex);
    CxPlatRefInitialize(&DatapathPartition->RefCount);

    CxPlatPoolInitialize(
        TRUE,
        RecvPacketLength,
        QUIC_POOL_DATA,
        &DatapathPartition->RecvBlockPool);
    CxPlatPoolInitialize(
        TRUE,
        MAX_UDP_PAYLOAD_LENGTH,
        QUIC_POOL_DATA,
        &DatapathPartition->SendBufferPool);
    CxPlatPoolInitialize(
        TRUE,
        CXPLAT_LARGE_SEND_BUFFER_SIZE,
        QUIC_POOL_DATA,
        &DatapathPartition->LargeSendBufferPool);
    CxPlatPoolInitialize(
        TRUE,
        sizeof(CXPLAT_SEND_DATA),
        QUIC_POOL_PLATFORM_SENDCTX,
        &DatapathPartition->SendDataPool);
}

QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvDataLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
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
    if (WorkerPool == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const size_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        CxPlatWorkerPoolGetCount(WorkerPool) * sizeof(CXPLAT_DATAPATH_PARTITION);

    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Datapath, DatapathLength);
    if (UdpCallbacks) {
        Datapath->UdpHandlers = *UdpCallbacks;
    }
    Datapath->WorkerPool = WorkerPool;
    Datapath->PartitionCount = 1; //CxPlatWorkerPoolGetCount(WorkerPool); // Darwin only supports a single receiver
    CxPlatRefInitializeEx(&Datapath->RefCount, Datapath->PartitionCount);

    for (uint32_t i = 0; i < Datapath->PartitionCount; i++) {
        CxPlatProcessorContextInitialize(
            Datapath,
            i,
            ClientRecvDataLength,
            &Datapath->Partitions[i]);
    }

    CXPLAT_FRE_ASSERT(CxPlatWorkerPoolAddRef(WorkerPool));
    *NewDataPath = Datapath;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRelease(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (CxPlatRefDecrement(&Datapath->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Datapath->Freed);
        CXPLAT_DBG_ASSERT(Datapath->Uninitialized);
        Datapath->Freed = TRUE;
#endif
        CxPlatWorkerPoolRelease(Datapath->WorkerPool);
        CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatProcessorContextRelease(
    _In_ CXPLAT_DATAPATH_PARTITION* DatapathPartition
    )
{
    if (CxPlatRefDecrement(&DatapathPartition->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!DatapathPartition->Uninitialized);
        DatapathPartition->Uninitialized = TRUE;
#endif
        CxPlatPoolUninitialize(&DatapathPartition->SendDataPool);
        CxPlatPoolUninitialize(&DatapathPartition->SendBufferPool);
        CxPlatPoolUninitialize(&DatapathPartition->LargeSendBufferPool);
        CxPlatPoolUninitialize(&DatapathPartition->RecvBlockPool);
        CxPlatDataPathRelease(DatapathPartition->Datapath);
    }
}

void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath != NULL) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Datapath->Uninitialized);
        Datapath->Uninitialized = TRUE;
#endif
        const uint16_t PartitionCount = Datapath->PartitionCount;
        for (uint32_t i = 0; i < PartitionCount; i++) {
            CxPlatProcessorContextRelease(&Datapath->Partitions[i]);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(PollingIdleTimeoutUs);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_FEATURES
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_FLAGS SocketFlags
    )
{
    UNREFERENCED_PARAMETER(SocketFlags);
    return Datapath->Features;
}

BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

DATAPATH_RX_IO_BLOCK*
CxPlatDataPathAllocRxIoBlock(
    _In_ CXPLAT_DATAPATH_PARTITION* DatapathPartition
    )
{
    DATAPATH_RX_IO_BLOCK* IoBlock =
        CxPlatPoolAlloc(&DatapathPartition->RecvBlockPool);
    if (IoBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "DATAPATH_RX_IO_BLOCK",
            0);
    } else {
        CxPlatZeroMemory(IoBlock, sizeof(*IoBlock));
        IoBlock->Route.State = RouteResolved;
        IoBlock->OwningPool = &DatapathPartition->RecvBlockPool;
        IoBlock->RecvPacket.Buffer = IoBlock->Buffer;
        IoBlock->RecvPacket.Allocated = TRUE;
    }
    return IoBlock;
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

    CxPlatSqeInitialize(
        SocketContext->DatapathPartition->EventQ,
        CxPlatSocketContextUninitializeEventComplete,
        &SocketContext->ShutdownSqe);
    CxPlatSqeInitializeEx(
        SocketContext->DatapathPartition->EventQ,
        SocketContext->SocketFd,
        CxPlatSocketContextIoEventComplete,
        &SocketContext->IoSqe);

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
#if defined(IP_RECVPKTINFO)
            ForceIpv4 ? IP_RECVPKTINFO : IPV6_RECVPKTINFO,
#elif defined(IP_PKTINFO)
            ForceIpv4 ? IP_PKTINFO : IPV6_RECVPKTINFO,
#elif defined(IP_RECVDSTADDR)
            ForceIpv4 ? IP_RECVDSTADDR : IPV6_RECVPKTINFO,
#else
#error "No socket option specified"
#endif
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

#if defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
    if (ForceIpv4) {
        Result =
            setsockopt(
                SocketContext->SocketFd, IPPROTO_IP, IP_RECVIF,
                (const void*)&Option, sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(IP_RECVIF) failed");
            goto Exit;
        }
    }
#endif

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

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketRelease(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (CxPlatRefDecrement(&Socket->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!Socket->Freed);
        CXPLAT_DBG_ASSERT(Socket->Uninitialized);
        Socket->Freed = TRUE;
#endif
        CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
    }
}

void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!SocketContext->Freed);
    SocketContext->Freed = TRUE;
#endif

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

    if (SocketContext->SocketFd != INVALID_SOCKET) {
        CxPlatEventQEnqueueEx(
            SocketContext->DatapathPartition->EventQ,
            &SocketContext->IoSqe,
            EVFILT_READ,
            EV_DELETE);
        close(SocketContext->SocketFd);
    }

    CxPlatLockUninitialize(&SocketContext->PendingSendDataLock);
    CxPlatRundownUninitialize(&SocketContext->UpcallRundown);

    if (SocketContext->DatapathPartition) {
        CxPlatProcessorContextRelease(SocketContext->DatapathPartition);
    }
    CxPlatSocketRelease(SocketContext->Binding);
}

void
CxPlatSocketContextUninitializeEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_SOCKET_CONTEXT, ShutdownSqe);
    CxPlatSocketContextUninitializeComplete(SocketContext);
}

void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!SocketContext->Uninitialized);
    SocketContext->Uninitialized = TRUE;
#endif

    if (!SocketContext->IoStarted) {
        CxPlatSocketContextUninitializeComplete(SocketContext);
    } else {
        CxPlatRundownReleaseAndWait(&SocketContext->UpcallRundown); // Block until all upcalls complete.

        //
        // Cancel and clean up any pending IO.
        //
        CxPlatEventQEnqueueEx(
            SocketContext->DatapathPartition->EventQ,
            &SocketContext->IoSqe,
            EVFILT_READ,
            EV_DELETE);
        CxPlatEventQEnqueue(
            SocketContext->DatapathPartition->EventQ,
            &SocketContext->ShutdownSqe);
    }
}

QUIC_STATUS
CxPlatSocketContextPrepareReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            CxPlatDataPathAllocRxIoBlock(SocketContext->DatapathPartition);
        if (SocketContext->CurrentRecvBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DATAPATH_RX_IO_BLOCK",
                0);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.Next = NULL;
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

    if (!CxPlatEventQEnqueueEx(
            SocketContext->DatapathPartition->EventQ,
            &SocketContext->IoSqe,
            EVFILT_READ,
            EV_ADD | EV_ENABLE)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "CxPlatEventQEnqueueEx failed");
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
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS; // cppcheck-suppress unreadVariable

    CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);
    CXPLAT_RECV_DATA* RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;

    BOOLEAN FoundLocalAddr = FALSE; // cppcheck-suppress unreadVariable
    BOOLEAN FoundTOS = FALSE; // cppcheck-suppress unreadVariable
    BOOLEAN FoundIfIdx = FALSE; // cppcheck-suppress unreadVariable
    QUIC_ADDR* LocalAddr = &RecvPacket->Route->LocalAddress;
    if (LocalAddr->Ipv6.sin6_family == AF_INET6) {
        LocalAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    QUIC_ADDR* RemoteAddr = &RecvPacket->Route->RemoteAddress;
    if (RemoteAddr->Ipv6.sin6_family == AF_INET6) {
        RemoteAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);
    }

    RecvPacket->Route->Queue = (CXPLAT_QUEUE*)SocketContext;
    RecvPacket->TypeOfService = 0;
    RecvPacket->HopLimitTTL = 0; // TODO: We are not supporting this on MacOS (yet) unless there's a business need.

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
                FoundLocalAddr = TRUE; // cppcheck-suppress unreadVariable
                FoundIfIdx = TRUE; // cppcheck-suppress unreadVariable
            } else if (CMsg->cmsg_type == IPV6_TCLASS) {
                RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                FoundTOS = TRUE; // cppcheck-suppress unreadVariable
            }
        } else if (CMsg->cmsg_level == IPPROTO_IP) {
#if defined(IP_PKTINFO)
            if (CMsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
                LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
                LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
                LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                FoundLocalAddr = TRUE;
                FoundIfIdx = TRUE;
            }
#elif defined(IP_RECVDSTADDR)
            if (CMsg->cmsg_type == IP_RECVDSTADDR) {
                struct in_addr *Info = (struct in_addr *)CMSG_DATA(CMsg);
                LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
                LocalAddr->Ipv4.sin_addr = *Info;
                LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                FoundLocalAddr = TRUE;
            }
#else
#error "No socket option specified"
#endif
#if defined(IP_RECVDSTADDR) && defined(IP_RECVIF)
            else if (CMsg->cmsg_type == IP_RECVIF) {
                struct sockaddr_dl *Info = (struct sockaddr_dl *)CMSG_DATA(CMsg);
                LocalAddr->Ipv6.sin6_scope_id = Info->sdl_index;
                FoundIfIdx = TRUE;
            }
#endif
            else if (CMsg->cmsg_type == IP_TOS || CMsg->cmsg_type == IP_RECVTOS) {
                RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                FoundTOS = TRUE; // cppcheck-suppress unreadVariable
            }
        }
    }

    CXPLAT_FRE_ASSERT(FoundLocalAddr);
    CXPLAT_FRE_ASSERT(FoundTOS);
    CXPLAT_FRE_ASSERT(FoundIfIdx);

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

    RecvPacket->PartitionIndex = SocketContext->DatapathPartition->PartitionIndex;

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
                SocketContext,
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
CxPlatSocketContextIoEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_SOCKET_CONTEXT, IoSqe);

    if (!CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
        return;
    }

    CXPLAT_DBG_ASSERT(Cqe->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));

    if (Cqe->filter == EVFILT_READ) {
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

    if (Cqe->filter == EVFILT_WRITE) {
        CxPlatSocketContextSendComplete(SocketContext);
    }

    CxPlatRundownRelease(&SocketContext->UpcallRundown);
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

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & CXPLAT_SOCKET_FLAG_PCP);

    uint32_t SocketCount = IsServerSocket ? Datapath->PartitionCount : 1;
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
    CxPlatRefInitializeEx(&Binding->RefCount, SocketCount);
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
        Binding->SocketContexts[i].DatapathPartition =
            IsServerSocket ?
                &Datapath->Partitions[i % Datapath->PartitionCount] :
                &Datapath->Partitions[Config->PartitionIndex];
        CxPlatRefIncrement(&Binding->SocketContexts[i].DatapathPartition->RefCount);
        CxPlatListInitializeHead(&Binding->SocketContexts[i].PendingSendDataHead);
        CxPlatLockInitialize(&Binding->SocketContexts[i].PendingSendDataLock);
        CxPlatRundownInitialize(&Binding->SocketContexts[i].UpcallRundown);
    }

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

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status = CxPlatSocketContextStartReceive(&Binding->SocketContexts[i]);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
        Binding->SocketContexts[i].IoStarted = TRUE;
    }

    Binding = NULL;

Exit:

    if (Binding != NULL) {
        CxPlatSocketDelete(Binding);
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

#if DEBUG
    CXPLAT_DBG_ASSERT(!Socket->Uninitialized);
    Socket->Uninitialized = TRUE;
#endif

    const uint32_t SocketCount =
        Socket->HasFixedRemoteAddress ? 1 : Socket->Datapath->PartitionCount;

    for (uint32_t i = 0; i < SocketCount; ++i) {
        CxPlatSocketContextUninitialize(&Socket->SocketContexts[i]);
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

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSocketRawSocketAvailable(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    UNREFERENCED_PARAMETER(Socket);
    return FALSE;
}

void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;
        DATAPATH_RX_IO_BLOCK* IoBlock =
            CXPLAT_CONTAINING_RECORD(Datagram, DATAPATH_RX_IO_BLOCK, RecvPacket);
        CxPlatPoolFree(IoBlock);
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
    CXPLAT_DBG_ASSERT(Socket != NULL);

    if (Config->Route->Queue == NULL) {
        Config->Route->Queue = (CXPLAT_QUEUE*)&Socket->SocketContexts[0];
    }

    CXPLAT_SOCKET_CONTEXT* SocketContext = (CXPLAT_SOCKET_CONTEXT*)Config->Route->Queue;
    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(&SocketContext->DatapathPartition->SendDataPool);
    if (SendData != NULL) {
        CxPlatZeroMemory(SendData, sizeof(*SendData));
        SendData->Owner = SocketContext->DatapathPartition;
        SendData->ECN = Config->ECN;
        SendData->DSCP = Config->DSCP;
        SendData->SegmentSize =
            (Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)
                ? Config->MaxPacketSize : 0;
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    for (size_t i = 0; i < SendData->BufferCount; ++i) {
        CxPlatPoolFree(SendData->Buffers[i].Buffer);
    }

    CxPlatPoolFree(SendData);
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
        (SendData->BufferCount < CXPLAT_MAX_BATCH_SEND) ||
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
    CXPLAT_DBG_ASSERT(SendData->BufferCount < CXPLAT_MAX_BATCH_SEND);

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
#ifdef DEBUG
    uint8_t* TailBuffer = SendData->Buffers[SendData->BufferCount - 1].Buffer;
#endif

    if (SendData->SegmentSize == 0) {
#ifdef DEBUG
        CXPLAT_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);
#endif

        CxPlatPoolFree(Buffer->Buffer);
        --SendData->BufferCount;
    } else {
#ifdef DEBUG
        TailBuffer += SendData->Buffers[SendData->BufferCount - 1].Length;
        CXPLAT_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);
#endif

        if (SendData->Buffers[SendData->BufferCount - 1].Length == 0) {
            CxPlatPoolFree(Buffer->Buffer);
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
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint64_t IoResult
    )
{
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            IoResult,
            "sendmmsg completion");
    }

    // TODO to add TCP
    // if (SocketContext->Parent->Type != CXPLAT_SOCKET_UDP) {
    //     SocketContext->Parent->Datapath->TcpHandlers.SendComplete(
    //         SocketContext->Parent,
    //         SocketContext->Parent->ClientContext,
    //         IoResult,
    //         SendData->TotalSize);
    // }

    CxPlatSendDataFree(SendData);
}

QUIC_STATUS
CxPlatSocketSendInternal(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN IsPendedSend
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
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

    CXPLAT_DBG_ASSERT(SocketContext != NULL && RemoteAddress != NULL && SendData != NULL);

    if (!IsPendedSend) {
        CxPlatSendDataFinalizeSendBuffer(SendData);
        for (size_t i = 0; i < SendData->BufferCount; ++i) {
            SendData->Iovs[i].iov_base = SendData->Buffers[i].Buffer;
            SendData->Iovs[i].iov_len = SendData->Buffers[i].Length;
        }
        QuicTraceEvent(
            DatapathSend,
            "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
            SocketContext->Binding,
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
    *(int *)CMSG_DATA(CMsg) = SendData->ECN | (SendData->DSCP << 2);

    if (!SocketContext->Binding->Connected) {
        Mhdr.msg_name = &MappedRemoteAddress;
        Mhdr.msg_namelen = sizeof(MappedRemoteAddress);
        Mhdr.msg_controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
        CMsg = CMSG_NXTHDR(&Mhdr, CMsg);
        CXPLAT_DBG_ASSERT(LocalAddress != NULL);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        if (RemoteAddress->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
            CMsg->cmsg_level = IPPROTO_IP;
#if defined(IP_PKTINFO)
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
#elif defined(IP_RECVDSTADDR)
            CMsg->cmsg_type = IP_RECVDSTADDR;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
#else
#error "No socket option specified"
#endif
            PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
            // TODO: Use Ipv4 instead of Ipv6.
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_spec_dst = LocalAddress->Ipv4.sin_addr;
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
            if (!CxPlatEventQEnqueueEx(
                    SocketContext->DatapathPartition->EventQ,
                    &SocketContext->IoSqe,
                    EVFILT_WRITE,
                    EV_ADD | EV_ONESHOT | EV_CLEAR)) {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "CxPlatEventQEnqueueEx failed");
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

void
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(Socket);
    CXPLAT_DBG_ASSERT(Route->Queue);
    CxPlatSocketSendInternal(
        (CXPLAT_SOCKET_CONTEXT*)Route->Queue,
        &Route->LocalAddress,
        &Route->RemoteAddress,
        SendData,
        FALSE);
}

uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ROUTE* Route
    )
{
    UNREFERENCED_PARAMETER(Route);
    CXPLAT_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketGetTcpStatistics(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ CXPLAT_TCP_STATISTICS* Statistics
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Statistics);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicCopyRouteInfo(
    _Inout_ CXPLAT_ROUTE* DstRoute,
    _In_ CXPLAT_ROUTE* SrcRoute
    )
{
    *DstRoute = *SrcRoute;
}

void
CxPlatResolveRouteComplete(
    _In_ void* Context,
    _Inout_ CXPLAT_ROUTE* Route,
    _In_reads_bytes_(6) const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Route);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(PathId);
}

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
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(PathId);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Callback);
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
    UNREFERENCED_PARAMETER(DstRoute);
    UNREFERENCED_PARAMETER(SrcRoute);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathRssConfigGet(
    _In_ uint32_t InterfaceIndex,
    _Outptr_ _At_(*RssConfig, __drv_allocatesMem(Mem))
        CXPLAT_RSS_CONFIG** RssConfig
    )
{
    UNREFERENCED_PARAMETER(InterfaceIndex);
    UNREFERENCED_PARAMETER(RssConfig);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathRssConfigFree(
    _In_ CXPLAT_RSS_CONFIG* RssConfig
    )
{
    UNREFERENCED_PARAMETER(RssConfig);
    CXPLAT_FRE_ASSERTMSG(FALSE, "CxPlatDataPathRssConfigFree not supported");
}
