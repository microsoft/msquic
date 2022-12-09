/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#include "platform_internal.h"
#include <linux/filter.h>
#include <linux/in6.h>
#include <netinet/udp.h>

#ifdef QUIC_CLOG
#include "datapath_epoll.c.clog.h"
#endif

CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be TRUE.");
CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

#ifdef HAS_SENDMMSG
#define CXPLAT_SENDMMSG sendmmsg
#else
static
int
cxplat_sendmmsg_shim(
    int fd,
    struct mmsghdr* Messages,
    unsigned int MessageLen,
    int Flags
    )
{
    unsigned int SuccessCount = 0;
    while (SuccessCount < MessageLen) {
        int Result = sendmsg(fd, &Messages[SuccessCount].msg_hdr, Flags);
        if (Result < 0) {
            return SuccessCount == 0 ? Result : (int)SuccessCount;
        }
        Messages[SuccessCount].msg_len = Result;
        SuccessCount++;
    }
    return SuccessCount;
}
#define CXPLAT_SENDMMSG cxplat_sendmmsg_shim
#endif

//
// The maximum single buffer size for sending coalesced payloads.
//
#define CXPLAT_LARGE_SEND_BUFFER_SIZE         0xFFFF

#ifdef DISABLE_POSIX_GSO
#ifdef UDP_SEGMENT
#undef UDP_SEGMENT
#endif
#endif

const uint16_t CXPLAT_MAX_BATCH_SEND =
    (CXPLAT_LARGE_SEND_BUFFER_SIZE / (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE));
#define CXPLAT_MAX_BATCH_RECEIVE 43

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
    // The socket context owning this send.
    //
    struct CXPLAT_SOCKET_CONTEXT* SocketContext;

    //
    // Entry in the pending send list.
    //
    CXPLAT_LIST_ENTRY TxEntry;

    //
    // The local address to bind to.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address to send to.
    //
    QUIC_ADDR RemoteAddress;

    //
    // The current QUIC_BUFFER returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

    //
    // The total buffer size for iovecs.
    //
    uint32_t TotalSize;

    //
    // The send segmentation size the app asked for.
    //
    uint16_t SegmentSize;

    //
    // Total number of packet buffers allocated (and iovecs used if !GSO).
    //
    uint16_t BufferCount;

    //
    // The number of iovecs that have been sent out. Only relavent if not doing
    // GSO.
    //
    uint16_t AlreadySentCount;

    //
    // Length of the calculated ControlBuffer. Value is zero until the data is
    // computed.
    //
    uint8_t ControlBufferLength;

    //
    // The type of ECN markings needed for send.
    //
    uint8_t ECN; // CXPLAT_ECN_TYPE

    //
    // Indicates that send is on a connected socket.
    //
    uint8_t OnConnectedSocket : 1;

    //
    // Indicates that segmentation is supported for the send data.
    //
    uint8_t SegmentationSupported : 1;

    //
    // Space for ancillary control data.
    //
    alignas(8)
    char ControlBuffer[
        CMSG_SPACE(sizeof(int)) +               // IP_TOS || IPV6_TCLASS
        CMSG_SPACE(sizeof(struct in6_pktinfo))  // IP_PKTINFO || IPV6_PKTINFO
    #ifdef UDP_SEGMENT
        + CMSG_SPACE(sizeof(uint16_t))          // UDP_SEGMENT
    #endif
        ];
    CXPLAT_STATIC_ASSERT(
        CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)),
        "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");

    //
    // Space for all the packet buffers.
    //
    uint8_t Buffer[CXPLAT_LARGE_SEND_BUFFER_SIZE];

    //
    // IO vectors used for sends on the socket.
    //
    struct iovec Iovs[1]; // variable length, depends on if GSO is being used
                          //   if GSO is used, only 1 is needed
                          //   if GSO is not used, then N are needed

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_RECV_MSG_CONTROL_BUFFER {
    char Data[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
              CMSG_SPACE(sizeof(struct in_pktinfo)) +
              2 * CMSG_SPACE(sizeof(int))];
} CXPLAT_RECV_MSG_CONTROL_BUFFER;

typedef struct CXPLAT_DATAPATH_PROC CXPLAT_DATAPATH_PROC;

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
    CXPLAT_DATAPATH_PROC* DatapathProc;

    //
    // The socket FD used by this socket context.
    //
    int SocketFd;

    //
    // The submission queue event for shutdown.
    //
    DATAPATH_SQE ShutdownSqe;

    //
    // The submission queue event for IO.
    //
    DATAPATH_SQE IoSqe;

    //
    // The submission queue event for flushing the send queue.
    //
    DATAPATH_SQE FlushTxSqe;

    //
    // The I/O vector for receive datagrams.
    //
    struct iovec RecvIov[CXPLAT_MAX_BATCH_RECEIVE];

    //
    // The control buffer used in RecvMsgHdr.
    //
    CXPLAT_RECV_MSG_CONTROL_BUFFER RecvMsgControl[CXPLAT_MAX_BATCH_RECEIVE];

    //
    // The buffer used to receive msg headers on socket.
    //
    struct mmsghdr RecvMsgHdr[CXPLAT_MAX_BATCH_RECEIVE];

    //
    // The receive block currently being used for receives on this socket.
    //
    CXPLAT_DATAPATH_RECV_BLOCK* CurrentRecvBlocks[CXPLAT_MAX_BATCH_RECEIVE];

    //
    // The head of list containg all pending sends on this socket.
    //
    CXPLAT_LIST_ENTRY TxQueue;

    //
    // Lock around the PendingSendData list.
    //
    CXPLAT_LOCK TxQueueLock;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    CXPLAT_RUNDOWN_REF UpcallRundown;

    //
    // Inidicates the SQEs have been initialized.
    //
    BOOLEAN SqeInitialized : 1;

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
typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PROC {

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
    // The ideal processor of the context.
    //
    uint16_t IdealProcessor;

#if DEBUG
    uint8_t Uninitialized : 1;
#endif

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvBlockPool;

    //
    // Pool of send packet contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL SendBlockPool;

} CXPLAT_DATAPATH_PROC;

//
// Represents a datapath object.
//

typedef struct CXPLAT_DATAPATH {

    //
    // UDP handlers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

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
    uint32_t ProcCount;

    //
    // The length of the CXPLAT_SEND_DATA. Calculated based on the support level
    // for GSO. No GSO support requires a larger send data to hold the extra
    // iovec structs.
    //
    uint32_t SendDataSize;

    //
    // When not using GSO, we preallocate multiple iovec structs to use with
    // sendmmsg (to simulate GSO).
    //
    uint32_t SendIoVecCount;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PROC Processors[];

} CXPLAT_DATAPATH;

CXPLAT_DATAPATH_PROC*
CxPlatDataPathGetProc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Processor
    )
{
    for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
        if (Datapath->Processors[i].IdealProcessor == Processor) {
            return &Datapath->Processors[i];
        }
    }
    CXPLAT_FRE_ASSERT(FALSE); // TODO - What now?!
    return NULL;
}

void
CxPlatDataPathCalculateFeatureSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    int UdpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (UdpSocket != INVALID_SOCKET) {
#ifdef UDP_SEGMENT
        int SegmentSize;
        socklen_t OptionLength = sizeof(SegmentSize);
        if (getsockopt(UdpSocket, IPPROTO_UDP, UDP_SEGMENT, &SegmentSize, &OptionLength) != SOCKET_ERROR) {
            Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
        }
#endif
        close(UdpSocket);
    }
}

void
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t IdealProcessor,
    _In_ uint32_t ClientRecvContextLength,
    _Out_ CXPLAT_DATAPATH_PROC* DatapathProc
    )
{
    const uint32_t RecvPacketLength =
        sizeof(CXPLAT_DATAPATH_RECV_BLOCK) + ClientRecvContextLength;

    CXPLAT_DBG_ASSERT(Datapath != NULL);
    DatapathProc->Datapath = Datapath;
    DatapathProc->IdealProcessor = IdealProcessor;
    DatapathProc->EventQ = CxPlatWorkerGetEventQ(IdealProcessor);
    CxPlatRefInitialize(&DatapathProc->RefCount);
    CxPlatPoolInitialize(TRUE, RecvPacketLength, QUIC_POOL_DATA, &DatapathProc->RecvBlockPool);
    CxPlatPoolInitialize(TRUE, Datapath->SendDataSize, QUIC_POOL_DATA, &DatapathProc->SendBlockPool);
}

QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
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

    if (!CxPlatWorkersLazyStart(Config)) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    const uint16_t* ProcessorList;
    uint32_t ProcessorCount;
    if (Config && Config->ProcessorCount) {
        ProcessorCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        ProcessorCount = CxPlatProcMaxCount();
        ProcessorList = NULL;
    }

    const size_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) + ProcessorCount * sizeof(CXPLAT_DATAPATH_PROC);

    CXPLAT_DATAPATH* Datapath =
        (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
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
    Datapath->ProcCount = ProcessorCount;
    Datapath->Features = CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING;
    CxPlatRefInitializeEx(&Datapath->RefCount, Datapath->ProcCount);
    CxPlatDataPathCalculateFeatureSupport(Datapath);

    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        Datapath->SendDataSize = sizeof(CXPLAT_SEND_DATA);
        Datapath->SendIoVecCount = 1;
    } else {
        const uint32_t SendDataSize =
            sizeof(CXPLAT_SEND_DATA) + (CXPLAT_MAX_BATCH_SEND - 1) * sizeof(struct iovec);
        Datapath->SendDataSize = SendDataSize;
        Datapath->SendIoVecCount = CXPLAT_MAX_BATCH_SEND;
    }

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatProcessorContextInitialize(
            Datapath,
            ProcessorList ? ProcessorList[i] : (uint16_t)i,
            ClientRecvContextLength,
            &Datapath->Processors[i]);
    }

    CXPLAT_FRE_ASSERT(CxPlatRundownAcquire(&CxPlatWorkerRundown));
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
        CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
        CxPlatRundownRelease(&CxPlatWorkerRundown);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatProcessorContextRelease(
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
    )
{
    if (CxPlatRefDecrement(&DatapathProc->RefCount)) {
#if DEBUG
        CXPLAT_DBG_ASSERT(!DatapathProc->Uninitialized);
        DatapathProc->Uninitialized = TRUE;
#endif
        CxPlatPoolUninitialize(&DatapathProc->SendBlockPool);
        CxPlatPoolUninitialize(&DatapathProc->RecvBlockPool);
        CxPlatDataPathRelease(DatapathProc->Datapath);
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
        const uint16_t ProcCount = Datapath->ProcCount;
        for (uint32_t i = 0; i < ProcCount; i++) {
            CxPlatProcessorContextRelease(&Datapath->Processors[i]);
        }
    }
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
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
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

QUIC_STATUS
CxPlatSocketConfigureRss(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ uint32_t SocketCount
    )
{
#ifdef SO_ATTACH_REUSEPORT_CBPF
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;

    struct sock_filter BpfCode[] = {
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF | SKF_AD_CPU},
        {BPF_ALU | BPF_MOD, 0, 0, SocketCount},
        {BPF_RET | BPF_A, 0, 0, 0}
    };

    struct sock_fprog BpfConfig = {
        .len = ARRAYSIZE(BpfCode),
        .filter = BpfCode
    };

    Result =
        setsockopt(
            SocketContext->SocketFd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_CBPF,
            (const void*)&BpfConfig,
            sizeof(BpfConfig));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "setsockopt(SO_ATTACH_REUSEPORT_CBPF) failed");
    }

    return Status;
#else
    UNREFERENCED_PARAMETER(SocketContext);
    UNREFERENCED_PARAMETER(SocketCount);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//

QUIC_STATUS
CxPlatSocketContextInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ BOOLEAN ForceShare
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    QUIC_ADDR MappedAddress = {0};
    socklen_t AssignedLocalAddressLength = 0;
    BOOLEAN ShutdownSqeInitialized = FALSE;
    BOOLEAN IoSqeInitialized = FALSE;
    BOOLEAN FlushTxInitialized = FALSE;

    CXPLAT_SOCKET* Binding = SocketContext->Binding;

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathProc->EventQ,
            &SocketContext->ShutdownSqe.Sqe,
            &SocketContext->ShutdownSqe)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }
    ShutdownSqeInitialized = TRUE;

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathProc->EventQ,
            &SocketContext->IoSqe.Sqe,
            &SocketContext->IoSqe)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }
    IoSqeInitialized = TRUE;

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathProc->EventQ,
            &SocketContext->FlushTxSqe.Sqe,
            &SocketContext->FlushTxSqe)) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }
    FlushTxInitialized = TRUE;

    //
    // Create datagram socket.
    //
    SocketContext->SocketFd =
        socket(
            AF_INET6,
            SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, // TODO check if SOCK_CLOEXEC is required?
            IPPROTO_UDP);
    if (SocketContext->SocketFd == INVALID_SOCKET) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }

    //
    // Set dual (IPv4 & IPv6) socket mode.
    //
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

    //
    // Set DON'T FRAG socket option.
    //

    //
    // Windows: setsockopt IPPROTO_IP IP_DONTFRAGMENT TRUE.
    // Linux: IP_DONTFRAGMENT option is not available. IP_MTU_DISCOVER/IPV6_MTU_DISCOVER
    // is the apparent alternative.
    //
    Option = IP_PMTUDISC_PROBE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_MTU_DISCOVER) failed");
        goto Exit;
    }
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_MTU_DISCOVER,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_MTU_DISCOVER) failed");
        goto Exit;
    }

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_DONTFRAG,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IPV6_DONTFRAG) failed");
        goto Exit;
    }

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //

    //
    // Windows: setsockopt IPPROTO_IPV6 IPV6_PKTINFO TRUE.
    // Android: Returns EINVAL. IPV6_PKTINFO option is not present in documentation.
    // IPV6_RECVPKTINFO seems like is the alternative.
    // TODO: Check if this works as expected?
    //
    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVPKTINFO,
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

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_PKTINFO,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_PKTINFO) failed");
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
            IPPROTO_IPV6,
            IPV6_RECVTCLASS,
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

    Option = TRUE;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_RECVTOS,
            (const void*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(IP_RECVTOS) failed");
        goto Exit;
    }

    //
    // The socket is shared by multiple QUIC endpoints, so increase the receive
    // buffer size.
    //
    Option = INT32_MAX;
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
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "setsockopt(SO_RCVBUF) failed");
        goto Exit;
    }

    //
    // Only set SO_REUSEPORT on a server socket, otherwise the client could be
    // assigned a server port (unless it's forcing sharing).
    //
    if (ForceShare || RemoteAddress == NULL) {
        //
        // The port is shared across processors.
        //
        Option = TRUE;
        Result =
            setsockopt(
                SocketContext->SocketFd,
                SOL_SOCKET,
                SO_REUSEPORT,
                (const void*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(SO_REUSEPORT) failed");
            goto Exit;
        }
    }

    CxPlatCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
    if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedAddress.Ipv6.sin6_family = AF_INET6;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            &MappedAddress.Ip,
            sizeof(MappedAddress));
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

    if (RemoteAddress != NULL) {
        CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
        CxPlatConvertToMappedV6(RemoteAddress, &MappedAddress);

        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }

        Result =
            connect(
                SocketContext->SocketFd,
                &MappedAddress.Ip,
                sizeof(MappedAddress));

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

#if DEBUG
    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    } else if (RemoteAddress && LocalAddress && LocalAddress->Ipv4.sin_port == 0) {
        //
        // A client socket being assigned the same port as a remote socket causes issues later
        // in the datapath and binding paths. Check to make sure this case was not given to us.
        //
        CXPLAT_DBG_ASSERT(Binding->LocalAddress.Ipv4.sin_port != RemoteAddress->Ipv4.sin_port);
    }
#else
    UNREFERENCED_PARAMETER(LocalAddress);
#endif

    if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
        Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }

    SocketContext->SqeInitialized = TRUE;

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
        if (ShutdownSqeInitialized) {
            CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->ShutdownSqe.Sqe);
        }
        if (IoSqeInitialized) {
            CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->IoSqe.Sqe);
        }
        if (FlushTxInitialized) {
            CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->FlushTxSqe.Sqe);
        }
    }

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

    for (ssize_t i = 0; i < CXPLAT_MAX_BATCH_RECEIVE; i++) {
        if (SocketContext->CurrentRecvBlocks[i] != NULL) {
            CxPlatRecvDataReturn(&SocketContext->CurrentRecvBlocks[i]->RecvPacket);
        }
    }

    while (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        CxPlatSendDataFree(
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&SocketContext->TxQueue),
                CXPLAT_SEND_DATA,
                TxEntry));
    }

    if (SocketContext->SocketFd != INVALID_SOCKET) {
        epoll_ctl(*SocketContext->DatapathProc->EventQ, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
        close(SocketContext->SocketFd);
    }

    if (SocketContext->SqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->ShutdownSqe.Sqe);
        CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->IoSqe.Sqe);
        CxPlatSqeCleanup(SocketContext->DatapathProc->EventQ, &SocketContext->FlushTxSqe.Sqe);
    }

    CxPlatLockUninitialize(&SocketContext->TxQueueLock);
    CxPlatRundownUninitialize(&SocketContext->UpcallRundown);

    if (SocketContext->DatapathProc) {
        CxPlatProcessorContextRelease(SocketContext->DatapathProc);
    }
    CxPlatSocketRelease(SocketContext->Binding);
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
        epoll_ctl(*SocketContext->DatapathProc->EventQ, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

        CXPLAT_FRE_ASSERT(
            CxPlatEventQEnqueue(
                SocketContext->DatapathProc->EventQ,
                &SocketContext->ShutdownSqe.Sqe,
                &SocketContext->ShutdownSqe));
    }
}

void
CxPlatSocketContextSetEvents(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ int Operation,
    _In_ uint32_t Events
    )
{
    struct epoll_event SockFdEpEvt = {
        .events = Events, .data = { .ptr = &SocketContext->IoSqe, } };

    int Ret =
        epoll_ctl(
            *SocketContext->DatapathProc->EventQ,
            Operation,
            SocketContext->SocketFd,
            &SockFdEpEvt);
    if (Ret != 0) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            errno,
            "epoll_ctl failed");
    }
}

QUIC_STATUS
CxPlatSocketContextPrepareReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CxPlatZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    CxPlatZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    for (ssize_t i = 0; i < CXPLAT_MAX_BATCH_RECEIVE; i++) {
        if (SocketContext->CurrentRecvBlocks[i] == NULL) {
            SocketContext->CurrentRecvBlocks[i] =
                CxPlatDataPathAllocRecvBlock(SocketContext->DatapathProc);
            if (SocketContext->CurrentRecvBlocks[i] == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "CXPLAT_DATAPATH_RECV_BLOCK",
                    0);
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
        }
        CXPLAT_DATAPATH_RECV_BLOCK* CurrentBlock = SocketContext->CurrentRecvBlocks[i];
        struct msghdr* MsgHdr = &SocketContext->RecvMsgHdr[i].msg_hdr;

        SocketContext->RecvIov[i].iov_base = CurrentBlock->RecvPacket.Buffer;
        CurrentBlock->RecvPacket.BufferLength = SocketContext->RecvIov[i].iov_len;
        CurrentBlock->RecvPacket.Route = &CurrentBlock->Route;

        MsgHdr->msg_name = &CurrentBlock->RecvPacket.Route->RemoteAddress;
        MsgHdr->msg_namelen = sizeof(CurrentBlock->RecvPacket.Route->RemoteAddress);
        MsgHdr->msg_iov = &SocketContext->RecvIov[i];
        MsgHdr->msg_iovlen = 1;
        MsgHdr->msg_control = &SocketContext->RecvMsgControl[i].Data;
        MsgHdr->msg_controllen = sizeof(SocketContext->RecvMsgControl[i].Data);
        MsgHdr->msg_flags = 0;
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatSocketContextStartReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = CxPlatSocketContextPrepareReceive(SocketContext);
    if (QUIC_SUCCEEDED(Status)) {
        CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_ADD, EPOLLIN);
    }
    return Status;
}

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ int MessagesReceived
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t BytesTransferred = 0;

    CXPLAT_FRE_ASSERT(MessagesReceived <= CXPLAT_MAX_BATCH_RECEIVE);

    CXPLAT_RECV_DATA* DatagramHead = NULL;
    CXPLAT_RECV_DATA* DatagramTail = NULL;

    for (int CurrentMessage = 0; CurrentMessage < MessagesReceived; CurrentMessage++) {
        CXPLAT_DATAPATH_RECV_BLOCK* CurrentBlock = SocketContext->CurrentRecvBlocks[CurrentMessage];
        SocketContext->CurrentRecvBlocks[CurrentMessage] = NULL;
        CXPLAT_RECV_DATA* RecvPacket = &CurrentBlock->RecvPacket;

        if (DatagramHead == NULL) {
            DatagramHead = RecvPacket;
            DatagramTail = DatagramHead;
        } else {
            DatagramTail->Next = RecvPacket;
            DatagramTail = DatagramTail->Next;
        }

        BOOLEAN FoundLocalAddr = FALSE;
        BOOLEAN FoundTOS = FALSE;
        QUIC_ADDR* LocalAddr = &RecvPacket->Route->LocalAddress;
        if (LocalAddr->Ipv6.sin6_family == AF_INET6) {
            LocalAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        }
        QUIC_ADDR* RemoteAddr = &RecvPacket->Route->RemoteAddress;
        if (RemoteAddr->Ipv6.sin6_family == AF_INET6) {
            RemoteAddr->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        }
        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

        RecvPacket->BufferLength = SocketContext->RecvMsgHdr[CurrentMessage].msg_len;
        BytesTransferred += RecvPacket->BufferLength;

        RecvPacket->TypeOfService = 0;

        struct cmsghdr *CMsg;
        struct msghdr* Msg = &SocketContext->RecvMsgHdr[CurrentMessage].msg_hdr;
        for (CMsg = CMSG_FIRSTHDR(Msg);
            CMsg != NULL;
            CMsg = CMSG_NXTHDR(Msg, CMsg)) {

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
                } else if (CMsg->cmsg_type == IP_TOS) {
                    RecvPacket->TypeOfService = *(uint8_t *)CMSG_DATA(CMsg);
                    FoundTOS = TRUE;
                }
            }
        }

        CXPLAT_FRE_ASSERT(FoundLocalAddr);
        CXPLAT_FRE_ASSERT(FoundTOS);

        RecvPacket->PartitionIndex = SocketContext->DatapathProc->IdealProcessor;

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            (uint32_t)RecvPacket->BufferLength,
            (uint32_t)RecvPacket->BufferLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
    }

    if (BytesTransferred == 0 || DatagramHead == NULL) {
        QuicTraceLogWarning(
            DatapathRecvEmpty,
            "[data][%p] Dropping datagram with empty payload.",
            SocketContext->Binding);
        goto Drop;
    }

    if (!SocketContext->Binding->PcpBinding) {
        CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath->UdpHandlers.Receive);
        SocketContext->Binding->Datapath->UdpHandlers.Receive(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            DatagramHead);
    } else{
        CxPlatPcpRecvCallback(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            DatagramHead);
    }

Drop: ;

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

    const uint32_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;
    CXPLAT_FRE_ASSERT(SocketCount > 0);
    const uint32_t CurrentProc = CxPlatProcCurrentNumber() % Datapath->ProcCount;
    const size_t BindingLength =
        sizeof(CXPLAT_SOCKET) + SocketCount * sizeof(CXPLAT_SOCKET_CONTEXT);

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
        Binding->SocketContexts[i].ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        Binding->SocketContexts[i].IoSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_IO;
        Binding->SocketContexts[i].FlushTxSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX;
        for (ssize_t j = 0; j < CXPLAT_MAX_BATCH_RECEIVE; j++) {
            Binding->SocketContexts[i].RecvIov[j].iov_len =
                Binding->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
        }
        Binding->SocketContexts[i].DatapathProc =
            IsServerSocket ?
                &Datapath->Processors[i] :
                CxPlatDataPathGetProc(Datapath, CurrentProc);
        CxPlatRefIncrement(&Binding->SocketContexts[i].DatapathProc->RefCount);
        CxPlatListInitializeHead(&Binding->SocketContexts[i].TxQueue);
        CxPlatLockInitialize(&Binding->SocketContexts[i].TxQueueLock);
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
                Config->RemoteAddress,
                Config->Flags & CXPLAT_SOCKET_FLAG_SHARE);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    if (IsServerSocket) {
        //
        // The return value is being ignored here, as if a system does not support
        // bpf we still want the server to work. If this happens, the sockets will
        // round robin, but each flow will be sent to the same socket, just not
        // based on RSS.
        //
        (void)CxPlatSocketConfigureRss(&Binding->SocketContexts[0], SocketCount);
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
        Socket->HasFixedRemoteAddress ? 1 : Socket->Datapath->ProcCount;

    for (uint32_t i = 0; i < SocketCount; ++i) {
        CxPlatSocketContextUninitialize(&Socket->SocketContexts[i]);
    }
}
uint16_t
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
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
    CXPLAT_DBG_ASSERT(MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);

    CXPLAT_SOCKET_CONTEXT* SocketContext;
    if (Socket->HasFixedRemoteAddress) {
        SocketContext = &Socket->SocketContexts[0];
    } else {
        uint32_t ProcNumber = CxPlatProcCurrentNumber() % Socket->Datapath->ProcCount;
        SocketContext = &Socket->SocketContexts[ProcNumber];
    }

    CXPLAT_SEND_DATA* SendData =
        CxPlatPoolAlloc(&SocketContext->DatapathProc->SendBlockPool);
    if (SendData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEND_DATA",
            Socket->Datapath->SendDataSize);
    } else {
        SendData->SocketContext = SocketContext;
        SendData->ClientBuffer.Buffer = SendData->Buffer;
        SendData->ClientBuffer.Length = 0;
        SendData->TotalSize = 0;
        SendData->SegmentSize = MaxPacketSize;
        SendData->BufferCount = 0;
        SendData->AlreadySentCount = 0;
        SendData->ControlBufferLength = 0;
        SendData->ECN = ECN;
        SendData->OnConnectedSocket = Socket->Connected;
        SendData->SegmentationSupported =
            !!(Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
        SendData->Iovs[0].iov_len = 0;
        SendData->Iovs[0].iov_base = SendData->Buffer;
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatPoolFree(&SendData->SocketContext->DatapathProc->SendBlockPool, SendData);
}

static
void
CxPlatSendDataFinalizeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->ClientBuffer.Length == 0) { // No buffer to finalize.
        return;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize == 0 || SendData->ClientBuffer.Length <= SendData->SegmentSize);
    CXPLAT_DBG_ASSERT(SendData->TotalSize + SendData->ClientBuffer.Length <= sizeof(SendData->Buffer));

    SendData->BufferCount++;
    SendData->TotalSize += SendData->ClientBuffer.Length;
    if (SendData->SegmentationSupported) {
        SendData->Iovs[0].iov_len += SendData->ClientBuffer.Length;
        if (SendData->SegmentSize == 0 ||
            SendData->ClientBuffer.Length < SendData->SegmentSize ||
            SendData->TotalSize + SendData->SegmentSize > sizeof(SendData->Buffer)) {
            SendData->ClientBuffer.Buffer = NULL;
        } else {
            SendData->ClientBuffer.Buffer += SendData->SegmentSize;
        }
    } else {
        struct iovec* IoVec = &SendData->Iovs[SendData->BufferCount - 1];
        IoVec->iov_base = SendData->ClientBuffer.Buffer;
        IoVec->iov_len = SendData->ClientBuffer.Length;
        if (SendData->TotalSize + SendData->SegmentSize > sizeof(SendData->Buffer) ||
            SendData->BufferCount == SendData->SocketContext->DatapathProc->Datapath->SendIoVecCount) {
            SendData->ClientBuffer.Buffer = NULL;
        } else {
            SendData->ClientBuffer.Buffer += SendData->ClientBuffer.Length;
        }
    }
    SendData->ClientBuffer.Length = 0;
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
    CxPlatSendDataFinalizeSendBuffer(SendData);
    CXPLAT_DBG_ASSERT(SendData->SegmentSize == 0 || SendData->SegmentSize >= MaxBufferLength);
    CXPLAT_DBG_ASSERT(SendData->TotalSize + MaxBufferLength <= sizeof(SendData->Buffer));
    CXPLAT_DBG_ASSERT(
        SendData->SegmentationSupported ||
        SendData->BufferCount < SendData->SocketContext->DatapathProc->Datapath->SendIoVecCount);
    UNREFERENCED_PARAMETER(MaxBufferLength);
    if (SendData->ClientBuffer.Buffer == NULL) {
        return NULL;
    }
    SendData->ClientBuffer.Length = MaxBufferLength;
    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    //
    // This must be the final send buffer; intermediate Iovs cannot be freed.
    //
    CXPLAT_DBG_ASSERT(Buffer == &SendData->ClientBuffer);
    Buffer->Length = 0;
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatSendDataFinalizeSendBuffer(SendData);
    return SendData->ClientBuffer.Buffer == NULL;
}

QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(IdealProcessor);

    //
    // Finalize the state of the send data and log the send.
    //
    CxPlatSendDataFinalizeSendBuffer(SendData);
    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->TotalSize,
        SendData->BufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    //
    // Cache the address, mapping the remote address as necessary.
    //
    CxPlatConvertToMappedV6(&Route->RemoteAddress, &SendData->RemoteAddress);
    SendData->LocalAddress = Route->LocalAddress;

    //
    // Queue the send and flush if necessary.
    //
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    CxPlatLockAcquire(&SocketContext->TxQueueLock);
    BOOLEAN FlushQueue = CxPlatListIsEmpty(&SocketContext->TxQueue);
    CxPlatListInsertTail(
        &SocketContext->TxQueue,
        &SendData->TxEntry);
    CxPlatLockRelease(&SocketContext->TxQueueLock);

    if (FlushQueue) {
        CXPLAT_FRE_ASSERT(
            CxPlatEventQEnqueue(
                SocketContext->DatapathProc->EventQ,
                &SocketContext->FlushTxSqe.Sqe,
                &SocketContext->FlushTxSqe));
    }

    return QUIC_STATUS_SUCCESS;
}

//
// This is defined and used instead of CMSG_NXTHDR because (1) we've already
// done the work to ensure the necessary space is available and (2) CMSG_NXTHDR
// apparently not only checks there is enough space to move to the next pointer
// but somehow assumes the next pointer has been writen already (?!) and tries
// to validate its length as well. That would work if you're reading an already
// populated buffer, but not if you're building one up (unless you've zero-init
// the entire buffer).
//
#define CXPLAT_CMSG_NXTHDR(cmsg) \
    (struct cmsghdr*)((uint8_t*)cmsg + CMSG_ALIGN(cmsg->cmsg_len))

void
CxPlatSendDataPopulateAncillaryData(
    _In_ CXPLAT_SEND_DATA* SendData,
    _Inout_ struct msghdr* Mhdr
    )
{
    Mhdr->msg_controllen = CMSG_SPACE(sizeof(int));
    struct cmsghdr *CMsg = CMSG_FIRSTHDR(Mhdr);
    CMsg->cmsg_level = SendData->LocalAddress.Ip.sa_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    CMsg->cmsg_type = SendData->LocalAddress.Ip.sa_family == AF_INET ? IP_TOS : IPV6_TCLASS;
    CMsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int*)CMSG_DATA(CMsg) = SendData->ECN;

    if (!SendData->OnConnectedSocket) {
        if (SendData->LocalAddress.Ip.sa_family == AF_INET) {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(struct in_pktinfo));
            CMsg = CXPLAT_CMSG_NXTHDR(CMsg);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo *PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
            PktInfo->ipi_ifindex = SendData->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo->ipi_spec_dst.s_addr = 0;
            PktInfo->ipi_addr = SendData->LocalAddress.Ipv4.sin_addr;
        } else {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
            CMsg = CXPLAT_CMSG_NXTHDR(CMsg);
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo *PktInfo6 = (struct in6_pktinfo*)CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = SendData->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = SendData->LocalAddress.Ipv6.sin6_addr;
        }
    }

#ifdef UDP_SEGMENT
    if (SendData->SegmentationSupported && SendData->SegmentSize > 0) {
        Mhdr->msg_controllen += CMSG_SPACE(sizeof(uint16_t));
        CMsg = CXPLAT_CMSG_NXTHDR(CMsg);
        CMsg->cmsg_level = SOL_UDP;
        CMsg->cmsg_type = UDP_SEGMENT;
        CMsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
        *((uint16_t*)CMSG_DATA(CMsg)) = SendData->SegmentSize;
    }
#endif

    CXPLAT_DBG_ASSERT(Mhdr->msg_controllen <= sizeof(SendData->ControlBuffer));
    SendData->ControlBufferLength = (uint8_t)Mhdr->msg_controllen;
}

BOOLEAN
CxPlatSendDataSendSegmented(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    struct msghdr msghdr;
    msghdr.msg_name = (void*)&SendData->RemoteAddress;
    msghdr.msg_namelen = sizeof(SendData->RemoteAddress);
    msghdr.msg_iov = SendData->Iovs;
    msghdr.msg_iovlen = 1;
    msghdr.msg_flags = 0;
    msghdr.msg_control = SendData->ControlBuffer;
    msghdr.msg_controllen = SendData->ControlBufferLength;
    if (SendData->ControlBufferLength == 0) {
        CxPlatSendDataPopulateAncillaryData(SendData, &msghdr);
    } else {
        msghdr.msg_controllen = SendData->ControlBufferLength;
    }

    if (sendmsg(SendData->SocketContext->SocketFd, &msghdr, 0) < 0) {
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
CxPlatSendDataSendMessages(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    struct mmsghdr Mhdrs[CXPLAT_MAX_BATCH_SEND];
    for (uint16_t i = SendData->AlreadySentCount; i < SendData->BufferCount; ++i) {
        struct msghdr* Mhdr = &Mhdrs[i].msg_hdr;
        Mhdrs[i].msg_len = 0;
        Mhdr->msg_name = (void*)&SendData->RemoteAddress;
        Mhdr->msg_namelen = sizeof(SendData->RemoteAddress);
        Mhdr->msg_iov = SendData->Iovs + i;
        Mhdr->msg_iovlen = 1;
        Mhdr->msg_flags = 0;
        Mhdr->msg_control = SendData->ControlBuffer;
        Mhdr->msg_controllen = SendData->ControlBufferLength;

        if (SendData->ControlBufferLength == 0) {
            CxPlatSendDataPopulateAncillaryData(SendData, Mhdr);
        } else {
            Mhdr->msg_controllen = SendData->ControlBufferLength;
        }
    }

    while (SendData->AlreadySentCount < SendData->BufferCount) {
        int SuccessfullySentMessages =
            CXPLAT_SENDMMSG(
                SendData->SocketContext->SocketFd,
                Mhdrs + SendData->AlreadySentCount,
                (unsigned int)(SendData->BufferCount - SendData->AlreadySentCount),
                0);
        CXPLAT_FRE_ASSERT(SuccessfullySentMessages != 0);
        if (SuccessfullySentMessages < 0) {
            return FALSE;
        }

        SendData->AlreadySentCount += SuccessfullySentMessages;
    }

    return TRUE;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(SendData->AlreadySentCount < CXPLAT_MAX_BATCH_SEND);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    BOOLEAN Success =
#ifdef UDP_SEGMENT
        SendData->SegmentationSupported ?
            CxPlatSendDataSendSegmented(SendData) :
#endif
            CxPlatSendDataSendMessages(SendData);
    if (!Success) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            Status = QUIC_STATUS_PENDING;
        } else {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                Status,
                "sendmmsg failed");

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
        }
    }

    return Status;
}

//
// Returns TRUE if the queue was completely drained, and FALSE if there are
// still pending sends.
//
void
CxPlatSocketContextFlushTxQueue(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ BOOLEAN SendAlreadyPending
    )
{
    CXPLAT_SEND_DATA* SendData = NULL;
    CxPlatLockAcquire(&SocketContext->TxQueueLock);
    if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        SendData =
            CXPLAT_CONTAINING_RECORD(
                SocketContext->TxQueue.Flink,
                CXPLAT_SEND_DATA,
                TxEntry);
    }
    CxPlatLockRelease(&SocketContext->TxQueueLock);

    while (SendData != NULL) {
        if (CxPlatSendDataSend(SendData) == QUIC_STATUS_PENDING) {
            if (!SendAlreadyPending) {
                //
                // Add the EPOLLOUT event since we have more pending sends.
                //
                CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
            }
            return;
        }

        CxPlatLockAcquire(&SocketContext->TxQueueLock);
        CxPlatListRemoveHead(&SocketContext->TxQueue);
        CxPlatSendDataFree(SendData);
        if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
            SendData =
                CXPLAT_CONTAINING_RECORD(
                    SocketContext->TxQueue.Flink,
                    CXPLAT_SEND_DATA,
                    TxEntry);
        } else {
            SendData = NULL;
        }
        CxPlatLockRelease(&SocketContext->TxQueueLock);
    }

    if (SendAlreadyPending) {
        //
        // Remove the EPOLLOUT event since we don't have any more pending sends.
        //
        CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_MOD, EPOLLIN);
    }
}

void
CxPlatDataPathSocketProcessIoCompletion(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (!CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
        return;
    }

    if (EPOLLERR & Cqe->events) {
        int ErrNum = 0;
        socklen_t OptLen = sizeof(ErrNum);
        ssize_t Ret =
            getsockopt(
                SocketContext->SocketFd,
                SOL_SOCKET,
                SO_ERROR,
                &ErrNum,
                &OptLen);
        if (Ret < 0) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                errno,
                "getsockopt(SO_ERROR) failed");
        } else {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketContext->Binding,
                ErrNum,
                "Socket error event");

            //
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
    }

    if (EPOLLIN & Cqe->events) {
        //
        // Read up to 4 receives before moving to another event.
        //
        for (int i = 0; i < 4; i++) {

            for (ssize_t i = 0; i < CXPLAT_MAX_BATCH_RECEIVE; i++) {
                CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvBlocks[i] != NULL);
            }

            int Ret =
                recvmmsg(
                    SocketContext->SocketFd,
                    SocketContext->RecvMsgHdr,
                    CXPLAT_MAX_BATCH_RECEIVE,
                    0,
                    NULL);
            if (Ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        errno,
                        "recvmmsg failed");
                }
                break;
            }
            CxPlatSocketContextRecvComplete(SocketContext, Ret);
        }
    }

    if (EPOLLOUT & Cqe->events) {
        CxPlatSocketContextFlushTxQueue(SocketContext, TRUE);
    }

    CxPlatRundownRelease(&SocketContext->UpcallRundown);
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        CXPLAT_SOCKET_CONTEXT* SocketContext =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, ShutdownSqe);
        CxPlatSocketContextUninitializeComplete(SocketContext);
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        CXPLAT_SOCKET_CONTEXT* SocketContext =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, IoSqe);
        CxPlatDataPathSocketProcessIoCompletion(SocketContext, Cqe);
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_FLUSH_TX: {
        CXPLAT_SOCKET_CONTEXT* SocketContext =
            CXPLAT_CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_CONTEXT, FlushTxSqe);
        CxPlatSocketContextFlushTxQueue(SocketContext, FALSE);
        break;
    }
    }
}
