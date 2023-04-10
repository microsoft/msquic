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

//
// The maximum single buffer size for single packet/datagram IO payloads.
//
#define CXPLAT_SMALL_IO_BUFFER_SIZE         MAX_UDP_PAYLOAD_LENGTH

//
// The maximum single buffer size for coalesced IO payloads.
//
#define CXPLAT_LARGE_IO_BUFFER_SIZE         0xFFFF

//
// The maximum batch size of IOs in that can use a single coalesced IO buffer.
// This is calculated base on the number of the smallest possible single
// packet/datagram payloads (i.e. IPv6) that can fit in the large buffer.
//
const uint16_t CXPLAT_MAX_IO_BATCH_SIZE =
    (CXPLAT_LARGE_IO_BUFFER_SIZE / (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE));

typedef struct CXPLAT_RECV_SUBBLOCK {

    struct CXPLAT_RECV_BLOCK* RecvBlock;
    CXPLAT_RECV_DATA RecvData;
    // CXPLAT_RECV_PACKET RecvPacket;

} CXPLAT_RECV_SUBBLOCK;

//
// A receive block to receive a UDP packet over the sockets.
//
typedef struct CXPLAT_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //
    CXPLAT_POOL* OwningPool;

    //
    // Represents the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // Ref count of receive data/packets that are using this block.
    //
    long RefCount;

    //
    // An array of sub-blocks to represent the datagram and metadata returned to
    // the app.
    //
    //CXPLAT_RECV_SUBBLOCK SubBlocks[0];

    //
    // Buffer that actually stores the UDP payload.
    //
    //uint8_t Buffer[]; // CXPLAT_SMALL_IO_BUFFER_SIZE or CXPLAT_LARGE_IO_BUFFER_SIZE

} CXPLAT_RECV_BLOCK;

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
    // Set of flags set to configure the send behavior.
    //
    uint8_t Flags; // CXPLAT_SEND_FLAGS

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
    uint8_t Buffer[CXPLAT_LARGE_IO_BUFFER_SIZE];

    //
    // IO vectors used for sends on the socket.
    //
    struct iovec Iovs[1]; // variable length, depends on if GSO is being used
                          //   if GSO is used, only 1 is needed
                          //   if GSO is not used, then N are needed

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_RECV_MSG_CONTROL_BUFFER {
    char Data[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
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

    struct xsk_socket_info* xsk_info;
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

    //
    // The length of the CXPLAT_RECV_DATA and CXPLAT_RECV_PACKET part of the
    // CXPLAT_RECV_BLOCK.
    //
    uint32_t RecvBlockStride;

    //
    // The offset of the raw buffer in the CXPLAT_RECV_BLOCK.
    //
    uint32_t RecvBlockBufferOffset;

    //
    // The total length of the CXPLAT_RECV_BLOCK. Calculated based on the
    // support level for GRO. No GRO only uses a single CXPLAT_RECV_DATA and
    // CXPLAT_RECV_PACKET, while GRO allows for multiple.
    //
    uint32_t RecvBlockSize;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // The per proc datapath contexts.
    //
    CXPLAT_DATAPATH_PROC Processors[];

} CXPLAT_DATAPATH;

#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include <net/if.h>

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	// struct stats_record stats;
	// struct stats_record prev_stats;
};

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};


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

#ifdef DEBUG
#define CXPLAT_DBG_ASSERT_CMSG(CMsg, type) \
    if (CMsg->cmsg_len < CMSG_LEN(sizeof(type))) { \
        printf("%u: cmsg[%u:%u] len (%u) < exp_len (%u)\n", \
            (uint32_t)__LINE__, \
            (uint32_t)CMsg->cmsg_level, (uint32_t)CMsg->cmsg_type, \
            (uint32_t)CMsg->cmsg_len, (uint32_t)CMSG_LEN(sizeof(type))); \
    }
#else
#define CXPLAT_DBG_ASSERT_CMSG(CMsg, type)
#endif

void
CxPlatDataPathCalculateFeatureSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength
    )
{
#ifdef UDP_SEGMENT
    //
    // Open up two sockets and send with GSO and receive with GRO, and make sure
    // everything **actually** works, so that we can be sure we can leverage
    // GRO.
    //
    int SendSocket = INVALID_SOCKET, RecvSocket = INVALID_SOCKET;
    struct sockaddr_in RecvAddr = {0}, RecvAddr2 = {0};
    socklen_t RecvAddrSize = sizeof(RecvAddr), RecvAddr2Size = sizeof(RecvAddr2);
    int PktInfoEnabled = 1, TosEnabled = 1, GroEnabled = 1;
    uint8_t Buffer[8 * 1476] = {0};
    struct iovec IoVec;
    IoVec.iov_base = Buffer;
    IoVec.iov_len = sizeof(Buffer);
    char SendControlBuffer[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))] = {0};
    struct msghdr SendMsg = {0};
    SendMsg.msg_name = &RecvAddr;
    SendMsg.msg_namelen = RecvAddrSize;
    SendMsg.msg_iov = &IoVec;
    SendMsg.msg_iovlen = 1;
    SendMsg.msg_control = SendControlBuffer;
    SendMsg.msg_controllen = sizeof(SendControlBuffer);
    struct cmsghdr *CMsg = CMSG_FIRSTHDR(&SendMsg);
    CMsg->cmsg_level = IPPROTO_IP;
    CMsg->cmsg_type = IP_TOS;
    CMsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int*)CMSG_DATA(CMsg) = 0x1;
    CMsg = CMSG_NXTHDR(&SendMsg, CMsg);
    CMsg->cmsg_level = SOL_UDP;
    CMsg->cmsg_type = UDP_SEGMENT;
    CMsg->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *((uint16_t*)CMSG_DATA(CMsg)) = 1476;
    RecvAddr.sin_family = AF_INET;
    RecvAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    char RecvControlBuffer[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
    struct msghdr RecvMsg = {0};
    RecvMsg.msg_name = &RecvAddr2;
    RecvMsg.msg_namelen = RecvAddr2Size;
    RecvMsg.msg_iov = &IoVec;
    RecvMsg.msg_iovlen = 1;
    RecvMsg.msg_control = RecvControlBuffer;
    RecvMsg.msg_controllen = sizeof(RecvControlBuffer);
#define VERIFY(X) if (!(X)) { goto Error; }
    SendSocket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    VERIFY(SendSocket != INVALID_SOCKET)
    RecvSocket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    VERIFY(RecvSocket != INVALID_SOCKET)
    VERIFY(setsockopt(SendSocket, IPPROTO_IP, IP_PKTINFO, &PktInfoEnabled, sizeof(PktInfoEnabled)) != SOCKET_ERROR)
    VERIFY(setsockopt(RecvSocket, IPPROTO_IP, IP_PKTINFO, &PktInfoEnabled, sizeof(PktInfoEnabled)) != SOCKET_ERROR)
    VERIFY(setsockopt(SendSocket, IPPROTO_IP, IP_RECVTOS, &TosEnabled, sizeof(TosEnabled)) != SOCKET_ERROR)
    VERIFY(setsockopt(RecvSocket, IPPROTO_IP, IP_RECVTOS, &TosEnabled, sizeof(TosEnabled)) != SOCKET_ERROR)
    VERIFY(bind(RecvSocket, (struct sockaddr*)&RecvAddr, RecvAddrSize) != SOCKET_ERROR)
#ifdef UDP_GRO
    VERIFY(setsockopt(RecvSocket, SOL_UDP, UDP_GRO, &GroEnabled, sizeof(GroEnabled)) != SOCKET_ERROR)
#endif
    VERIFY(getsockname(RecvSocket, (struct sockaddr*)&RecvAddr, &RecvAddrSize) != SOCKET_ERROR)
    VERIFY(connect(SendSocket, (struct sockaddr*)&RecvAddr, RecvAddrSize) != SOCKET_ERROR)
    VERIFY(sendmsg(SendSocket, &SendMsg, 0) == sizeof(Buffer))
    //
    // We were able to at least send successfully, so indicate the send
    // segmentation feature as available.
    //
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
#ifdef UDP_GRO
    VERIFY(recvmsg(RecvSocket, &RecvMsg, 0) == sizeof(Buffer))
    BOOLEAN FoundPKTINFO = FALSE, FoundTOS = FALSE, FoundGRO = FALSE;
    for (CMsg = CMSG_FIRSTHDR(&RecvMsg); CMsg != NULL; CMsg = CMSG_NXTHDR(&RecvMsg, CMsg)) {
        if (CMsg->cmsg_level == IPPROTO_IP) {
            if (CMsg->cmsg_type == IP_PKTINFO) {
                FoundPKTINFO = TRUE;
            } else if (CMsg->cmsg_type == IP_TOS) {
                CXPLAT_DBG_ASSERT_CMSG(CMsg, uint8_t);
                VERIFY(0x1 == *(uint8_t*)CMSG_DATA(CMsg))
                FoundTOS = TRUE;
            }
        } else if (CMsg->cmsg_level == IPPROTO_UDP) {
            if (CMsg->cmsg_type == UDP_GRO) {
                CXPLAT_DBG_ASSERT_CMSG(CMsg, uint16_t);
                VERIFY(1476 == *(uint16_t*)CMSG_DATA(CMsg))
                FoundGRO = TRUE;
            }
        }
    }
    VERIFY(FoundPKTINFO)
    VERIFY(FoundTOS)
    VERIFY(FoundGRO)
    //
    // We were able receive everything successfully so we can indicate the
    // receive coalescing feature as available.
    //
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_COALESCING;
#endif // UDP_GRO
Error:
    if (RecvSocket != INVALID_SOCKET) { close(RecvSocket); }
    if (SendSocket != INVALID_SOCKET) { close(SendSocket); }
#endif // UDP_SEGMENT

    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        Datapath->SendDataSize = sizeof(CXPLAT_SEND_DATA);
        Datapath->SendIoVecCount = 1;
    } else {
        const uint32_t SendDataSize =
            sizeof(CXPLAT_SEND_DATA) + (CXPLAT_MAX_IO_BATCH_SIZE - 1) * sizeof(struct iovec);
        Datapath->SendDataSize = SendDataSize;
        Datapath->SendIoVecCount = CXPLAT_MAX_IO_BATCH_SIZE;
    }

    Datapath->RecvBlockStride =
        sizeof(CXPLAT_RECV_SUBBLOCK) + ClientRecvContextLength;
    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
        Datapath->RecvBlockBufferOffset =
            sizeof(CXPLAT_RECV_BLOCK) +
            CXPLAT_MAX_IO_BATCH_SIZE * Datapath->RecvBlockStride;
        Datapath->RecvBlockSize =
            Datapath->RecvBlockBufferOffset + CXPLAT_LARGE_IO_BUFFER_SIZE;
    } else {
        Datapath->RecvBlockBufferOffset =
            sizeof(CXPLAT_RECV_BLOCK) + Datapath->RecvBlockStride;
        Datapath->RecvBlockSize =
            Datapath->RecvBlockBufferOffset + CXPLAT_SMALL_IO_BUFFER_SIZE;
    }
}

void
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t IdealProcessor,
    _Out_ CXPLAT_DATAPATH_PROC* DatapathProc
    )
{
    CXPLAT_DBG_ASSERT(Datapath != NULL);
    DatapathProc->Datapath = Datapath;
    DatapathProc->IdealProcessor = IdealProcessor;
    DatapathProc->EventQ = CxPlatWorkerGetEventQ(IdealProcessor);
    CxPlatRefInitialize(&DatapathProc->RefCount);
    CxPlatPoolInitialize(TRUE, Datapath->RecvBlockSize, QUIC_POOL_DATA, &DatapathProc->RecvBlockPool);
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
    CxPlatDataPathCalculateFeatureSupport(Datapath, ClientRecvContextLength);

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatProcessorContextInitialize(
            Datapath,
            ProcessorList ? ProcessorList[i] : (uint16_t)i,
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

    struct sock_fprog BpfConfig = {0};
	BpfConfig.len = ARRAYSIZE(BpfCode);
    BpfConfig.filter = BpfCode;

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

// TODO: use QUIC error code
/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}
	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
}

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* This struct allow us to set ifindex, this features is used for
	 * hardware offloading XDP programs (note this sets libbpf
	 * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.ifindex   = ifindex,
	};
	prog_load_attr.file = filename;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

struct bpf_object *load_bpf_and_xdp_attach(const char* filename, char* progsec, int ifindex)
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0; // ?
	int prog_fd = -1;
	int err;

    bpf_obj = load_bpf_object_file(filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, progsec);
	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", progsec);
		exit(EXIT_FAIL_BPF);
	}

	//strncpy(progsec, bpf_program__section_name(bpf_prog), 32);

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
    int xdp_flags = 0;
	err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
	if (err)
		exit(err);

	return bpf_obj;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
			       NULL);
	if (ret) {
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
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
    // TODO: use
    QUIC_ADDR_STR LocalAddrStr;
    QUIC_ADDR_STR RemoteAddrStr;
    if (LocalAddress)
        QuicAddrToString(LocalAddress, &LocalAddrStr);
    if (RemoteAddress)
        QuicAddrToString(RemoteAddress, &RemoteAddrStr);

    fprintf(stderr, "IN CxPlatSocketContextInitialize Local:%s, Remote:%s\n", LocalAddress ? LocalAddrStr.Address : "NULL", RemoteAddress ? RemoteAddrStr.Address : "NULL");
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    // int Result = 0;
    // int Option = 0;
    // QUIC_ADDR MappedAddress = {0};
    // socklen_t AssignedLocalAddressLength = 0;
    BOOLEAN ShutdownSqeInitialized = FALSE;
    BOOLEAN IoSqeInitialized = FALSE;
    BOOLEAN FlushTxInitialized = FALSE;

    CXPLAT_SOCKET* Binding = SocketContext->Binding;

    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathProc->Datapath);

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

    // TODO: input via config?
    //const char* ifname = "eth0";
    const char* ifname = "lo";
    int ifindex = if_nametoindex(ifname);

    fprintf(stderr, "bef load_bpf_and_xdp_attach\n");
    struct bpf_object *bpf_obj = load_bpf_and_xdp_attach("./datapath_raw_xdp_kern.o", "xdp_prog", ifindex);
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "xsks_map");
    int xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks map found: %s\n",
            strerror(xsks_map_fd));
        exit(EXIT_FAILURE);
    }

	void *packet_buffer;
	uint64_t packet_buffer_size;
	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
			   getpagesize(), /* PAGE_SIZE aligned */
			   packet_buffer_size)) {
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
    struct xsk_umem_info *umem;
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL) {
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

    //
    // Create datagram socket.
    //
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	uint32_t prog_id = 0;
	int i;
	int ret;

	xsk_info = calloc(1, sizeof(*xsk_info)); // TODO: free
	if (!xsk_info) {
		goto Exit;
    }

    // TODO: share port from Binding->LocalAddress to BPF map
	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    // TODO: auto detect?
	xsk_cfg.libbpf_flags = 0;
	// xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
	// xsk_cfg.bind_flags = XDP_COPY;
	xsk_cfg.xdp_flags = 0;
	xsk_cfg.bind_flags = 0;
    int queue_id = 0; // TODO: check
    fprintf(stderr, "bef xsk_socket__create\n");
	ret = xsk_socket__create(&xsk_info->xsk, ifname,
				 queue_id, umem->umem, &xsk_info->rx,
				 &xsk_info->tx, &xsk_cfg);
    if (ret) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "socket failed");
        goto Exit;
    }
    SocketContext->xsk_info = xsk_info;
	
    ret = bpf_get_link_xdp_id(ifindex, &prog_id, xsk_cfg.xdp_flags);
    if (ret) {
        goto Exit;
    }

	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
				     XSK_RING_PROD__DEFAULT_NUM_DESCS,
				     &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		goto Exit;
    }

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++) {
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);
    }

	xsk_ring_prod__submit(&xsk_info->umem->fq,
			      XSK_RING_PROD__DEFAULT_NUM_DESCS);

    //
    // Set dual (IPv4 & IPv6) socket mode.
    //
    // Option = FALSE;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IPV6,
    //         IPV6_V6ONLY,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IPV6_V6ONLY) failed");
    //     goto Exit;
    // }

    //
    // Set DON'T FRAG socket option.
    //

    //
    // Windows: setsockopt IPPROTO_IP IP_DONTFRAGMENT TRUE.
    // Linux: IP_DONTFRAGMENT option is not available. IP_MTU_DISCOVER/IPV6_MTU_DISCOVER
    // is the apparent alternative.
    //
    // Option = IP_PMTUDISC_PROBE;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IP,
    //         IP_MTU_DISCOVER,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IP_MTU_DISCOVER) failed");
    //     goto Exit;
    // }
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IPV6,
    //         IPV6_MTU_DISCOVER,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IPV6_MTU_DISCOVER) failed");
    //     goto Exit;
    // }

    // Option = TRUE;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IPV6,
    //         IPV6_DONTFRAG,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IPV6_DONTFRAG) failed");
    //     goto Exit;
    // }

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //

    //
    // Windows: setsockopt IPPROTO_IPV6 IPV6_PKTINFO TRUE.
    // Android: Returns EINVAL. IPV6_PKTINFO option is not present in documentation.
    // IPV6_RECVPKTINFO seems like is the alternative.
    // TODO: Check if this works as expected?
    //
    // Option = TRUE;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IPV6,
    //         IPV6_RECVPKTINFO,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IPV6_RECVPKTINFO) failed");
    //     goto Exit;
    // }

    //
    // Set socket option to receive TOS (= DSCP + ECN) information from the
    // incoming packet.
    //
    // Option = TRUE;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IPV6,
    //         IPV6_RECVTCLASS,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IPV6_RECVTCLASS) failed");
    //     goto Exit;
    // }

    // Option = TRUE;
    // Result =
    //     setsockopt(
    //         SocketContext->SocketFd,
    //         IPPROTO_IP,
    //         IP_RECVTOS,
    //         (const void*)&Option,
    //         sizeof(Option));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(IP_RECVTOS) failed");
    //     goto Exit;
    // }

#ifdef UDP_GRO
    if (SocketContext->DatapathProc->Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
        // Option = TRUE;
        // Result =
        //     setsockopt(
        //         SocketContext->SocketFd,
        //         SOL_UDP,
        //         UDP_GRO,
        //         (const void*)&Option,
        //         sizeof(Option));
        // if (Result == SOCKET_ERROR) {
        //     Status = errno;
        //     QuicTraceEvent(
        //         DatapathErrorStatus,
        //         "[data][%p] ERROR, %u, %s.",
        //         Binding,
        //         Status,
        //         "setsockopt(UDP_GRO) failed");
        //     goto Exit;
        // }
    }
#endif

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
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "setsockopt(SO_RCVBUF) failed");
    //     goto Exit;
    // }

    //
    // Only set SO_REUSEPORT on a server socket, otherwise the client could be
    // assigned a server port (unless it's forcing sharing).
    //
    if (ForceShare || RemoteAddress == NULL) {
        //
        // The port is shared across processors.
        //
        // Option = TRUE;
        // Result =
        //     setsockopt(
        //         SocketContext->SocketFd,
        //         SOL_SOCKET,
        //         SO_REUSEPORT,
        //         (const void*)&Option,
        //         sizeof(Option));
        // if (Result == SOCKET_ERROR) {
        //     Status = errno;
        //     QuicTraceEvent(
        //         DatapathErrorStatus,
        //         "[data][%p] ERROR, %u, %s.",
        //         Binding,
        //         Status,
        //         "setsockopt(SO_REUSEPORT) failed");
        //     goto Exit;
        // }
    }

    // CxPlatCopyMemory(&MappedAddress, &Binding->LocalAddress, sizeof(MappedAddress));
    // if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
    //     MappedAddress.Ipv6.sin6_family = AF_INET6;
    // }

    // Result =
    //     bind(
    //         SocketContext->SocketFd,
    //         &MappedAddress.Ip,
    //         sizeof(MappedAddress));
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "bind failed");
    //     goto Exit;
    // }

    if (RemoteAddress != NULL) {
        // TODO: any equivalent of AF_XDP?

        // CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
        // CxPlatConvertToMappedV6(RemoteAddress, &MappedAddress);

        // if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        //     MappedAddress.Ipv6.sin6_family = AF_INET6;
        // }

        // Result =
        //     connect(
        //         SocketContext->SocketFd,
        //         &MappedAddress.Ip,
        //         sizeof(MappedAddress));

        // if (Result == SOCKET_ERROR) {
        //     Status = errno;
        //     QuicTraceEvent(
        //         DatapathErrorStatus,
        //         "[data][%p] ERROR, %u, %s.",
        //         Binding,
        //         Status,
        //         "connect failed");
        //     goto Exit;
        // }
        // Binding->Connected = TRUE;
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    // TODO: any equivalent of AF_XDP?
    // AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
    // Result =
    //     getsockname(
    //         SocketContext->SocketFd,
    //         (struct sockaddr *)&Binding->LocalAddress,
    //         &AssignedLocalAddressLength);
    // if (Result == SOCKET_ERROR) {
    //     Status = errno;
    //     QuicTraceEvent(
    //         DatapathErrorStatus,
    //         "[data][%p] ERROR, %u, %s.",
    //         Binding,
    //         Status,
    //         "getsockname failed");
    //     goto Exit;
    // }

// #if DEBUG
//     if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
//         CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
//     } else if (RemoteAddress && LocalAddress && LocalAddress->Ipv4.sin_port == 0) {
//         //
//         // A client socket being assigned the same port as a remote socket causes issues later
//         // in the datapath and binding paths. Check to make sure this case was not given to us.
//         //
//         CXPLAT_DBG_ASSERT(Binding->LocalAddress.Ipv4.sin_port != RemoteAddress->Ipv4.sin_port);
//     }
// #else
//     UNREFERENCED_PARAMETER(LocalAddress);
// #endif

    // if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
    //     Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    // }

    // SocketContext->SqeInitialized = TRUE;

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

    fprintf(stderr, "OUT CxPlatSocketContextInitialize Local:%s, Remote:%s\n", LocalAddrStr.Address, RemoteAddrStr.Address);
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
            CxPlatSocketContextInitialize( // call socket()
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
        CxPlatSocketContextSetEvents(&Binding->SocketContexts[i], EPOLL_CTL_ADD, EPOLLIN);
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

//
// Receive Path
//

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Packet
    )
{
    return (CXPLAT_RECV_DATA*)((char *)Packet - sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const RecvData
    )
{
    return (CXPLAT_RECV_PACKET*)(RecvData + 1);
}

void
CxPlatSocketHandleErrors(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
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

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _Inout_ CXPLAT_RECV_BLOCK** RecvBlocks,
    _In_ struct mmsghdr* RecvMsgHdr,
    _In_ int MessagesReceived
    )
{
    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathProc->Datapath);

    uint32_t BytesTransferred = 0;
    CXPLAT_RECV_DATA* DatagramHead = NULL;
    CXPLAT_RECV_DATA** DatagramTail = &DatagramHead;
    for (int CurrentMessage = 0; CurrentMessage < MessagesReceived; CurrentMessage++) {
        CXPLAT_RECV_BLOCK* RecvBlock = RecvBlocks[CurrentMessage];
        RecvBlocks[CurrentMessage] = NULL;
        BytesTransferred += RecvMsgHdr[CurrentMessage].msg_len;

        uint8_t TOS = 0;
        uint16_t SegmentLength = 0;
        BOOLEAN FoundLocalAddr = FALSE, FoundTOS = FALSE;
        QUIC_ADDR* LocalAddr = &RecvBlock->Route.LocalAddress;
        QUIC_ADDR* RemoteAddr = &RecvBlock->Route.RemoteAddress;
        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);
        RecvBlock->Route.Queue = SocketContext;

        //
        // Process the ancillary control messages to get the local address,
        // type of service and possibly the GRO segmentation length.
        //
        struct msghdr* Msg = &RecvMsgHdr[CurrentMessage].msg_hdr;
        for (struct cmsghdr *CMsg = CMSG_FIRSTHDR(Msg); CMsg != NULL; CMsg = CMSG_NXTHDR(Msg, CMsg)) {
            if (CMsg->cmsg_level == IPPROTO_IPV6) {
                if (CMsg->cmsg_type == IPV6_PKTINFO) {
                    struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*)CMSG_DATA(CMsg);
                    LocalAddr->Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
                    LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                    LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                    CxPlatConvertFromMappedV6(LocalAddr, LocalAddr);
                    LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;
                } else if (CMsg->cmsg_type == IPV6_TCLASS) {
                    CXPLAT_DBG_ASSERT_CMSG(CMsg, uint8_t);
                    TOS = *(uint8_t*)CMSG_DATA(CMsg);
                    FoundTOS = TRUE;
                } else {
                    CXPLAT_DBG_ASSERT(FALSE);
                }
            } else if (CMsg->cmsg_level == IPPROTO_IP) {
                if (CMsg->cmsg_type == IP_TOS) {
                    CXPLAT_DBG_ASSERT_CMSG(CMsg, uint8_t);
                    TOS = *(uint8_t*)CMSG_DATA(CMsg);
                    FoundTOS = TRUE;
                } else {
                    CXPLAT_DBG_ASSERT(FALSE);
                }
            } else if (CMsg->cmsg_level == IPPROTO_UDP) {
#ifdef UDP_GRO
                if (CMsg->cmsg_type == UDP_GRO) {
                    CXPLAT_DBG_ASSERT_CMSG(CMsg, uint16_t);
                    SegmentLength = *(uint16_t*)CMSG_DATA(CMsg);
                }
#endif
            } else {
                CXPLAT_DBG_ASSERT(FALSE);
            }
        }

        CXPLAT_FRE_ASSERT(FoundLocalAddr);
        CXPLAT_FRE_ASSERT(FoundTOS);

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            RecvMsgHdr[CurrentMessage].msg_len,
            SegmentLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        if (SegmentLength == 0) {
            SegmentLength = RecvMsgHdr[CurrentMessage].msg_len;
        }

        CXPLAT_RECV_SUBBLOCK* SubBlock = (CXPLAT_RECV_SUBBLOCK*)(RecvBlock + 1);
        uint8_t* RecvBuffer =
            (uint8_t*)RecvBlock + SocketContext->DatapathProc->Datapath->RecvBlockBufferOffset;
        RecvBlock->RefCount = 0;

        //
        // Build up the chain of receive packets to indicate up to the app.
        //
        uint32_t Offset = 0;
        while (Offset < RecvMsgHdr[CurrentMessage].msg_len &&
               RecvBlock->RefCount < CXPLAT_MAX_IO_BATCH_SIZE) {
            RecvBlock->RefCount++;
            SubBlock->RecvBlock = RecvBlock;

            CXPLAT_RECV_DATA* RecvData = &SubBlock->RecvData;
            RecvData->Next = NULL;
            RecvData->Route = &RecvBlock->Route;
            RecvData->Buffer = RecvBuffer + Offset;
            if (RecvMsgHdr[CurrentMessage].msg_len - Offset < SegmentLength) {
                RecvData->BufferLength = (uint16_t)(RecvMsgHdr[CurrentMessage].msg_len - Offset);
            } else {
                RecvData->BufferLength = SegmentLength;
            }
            RecvData->PartitionIndex = SocketContext->DatapathProc->IdealProcessor;
            RecvData->TypeOfService = TOS;
            RecvData->Allocated = TRUE;
            RecvData->QueuedOnConnection = FALSE;
            RecvData->Reserved = FALSE;

            *DatagramTail = RecvData;
            DatagramTail = &RecvData->Next;

            Offset += RecvData->BufferLength;
            SubBlock = (CXPLAT_RECV_SUBBLOCK*)
                ((char*)SubBlock + SocketContext->DatapathProc->Datapath->RecvBlockStride);
        }
    }

    if (BytesTransferred == 0 || DatagramHead == NULL) {
        QuicTraceLogWarning(
            DatapathRecvEmpty,
            "[data][%p] Dropping datagram with empty payload.",
            SocketContext->Binding);
        return;
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
}

void
CxPlatSocketReceiveCoalesced(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc = SocketContext->DatapathProc;
    CXPLAT_RECV_BLOCK* RecvBlock = NULL;
    struct mmsghdr RecvMsgHdr;
    CXPLAT_RECV_MSG_CONTROL_BUFFER RecvMsgControl;
    struct iovec RecvIov;

    do {
        uint32_t RetryCount = 0;
        do {
            RecvBlock = CxPlatPoolAlloc(&DatapathProc->RecvBlockPool);
        } while (RecvBlock == NULL && ++RetryCount < 10);
        if (RecvBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_RECV_BLOCK",
                0);
            goto Exit;
        }

        RecvBlock->OwningPool = &DatapathProc->RecvBlockPool;

        struct msghdr* MsgHdr = &RecvMsgHdr.msg_hdr;
        MsgHdr->msg_name = &RecvBlock->Route.RemoteAddress;
        MsgHdr->msg_namelen = sizeof(RecvBlock->Route.RemoteAddress);
        MsgHdr->msg_iov = &RecvIov;
        MsgHdr->msg_iovlen = 1;
        MsgHdr->msg_control = &RecvMsgControl.Data;
        MsgHdr->msg_controllen = sizeof(RecvMsgControl.Data);
        MsgHdr->msg_flags = 0;
        RecvIov.iov_base = (char*)RecvBlock + DatapathProc->Datapath->RecvBlockBufferOffset;
        RecvIov.iov_len = CXPLAT_LARGE_IO_BUFFER_SIZE;

        int Ret =
            recvmmsg(
                SocketContext->SocketFd,
                &RecvMsgHdr,
                1,
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

        CXPLAT_DBG_ASSERT(Ret == 1);
        CxPlatSocketContextRecvComplete(SocketContext, &RecvBlock, &RecvMsgHdr, Ret);

    } while (TRUE);

Exit:

    if (RecvBlock) {
        CxPlatPoolFree(&DatapathProc->RecvBlockPool, RecvBlock);
    }
}

void
CxPlatSocketReceiveMessages(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc = SocketContext->DatapathProc;
    CXPLAT_RECV_BLOCK* RecvBlocks[CXPLAT_MAX_IO_BATCH_SIZE];
    struct mmsghdr RecvMsgHdr[CXPLAT_MAX_IO_BATCH_SIZE];
    CXPLAT_RECV_MSG_CONTROL_BUFFER RecvMsgControl[CXPLAT_MAX_IO_BATCH_SIZE];
    struct iovec RecvIov[CXPLAT_MAX_IO_BATCH_SIZE];
    CxPlatZeroMemory(RecvBlocks, sizeof(RecvBlocks));

    do {
        uint32_t RetryCount = 0;
        for (uint32_t i = 0; i < CXPLAT_MAX_IO_BATCH_SIZE && RecvBlocks[i] == NULL; ++i) {

            CXPLAT_RECV_BLOCK* RecvBlock;
            do {
                RecvBlock = CxPlatPoolAlloc(&DatapathProc->RecvBlockPool);
            } while (RecvBlock == NULL && ++RetryCount < 10);
            if (RecvBlock == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "CXPLAT_RECV_BLOCK",
                    0);
                goto Exit;
            }

            RecvBlocks[i] = RecvBlock;
            RecvBlock->OwningPool = &DatapathProc->RecvBlockPool;

            struct msghdr* MsgHdr = &RecvMsgHdr[i].msg_hdr;
            MsgHdr->msg_name = &RecvBlock->Route.RemoteAddress;
            MsgHdr->msg_namelen = sizeof(RecvBlock->Route.RemoteAddress);
            MsgHdr->msg_iov = &RecvIov[i];
            MsgHdr->msg_iovlen = 1;
            MsgHdr->msg_control = &RecvMsgControl[i].Data;
            MsgHdr->msg_controllen = sizeof(RecvMsgControl[i].Data);
            MsgHdr->msg_flags = 0;
            RecvIov[i].iov_base = (char*)RecvBlock + DatapathProc->Datapath->RecvBlockBufferOffset;
            RecvIov[i].iov_len = CXPLAT_SMALL_IO_BUFFER_SIZE;
        }

        int Ret =
            recvmmsg(
                SocketContext->SocketFd,
                RecvMsgHdr,
                (int)CXPLAT_MAX_IO_BATCH_SIZE,
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

        CXPLAT_DBG_ASSERT(Ret <= CXPLAT_MAX_IO_BATCH_SIZE);
        CxPlatSocketContextRecvComplete(SocketContext, RecvBlocks, RecvMsgHdr, Ret);

    } while (TRUE);

Exit:

    for (uint32_t i = 0; i < CXPLAT_MAX_IO_BATCH_SIZE; ++i) {
        if (RecvBlocks[i]) {
            CxPlatPoolFree(&DatapathProc->RecvBlockPool, RecvBlocks[i]);
        }
    }
}

static bool process_packet(struct xsk_socket_info *xsk,
			                uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    // int ret;
    uint8_t tmp_mac[ETH_ALEN];
    struct ethhdr *eth = (struct ethhdr *) pkt;
    // char mac_src[18] = {0};
    // char mac_dst[18] = {0};
    // sprintf(mac_src, "%02x:%02x:%02x:%02x:%02x:%02x",
    //         eth->h_source[0], eth->h_source[1], eth->h_source[2],
    //         eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    // sprintf(mac_dst, "%02x:%02x:%02x:%02x:%02x:%02x",
    //         eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
    //         eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);
    // memcpy(eth->h_source, eth->h_dest, ETH_ALEN);

    struct iphdr *iph = (struct iphdr *) (eth + 1);
    if (iph->version == 4) {
        // struct in_addr tmp_ip;
        struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + iph->ihl * 4);

        if (ntohs(eth->h_proto) != ETH_P_IP ||
            len < (sizeof(*eth) + sizeof(*iph) + sizeof(*udph)) ||
            iph->protocol != IPPROTO_UDP) // TODO: check Binding->LocalAddress port
            return false;
    } else if (iph->version == 6) {
        // struct in6_addr tmp_ip6;
        struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
        struct udphdr *udph = (struct udphdr *)((uint8_t *)ipv6 + sizeof(struct ipv6hdr));

        if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
            len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*udph)) ||
            ipv6->nexthdr != IPPROTO_UDP)
            return false;
    } else {
        fprintf(stderr, "Unknown IP version: %u\n", iph->version);
        return false;
    }

    // TODO: convert to Packet?
    //       call CxPlatSocketContextRecvComplete to finalize receive

    return true;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

void handle_receive_packets(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    struct xsk_socket_info *xsk = SocketContext->xsk_info;
    unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	unsigned int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
					xsk_umem_free_frames(xsk));

	if (stock_frames > 0) {

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
					     &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
						     &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
}

void
CxPlatSocketReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    handle_receive_packets(SocketContext);
    // if (SocketContext->DatapathProc->Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
    //     CxPlatSocketReceiveCoalesced(SocketContext);
    // } else {
    //     CxPlatSocketReceiveMessages(SocketContext);
    // }
}

void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;
        CXPLAT_RECV_SUBBLOCK* SubBlock =
            CXPLAT_CONTAINING_RECORD(Datagram, CXPLAT_RECV_SUBBLOCK, RecvData);
        if (InterlockedDecrement(&SubBlock->RecvBlock->RefCount) == 0) {
            CxPlatPoolFree(SubBlock->RecvBlock->OwningPool, SubBlock->RecvBlock);
        }
    }
}

//
// Send Path
//

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    // TODO: xsk_ring_prod__reserve

    CXPLAT_DBG_ASSERT(Socket != NULL);
    CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);
    if (Config->Route->Queue == NULL) {
        Config->Route->Queue = &Socket->SocketContexts[0];
    }

    CXPLAT_SOCKET_CONTEXT* SocketContext = Config->Route->Queue;
    CXPLAT_DBG_ASSERT(SocketContext->Binding == Socket);
    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathProc->Datapath);
    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(&SocketContext->DatapathProc->SendBlockPool);
    if (SendData != NULL) {
        SendData->SocketContext = SocketContext;
        SendData->ClientBuffer.Buffer = SendData->Buffer;
        SendData->ClientBuffer.Length = 0;
        SendData->TotalSize = 0;
        SendData->SegmentSize = Config->MaxPacketSize;
        SendData->BufferCount = 0;
        SendData->AlreadySentCount = 0;
        SendData->ControlBufferLength = 0;
        SendData->ECN = Config->ECN;
        SendData->Flags = Config->Flags;
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
    // TODO: which should be freed?
    //       need to wait completion queue?
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
    // TODO: xsk_umem__alloc
    // TODO: use umem buffer as it is instead of copying in XdpSend

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
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    );

QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(Socket);

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
    // Check to see if we need to pend because there's already queue.
    //
    BOOLEAN SendPending = FALSE, FlushTxQueue = FALSE;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    CxPlatLockAcquire(&SocketContext->TxQueueLock);
    if (/*SendData->Flags & CXPLAT_SEND_FLAGS_MAX_THROUGHPUT ||*/
        !CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        FlushTxQueue = CxPlatListIsEmpty(&SocketContext->TxQueue);
        CxPlatListInsertTail(&SocketContext->TxQueue, &SendData->TxEntry);
        SendPending = TRUE;
    }
    CxPlatLockRelease(&SocketContext->TxQueueLock);
    if (SendPending) {
        if (FlushTxQueue) {
            CXPLAT_FRE_ASSERT(
                CxPlatEventQEnqueue(
                    SocketContext->DatapathProc->EventQ,
                    &SocketContext->FlushTxSqe.Sqe,
                    &SocketContext->FlushTxSqe));
        }
        return QUIC_STATUS_SUCCESS;
    }

    //
    // Go ahead and try to send on the socket.
    //
    QUIC_STATUS Status = CxPlatSendDataSend(SendData);
    if (Status == QUIC_STATUS_PENDING) {
        //
        // Couldn't send right now, so queue up the send and wait for send
        // (EPOLLOUT) to be ready.
        //
        CxPlatLockAcquire(&SocketContext->TxQueueLock);
        CxPlatListInsertTail(&SocketContext->TxQueue, &SendData->TxEntry);
        CxPlatLockRelease(&SocketContext->TxQueueLock);
        CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT);
        Status = QUIC_STATUS_SUCCESS;
    } else {
        CxPlatSendDataFree(SendData);
    }

    return Status;
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

#ifdef HAS_SENDMMSG
#define cxplat_sendmmsg sendmmsg
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
#define cxplat_sendmmsg cxplat_sendmmsg_shim
#endif

BOOLEAN
CxPlatSendDataSendMessages(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    struct mmsghdr Mhdrs[CXPLAT_MAX_IO_BATCH_SIZE];
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
            cxplat_sendmmsg(
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

BOOLEAN
XdpSend(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    // TODO: return false for PENDING status
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    struct xsk_socket_info* xsk_info = SocketContext->xsk_info;
    QUIC_BUFFER *buffer = &SendData->ClientBuffer;
    uint32_t idx_tx = 0; // TODO:

    // TODO: batch send by replacing 2nd argument
    int ret = xsk_ring_prod__reserve(&xsk_info->tx, 1, &idx_tx);
    if (!ret) {
        // TODO: reserve again until space is available
    }

    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk_info->tx, idx_tx);
    uint64_t addr = xsk_umem__add_offset_to_addr((void*)buffer->Buffer - xsk_info->umem->buffer); // TODO: is this really correct?
    void *frame = xsk_umem__get_data(xsk_info->umem->buffer, addr);
    memcpy(frame, buffer->Buffer, buffer->Length);    
    tx_desc->addr = addr;
    tx_desc->len = buffer->Length;

    /* Submit the packet for transmission */
    xsk_ring_prod__submit(&xsk_info->tx, 1);

    return TRUE;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(SendData->AlreadySentCount < CXPLAT_MAX_IO_BATCH_SIZE);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    BOOLEAN Success = XdpSend(SendData);
//     BOOLEAN Success =
// #ifdef UDP_SEGMENT
//         SendData->SegmentationSupported ?
//             CxPlatSendDataSendSegmented(SendData) :
// #endif
//             CxPlatSendDataSendMessages(SendData);
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

        // TODO: maybe this does not work for xdp
        //       normal socket copy data buffer to kernel, so user level buffer can be freed
        //       xdp requires to watch Cq then free.
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
    if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
        if (EPOLLERR & Cqe->events) {
            CxPlatSocketHandleErrors(SocketContext);
        }
        if (EPOLLIN & Cqe->events) {
            CxPlatSocketReceive(SocketContext);
        }
        if (EPOLLOUT & Cqe->events) {
            CxPlatSocketContextFlushTxQueue(SocketContext, TRUE);
        }
        CxPlatRundownRelease(&SocketContext->UpcallRundown);
    }
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
