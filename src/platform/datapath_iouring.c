/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Environment:

    Linux

--*/

#include "platform_internal.h"
#include "datapath_linux.h"

#ifdef QUIC_CLOG
#include "datapath_iouring.c.clog.h"
#endif

CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be TRUE.");
CXPLAT_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be TRUE.");

//
// Context value within the IoSqe to indicate the type of IO operation.
//
typedef enum DATAPATH_CONTEXT_TYPE {
    DatapathContextRecv,
    DatapathContextSend,
} DATAPATH_CONTEXT_TYPE;

//
// Contains all the info for a single RX IO operation. Multiple RX packets may
// come from a single IO operation.
//
typedef struct __attribute__((aligned(CXPLAT_MEMORY_ALIGNMENT))) DATAPATH_RX_IO_BLOCK {
    //
    // Represents the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // Ref count of receive data/packets that are using this block.
    //
    long RefCount;

    //
    // The index of the buffer.
    // Review: could be inferred?
    //
    uint32_t BufferIndex;

    //
    // The partition this packet is allocated from.
    //
    CXPLAT_DATAPATH_PARTITION* DatapathPartition;

    //
    // An array of packets to represent the datagram and metadata returned to
    // the app.
    //
    //DATAPATH_RX_PACKET Packets[0];

    //
    // Buffer that actually stores the UDP payload.
    //
    //uint8_t Buffer[]; // CXPLAT_SMALL_IO_BUFFER_SIZE or CXPLAT_LARGE_IO_BUFFER_SIZE

} DATAPATH_RX_IO_BLOCK;

typedef struct __attribute__((aligned(CXPLAT_MEMORY_ALIGNMENT))) DATAPATH_RX_PACKET {
    //
    // The IO block that owns the packet.
    //
    DATAPATH_RX_IO_BLOCK* IoBlock;

    //
    // Publicly visible receive data.
    //
    CXPLAT_RECV_DATA Data;

} DATAPATH_RX_PACKET;

#if DEBUG

typedef enum CXPLAT_SEND_DATA_STATE {
    SendStateAllocated,
    SendStateQueued,
    SendStateSending,
    SendStateSendComplete,
    SendStateFreed,
    SendStateMax
} CXPLAT_SEND_DATA_STATE;

#endif // DEBUG

//
// Send context.
//

typedef struct CXPLAT_SEND_DATA {
    CXPLAT_SEND_DATA_COMMON;
    //
    // The socket context owning this send.
    //
    struct CXPLAT_SOCKET_CONTEXT* SocketContext;

    //
    // The submission queue entry for the send.
    //
    CXPLAT_SOCKET_SQE Sqe;

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
    // The message header for the send.
    //
    struct msghdr MsgHdr;

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
    // The total number of bytes buffer sent (only used for TCP).
    //
    uint32_t TotalBytesSent;

#if DEBUG
    CXPLAT_SEND_DATA_STATE State;
#endif

    //
    // IO vectors used for sends on the socket.
    //
    struct iovec Iovs[1]; // variable length, depends on if GSO is being used
                          //   if GSO is used, only 1 is needed
                          //   if GSO is not used, then N are needed

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_RECV_MSG_CONTROL_BUFFER {
    char Data[CMSG_SPACE(sizeof(struct in6_pktinfo)) + // IP_PKTINFO
              3 * CMSG_SPACE(sizeof(int))]; // TOS + IP_TTL

} CXPLAT_RECV_MSG_CONTROL_BUFFER;

CXPLAT_EVENT_COMPLETION CxPlatSocketContextUninitializeEventComplete;
CXPLAT_EVENT_BATCH_COMPLETION CxPlatSocketContextIoEventComplete;

const struct msghdr CxPlatRecvMsgHdr = {
    .msg_namelen = ALIGN_UP_BY(sizeof(QUIC_ADDR), CXPLAT_MEMORY_ALIGNMENT),
    .msg_controllen = CXPLAT_FIELD_SIZE(CXPLAT_RECV_MSG_CONTROL_BUFFER, Data),
};
const uint32_t RecvBufCount = 1024;

void
CxPlatSocketIoStart(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_SOCKET_IO_TAG Tag
    )
{
    CXPLAT_DBG_ASSERT(!SocketContext->LockedFlags.Shutdown);
    CXPLAT_DBG_ASSERT(InterlockedIncrement64(&SocketContext->IoCountTags[Tag]) > 0);
    UNREFERENCED_PARAMETER(Tag);
    SocketContext->IoCount++;
}

struct io_uring_sqe*
CxPlatSocketAllocSqe(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_EVENTQ* EventQ = SocketContext->DatapathPartition->EventQ;
    struct io_uring_sqe* io_sqe = CxPlatEventGetSqe(EventQ);
    if (io_sqe == NULL) {
        CxPlatEventQSubmit(EventQ);
        io_sqe = CxPlatEventGetSqe(EventQ);
    }
    return io_sqe;
}

uint32_t
CxPlatGetBufferPoolBufferSize(
    _In_ const CXPLAT_REGISTERED_BUFFER_POOL* Pool
    )
{
    return Pool->BufferSize;
}

uint8_t*
CxPlatGetBufferPoolBuffer(
    _In_ const CXPLAT_REGISTERED_BUFFER_POOL* Pool,
    _In_ uint32_t Index
    )
{
    return Pool->Buffers + (Index * Pool->BufferSize);
}

void
CxPlatFreeBufferPool(
    _In_ CXPLAT_DATAPATH_PARTITION* DatapathPartition,
    _In_ CXPLAT_IO_RING_BUF_GROUP BufferGroup,
    _Inout_ CXPLAT_REGISTERED_BUFFER_POOL* Pool
    )
{
    if (Pool->Buffers != NULL) {
        io_uring_unregister_buf_ring(&DatapathPartition->EventQ->Ring, BufferGroup);
        Pool->Buffers = NULL;
    }
    if (Pool->Ring != NULL) {
        free(Pool->Ring);
        Pool->Ring = NULL;
    }
}

QUIC_STATUS
CxPlatCreateBufferPool(
    _In_ CXPLAT_DATAPATH_PARTITION* DatapathPartition,
    _In_ uint32_t BufferSize,
    _In_ uint32_t BufferCount,
    _In_ CXPLAT_IO_RING_BUF_GROUP BufferGroup,
    _Out_ CXPLAT_REGISTERED_BUFFER_POOL* Pool
    )
{
    int Result;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_DBG_ASSERT(BufferSize % CXPLAT_MEMORY_ALIGNMENT == 0);

    CxPlatZeroMemory(Pool, sizeof(*Pool));
    CxPlatLockInitialize(&Pool->Lock);

    Pool->TotalSize = BufferCount * (sizeof(struct io_uring_buf) + BufferSize);
    if (posix_memalign(&Pool->Ring, getpagesize(), Pool->TotalSize)) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_REGISTERED_BUFFER_POOL",
            Pool->TotalSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    io_uring_buf_ring_init(Pool->Ring);

    struct io_uring_buf_reg reg = (struct io_uring_buf_reg) {
        .ring_addr = (uint64_t)Pool->Ring,
        .ring_entries = BufferCount,
        .bgid = (uint16_t)BufferGroup
    };

    Result = io_uring_register_buf_ring(&DatapathPartition->EventQ->Ring, &reg, 0);
    if (Result) {
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            DatapathPartition,
            Status,
            "io_uring_register_buf_ring failed");
            goto Exit;
    }

    //
    // Review: we may also want to io_uring_register_buffers for
    // io_uring_prep_send_zc_fixed.
    //

    Pool->Buffers = (uint8_t*)Pool->Ring + sizeof(struct io_uring_buf) * BufferCount;
    Pool->BufferSize = BufferSize;

Exit:

    if (QUIC_FAILED(Status)) {
        CxPlatFreeBufferPool(DatapathPartition, BufferGroup, Pool);
    }

    return Status;
}

QUIC_STATUS
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t PartitionIndex,
    _Out_ CXPLAT_DATAPATH_PARTITION* DatapathPartition
    )
{
    QUIC_STATUS Status;

    CXPLAT_DBG_ASSERT(Datapath != NULL);
    DatapathPartition->Datapath = Datapath;
    DatapathPartition->PartitionIndex = PartitionIndex;
    DatapathPartition->EventQ = CxPlatWorkerPoolGetEventQ(Datapath->WorkerPool, PartitionIndex);
    CxPlatRefInitialize(&DatapathPartition->RefCount);

    CxPlatPoolInitialize(
        TRUE, Datapath->SendDataSize, QUIC_POOL_DATA, &DatapathPartition->SendBlockPool);

    Status =
        CxPlatCreateBufferPool(
            DatapathPartition, Datapath->RecvBlockSize, RecvBufCount,
            CxPlatIoRingBufGroupRecv, &DatapathPartition->RecvRegisteredBufferPool);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    for (uint32_t i = 0; i < RecvBufCount; i++) {
        DATAPATH_RX_IO_BLOCK* IoBlock =
            (DATAPATH_RX_IO_BLOCK*)CxPlatGetBufferPoolBuffer(
                &DatapathPartition->RecvRegisteredBufferPool, i);
        IoBlock->BufferIndex = i;
        IoBlock->DatapathPartition = DatapathPartition;
        io_uring_buf_ring_add(
            DatapathPartition->RecvRegisteredBufferPool.Ring,
            (uint8_t*)IoBlock + DatapathPartition->Datapath->RecvBlockBufferOffset,
            CxPlatGetBufferPoolBufferSize(&DatapathPartition->RecvRegisteredBufferPool) -
                DatapathPartition->Datapath->RecvBlockBufferOffset,
            i, io_uring_buf_ring_mask(RecvBufCount), i);
    }
    io_uring_buf_ring_advance(DatapathPartition->RecvRegisteredBufferPool.Ring, RecvBufCount);

Exit:

    return Status;
}

QUIC_STATUS
DataPathInitialize(
    _In_ uint32_t ClientRecvDataLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_ CXPLAT_DATAPATH_INIT_CONFIG* InitConfig,
    _Out_ CXPLAT_DATAPATH** NewDatapath
    )
{
    UNREFERENCED_PARAMETER(TcpCallbacks);
    UNREFERENCED_PARAMETER(InitConfig);

    if (NewDatapath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }
    if (TcpCallbacks != NULL) {
        if (TcpCallbacks->Accept == NULL ||
            TcpCallbacks->Connect == NULL ||
            TcpCallbacks->Receive == NULL ||
            TcpCallbacks->SendComplete == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }
    if (WorkerPool == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const size_t DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        CxPlatWorkerPoolGetCount(WorkerPool) * sizeof(CXPLAT_DATAPATH_PARTITION);

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
    if (TcpCallbacks) {
        Datapath->TcpHandlers = *TcpCallbacks;
    }
    Datapath->WorkerPool = WorkerPool;

    Datapath->PartitionCount = (uint16_t)CxPlatWorkerPoolGetCount(WorkerPool);
    Datapath->Features = CXPLAT_DATAPATH_FEATURE_LOCAL_PORT_SHARING;
    CxPlatRefInitializeEx(&Datapath->RefCount, Datapath->PartitionCount);
    CxPlatDataPathCalculateFeatureSupport(Datapath);

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
        ALIGN_UP_BY(sizeof(DATAPATH_RX_PACKET) + ClientRecvDataLength, CXPLAT_MEMORY_ALIGNMENT);
    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
        Datapath->RecvBlockBufferOffset =
            sizeof(DATAPATH_RX_IO_BLOCK) +
            CXPLAT_MAX_IO_BATCH_SIZE * Datapath->RecvBlockStride;
        Datapath->RecvBlockSize =
            ALIGN_UP_BY(
                Datapath->RecvBlockBufferOffset + CXPLAT_LARGE_IO_BUFFER_SIZE,
                CXPLAT_MEMORY_ALIGNMENT);
    } else {
        Datapath->RecvBlockBufferOffset =
            sizeof(DATAPATH_RX_IO_BLOCK) + Datapath->RecvBlockStride;
        Datapath->RecvBlockSize =
            ALIGN_UP_BY(
                Datapath->RecvBlockBufferOffset + CXPLAT_SMALL_IO_BUFFER_SIZE,
                CXPLAT_MEMORY_ALIGNMENT);
    }

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->PartitionCount; i++) {
        QUIC_STATUS Status =
            CxPlatProcessorContextInitialize(Datapath, i, &Datapath->Partitions[i]);
        if (QUIC_FAILED(Status)) {
            return Status;
        }
    }

    CXPLAT_FRE_ASSERT(CxPlatWorkerPoolAddRef(WorkerPool, CXPLAT_WORKER_POOL_REF_IOURING));
    *NewDatapath = Datapath;

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
        CxPlatWorkerPoolRelease(Datapath->WorkerPool, CXPLAT_WORKER_POOL_REF_IOURING);
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
        CxPlatFreeBufferPool(
            DatapathPartition, CxPlatIoRingBufGroupRecv,
            &DatapathPartition->RecvRegisteredBufferPool);
        CxPlatPoolUninitialize(&DatapathPartition->SendBlockPool);
        CxPlatDataPathRelease(DatapathPartition->Datapath);
    }
}

void
DataPathUninitialize(
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

QUIC_STATUS
CxPlatSocketContextSqeInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET* Binding = SocketContext->Binding;
    BOOLEAN ShutdownSqeInitialized = FALSE;

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathPartition->EventQ,
            CxPlatSocketContextUninitializeEventComplete,
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
    CxPlatSocketIoStart(SocketContext, IoTagShutdown);

    if (!CxPlatBatchSqeInitialize(
            SocketContext->DatapathPartition->EventQ,
            CxPlatSocketContextIoEventComplete,
            &SocketContext->IoSqe.Sqe)) {
        SocketContext->IoSqe.Context = (void*)DatapathContextRecv; // NOLINT performance-no-int-to-ptr
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "CxPlatSqeInitialize failed");
        goto Exit;
    }

    SocketContext->SqeInitialized = TRUE;
    return QUIC_STATUS_SUCCESS;

Exit:

    if (ShutdownSqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->ShutdownSqe);
    }

    return Status;
}

//
// Socket context interface. It abstracts a (generally per-processor) UDP socket
// and the corresponding logic/functionality like send and receive processing.
//
QUIC_STATUS
CxPlatSocketContextInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _In_ const uint16_t PartitionIndex,
    _In_ CXPLAT_SOCKET_TYPE SocketType
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Result = 0;
    int Option = 0;
    QUIC_ADDR MappedAddress = {0};
    socklen_t AssignedLocalAddressLength = 0;

    CXPLAT_SOCKET* Binding = SocketContext->Binding;
    CXPLAT_DATAPATH* Datapath = Binding->Datapath;

    CXPLAT_DBG_ASSERT(PartitionIndex < Datapath->PartitionCount);
    SocketContext->DatapathPartition = &Datapath->Partitions[PartitionIndex];
    CxPlatRefIncrement(&SocketContext->DatapathPartition->RefCount);

    Status = CxPlatSocketContextSqeInitialize(SocketContext);
    if (QUIC_FAILED(Status) || SocketType == CXPLAT_SOCKET_TCP_SERVER) {
        goto Exit;
    }

    //
    // Create datagram socket. (Review: these steps could be performed using the io_uring).
    //
    SocketContext->SocketFd =
        socket(
            AF_INET6,
            (SocketType == CXPLAT_SOCKET_UDP ? SOCK_DGRAM : SOCK_STREAM) |
                SOCK_NONBLOCK,
            SocketType == CXPLAT_SOCKET_UDP ? IPPROTO_UDP : IPPROTO_TCP);
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

    if (SocketType == CXPLAT_SOCKET_UDP) {
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
        // On Linux, IP_HOPLIMIT does not exist. So we will use IP_RECVTTL, IPV6_RECVHOPLIMIT instead.
        //
        Option = TRUE;
        Result =
            setsockopt(
                SocketContext->SocketFd,
                IPPROTO_IP,
                IP_RECVTTL,
                (const void*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(IP_RECVTTL) failed");
            goto Exit;
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketContext->SocketFd,
                IPPROTO_IPV6,
                IPV6_RECVHOPLIMIT,
                (const void*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(IPV6_RECVHOPLIMIT) failed");
            goto Exit;
        }

    #ifdef UDP_GRO
        if (SocketContext->DatapathPartition->Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
            Option = TRUE;
            Result =
                setsockopt(
                    SocketContext->SocketFd,
                    SOL_UDP,
                    UDP_GRO,
                    (const void*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Binding,
                    Status,
                    "setsockopt(UDP_GRO) failed");
                goto Exit;
            }
        }
    #endif

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
        if ((Config->Flags & CXPLAT_SOCKET_FLAG_SHARE || Config->RemoteAddress == NULL) &&
            SocketContext->Binding->Datapath->PartitionCount > 1) {
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
    } else if (SocketType == CXPLAT_SOCKET_TCP_LISTENER) {
        //
        // Set SO_REUSEPORT to allow multiple TCP listeners to
        // bind to the same port and load balance the connections across them.
        // Meanwhile, it allows us to bind to the port that's held by
        // passive connections.
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

    QUIC_ADDR_STR LocalAddressStr;
    QUIC_ADDR_STR RemoteAddressStr;
    QuicAddrToString(&MappedAddress, &LocalAddressStr);

    if (Config->RemoteAddress != NULL) {
        CxPlatZeroMemory(&MappedAddress, sizeof(MappedAddress));
        CxPlatConvertToMappedV6(Config->RemoteAddress, &MappedAddress);

        if (MappedAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
            MappedAddress.Ipv6.sin6_family = AF_INET6;
        }
        QuicAddrToString(&MappedAddress, &RemoteAddressStr);
        Result =
            connect(
                SocketContext->SocketFd,
                &MappedAddress.Ip,
                sizeof(MappedAddress));
        if (Result == SOCKET_ERROR && errno != EINPROGRESS) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "connect failed");
            goto Exit;
        }
        Binding->Connected = SocketType != CXPLAT_SOCKET_TCP;
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
            (struct sockaddr*)&Binding->LocalAddress,
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
    if (Config->LocalAddress && Config->LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(Config->LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    } else if (Config->RemoteAddress && Config->LocalAddress && Config->LocalAddress->Ipv4.sin_port == 0) {
        //
        // A client socket being assigned the same port as a remote socket causes issues later
        // in the datapath and binding paths. Check to make sure this case was not given to us.
        //
        CXPLAT_DBG_ASSERT(Binding->LocalAddress.Ipv4.sin_port != Config->RemoteAddress->Ipv4.sin_port);
    }
#endif

    if (Binding->LocalAddress.Ipv6.sin6_family == AF_INET6) {
        Binding->LocalAddress.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
    }

    if (SocketType == CXPLAT_SOCKET_TCP_LISTENER) {
        Result =
            listen(
                SocketContext->SocketFd,
                100);
        if (Result == SOCKET_ERROR) {
            int error = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                error,
                "listen");
            goto Exit;
        }
    }

Exit:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->SocketFd);
        SocketContext->SocketFd = INVALID_SOCKET;
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
        CXPLAT_FREE(CxPlatSocketToRaw(Socket), QUIC_POOL_SOCKET);
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

    CXPLAT_DBG_ASSERT(SocketContext->AcceptSocket == NULL);

    if (SocketContext->SocketFd != INVALID_SOCKET) {
        close(SocketContext->SocketFd);
    }

    if (SocketContext->SqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->ShutdownSqe);
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->IoSqe.Sqe);
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->FlushTxSqe);
    }

    CxPlatRundownUninitialize(&SocketContext->UpcallRundown);

    if (SocketContext->DatapathPartition) {
        CxPlatProcessorContextRelease(SocketContext->DatapathPartition);
    }
    CxPlatSocketRelease(SocketContext->Binding);
}

void
CxPlatSocketIoComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_SOCKET_IO_TAG Tag
    )
{
    CXPLAT_DBG_ASSERT(SocketContext->IoCount > 0);
    CXPLAT_DBG_ASSERT(InterlockedDecrement64(&SocketContext->IoCountTags[Tag]) >= 0);
    UNREFERENCED_PARAMETER(Tag);

    if (--SocketContext->IoCount == 0) {
        CxPlatSocketContextUninitializeComplete(SocketContext);
    }
}

void
CxPlatSocketContextUninitializeEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_SOCKET_CONTEXT, ShutdownSqe);
    CXPLAT_DBG_ASSERT(SocketContext->LockedFlags.Shutdown);

    CXPLAT_DBG_ASSERT((*Cqe)->res == 1 || !SocketContext->LockedFlags.MultiRecvStarted);
    CxPlatSocketIoComplete(SocketContext, IoTagShutdown);
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
        CXPLAT_DATAPATH_PARTITION* DatapathPartition = SocketContext->DatapathPartition;
        struct io_uring_sqe* Sqe;

        if (SocketContext->Binding->Type == CXPLAT_SOCKET_TCP ||
            SocketContext->Binding->Type == CXPLAT_SOCKET_TCP_SERVER) {
            //
            // For TCP sockets, we should shutdown the socket before closing it.
            //
            SocketContext->Binding->DisconnectIndicated = TRUE;
            if (shutdown(SocketContext->SocketFd, SHUT_RDWR) != 0) {
                int Errno = errno;
                if (Errno != ENOTCONN) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        SocketContext->Binding,
                        Errno,
                        "shutdown");
                }
            }
        }

        CxPlatRundownReleaseAndWait(&SocketContext->UpcallRundown); // Block until all upcalls complete.

        CxPlatLockAcquire(&DatapathPartition->EventQ->Lock);
        Sqe = CxPlatSocketAllocSqe(SocketContext);
        CXPLAT_FRE_ASSERT(Sqe != NULL);
        io_uring_prep_cancel(Sqe, &SocketContext->IoSqe.Sqe, IORING_ASYNC_CANCEL_ALL);
        io_uring_sqe_set_data(Sqe, &SocketContext->ShutdownSqe);
        CxPlatEventQSubmit(DatapathPartition->EventQ);
        SocketContext->LockedFlags.Shutdown = TRUE;
        CxPlatLockRelease(&DatapathPartition->EventQ->Lock);
    }
}

void
CxPlatSocketContextStartMultiRecvUnderLock(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_EVENTQ* EventQ = SocketContext->DatapathPartition->EventQ;

    CXPLAT_DBG_ASSERT(!SocketContext->LockedFlags.MultiRecvStarted);
    CXPLAT_DBG_ASSERT(!SocketContext->LockedFlags.Shutdown);

    struct io_uring_sqe* Sqe = CxPlatSocketAllocSqe(SocketContext);
    if (Sqe == NULL) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            errno,
            "CxPlatSocketAllocSqe failed");
        //
        // Review: this will cause the receive data path to hang. Elsewhere,
        // MsQuic has similar gaps in its data path low resource handling, but
        // this should be made more robust.
        //
        CXPLAT_DBG_ASSERT(FALSE);
        return;
    }

    io_uring_prep_recvmsg_multishot(
        Sqe, SocketContext->SocketFd, (struct msghdr*)&CxPlatRecvMsgHdr, MSG_TRUNC);
    Sqe->flags |= IOSQE_BUFFER_SELECT;
    Sqe->buf_group = CxPlatIoRingBufGroupRecv;
    io_uring_sqe_set_data(Sqe, &SocketContext->IoSqe.Sqe);
    CxPlatEventQSubmit(EventQ);

    CXPLAT_DBG_ONLY(SocketContext->LockedFlags.MultiRecvStarted = TRUE);
    CxPlatSocketIoStart(SocketContext, IoTagRecv);
}

void
CxPlatSocketContextStartMultiRecv(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_EVENTQ* EventQ = SocketContext->DatapathPartition->EventQ;
    CxPlatLockAcquire(&EventQ->Lock);
    CxPlatSocketContextStartMultiRecvUnderLock(SocketContext);
    CxPlatLockRelease(&EventQ->Lock);
}

//
// Datapath binding interface.
//

QUIC_STATUS
SocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    const BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;
    const BOOLEAN NumPerProcessorSockets = IsServerSocket && Datapath->PartitionCount > 1;
    const uint16_t SocketCount = NumPerProcessorSockets ? (uint16_t)CxPlatProcCount() : 1;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & CXPLAT_SOCKET_FLAG_PCP);

    const size_t RawBindingLength =
        CxPlatGetRawSocketSize() + SocketCount * sizeof(CXPLAT_SOCKET_CONTEXT);
    CXPLAT_SOCKET_RAW* RawBinding =
        (CXPLAT_SOCKET_RAW*)CXPLAT_ALLOC_PAGED(RawBindingLength, QUIC_POOL_SOCKET);
    if (RawBinding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawBindingLength);
        goto Exit;
    }
    CXPLAT_SOCKET* Binding = CxPlatRawToSocket(RawBinding);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    CxPlatZeroMemory(RawBinding, RawBindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = Config->CallbackContext;
    Binding->NumPerProcessorSockets = NumPerProcessorSockets;
    Binding->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    Binding->Mtu = CXPLAT_MAX_MTU;
    Binding->Type = CXPLAT_SOCKET_UDP;
    CxPlatRefInitializeEx(&Binding->RefCount, SocketCount);
    if (Config->LocalAddress) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    if (Config->Flags & CXPLAT_SOCKET_FLAG_PCP) {
        Binding->PcpBinding = TRUE;
    }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET;
        CxPlatListInitializeHead(&Binding->SocketContexts[i].TxQueue);
        CxPlatRundownInitialize(&Binding->SocketContexts[i].UpcallRundown);
    }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextInitialize(
                &Binding->SocketContexts[i],
                Config,
                Config->RemoteAddress ? Config->PartitionIndex : (i % Datapath->PartitionCount),
                Binding->Type);
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
        //
        // Review: the sockets can be registered with io_uring for better perf.
        //
        Binding->SocketContexts[i].IoStarted = TRUE;
        CxPlatSocketContextStartMultiRecv(&Binding->SocketContexts[i]);
    }

    Binding = NULL;
    RawBinding = NULL;

Exit:

    if (RawBinding != NULL) {
        SocketDelete(CxPlatRawToSocket(RawBinding));
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateTcp(
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
SocketCreateTcpListener(
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
SocketDelete(
    _In_ CXPLAT_SOCKET* Socket
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

    const uint16_t SocketCount =
        Socket->NumPerProcessorSockets ? (uint16_t)CxPlatProcCount() : 1;

    for (uint32_t i = 0; i < SocketCount; ++i) {
        CxPlatSocketContextUninitialize(&Socket->SocketContexts[i]);
    }
}

//
// Receive Path
//

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
    } else if (ErrNum != 0) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            ErrNum,
            "Socket error event");


        if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
            if (SocketContext->Binding->Type == CXPLAT_SOCKET_UDP) {
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
            } else {
                if (!SocketContext->Binding->DisconnectIndicated) {
                    SocketContext->Binding->DisconnectIndicated = TRUE;
                    SocketContext->Binding->Datapath->TcpHandlers.Connect(
                        SocketContext->Binding,
                        SocketContext->Binding->ClientContext,
                        FALSE);
                }
            }

            CxPlatRundownRelease(&SocketContext->UpcallRundown);
        }
    }
}

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _Inout_ DATAPATH_RX_IO_BLOCK** IoBlocks,
    _In_ struct msghdr* RecvMsgHdr
    )
{
    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathPartition->Datapath);

    uint32_t BytesTransferred = 0;
    CXPLAT_RECV_DATA* DatagramHead = NULL;
    CXPLAT_RECV_DATA** DatagramTail = &DatagramHead;
    for (int CurrentMessage = 0; CurrentMessage < 1; CurrentMessage++) {
        DATAPATH_RX_IO_BLOCK* IoBlock = IoBlocks[CurrentMessage];
        IoBlocks[CurrentMessage] = NULL;
        uint32_t MsgLen = (uint32_t)RecvMsgHdr->msg_iov->iov_len;
        BytesTransferred += MsgLen;

        uint8_t TOS = 0;
        int HopLimitTTL = 0;
        uint16_t SegmentLength = 0;
        BOOLEAN FoundLocalAddr = FALSE, FoundTOS = FALSE, FoundTTL = FALSE;
        QUIC_ADDR* LocalAddr = &IoBlock->Route.LocalAddress;
        QUIC_ADDR* RemoteAddr = RecvMsgHdr->msg_name;
        CxPlatConvertFromMappedV6(RemoteAddr, &IoBlock->Route.RemoteAddress);
        IoBlock->Route.Queue = (CXPLAT_QUEUE*)SocketContext;

        //
        // Process the ancillary control messages to get the local address,
        // type of service and possibly the GRO segmentation length.
        //
        struct msghdr* Msg = RecvMsgHdr;
        for (struct cmsghdr*CMsg = CMSG_FIRSTHDR(Msg); CMsg != NULL; CMsg = CMSG_NXTHDR(Msg, CMsg)) {
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
                } else if (CMsg->cmsg_type == IPV6_HOPLIMIT) {
                    HopLimitTTL = *CMSG_DATA(CMsg);
                    CXPLAT_DBG_ASSERT(HopLimitTTL < 256);
                    CXPLAT_DBG_ASSERT(HopLimitTTL > 0);
                    FoundTTL = TRUE;
                } else {
                    CXPLAT_DBG_ASSERT(FALSE);
                }
            } else if (CMsg->cmsg_level == IPPROTO_IP) {
                if (CMsg->cmsg_type == IP_TOS) {
                    CXPLAT_DBG_ASSERT_CMSG(CMsg, uint8_t);
                    TOS = *(uint8_t*)CMSG_DATA(CMsg);
                    FoundTOS = TRUE;
                } else if (CMsg->cmsg_type == IP_TTL) {
                    HopLimitTTL = *CMSG_DATA(CMsg);
                    CXPLAT_DBG_ASSERT(HopLimitTTL < 256);
                    CXPLAT_DBG_ASSERT(HopLimitTTL > 0);
                    FoundTTL = TRUE;
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
        CXPLAT_FRE_ASSERT(FoundTTL);

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            MsgLen,
            SegmentLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        if (SegmentLength == 0) {
            SegmentLength = MsgLen;
        }

        DATAPATH_RX_PACKET* Datagram = (DATAPATH_RX_PACKET*)(IoBlock + 1);
        uint8_t* RecvBuffer = Msg->msg_iov->iov_base;
        IoBlock->RefCount = 0;

        //
        // Build up the chain of receive packets to indicate up to the app.
        //
        uint32_t Offset = 0;
        while (Offset < MsgLen &&
               IoBlock->RefCount < CXPLAT_MAX_IO_BATCH_SIZE) {
            IoBlock->RefCount++;
            Datagram->IoBlock = IoBlock;

            CXPLAT_RECV_DATA* RecvData = &Datagram->Data;
            RecvData->Next = NULL;
            RecvData->Route = &IoBlock->Route;
            RecvData->Buffer = RecvBuffer + Offset;
            if (MsgLen - Offset < SegmentLength) {
                RecvData->BufferLength = (uint16_t)(MsgLen - Offset);
            } else {
                RecvData->BufferLength = SegmentLength;
            }
            RecvData->PartitionIndex = SocketContext->DatapathPartition->PartitionIndex;
            RecvData->TypeOfService = TOS;
            RecvData->HopLimitTTL = (uint8_t)HopLimitTTL;
            RecvData->Allocated = TRUE;
            RecvData->Route->DatapathType = RecvData->DatapathType = CXPLAT_DATAPATH_TYPE_NORMAL;
            RecvData->QueuedOnConnection = FALSE;
            RecvData->Reserved = FALSE;

            *DatagramTail = RecvData;
            DatagramTail = &RecvData->Next;

            Offset += RecvData->BufferLength;
            Datagram = (DATAPATH_RX_PACKET*)
                ((char*)Datagram + SocketContext->DatapathPartition->Datapath->RecvBlockStride);
        }
    }

    if (BytesTransferred == 0 || DatagramHead == NULL) {
        QuicTraceLogWarning(
            DatapathRecvEmpty,
            "[data][%p] Dropping datagram with empty payload.",
            SocketContext->Binding);
        return;
    }

    if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
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

        CxPlatRundownRelease(&SocketContext->UpcallRundown);
    }
}

void
CxPlatSocketReceiveComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_CQE Cqe
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathPartition = SocketContext->DatapathPartition;
    DATAPATH_RX_IO_BLOCK* IoBlock;
    uint8_t* IoPayload;
    struct msghdr RecvMsgHdrs[1];
    struct iovec RecvIov;
    uint32_t BufferIndex;
    struct io_uring_recvmsg_out* RecvMsgOut;

    if (Cqe->res == -ENOBUFS) {
        //
        // Ignore packet loss indications for now.
        //
        goto Exit;
    }

    if (Cqe->res < 0) {
        if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
            CxPlatSocketHandleError(SocketContext, -Cqe->res);
            CxPlatRundownRelease(&SocketContext->UpcallRundown);
        }
        goto Exit;
    }

    CXPLAT_DBG_ASSERT(Cqe->flags & IORING_CQE_F_BUFFER);

    BufferIndex = Cqe->flags >> 16;
    IoBlock =
        (DATAPATH_RX_IO_BLOCK*)CxPlatGetBufferPoolBuffer(
            &DatapathPartition->RecvRegisteredBufferPool, BufferIndex);
    IoPayload = (uint8_t*)IoBlock + DatapathPartition->Datapath->RecvBlockBufferOffset;
    RecvMsgOut = io_uring_recvmsg_validate(IoPayload, Cqe->res, (struct msghdr*)&CxPlatRecvMsgHdr);
    CXPLAT_FRE_ASSERT(RecvMsgOut != NULL); // Review: can this legally fail?

    CXPLAT_DBG_ASSERT((uintptr_t)IoBlock % CXPLAT_MEMORY_ALIGNMENT == 0);

    IoBlock->Route.State = RouteResolved;

    //
    // Review: these can be batched by propagating the CQE array here.
    //
    struct msghdr* MsgHdr = &RecvMsgHdrs[0];
    MsgHdr->msg_name = io_uring_recvmsg_name(RecvMsgOut);
    MsgHdr->msg_namelen = RecvMsgOut->namelen;
    MsgHdr->msg_iov = &RecvIov;
    MsgHdr->msg_iovlen = 1;
    MsgHdr->msg_control =
        io_uring_recvmsg_cmsg_firsthdr(RecvMsgOut, (struct msghdr*)&CxPlatRecvMsgHdr);
    MsgHdr->msg_controllen = RecvMsgOut->controllen;
    MsgHdr->msg_flags = 0;
    RecvIov.iov_base = io_uring_recvmsg_payload(RecvMsgOut, (struct msghdr*)&CxPlatRecvMsgHdr);
    RecvIov.iov_len =
        io_uring_recvmsg_payload_length(RecvMsgOut, Cqe->res, (struct msghdr*)&CxPlatRecvMsgHdr);

    CxPlatSocketContextRecvComplete(SocketContext, &IoBlock, RecvMsgHdrs);

Exit:

    if (!(Cqe->flags & IORING_CQE_F_MORE)) {
        CXPLAT_DBG_ASSERT(SocketContext->LockedFlags.MultiRecvStarted);
        CXPLAT_DBG_ONLY(SocketContext->LockedFlags.MultiRecvStarted = FALSE);

        if (!SocketContext->LockedFlags.Shutdown) {
            CxPlatSocketContextStartMultiRecvUnderLock(SocketContext);
        }

        CxPlatSocketIoComplete(SocketContext, IoTagRecv);
    }
}

void
RecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;
        DATAPATH_RX_IO_BLOCK* IoBlock =
            CXPLAT_CONTAINING_RECORD(Datagram, DATAPATH_RX_PACKET, Data)->IoBlock;
        if (InterlockedDecrement(&IoBlock->RefCount) == 0) {
            CXPLAT_DATAPATH_PARTITION* DatapathPartition = IoBlock->DatapathPartition;
            //
            // Review: this is amenable to batching, but the added complexity
            // may not be worth it.
            //
            CxPlatLockAcquire(&DatapathPartition->RecvRegisteredBufferPool.Lock);
            io_uring_buf_ring_add(
                DatapathPartition->RecvRegisteredBufferPool.Ring,
                (uint8_t*)IoBlock + DatapathPartition->Datapath->RecvBlockBufferOffset,
                CxPlatGetBufferPoolBufferSize(&DatapathPartition->RecvRegisteredBufferPool) -
                    DatapathPartition->Datapath->RecvBlockBufferOffset,
                IoBlock->BufferIndex, io_uring_buf_ring_mask(RecvBufCount), 0);
            io_uring_buf_ring_advance(DatapathPartition->RecvRegisteredBufferPool.Ring, 1);
            CxPlatLockRelease(&DatapathPartition->RecvRegisteredBufferPool.Lock);
        }
    }
}

//
// Send Path
//

#if DEBUG

CXPLAT_SEND_DATA_STATE
SendDataUpdateState(
    _Inout_ CXPLAT_SEND_DATA* SendData,
    _In_ CXPLAT_SEND_DATA_STATE NewState
    )
{
    return (CXPLAT_SEND_DATA_STATE)InterlockedExchange32((int32_t*)&SendData->State, (int32_t)NewState);
}

#endif // DEBUG

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
SendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    CXPLAT_DBG_ASSERT(Socket->Type != CXPLAT_SOCKET_UDP || Config->MaxPacketSize <= MAX_UDP_PAYLOAD_LENGTH);
    if (Config->Route->Queue == NULL) {
        Config->Route->Queue = (CXPLAT_QUEUE*)&Socket->SocketContexts[0];
    }

    CXPLAT_SOCKET_CONTEXT* SocketContext = (CXPLAT_SOCKET_CONTEXT*)Config->Route->Queue;
    CXPLAT_DBG_ASSERT(SocketContext->Binding == Socket);
    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathPartition->Datapath);
    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(&SocketContext->DatapathPartition->SendBlockPool);
    if (SendData != NULL) {
        SendData->SocketContext = SocketContext;
        SendData->ClientBuffer.Buffer = SendData->Buffer;
        SendData->ClientBuffer.Length = 0;
        SendData->TotalSize = 0;
        SendData->TotalBytesSent = 0;
        SendData->SegmentSize =
            (Socket->Type != CXPLAT_SOCKET_UDP ||
             Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)
                ? Config->MaxPacketSize : 0;
        SendData->BufferCount = 0;
        SendData->AlreadySentCount = 0;
        SendData->ControlBufferLength = 0;
        SendData->ECN = Config->ECN;
        SendData->DSCP = Config->DSCP;
        SendData->Flags = Config->Flags;
        SendData->OnConnectedSocket = Socket->Connected;
        SendData->SegmentationSupported =
            !!(Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
        SendData->Iovs[0].iov_len = 0;
        SendData->Iovs[0].iov_base = SendData->Buffer;
        SendData->DatapathType = Config->Route->DatapathType = CXPLAT_DATAPATH_TYPE_NORMAL;
        CXPLAT_DBG_ONLY(SendDataUpdateState(SendData, SendStateAllocated));
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendDataUpdateState(SendData, SendStateFreed) != SendStateFreed);
    CxPlatPoolFree(SendData);
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
            SendData->TotalSize + SendData->ClientBuffer.Length > sizeof(SendData->Buffer) ||
            SendData->BufferCount == SendData->SocketContext->DatapathPartition->Datapath->SendIoVecCount) {
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
SendDataAllocBuffer(
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
        SendData->BufferCount < SendData->SocketContext->DatapathPartition->Datapath->SendIoVecCount);
    CXPLAT_DBG_ASSERT(SendData->State == SendStateAllocated);
    UNREFERENCED_PARAMETER(MaxBufferLength);
    if (SendData->ClientBuffer.Buffer == NULL) {
        return NULL;
    }
    SendData->ClientBuffer.Length = MaxBufferLength;
    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    //
    // This must be the final send buffer; intermediate Iovs cannot be freed.
    //
    CXPLAT_DBG_ASSERT(Buffer == &SendData->ClientBuffer);
    CXPLAT_DBG_ASSERT(SendData->State == SendStateAllocated);
    Buffer->Length = 0;
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
SendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatSendDataFinalizeSendBuffer(SendData);
    return SendData->ClientBuffer.Buffer == NULL;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN AlreadyLocked,
    _In_ BOOLEAN AlreadyQueued
    );

void
SocketSend(
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
    // Go ahead and try to send on the socket.
    //
    CxPlatSendDataSend(SendData, FALSE, FALSE);
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
    struct cmsghdr* CMsg = CMSG_FIRSTHDR(Mhdr);
    CMsg->cmsg_level = SendData->LocalAddress.Ip.sa_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    CMsg->cmsg_type = SendData->LocalAddress.Ip.sa_family == AF_INET ? IP_TOS : IPV6_TCLASS;
    CMsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int*)CMSG_DATA(CMsg) = SendData->ECN | (SendData->DSCP << 2);

    if (!SendData->OnConnectedSocket) {
        if (SendData->LocalAddress.Ip.sa_family == AF_INET) {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(struct in_pktinfo));
            CMsg = CXPLAT_CMSG_NXTHDR(CMsg);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo* PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
            PktInfo->ipi_ifindex = SendData->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo->ipi_spec_dst = SendData->LocalAddress.Ipv4.sin_addr;
            PktInfo->ipi_addr = SendData->LocalAddress.Ipv4.sin_addr;
        } else {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
            CMsg = CXPLAT_CMSG_NXTHDR(CMsg);
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo* PktInfo6 = (struct in6_pktinfo*)CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = SendData->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = SendData->LocalAddress.Ipv6.sin6_addr;
        }
    }

#ifdef UDP_SEGMENT
    if (SendData->SegmentationSupported && SendData->SegmentSize > 0 && Mhdr->msg_iov->iov_len > SendData->SegmentSize) {
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

QUIC_STATUS
CxPlatSendDataSendSegmented(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN AlreadyLocked,
    _In_ BOOLEAN AlreadyQueued
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathPartition = SendData->SocketContext->DatapathPartition;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    struct io_uring_sqe* Sqe;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!AlreadyLocked) { // Review: can we infer this from thread ID?
        CxPlatLockAcquire(&DatapathPartition->EventQ->Lock);
    }

    if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        if (!AlreadyQueued) {
            CxPlatListInsertTail(&SocketContext->TxQueue, &SendData->TxEntry);
            CXPLAT_DBG_ASSERT(SendDataUpdateState(SendData, SendStateQueued) ==
                SendStateAllocated);
        }
        Status = QUIC_STATUS_PENDING;
        goto Exit;
    }

    Sqe = CxPlatSocketAllocSqe(SocketContext);
    if (Sqe == NULL) {
        if (!AlreadyQueued) {
            CxPlatListInsertTail(&SocketContext->TxQueue, &SendData->TxEntry);
            CXPLAT_DBG_ASSERT(SendDataUpdateState(SendData, SendStateQueued) ==
                SendStateAllocated);
        }
        Status = QUIC_STATUS_PENDING;
        goto Exit;
    }

    SendData->MsgHdr.msg_name = (void*)&SendData->RemoteAddress;
    SendData->MsgHdr.msg_namelen = sizeof(SendData->RemoteAddress);
    SendData->MsgHdr.msg_iov = SendData->Iovs;
    SendData->MsgHdr.msg_iovlen = 1;
    SendData->MsgHdr.msg_flags = 0;
    SendData->MsgHdr.msg_control = SendData->ControlBuffer;
    SendData->MsgHdr.msg_controllen = SendData->ControlBufferLength;
    if (SendData->ControlBufferLength == 0) {
        CxPlatSendDataPopulateAncillaryData(SendData, &SendData->MsgHdr);
    } else {
        SendData->MsgHdr.msg_controllen = SendData->ControlBufferLength;
    }

    io_uring_prep_sendmsg(Sqe, SendData->SocketContext->SocketFd, &SendData->MsgHdr, 0);
    io_uring_sqe_set_data(Sqe, (void*)&SendData->Sqe);
    CxPlatBatchSqeInitialize(
        DatapathPartition->EventQ, CxPlatSocketContextIoEventComplete, &SendData->Sqe.Sqe);
    SendData->Sqe.Context = (void*)DatapathContextSend; // NOLINT performance-no-int-to-ptr
    CxPlatSocketIoStart(SocketContext, IoTagSend);
    CXPLAT_DBG_ASSERT(SendDataUpdateState(SendData, SendStateSending) ==
        (AlreadyQueued ? SendStateQueued : SendStateAllocated));

Exit:

    if (!AlreadyLocked) {
        //
        // Review: as an experiment with batching, instead of immediately
        // submitting, this marks the EventQ as needing a submit and performs
        // the submit when the EventQ is next dequeued. This only works if the
        // caller is running on the socket's partition. There is not a good
        // abstraction for that check right now, because caller alignment is
        // not guaranteed.
        //
        if (DatapathPartition->OwningThreadID == CxPlatCurThreadID()) {
            DatapathPartition->EventQ->NeedsSubmit = TRUE;
        } else {
            CxPlatEventQSubmit(DatapathPartition->EventQ);
        }
        CxPlatLockRelease(&DatapathPartition->EventQ->Lock);
    }

    return Status;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ BOOLEAN AlreadyLocked,
    _In_ BOOLEAN AlreadyQueued
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(SendData->AlreadySentCount < CXPLAT_MAX_IO_BATCH_SIZE);
    CXPLAT_SOCKET_TYPE SocketType = SendData->SocketContext->Binding->Type;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;

    Status = CxPlatSendDataSendSegmented(SendData, AlreadyLocked, AlreadyQueued);

    if (QUIC_FAILED(Status)) {
        if (Status != QUIC_STATUS_PENDING) {
            Status = errno;
            if (SocketType == CXPLAT_SOCKET_UDP) {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "sendmsg (GSO) failed");
            } else {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "send failed");
            }

            if (Status == EIO &&
                SocketContext->Binding->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
                //
                // EIO generally indicates the GSO isn't supported by the NIC,
                // so disable segmentation on the datapath globally.
                //
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Disabling segmentation support globally");
                SocketContext->Binding->Datapath->Features &=
                    ~CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
            }

            //
            // Unreachable events can sometimes come synchronously.
            // Send unreachable notification to MsQuic if any related
            // errors were received.
            //
            if (Status == ECONNREFUSED ||
                Status == EHOSTUNREACH ||
                Status == ENETUNREACH) {
                if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
                    if (!SocketContext->Binding->PcpBinding) {
                        SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
                            SocketContext->Binding,
                            SocketContext->Binding->ClientContext,
                            &SocketContext->Binding->RemoteAddress);
                    }

                    CxPlatRundownRelease(&SocketContext->UpcallRundown);
                }
            }
        }
    }

    return Status;
}

void
CxPlatSocketContextSendComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_CQE Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(&Cqe);
    CXPLAT_SEND_DATA* SendData = CXPLAT_CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe);

    CXPLAT_DBG_ASSERT(SendDataUpdateState(SendData, SendStateSendComplete) == SendStateSending);
    CxPlatSendDataFree(SendData);
    SendData = NULL;

    if (SocketContext->LockedFlags.Shutdown) {
        goto Exit;
    }

    if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
        SendData =
            CXPLAT_CONTAINING_RECORD(
                SocketContext->TxQueue.Flink,
                CXPLAT_SEND_DATA,
                TxEntry);
    }

    while (SendData != NULL) {
        QUIC_STATUS Status = CxPlatSendDataSend(SendData, TRUE, TRUE);
        if (Status == QUIC_STATUS_PENDING) {
            //
            // The io_uring is full. We'll get a completion when there's more space, and then
            // continue sending.
            //
            goto Exit;
        }

        CxPlatListRemoveHead(&SocketContext->TxQueue);
        if (!CxPlatListIsEmpty(&SocketContext->TxQueue)) {
            SendData =
                CXPLAT_CONTAINING_RECORD(
                    SocketContext->TxQueue.Flink,
                    CXPLAT_SEND_DATA,
                    TxEntry);
        } else {
            SendData = NULL;
        }
    }

Exit:

    CxPlatSocketIoComplete(SocketContext, IoTagSend);
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

CXPLAT_SOCKET_CONTEXT*
GetSocketContextFromSqe(
    _In_ CXPLAT_SQE* Sqe
    )
{
    CXPLAT_SOCKET_SQE* SocketSqe = CXPLAT_CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_SQE, Sqe);

    switch ((DATAPATH_CONTEXT_TYPE)(uintptr_t)SocketSqe->Context) {
    case DatapathContextRecv:
        return CXPLAT_CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_CONTEXT, IoSqe.Sqe);
    case DatapathContextSend:
        return CXPLAT_CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe)->SocketContext;
    default:
        CXPLAT_DBG_ASSERT(FALSE);
        return NULL;
    }
}

void
CxPlatSocketContextIoEventComplete(
    _Inout_ CXPLAT_CQE** Cqes,
    _Inout_ uint32_t* CqeCount
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(*Cqes);
    CXPLAT_SOCKET_CONTEXT* SocketContext = GetSocketContextFromSqe(Sqe);
    CXPLAT_DATAPATH_PARTITION* DatapathPartition = SocketContext->DatapathPartition;
    CXPLAT_EVENTQ* EventQ = DatapathPartition->EventQ;

    //
    // Review: this lazy thread ID initialization is not ideal. Instead,
    // partitions boundaries should be strictly enforced in io_uring mode,
    // eliminating the need for thread + locks.
    //
    if (DatapathPartition->OwningThreadID == 0) {
        DatapathPartition->OwningThreadID = CxPlatCurThreadID();
    }

    CxPlatLockAcquire(&EventQ->Lock);

    while (TRUE) {
        CXPLAT_SOCKET_SQE* SocketSqe = CXPLAT_CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_SQE, Sqe);

        //
        // Review: these functions could be unrolled to batch within an IO
        // type on a socket.
        //
        switch ((DATAPATH_CONTEXT_TYPE)(uintptr_t)SocketSqe->Context) {
        case DatapathContextRecv:
            CxPlatSocketReceiveComplete(SocketContext, *Cqes[0]);
            break;
        case DatapathContextSend:
            CxPlatSocketContextSendComplete(SocketContext, *Cqes[0]);
            break;
        default:
            CXPLAT_DBG_ASSERT(FALSE);
        }

        (*Cqes)++;
        (*CqeCount)--;

        if (*CqeCount == 0 ||
            CxPlatCqeGetSqe(*Cqes)->Completion != CxPlatSocketContextIoEventComplete) {
            break;
        }

        Sqe = CxPlatCqeGetSqe(*Cqes);
        SocketContext = GetSocketContextFromSqe(Sqe);
    }

    CxPlatEventQSubmit(EventQ);

    CxPlatLockRelease(&EventQ->Lock);
}
