/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#include "platform_internal.h"
#include <fcntl.h>
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
// Payload size: 65535 - 8 (UDP header) - 20 (IP header) = 65507 bytes.
//
#define CXPLAT_LARGE_IO_BUFFER_SIZE         0xFFE3

//
// The maximum batch size of IOs in that can use a single coalesced IO buffer.
// This is calculated base on the number of the smallest possible single
// packet/datagram payloads (i.e. IPv6) that can fit in the large buffer.
//
const uint16_t CXPLAT_MAX_IO_BATCH_SIZE =
    (CXPLAT_LARGE_IO_BUFFER_SIZE / (1280 - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE));

//
// Contains all the info for a single RX IO operation. Multiple RX packets may
// come from a single IO operation.
//
typedef struct __attribute__((aligned(16))) DATAPATH_RX_IO_BLOCK {
    //
    // Represents the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // Ref count of receive data/packets that are using this block.
    //
    long RefCount;

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

typedef struct __attribute__((aligned(16))) DATAPATH_RX_PACKET {
    //
    // The IO block that owns the packet.
    //
    DATAPATH_RX_IO_BLOCK* IoBlock;

    //
    // Publicly visible receive data.
    //
    CXPLAT_RECV_DATA Data;

} DATAPATH_RX_PACKET;

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

CXPLAT_EVENT_COMPLETION CxPlatSocketContextUninitializeEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatSocketContextFlushTxEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatSocketContextIoEventComplete;

void
CxPlatDataPathCalculateFeatureSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvDataLength
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
        sizeof(DATAPATH_RX_PACKET) + ClientRecvDataLength;
    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
        Datapath->RecvBlockBufferOffset =
            sizeof(DATAPATH_RX_IO_BLOCK) +
            CXPLAT_MAX_IO_BATCH_SIZE * Datapath->RecvBlockStride;
        Datapath->RecvBlockSize =
            Datapath->RecvBlockBufferOffset + CXPLAT_LARGE_IO_BUFFER_SIZE;
    } else {
        Datapath->RecvBlockBufferOffset =
            sizeof(DATAPATH_RX_IO_BLOCK) + Datapath->RecvBlockStride;
        Datapath->RecvBlockSize =
            Datapath->RecvBlockBufferOffset + CXPLAT_SMALL_IO_BUFFER_SIZE;
    }

    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_TCP;
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_TTL;
    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_DSCP;
}

void
CxPlatProcessorContextInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t PartitionIndex,
    _Out_ CXPLAT_DATAPATH_PARTITION* DatapathPartition
    )
{
    CXPLAT_DBG_ASSERT(Datapath != NULL);
    DatapathPartition->Datapath = Datapath;
    DatapathPartition->PartitionIndex = PartitionIndex;
    DatapathPartition->EventQ = CxPlatWorkerPoolGetEventQ(Datapath->WorkerPool, PartitionIndex);
    CxPlatRefInitialize(&DatapathPartition->RefCount);
    CxPlatPoolInitialize(TRUE, Datapath->RecvBlockSize, QUIC_POOL_DATA, &DatapathPartition->RecvBlockPool);
    CxPlatPoolInitialize(TRUE, Datapath->SendDataSize, QUIC_POOL_DATA, &DatapathPartition->SendBlockPool);
}

QUIC_STATUS
DataPathInitialize(
    _In_ uint32_t ClientRecvDataLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _Out_ CXPLAT_DATAPATH** NewDatapath
    )
{
    UNREFERENCED_PARAMETER(TcpCallbacks);

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
    CxPlatDataPathCalculateFeatureSupport(Datapath, ClientRecvDataLength);

    //
    // Initialize the per processor contexts.
    //
    for (uint32_t i = 0; i < Datapath->PartitionCount; i++) {
        CxPlatProcessorContextInitialize(
            Datapath, i, &Datapath->Partitions[i]);
    }

    CXPLAT_FRE_ASSERT(CxPlatWorkerPoolAddRef(WorkerPool));
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
        CxPlatPoolUninitialize(&DatapathPartition->SendBlockPool);
        CxPlatPoolUninitialize(&DatapathPartition->RecvBlockPool);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
DataPathUpdatePollingIdleTimeout(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t PollingIdleTimeoutUs
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(PollingIdleTimeoutUs);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_FEATURES
DataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return Datapath->Features;
}

BOOLEAN
DataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
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
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF | SKF_AD_CPU}, // Load CPU number
        {BPF_ALU | BPF_MOD, 0, 0, SocketCount}, // MOD by SocketCount
        {BPF_RET | BPF_A, 0, 0, 0} // Return
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

QUIC_STATUS
CxPlatSocketContextSqeInitialize(
    _Inout_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET* Binding = SocketContext->Binding;
    BOOLEAN ShutdownSqeInitialized = FALSE;
    BOOLEAN IoSqeInitialized = FALSE;

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

    if (!CxPlatSqeInitialize(
            SocketContext->DatapathPartition->EventQ,
            CxPlatSocketContextIoEventComplete,
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
            SocketContext->DatapathPartition->EventQ,
            CxPlatSocketContextFlushTxEventComplete,
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

    SocketContext->SqeInitialized = TRUE;
    return QUIC_STATUS_SUCCESS;

Exit:

    if (ShutdownSqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->ShutdownSqe);
    }
    if (IoSqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->IoSqe);
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
    // Create datagram socket.
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

        //
        // Prevent the socket from entering TIME_WAIT state when closed.
        //
        struct linger LingerOpt;
        LingerOpt.l_onoff = TRUE;   // Enable linger
        LingerOpt.l_linger = 0;     // Linger time of 0 seconds (immediate reset)
        Result = setsockopt(SocketContext->SocketFd, SOL_SOCKET, SO_LINGER, &LingerOpt, sizeof(LingerOpt));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(SO_LINGER) failed");
            goto Exit;
        }
    } else if (SocketType == CXPLAT_SOCKET_TCP) {
        //
        // Prevent the socket from entering TIME_WAIT state when closed.
        //
        struct linger LingerOpt;
        LingerOpt.l_onoff = TRUE;   // Enable linger
        LingerOpt.l_linger = 0;     // Linger time of 0 seconds (immediate reset)
        Result = setsockopt(SocketContext->SocketFd, SOL_SOCKET, SO_LINGER, &LingerOpt, sizeof(LingerOpt));
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "setsockopt(SO_LINGER) failed");
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
        epoll_ctl(*SocketContext->DatapathPartition->EventQ, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);
        close(SocketContext->SocketFd);
    }

    if (SocketContext->SqeInitialized) {
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->ShutdownSqe);
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->IoSqe);
        CxPlatSqeCleanup(SocketContext->DatapathPartition->EventQ, &SocketContext->FlushTxSqe);
    }

    CxPlatLockUninitialize(&SocketContext->TxQueueLock);
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

        //
        // Cancel and clean up any pending IO.
        //
        epoll_ctl(*SocketContext->DatapathPartition->EventQ, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

        CXPLAT_FRE_ASSERT(
            CxPlatEventQEnqueue(
                SocketContext->DatapathPartition->EventQ,
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
            *SocketContext->DatapathPartition->EventQ,
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
        CxPlatLockInitialize(&Binding->SocketContexts[i].TxQueueLock);
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
        CxPlatSocketContextSetEvents(&Binding->SocketContexts[i], EPOLL_CTL_ADD, EPOLLIN);
        Binding->SocketContexts[i].IoStarted = TRUE;
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
CxPlatSocketCreateTcpInternal(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_TYPE Type,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _In_opt_ CXPLAT_SOCKET_CONTEXT* ListenerSocketContext,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status;
    uint16_t PartitionIndex;
    uint32_t EpollEvents = ListenerSocketContext ? EPOLLIN : EPOLLOUT | EPOLLIN;

    CXPLAT_DBG_ASSERT(Datapath->TcpHandlers.Receive != NULL);

    CXPLAT_SOCKET_CONTEXT* SocketContext = NULL;
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + sizeof(CXPLAT_SOCKET_CONTEXT);
    CXPLAT_SOCKET_RAW* RawBinding = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawBinding == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CXPLAT_SOCKET* Binding = CxPlatRawToSocket(RawBinding);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    CxPlatZeroMemory(RawBinding, RawSocketLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->HasFixedRemoteAddress = TRUE;
    Binding->Mtu = CXPLAT_MAX_MTU;
    Binding->Type = Type;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }

    Binding->RecvBufLen = Datapath->RecvBlockSize - Datapath->RecvBlockBufferOffset;
    if (Type == CXPLAT_SOCKET_TCP_SERVER) {
        //
        // The accepted socket must be assigned to the same partition as the listener
        // to prevent race conditions, e.g. accept handler racing with receive handler.
        // Also, it distributes the load across the partitions.
        //
        PartitionIndex = ListenerSocketContext->DatapathPartition->PartitionIndex;
    } else {
        PartitionIndex =
            RemoteAddress ?
                ((uint16_t)(CxPlatProcCurrentNumber() % Datapath->PartitionCount)) : 0;
    }

    CxPlatRefInitializeEx(&Binding->RefCount, 1);

    SocketContext = &Binding->SocketContexts[0];
    SocketContext->Binding = Binding;
    SocketContext->SocketFd = INVALID_SOCKET;
    CxPlatListInitializeHead(&SocketContext->TxQueue);
    CxPlatLockInitialize(&SocketContext->TxQueueLock);
    CxPlatRundownInitialize(&SocketContext->UpcallRundown);

    CXPLAT_UDP_CONFIG Config = {
        .LocalAddress = LocalAddress,
        .RemoteAddress = RemoteAddress
    };
    Status =
        CxPlatSocketContextInitialize(
            SocketContext,
            &Config,
            PartitionIndex,
            Binding->Type);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    if (Type == CXPLAT_SOCKET_TCP_SERVER) {
        socklen_t AssignedRemoteAddressLength = sizeof(Binding->RemoteAddress);
        SocketContext->SocketFd =
            accept4(
                ListenerSocketContext->SocketFd,
                (struct sockaddr*)&Binding->RemoteAddress,
                &AssignedRemoteAddressLength, SOCK_NONBLOCK);
        if (SocketContext->SocketFd == INVALID_SOCKET) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "accept failed");
            goto Exit;
        }

        socklen_t AssignedLocalAddressLength = sizeof(Binding->LocalAddress);
        int Result =
            getsockname(
                SocketContext->SocketFd,
                (struct sockaddr*)&Binding->LocalAddress,
                &AssignedLocalAddressLength);
        if (Result == SOCKET_ERROR) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "getsockname failed");
            goto Exit;
        }
    }

    CxPlatConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
        if (Binding->Type == CXPLAT_SOCKET_TCP_SERVER) {
            CxPlatConvertFromMappedV6(&Binding->RemoteAddress, &Binding->RemoteAddress);
        } else {
            Binding->RemoteAddress.Ipv4.sin_port = 0;
        }
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    CxPlatSocketContextSetEvents(SocketContext, EPOLL_CTL_ADD, EpollEvents);
    SocketContext->IoStarted = TRUE;

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
    return
        CxPlatSocketCreateTcpInternal(
            Datapath,
            CXPLAT_SOCKET_TCP,
            LocalAddress,
            RemoteAddress,
            CallbackContext,
            NULL,
            Socket);
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
    QUIC_STATUS Status;

    CXPLAT_DBG_ASSERT(Datapath->TcpHandlers.Receive != NULL);
    const uint16_t SocketCount = Datapath->PartitionCount > 1 ? (uint16_t)CxPlatProcCount() : 1;
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + SocketCount * sizeof(CXPLAT_SOCKET_CONTEXT);
    CXPLAT_SOCKET_RAW* RawBinding = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawBinding == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    CXPLAT_SOCKET* Binding = CxPlatRawToSocket(RawBinding);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(0, NULL));

    CxPlatZeroMemory(RawBinding, RawSocketLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = CallbackContext;
    Binding->HasFixedRemoteAddress = FALSE;
    Binding->NumPerProcessorSockets = Datapath->PartitionCount > 1;
    Binding->Mtu = CXPLAT_MAX_MTU;
    Binding->Type = CXPLAT_SOCKET_TCP_LISTENER;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
        if (Binding->LocalAddress.Ip.sa_family == AF_UNSPEC) {
            Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
        }
    } else {
        Binding->LocalAddress.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    CxPlatRefInitializeEx(&Binding->RefCount, SocketCount);

    CXPLAT_UDP_CONFIG Config = {
        .LocalAddress = LocalAddress,
        .RemoteAddress = NULL
    };

    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET;
        CxPlatListInitializeHead(&Binding->SocketContexts[i].TxQueue);
        CxPlatLockInitialize(&Binding->SocketContexts[i].TxQueueLock);
        CxPlatRundownInitialize(&Binding->SocketContexts[i].UpcallRundown);
    }

    for (uint32_t i = 0; i < SocketCount; i++) {
        Status =
            CxPlatSocketContextInitialize(
                &Binding->SocketContexts[i],
                &Config,
                i % Datapath->PartitionCount,
                Binding->Type);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    *Socket = Binding;

    //
    // RSS based load balancing for listeners. This is not necessarily better
    // than the default round-robin strategy, but it's good to keep TCP behavior
    // consistent with UDP.
    //
    (void)CxPlatSocketConfigureRss(&Binding->SocketContexts[0], SocketCount);

    for (uint32_t i = 0; i < SocketCount; i++) {
        CxPlatSocketContextSetEvents(&Binding->SocketContexts[i], EPOLL_CTL_ADD, EPOLLIN);
        Binding->SocketContexts[i].IoStarted = TRUE;
    }

    Binding = NULL;
    RawBinding = NULL;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (RawBinding != NULL) {
        SocketDelete(CxPlatRawToSocket(RawBinding));
    }

    return Status;
}

void
CxPlatSocketContextAcceptCompletion(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
    CXPLAT_DATAPATH* Datapath = SocketContext->Binding->Datapath;
    CXPLAT_SOCKET* AcceptSocket = NULL;

    QUIC_STATUS Status =
        CxPlatSocketCreateTcpInternal(
            Datapath,
            CXPLAT_SOCKET_TCP_SERVER,
            NULL,
            NULL,
            NULL,
            SocketContext,
            (CXPLAT_SOCKET**)&AcceptSocket);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        Datapath->TcpHandlers.Accept(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            AcceptSocket,
            &AcceptSocket->ClientContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    AcceptSocket = NULL;

Error:

    if (AcceptSocket != NULL) {
        SocketDelete(AcceptSocket);
        AcceptSocket = NULL;
    }
}

void
CxPlatSocketContextConnectCompletion(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
    CXPLAT_DATAPATH* Datapath = SocketContext->Binding->Datapath;

    Datapath->TcpHandlers.Connect(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        TRUE);
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
    }
}

void
CxPlatSocketContextRecvComplete(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext,
    _Inout_ DATAPATH_RX_IO_BLOCK** IoBlocks,
    _In_ struct mmsghdr* RecvMsgHdr,
    _In_ int MessagesReceived
    )
{
    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath == SocketContext->DatapathPartition->Datapath);

    uint32_t BytesTransferred = 0;
    CXPLAT_RECV_DATA* DatagramHead = NULL;
    CXPLAT_RECV_DATA** DatagramTail = &DatagramHead;
    for (int CurrentMessage = 0; CurrentMessage < MessagesReceived; CurrentMessage++) {
        DATAPATH_RX_IO_BLOCK* IoBlock = IoBlocks[CurrentMessage];
        IoBlocks[CurrentMessage] = NULL;
        BytesTransferred += RecvMsgHdr[CurrentMessage].msg_len;

        uint8_t TOS = 0;
        int HopLimitTTL = 0;
        uint16_t SegmentLength = 0;
        BOOLEAN FoundLocalAddr = FALSE, FoundTOS = FALSE, FoundTTL = FALSE;
        QUIC_ADDR* LocalAddr = &IoBlock->Route.LocalAddress;
        QUIC_ADDR* RemoteAddr = &IoBlock->Route.RemoteAddress;
        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);
        IoBlock->Route.Queue = (CXPLAT_QUEUE*)SocketContext;

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
            RecvMsgHdr[CurrentMessage].msg_len,
            SegmentLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        if (SegmentLength == 0) {
            SegmentLength = RecvMsgHdr[CurrentMessage].msg_len;
        }

        DATAPATH_RX_PACKET* Datagram = (DATAPATH_RX_PACKET*)(IoBlock + 1);
        uint8_t* RecvBuffer =
            (uint8_t*)IoBlock + SocketContext->DatapathPartition->Datapath->RecvBlockBufferOffset;
        IoBlock->RefCount = 0;

        //
        // Build up the chain of receive packets to indicate up to the app.
        //
        uint32_t Offset = 0;
        while (Offset < RecvMsgHdr[CurrentMessage].msg_len &&
               IoBlock->RefCount < CXPLAT_MAX_IO_BATCH_SIZE) {
            IoBlock->RefCount++;
            Datagram->IoBlock = IoBlock;

            CXPLAT_RECV_DATA* RecvData = &Datagram->Data;
            RecvData->Next = NULL;
            RecvData->Route = &IoBlock->Route;
            RecvData->Buffer = RecvBuffer + Offset;
            if (RecvMsgHdr[CurrentMessage].msg_len - Offset < SegmentLength) {
                RecvData->BufferLength = (uint16_t)(RecvMsgHdr[CurrentMessage].msg_len - Offset);
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
    CXPLAT_DATAPATH_PARTITION* DatapathPartition = SocketContext->DatapathPartition;
    DATAPATH_RX_IO_BLOCK* IoBlock = NULL;
    struct mmsghdr RecvMsgHdr;
    CXPLAT_RECV_MSG_CONTROL_BUFFER RecvMsgControl;
    struct iovec RecvIov;

    do {
        uint32_t RetryCount = 0;
        do {
            IoBlock = CxPlatPoolAlloc(&DatapathPartition->RecvBlockPool);
        } while (IoBlock == NULL && ++RetryCount < 10);
        if (IoBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DATAPATH_RX_IO_BLOCK",
                0);
            goto Exit;
        }

        IoBlock->Route.State = RouteResolved;

        struct msghdr* MsgHdr = &RecvMsgHdr.msg_hdr;
        MsgHdr->msg_name = &IoBlock->Route.RemoteAddress;
        MsgHdr->msg_namelen = sizeof(IoBlock->Route.RemoteAddress);
        MsgHdr->msg_iov = &RecvIov;
        MsgHdr->msg_iovlen = 1;
        MsgHdr->msg_control = &RecvMsgControl.Data;
        MsgHdr->msg_controllen = sizeof(RecvMsgControl.Data);
        MsgHdr->msg_flags = 0;
        RecvIov.iov_base = (char*)IoBlock + DatapathPartition->Datapath->RecvBlockBufferOffset;
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
        CxPlatSocketContextRecvComplete(SocketContext, &IoBlock, &RecvMsgHdr, Ret);

    } while (TRUE);

Exit:

    if (IoBlock) {
        CxPlatPoolFree(IoBlock);
    }
}

void
CxPlatSocketReceiveMessages(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathPartition = SocketContext->DatapathPartition;
    DATAPATH_RX_IO_BLOCK* IoBlocks[CXPLAT_MAX_IO_BATCH_SIZE];
    struct mmsghdr RecvMsgHdr[CXPLAT_MAX_IO_BATCH_SIZE];
    CXPLAT_RECV_MSG_CONTROL_BUFFER RecvMsgControl[CXPLAT_MAX_IO_BATCH_SIZE];
    struct iovec RecvIov[CXPLAT_MAX_IO_BATCH_SIZE];
    CxPlatZeroMemory(IoBlocks, sizeof(IoBlocks));

    do {
        uint32_t RetryCount = 0;
        for (uint32_t i = 0; i < CXPLAT_MAX_IO_BATCH_SIZE && IoBlocks[i] == NULL; ++i) {

            DATAPATH_RX_IO_BLOCK* IoBlock;
            do {
                IoBlock = CxPlatPoolAlloc(&DatapathPartition->RecvBlockPool);
            } while (IoBlock == NULL && ++RetryCount < 10);
            if (IoBlock == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "DATAPATH_RX_IO_BLOCK",
                    0);
                goto Exit;
            }

            IoBlocks[i] = IoBlock;
            IoBlock->Route.State = RouteResolved;

            struct msghdr* MsgHdr = &RecvMsgHdr[i].msg_hdr;
            MsgHdr->msg_name = &IoBlock->Route.RemoteAddress;
            MsgHdr->msg_namelen = sizeof(IoBlock->Route.RemoteAddress);
            MsgHdr->msg_iov = &RecvIov[i];
            MsgHdr->msg_iovlen = 1;
            MsgHdr->msg_control = &RecvMsgControl[i].Data;
            MsgHdr->msg_controllen = sizeof(RecvMsgControl[i].Data);
            MsgHdr->msg_flags = 0;
            RecvIov[i].iov_base = (char*)IoBlock + DatapathPartition->Datapath->RecvBlockBufferOffset;
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
        CxPlatSocketContextRecvComplete(SocketContext, IoBlocks, RecvMsgHdr, Ret);

    } while (TRUE);

Exit:

    for (uint32_t i = 0; i < CXPLAT_MAX_IO_BATCH_SIZE; ++i) {
        if (IoBlocks[i]) {
            CxPlatPoolFree(IoBlocks[i]);
        }
    }
}

void
CxPlatSocketReceiveTcpData(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathPartition = SocketContext->DatapathPartition;
    DATAPATH_RX_IO_BLOCK* IoBlock = NULL;

    //
    // Read in a loop until the blocking error is encountered unless EOF or other failures
    // are met.
    //
    do {
        uint32_t RetryCount = 0;
        do {
            IoBlock = CxPlatPoolAlloc(&DatapathPartition->RecvBlockPool);
        } while (IoBlock == NULL && ++RetryCount < 10);
        if (IoBlock == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "DATAPATH_RX_IO_BLOCK",
                0);
            goto Exit;
        }

        IoBlock->Route.State = RouteResolved;
        IoBlock->Route.Queue = (CXPLAT_QUEUE*)SocketContext;
        IoBlock->RefCount = 0;

        uint8_t* Buffer = (uint8_t*)IoBlock + DatapathPartition->Datapath->RecvBlockBufferOffset;
        int NumberOfBytesTransferred = read(SocketContext->SocketFd, Buffer, SocketContext->Binding->RecvBufLen);

        if (NumberOfBytesTransferred == 0) {
            if (!SocketContext->Binding->DisconnectIndicated) {
                SocketContext->Binding->DisconnectIndicated = TRUE;
                SocketContext->Binding->Datapath->TcpHandlers.Connect(
                    SocketContext->Binding,
                    SocketContext->Binding->ClientContext,
                    FALSE);
            }
            goto Exit;
        } else if (NumberOfBytesTransferred < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    errno,
                    "read failed");
            }
            goto Exit;
        } else {
            DATAPATH_RX_PACKET* Datagram = (DATAPATH_RX_PACKET*)(IoBlock + 1);
            Datagram->IoBlock = IoBlock;
            CXPLAT_RECV_DATA* Data = &Datagram->Data;

            Data->Next = NULL;
            Data->Buffer = Buffer;
            Data->BufferLength = NumberOfBytesTransferred;
            Data->Route = &IoBlock->Route;
            Data->PartitionIndex = SocketContext->DatapathPartition->PartitionIndex;
            Data->TypeOfService = 0;
            Data->Allocated = TRUE;
            Data->Route->DatapathType = Data->DatapathType = CXPLAT_DATAPATH_TYPE_NORMAL;
            Data->QueuedOnConnection = FALSE;
            IoBlock->RefCount++;
            IoBlock = NULL;

            SocketContext->Binding->Datapath->TcpHandlers.Receive(
                SocketContext->Binding,
                SocketContext->Binding->ClientContext,
                Data);
        }
    } while (TRUE);

Exit:
    if (IoBlock) {
        CxPlatPoolFree(IoBlock);
    }
}

void
CxPlatSocketReceive(
    _In_ CXPLAT_SOCKET_CONTEXT* SocketContext
    )
{
    if (SocketContext->Binding->Type == CXPLAT_SOCKET_UDP) {
        if (SocketContext->DatapathPartition->Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
            CxPlatSocketReceiveCoalesced(SocketContext);
        } else {
            CxPlatSocketReceiveMessages(SocketContext);
        }
    } else {
        CxPlatSocketReceiveTcpData(SocketContext);
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
        DATAPATH_RX_PACKET* Packet =
            CXPLAT_CONTAINING_RECORD(Datagram, DATAPATH_RX_PACKET, Data);
        if (InterlockedDecrement(&Packet->IoBlock->RefCount) == 0) {
            CxPlatPoolFree(Packet->IoBlock);
        }
    }
}

//
// Send Path
//

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
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
SendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
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
    _In_ CXPLAT_SEND_DATA* SendData
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
                    SocketContext->DatapathPartition->EventQ,
                    &SocketContext->FlushTxSqe));
        }
        return;
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
    } else {
        if (Socket->Type != CXPLAT_SOCKET_UDP) {
            SocketContext->Binding->Datapath->TcpHandlers.SendComplete(
                SocketContext->Binding,
                SocketContext->Binding->ClientContext,
                Status,
                SendData->TotalSize);
        }
        CxPlatSendDataFree(SendData);
    }
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
    *(int*)CMSG_DATA(CMsg) = SendData->ECN | (SendData->DSCP << 2);

    if (!SendData->OnConnectedSocket) {
        if (SendData->LocalAddress.Ip.sa_family == AF_INET) {
            Mhdr->msg_controllen += CMSG_SPACE(sizeof(struct in_pktinfo));
            CMsg = CXPLAT_CMSG_NXTHDR(CMsg);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo *PktInfo = (struct in_pktinfo*)CMSG_DATA(CMsg);
            PktInfo->ipi_ifindex = SendData->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo->ipi_spec_dst = SendData->LocalAddress.Ipv4.sin_addr;
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
CxPlatSendDataSendTcp(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    while (SendData->TotalSize > SendData->TotalBytesSent) {
        int BytesSent =
            send(
                SendData->SocketContext->SocketFd,
                SendData->Buffer + SendData->TotalBytesSent,
                SendData->TotalSize - SendData->TotalBytesSent,
                MSG_NOSIGNAL);
        if (BytesSent < 0) {
            return FALSE;
        }
        SendData->TotalBytesSent += BytesSent;
    }

    return TRUE;
}

QUIC_STATUS
CxPlatSendDataSend(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(SendData->AlreadySentCount < CXPLAT_MAX_IO_BATCH_SIZE);
    CXPLAT_SOCKET_TYPE SocketType = SendData->SocketContext->Binding->Type;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_SOCKET_CONTEXT* SocketContext = SendData->SocketContext;
    BOOLEAN Success;

    if (SocketType == CXPLAT_SOCKET_UDP) {
        Success =
#ifdef UDP_SEGMENT
            SendData->SegmentationSupported ?
                CxPlatSendDataSendSegmented(SendData) : CxPlatSendDataSendMessages(SendData);
#else
            CxPlatSendDataSendMessages(SendData);
#endif
    } else {
        Success = CxPlatSendDataSendTcp(SendData);
    }

    if (!Success) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            Status = QUIC_STATUS_PENDING;
        } else {
            Status = errno;
            if (SocketType == CXPLAT_SOCKET_UDP) {
#ifdef UDP_SEGMENT
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "sendmsg (GSO) failed");
#else
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketContext->Binding,
                    Status,
                    "sendmmsg failed");
#endif
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
        QUIC_STATUS Status = CxPlatSendDataSend(SendData);
        if (Status == QUIC_STATUS_PENDING) {
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
        if (SocketContext->Binding->Type != CXPLAT_SOCKET_UDP) {
            SocketContext->Binding->Datapath->TcpHandlers.SendComplete(
                SocketContext->Binding,
                SocketContext->Binding->ClientContext,
                Status,
                SendData->TotalSize);
        }
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
CxPlatSocketContextFlushTxEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_SOCKET_CONTEXT, FlushTxSqe);
    CxPlatSocketContextFlushTxQueue(SocketContext, FALSE);
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

void
CxPlatSocketContextIoEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_CONTEXT* SocketContext =
        CXPLAT_CONTAINING_RECORD(CxPlatCqeGetSqe(Cqe), CXPLAT_SOCKET_CONTEXT, IoSqe);

    if (CxPlatRundownAcquire(&SocketContext->UpcallRundown)) {
        if (EPOLLERR & Cqe->events) {
            CxPlatSocketHandleErrors(SocketContext);
        }
        if (EPOLLIN & Cqe->events) {
            if (SocketContext->Binding->Type == CXPLAT_SOCKET_TCP_LISTENER) {
                CxPlatSocketContextAcceptCompletion(SocketContext, Cqe);
            } else {
                CxPlatSocketReceive(SocketContext);
            }
        }
        if (EPOLLOUT & Cqe->events) {
            if (SocketContext->Binding->Type == CXPLAT_SOCKET_TCP && !SocketContext->Binding->Connected) {
                CxPlatSocketContextConnectCompletion(SocketContext, Cqe);
                SocketContext->Binding->Connected = TRUE;
            } else {
                CxPlatSocketContextFlushTxQueue(SocketContext, TRUE);
            }
        }
        CxPlatRundownRelease(&SocketContext->UpcallRundown);
    }
}
