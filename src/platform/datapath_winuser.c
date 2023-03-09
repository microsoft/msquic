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

#ifdef QUIC_FUZZER

int
CxPlatFuzzerSendMsg(
    _In_ SOCKET s,
    _In_ LPWSAMSG lpMsg,
    _In_ DWORD dwFlags,
    _Out_ LPDWORD lpNumberOfBytesSent,
    _In_ LPWSAOVERLAPPED lpOverlapped,
    _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );

int
CxPlatFuzzerRecvMsg(
    _In_ SOCKET s,
    _Inout_ LPWSAMSG lpMsg,
    _Out_ LPDWORD lpdwNumberOfBytesRecvd,
    _In_ LPWSAOVERLAPPED lpOverlapped,
    _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );

#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses

//
// This IOCTL allows for creating per-processor sockets for the same UDP port.
// This is used to get better parallelization to improve performance.
//
#ifndef SIO_CPU_AFFINITY
#define SIO_CPU_AFFINITY  _WSAIOW(IOC_VENDOR,21)
#endif

#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE           2
#endif

#ifndef UDP_RECV_MAX_COALESCED_SIZE
#define UDP_RECV_MAX_COALESCED_SIZE 3
#endif

#ifndef UDP_COALESCED_INFO
#define UDP_COALESCED_INFO          3
#endif

//
// The maximum number of UDP datagrams that can be sent with one call.
//
#define CXPLAT_MAX_BATCH_SEND                 1

//
// The maximum receive payload size.
//
#define MAX_RECV_PAYLOAD_LENGTH \
    (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE)

//
// The maximum UDP receive coalescing payload.
//
#define MAX_URO_PAYLOAD_LENGTH              (UINT16_MAX - CXPLAT_UDP_HEADER_SIZE)

//
// The maximum single buffer size for sending coalesced payloads.
//
#define CXPLAT_LARGE_SEND_BUFFER_SIZE         0xFFFF

//
// The maximum number of UDP datagrams to preallocate for URO.
//
#define URO_MAX_DATAGRAMS_PER_INDICATION    64

//
// The number of entries in each RIO socket's receive request queue (RQ).
//
#define RIO_RECV_QUEUE_DEPTH 256

//
// The maximum number of RIO receive buffers held in each per-processor pool.
//
#define RIO_MAX_RECV_POOL_SIZE 8192

//
// The number of entries in each RIO socket's send request queue (RQ).
//
#define RIO_SEND_QUEUE_DEPTH 256

//
// The maximum number of RIO send buffers held in each per-processor pool.
//
#define RIO_MAX_SEND_POOL_SIZE 8192

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_BUFFER) == sizeof(WSABUF),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_BUFFER, Length) == FIELD_OFFSET(WSABUF, len),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_BUFFER, Buffer) == FIELD_OFFSET(WSABUF, buf),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");

#define IsUnreachableErrorCode(ErrorCode) \
( \
    ErrorCode == ERROR_NETWORK_UNREACHABLE || \
    ErrorCode == ERROR_HOST_UNREACHABLE || \
    ErrorCode == ERROR_PROTOCOL_UNREACHABLE || \
    ErrorCode == ERROR_PORT_UNREACHABLE || \
    ErrorCode == WSAENETUNREACH || \
    ErrorCode == WSAEHOSTUNREACH || \
    ErrorCode == WSAECONNRESET \
)

typedef struct CXPLAT_DATAPATH_PROC CXPLAT_DATAPATH_PROC;   // Per-processor datapath state.
typedef struct CXPLAT_SOCKET_PROC CXPLAT_SOCKET_PROC;       // Per-processor socket state.

typedef enum CXPLAT_SOCKET_TYPE {
    CXPLAT_SOCKET_UDP             = 0,
    CXPLAT_SOCKET_TCP_LISTENER    = 1,
    CXPLAT_SOCKET_TCP             = 2,
    CXPLAT_SOCKET_TCP_SERVER      = 3
} CXPLAT_SOCKET_TYPE;

//
// Type of IO.
//
typedef enum DATAPATH_IO_TYPE {
    DATAPATH_IO_SIGNATURE         = 'WINU',
    DATAPATH_IO_RECV              = DATAPATH_IO_SIGNATURE + 1,
    DATAPATH_IO_SEND              = DATAPATH_IO_SIGNATURE + 2,
    DATAPATH_IO_QUEUE_SEND        = DATAPATH_IO_SIGNATURE + 3,
    DATAPATH_IO_ACCEPTEX          = DATAPATH_IO_SIGNATURE + 4,
    DATAPATH_IO_CONNECTEX         = DATAPATH_IO_SIGNATURE + 5,
    DATAPATH_IO_RIO_NOTIFY        = DATAPATH_IO_SIGNATURE + 6,
    DATAPATH_IO_RIO_RECV          = DATAPATH_IO_SIGNATURE + 7,
    DATAPATH_IO_RIO_SEND          = DATAPATH_IO_SIGNATURE + 8,
    DATAPATH_IO_RECV_FAILURE      = DATAPATH_IO_SIGNATURE + 9,
    DATAPATH_IO_MAX
} DATAPATH_IO_TYPE;

//
// IO header for SQE->CQE based completions.
//
typedef struct DATAPATH_IO_SQE {
    DATAPATH_IO_TYPE IoType;
    DATAPATH_SQE DatapathSqe;
} DATAPATH_IO_SQE;

//
// Internal receive context.
//
typedef struct CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT {
    //
    // The owning datagram pool.
    //
    CXPLAT_POOL* OwningPool;

    //
    // The owning per-processor socket.
    //
    CXPLAT_SOCKET_PROC* SocketProc;

    //
    // The reference count of the receive buffer.
    //
    ULONG ReferenceCount;

    //
    // The RIO buffer ID, or RIO_INVALID_BUFFERID if not registered.
    //
    RIO_BUFFERID RioBufferId;

    //
    // Contains the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // The receive SQE.
    //
    DATAPATH_IO_SQE Sqe;

    //
    // Contains the control data resulting from the receive.
    //
    char ControlBuf[
        RIO_CMSG_BASE_SIZE +
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(DWORD)) +         // UDP_COALESCED_INFO
        WSA_CMSG_SPACE(sizeof(INT))             // IP_ECN
        ];

    //
    // Contains the input and output message data.
    //
    WSAMSG WsaMsgHdr;

} CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT;

//
// Internal receive context.
//
typedef struct CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT {

    //
    // The owning allocation.
    //
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext;

} CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT;

//
// Header prefixed to each RIO send buffer.
//
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) CXPLAT_RIO_SEND_BUFFER_HEADER {
    //
    // The IO type.
    //
    DATAPATH_IO_TYPE IoType;

    //
    // The RIO buffer ID.
    //
    RIO_BUFFERID RioBufferId;

    //
    // This send buffer's datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // This send buffer's send data.
    //
    CXPLAT_SEND_DATA* SendData;
} CXPLAT_RIO_SEND_BUFFER_HEADER;

//
// Send context.
//
typedef struct CXPLAT_SEND_DATA {
    //
    // The per-processor socket for this send data.
    //
    CXPLAT_SOCKET_PROC* SocketProc;

    //
    // The submission queue entry for the send completion.
    //
    DATAPATH_IO_SQE Sqe;

    //
    // The owning processor context.
    //
    CXPLAT_DATAPATH_PROC* Owner;

    //
    // The pool for this send data.
    //
    CXPLAT_POOL* SendDataPool;

    //
    // The pool for send buffers within this send data.
    //
    CXPLAT_POOL* BufferPool;

    //
    // The total buffer size for WsaBuffers.
    //
    uint32_t TotalSize;

    //
    // The send segmentation size; zero if segmentation is not performed.
    //
    uint16_t SegmentSize;

    //
    // The type of ECN markings needed for send.
    //
    uint8_t ECN; // CXPLAT_ECN_TYPE

    //
    // Set of flags set to configure the send behavior.
    //
    uint8_t SendFlags; // CXPLAT_SEND_FLAGS

    //
    // The current number of WsaBuffers used.
    //
    uint8_t WsaBufferCount;

    //
    // Contains all the datagram buffers to pass to the socket.
    //
    WSABUF WsaBuffers[CXPLAT_MAX_BATCH_SEND];

    //
    // The WSABUF returned to the client for segmented sends.
    //
    WSABUF ClientBuffer;

    //
    // The RIO buffer ID, or RIO_INVALID_BUFFERID if not registered.
    //
    RIO_BUFFERID RioBufferId;

    //
    // The RIO send overflow entry. Used when the RIO send RQ is full.
    //
    CXPLAT_LIST_ENTRY RioOverflowEntry;

    //
    // The buffer for send control data.
    //
    char CtrlBuf[
        RIO_CMSG_BASE_SIZE +
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(INT)) +           // IP_ECN
        WSA_CMSG_SPACE(sizeof(DWORD))           // UDP_SEND_MSG_SIZE
        ];

    //
    // The local address to bind to.
    //
    QUIC_ADDR LocalAddress;

    //
    // The V6-mapped remote address to send to.
    //
    QUIC_ADDR MappedRemoteAddress;
} CXPLAT_SEND_DATA;

//
// Per-processor socket state.
//
typedef struct QUIC_CACHEALIGN CXPLAT_SOCKET_PROC {
    //
    // Used to synchronize clean up.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Submission queue event for IO completion
    //
    DATAPATH_IO_SQE IoSqe;

    //
    // Submission queue event for RIO IO completion
    //
    DATAPATH_IO_SQE RioSqe;

    //
    // Submission queue event for shutdown
    //
    DATAPATH_SQE ShutdownSqe;

    //
    // The datapath per-processor context.
    //
    CXPLAT_DATAPATH_PROC* DatapathProc;

    //
    // Parent CXPLAT_SOCKET.
    //
    CXPLAT_SOCKET* Parent;

    //
    // Socket handle to the networking stack.
    //
    SOCKET Socket;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    CXPLAT_RUNDOWN_REF UpcallRundown;

    //
    // Flag indicates the socket started processing IO.
    //
    BOOLEAN IoStarted : 1;

    //
    // Flag indicates a persistent out-of-memory failure for the receive path.
    //
    BOOLEAN RecvFailure : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // The set of parameters/state passed to WsaRecvMsg for the IP stack to
    // populate to indicate the result of the receive.
    //

    union {
    //
    // Normal TCP/UDP socket data
    //
    struct {
    RIO_CQ RioCq;
    RIO_RQ RioRq;
    ULONG RioRecvCount;
    ULONG RioSendCount;
    CXPLAT_LIST_ENTRY RioSendOverflow;
    BOOLEAN RioNotifyArmed;
    };
    //
    // TCP Listener socket data
    //
    struct {
    CXPLAT_SOCKET* AcceptSocket;
    char AcceptAddrSpace[
        sizeof(SOCKADDR_INET) + 16 +
        sizeof(SOCKADDR_INET) + 16
        ];
    };
    };
} CXPLAT_SOCKET_PROC;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct CXPLAT_SOCKET {

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // Client context pointer.
    //
    void *ClientContext;

    //
    // The local address and port.
    //
    SOCKADDR_INET LocalAddress;

    //
    // The remote address and port.
    //
    SOCKADDR_INET RemoteAddress;

    //
    // Synchronization mechanism for cleanup.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The local interface's MTU.
    //
    uint16_t Mtu;

    //
    // The size of a receive buffer's payload.
    //
    uint32_t RecvBufLen;

    //
    // Socket type.
    //
    uint8_t Type : 2; // CXPLAT_SOCKET_TYPE

    //
    // Flag indicates the socket has a default remote destination.
    //
    uint8_t HasFixedRemoteAddress : 1;

    //
    // Flag indicates the socket indicated a disconnect event.
    //
    uint8_t DisconnectIndicated : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    uint8_t PcpBinding : 1;

    //
    // Flag indicates the socket is using RIO instead of traditional Winsock.
    //
    uint8_t UseRio : 1;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // Per-processor socket contexts.
    //
    CXPLAT_SOCKET_PROC Processors[0];

} CXPLAT_SOCKET;

//
// Represents a single IO completion port and thread for processing work that is
// completed on a single processor.
//
typedef struct QUIC_CACHEALIGN CXPLAT_DATAPATH_PROC {

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // Event queue used for processing work.
    //
    CXPLAT_EVENTQ* EventQ;

    //
    // Used to synchronize clean up.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The index of ideal processor for this datapath.
    //
    uint16_t IdealProcessor;

#if DEBUG
    uint8_t Uninitialized : 1;
#endif

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendDataPool;

    //
    // Pool of send contexts to be shared by all RIO sockets on this core.
    //
    CXPLAT_POOL RioSendDataPool;

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
    // Pool of send buffers to be shared by all RIO sockets on this core.
    //
    CXPLAT_POOL RioSendBufferPool;

    //
    // Pool of large segmented send buffers to be shared by all RIO sockets on
    // this core.
    //
    CXPLAT_POOL RioLargeSendBufferPool;

    //
    // Pool of receive datagram contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvDatagramPool;

    //
    // Pool of RIO receive datagram contexts and buffers to be shared by all
    // RIO sockets on this core.
    //
    CXPLAT_POOL RioRecvPool;

} CXPLAT_DATAPATH_PROC;

//
// Main structure for tracking all UDP abstractions.
//
typedef struct CXPLAT_DATAPATH {

    //
    // The UDP callback function pointers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    // The TCP callback function pointers.
    //
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpHandlers;

    //
    // Function pointer to AcceptEx.
    //
    LPFN_ACCEPTEX AcceptEx;

    //
    // Function pointer to ConnectEx.
    //
    LPFN_CONNECTEX ConnectEx;

    //
    // Function pointer to WSASendMsg.
    //
    LPFN_WSASENDMSG WSASendMsg;

    //
    // Function pointer to WSARecvMsg.
    //
    LPFN_WSARECVMSG WSARecvMsg;

    //
    // Function pointer table for RIO.
    //
    RIO_EXTENSION_FUNCTION_TABLE RioDispatch;

    //
    // Used to synchronize clean up.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // The size of each receive datagram array element, including client context,
    // internal context, and padding.
    //
    uint32_t DatagramStride;

    //
    // The offset of the receive payload buffer from the start of the receive
    // context.
    //
    uint32_t RecvPayloadOffset;

    //
    // The number of processors.
    //
    uint16_t ProcCount;

    //
    // Maximum batch sizes supported for send.
    //
    uint8_t MaxSendBatchSize;

#if DEBUG
    uint8_t Uninitialized : 1;
    uint8_t Freed : 1;
#endif

    //
    // Per-processor completion contexts.
    //
    CXPLAT_DATAPATH_PROC Processors[0];

} CXPLAT_DATAPATH;

#ifdef DEBUG
#ifndef AllocOffset
#define AllocOffset (sizeof(void*) * 2)
#endif
#endif

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
void*
CxPlatLargeAlloc(
    _In_ size_t ByteCount,
    _In_ uint32_t Tag
    )
{
#ifdef DEBUG
    uint32_t Rand;
    if ((CxPlatform.AllocFailDenominator > 0 && (CxPlatRandom(sizeof(Rand), &Rand), Rand % CxPlatform.AllocFailDenominator) == 1) ||
        (CxPlatform.AllocFailDenominator < 0 && InterlockedIncrement(&CxPlatform.AllocCounter) % CxPlatform.AllocFailDenominator == 0)) {
        return NULL;
    }

    void* Alloc =
        VirtualAlloc(NULL, ByteCount + AllocOffset, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Alloc == NULL) {
        return NULL;
    }
    *((uint32_t*)Alloc) = Tag;
    return (void*)((uint8_t*)Alloc + AllocOffset);
#else
    UNREFERENCED_PARAMETER(Tag);
    return VirtualAlloc(NULL, ByteCount, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
}

void
CxPlatLargeFree(
    __drv_freesMem(Mem) _Frees_ptr_ void* Mem,
    _In_ uint32_t Tag
    )
{
#ifdef DEBUG
    void* ActualAlloc = (void*)((uint8_t*)Mem - AllocOffset);
    if (Mem != NULL) {
        uint32_t TagToCheck = *((uint32_t*)ActualAlloc);
        CXPLAT_DBG_ASSERT(TagToCheck == Tag);
    } else {
        ActualAlloc = NULL;
    }
    (void)VirtualFree(ActualAlloc, 0, MEM_RELEASE);
#else
    UNREFERENCED_PARAMETER(Tag);
    (void)VirtualFree(Mem, 0, MEM_RELEASE);
#endif
}

VOID
CxPlatStartDatapathIo(
    _Inout_ DATAPATH_IO_SQE* Sqe,
    _In_ DATAPATH_IO_TYPE IoType
    )
{
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.CqeType == CXPLAT_CQE_TYPE_SOCKET_IO);
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.Sqe.UserData == &Sqe->DatapathSqe);
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.Sqe.Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_DBG_ASSERT(Sqe->IoType == 0);

    Sqe->IoType = IoType;
    CxPlatZeroMemory(&Sqe->DatapathSqe.Sqe.Overlapped, sizeof(Sqe->DatapathSqe.Sqe.Overlapped));
}

VOID
CxPlatStopDatapathIo(
    _Inout_ DATAPATH_IO_SQE* Sqe
    )
{
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.CqeType == CXPLAT_CQE_TYPE_SOCKET_IO);
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.Sqe.UserData == &Sqe->DatapathSqe);
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.Sqe.Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_DBG_ASSERT(Sqe->IoType > DATAPATH_IO_SIGNATURE && Sqe->IoType < DATAPATH_IO_MAX);
    DBG_UNREFERENCED_PARAMETER(Sqe);
#if DEBUG
    Sqe->IoType = 0;
#endif
}

VOID
CxPlatStopInlineDatapathIo(
    _Inout_ DATAPATH_IO_SQE* Sqe
    )
{
    //
    // We want to assert the overlapped result is not pending below, but Winsock
    // and the Windows kernel may leave the overlapped struct in the pending
    // state if an IO completes inline. Ignore the overlapped result in this
    // case.
    //
    Sqe->DatapathSqe.Sqe.Overlapped.Internal = 0;
    CxPlatStopDatapathIo(Sqe);
}

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)
        (((PUCHAR)Context) -
            sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) -
            sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)
        (((PUCHAR)Datagram) +
            sizeof(CXPLAT_RECV_DATA) +
            sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT));
}

CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*
CxPlatDataPathDatagramToInternalDatagramContext(
    _In_ CXPLAT_RECV_DATA* Datagram
    )
{
    return (CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*)
        (((PUCHAR)Datagram) + sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_DATAPATH_PROC*
CxPlatDataPathGetProc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Processor
    )
{
    for (uint16_t i = 0; i < Datapath->ProcCount; ++i) {
        if (Datapath->Processors[i].IdealProcessor == Processor) {
            return &Datapath->Processors[i];
        }
    }
    CXPLAT_FRE_ASSERT(FALSE); // TODO - What now?!
    return NULL;
}

_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
CxPlatSocketStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Out_opt_ ULONG* SyncIoResult,
    _Out_opt_ uint16_t* SyncBytesReceived,
    _Out_opt_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT** SyncRecvContext
    );

void
CxPlatDataPathStartReceiveAsync(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
);

QUIC_STATUS
CxPlatSocketStartAccept(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

void*
RioRecvBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void
RioRecvBufferFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void*
RioSendDataAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void
RioSendDataFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void*
RioSendBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void*
RioSendLargeBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void
RioSendBufferFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void
CxPlatDataPathStartRioSends(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

void
CxPlatSendDataComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ ULONG IoResult
    );

BOOLEAN
CxPlatDataPathRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext,
    _In_ ULONG IoResult,
    _In_ uint16_t BytesTransferred
    );

void
CxPlatFreeRecvContext(
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext
    );

void
CxPlatDataPathQueryRssScalabilityInfo(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    int Result;
    DWORD BytesReturned;
    RSS_SCALABILITY_INFO RssInfo = { 0 };

    SOCKET RssSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (RssSocket == INVALID_SOCKET) {
        int WsaError = WSAGetLastError();
        QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[data] RSS helper socket failed to open, 0x%x",
            WsaError);
        goto Error;
    }

    Result =
        WSAIoctl(
            RssSocket,
            SIO_QUERY_RSS_SCALABILITY_INFO,
            NULL,
            0,
            &RssInfo,
            sizeof(RssInfo),
            &BytesReturned,
            NULL,
            NULL);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceLogWarning(
            DatapathQueryRssProcessorInfoFailed,
            "[data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            WsaError);
        goto Error;
    }

    if (RssInfo.RssEnabled) {
        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING;
    }

Error:

    if (RssSocket != INVALID_SOCKET) {
        closesocket(RssSocket);
    }
}

QUIC_STATUS
CxPlatDataPathQuerySockoptSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    int Result;
    int OptionLength;
    DWORD BytesReturned;
    GUID AcceptExGuid = WSAID_ACCEPTEX;
    GUID ConnectExGuid = WSAID_CONNECTEX;
    GUID WSASendMsgGuid = WSAID_WSASENDMSG;
    GUID WSARecvMsgGuid = WSAID_WSARECVMSG;
    GUID RioGuid = WSAID_MULTIPLE_RIO;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    SOCKET UdpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (UdpSocket == INVALID_SOCKET) {
        int WsaError = WSAGetLastError();
        QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[data] UDP send segmentation helper socket failed to open, 0x%x",
            WsaError);
        goto Error;
    }

    Result =
        WSAIoctl(
            UdpSocket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &AcceptExGuid,
            sizeof(AcceptExGuid),
            &Datapath->AcceptEx,
            sizeof(Datapath->AcceptEx),
            &BytesReturned,
            NULL,
            NULL);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "SIO_GET_EXTENSION_FUNCTION_POINTER (AcceptEx)");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Result =
        WSAIoctl(
            UdpSocket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &ConnectExGuid,
            sizeof(ConnectExGuid),
            &Datapath->ConnectEx,
            sizeof(Datapath->ConnectEx),
            &BytesReturned,
            NULL,
            NULL);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "SIO_GET_EXTENSION_FUNCTION_POINTER (ConnectEx)");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Result =
        WSAIoctl(
            UdpSocket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSASendMsgGuid,
            sizeof(WSASendMsgGuid),
            &Datapath->WSASendMsg,
            sizeof(Datapath->WSASendMsg),
            &BytesReturned,
            NULL,
            NULL);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "SIO_GET_EXTENSION_FUNCTION_POINTER (WSASendMsg)");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Result =
        WSAIoctl(
            UdpSocket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSARecvMsgGuid,
            sizeof(WSARecvMsgGuid),
            &Datapath->WSARecvMsg,
            sizeof(Datapath->WSARecvMsg),
            &BytesReturned,
            NULL,
            NULL);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "SIO_GET_EXTENSION_FUNCTION_POINTER (WSARecvMsg)");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Result =
        WSAIoctl(
            UdpSocket,
            SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
            &RioGuid,
            sizeof(RioGuid),
            &Datapath->RioDispatch,
            sizeof(Datapath->RioDispatch),
            &BytesReturned,
            NULL,
            NULL);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER (RIO)");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

#ifdef QUIC_FUZZER
    MsQuicFuzzerContext.RealSendMsg = (PVOID)Datapath->WSASendMsg;
    MsQuicFuzzerContext.RealRecvMsg = (PVOID)Datapath->WSARecvMsg;
    Datapath->WSASendMsg = QuicFuzzerSendMsg;
    Datapath->WSARecvMsg = QuicFuzzerRecvMsg;
#endif

{
    DWORD SegmentSize;
    OptionLength = sizeof(SegmentSize);
    Result =
        getsockopt(
            UdpSocket,
            IPPROTO_UDP,
            UDP_SEND_MSG_SIZE,
            (char*)&SegmentSize,
            &OptionLength);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceLogWarning(
            DatapathQueryUdpSendMsgFailed,
            "[data] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
            WsaError);
    } else {
        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;
    }
}

{
    DWORD UroMaxCoalescedMsgSize = TRUE;
    OptionLength = sizeof(UroMaxCoalescedMsgSize);
    Result =
        getsockopt(
            UdpSocket,
            IPPROTO_UDP,
            UDP_RECV_MAX_COALESCED_SIZE,
            (char*)&UroMaxCoalescedMsgSize,
            &OptionLength);
    if (Result != NO_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceLogWarning(
            DatapathQueryRecvMaxCoalescedSizeFailed,
            "[data] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
            WsaError);
    } else {
        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_COALESCING;
    }
}

Error:

    if (UdpSocket != INVALID_SOCKET) {
        closesocket(UdpSocket);
    }

    return Status;
}

//
// To determine the OS version, we are going to use RtlGetVersion API
// since GetVersion call can be shimmed on Win8.1+.
//
typedef LONG (WINAPI *FuncRtlGetVersion)(RTL_OSVERSIONINFOW *);

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
    int WsaError;
    QUIC_STATUS Status;
    WSADATA WsaData;
    const uint16_t* ProcessorList;
    uint32_t ProcessorCount;
    uint32_t DatapathLength;
    CXPLAT_DATAPATH* Datapath = NULL;
    BOOLEAN WsaInitialized = FALSE;

    if (NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }
    if (TcpCallbacks != NULL) {
        if (TcpCallbacks->Accept == NULL ||
            TcpCallbacks->Connect == NULL ||
            TcpCallbacks->Receive == NULL ||
            TcpCallbacks->SendComplete == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }
    }

    if (!CxPlatWorkersLazyStart(Config)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    if ((WsaError = WSAStartup(MAKEWORD(2, 2), &WsaData)) != 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "WSAStartup");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Exit;
    }
    WsaInitialized = TRUE;

    if (Config && Config->ProcessorCount) {
        ProcessorCount = Config->ProcessorCount;
        ProcessorList = Config->ProcessorList;
    } else {
        ProcessorCount = CxPlatProcMaxCount();
        ProcessorList = NULL;
    }

    DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        ProcessorCount * sizeof(CXPLAT_DATAPATH_PROC);

    Datapath = (CXPLAT_DATAPATH*)CXPLAT_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    RtlZeroMemory(Datapath, DatapathLength);
    if (UdpCallbacks) {
        Datapath->UdpHandlers = *UdpCallbacks;
    }
    if (TcpCallbacks) {
        Datapath->TcpHandlers = *TcpCallbacks;
    }
    Datapath->ProcCount = (uint16_t)ProcessorCount;
    CxPlatRefInitializeEx(&Datapath->RefCount, Datapath->ProcCount);

    CxPlatDataPathQueryRssScalabilityInfo(Datapath);
    Status = CxPlatDataPathQuerySockoptSupport(Datapath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Check for port reservation support.
    //
#ifndef QUIC_UWP_BUILD
    HMODULE NtDllHandle = LoadLibraryA("ntdll.dll");
    if (NtDllHandle) {
        FuncRtlGetVersion VersionFunc = (FuncRtlGetVersion)GetProcAddress(NtDllHandle, "RtlGetVersion");
        if (VersionFunc) {
            RTL_OSVERSIONINFOW VersionInfo = {0};
            VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
            if ((*VersionFunc)(&VersionInfo) == 0) {
                //
                // Only RS5 and newer can use the port reservation feature safely.
                //
                if (VersionInfo.dwBuildNumber >= 17763) {
                    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS;
                }
            }
        }
        FreeLibrary(NtDllHandle);
    }
#endif

    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        //
        // UDP send batching is actually supported on even earlier Windows
        // versions than USO, but we have no good way to dynamically query
        // support level. So we just couple the two features' support level
        // together, since send batching is guaranteed to be supported if USO
        // is.
        //
        Datapath->MaxSendBatchSize = CXPLAT_MAX_BATCH_SEND;
    } else {
        Datapath->MaxSendBatchSize = 1;
    }

    const uint32_t MessageCount =
        (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING)
            ? URO_MAX_DATAGRAMS_PER_INDICATION : 1;

    Datapath->DatagramStride =
        ALIGN_UP(
            sizeof(CXPLAT_RECV_DATA) +
            sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) +
            ClientRecvContextLength,
            PVOID);
    Datapath->RecvPayloadOffset =
        sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT) +
        MessageCount * Datapath->DatagramStride;

    const uint32_t RecvDatagramLength =
        Datapath->RecvPayloadOffset +
            ((Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
                MAX_URO_PAYLOAD_LENGTH : MAX_RECV_PAYLOAD_LENGTH);

    for (uint16_t i = 0; i < Datapath->ProcCount; i++) {

        Datapath->Processors[i].Datapath = Datapath;
        Datapath->Processors[i].IdealProcessor =
            ProcessorList ? ProcessorList[i] : (uint16_t)i;
        Datapath->Processors[i].EventQ =
            CxPlatWorkerGetEventQ(Datapath->Processors[i].IdealProcessor);
        CxPlatRefInitialize(&Datapath->Processors[i].RefCount);

        CxPlatPoolInitialize(
            FALSE,
            sizeof(CXPLAT_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            &Datapath->Processors[i].SendDataPool);

        CxPlatPoolInitializeEx(
            FALSE,
            sizeof(CXPLAT_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            0,
            RioSendDataAllocate,
            RioSendDataFree,
            &Datapath->Processors[i].RioSendDataPool);

        CxPlatPoolInitialize(
            FALSE,
            MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            &Datapath->Processors[i].SendBufferPool);

        CxPlatPoolInitialize(
            FALSE,
            CXPLAT_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            &Datapath->Processors[i].LargeSendBufferPool);

        CxPlatPoolInitializeEx(
            FALSE,
            MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            RIO_MAX_SEND_POOL_SIZE,
            RioSendBufferAllocate,
            RioSendBufferFree,
            &Datapath->Processors[i].RioSendBufferPool);

        CxPlatPoolInitializeEx(
            FALSE,
            CXPLAT_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            RIO_MAX_SEND_POOL_SIZE,
            RioSendLargeBufferAllocate,
            RioSendBufferFree,
            &Datapath->Processors[i].RioLargeSendBufferPool);

        CxPlatPoolInitialize(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->Processors[i].RecvDatagramPool);

        CxPlatPoolInitializeEx(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            RIO_MAX_RECV_POOL_SIZE,
            RioRecvBufferAllocate,
            RioRecvBufferFree,
            &Datapath->Processors[i].RioRecvPool);
    }

    CXPLAT_FRE_ASSERT(CxPlatRundownAcquire(&CxPlatWorkerRundown));
    *NewDataPath = Datapath;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Datapath != NULL) {
            CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
        }
        if (WsaInitialized) {
            (void)WSACleanup();
        }
    }

Exit:

    return Status;
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
        WSACleanup();
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
        CxPlatPoolUninitialize(&DatapathProc->SendDataPool);
        CxPlatPoolUninitialize(&DatapathProc->RioSendDataPool);
        CxPlatPoolUninitialize(&DatapathProc->SendBufferPool);
        CxPlatPoolUninitialize(&DatapathProc->LargeSendBufferPool);
        CxPlatPoolUninitialize(&DatapathProc->RioSendBufferPool);
        CxPlatPoolUninitialize(&DatapathProc->RioLargeSendBufferPool);
        CxPlatPoolUninitialize(&DatapathProc->RecvDatagramPool);
        CxPlatPoolUninitialize(&DatapathProc->RioRecvPool);
        CxPlatDataPathRelease(DatapathProc->Datapath);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
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
        for (uint16_t i = 0; i < ProcCount; i++) {
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

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
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
    const ULONG Flags =
        GAA_FLAG_INCLUDE_ALL_INTERFACES |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME |
        GAA_FLAG_SKIP_DNS_INFO;

    UNREFERENCED_PARAMETER(Datapath);

    ULONG AdapterAddressesSize = 0;
    PIP_ADAPTER_ADDRESSES AdapterAddresses = NULL;
    uint32_t Index = 0;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ULONG Error;
    do {
        Error =
            GetAdaptersAddresses(
                AF_UNSPEC,
                Flags,
                NULL,
                AdapterAddresses,
                &AdapterAddressesSize);
        if (Error == ERROR_BUFFER_OVERFLOW) {
            if (AdapterAddresses) {
                CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
            }
            AdapterAddresses = CXPLAT_ALLOC_NONPAGED(AdapterAddressesSize, QUIC_POOL_DATAPATH_ADDRESSES);
            if (!AdapterAddresses) {
                Error = ERROR_NOT_ENOUGH_MEMORY;
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "PIP_ADAPTER_ADDRESSES",
                    AdapterAddressesSize);
            }
        }
    } while (Error == ERROR_BUFFER_OVERFLOW);

    if (Error != ERROR_SUCCESS) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GetAdaptersAddresses");
        Status = HRESULT_FROM_WIN32(Error);
        goto Exit;
    }

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS_LH Iter2 = Iter->FirstUnicastAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            Index++;
        }
    }

    if (Index == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No local unicast addresses found");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    *Addresses = CXPLAT_ALLOC_NONPAGED(Index * sizeof(CXPLAT_ADAPTER_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
    if (*Addresses == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Addresses",
            Index * sizeof(CXPLAT_ADAPTER_ADDRESS));
        goto Exit;
    }

    CxPlatZeroMemory(*Addresses, Index * sizeof(CXPLAT_ADAPTER_ADDRESS));
    *AddressesCount = Index;
    Index = 0;

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS_LH Iter2 = Iter->FirstUnicastAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            CxPlatCopyMemory(
                &(*Addresses)[Index].Address,
                Iter2->Address.lpSockaddr,
                sizeof(QUIC_ADDR));
            (*Addresses)[Index].InterfaceIndex =
                Iter2->Address.lpSockaddr->sa_family == AF_INET ?
                    (uint32_t)Iter->IfIndex : (uint32_t)Iter->Ipv6IfIndex;
            (*Addresses)[Index].InterfaceType = (uint16_t)Iter->IfType;
            (*Addresses)[Index].OperationStatus = (CXPLAT_OPERATION_STATUS)Iter->OperStatus;
            Index++;
        }
    }

Exit:

    if (AdapterAddresses) {
        CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
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
    const ULONG Flags =
        GAA_FLAG_INCLUDE_GATEWAYS |
        GAA_FLAG_INCLUDE_ALL_INTERFACES |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_MULTICAST;

    UNREFERENCED_PARAMETER(Datapath);

    ULONG AdapterAddressesSize = 0;
    PIP_ADAPTER_ADDRESSES AdapterAddresses = NULL;
    uint32_t Index = 0;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ULONG Error;
    do {
        Error =
            GetAdaptersAddresses(
                AF_UNSPEC,
                Flags,
                NULL,
                AdapterAddresses,
                &AdapterAddressesSize);
        if (Error == ERROR_BUFFER_OVERFLOW) {
            if (AdapterAddresses) {
                CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
            }
            AdapterAddresses = CXPLAT_ALLOC_NONPAGED(AdapterAddressesSize, QUIC_POOL_DATAPATH_ADDRESSES);
            if (!AdapterAddresses) {
                Error = ERROR_NOT_ENOUGH_MEMORY;
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "PIP_ADAPTER_ADDRESSES",
                    AdapterAddressesSize);
            }
        }
    } while (Error == ERROR_BUFFER_OVERFLOW);

    if (Error != ERROR_SUCCESS) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GetAdaptersAddresses");
        Status = HRESULT_FROM_WIN32(Error);
        goto Exit;
    }

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_GATEWAY_ADDRESS_LH Iter2 = Iter->FirstGatewayAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            Index++;
        }
    }

    if (Index == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No gateway server addresses found");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    *GatewayAddresses = CXPLAT_ALLOC_NONPAGED(Index * sizeof(QUIC_ADDR), QUIC_POOL_DATAPATH_ADDRESSES);
    if (*GatewayAddresses == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "GatewayAddresses",
            Index * sizeof(QUIC_ADDR));
        goto Exit;
    }

    CxPlatZeroMemory(*GatewayAddresses, Index * sizeof(QUIC_ADDR));
    *GatewayAddressesCount = Index;
    Index = 0;

    for (PIP_ADAPTER_ADDRESSES Iter = AdapterAddresses; Iter != NULL; Iter = Iter->Next) {
        for (PIP_ADAPTER_GATEWAY_ADDRESS_LH Iter2 = Iter->FirstGatewayAddress; Iter2 != NULL; Iter2 = Iter2->Next) {
            CxPlatCopyMemory(
                &(*GatewayAddresses)[Index],
                Iter2->Address.lpSockaddr,
                sizeof(QUIC_ADDR));
            Index++;
        }
    }

Exit:

    if (AdapterAddresses) {
        CXPLAT_FREE(AdapterAddresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return Status;
}

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

void
CxPlatSocketArmRioNotify(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    if (!SocketProc->RioNotifyArmed) {
        SocketProc->RioNotifyArmed = TRUE;
        CxPlatRefIncrement(&SocketProc->RefCount);
        CxPlatStartDatapathIo(&SocketProc->RioSqe, DATAPATH_IO_RIO_NOTIFY);
        ULONG NotifyResult = SocketProc->DatapathProc->Datapath->
            RioDispatch.RIONotify(SocketProc->RioCq);
        CXPLAT_TEL_ASSERT(NotifyResult == ERROR_SUCCESS);
        DBG_UNREFERENCED_LOCAL_VARIABLE(NotifyResult);
    }
}

QUIC_STATUS
CxPlatSocketEnqueueSqe(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ uint32_t NumBytes
    )
{
    CXPLAT_DBG_ASSERT(!SocketProc->Uninitialized);
    CXPLAT_DBG_ASSERT(!SocketProc->Freed);
    if (!CxPlatEventQEnqueueEx(
            SocketProc->DatapathProc->EventQ,
            &Sqe->DatapathSqe.Sqe,
            NumBytes,
            &Sqe->DatapathSqe)) {
        const DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            LastError,
            "CxPlatSocketEnqueueSqe");
        return HRESULT_FROM_WIN32(LastError);
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status;
    int Result;
    int Option;
    BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;
    uint16_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;
    INET_PORT_RESERVATION_INSTANCE PortReservation;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & CXPLAT_SOCKET_FLAG_PCP);

    uint32_t SocketLength =
        sizeof(CXPLAT_SOCKET) + SocketCount * sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET* Socket = CXPLAT_ALLOC_PAGED(SocketLength, QUIC_POOL_SOCKET);
    if (Socket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            SocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = Config->CallbackContext;
    Socket->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    Socket->Type = CXPLAT_SOCKET_UDP;
    Socket->UseRio = FALSE;
    if (Config->LocalAddress) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    if (Config->Flags & CXPLAT_SOCKET_FLAG_PCP) {
        Socket->PcpBinding = TRUE;
    }
    CxPlatRefInitializeEx(&Socket->RefCount, SocketCount);

    Socket->RecvBufLen =
        (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
            MAX_URO_PAYLOAD_LENGTH :
            Socket->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;

    for (uint16_t i = 0; i < SocketCount; i++) {
        CxPlatRefInitialize(&Socket->Processors[i].RefCount);
        Socket->Processors[i].Parent = Socket;
        Socket->Processors[i].DatapathProc = NULL;
        Socket->Processors[i].Socket = INVALID_SOCKET;
        Socket->Processors[i].IoStarted = FALSE;
        Socket->Processors[i].ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        CxPlatDatapathSqeInitialize(
            &Socket->Processors[i].IoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        CxPlatRundownInitialize(&Socket->Processors[i].UpcallRundown);
        Socket->Processors[i].RioCq = RIO_INVALID_CQ;
        Socket->Processors[i].RioRq = RIO_INVALID_RQ;
        CxPlatListInitializeHead(&Socket->Processors[i].RioSendOverflow);
    }

    for (uint16_t i = 0; i < SocketCount; i++) {

        CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[i];
        uint16_t AffinitizedProcessor = (uint16_t)i;
        DWORD SocketFlags = WSA_FLAG_OVERLAPPED;
        DWORD BytesReturned;

        if (Socket->UseRio) {
            SocketFlags |= WSA_FLAG_REGISTERED_IO;
        }

        SocketProc->Socket =
            WSASocketW(
                AF_INET6,
                SOCK_DGRAM,
                IPPROTO_UDP,
                NULL,
                0,
                SocketFlags);
        if (SocketProc->Socket == INVALID_SOCKET) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "WSASocketW");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

#ifdef QUIC_FUZZER
        MsQuicFuzzerContext.Socket = SocketProc->Socket;
#endif

        Option = FALSE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_V6ONLY");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        if (Config->RemoteAddress == NULL) {
            uint16_t Processor = i; // API only supports 16-bit proc index.
            Result =
                WSAIoctl(
                    SocketProc->Socket,
                    SIO_CPU_AFFINITY,
                    &Processor,
                    sizeof(Processor),
                    NULL,
                    0,
                    &BytesReturned,
                    NULL,
                    NULL);
            if (Result != NO_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "SIO_CPU_AFFINITY");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IP,
                IP_DONTFRAGMENT,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IP_DONTFRAGMENT");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IPV6,
                IPV6_DONTFRAG,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_DONTFRAG");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_PKTINFO");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IP,
                IP_PKTINFO,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IP_PKTINFO");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IPV6,
                IPV6_ECN,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_ECN");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        Option = TRUE;
        Result =
            setsockopt(
                SocketProc->Socket,
                IPPROTO_IP,
                IP_ECN,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IP_ECN");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        //
        // The socket is shared by multiple endpoints, so increase the receive
        // buffer size.
        //
        Option = MAXINT32;
        Result =
            setsockopt(
                SocketProc->Socket,
                SOL_SOCKET,
                SO_RCVBUF,
                (char*)&Option,
                sizeof(Option));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set SO_RCVBUF");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
            Option = MAX_URO_PAYLOAD_LENGTH;
            Result =
                setsockopt(
                    SocketProc->Socket,
                    IPPROTO_UDP,
                    UDP_RECV_MAX_COALESCED_SIZE,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set UDP_RECV_MAX_COALESCED_SIZE");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }

        //
        // Disable automatic IO completions being queued if the call completes
        // synchronously. This is because we want to be able to complete sends
        // inline, if possible.
        //
        if (!SetFileCompletionNotificationModes(
                (HANDLE)SocketProc->Socket,
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                LastError,
                "SetFileCompletionNotificationModes");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

        if (Config->RemoteAddress != NULL) {
            AffinitizedProcessor =
                ((uint16_t)CxPlatProcCurrentNumber()) % Datapath->ProcCount;
        }

QUIC_DISABLED_BY_FUZZER_START;

        SocketProc->DatapathProc =
            CxPlatDataPathGetProc(Datapath, AffinitizedProcessor);
        CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

        if (!CxPlatEventQAssociateHandle(
                SocketProc->DatapathProc->EventQ,
                (HANDLE)SocketProc->Socket)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                LastError,
                "CreateIoCompletionPort");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

        if (Socket->UseRio) {
            RIO_NOTIFICATION_COMPLETION NotificationCompletion = {0};
            NotificationCompletion.Type = RIO_IOCP_COMPLETION;
            NotificationCompletion.Iocp.IocpHandle =
                *SocketProc->DatapathProc->EventQ;
            NotificationCompletion.Iocp.Overlapped =
                &SocketProc->RioSqe.DatapathSqe.Sqe.Overlapped;

            CxPlatDatapathSqeInitialize(
                &SocketProc->RioSqe.DatapathSqe,
                CXPLAT_CQE_TYPE_SOCKET_IO);

            SocketProc->RioCq =
                Datapath->RioDispatch.RIOCreateCompletionQueue(
                    RIO_RECV_QUEUE_DEPTH + RIO_SEND_QUEUE_DEPTH,
                    &NotificationCompletion);
            if (SocketProc->RioCq == RIO_INVALID_CQ) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "RIOCreateCompletionQueue");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

            #pragma warning(suppress:6387) // _Param_(8)' could be '0' - by design.
            SocketProc->RioRq =
                Datapath->RioDispatch.RIOCreateRequestQueue(
                    SocketProc->Socket, RIO_RECV_QUEUE_DEPTH, 1,
                    RIO_SEND_QUEUE_DEPTH, 1, SocketProc->RioCq,
                    SocketProc->RioCq, NULL);
            if (SocketProc->RioRq == RIO_INVALID_RQ) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "RIOCreateRequestQueue");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }

        if (Config->InterfaceIndex != 0) {
            Option = (int)Config->InterfaceIndex;
            Result =
                setsockopt(
                    SocketProc->Socket,
                    IPPROTO_IPV6,
                    IPV6_UNICAST_IF,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set IPV6_UNICAST_IF");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
            Option = (int)htonl(Config->InterfaceIndex);
            Result =
                setsockopt(
                    SocketProc->Socket,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (char*)&Option,
                    sizeof(Option));
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set IP_UNICAST_IF");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }

        if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_PORT_RESERVATIONS &&
            Config->LocalAddress &&
            Config->LocalAddress->Ipv4.sin_port != 0) {
            if (i == 0) {
                //
                // Create a port reservation for the local port.
                //
                INET_PORT_RANGE PortRange;
                PortRange.StartPort = Config->LocalAddress->Ipv4.sin_port;
                PortRange.NumberOfPorts = 1;

                Result =
                    WSAIoctl(
                        SocketProc->Socket,
                        SIO_ACQUIRE_PORT_RESERVATION,
                        &PortRange,
                        sizeof(PortRange),
                        &PortReservation,
                        sizeof(PortReservation),
                        &BytesReturned,
                        NULL,
                        NULL);
                if (Result == SOCKET_ERROR) {
                    int WsaError = WSAGetLastError();
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "SIO_ACQUIRE_PORT_RESERVATION");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Error;
                }
            }

            //
            // Associate the port reservation with the socket.
            //
            Result =
                WSAIoctl(
                    SocketProc->Socket,
                    SIO_ASSOCIATE_PORT_RESERVATION,
                    &PortReservation.Token,
                    sizeof(PortReservation.Token),
                    NULL,
                    0,
                    &BytesReturned,
                    NULL,
                    NULL);
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "SIO_ASSOCIATE_PORT_RESERVATION");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }

        Result =
            bind(
                SocketProc->Socket,
                (PSOCKADDR)&Socket->LocalAddress,
                sizeof(Socket->LocalAddress));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "bind");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        if (Config->RemoteAddress != NULL) {
            SOCKADDR_INET MappedRemoteAddress = { 0 };
            CxPlatConvertToMappedV6(Config->RemoteAddress, &MappedRemoteAddress);

            Result =
                connect(
                    SocketProc->Socket,
                    (PSOCKADDR)&MappedRemoteAddress,
                    sizeof(MappedRemoteAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "connect");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }

        if (i == 0) {

            //
            // If no specific local port was indicated, then the stack just
            // assigned this socket a port. We need to query it and use it for
            // all the other sockets we are going to create.
            //

            int AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
            Result =
                getsockname(
                    SocketProc->Socket,
                    (PSOCKADDR)&Socket->LocalAddress,
                    &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "getsockaddress");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

            if (Config->LocalAddress && Config->LocalAddress->Ipv4.sin_port != 0) {
                CXPLAT_DBG_ASSERT(Config->LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
            }
        }

QUIC_DISABLED_BY_FUZZER_END;
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    if (Config->RemoteAddress != NULL) {
        Socket->RemoteAddress = *Config->RemoteAddress;
    } else {
        Socket->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewSocket = Socket;

    for (uint16_t i = 0; i < SocketCount; i++) {
        CxPlatDataPathStartReceiveAsync(&Socket->Processors[i]);
        Socket->Processors[i].IoStarted = TRUE;
    }

    Status = QUIC_STATUS_SUCCESS;
    Socket = NULL;

Error:

    if (Socket != NULL) {
        CxPlatSocketDelete(Socket);
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
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status;
    int Result;
    int Option;
    DWORD BytesReturned;
    uint16_t AffinitizedProcessor;

    CXPLAT_DBG_ASSERT(Datapath->TcpHandlers.Receive != NULL);

    CXPLAT_SOCKET_PROC* SocketProc = NULL;
    uint32_t SocketLength = sizeof(CXPLAT_SOCKET) + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET* Socket = CXPLAT_ALLOC_PAGED(SocketLength, QUIC_POOL_SOCKET);
    if (Socket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            SocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = TRUE;
    Socket->Type = Type;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    AffinitizedProcessor = RemoteAddress ?
        (((uint16_t)CxPlatProcCurrentNumber()) % Datapath->ProcCount) : 0;
    Socket->Mtu = CXPLAT_MAX_MTU;
    Socket->RecvBufLen =
        (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
            MAX_URO_PAYLOAD_LENGTH : MAX_RECV_PAYLOAD_LENGTH;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);

    SocketProc = &Socket->Processors[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    SocketProc->ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
    CxPlatDatapathSqeInitialize(&SocketProc->IoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatRundownInitialize(&SocketProc->UpcallRundown);
    SocketProc->RioCq = RIO_INVALID_CQ;
    SocketProc->RioRq = RIO_INVALID_RQ;
    CxPlatListInitializeHead(&SocketProc->RioSendOverflow);

    SocketProc->Socket =
        WSASocketW(
            AF_INET6,
            SOCK_STREAM,
            IPPROTO_TCP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
    if (SocketProc->Socket == INVALID_SOCKET) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "WSASocketW");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Option = FALSE;
    Result =
        setsockopt(
            SocketProc->Socket,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (char*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "Set IPV6_V6ONLY");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
            (HANDLE)SocketProc->Socket,
            FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "SetFileCompletionNotificationModes");
        Status = HRESULT_FROM_WIN32(LastError);
        goto Error;
    }

    if (Type != CXPLAT_SOCKET_TCP_SERVER) {

        SocketProc->DatapathProc =
            CxPlatDataPathGetProc(Datapath, AffinitizedProcessor);
        CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

        if (!CxPlatEventQAssociateHandle(
                SocketProc->DatapathProc->EventQ,
                (HANDLE)SocketProc->Socket)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                LastError,
                "CreateIoCompletionPort");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

        Result =
            bind(
                SocketProc->Socket,
                (PSOCKADDR)&Socket->LocalAddress,
                sizeof(Socket->LocalAddress));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "bind");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        if (RemoteAddress != NULL) {
            SOCKADDR_INET MappedRemoteAddress = { 0 };
            CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

            CxPlatStartDatapathIo(&SocketProc->IoSqe, DATAPATH_IO_CONNECTEX);

            Result =
                Datapath->ConnectEx(
                    SocketProc->Socket,
                    (PSOCKADDR)&MappedRemoteAddress,
                    sizeof(MappedRemoteAddress),
                    NULL,
                    0,
                    &BytesReturned,
                    &SocketProc->IoSqe.DatapathSqe.Sqe.Overlapped);
            if (Result == FALSE) {
                int WsaError = WSAGetLastError();
                if (WsaError != WSA_IO_PENDING) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "ConnectEx");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Error;
                }
            } else {
                //
                // Manually post IO completion if connect completed synchronously.
                //
                Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesReturned);
                if (QUIC_FAILED(Status)) {
                    goto Error;
                }
            }

            SocketProc->IoStarted = TRUE;
        }

        //
        // If no specific local port was indicated, then the stack just
        // assigned this socket a port. We need to query it and use it for
        // all the other sockets we are going to create.
        //

        int AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
        Result =
            getsockname(
                SocketProc->Socket,
                (PSOCKADDR)&Socket->LocalAddress,
                &AssignedLocalAddressLength);
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "getsockaddress");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
            CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
        }
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    if (RemoteAddress != NULL) {
        Socket->RemoteAddress = *RemoteAddress;
    } else {
        Socket->RemoteAddress.Ipv4.sin_port = 0;
    }

    *NewSocket = Socket;
    Socket = NULL;

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (Socket != NULL) {
        CxPlatSocketDelete(Socket);
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
    return
        CxPlatSocketCreateTcpInternal(
            Datapath,
            CXPLAT_SOCKET_TCP,
            LocalAddress,
            RemoteAddress,
            CallbackContext,
            Socket);
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
    QUIC_STATUS Status;
    int Result;
    int Option;

    CXPLAT_DBG_ASSERT(Datapath->TcpHandlers.Receive != NULL);

    CXPLAT_SOCKET_PROC* SocketProc = NULL;
    uint32_t SocketLength = sizeof(CXPLAT_SOCKET) + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET* Socket = CXPLAT_ALLOC_PAGED(SocketLength, QUIC_POOL_SOCKET);
    if (Socket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            SocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(0, NULL));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = FALSE;
    Socket->Type = CXPLAT_SOCKET_TCP_LISTENER;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
        if (Socket->LocalAddress.si_family == AF_UNSPEC) {
            Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
        }
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);

    SocketProc = &Socket->Processors[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    SocketProc->ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
    CxPlatDatapathSqeInitialize(&SocketProc->IoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatRundownInitialize(&SocketProc->UpcallRundown);
    SocketProc->RioCq = RIO_INVALID_CQ;
    SocketProc->RioRq = RIO_INVALID_RQ;
    CxPlatListInitializeHead(&SocketProc->RioSendOverflow);

    SocketProc->Socket =
        WSASocketW(
            AF_INET6,
            SOCK_STREAM,
            IPPROTO_TCP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
    if (SocketProc->Socket == INVALID_SOCKET) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "WSASocketW");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Option = FALSE;
    Result =
        setsockopt(
            SocketProc->Socket,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (char*)&Option,
            sizeof(Option));
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "Set IPV6_V6ONLY");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
            (HANDLE)SocketProc->Socket,
            FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "SetFileCompletionNotificationModes");
        Status = HRESULT_FROM_WIN32(LastError);
        goto Error;
    }

    SocketProc->DatapathProc = &Datapath->Processors[0]; // TODO - Something better?
    CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

    if (!CxPlatEventQAssociateHandle(
            SocketProc->DatapathProc->EventQ,
            (HANDLE)SocketProc->Socket)) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "CreateIoCompletionPort");
        Status = HRESULT_FROM_WIN32(LastError);
        goto Error;
    }

    Result =
        bind(
            SocketProc->Socket,
            (PSOCKADDR)&Socket->LocalAddress,
            sizeof(Socket->LocalAddress));
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "bind");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //

    int AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
    Result =
        getsockname(
            SocketProc->Socket,
            (PSOCKADDR)&Socket->LocalAddress,
            &AssignedLocalAddressLength);
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "getsockaddress");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    Result =
        listen(
            SocketProc->Socket,
            100);
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            WsaError,
            "listen");
        Status = HRESULT_FROM_WIN32(WsaError);
        goto Error;
    }

    Status = CxPlatSocketStartAccept(SocketProc);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    SocketProc->IoStarted = TRUE;

    *NewSocket = Socket;
    Socket = NULL;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (Socket != NULL) {
        CxPlatSocketDelete(Socket);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
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
        (Socket->Type == CXPLAT_SOCKET_UDP && !Socket->HasFixedRemoteAddress) ?
            Socket->Datapath->ProcCount : 1;

    for (uint16_t i = 0; i < SocketCount; ++i) {
        CxPlatSocketContextUninitialize(&Socket->Processors[i]);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketRelease(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (CxPlatRefDecrement(&Socket->RefCount)) {
        QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            Socket);
#if DEBUG
        CXPLAT_DBG_ASSERT(!Socket->Freed);
        CXPLAT_DBG_ASSERT(Socket->Uninitialized);
        Socket->Freed = TRUE;
#endif
        CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketContextUninitialize(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CXPLAT_DBG_ASSERT(!SocketProc->Uninitialized);

    if (!SocketProc->IoStarted) {
        //
        // IO never started for this socket, so just kill the socket and process
        // completion inline.
        //
#if DEBUG
        SocketProc->Uninitialized = TRUE;
#endif
        if (SocketProc->Socket != INVALID_SOCKET &&
            closesocket(SocketProc->Socket) == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc,
                WsaError,
                "closesocket");
        }
        CxPlatSocketContextUninitializeComplete(SocketProc);
        return;
    }

    if (SocketProc->Parent->Type == CXPLAT_SOCKET_TCP ||
        SocketProc->Parent->Type == CXPLAT_SOCKET_TCP_SERVER) {
        //
        // For TCP sockets, we should shutdown the socket before closing it.
        //
        SocketProc->Parent->DisconnectIndicated = TRUE;
        if (shutdown(SocketProc->Socket, SD_BOTH) == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            if (WsaError != WSAENOTCONN) {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketProc,
                    WsaError,
                    "shutdown");
            }
        }
    }

    //
    // Block on all outstanding upcalls to the app so ensure they get no more.
    //
    CxPlatRundownReleaseAndWait(&SocketProc->UpcallRundown);

#if DEBUG
    SocketProc->Uninitialized = TRUE;
#endif

QUIC_DISABLED_BY_FUZZER_START;

    if (closesocket(SocketProc->Socket) == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc,
            WsaError,
            "closesocket");
    }

QUIC_DISABLED_BY_FUZZER_END;

    CXPLAT_FRE_ASSERT(
        CxPlatEventQEnqueue(
            SocketProc->DatapathProc->EventQ,
            &SocketProc->ShutdownSqe.Sqe,
            &SocketProc->ShutdownSqe));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketContextUninitializeComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!SocketProc->Freed);
    SocketProc->Freed = TRUE;
#endif

    if (SocketProc->Parent->Type != CXPLAT_SOCKET_TCP_LISTENER) {
        CXPLAT_DBG_ASSERT(SocketProc->RioRecvCount == 0);
        CXPLAT_DBG_ASSERT(SocketProc->RioSendCount == 0);
        CXPLAT_DBG_ASSERT(SocketProc->RioNotifyArmed == FALSE);

        while (!CxPlatListIsEmpty(&SocketProc->RioSendOverflow)) {
            CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&SocketProc->RioSendOverflow);
            CXPLAT_SEND_DATA* SendData =
                CONTAINING_RECORD(Entry, CXPLAT_SEND_DATA, RioOverflowEntry);
            CxPlatSendDataComplete(SocketProc, SendData, WSA_OPERATION_ABORTED);
        }

        if (SocketProc->RioCq != RIO_INVALID_CQ) {
            SocketProc->DatapathProc->Datapath->RioDispatch.
                RIOCloseCompletionQueue(SocketProc->RioCq);
            SocketProc->RioCq = RIO_INVALID_CQ;
        }
    } else {
        if (SocketProc->AcceptSocket != NULL) {
            CxPlatSocketDelete(SocketProc->AcceptSocket);
            SocketProc->AcceptSocket = NULL;
        }
    }

    CxPlatRundownUninitialize(&SocketProc->UpcallRundown);

    QuicTraceLogVerbose(
        DatapathSocketContextComplete,
        "[data][%p] Socket context shutdown",
        SocketProc);

    if (SocketProc->DatapathProc) {
        CxPlatProcessorContextRelease(SocketProc->DatapathProc);
    }
    CxPlatSocketRelease(SocketProc->Parent);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

void*
RioRecvBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PROC, RioRecvPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;

    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = CxPlatLargeAlloc(Size, Tag);

    if (RecvContext != NULL) {
        RecvContext->RioBufferId =
            Datapath->RioDispatch.RIORegisterBuffer((char*)RecvContext, Size);

        if (RecvContext->RioBufferId == RIO_INVALID_BUFFERID) {
            CxPlatLargeFree(RecvContext, Tag);
            RecvContext = NULL;
        }
    }

    return RecvContext;
}

void
RioRecvBufferFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = Entry;
    CXPLAT_DATAPATH_PROC* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PROC, RioRecvPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;

    CXPLAT_DBG_ASSERT(RecvContext->RioBufferId != RIO_INVALID_BUFFERID);
    Datapath->RioDispatch.RIODeregisterBuffer(RecvContext->RioBufferId);
    CxPlatLargeFree(RecvContext, Tag);
}

CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT*
CxPlatSocketAllocRecvContext(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc = SocketProc->DatapathProc;
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext;
    CXPLAT_POOL* OwningPool;

    if (SocketProc->Parent->UseRio) {
        OwningPool = &DatapathProc->RioRecvPool;
    } else {
        OwningPool = &DatapathProc->RecvDatagramPool;
    }

    RecvContext = CxPlatPoolAlloc(OwningPool);

    if (RecvContext != NULL) {
        RecvContext->OwningPool = OwningPool;
        RecvContext->ReferenceCount = 0;
        RecvContext->SocketProc = SocketProc;
#if DEBUG
        RecvContext->Sqe.IoType = 0;
#endif
    }

    return RecvContext;
}

void
CxPlatSocketFreeRecvContext(
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext
    )
{
    CxPlatPoolFree(RecvContext->OwningPool, RecvContext);
}

QUIC_STATUS
CxPlatSocketStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc
    )
{
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath = ListenerSocketProc->Parent->Datapath;
    DWORD BytesRecv = 0;
    int Result;

    //
    // Initialize a server socket to accept.
    //
    if (ListenerSocketProc->AcceptSocket == NULL) {
        Status =
            CxPlatSocketCreateTcpInternal(
                Datapath,
                CXPLAT_SOCKET_TCP_SERVER,
                NULL,
                NULL,
                NULL,
                &ListenerSocketProc->AcceptSocket);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    CxPlatStartDatapathIo(&ListenerSocketProc->IoSqe, DATAPATH_IO_ACCEPTEX);

    Result =
        Datapath->AcceptEx(
            ListenerSocketProc->Socket,
            ListenerSocketProc->AcceptSocket->Processors[0].Socket,
            &ListenerSocketProc->AcceptAddrSpace,
            0,                          // dwReceiveDataLength
            sizeof(SOCKADDR_INET)+16,   // dwLocalAddressLength
            sizeof(SOCKADDR_INET)+16,   // dwRemoteAddressLength
            &BytesRecv,
            &ListenerSocketProc->IoSqe.DatapathSqe.Sqe.Overlapped);
    if (Result == FALSE) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                WsaError,
                "AcceptEx");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }
    } else {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(ListenerSocketProc, &ListenerSocketProc->IoSqe, BytesRecv);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    return Status;
}

void
CxPlatDataPathSocketProcessAcceptCompletion(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_PROC* ListenerSocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);

    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;
    }

    if (!CxPlatRundownAcquire(&ListenerSocketProc->UpcallRundown)) {
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS) {
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket != NULL);
        CXPLAT_SOCKET_PROC* AcceptSocketProc = &ListenerSocketProc->AcceptSocket->Processors[0];
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent);
        DWORD BytesReturned;
        SOCKET_PROCESSOR_AFFINITY RssAffinity = { 0 };
        uint16_t AffinitizedProcessor = 0;

        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            ListenerSocketProc->Parent,
            0,
            "AcceptEx Completed!");

        int Result =
            setsockopt(
                AcceptSocketProc->Socket,
                SOL_SOCKET,
                SO_UPDATE_ACCEPT_CONTEXT,
                (char*)&ListenerSocketProc->Socket,
                sizeof(ListenerSocketProc->Socket));
        if (Result == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->AcceptSocket,
                WsaError,
                "Set UPDATE_ACCEPT_CONTEXT");
            goto Error;
        }

        Result =
            WSAIoctl(
                AcceptSocketProc->Socket,
                SIO_QUERY_RSS_PROCESSOR_INFO,
                NULL,
                0,
                &RssAffinity,
                sizeof(RssAffinity),
                &BytesReturned,
                NULL,
                NULL);
        if (Result == NO_ERROR) {
            AffinitizedProcessor =
                (uint16_t)CxPlatProcessorGroupInfo[RssAffinity.Processor.Group].Offset +
                (uint16_t)RssAffinity.Processor.Number;
        }

        AcceptSocketProc->DatapathProc =
            CxPlatDataPathGetProc(ListenerSocketProc->Parent->Datapath, AffinitizedProcessor);
        CxPlatRefIncrement(&AcceptSocketProc->DatapathProc->RefCount);

        if (!CxPlatEventQAssociateHandle(
                AcceptSocketProc->DatapathProc->EventQ,
                (HANDLE)AcceptSocketProc->Socket)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->AcceptSocket,
                LastError,
                "CreateIoCompletionPort (accepted)");
            goto Error;
        }

        CxPlatDataPathStartReceiveAsync(AcceptSocketProc);

        AcceptSocketProc->IoStarted = TRUE;
        ListenerSocketProc->Parent->Datapath->TcpHandlers.Accept(
            ListenerSocketProc->Parent,
            ListenerSocketProc->Parent->ClientContext,
            ListenerSocketProc->AcceptSocket,
            &ListenerSocketProc->AcceptSocket->ClientContext);
        ListenerSocketProc->AcceptSocket = NULL;

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            ListenerSocketProc->Parent,
            IoResult,
            "AcceptEx completion");
    }

Error:

    if (ListenerSocketProc->AcceptSocket != NULL) {
        CxPlatSocketDelete(ListenerSocketProc->AcceptSocket);
        ListenerSocketProc->AcceptSocket = NULL;
    }

    //
    // Try to start a new accept.
    //
    (void)CxPlatSocketStartAccept(ListenerSocketProc);

    CxPlatRundownRelease(&ListenerSocketProc->UpcallRundown);
}

void
CxPlatDataPathSocketProcessConnectCompletion(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);

    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;
    }

    if (!CxPlatRundownAcquire(&SocketProc->UpcallRundown)) {
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS) {

        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            0,
            "ConnectEx Completed!");

        SocketProc->Parent->Datapath->TcpHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            TRUE);

        //
        // Try to start a new receive.
        //
        CxPlatDataPathStartReceiveAsync(SocketProc);

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "ConnectEx completion");

        SocketProc->Parent->Datapath->TcpHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            FALSE);
    }

    CxPlatRundownRelease(&SocketProc->UpcallRundown);
}

void
CxPlatSocketHandleUnreachableError(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext,
    _In_ ULONG ErrorCode
    )
{
    PSOCKADDR_INET RemoteAddr = &RecvContext->Route.RemoteAddress;
    UNREFERENCED_PARAMETER(ErrorCode);

    CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

#if QUIC_CLOG
    QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[data][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketProc->Parent,
        ErrorCode,
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

    SocketProc->Parent->Datapath->UdpHandlers.Unreachable(
        SocketProc->Parent,
        SocketProc->Parent->ClientContext,
        RemoteAddr);
}

QUIC_STATUS
CxPlatSocketStartRioReceives(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    QUIC_STATUS Status;
    BOOLEAN NeedCommit = FALSE;
    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;

    while (SocketProc->RioRecvCount < RIO_RECV_QUEUE_DEPTH) {
        RIO_BUF Data = {0};
        RIO_BUF RemoteAddr = {0};
        RIO_BUF Control = {0};
        DWORD RioFlags = 0;

        CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
            CxPlatSocketAllocRecvContext(SocketProc);
        if (RecvContext == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Socket Receive Buffer",
                Datapath->RecvPayloadOffset + SocketProc->Parent->RecvBufLen);
            goto Error;
        }

        if (SocketProc->RioRecvCount < RIO_RECV_QUEUE_DEPTH - 1) {
            RioFlags |= RIO_MSG_DEFER;
        }

        Data.BufferId = RecvContext->RioBufferId;
        Data.Offset = Datapath->RecvPayloadOffset;
        Data.Length = SocketProc->Parent->RecvBufLen;
        RemoteAddr.BufferId = RecvContext->RioBufferId;
        RemoteAddr.Offset =
            FIELD_OFFSET(CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT, Route.RemoteAddress);
        RemoteAddr.Length = sizeof(RecvContext->Route.RemoteAddress);
        Control.BufferId = RecvContext->RioBufferId;
        Control.Offset = FIELD_OFFSET(CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT, ControlBuf);
        Control.Length = sizeof(RecvContext->ControlBuf);
        RecvContext->Sqe.IoType = DATAPATH_IO_RIO_RECV;

        if (!Datapath->RioDispatch.RIOReceiveEx(
                SocketProc->RioRq, &Data, 1, NULL, &RemoteAddr,
                &Control, NULL, RioFlags, &RecvContext->Sqe.IoType)) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                WsaError,
                "RIOReceiveEx");
            Status = HRESULT_FROM_WIN32(WsaError);
            CxPlatSocketFreeRecvContext(RecvContext);
            goto Error;
        }

        if (RioFlags & RIO_MSG_DEFER) {
            NeedCommit = TRUE;
        }

        SocketProc->RioRecvCount++;
    }

    NeedCommit = FALSE;
    Status = QUIC_STATUS_PENDING;

Error:

    if (NeedCommit) {
        #pragma warning(suppress:6387) // _Param_(9)' could be '0' - by design.
        if (!Datapath->RioDispatch.RIOReceiveEx(
                SocketProc->RioRq, NULL, 0, NULL, NULL, NULL, NULL,
                RIO_MSG_COMMIT_ONLY, NULL)) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                WsaError,
                "RIOReceiveEx");
            Status = HRESULT_FROM_WIN32(WsaError);
        } else {
            //
            // At least one receive was posted and committed, guaranteeing
            // forward progress, so indicate the partial success.
            //
            Status = QUIC_STATUS_PENDING;
        }
    }

    if (QUIC_SUCCEEDED(Status)) {
        CxPlatSocketArmRioNotify(SocketProc);
    }

    return Status;
}

_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
CxPlatSocketStartWinsockReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Out_opt_ ULONG* SyncIoResult,
    _Out_opt_ uint16_t* SyncBytesReceived,
    _Out_opt_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT** SyncRecvContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext;
    int Result;
    DWORD BytesRecv = 0;
    WSABUF WsaBuf;

    CXPLAT_DBG_ASSERT((SyncIoResult != NULL) == (SyncBytesReceived != NULL));
    CXPLAT_DBG_ASSERT((SyncIoResult != NULL) == (SyncRecvContext != NULL));
    CXPLAT_DBG_ASSERT(SocketProc->Parent->Type != CXPLAT_SOCKET_TCP_LISTENER);

    //
    // Get a receive buffer we can pass to WinSock.
    //
    RecvContext = CxPlatSocketAllocRecvContext(SocketProc);
    if (RecvContext == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Socket Receive Buffer",
            SocketProc->Parent->Datapath->RecvPayloadOffset + SocketProc->Parent->RecvBufLen);
        goto Error;
    }

    CxPlatDatapathSqeInitialize(&RecvContext->Sqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatStartDatapathIo(&RecvContext->Sqe, DATAPATH_IO_RECV);

    WsaBuf.buf = ((CHAR*)RecvContext) + Datapath->RecvPayloadOffset;
    WsaBuf.len = SocketProc->Parent->RecvBufLen;

    RtlZeroMemory(&RecvContext->WsaMsgHdr, sizeof(RecvContext->WsaMsgHdr));

    RecvContext->WsaMsgHdr.name = (PSOCKADDR)&RecvContext->Route.RemoteAddress;
    RecvContext->WsaMsgHdr.namelen = sizeof(RecvContext->Route.RemoteAddress);

    RecvContext->WsaMsgHdr.lpBuffers = &WsaBuf;
    RecvContext->WsaMsgHdr.dwBufferCount = 1;

    RecvContext->WsaMsgHdr.Control.buf = RecvContext->ControlBuf;
    RecvContext->WsaMsgHdr.Control.len = sizeof(RecvContext->ControlBuf);

Retry_recv:

    if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP) {
        Result =
            SocketProc->Parent->Datapath->WSARecvMsg(
                SocketProc->Socket,
                &RecvContext->WsaMsgHdr,
                &BytesRecv,
                &RecvContext->Sqe.DatapathSqe.Sqe.Overlapped,
                NULL);
    } else {
        DWORD Flags = 0;
        Result =
            WSARecv(
                SocketProc->Socket,
                &WsaBuf,
                1,
                &BytesRecv,
                &Flags,
                &RecvContext->Sqe.DatapathSqe.Sqe.Overlapped,
                NULL);
    }

    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP &&
                WsaError == WSAECONNRESET) {
                CxPlatSocketHandleUnreachableError(SocketProc, RecvContext, (ULONG)WsaError);
                goto Retry_recv;
            } else {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketProc->Parent,
                    WsaError,
                    "WSARecvMsg");
                Status = HRESULT_FROM_WIN32(WsaError);
                CxPlatStopInlineDatapathIo(&RecvContext->Sqe);

                if (SyncBytesReceived != NULL) {
                    *SyncBytesReceived = 0;
                    *SyncIoResult = WsaError;
                    *SyncRecvContext = RecvContext;
                } else {
                    CxPlatStartDatapathIo(&RecvContext->Sqe, DATAPATH_IO_RECV_FAILURE);
                    RecvContext->Sqe.DatapathSqe.Sqe.Overlapped.Internal = WsaError;

                    Status = CxPlatSocketEnqueueSqe(SocketProc, &RecvContext->Sqe, 0);
                    if (QUIC_FAILED(Status)) {
                        goto Error;
                    }
                    Status = QUIC_STATUS_PENDING;
                }

                goto Error;
            }
        }
        Status = QUIC_STATUS_PENDING;
        RecvContext = NULL;

    } else if (SyncBytesReceived == NULL) {
        //
        // Manually post IO completion if receive completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(SocketProc, &RecvContext->Sqe, BytesRecv);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
        Status = QUIC_STATUS_PENDING;
        RecvContext = NULL;
    } else {
        CXPLAT_DBG_ASSERT(BytesRecv < UINT16_MAX);
        *SyncBytesReceived = (uint16_t)BytesRecv;
        *SyncIoResult = NO_ERROR;
        *SyncRecvContext = RecvContext;
        CxPlatStopInlineDatapathIo(&RecvContext->Sqe);
        RecvContext = NULL;
    }

Error:

    if (RecvContext) {
        CxPlatSocketFreeRecvContext(RecvContext);
    }

    return Status;
}

_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
CxPlatSocketStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Out_opt_ ULONG* SyncIoResult,
    _Out_opt_ uint16_t* SyncBytesReceived,
    _Out_opt_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT** SyncRecvContext
    )
{
    QUIC_STATUS Status;

    if (SocketProc->Parent->UseRio) {
        Status = CxPlatSocketStartRioReceives(SocketProc);
        CXPLAT_DBG_ASSERT(Status != QUIC_STATUS_SUCCESS);
    } else {
        Status =
            CxPlatSocketStartWinsockReceive(
                SocketProc, SyncIoResult, SyncBytesReceived, SyncRecvContext);
    }

    return Status;
}

BOOLEAN
CxPlatDataPathUdpRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext,
    _In_ ULONG IoResult,
    _In_ UINT16 NumberOfBytesTransferred
    )
{
    PSOCKADDR_INET RemoteAddr = &RecvContext->Route.RemoteAddress;
    PSOCKADDR_INET LocalAddr = &RecvContext->Route.LocalAddress;
    BOOLEAN NeedReceive = TRUE;
    RecvContext->Route.Queue = SocketProc;

    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        NeedReceive = FALSE;
        goto Drop;

    } else if (IsUnreachableErrorCode(IoResult)) {

        if (!SocketProc->Parent->PcpBinding) {
            CxPlatSocketHandleUnreachableError(SocketProc, RecvContext, IoResult);
        }

    } else if (IoResult == ERROR_MORE_DATA ||
        (IoResult == NO_ERROR && SocketProc->Parent->RecvBufLen < NumberOfBytesTransferred)) {

        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

#if QUIC_CLOG
        QuicTraceLogVerbose(
            DatapathTooLarge,
            "[data][%p] Received larger than expected datagram from %!ADDR!",
            SocketProc->Parent,
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

        //
        // TODO - Indicate to Core library.
        //

    } else if (IoResult == QUIC_STATUS_SUCCESS) {

        CXPLAT_RECV_DATA* RecvDataChain = NULL;
        CXPLAT_RECV_DATA** DatagramChainTail = &RecvDataChain;

        CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
        CXPLAT_RECV_DATA* Datagram;
        PUCHAR RecvPayload = ((PUCHAR)RecvContext) + Datapath->RecvPayloadOffset;

        BOOLEAN FoundLocalAddr = FALSE;
        UINT16 MessageLength = NumberOfBytesTransferred;
        ULONG MessageCount = 0;
        BOOLEAN IsCoalesced = FALSE;
        INT ECN = 0;

        if (SocketProc->Parent->UseRio) {
            PRIO_CMSG_BUFFER RioRcvMsg = (PRIO_CMSG_BUFFER)RecvContext->ControlBuf;
            RecvContext->WsaMsgHdr.Control.buf = RecvContext->ControlBuf + RIO_CMSG_BASE_SIZE;
            RecvContext->WsaMsgHdr.Control.len = RioRcvMsg->TotalLength - RIO_CMSG_BASE_SIZE;
        }

        for (WSACMSGHDR* CMsg = CMSG_FIRSTHDR(&RecvContext->WsaMsgHdr);
            CMsg != NULL;
            CMsg = CMSG_NXTHDR(&RecvContext->WsaMsgHdr, CMsg)) {

            if (CMsg->cmsg_level == IPPROTO_IPV6) {
                if (CMsg->cmsg_type == IPV6_PKTINFO) {
                    PIN6_PKTINFO PktInfo6 = (PIN6_PKTINFO)WSA_CMSG_DATA(CMsg);
                    LocalAddr->si_family = QUIC_ADDRESS_FAMILY_INET6;
                    LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                    LocalAddr->Ipv6.sin6_port = SocketProc->Parent->LocalAddress.Ipv6.sin6_port;
                    CxPlatConvertFromMappedV6(LocalAddr, LocalAddr);
                    LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;
                } else if (CMsg->cmsg_type == IPV6_ECN) {
                    ECN = *(PINT)WSA_CMSG_DATA(CMsg);
                    CXPLAT_DBG_ASSERT(ECN < UINT8_MAX);
                }
            } else if (CMsg->cmsg_level == IPPROTO_IP) {
                if (CMsg->cmsg_type == IP_PKTINFO) {
                    PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
                    LocalAddr->si_family = QUIC_ADDRESS_FAMILY_INET;
                    LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
                    LocalAddr->Ipv4.sin_port = SocketProc->Parent->LocalAddress.Ipv6.sin6_port;
                    LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                    FoundLocalAddr = TRUE;
                } else if (CMsg->cmsg_type == IP_ECN) {
                    ECN = *(PINT)WSA_CMSG_DATA(CMsg);
                    CXPLAT_DBG_ASSERT(ECN < UINT8_MAX);
                }
            } else if (CMsg->cmsg_level == IPPROTO_UDP) {
                if (CMsg->cmsg_type == UDP_COALESCED_INFO) {
                    CXPLAT_DBG_ASSERT(*(PDWORD)WSA_CMSG_DATA(CMsg) <= SocketProc->Parent->RecvBufLen);
                    MessageLength = (UINT16)*(PDWORD)WSA_CMSG_DATA(CMsg);
                    IsCoalesced = TRUE;
                }
            }
        }

        if (!FoundLocalAddr) {
            //
            // The underlying data path does not guarantee ancillary data for
            // enabled socket options when the system is under memory pressure.
            //
            QuicTraceLogWarning(
                DatapathMissingInfo,
                "[data][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketProc->Parent);
            goto Drop;
        }

        if (NumberOfBytesTransferred == 0) {
            QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[data][%p] Dropping datagram with empty payload.",
                SocketProc->Parent);
            goto Drop;
        }

        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketProc->Parent,
            NumberOfBytesTransferred,
            MessageLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= SocketProc->Parent->RecvBufLen);

        Datagram = (CXPLAT_RECV_DATA*)(RecvContext + 1);

        for ( ;
            NumberOfBytesTransferred != 0;
            NumberOfBytesTransferred -= MessageLength) {

            CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext =
                CxPlatDataPathDatagramToInternalDatagramContext(Datagram);
            InternalDatagramContext->RecvContext = RecvContext;

            if (MessageLength > NumberOfBytesTransferred) {
                //
                // The last message is smaller than all the rest.
                //
                MessageLength = NumberOfBytesTransferred;
            }

            Datagram->Next = NULL;
            Datagram->Buffer = RecvPayload;
            Datagram->BufferLength = MessageLength;
            Datagram->Route = &RecvContext->Route;
            Datagram->PartitionIndex = SocketProc->DatapathProc->IdealProcessor;
            Datagram->TypeOfService = (uint8_t)ECN;
            Datagram->Allocated = TRUE;
            Datagram->QueuedOnConnection = FALSE;

            RecvPayload += MessageLength;

            //
            // Add the datagram to the end of the current chain.
            //
            *DatagramChainTail = Datagram;
            DatagramChainTail = &Datagram->Next;
            RecvContext->ReferenceCount++;

            Datagram = (CXPLAT_RECV_DATA*)
                (((PUCHAR)Datagram) +
                    SocketProc->Parent->Datapath->DatagramStride);

            if (IsCoalesced && ++MessageCount == URO_MAX_DATAGRAMS_PER_INDICATION) {
                QuicTraceLogWarning(
                    DatapathUroPreallocExceeded,
                    "[data][%p] Exceeded URO preallocation capacity.",
                    SocketProc->Parent);
                break;
            }
        }

        RecvContext = NULL;
        CXPLAT_DBG_ASSERT(RecvDataChain);

#ifdef QUIC_FUZZER
        if (MsQuicFuzzerContext.RecvCallback) {
            CXPLAT_RECV_DATA *_DatagramIter = RecvDataChain;

            while (_DatagramIter) {
                MsQuicFuzzerContext.RecvCallback(
                    MsQuicFuzzerContext.CallbackContext,
                    _DatagramIter->Buffer,
                    _DatagramIter->BufferLength);
                _DatagramIter = _DatagramIter->Next;
            }
        }
#endif

        if (!SocketProc->Parent->PcpBinding) {
            SocketProc->Parent->Datapath->UdpHandlers.Receive(
                SocketProc->Parent,
                SocketProc->Parent->ClientContext,
                RecvDataChain);
        } else {
            CxPlatPcpRecvCallback(
                SocketProc->Parent,
                SocketProc->Parent->ClientContext,
                RecvDataChain);
        }

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSARecvMsg completion");
    }

Drop:

    if (RecvContext != NULL) {
        CxPlatSocketFreeRecvContext(RecvContext);
    }

    return NeedReceive;
}

BOOLEAN
CxPlatDataPathStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Out_opt_ ULONG* IoResult,
    _Out_opt_ uint16_t* InlineBytesTransferred,
    _Out_opt_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT** RecvContext
    )
{
    //
    // Try to start a new receive. Returns TRUE if the receive completed inline.
    //

    const int32_t MAX_RECV_RETRIES = 10;
    int32_t RetryCount = 0;
    QUIC_STATUS Status;
    do {
        Status =
            CxPlatSocketStartReceive(
                SocketProc,
                IoResult,
                InlineBytesTransferred,
                RecvContext);
    } while (Status == QUIC_STATUS_OUT_OF_MEMORY && ++RetryCount < MAX_RECV_RETRIES);

    if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
        CXPLAT_DBG_ASSERT(RetryCount == MAX_RECV_RETRIES);
        SocketProc->RecvFailure = TRUE;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "CxPlatSocketStartReceive failed multiple times. Receive will no longer work.");
        Status = QUIC_STATUS_PENDING;
    }

    return Status != QUIC_STATUS_PENDING;
}

void
CxPlatDataPathStartReceiveAsync(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CxPlatDataPathStartReceive(SocketProc, NULL, NULL, NULL);
}

void
CxPlatDataPathSocketProcessRioCompletion(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, RioSqe);
    CXPLAT_DATAPATH* Datapath = SocketProc->DatapathProc->Datapath;
    ULONG ResultCount;
    BOOLEAN UpcallAcquired;
    ULONG TotalResultCount = 0;

    CXPLAT_DBG_ASSERT(SocketProc->RioNotifyArmed);
    SocketProc->RioNotifyArmed = FALSE;
    UpcallAcquired = CxPlatRundownAcquire(&SocketProc->UpcallRundown);

    do {
        BOOLEAN NeedReceive = FALSE;
        RIORESULT Results[32];

        ResultCount =
            Datapath->RioDispatch.RIODequeueCompletion(
                SocketProc->RioCq, Results, RTL_NUMBER_OF(Results));

        CXPLAT_FRE_ASSERT(ResultCount != RIO_CORRUPT_CQ);

        for (ULONG i = 0; i < ResultCount; i++) {
            DATAPATH_IO_TYPE* IoType =
                (DATAPATH_IO_TYPE*)(ULONG_PTR)Results[i].RequestContext;

            switch (*IoType) {
            case DATAPATH_IO_RIO_RECV:
                CXPLAT_DBG_ASSERT(Results[i].BytesTransferred <= UINT16_MAX);
                CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
                    CONTAINING_RECORD(IoType, CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT, Sqe.IoType);

                if (UpcallAcquired) {
                    NeedReceive =
                        CxPlatDataPathRecvComplete(
                            SocketProc,
                            RecvContext,
                            Results[i].Status,
                            (UINT16)Results[i].BytesTransferred);
                } else {
                    CxPlatFreeRecvContext(RecvContext);
                }

                SocketProc->RioRecvCount--;
                break;

            case DATAPATH_IO_RIO_SEND:
                CXPLAT_RIO_SEND_BUFFER_HEADER* SendHeader =
                    CONTAINING_RECORD(IoType, CXPLAT_RIO_SEND_BUFFER_HEADER, IoType);
                CXPLAT_SEND_DATA* SendData = SendHeader->SendData;

                CxPlatSendDataComplete(SocketProc, SendData, Results[i].Status);

                SocketProc->RioSendCount--;
                break;

            default:
                CXPLAT_DBG_ASSERT(FALSE);
                break;
            }
        }

        if (UpcallAcquired) {
            if (NeedReceive) {
                CxPlatDataPathStartReceiveAsync(SocketProc);
                NeedReceive = FALSE;
            }

            CxPlatDataPathStartRioSends(SocketProc);
        }

        TotalResultCount += ResultCount;
    } while (ResultCount > 0 && (TotalResultCount < 256 || !UpcallAcquired));

    if (SocketProc->RioRecvCount > 0 || SocketProc->RioSendCount > 0) {
        CxPlatSocketArmRioNotify(SocketProc);
    }

    if (UpcallAcquired) {
        CxPlatRundownRelease(&SocketProc->UpcallRundown);
    }

    if (CxPlatRefDecrement(&SocketProc->RefCount)) {
        CxPlatSocketContextUninitializeComplete(SocketProc);
    }
}

BOOLEAN
CxPlatDataPathTcpRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext,
    _In_ ULONG IoResult,
    _In_ UINT16 NumberOfBytesTransferred
    )
{
    BOOLEAN NeedReceive = TRUE;

    PSOCKADDR_INET RemoteAddr = &RecvContext->Route.RemoteAddress;
    PSOCKADDR_INET LocalAddr = &RecvContext->Route.LocalAddress;

    if (IoResult == WSAENOTSOCK ||
        IoResult == WSA_OPERATION_ABORTED ||
        IoResult == ERROR_NETNAME_DELETED ||
        IoResult == WSAECONNRESET) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        if (!SocketProc->Parent->DisconnectIndicated) {
            SocketProc->Parent->DisconnectIndicated = TRUE;
            SocketProc->Parent->Datapath->TcpHandlers.Connect(
                SocketProc->Parent,
                SocketProc->Parent->ClientContext,
                FALSE);
        }

        NeedReceive = FALSE;
        goto Drop;

    } else if (IoResult == QUIC_STATUS_SUCCESS) {

        if (NumberOfBytesTransferred == 0) {
            if (!SocketProc->Parent->DisconnectIndicated) {
                SocketProc->Parent->DisconnectIndicated = TRUE;
                SocketProc->Parent->Datapath->TcpHandlers.Connect(
                    SocketProc->Parent,
                    SocketProc->Parent->ClientContext,
                    FALSE);
            }

            goto Drop;
        }

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketProc->Parent,
            NumberOfBytesTransferred,
            NumberOfBytesTransferred,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= SocketProc->Parent->RecvBufLen);

        CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
        CXPLAT_RECV_DATA* Data = (CXPLAT_RECV_DATA*)(RecvContext + 1);

        CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext =
            CxPlatDataPathDatagramToInternalDatagramContext(Data);
        InternalDatagramContext->RecvContext = RecvContext;

        Data->Next = NULL;
        Data->Buffer = ((PUCHAR)RecvContext) + Datapath->RecvPayloadOffset;
        Data->BufferLength = NumberOfBytesTransferred;
        Data->Route = &RecvContext->Route;
        Data->PartitionIndex = SocketProc->DatapathProc->IdealProcessor;
        Data->TypeOfService = 0;
        Data->Allocated = TRUE;
        Data->QueuedOnConnection = FALSE;
        RecvContext->ReferenceCount++;
        RecvContext = NULL;

        SocketProc->Parent->Datapath->TcpHandlers.Receive(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            Data);

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSARecv completion");
    }

Drop:

    if (RecvContext != NULL) {
        CxPlatSocketFreeRecvContext(RecvContext);
    }

    return NeedReceive;
}

void
CxPlatFreeRecvContext(
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext
    )
{
    CXPLAT_DBG_ASSERT(RecvContext->ReferenceCount == 0);
    CxPlatPoolFree(RecvContext->OwningPool, RecvContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CXPLAT_RECV_DATA* Datagram;

    LONG BatchedBufferCount = 0;
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* BatchedInternalContext = NULL;

    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;

        CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalBufferContext =
            CxPlatDataPathDatagramToInternalDatagramContext(Datagram);
        CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext =
            InternalBufferContext->RecvContext;

        if (BatchedInternalContext == InternalContext) {
            BatchedBufferCount++;
        } else {
            if (BatchedInternalContext != NULL &&
                InterlockedAdd(
                    (PLONG)&BatchedInternalContext->ReferenceCount,
                    -BatchedBufferCount) == 0) {
                //
                // Clean up the data indication.
                //
                CxPlatSocketFreeRecvContext(BatchedInternalContext);
            }

            BatchedInternalContext = InternalContext;
            BatchedBufferCount = 1;
        }
    }

    if (BatchedInternalContext != NULL &&
        InterlockedAdd(
            (PLONG)&BatchedInternalContext->ReferenceCount,
            -BatchedBufferCount) == 0) {
        //
        // Clean up the data indication.
        //
        CxPlatSocketFreeRecvContext(BatchedInternalContext);
    }
}

BOOLEAN
CxPlatDataPathRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext,
    _In_ ULONG IoResult,
    _In_ uint16_t BytesTransferred
    )
{
    if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP) {
        return
            CxPlatDataPathUdpRecvComplete(
                SocketProc,
                RecvContext,
                IoResult,
                BytesTransferred);
    } else {
        return
            CxPlatDataPathTcpRecvComplete(
                SocketProc,
                RecvContext,
                IoResult,
                BytesTransferred);
    }
}

void
CxPlatDataPathSocketProcessReceiveInternal(
    _In_ CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext,
    _In_ uint16_t BytesTransferred,
    _In_ ULONG IoResult
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = RecvContext->SocketProc;

    if (!CxPlatRundownAcquire(&SocketProc->UpcallRundown)) {
        return;
    }

    for (ULONG InlineReceiveCount = 10; InlineReceiveCount > 0; InlineReceiveCount--) {
        BOOLEAN StartReceive =
            CxPlatDataPathRecvComplete(
                SocketProc, RecvContext, IoResult, BytesTransferred);

        if (!StartReceive ||
            !CxPlatDataPathStartReceive(
                SocketProc,
                InlineReceiveCount > 1 ? &IoResult : NULL,
                InlineReceiveCount > 1 ? &BytesTransferred : NULL,
                InlineReceiveCount > 1 ? &RecvContext : NULL)) {
            break;
        }
    }

    CxPlatRundownRelease(&SocketProc->UpcallRundown);
}

void
CxPlatDataPathSocketProcessReceiveCompletion(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
        CONTAINING_RECORD(Sqe, CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT, Sqe);

    CXPLAT_DBG_ASSERT(Cqe->dwNumberOfBytesTransferred <= UINT16_MAX);
    uint16_t BytesTransferred = (uint16_t)Cqe->dwNumberOfBytesTransferred;
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);

    CxPlatDataPathSocketProcessReceiveInternal(RecvContext, BytesTransferred, IoResult);
}

void
CxPlatDataPathSocketProcessReceiveFailure(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
        CONTAINING_RECORD(Sqe, CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT, Sqe);

    CXPLAT_DBG_ASSERT(Cqe->dwNumberOfBytesTransferred == 0);
    uint16_t BytesTransferred = (uint16_t)Cqe->dwNumberOfBytesTransferred;
    ULONG IoResult = (ULONG)Cqe->Internal;

    CxPlatDataPathSocketProcessReceiveInternal(RecvContext, BytesTransferred, IoResult);
}

void*
RioSendDataAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PROC, RioSendDataPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;
    CXPLAT_SEND_DATA* SendData;

    SendData = CxPlatLargeAlloc(Size, Tag);

    if (SendData != NULL) {
        SendData->RioBufferId =
            Datapath->RioDispatch.RIORegisterBuffer((char*)SendData, Size);
        if (SendData->RioBufferId == RIO_INVALID_BUFFERID) {
            CxPlatLargeFree(SendData, Tag);
            SendData = NULL;
        }
    }

    return SendData;
}

void
RioSendDataFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_SEND_DATA* SendData = Entry;
    CXPLAT_DATAPATH* Datapath = SendData->Owner->Datapath;

    UNREFERENCED_PARAMETER(Pool);

    CXPLAT_DBG_ASSERT(SendData->RioBufferId != RIO_INVALID_BUFFERID);
    Datapath->RioDispatch.RIODeregisterBuffer(SendData->RioBufferId);
    CxPlatLargeFree(SendData, Tag);
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
        Config->Route->Queue = &Socket->Processors[0];
    }

    CXPLAT_SOCKET_PROC* SocketProc = Config->Route->Queue;
    CXPLAT_DATAPATH_PROC* DatapathProc = SocketProc->DatapathProc;
    CXPLAT_POOL* SendDataPool =
        Socket->UseRio ? &DatapathProc->RioSendDataPool : &DatapathProc->SendDataPool;

    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(SendDataPool);

    if (SendData != NULL) {
        SendData->Owner = DatapathProc;
        SendData->SendDataPool = SendDataPool;
        SendData->ECN = Config->ECN;
        SendData->SendFlags = Config->Flags;
        SendData->SegmentSize =
            (Socket->Type != CXPLAT_SOCKET_UDP ||
             Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)
                ? Config->MaxPacketSize : 0;
        SendData->TotalSize = 0;
        SendData->WsaBufferCount = 0;
        SendData->ClientBuffer.len = 0;
        SendData->ClientBuffer.buf = NULL;
#if DEBUG
        SendData->Sqe.IoType = 0;
#endif

        if (Socket->UseRio) {
            SendData->BufferPool =
                SendData->SegmentSize > 0 ?
                    &DatapathProc->RioLargeSendBufferPool :
                    &DatapathProc->RioSendBufferPool;
        } else {
            SendData->BufferPool =
                SendData->SegmentSize > 0 ?
                    &DatapathProc->LargeSendBufferPool :
                    &DatapathProc->SendBufferPool;
        }
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    for (UINT8 i = 0; i < SendData->WsaBufferCount; ++i) {
        CxPlatPoolFree(SendData->BufferPool, SendData->WsaBuffers[i].buf);
    }

    CxPlatPoolFree(SendData->SendDataPool, SendData);
}

CXPLAT_RIO_SEND_BUFFER_HEADER*
RioSendBufferHeaderFromBuffer(
    _In_ char* Buffer
    )
{
    return ((CXPLAT_RIO_SEND_BUFFER_HEADER*)Buffer) - 1;
}

void*
RioSendBufferAllocateInternal(
    CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t Size,
    _In_ uint32_t Tag
    )
{
    CXPLAT_RIO_SEND_BUFFER_HEADER* RioHeader;
    void* Buffer = NULL;

    CXPLAT_DBG_ASSERT(Size + (uint32_t)sizeof(*RioHeader) > Size);
    RioHeader = CxPlatLargeAlloc(Size + sizeof(*RioHeader), Tag);

    if (RioHeader != NULL) {
        Buffer = RioHeader + 1;

        RioHeader->Datapath = Datapath;
        RioHeader->RioBufferId = Datapath->RioDispatch.RIORegisterBuffer(Buffer, Size);
        if (RioHeader->RioBufferId == RIO_INVALID_BUFFERID) {
            CxPlatLargeFree(RioHeader, Tag);
            RioHeader = NULL;
            Buffer = NULL;
        }
    }

    return Buffer;
}

void*
RioSendBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PROC, RioSendBufferPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;

    return RioSendBufferAllocateInternal(Datapath, Size, Tag);
}

void*
RioSendLargeBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PROC, RioLargeSendBufferPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;

    return RioSendBufferAllocateInternal(Datapath, Size, Tag);
}

void
RioSendBufferFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_RIO_SEND_BUFFER_HEADER* RioHeader = RioSendBufferHeaderFromBuffer(Entry);
    CXPLAT_DATAPATH* Datapath = RioHeader->Datapath;

    UNREFERENCED_PARAMETER(Pool);

    CXPLAT_DBG_ASSERT(RioHeader->RioBufferId != RIO_INVALID_BUFFERID);
    Datapath->RioDispatch.RIODeregisterBuffer(RioHeader->RioBufferId);
    CxPlatLargeFree(RioHeader, Tag);
}

static
BOOLEAN
CxPlatSendDataCanAllocSendSegment(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    if (!SendData->ClientBuffer.buf) {
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(SendData->WsaBufferCount > 0);

    ULONG BytesAvailable =
        CXPLAT_LARGE_SEND_BUFFER_SIZE -
            SendData->WsaBuffers[SendData->WsaBufferCount - 1].len -
            SendData->ClientBuffer.len;

    return MaxBufferLength <= BytesAvailable;
}

static
BOOLEAN
CxPlatSendDataCanAllocSend(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    return
        (SendData->WsaBufferCount < SendData->Owner->Datapath->MaxSendBatchSize) ||
        ((SendData->SegmentSize > 0) &&
            CxPlatSendDataCanAllocSendSegment(SendData, MaxBufferLength));
}

static
void
CxPlatSendDataFinalizeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->ClientBuffer.len == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendData->WsaBufferCount > 0) {
            CXPLAT_DBG_ASSERT(SendData->WsaBuffers[SendData->WsaBufferCount - 1].len < UINT16_MAX);
            SendData->TotalSize +=
                SendData->WsaBuffers[SendData->WsaBufferCount - 1].len;
        }
        return;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0 && SendData->WsaBufferCount > 0);
    CXPLAT_DBG_ASSERT(SendData->ClientBuffer.len > 0 && SendData->ClientBuffer.len <= SendData->SegmentSize);
    CXPLAT_DBG_ASSERT(CxPlatSendDataCanAllocSendSegment(SendData, 0));

    //
    // Append the client's buffer segment to our internal send buffer.
    //
    SendData->WsaBuffers[SendData->WsaBufferCount - 1].len +=
        SendData->ClientBuffer.len;
    SendData->TotalSize += SendData->ClientBuffer.len;

    if (SendData->ClientBuffer.len == SendData->SegmentSize) {
        SendData->ClientBuffer.buf += SendData->SegmentSize;
        SendData->ClientBuffer.len = 0;
    } else {
        //
        // The next segment allocation must create a new backing buffer.
        //
        SendData->ClientBuffer.buf = NULL;
        SendData->ClientBuffer.len = 0;
    }
}

_Success_(return != NULL)
static
WSABUF*
CxPlatSendDataAllocDataBuffer(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendData->WsaBufferCount < SendData->Owner->Datapath->MaxSendBatchSize);

    WSABUF* WsaBuffer = &SendData->WsaBuffers[SendData->WsaBufferCount];
    WsaBuffer->buf = CxPlatPoolAlloc(SendData->BufferPool);
    if (WsaBuffer->buf == NULL) {
        return NULL;
    }
    ++SendData->WsaBufferCount;

    return WsaBuffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendDataAllocPacketBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    WSABUF* WsaBuffer = CxPlatSendDataAllocDataBuffer(SendData);
    if (WsaBuffer != NULL) {
        WsaBuffer->len = MaxBufferLength;
    }
    return (QUIC_BUFFER*)WsaBuffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendDataAllocSegmentBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= SendData->SegmentSize);

    if (CxPlatSendDataCanAllocSendSegment(SendData, MaxBufferLength)) {
        //
        // All clear to return the next segment of our contiguous buffer.
        //
        SendData->ClientBuffer.len = MaxBufferLength;
        return (QUIC_BUFFER*)&SendData->ClientBuffer;
    }

    WSABUF* WsaBuffer = CxPlatSendDataAllocDataBuffer(SendData);
    if (WsaBuffer == NULL) {
        return NULL;
    }

    //
    // Provide a virtual WSABUF to the client. Once the client has committed
    // to a final send size, we'll append it to our internal backing buffer.
    //
    WsaBuffer->len = 0;
    SendData->ClientBuffer.buf = WsaBuffer->buf;
    SendData->ClientBuffer.len = MaxBufferLength;

    return (QUIC_BUFFER*)&SendData->ClientBuffer;
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

    if (!CxPlatSendDataCanAllocSend(SendData, MaxBufferLength)) {
        return NULL;
    }

    if (SendData->SegmentSize == 0) {
        return CxPlatSendDataAllocPacketBuffer(SendData, MaxBufferLength);
    } else {
        return CxPlatSendDataAllocSegmentBuffer(SendData, MaxBufferLength);
    }
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
    PCHAR TailBuffer = SendData->WsaBuffers[SendData->WsaBufferCount - 1].buf;

    if (SendData->SegmentSize == 0) {
        CXPLAT_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);

        CxPlatPoolFree(SendData->BufferPool, Buffer->Buffer);
        --SendData->WsaBufferCount;
    } else {
        TailBuffer += SendData->WsaBuffers[SendData->WsaBufferCount - 1].len;
        CXPLAT_DBG_ASSERT(Buffer->Buffer == (uint8_t*)TailBuffer);

        if (SendData->WsaBuffers[SendData->WsaBufferCount - 1].len == 0) {
            CxPlatPoolFree(SendData->BufferPool, Buffer->Buffer);
            --SendData->WsaBufferCount;
        }

        SendData->ClientBuffer.buf = NULL;
        SendData->ClientBuffer.len = 0;
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
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ ULONG IoResult
    )
{
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSASendMsg completion");
    }

    if (SocketProc->Parent->Type != CXPLAT_SOCKET_UDP) {
        SocketProc->Parent->Datapath->TcpHandlers.SendComplete(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            IoResult,
            SendData->TotalSize);
    }

    CxPlatSendDataFree(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSendInline(
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath;
    CXPLAT_SOCKET_PROC* SocketProc;
    CXPLAT_SOCKET* Socket;
    int Result;
    DWORD BytesSent;

    SocketProc = SendData->SocketProc;
    Datapath = SocketProc->Parent->Datapath;
    Socket = SocketProc->Parent;

    if (SocketProc->RioSendCount == RIO_SEND_QUEUE_DEPTH) {
        CxPlatListInsertTail(&SocketProc->RioSendOverflow, &SendData->RioOverflowEntry);
        return QUIC_STATUS_PENDING;
    }

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->TotalSize,
        SendData->WsaBufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(SendData->MappedRemoteAddress), &SendData->MappedRemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

    WSAMSG WSAMhdr;
    WSAMhdr.dwFlags = 0;
    if (Socket->HasFixedRemoteAddress) {
        WSAMhdr.name = NULL;
        WSAMhdr.namelen = 0;
    } else {
        WSAMhdr.name = (LPSOCKADDR)&SendData->MappedRemoteAddress;
        WSAMhdr.namelen = sizeof(SendData->MappedRemoteAddress);
    }
    WSAMhdr.lpBuffers = SendData->WsaBuffers;
    WSAMhdr.dwBufferCount = SendData->WsaBufferCount;
    WSAMhdr.Control.buf = RIO_CMSG_BASE_SIZE + SendData->CtrlBuf;
    WSAMhdr.Control.len = 0;

    PWSACMSGHDR CMsg = NULL;
    if (LocalAddress->si_family == QUIC_ADDRESS_FAMILY_INET) {

        if (!Socket->HasFixedRemoteAddress) {
            WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(IN_PKTINFO));
            CMsg = WSA_CMSG_FIRSTHDR(&WSAMhdr);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));
            PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
        }

        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(INT));
        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        CMsg->cmsg_level = IPPROTO_IP;
        CMsg->cmsg_type = IP_ECN;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
        *(PINT)WSA_CMSG_DATA(CMsg) = SendData->ECN;

    } else {

        if (!Socket->HasFixedRemoteAddress) {
            WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(IN6_PKTINFO));
            CMsg = WSA_CMSG_FIRSTHDR(&WSAMhdr);
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));
            PIN6_PKTINFO PktInfo6 = (PIN6_PKTINFO)WSA_CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
        }

        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(INT));
        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        CMsg->cmsg_level = IPPROTO_IPV6;
        CMsg->cmsg_type = IPV6_ECN;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
        *(PINT)WSA_CMSG_DATA(CMsg) = SendData->ECN;
    }

    if (SendData->SegmentSize > 0) {
        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(DWORD));
        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        CMsg->cmsg_level = IPPROTO_UDP;
        CMsg->cmsg_type = UDP_SEND_MSG_SIZE;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD));
        *(PDWORD)WSA_CMSG_DATA(CMsg) = SendData->SegmentSize;
    }

    //
    // Start the async send.
    //
    CxPlatDatapathSqeInitialize(&SendData->Sqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatStartDatapathIo(&SendData->Sqe, DATAPATH_IO_SEND);

    if (Socket->Type == CXPLAT_SOCKET_UDP) {
        if (Socket->UseRio) {
            RIO_BUF RemoteAddr = {0};
            RIO_BUF Control = {0};
            PRIO_CMSG_BUFFER RioCmsg = (PRIO_CMSG_BUFFER)SendData->CtrlBuf;

            RemoteAddr.BufferId = SendData->RioBufferId;
            RemoteAddr.Offset = FIELD_OFFSET(CXPLAT_SEND_DATA, MappedRemoteAddress);
            RemoteAddr.Length = sizeof(SendData->MappedRemoteAddress);

            RioCmsg->TotalLength = RIO_CMSG_BASE_SIZE + WSAMhdr.Control.len;
            Control.BufferId = SendData->RioBufferId;
            Control.Offset = FIELD_OFFSET(CXPLAT_SEND_DATA, CtrlBuf);
            Control.Length = RioCmsg->TotalLength;

            //
            // RIO does not yet natively support sending more than one buffer at
            // a time. Since this module also does not implement send batching,
            // instead of correctly reference counting buffers (adding runtime
            // and code complexity cost) simply assert exactly one send buffer
            // is requested.
            //
            CXPLAT_STATIC_ASSERT(CXPLAT_MAX_BATCH_SEND == 1, "RIO doesn't support batched sends");
            CXPLAT_FRE_ASSERT(SendData->WsaBufferCount == 1);

            for (UINT8 i = 0; i < SendData->WsaBufferCount; i++) {
                RIO_BUF Data = {0};
                CXPLAT_RIO_SEND_BUFFER_HEADER* SendHeader =
                    RioSendBufferHeaderFromBuffer(SendData->WsaBuffers[i].buf);

                Data.BufferId = SendHeader->RioBufferId;
                Data.Length = SendData->WsaBuffers[i].len;
                SendHeader->IoType = DATAPATH_IO_RIO_SEND;
                SendHeader->SendData = SendData;

                if (!Datapath->RioDispatch.RIOSendEx(
                        SocketProc->RioRq, &Data, 1, NULL, &RemoteAddr,
                        &Control, NULL, 0, &SendHeader->IoType)) {
                    int WsaError = WSAGetLastError();
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        SocketProc->Parent,
                        WsaError,
                        "RIOSendEx");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Exit;
                }

                SocketProc->RioSendCount++;

                CxPlatSocketArmRioNotify(SocketProc);
            }

            WSASetLastError(WSA_IO_PENDING);
            Result = SOCKET_ERROR;
        } else {
            Result =
                Datapath->WSASendMsg(
                    SocketProc->Socket,
                    &WSAMhdr,
                    0,
                    &BytesSent,
                    &SendData->Sqe.DatapathSqe.Sqe.Overlapped,
                    NULL);
        }
    } else {
        Result =
            WSASend(
                SocketProc->Socket,
                SendData->WsaBuffers,
                SendData->WsaBufferCount,
                &BytesSent,
                0,
                &SendData->Sqe.DatapathSqe.Sqe.Overlapped,
                NULL);
    }

    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                WsaError,
                "WSASendMsg");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Exit;
        }
    } else {
        //
        // Completed synchronously.
        //
        CxPlatSendDataComplete(
            SocketProc,
            SendData,
            QUIC_STATUS_SUCCESS);
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        CxPlatSendDataFree(SendData);
    }

    return Status;
}

QUIC_STATUS
CxPlatSocketSendEnqueue(
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;

    CxPlatCopyMemory(
        &SendData->LocalAddress,
        &Route->LocalAddress,
        sizeof(Route->LocalAddress));

    CxPlatDatapathSqeInitialize(&SendData->Sqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatStartDatapathIo(&SendData->Sqe, DATAPATH_IO_QUEUE_SEND);
    return CxPlatSocketEnqueueSqe(SocketProc, &SendData->Sqe, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL && Route != NULL && SendData != NULL);

    CXPLAT_DBG_ASSERT(Route->Queue);
    CXPLAT_SOCKET_PROC* SocketProc = Route->Queue;

    SendData->SocketProc = SocketProc;
    CxPlatSendDataFinalizeSendBuffer(SendData);

    //
    // Map V4 address to dual-stack socket format.
    //
    CxPlatConvertToMappedV6(&Route->RemoteAddress, &SendData->MappedRemoteAddress);

    if (Socket->UseRio) {
        //
        // Currently RIO always queues sends.
        //
        return CxPlatSocketSendEnqueue(Route, SendData);
    }

    if ((Socket->Type != CXPLAT_SOCKET_UDP) ||
        !(SendData->SendFlags & CXPLAT_SEND_FLAGS_MAX_THROUGHPUT)) {
        //
        // Currently TCP always sends inline.
        //
        return
            CxPlatSocketSendInline(
                &Route->LocalAddress,
                SendData);
    }

    return CxPlatSocketSendEnqueue(Route, SendData);
}

void
CxPlatDataPathSocketProcessQueuedSend(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
    CXPLAT_SEND_DATA* SendData = CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe);
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;

    if (CxPlatRundownAcquire(&SocketProc->UpcallRundown)) {
        CxPlatSocketSendInline(
            &SendData->LocalAddress,
            SendData);
        CxPlatRundownRelease(&SocketProc->UpcallRundown);
    } else {
        CxPlatSendDataComplete(
            SocketProc,
            SendData,
            WSAESHUTDOWN);
    }
}

void
CxPlatDataPathStartRioSends(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    while (!CxPlatListIsEmpty(&SocketProc->RioSendOverflow) &&
        SocketProc->RioSendCount < RIO_SEND_QUEUE_DEPTH) {
        CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&SocketProc->RioSendOverflow);
        CXPLAT_SEND_DATA* SendData = CONTAINING_RECORD(Entry, CXPLAT_SEND_DATA, RioOverflowEntry);

        //
        // RIO always queues sends.
        //
        CxPlatSocketSendInline(
            &SendData->LocalAddress,
            SendData);
    }
}

void
CxPlatDataPathSocketProcessSendCompletion(
    _In_ DATAPATH_IO_SQE* Sqe,
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SEND_DATA* SendData = CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe);
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;

    CxPlatSendDataComplete(
        SocketProc,
        SendData,
        RtlNtStatusToDosError((NTSTATUS)Cqe->Internal));
}

void
CxPlatDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN: {
        CXPLAT_SOCKET_PROC* SocketProc =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), CXPLAT_SOCKET_PROC, ShutdownSqe);
        if (CxPlatRefDecrement(&SocketProc->RefCount)) {
            CxPlatSocketContextUninitializeComplete(SocketProc);
        }
        break;
    }
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        DATAPATH_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_IO_SQE, DatapathSqe);
        DATAPATH_IO_TYPE IoType = Sqe->IoType;

        CxPlatStopDatapathIo(Sqe);

        switch (IoType) {
        case DATAPATH_IO_RECV:
            CxPlatDataPathSocketProcessReceiveCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_SEND:
            CxPlatDataPathSocketProcessSendCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_QUEUE_SEND:
            CxPlatDataPathSocketProcessQueuedSend(Sqe, Cqe);
            break;

        case DATAPATH_IO_ACCEPTEX:
            CxPlatDataPathSocketProcessAcceptCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_CONNECTEX:
            CxPlatDataPathSocketProcessConnectCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_RIO_NOTIFY:
            CxPlatDataPathSocketProcessRioCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_RECV_FAILURE:
            CxPlatDataPathSocketProcessReceiveFailure(Sqe, Cqe);
            break;

        default:
            CXPLAT_DBG_ASSERT(FALSE);
            break;
        }
        break;
    }
    default: CXPLAT_DBG_ASSERT(FALSE); break;
    }
}

#ifdef QUIC_FUZZER

__declspec(noinline)
void
CxPlatFuzzerReceiveInject(
    _In_ const QUIC_ADDR *SourceAddress,
    _In_reads_(PacketLength) uint8_t *PacketData,
    _In_ uint16_t PacketLength
    )
{
    if (PacketLength > QUIC_FUZZ_BUFFER_MAX) {
        return;
    }

    CXPLAT_SOCKET_PROC* Socket = (CXPLAT_SOCKET_PROC*)MsQuicFuzzerContext.Socket;

    if (!Socket) {
        return;
    }

    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
        CxPlatSocketAllocRecvContext(Socket->SocketProc);
    if (!RecvContext) {
        return;
    }

    RecvContext->Route.RemoteAddress = *SourceAddress;

    CXPLAT_RECV_DATA* Datagram = (CXPLAT_RECV_DATA*)(RecvContext + 1);

    Datagram->Next = NULL;
    Datagram->BufferLength = PacketLength;
    Datagram->Route = &RecvContext->Route;
    Datagram->Allocated = TRUE;
    Datagram->QueuedOnConnection = FALSE;
    Datagram->Buffer = ((PUCHAR)RecvContext) + Socket->Socket->Datapath->RecvPayloadOffset;

    memcpy(Datagram->Buffer, PacketData, Datagram->BufferLength);

    if (MsQuicFuzzerContext.RecvCallback) {
        MsQuicFuzzerContext.RecvCallback(
            MsQuicFuzzerContext.CallbackContext,
            Datagram->Buffer,
            Datagram->BufferLength);
    }

    Socket->Socket->Datapath->RecvHandler(
            Socket->Socket,
            Socket->Socket->ClientContext,
            Datagram);
}

int
CxPlatFuzzerRecvMsg(
    _In_ SOCKET s,
    _Inout_ LPWSAMSG lpMsg,
    _Out_ LPDWORD lpdwNumberOfBytesRecvd,
    _In_ LPWSAOVERLAPPED lpOverlapped,
    _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    if (!MsQuicFuzzerContext.RedirectDataPath) {
        CXPLAT_DBG_ASSERT(MsQuicFuzzerContext.RealRecvMsg);

        return ((LPFN_WSARECVMSG)MsQuicFuzzerContext.RealRecvMsg)(
            s,
            lpMsg,
            lpdwNumberOfBytesRecvd,
            lpOverlapped,
            lpCompletionRoutine);
    }

    *lpdwNumberOfBytesRecvd = 0;

    WSASetLastError(WSA_IO_PENDING);

    return SOCKET_ERROR;
}

int
CxPlatFuzzerSendMsg(
    _In_ SOCKET s,
    _In_ LPWSAMSG lpMsg,
    _In_ DWORD dwFlags,
    _Out_ LPDWORD lpNumberOfBytesSent,
    _In_ LPWSAOVERLAPPED lpOverlapped,
    _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    if (MsQuicFuzzerContext.SendCallback) {
        for (DWORD i = 0; i < lpMsg->dwBufferCount; i++) {
            MsQuicFuzzerContext.SendCallback(
                MsQuicFuzzerContext.CallbackContext,
                (uint8_t*)lpMsg->lpBuffers[i].buf,
                lpMsg->lpBuffers[i].len);
        }
    }

    if (!MsQuicFuzzerContext.RedirectDataPath) {
        CXPLAT_DBG_ASSERT(MsQuicFuzzerContext.RealSendMsg);

        return ((LPFN_WSASENDMSG)MsQuicFuzzerContext.RealSendMsg)(
            s,
            lpMsg,
            dwFlags,
            lpNumberOfBytesSent,
            lpOverlapped,
            lpCompletionRoutine);
    }

    return 0;
}

#endif // QUIC_FUZZER
