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


//
// Contains all the info for a single RX IO operation. Multiple RX packets may
// come from a single IO operation.
//
typedef struct DATAPATH_RX_IO_BLOCK {
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
    // Contains the input and output message data.
    //
    WSAMSG WsaMsgHdr;
    WSABUF WsaControlBuf;

    //
    // Contains the control data resulting from the receive.
    //
    char ControlBuf[
        RIO_CMSG_BASE_SIZE +
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(DWORD)) +         // UDP_COALESCED_INFO
        WSA_CMSG_SPACE(sizeof(INT))             // IP_ECN
        ];

} DATAPATH_RX_IO_BLOCK;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) DATAPATH_RX_PACKET {
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
    CXPLAT_SEND_DATA_COMMON;
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
    CXPLAT_DATAPATH_PARTITION* Owner;

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


_IRQL_requires_max_(PASSIVE_LEVEL)
void
SocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    );

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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketContextRelease(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

VOID
CxPlatStartDatapathIo(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
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
    CxPlatRefIncrement(&SocketProc->RefCount);
}

VOID
CxPlatCancelDatapathIo(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Inout_ DATAPATH_IO_SQE* Sqe
    )
{
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.CqeType == CXPLAT_CQE_TYPE_SOCKET_IO);
    CXPLAT_DBG_ASSERT(Sqe->DatapathSqe.Sqe.UserData == &Sqe->DatapathSqe);
    CXPLAT_DBG_ASSERT(Sqe->IoType > DATAPATH_IO_SIGNATURE && Sqe->IoType < DATAPATH_IO_MAX);
    DBG_UNREFERENCED_PARAMETER(Sqe);
#if DEBUG
    Sqe->IoType = 0;
#endif
    CxPlatSocketContextRelease(SocketProc);
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
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ ULONG IoResult
    );

BOOLEAN
CxPlatDataPathRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock,
    _In_ ULONG IoResult,
    _In_ uint16_t BytesTransferred
    );

void
CxPlatFreeRxIoBlock(
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock
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

    Datapath->Features |= CXPLAT_DATAPATH_FEATURE_TCP;

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
DataPathInitialize(
    _In_ uint32_t ClientRecvDataLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH** NewDatapath
    )
{
    int WsaError;
    QUIC_STATUS Status;
    WSADATA WsaData;
    uint32_t PartitionCount = CxPlatProcMaxCount();
    uint32_t DatapathLength;
    CXPLAT_DATAPATH* Datapath = NULL;
    BOOLEAN WsaInitialized = FALSE;

    if (NewDatapath == NULL) {
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
        PartitionCount = Config->ProcessorCount;
    }

    DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        PartitionCount * sizeof(CXPLAT_DATAPATH_PARTITION);

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

    if (Config && (Config->Flags & QUIC_EXECUTION_CONFIG_FLAG_QTIP)) {
        Datapath->UseTcp = TRUE;
    }

    Datapath->PartitionCount = (uint16_t)PartitionCount;
    CxPlatRefInitializeEx(&Datapath->RefCount, Datapath->PartitionCount);
    Datapath->UseRio = Config && !!(Config->Flags & QUIC_EXECUTION_CONFIG_FLAG_RIO);

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
            sizeof(DATAPATH_RX_PACKET) +
            ClientRecvDataLength,
            PVOID);
    Datapath->RecvPayloadOffset =
        sizeof(DATAPATH_RX_IO_BLOCK) +
        MessageCount * Datapath->DatagramStride;

    const uint32_t RecvDatagramLength =
        Datapath->RecvPayloadOffset +
            ((Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
                MAX_URO_PAYLOAD_LENGTH : MAX_RECV_PAYLOAD_LENGTH);

    for (uint16_t i = 0; i < Datapath->PartitionCount; i++) {

        Datapath->Partitions[i].Datapath = Datapath;
        Datapath->Partitions[i].PartitionIndex = (uint16_t)i;
        Datapath->Partitions[i].EventQ = CxPlatWorkerGetEventQ(i);
        CxPlatRefInitialize(&Datapath->Partitions[i].RefCount);

        CxPlatPoolInitialize(
            FALSE,
            sizeof(CXPLAT_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            &Datapath->Partitions[i].SendDataPool);

        CxPlatPoolInitializeEx(
            FALSE,
            sizeof(CXPLAT_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            0,
            RioSendDataAllocate,
            RioSendDataFree,
            &Datapath->Partitions[i].RioSendDataPool);

        CxPlatPoolInitialize(
            FALSE,
            MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            &Datapath->Partitions[i].SendBufferPool);

        CxPlatPoolInitialize(
            FALSE,
            CXPLAT_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            &Datapath->Partitions[i].LargeSendBufferPool);

        CxPlatPoolInitializeEx(
            FALSE,
            MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            RIO_MAX_SEND_POOL_SIZE,
            RioSendBufferAllocate,
            RioSendBufferFree,
            &Datapath->Partitions[i].RioSendBufferPool);

        CxPlatPoolInitializeEx(
            FALSE,
            CXPLAT_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            RIO_MAX_SEND_POOL_SIZE,
            RioSendLargeBufferAllocate,
            RioSendBufferFree,
            &Datapath->Partitions[i].RioLargeSendBufferPool);

        CxPlatPoolInitialize(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->Partitions[i].RecvDatagramPool);

        CxPlatPoolInitializeEx(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            RIO_MAX_RECV_POOL_SIZE,
            RioRecvBufferAllocate,
            RioRecvBufferFree,
            &Datapath->Partitions[i].RioRecvPool);
    }

    CXPLAT_FRE_ASSERT(CxPlatRundownAcquire(&CxPlatWorkerRundown));
    *NewDatapath = Datapath;
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
        CXPLAT_DBG_ASSERT(!Datapath->Freed);
        CXPLAT_DBG_ASSERT(Datapath->Uninitialized);
        Datapath->Freed = TRUE;
        CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
        WSACleanup();
        CxPlatRundownRelease(&CxPlatWorkerRundown);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatProcessorContextRelease(
    _In_ CXPLAT_DATAPATH_PARTITION* DatapathProc
    )
{
    if (CxPlatRefDecrement(&DatapathProc->RefCount)) {
        CXPLAT_DBG_ASSERT(!DatapathProc->Uninitialized);
        DatapathProc->Uninitialized = TRUE;
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
DataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath != NULL) {
        CXPLAT_DBG_ASSERT(!Datapath->Uninitialized);
        Datapath->Uninitialized = TRUE;
        const uint16_t PartitionCount = Datapath->PartitionCount;
        for (uint16_t i = 0; i < PartitionCount; i++) {
            CxPlatProcessorContextRelease(&Datapath->Partitions[i]);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
DataPathUpdateConfig(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Config);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
DataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return Datapath->Features;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
DataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

void
CxPlatSocketArmRioNotify(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    if (!SocketProc->RioNotifyArmed) {
        SocketProc->RioNotifyArmed = TRUE;
        CxPlatStartDatapathIo(SocketProc, &SocketProc->RioSqe, DATAPATH_IO_RIO_NOTIFY);
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
SocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status;
    const BOOLEAN IsServerSocket = Config->RemoteAddress == NULL;
    const BOOLEAN NumPerProcessorSockets = IsServerSocket && Datapath->PartitionCount > 1;
    const uint16_t SocketCount = NumPerProcessorSockets ? (uint16_t)CxPlatProcMaxCount() : 1;
    INET_PORT_RESERVATION_INSTANCE PortReservation;
    int Result, Option;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL || Config->Flags & CXPLAT_SOCKET_FLAG_PCP);
    CXPLAT_DBG_ASSERT(IsServerSocket || Config->PartitionIndex < Datapath->PartitionCount);

    const uint32_t RawSocketLength = CxPlatGetRawSocketSize() + SocketCount * sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET_RAW* RawSocket = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CXPLAT_SOCKET* Socket = CxPlatRawToSocket(RawSocket);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = Config->CallbackContext;
    Socket->NumPerProcessorSockets = NumPerProcessorSockets;
    Socket->HasFixedRemoteAddress = (Config->RemoteAddress != NULL);
    Socket->Type = CXPLAT_SOCKET_UDP;
    Socket->UseRio = Datapath->UseRio;
    Socket->UseTcp = Datapath->UseTcp;
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

    if (Datapath->UseTcp) {
        //
        // Skip normal socket settings to use AuxSocket in raw socket
        //
        goto Skip;
    }

    Socket->RecvBufLen =
        (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
            MAX_URO_PAYLOAD_LENGTH :
            Socket->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;

    for (uint16_t i = 0; i < SocketCount; i++) {
        CxPlatRefInitialize(&Socket->PerProcSockets[i].RefCount);
        Socket->PerProcSockets[i].Parent = Socket;
        Socket->PerProcSockets[i].Socket = INVALID_SOCKET;
        CxPlatDatapathSqeInitialize(
            &Socket->PerProcSockets[i].IoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        CxPlatRundownInitialize(&Socket->PerProcSockets[i].RundownRef);
        Socket->PerProcSockets[i].RioCq = RIO_INVALID_CQ;
        Socket->PerProcSockets[i].RioRq = RIO_INVALID_RQ;
        CxPlatListInitializeHead(&Socket->PerProcSockets[i].RioSendOverflow);
    }

    for (uint16_t i = 0; i < SocketCount; i++) {

        CXPLAT_SOCKET_PROC* SocketProc = &Socket->PerProcSockets[i];
        const uint16_t PartitionIndex =
            Config->RemoteAddress ?
                Config->PartitionIndex :
                i % Datapath->PartitionCount;
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

        CXPLAT_DBG_ASSERT(PartitionIndex < Datapath->PartitionCount);
        SocketProc->DatapathProc = &Datapath->Partitions[PartitionIndex];
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
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

Skip:

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

    if (!Socket->UseTcp) {
        for (uint16_t i = 0; i < SocketCount; i++) {
            CxPlatDataPathStartReceiveAsync(&Socket->PerProcSockets[i]);
            Socket->PerProcSockets[i].IoStarted = TRUE;
        }
    }

    Socket = NULL;
    RawSocket = NULL;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (RawSocket != NULL) {
        SocketDelete(CxPlatRawToSocket(RawSocket));
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
    uint16_t PartitionIndex;

    CXPLAT_DBG_ASSERT(Datapath->TcpHandlers.Receive != NULL);

    CXPLAT_SOCKET_PROC* SocketProc = NULL;
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET_RAW* RawSocket = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CXPLAT_SOCKET* Socket = CxPlatRawToSocket(RawSocket);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = TRUE;
    Socket->Type = Type;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    PartitionIndex =
        RemoteAddress ?
            ((uint16_t)(CxPlatProcCurrentNumber() % Datapath->PartitionCount)) : 0;
    Socket->Mtu = CXPLAT_MAX_MTU;
    Socket->RecvBufLen =
        (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
            MAX_URO_PAYLOAD_LENGTH : MAX_RECV_PAYLOAD_LENGTH;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);

    SocketProc = &Socket->PerProcSockets[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    CxPlatDatapathSqeInitialize(&SocketProc->IoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatRundownInitialize(&SocketProc->RundownRef);
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
            &Datapath->Partitions[PartitionIndex];
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

            CxPlatStartDatapathIo(SocketProc, &SocketProc->IoSqe, DATAPATH_IO_CONNECTEX);

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
                    CxPlatCancelDatapathIo(SocketProc, &SocketProc->IoSqe);
                    goto Error;
                }
            } else {
                //
                // Manually post IO completion if connect completed synchronously.
                //
                Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesReturned);
                if (QUIC_FAILED(Status)) {
                    CxPlatCancelDatapathIo(SocketProc, &SocketProc->IoSqe);
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
    RawSocket = NULL;

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (RawSocket != NULL) {
        SocketDelete(CxPlatRawToSocket(RawSocket));
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
            Socket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateTcpListener(
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
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET_RAW* RawSocket = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    CXPLAT_SOCKET* Socket = CxPlatRawToSocket(RawSocket);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(0, NULL));

    ZeroMemory(RawSocket, RawSocketLength);
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

    SocketProc = &Socket->PerProcSockets[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    CxPlatDatapathSqeInitialize(&SocketProc->IoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatRundownInitialize(&SocketProc->RundownRef);
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

    SocketProc->DatapathProc = &Datapath->Partitions[0]; // TODO - Something better?
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
    RawSocket = NULL;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (RawSocket != NULL) {
        SocketDelete(CxPlatRawToSocket(RawSocket));
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketRelease(
    _In_ CXPLAT_SOCKET* Socket
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
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

    CXPLAT_DBG_ASSERT(!Socket->Uninitialized);
    Socket->Uninitialized = TRUE;

    if (Socket->UseTcp) {
        CxPlatSocketRelease(Socket);
        return;
    }

    const uint16_t SocketCount =
        Socket->NumPerProcessorSockets ? (uint16_t)CxPlatProcMaxCount() : 1;
    for (uint16_t i = 0; i < SocketCount; ++i) {
        CxPlatSocketContextUninitialize(&Socket->PerProcSockets[i]);
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
        CXPLAT_DBG_ASSERT(!Socket->Freed);
        CXPLAT_DBG_ASSERT(Socket->Uninitialized);
        Socket->Freed = TRUE;
        CXPLAT_FREE(CxPlatSocketToRaw(Socket), QUIC_POOL_SOCKET);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketContextRelease(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CXPLAT_DBG_ASSERT(!SocketProc->Freed);
    if (CxPlatRefDecrement(&SocketProc->RefCount)) {
        if (SocketProc->Parent->Type != CXPLAT_SOCKET_TCP_LISTENER) {
            CXPLAT_DBG_ASSERT(SocketProc->RioRecvCount == 0);
            CXPLAT_DBG_ASSERT(SocketProc->RioSendCount == 0);
            CXPLAT_DBG_ASSERT(SocketProc->RioNotifyArmed == FALSE);

            while (!CxPlatListIsEmpty(&SocketProc->RioSendOverflow)) {
                CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&SocketProc->RioSendOverflow);
                CxPlatSendDataComplete(
                    CONTAINING_RECORD(Entry, CXPLAT_SEND_DATA, RioOverflowEntry),
                    WSA_OPERATION_ABORTED);
            }

            if (SocketProc->RioCq != RIO_INVALID_CQ) {
                SocketProc->DatapathProc->Datapath->RioDispatch.
                    RIOCloseCompletionQueue(SocketProc->RioCq);
                SocketProc->RioCq = RIO_INVALID_CQ;
            }
        } else {
            if (SocketProc->AcceptSocket != NULL) {
                SocketDelete(SocketProc->AcceptSocket);
                SocketProc->AcceptSocket = NULL;
            }
        }

        CxPlatRundownUninitialize(&SocketProc->RundownRef);

        QuicTraceLogVerbose(
            DatapathSocketContextComplete,
            "[data][%p] Socket context shutdown",
            SocketProc);

        if (SocketProc->DatapathProc) {
            CxPlatProcessorContextRelease(SocketProc->DatapathProc);
        }

        SocketProc->Freed = TRUE;
        CxPlatSocketRelease(SocketProc->Parent);
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
        SocketProc->Uninitialized = TRUE;
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
        CxPlatSocketContextRelease(SocketProc);
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
    // Block on all outstanding references. This ensure that there are no more
    // calls on the Socket, and that the app doesn't get any more upcalls after
    // this.
    //
    CxPlatRundownReleaseAndWait(&SocketProc->RundownRef);
    SocketProc->Uninitialized = TRUE;

    //
    // Close the socket handle, which will cancel all outstanding IO. The
    // processing of those completions will release their references on the
    // context.
    //
    if (closesocket(SocketProc->Socket) == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc,
            WsaError,
            "closesocket");
    }

    //
    // Finally, release the "main" reference on the context from the parent. If
    // there are no outstanding IOs, then the context will be cleaned up inline.
    //
    CxPlatSocketContextRelease(SocketProc);
}

void*
RioRecvBufferAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PARTITION, RioRecvPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;

    DATAPATH_RX_IO_BLOCK* IoBlock = CxPlatLargeAlloc(Size, Tag);

    if (IoBlock != NULL) {
        IoBlock->RioBufferId =
            Datapath->RioDispatch.RIORegisterBuffer((char*)IoBlock, Size);

        if (IoBlock->RioBufferId == RIO_INVALID_BUFFERID) {
            CxPlatLargeFree(IoBlock, Tag);
            IoBlock = NULL;
        }
    }

    return IoBlock;
}

void
RioRecvBufferFree(
    _In_ void* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    DATAPATH_RX_IO_BLOCK* IoBlock = Entry;
    CXPLAT_DATAPATH_PARTITION* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PARTITION, RioRecvPool);
    CXPLAT_DATAPATH* Datapath = DatapathProc->Datapath;

    CXPLAT_DBG_ASSERT(IoBlock->RioBufferId != RIO_INVALID_BUFFERID);
    Datapath->RioDispatch.RIODeregisterBuffer(IoBlock->RioBufferId);
    CxPlatLargeFree(IoBlock, Tag);
}

DATAPATH_RX_IO_BLOCK*
CxPlatSocketAllocRxIoBlock(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathProc = SocketProc->DatapathProc;
    DATAPATH_RX_IO_BLOCK* IoBlock;
    CXPLAT_POOL* OwningPool;

    if (SocketProc->Parent->UseRio) {
        OwningPool = &DatapathProc->RioRecvPool;
    } else {
        OwningPool = &DatapathProc->RecvDatagramPool;
    }

    IoBlock = CxPlatPoolAlloc(OwningPool);

    if (IoBlock != NULL) {
        IoBlock->Route.State = RouteResolved;
        IoBlock->OwningPool = OwningPool;
        IoBlock->ReferenceCount = 0;
        IoBlock->SocketProc = SocketProc;
#if DEBUG
        IoBlock->Sqe.IoType = 0;
#endif
    }

    return IoBlock;
}

void
CxPlatSocketFreeRxIoBlock(
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock
    )
{
    CxPlatPoolFree(IoBlock->OwningPool, IoBlock);
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
                (CXPLAT_SOCKET**)&ListenerSocketProc->AcceptSocket);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    CxPlatStartDatapathIo(ListenerSocketProc, &ListenerSocketProc->IoSqe, DATAPATH_IO_ACCEPTEX);

    Result =
        Datapath->AcceptEx(
            ListenerSocketProc->Socket,
            ListenerSocketProc->AcceptSocket->PerProcSockets[0].Socket,
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
            CxPlatCancelDatapathIo(ListenerSocketProc, &ListenerSocketProc->IoSqe);
            goto Error;
        }
    } else {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(ListenerSocketProc, &ListenerSocketProc->IoSqe, BytesRecv);
        if (QUIC_FAILED(Status)) {
            CxPlatCancelDatapathIo(ListenerSocketProc, &ListenerSocketProc->IoSqe);
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

    if (!CxPlatRundownAcquire(&ListenerSocketProc->RundownRef)) {
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS) {
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket != NULL);
        CXPLAT_SOCKET_PROC* AcceptSocketProc = &ListenerSocketProc->AcceptSocket->PerProcSockets[0];
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent);
        DWORD BytesReturned;
        SOCKET_PROCESSOR_AFFINITY RssAffinity = { 0 };
        uint16_t PartitionIndex = 0;

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

        CXPLAT_DATAPATH* Datapath = ListenerSocketProc->Parent->Datapath;

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
            PartitionIndex =
                ((uint16_t)CxPlatProcessorGroupInfo[RssAffinity.Processor.Group].Offset +
                (uint16_t)RssAffinity.Processor.Number) % Datapath->PartitionCount;
        }

        AcceptSocketProc->DatapathProc =
            &Datapath->Partitions[PartitionIndex]; // TODO - Something better?
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
        Datapath->TcpHandlers.Accept(
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
        SocketDelete(ListenerSocketProc->AcceptSocket);
        ListenerSocketProc->AcceptSocket = NULL;
    }

    //
    // Try to start a new accept.
    //
    (void)CxPlatSocketStartAccept(ListenerSocketProc);

    CxPlatRundownRelease(&ListenerSocketProc->RundownRef);
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

    if (!CxPlatRundownAcquire(&SocketProc->RundownRef)) {
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

    CxPlatRundownRelease(&SocketProc->RundownRef);
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

        DATAPATH_RX_IO_BLOCK* IoBlock =
            CxPlatSocketAllocRxIoBlock(SocketProc);
        if (IoBlock == NULL) {
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

        Data.BufferId = IoBlock->RioBufferId;
        Data.Offset = Datapath->RecvPayloadOffset;
        Data.Length = SocketProc->Parent->RecvBufLen;
        RemoteAddr.BufferId = IoBlock->RioBufferId;
        RemoteAddr.Offset =
            FIELD_OFFSET(DATAPATH_RX_IO_BLOCK, Route.RemoteAddress);
        RemoteAddr.Length = sizeof(IoBlock->Route.RemoteAddress);
        Control.BufferId = IoBlock->RioBufferId;
        Control.Offset = FIELD_OFFSET(DATAPATH_RX_IO_BLOCK, ControlBuf);
        Control.Length = sizeof(IoBlock->ControlBuf);
        IoBlock->Sqe.IoType = DATAPATH_IO_RIO_RECV;

        if (!Datapath->RioDispatch.RIOReceiveEx(
                SocketProc->RioRq, &Data, 1, NULL, &RemoteAddr,
                &Control, NULL, RioFlags, &IoBlock->Sqe.IoType)) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                WsaError,
                "RIOReceiveEx");
            Status = HRESULT_FROM_WIN32(WsaError);
            CxPlatSocketFreeRxIoBlock(IoBlock);
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
    _Out_opt_ DATAPATH_RX_IO_BLOCK** SyncIoBlock
    )
{
    const CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;

    CXPLAT_DBG_ASSERT((SyncIoResult != NULL) == (SyncBytesReceived != NULL));
    CXPLAT_DBG_ASSERT((SyncIoResult != NULL) == (SyncIoBlock != NULL));
    CXPLAT_DBG_ASSERT(SocketProc->Parent->Type != CXPLAT_SOCKET_TCP_LISTENER);

    //
    // Get a receive buffer we can pass to WinSock.
    //
    DATAPATH_RX_IO_BLOCK* IoBlock =
        CxPlatSocketAllocRxIoBlock(SocketProc);
    if (IoBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Socket Receive Buffer",
            SocketProc->Parent->Datapath->RecvPayloadOffset + SocketProc->Parent->RecvBufLen);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    //
    // Initialize all the receive state before calling down to the socket. This
    // includes preparing the IO completion entry, the ancillary data buffers,
    // and adding a ref count for the outstanding receive packet that will be
    // held by the socket until it completes.
    //

    CxPlatDatapathSqeInitialize(&IoBlock->Sqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatStartDatapathIo(SocketProc, &IoBlock->Sqe, DATAPATH_IO_RECV);

    IoBlock->WsaControlBuf.buf = ((CHAR*)IoBlock) + Datapath->RecvPayloadOffset;
    IoBlock->WsaControlBuf.len = SocketProc->Parent->RecvBufLen;

    IoBlock->WsaMsgHdr.name = (PSOCKADDR)&IoBlock->Route.RemoteAddress;
    IoBlock->WsaMsgHdr.namelen = sizeof(IoBlock->Route.RemoteAddress);
    IoBlock->WsaMsgHdr.lpBuffers = &IoBlock->WsaControlBuf;
    IoBlock->WsaMsgHdr.dwBufferCount = 1;
    IoBlock->WsaMsgHdr.Control.buf = IoBlock->ControlBuf;
    IoBlock->WsaMsgHdr.Control.len = sizeof(IoBlock->ControlBuf);
    IoBlock->WsaMsgHdr.dwFlags = 0;

    //
    // Call the appropriate WinSock API to start the receive. It may complete
    // inline, in which it doesn't automatically queue the IO completion.
    // Depending on if the caller is prepared to handle completions
    // synchronously or not, we either queue the completion or return the
    // result.
    //

    int Result;
    DWORD BytesRecv = 0;
    if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP) {
        Result =
            SocketProc->Parent->Datapath->WSARecvMsg(
                SocketProc->Socket,
                &IoBlock->WsaMsgHdr,
                &BytesRecv,
                &IoBlock->Sqe.DatapathSqe.Sqe.Overlapped,
                NULL);
    } else {
        Result =
            WSARecv(
                SocketProc->Socket,
                &IoBlock->WsaControlBuf,
                1,
                &BytesRecv,
                &IoBlock->WsaMsgHdr.dwFlags,
                &IoBlock->Sqe.DatapathSqe.Sqe.Overlapped,
                NULL);
    }

    int WsaError = NO_ERROR;
    if (Result == SOCKET_ERROR) {
        WsaError = WSAGetLastError();
        CXPLAT_DBG_ASSERT(WsaError != NO_ERROR);
        if (WsaError == WSA_IO_PENDING) {
            return QUIC_STATUS_PENDING;
        }
        //
        // Update the SQE to indicate the failure.
        //
        if (SyncBytesReceived == NULL) {
            IoBlock->Sqe.IoType = DATAPATH_IO_RECV_FAILURE;
            BytesRecv = (DWORD)WsaError;
        }
    }

    if (SyncBytesReceived != NULL) {
        //
        // The receive completed inline (success or failure), and the caller is
        // prepared to handle it synchronously.
        //
        CxPlatStopInlineDatapathIo(&IoBlock->Sqe);
        CXPLAT_DBG_ASSERT(BytesRecv < UINT16_MAX);
        *SyncBytesReceived = (uint16_t)BytesRecv;
        *SyncIoResult = WsaError;
        *SyncIoBlock = IoBlock;
        return QUIC_STATUS_SUCCESS;
    }

    //
    // Manually queue the IO completion for the receive since the caller isn't
    // prepared to handle it synchronously.
    //
    QUIC_STATUS Status = CxPlatSocketEnqueueSqe(SocketProc, &IoBlock->Sqe, BytesRecv);
    if (QUIC_FAILED(Status)) {
        //
        // N.B. The above function generally can only fail if the OS failed to
        // allocate memory internally. There isn't much we can do at this point,
        // and this likely should simply be treated as a fatal error.
        //
        CXPLAT_DBG_ASSERT(FALSE); // We don't expect tests to hit this.
        CxPlatCancelDatapathIo(SocketProc, &IoBlock->Sqe);
        CxPlatSocketFreeRxIoBlock(IoBlock);
        return Status;
    }

    return QUIC_STATUS_PENDING;
}

_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
CxPlatSocketStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Out_opt_ ULONG* SyncIoResult,
    _Out_opt_ uint16_t* SyncBytesReceived,
    _Out_opt_ DATAPATH_RX_IO_BLOCK** SyncIoBlock
    )
{
    QUIC_STATUS Status;

    if (SocketProc->Parent->UseRio) {
        Status = CxPlatSocketStartRioReceives(SocketProc);
        CXPLAT_DBG_ASSERT(Status != QUIC_STATUS_SUCCESS);
    } else {
        Status =
            CxPlatSocketStartWinsockReceive(
                SocketProc, SyncIoResult, SyncBytesReceived, SyncIoBlock);
    }

    return Status;
}

BOOLEAN
CxPlatDataPathUdpRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock,
    _In_ ULONG IoResult,
    _In_ UINT16 NumberOfBytesTransferred
    )
{
    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        CxPlatSocketFreeRxIoBlock(IoBlock);
        return FALSE;
    }

    PSOCKADDR_INET LocalAddr = &IoBlock->Route.LocalAddress;
    PSOCKADDR_INET RemoteAddr = &IoBlock->Route.RemoteAddress;
    CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);
    IoBlock->Route.Queue = SocketProc;

    if (IsUnreachableErrorCode(IoResult)) {

        if (!SocketProc->Parent->PcpBinding) {
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

    } else if (IoResult == ERROR_MORE_DATA ||
        (IoResult == NO_ERROR && SocketProc->Parent->RecvBufLen < NumberOfBytesTransferred)) {
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

    } else if (IoResult == NO_ERROR) {

        if (NumberOfBytesTransferred == 0) {
            CXPLAT_DBG_ASSERT(FALSE); // Not expected in tests
            QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[data][%p] Dropping datagram with empty payload.",
                SocketProc->Parent);
            goto Drop;
        }

        CXPLAT_RECV_DATA* RecvDataChain = NULL;
        CXPLAT_RECV_DATA** DatagramChainTail = &RecvDataChain;

        CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
        CXPLAT_RECV_DATA* Datagram;
        PUCHAR RecvPayload = ((PUCHAR)IoBlock) + Datapath->RecvPayloadOffset;

        BOOLEAN FoundLocalAddr = FALSE;
        UINT16 MessageLength = NumberOfBytesTransferred;
        ULONG MessageCount = 0;
        BOOLEAN IsCoalesced = FALSE;
        INT ECN = 0;

        if (SocketProc->Parent->UseRio) {
            PRIO_CMSG_BUFFER RioRcvMsg = (PRIO_CMSG_BUFFER)IoBlock->ControlBuf;
            IoBlock->WsaMsgHdr.Control.buf = IoBlock->ControlBuf + RIO_CMSG_BASE_SIZE;
            IoBlock->WsaMsgHdr.Control.len = RioRcvMsg->TotalLength - RIO_CMSG_BASE_SIZE;
        }

        for (WSACMSGHDR* CMsg = CMSG_FIRSTHDR(&IoBlock->WsaMsgHdr);
            CMsg != NULL;
            CMsg = CMSG_NXTHDR(&IoBlock->WsaMsgHdr, CMsg)) {

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
            CXPLAT_DBG_ASSERT(FALSE); // Not expected in tests
            QuicTraceLogWarning(
                DatapathMissingInfo,
                "[data][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketProc->Parent);
            goto Drop;
        }

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketProc->Parent,
            NumberOfBytesTransferred,
            MessageLength,
            CASTED_CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= SocketProc->Parent->RecvBufLen);

        Datagram = (CXPLAT_RECV_DATA*)(IoBlock + 1);

        for ( ;
            NumberOfBytesTransferred != 0;
            NumberOfBytesTransferred -= MessageLength) {

            CXPLAT_CONTAINING_RECORD(
                Datagram, DATAPATH_RX_PACKET, Data)->IoBlock = IoBlock;

            if (MessageLength > NumberOfBytesTransferred) {
                //
                // The last message is smaller than all the rest.
                //
                MessageLength = NumberOfBytesTransferred;
            }

            Datagram->Next = NULL;
            Datagram->Buffer = RecvPayload;
            Datagram->BufferLength = MessageLength;
            Datagram->Route = &IoBlock->Route;
            Datagram->PartitionIndex =
                SocketProc->DatapathProc->PartitionIndex % SocketProc->DatapathProc->Datapath->PartitionCount;
            Datagram->TypeOfService = (uint8_t)ECN;
            Datagram->Allocated = TRUE;
            Datagram->Route->DatapathType = Datagram->DatapathType = CXPLAT_DATAPATH_TYPE_USER;
            Datagram->QueuedOnConnection = FALSE;

            RecvPayload += MessageLength;

            //
            // Add the datagram to the end of the current chain.
            //
            *DatagramChainTail = Datagram;
            DatagramChainTail = &Datagram->Next;
            IoBlock->ReferenceCount++;

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

        IoBlock = NULL;
        CXPLAT_DBG_ASSERT(RecvDataChain);

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
        CXPLAT_DBG_ASSERT(FALSE); // Not expected in test scenarios
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSARecvMsg completion");
    }

Drop:

    if (IoBlock != NULL) {
        CxPlatSocketFreeRxIoBlock(IoBlock);
    }

    return TRUE;
}

//
// Try to start a new receive. Returns TRUE if the receive completed inline.
//
BOOLEAN
CxPlatDataPathStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _Out_opt_ ULONG* IoResult,
    _Out_opt_ uint16_t* InlineBytesTransferred,
    _Out_opt_ DATAPATH_RX_IO_BLOCK** IoBlock
    )
{
    const int32_t MAX_RECV_RETRIES = 10;
    int32_t RetryCount = 0;
    QUIC_STATUS Status;
    do {
        Status =
            CxPlatSocketStartReceive(
                SocketProc,
                IoResult,
                InlineBytesTransferred,
                IoBlock);
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
    UpcallAcquired = CxPlatRundownAcquire(&SocketProc->RundownRef);

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
                DATAPATH_RX_IO_BLOCK* IoBlock =
                    CONTAINING_RECORD(IoType, DATAPATH_RX_IO_BLOCK, Sqe.IoType);

                if (UpcallAcquired) {
                    NeedReceive =
                        CxPlatDataPathRecvComplete(
                            SocketProc,
                            IoBlock,
                            Results[i].Status,
                            (UINT16)Results[i].BytesTransferred);
                } else {
                    CxPlatFreeRxIoBlock(IoBlock);
                }

                SocketProc->RioRecvCount--;
                break;

            case DATAPATH_IO_RIO_SEND:
                CXPLAT_RIO_SEND_BUFFER_HEADER* SendHeader =
                    CONTAINING_RECORD(IoType, CXPLAT_RIO_SEND_BUFFER_HEADER, IoType);
                CxPlatSendDataComplete(SendHeader->SendData, Results[i].Status);
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
        CxPlatRundownRelease(&SocketProc->RundownRef);
    }
}

BOOLEAN
CxPlatDataPathTcpRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock,
    _In_ ULONG IoResult,
    _In_ UINT16 NumberOfBytesTransferred
    )
{
    BOOLEAN NeedReceive = TRUE;

    PSOCKADDR_INET RemoteAddr = &IoBlock->Route.RemoteAddress;
    PSOCKADDR_INET LocalAddr = &IoBlock->Route.LocalAddress;

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
        CXPLAT_RECV_DATA* Data = (CXPLAT_RECV_DATA*)(IoBlock + 1);

        CXPLAT_CONTAINING_RECORD(Data, DATAPATH_RX_PACKET, Data)->IoBlock = IoBlock;

        Data->Next = NULL;
        Data->Buffer = ((PUCHAR)IoBlock) + Datapath->RecvPayloadOffset;
        Data->BufferLength = NumberOfBytesTransferred;
        Data->Route = &IoBlock->Route;
        Data->PartitionIndex = SocketProc->DatapathProc->PartitionIndex;
        Data->TypeOfService = 0;
        Data->Allocated = TRUE;
        Data->Route->DatapathType = Data->DatapathType = CXPLAT_DATAPATH_TYPE_USER;
        Data->QueuedOnConnection = FALSE;
        IoBlock->ReferenceCount++;
        IoBlock = NULL;

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

    if (IoBlock != NULL) {
        CxPlatSocketFreeRxIoBlock(IoBlock);
    }

    return NeedReceive;
}

void
CxPlatFreeRxIoBlock(
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock
    )
{
    CXPLAT_DBG_ASSERT(IoBlock->ReferenceCount == 0);
    CxPlatPoolFree(IoBlock->OwningPool, IoBlock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    LONG BatchedBufferCount = 0;
    DATAPATH_RX_IO_BLOCK* BatchIoBlock = NULL;

    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;

        DATAPATH_RX_IO_BLOCK* IoBlock =
            CXPLAT_CONTAINING_RECORD(Datagram, DATAPATH_RX_PACKET, Data)->IoBlock;

        if (BatchIoBlock == IoBlock) {
            BatchedBufferCount++;
        } else {
            if (BatchIoBlock != NULL &&
                InterlockedAdd(
                    (PLONG)&BatchIoBlock->ReferenceCount,
                    -BatchedBufferCount) == 0) {
                //
                // Clean up the data indication.
                //
                CxPlatSocketFreeRxIoBlock(BatchIoBlock);
            }

            BatchIoBlock = IoBlock;
            BatchedBufferCount = 1;
        }
    }

    if (BatchIoBlock != NULL &&
        InterlockedAdd(
            (PLONG)&BatchIoBlock->ReferenceCount,
            -BatchedBufferCount) == 0) {
        //
        // Clean up the data indication.
        //
        CxPlatSocketFreeRxIoBlock(BatchIoBlock);
    }
}

BOOLEAN
CxPlatDataPathRecvComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock,
    _In_ ULONG IoResult,
    _In_ uint16_t BytesTransferred
    )
{
    if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP) {
        return
            CxPlatDataPathUdpRecvComplete(
                SocketProc,
                IoBlock,
                IoResult,
                BytesTransferred);
    } else {
        return
            CxPlatDataPathTcpRecvComplete(
                SocketProc,
                IoBlock,
                IoResult,
                BytesTransferred);
    }
}

void
CxPlatDataPathSocketProcessReceive(
    _In_ DATAPATH_RX_IO_BLOCK* IoBlock,
    _In_ uint16_t BytesTransferred,
    _In_ ULONG IoResult
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = IoBlock->SocketProc;

    CXPLAT_DBG_ASSERT(!SocketProc->Freed);
    if (!CxPlatRundownAcquire(&SocketProc->RundownRef)) {
        //
        // Even though we can't process the completion (because the socket is
        // cleaning up) we still need to release the reference it has on the
        // context.
        //
        CxPlatSocketContextRelease(SocketProc);
        return;
    }

    CXPLAT_DBG_ASSERT(!SocketProc->Uninitialized);

    for (ULONG InlineReceiveCount = 10; InlineReceiveCount > 0; InlineReceiveCount--) {
        //
        // Process the receive completion and start the next receive. Since
        // there may be more data queued in AFD than this one completion, we
        // will process any new receive completions inline (up to 10). After
        // that, we will allow the receive to complete asynchronously.
        //
        CxPlatSocketContextRelease(SocketProc);
        if (!CxPlatDataPathRecvComplete(
                SocketProc, IoBlock, IoResult, BytesTransferred) ||
            !CxPlatDataPathStartReceive(
                SocketProc,
                InlineReceiveCount > 1 ? &IoResult : NULL,
                InlineReceiveCount > 1 ? &BytesTransferred : NULL,
                InlineReceiveCount > 1 ? &IoBlock : NULL)) {
            break;
        }
    }

    CxPlatRundownRelease(&SocketProc->RundownRef);
}

void*
RioSendDataAllocate(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PARTITION, RioSendDataPool);
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
SendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);

    if (Config->Route->Queue == NULL) {
        Config->Route->Queue = &Socket->PerProcSockets[0];
    }

    CXPLAT_SOCKET_PROC* SocketProc = Config->Route->Queue;
    CXPLAT_DATAPATH_PARTITION* DatapathProc = SocketProc->DatapathProc;
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
        SendData->DatapathType = Config->Route->DatapathType = CXPLAT_DATAPATH_TYPE_USER;
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
SendDataFree(
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
    CXPLAT_DATAPATH_PARTITION* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PARTITION, RioSendBufferPool);
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
    CXPLAT_DATAPATH_PARTITION* DatapathProc =
        CXPLAT_CONTAINING_RECORD(Pool, CXPLAT_DATAPATH_PARTITION, RioLargeSendBufferPool);
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
SendDataAllocBuffer(
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
SendDataFreeBuffer(
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
SendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return !CxPlatSendDataCanAllocSend(SendData, SendData->SegmentSize);
}

void
CxPlatSendDataComplete(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ ULONG IoResult
    )
{
    const CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;

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

    SendDataFree(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSendWithRio(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ WSAMSG* WSAMhdr
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;
    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;

    RIO_BUF RemoteAddr = {0};
    RIO_BUF Control = {0};
    PRIO_CMSG_BUFFER RioCmsg = (PRIO_CMSG_BUFFER)SendData->CtrlBuf;

    RemoteAddr.BufferId = SendData->RioBufferId;
    RemoteAddr.Offset = FIELD_OFFSET(CXPLAT_SEND_DATA, MappedRemoteAddress);
    RemoteAddr.Length = sizeof(SendData->MappedRemoteAddress);

    RioCmsg->TotalLength = RIO_CMSG_BASE_SIZE + WSAMhdr->Control.len;
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
            SendDataFree(SendData);
            return HRESULT_FROM_WIN32(WsaError);
        }

        SocketProc->RioSendCount++;
        CxPlatSocketArmRioNotify(SocketProc);
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSendInline(
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;
    if (SocketProc->RioSendCount == RIO_SEND_QUEUE_DEPTH) {
        CxPlatListInsertTail(&SocketProc->RioSendOverflow, &SendData->RioOverflowEntry);
        return QUIC_STATUS_PENDING;
    }

    QUIC_STATUS Status;
    int Result;
    DWORD BytesSent;
    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    CXPLAT_SOCKET* Socket = SocketProc->Parent;

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

    if (Socket->Type == CXPLAT_SOCKET_UDP && Socket->UseRio) {
        return CxPlatSocketSendWithRio(SendData, &WSAMhdr);
    }

    //
    // Start the async send.
    //
    CxPlatDatapathSqeInitialize(&SendData->Sqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatStartDatapathIo(SocketProc, &SendData->Sqe, DATAPATH_IO_SEND);

    if (Socket->Type == CXPLAT_SOCKET_UDP) {
        Result =
            Datapath->WSASendMsg(
                SocketProc->Socket,
                &WSAMhdr,
                0,
                &BytesSent,
                &SendData->Sqe.DatapathSqe.Sqe.Overlapped,
                NULL);
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

    int WsaError = NO_ERROR;
    if (Result == SOCKET_ERROR) {
        WsaError = WSAGetLastError();
        if (WsaError == WSA_IO_PENDING) {
            return QUIC_STATUS_SUCCESS;
        }
        Status = HRESULT_FROM_WIN32(WsaError);
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

    //
    // Completed synchronously, so process the completion inline.
    //
    CxPlatCancelDatapathIo(SocketProc, &SendData->Sqe);
    CxPlatSendDataComplete(SendData, WsaError);

    return Status;
}

QUIC_STATUS
CxPlatSocketSendEnqueue(
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    SendData->LocalAddress = Route->LocalAddress;
    CxPlatDatapathSqeInitialize(&SendData->Sqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
    CxPlatStartDatapathIo(SendData->SocketProc, &SendData->Sqe, DATAPATH_IO_QUEUE_SEND);
    QUIC_STATUS Status = CxPlatSocketEnqueueSqe(SendData->SocketProc, &SendData->Sqe, 0);
    if (QUIC_FAILED(Status)) {
        CxPlatCancelDatapathIo(SendData->SocketProc, &SendData->Sqe);
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
SocketSend(
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

    if (CxPlatRundownAcquire(&SocketProc->RundownRef)) {
        CxPlatSocketSendInline(&SendData->LocalAddress, SendData);
        CxPlatRundownRelease(&SocketProc->RundownRef);
    } else {
        CxPlatSendDataComplete(SendData, WSAESHUTDOWN);
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
DataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    switch (CxPlatCqeType(Cqe)) {
    case CXPLAT_CQE_TYPE_SOCKET_IO: {
        DATAPATH_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_IO_SQE, DatapathSqe);
        DATAPATH_IO_TYPE IoType = Sqe->IoType;
        CXPLAT_SOCKET_PROC* SocketProc = NULL;

        CxPlatStopDatapathIo(Sqe);

        switch (IoType) {
        case DATAPATH_IO_RECV:
            //
            // N.B. We don't set SocketProc here because receive completions are
            // special (they loop internally).
            //
            CXPLAT_DBG_ASSERT(Cqe->dwNumberOfBytesTransferred <= UINT16_MAX);
            CxPlatDataPathSocketProcessReceive(
                CONTAINING_RECORD(Sqe, DATAPATH_RX_IO_BLOCK, Sqe),
                (uint16_t)Cqe->dwNumberOfBytesTransferred,
                RtlNtStatusToDosError((NTSTATUS)Cqe->Internal));
            break;

        case DATAPATH_IO_SEND:
            SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe)->SocketProc;
            CxPlatSendDataComplete(
                CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe),
                RtlNtStatusToDosError((NTSTATUS)Cqe->Internal));
            break;

        case DATAPATH_IO_QUEUE_SEND:
            SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe)->SocketProc;
            CxPlatDataPathSocketProcessQueuedSend(Sqe, Cqe);
            break;

        case DATAPATH_IO_ACCEPTEX:
            SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
            CxPlatDataPathSocketProcessAcceptCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_CONNECTEX:
            SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
            CxPlatDataPathSocketProcessConnectCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_RIO_NOTIFY:
            SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, RioSqe);
            CxPlatDataPathSocketProcessRioCompletion(Sqe, Cqe);
            break;

        case DATAPATH_IO_RECV_FAILURE:
            //
            // N.B. We don't set SocketProc here because receive completions are
            // special (they loop internally).
            //
            CxPlatDataPathSocketProcessReceive(
                CONTAINING_RECORD(Sqe, DATAPATH_RX_IO_BLOCK, Sqe),
                0,
                (ULONG)Cqe->dwNumberOfBytesTransferred);
            break;

        default:
            CXPLAT_DBG_ASSERT(FALSE);
            break;
        }

        if (SocketProc) {
            CxPlatSocketContextRelease(SocketProc);
        }
        break;
    }
    default: CXPLAT_DBG_ASSERT(FALSE); break;
    }
}
