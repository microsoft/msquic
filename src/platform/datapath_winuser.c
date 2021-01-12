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

//
// Not yet available in the SDK. When available this code can be removed.
//
#if 1
#define UDP_SEND_MSG_SIZE           2
#define UDP_RECV_MAX_COALESCED_SIZE 3
#define UDP_COALESCED_INFO          3
#endif

//
// The maximum number of UDP datagrams that can be sent with one call.
//
#define CXPLAT_MAX_BATCH_SEND                 7

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

static_assert(
    sizeof(QUIC_BUFFER) == sizeof(WSABUF),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
static_assert(
    FIELD_OFFSET(QUIC_BUFFER, Length) == FIELD_OFFSET(WSABUF, len),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
static_assert(
    FIELD_OFFSET(QUIC_BUFFER, Buffer) == FIELD_OFFSET(WSABUF, buf),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");

#define IsUnreachableErrorCode(ErrorCode) \
( \
    ErrorCode == ERROR_NETWORK_UNREACHABLE || \
    ErrorCode == ERROR_HOST_UNREACHABLE || \
    ErrorCode == ERROR_PROTOCOL_UNREACHABLE || \
    ErrorCode == ERROR_PORT_UNREACHABLE \
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
// Internal receive context.
//
typedef struct CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT {

    //
    // The owning datagram pool.
    //
    CXPLAT_POOL* OwningPool;

    //
    // The reference count of the receive buffer.
    //
    ULONG ReferenceCount;

    //
    // Contains the 4 tuple.
    //
    CXPLAT_TUPLE Tuple;

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
// Send context.
//
typedef struct CXPLAT_SEND_DATA {

    //
    // The Overlapped structure for I/O completion.
    //
    OVERLAPPED Overlapped;

    //
    // The owning processor context.
    //
    CXPLAT_DATAPATH_PROC* Owner;

    //
    // The total buffer size for WsaBuffers.
    //
    uint32_t TotalSize;

    //
    // The send segmentation size; zero if segmentation is not performed.
    //
    UINT16 SegmentSize;

    //
    // The type of ECN markings needed for send.
    //
    CXPLAT_ECN_TYPE ECN;

    //
    // The current number of WsaBuffers used.
    //
    UINT8 WsaBufferCount;

    //
    // Contains all the datagram buffers to pass to the socket.
    //
    WSABUF WsaBuffers[CXPLAT_MAX_BATCH_SEND];

    //
    // The WSABUF returned to the client for segmented sends.
    //
    WSABUF ClientBuffer;

} CXPLAT_SEND_DATA;

//
// Per-processor socket state.
//
typedef struct CXPLAT_SOCKET_PROC {

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
    // The set of parameters/state passed to WsaRecvMsg for the IP stack to
    // populate to indicate the result of the receive.
    //

    union {
    //
    // Normal TCP/UDP socket data
    //
    struct {
    WSABUF RecvWsaBuf;
    char RecvWsaMsgControlBuf[
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(DWORD)) +         // UDP_COALESCED_INFO
        WSA_CMSG_SPACE(sizeof(INT))             // IP_ECN
        ];
    WSAMSG RecvWsaMsgHdr;
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* CurrentRecvContext;
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
    OVERLAPPED Overlapped;

} CXPLAT_SOCKET_PROC;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct CXPLAT_SOCKET {

    //
    // Socket type.
    //
    uint8_t Type : 2; // CXPLAT_SOCKET_TYPE

    //
    // Flag indicates the socket has a default remote destination.
    //
    uint8_t HasFixedRemoteAddress : 1;

    //
    // Flag indicates the socket successfully connected.
    //
    uint8_t ConnectComplete : 1;

    //
    // Flag indicates the socket indicated a disconnect event.
    //
    uint8_t DisconnectIndicated : 1;

    //
    // Flag indicates the socket has not been exposed externally yet.
    //
    uint8_t Internal : 1;

    //
    // The index of the affinitized receive processor for a connected socket.
    //
    uint16_t ProcessorAffinity;

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The local address and port.
    //
    SOCKADDR_INET LocalAddress;

    //
    // The remote address and port.
    //
    SOCKADDR_INET RemoteAddress;

    //
    // The local interface's MTU.
    //
    UINT16 Mtu;

    //
    // The number of per-processor socket contexts that still need to be cleaned up.
    //
    short volatile ProcsOutstanding;

    //
    // Client context pointer.
    //
    void *ClientContext;

    //
    // Per-processor socket contexts.
    //
    CXPLAT_SOCKET_PROC Processors[0];

} CXPLAT_SOCKET;

//
// Represents a single IO completion port and thread for processing work that
// is completed on a single processor.
//
typedef struct CXPLAT_DATAPATH_PROC {

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // IO Completion Socket used for the processing completions on the socket.
    //
    HANDLE IOCP;

    //
    // Thread used for handling IOCP completions.
    //
    HANDLE CompletionThread;

    //
    // The ID of the CompletionThread.
    //
    uint32_t ThreadId;

    //
    // The index of the context in the datapath's array.
    //
    uint16_t Index;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendContextPool;

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
    // Pool of receive datagram contexts and buffers to be shared by all sockets
    // on this core.
    //
    CXPLAT_POOL RecvDatagramPool;

} CXPLAT_DATAPATH_PROC;

//
// Main structure for tracking all UDP abstractions.
//
typedef struct CXPLAT_DATAPATH {

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // Flag used to shutdown the completion thread.
    //
    BOOLEAN Shutdown;

    //
    // Maximum batch sizes supported for send.
    //
    UINT8 MaxSendBatchSize;

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
    // Rundown for waiting on binding cleanup.
    //
    CXPLAT_RUNDOWN_REF SocketsRundown;

    //
    // The UDP callback function pointers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

    //
    // The TCP callback function pointers.
    //
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpHandlers;

    //
    // Size of the client's CXPLAT_RECV_PACKET.
    //
    uint32_t ClientRecvContextLength;

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
    // Per-processor completion contexts.
    //
    CXPLAT_DATAPATH_PROC Processors[0];

} CXPLAT_DATAPATH;

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

QUIC_STATUS
CxPlatSocketStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
    );

QUIC_STATUS
CxPlatSocketStartAccept(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
    );

//
// Callback function for IOCP Worker Thread.
//
DWORD
WINAPI
CxPlatDataPathWorkerThread(
    _In_ void* Context
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

#ifdef QUIC_FUZZER
    MsQuicFuzzerContext.RealSendMsg = (PVOID)Datapath->WSASendMsg;
    MsQuicFuzzerContext.RealRecvMsg = (PVOID)Datapath->WSARecvMsg;
    Datapath->WSASendMsg = QuicFuzzerSendMsg;
    Datapath->WSARecvMsg = QuicFuzzerRecvMsg;
#endif

#ifdef UDP_SEND_MSG_SIZE
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
#endif

#ifdef UDP_RECV_MAX_COALESCED_SIZE
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
#endif

Error:

    if (UdpSocket != INVALID_SOCKET) {
        closesocket(UdpSocket);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    int WsaError;
    QUIC_STATUS Status;
    WSADATA WsaData;
    CXPLAT_DATAPATH* Datapath;
    uint32_t DatapathLength;

    uint32_t MaxProcCount = CxPlatProcActiveCount();
    CXPLAT_DBG_ASSERT(MaxProcCount <= UINT16_MAX - 1);
    if (MaxProcCount >= UINT16_MAX) {
        MaxProcCount = UINT16_MAX - 1;
    }

    if (NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        Datapath = NULL;
        goto Exit;
    }
    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            Datapath = NULL;
            goto Exit;
        }
    }
    if (TcpCallbacks != NULL) {
        if (TcpCallbacks->Accept == NULL ||
            TcpCallbacks->Connect == NULL ||
            TcpCallbacks->Receive == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            Datapath = NULL;
            goto Exit;
        }
    }

    if ((WsaError = WSAStartup(MAKEWORD(2, 2), &WsaData)) != 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            WsaError,
            "WSAStartup");
        Status = HRESULT_FROM_WIN32(WsaError);
        Datapath = NULL;
        goto Exit;
    }

    DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        MaxProcCount * sizeof(CXPLAT_DATAPATH_PROC);

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
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = (uint16_t)MaxProcCount;
    CxPlatRundownInitialize(&Datapath->SocketsRundown);

    CxPlatDataPathQueryRssScalabilityInfo(Datapath);
    Status = CxPlatDataPathQuerySockoptSupport(Datapath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

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

    uint32_t MessageCount =
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

    uint32_t RecvDatagramLength =
        Datapath->RecvPayloadOffset + MAX_URO_PAYLOAD_LENGTH;

    for (uint16_t i = 0; i < Datapath->ProcCount; i++) {

        //
        // This creates a per processor IO completion port and thread. It
        // explicitly affinitizes the thread to a processor. This is so that
        // our per UDP socket receives maintain their RSS core all the way up.
        //

        Datapath->Processors[i].Datapath = Datapath;
        Datapath->Processors[i].Index = i;

        CxPlatPoolInitialize(
            FALSE,
            sizeof(CXPLAT_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            &Datapath->Processors[i].SendContextPool);

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

        CxPlatPoolInitialize(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->Processors[i].RecvDatagramPool);

        Datapath->Processors[i].IOCP =
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                NULL,
                0,
                1);
        if (Datapath->Processors[i].IOCP == NULL) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                LastError,
                "CreateIoCompletionPort");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

        Datapath->Processors[i].CompletionThread =
            CreateThread(
                NULL,
                0,
                CxPlatDataPathWorkerThread,
                &Datapath->Processors[i],
                0,
                NULL);
        if (Datapath->Processors[i].CompletionThread == NULL) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                LastError,
                "CreateThread");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

        const CXPLAT_PROCESSOR_INFO* ProcInfo = &CxPlatProcessorInfo[i];
        GROUP_AFFINITY Group = {0};
        Group.Mask = (KAFFINITY)(1llu << ProcInfo->Index);
        Group.Group = ProcInfo->Group;
        if (!SetThreadGroupAffinity(
                Datapath->Processors[i].CompletionThread,
                &Group,
                NULL)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                LastError,
                "SetThreadGroupAffinity");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

#ifdef QUIC_UWP_BUILD
        SetThreadDescription(Datapath->Processors[i].CompletionThread, L"CXPLAT_DATAPATH");
#else
        THREAD_NAME_INFORMATION ThreadNameInfo;
        RtlInitUnicodeString(&ThreadNameInfo.ThreadName, L"CXPLAT_DATAPATH");
        NTSTATUS NtStatus =
            NtSetInformationThread(
                Datapath->Processors[i].CompletionThread,
                ThreadNameInformation,
                &ThreadNameInfo,
                sizeof(ThreadNameInfo));
        if (!NT_SUCCESS(NtStatus)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                NtStatus,
                "NtSetInformationThread(name)");
        }
#endif
    }

    *NewDataPath = Datapath;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Datapath != NULL) {
            for (uint16_t i = 0; i < Datapath->ProcCount; i++) {
                if (Datapath->Processors[i].IOCP) {
                    CloseHandle(Datapath->Processors[i].IOCP);
                }
                if (Datapath->Processors[i].CompletionThread) {
                    CloseHandle(Datapath->Processors[i].CompletionThread);
                }
                CxPlatPoolUninitialize(&Datapath->Processors[i].SendContextPool);
                CxPlatPoolUninitialize(&Datapath->Processors[i].SendBufferPool);
                CxPlatPoolUninitialize(&Datapath->Processors[i].LargeSendBufferPool);
                CxPlatPoolUninitialize(&Datapath->Processors[i].RecvDatagramPool);
            }
            CxPlatRundownUninitialize(&Datapath->SocketsRundown);
            CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
        }
        (void)WSACleanup();
    }

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

    //
    // Wait for all outstanding binding to clean up.
    //
    CxPlatRundownReleaseAndWait(&Datapath->SocketsRundown);

    //
    // Disable processing on the completion threads and kick the IOCPs to make
    // sure the threads knows they are disabled.
    //
    Datapath->Shutdown = TRUE;
    for (uint16_t i = 0; i < Datapath->ProcCount; i++) {
        PostQueuedCompletionStatus(
            Datapath->Processors[i].IOCP, 0, (ULONG_PTR)NULL, NULL);
    }

    //
    // Wait for the worker threads to finish up. Then clean it up.
    //
    for (uint16_t i = 0; i < Datapath->ProcCount; i++) {
        WaitForSingleObject(Datapath->Processors[i].CompletionThread, INFINITE);
        CloseHandle(Datapath->Processors[i].CompletionThread);
    }

    for (uint16_t i = 0; i < Datapath->ProcCount; i++) {
        CloseHandle(Datapath->Processors[i].IOCP);
        CxPlatPoolUninitialize(&Datapath->Processors[i].SendContextPool);
        CxPlatPoolUninitialize(&Datapath->Processors[i].SendBufferPool);
        CxPlatPoolUninitialize(&Datapath->Processors[i].LargeSendBufferPool);
        CxPlatPoolUninitialize(&Datapath->Processors[i].RecvDatagramPool);
    }

    CxPlatRundownUninitialize(&Datapath->SocketsRundown);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);

    WSACleanup();
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

    memcpy(Address, Ai->ai_addr, Ai->ai_addrlen);
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

    int Result =
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            HostName,
            -1,
            NULL,
            0);
    if (Result == 0) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "Calculate hostname wchar length");
        Status = HRESULT_FROM_WIN32(LastError);
        goto Exit;
    }

    HostNameW = CXPLAT_ALLOC_PAGED(sizeof(WCHAR) * Result, QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (HostNameW == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Wchar hostname",
            sizeof(WCHAR) * Result);
        goto Exit;
    }

    Result =
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            HostName,
            -1,
            HostNameW,
            Result);
    if (Result == 0) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "Convert hostname to wchar");
        Status = HRESULT_FROM_WIN32(LastError);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status;
    int Result;
    int Option;
    BOOLEAN IsServerSocket = RemoteAddress == NULL;
    uint16_t SocketCount = IsServerSocket ? Datapath->ProcCount : 1;

    CXPLAT_DBG_ASSERT(Datapath->UdpHandlers.Receive != NULL);

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
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = (RemoteAddress != NULL);
    Socket->Internal = FALSE;
    Socket->Type = CXPLAT_SOCKET_UDP;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRundownAcquire(&Datapath->SocketsRundown);

    for (uint16_t i = 0; i < SocketCount; i++) {
        Socket->Processors[i].Parent = Socket;
        Socket->Processors[i].Socket = INVALID_SOCKET;
        Socket->Processors[i].RecvWsaBuf.len =
            (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
                MAX_URO_PAYLOAD_LENGTH :
                Socket->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
        CxPlatRundownInitialize(&Socket->Processors[i].UpcallRundown);
    }

    for (uint16_t i = 0; i < SocketCount; i++) {

        CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[i];
        uint16_t AffinitizedProcessor = (uint16_t)i;
        DWORD BytesReturned;

        SocketProc->Socket =
            WSASocketW(
                AF_INET6,
                SOCK_DGRAM,
                IPPROTO_UDP,
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

        if (RemoteAddress == NULL) {
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

#ifdef UDP_RECV_MAX_COALESCED_SIZE
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
#endif

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

        if (RemoteAddress != NULL) {
            AffinitizedProcessor =
                ((uint16_t)CxPlatProcCurrentNumber()) % Datapath->ProcCount;
            Socket->ProcessorAffinity = AffinitizedProcessor;
        }

QUIC_DISABLED_BY_FUZZER_START;

        if (Datapath->Processors[AffinitizedProcessor].IOCP !=
            CreateIoCompletionPort(
                (HANDLE)SocketProc->Socket,
                Datapath->Processors[AffinitizedProcessor].IOCP,
                (ULONG_PTR)SocketProc,
                0)) {
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

            if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
                CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
            }
        }

QUIC_DISABLED_BY_FUZZER_END;
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    if (RemoteAddress != NULL) {
        Socket->RemoteAddress = *RemoteAddress;
    } else {
        Socket->RemoteAddress.Ipv4.sin_port = 0;
    }

    Socket->ConnectComplete = TRUE;

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewSocket = Socket;

    Socket->ProcsOutstanding = (short)SocketCount;
    for (uint16_t i = 0; i < SocketCount; i++) {
        uint16_t Processor =
            Socket->HasFixedRemoteAddress ? Socket->ProcessorAffinity : i;

        Status =
            CxPlatSocketStartReceive(
                &Socket->Processors[i],
                &Datapath->Processors[Processor]);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Socket != NULL) {
            QuicTraceEvent(
                DatapathDestroyed,
                "[data][%p] Destroyed",
                Socket);
            if (Socket->ProcsOutstanding != 0) {
                for (uint16_t i = 0; i < SocketCount; i++) {
                    CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[i];
                    uint16_t Processor =
                         Socket->HasFixedRemoteAddress ? Socket->ProcessorAffinity : i;

QUIC_DISABLED_BY_FUZZER_START;

                    CancelIo((HANDLE)SocketProc->Socket);
                    closesocket(SocketProc->Socket);

QUIC_DISABLED_BY_FUZZER_END;

                    //
                    // Queue a completion to clean up the socket context.
                    //
                    PostQueuedCompletionStatus(
                        Socket->Datapath->Processors[Processor].IOCP,
                        UINT32_MAX,
                        (ULONG_PTR)SocketProc,
                        &SocketProc->Overlapped);
                }
            } else {
                for (uint16_t i = 0; i < SocketCount; i++) {
                    CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[i];

QUIC_DISABLED_BY_FUZZER_START;

                    if (SocketProc->Socket != INVALID_SOCKET) {
                        closesocket(SocketProc->Socket);
                    }

QUIC_DISABLED_BY_FUZZER_END;

                    CxPlatRundownUninitialize(&SocketProc->UpcallRundown);
                }
                CxPlatRundownRelease(&Datapath->SocketsRundown);
                CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
            }
        }
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
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = TRUE;
    Socket->Internal = (Type == CXPLAT_SOCKET_TCP_SERVER);
    Socket->Type = Type;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    if (RemoteAddress) {
        Socket->ProcessorAffinity =
            ((uint16_t)CxPlatProcCurrentNumber()) % Datapath->ProcCount;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRundownAcquire(&Datapath->SocketsRundown);

    SocketProc = &Socket->Processors[0];
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    SocketProc->RecvWsaBuf.len = MAX_URO_PAYLOAD_LENGTH;
    CxPlatRundownInitialize(&SocketProc->UpcallRundown);

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

        if (Datapath->Processors[Socket->ProcessorAffinity].IOCP !=
            CreateIoCompletionPort(
                (HANDLE)SocketProc->Socket,
                Datapath->Processors[Socket->ProcessorAffinity].IOCP,
                (ULONG_PTR)SocketProc,
                0)) {
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

            Result =
                Datapath->ConnectEx(
                    SocketProc->Socket,
                    (PSOCKADDR)&MappedRemoteAddress,
                    sizeof(MappedRemoteAddress),
                    NULL,
                    0,
                    &BytesReturned,
                    &SocketProc->Overlapped);
            if (Result == FALSE) {
                int WsaError = WSAGetLastError();
                if (WsaError != WSA_IO_PENDING) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "AcceptEx");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Error;
                }
            } else {
                //
                // Manually post IO completion if connect completed synchronously.
                //
                if (!PostQueuedCompletionStatus(
                        Datapath->Processors[Socket->ProcessorAffinity].IOCP,
                        BytesReturned,
                        (ULONG_PTR)SocketProc,
                        &SocketProc->Overlapped)) {
                    DWORD LastError = GetLastError();
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Socket,
                        LastError,
                        "PostQueuedCompletionStatus");
                    Status = HRESULT_FROM_WIN32(LastError);
                    goto Error;
                }
            }
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

    Socket->ProcsOutstanding = 1;

    *NewSocket = Socket;

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Socket != NULL) {
            QuicTraceEvent(
                DatapathDestroyed,
                "[data][%p] Destroyed",
                Socket);
            if (Socket->ProcsOutstanding != 0) {

                CancelIo((HANDLE)SocketProc->Socket);
                closesocket(SocketProc->Socket);

                //
                // Queue a completion to clean up the socket context.
                //
                PostQueuedCompletionStatus(
                    Socket->Datapath->Processors[Socket->ProcessorAffinity].IOCP,
                    UINT32_MAX,
                    (ULONG_PTR)SocketProc,
                    &SocketProc->Overlapped);
            } else {

                if (SocketProc->Socket != INVALID_SOCKET) {
                    closesocket(SocketProc->Socket);
                }
                CxPlatRundownUninitialize(&SocketProc->UpcallRundown);

                CxPlatRundownRelease(&Datapath->SocketsRundown);
                CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
            }
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
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(0, NULL));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = FALSE;
    Socket->Internal = FALSE;
    Socket->Type = CXPLAT_SOCKET_TCP_LISTENER;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRundownAcquire(&Datapath->SocketsRundown);

    SocketProc = &Socket->Processors[0];
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    CxPlatRundownInitialize(&SocketProc->UpcallRundown);

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

    if (Datapath->Processors[Socket->ProcessorAffinity].IOCP !=
        CreateIoCompletionPort(
            (HANDLE)SocketProc->Socket,
            Datapath->Processors[Socket->ProcessorAffinity].IOCP,
            (ULONG_PTR)SocketProc,
            0)) {
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

    Socket->ProcsOutstanding = 1;

    Status =
        CxPlatSocketStartAccept(
            SocketProc,
            &Datapath->Processors[Socket->ProcessorAffinity]);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    *NewSocket = Socket;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Socket != NULL) {
            QuicTraceEvent(
                DatapathDestroyed,
                "[data][%p] Destroyed",
                Socket);
            if (Socket->ProcsOutstanding != 0) {
                CancelIo((HANDLE)SocketProc->Socket);
                closesocket(SocketProc->Socket);

                //
                // Queue a completion to clean up the socket context.
                //
                PostQueuedCompletionStatus(
                    Datapath->Processors[Socket->ProcessorAffinity].IOCP,
                    UINT32_MAX,
                    (ULONG_PTR)SocketProc,
                    &SocketProc->Overlapped);
            } else {

                if (SocketProc->Socket != INVALID_SOCKET) {
                    closesocket(SocketProc->Socket);
                }
                CxPlatRundownUninitialize(&SocketProc->UpcallRundown);

                CxPlatRundownRelease(&Datapath->SocketsRundown);
                CXPLAT_FREE(Socket, QUIC_POOL_SOCKET);
            }
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathSocketContextShutdown(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

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

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    CXPLAT_DATAPATH* Datapath = Socket->Datapath;

    if (Socket->Internal) {
        CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[0];
        if (closesocket(SocketProc->Socket) == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "closesocket");
        }
        CxPlatDataPathSocketContextShutdown(&Socket->Processors[0]);

    } else if (Socket->HasFixedRemoteAddress || Socket->Type != CXPLAT_SOCKET_UDP) {
        CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[0];
        uint32_t Processor = Socket->ProcessorAffinity;
        CXPLAT_DBG_ASSERT(
            Datapath->Processors[Processor].ThreadId != GetCurrentThreadId());
        if (Socket->Type == CXPLAT_SOCKET_TCP ||
            Socket->Type == CXPLAT_SOCKET_TCP_SERVER) {
            SocketProc->Parent->DisconnectIndicated = TRUE;
            if (shutdown(SocketProc->Socket, SD_BOTH) == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                if (WsaError != WSAENOTCONN) {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "shutdown");
                }
            }
        }
        CxPlatRundownReleaseAndWait(&SocketProc->UpcallRundown);

QUIC_DISABLED_BY_FUZZER_START;

        CancelIo((HANDLE)SocketProc->Socket);
        if (closesocket(SocketProc->Socket) == SOCKET_ERROR) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "closesocket");
        }

QUIC_DISABLED_BY_FUZZER_END;

        PostQueuedCompletionStatus(
            Datapath->Processors[Processor].IOCP,
            UINT32_MAX,
            (ULONG_PTR)SocketProc,
            &SocketProc->Overlapped);

    } else {
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[i];
            CXPLAT_DBG_ASSERT(
                Datapath->Processors[i].ThreadId != GetCurrentThreadId());
            CxPlatRundownReleaseAndWait(&SocketProc->UpcallRundown);
        }
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            CXPLAT_SOCKET_PROC* SocketProc = &Socket->Processors[i];
            uint32_t Processor = i;

QUIC_DISABLED_BY_FUZZER_START;

            CancelIo((HANDLE)SocketProc->Socket);
            closesocket(SocketProc->Socket);

QUIC_DISABLED_BY_FUZZER_END;

            PostQueuedCompletionStatus(
                Datapath->Processors[Processor].IOCP,
                UINT32_MAX,
                (ULONG_PTR)SocketProc,
                &SocketProc->Overlapped);
        }
    }

    QuicTraceLogVerbose(
        DatapathShutDownReturn,
        "[data][%p] Shut down (return)",
        Socket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathSocketContextShutdown(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    if (SocketProc->Parent->Type == CXPLAT_SOCKET_TCP_LISTENER) {
        if (SocketProc->AcceptSocket != NULL) {
            CxPlatSocketDelete(SocketProc->AcceptSocket);
            SocketProc->AcceptSocket = NULL;
        }

    } else if (SocketProc->CurrentRecvContext != NULL) {
        CxPlatPoolFree(
            SocketProc->CurrentRecvContext->OwningPool,
            SocketProc->CurrentRecvContext);
        SocketProc->CurrentRecvContext = NULL;
    }

    CxPlatRundownUninitialize(&SocketProc->UpcallRundown);

    if (InterlockedDecrement16(
            &SocketProc->Parent->ProcsOutstanding) == 0) {
        //
        // Last socket context cleaned up, so now the binding can be freed.
        //
        CxPlatRundownRelease(&SocketProc->Parent->Datapath->SocketsRundown);
        QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            SocketProc->Parent);
        CXPLAT_FREE(SocketProc->Parent, QUIC_POOL_SOCKET);
    }
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

CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT*
CxPlatSocketAllocRecvContext(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ UINT16 ProcIndex
    )
{
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
        CxPlatPoolAlloc(&Datapath->Processors[ProcIndex].RecvDatagramPool);

    if (RecvContext != NULL) {
        RecvContext->OwningPool =
            &Datapath->Processors[ProcIndex].RecvDatagramPool;
        RecvContext->ReferenceCount = 0;
    }

    return RecvContext;
}

QUIC_STATUS
CxPlatSocketStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
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

    RtlZeroMemory(
        &ListenerSocketProc->Overlapped,
        sizeof(ListenerSocketProc->Overlapped));

    Result =
        Datapath->AcceptEx(
            ListenerSocketProc->Socket,
            ListenerSocketProc->AcceptSocket->Processors[0].Socket,
            &ListenerSocketProc->AcceptAddrSpace,
            0,                          // dwReceiveDataLength
            sizeof(SOCKADDR_INET)+16,   // dwLocalAddressLength
            sizeof(SOCKADDR_INET)+16,   // dwRemoteAddressLength
            &BytesRecv,
            &ListenerSocketProc->Overlapped);
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
        if (!PostQueuedCompletionStatus(
                DatapathProc->IOCP,
                BytesRecv,
                (ULONG_PTR)ListenerSocketProc,
                &ListenerSocketProc->Overlapped)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                LastError,
                "PostQueuedCompletionStatus");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    return Status;
}

void
CxPlatDataPathAcceptComplete(
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc,
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ ULONG IoResult
    )
{
    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS) {
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket != NULL);
        CXPLAT_SOCKET_PROC* AcceptSocketProc = &ListenerSocketProc->AcceptSocket->Processors[0];
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent);

        AcceptSocketProc->Parent->ConnectComplete = TRUE;
        AcceptSocketProc->Parent->ProcessorAffinity = 0;
        // TODO - Query for RSS info

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

        if (DatapathProc->IOCP !=
            CreateIoCompletionPort(
                (HANDLE)AcceptSocketProc->Socket,
                DatapathProc->IOCP,
                (ULONG_PTR)AcceptSocketProc,
                0)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->AcceptSocket,
                LastError,
                "CreateIoCompletionPort (accepted)");
            goto Error;
        }

        if (QUIC_FAILED(
            CxPlatSocketStartReceive(
                AcceptSocketProc,
                DatapathProc))) {
            goto Error;
        }

        AcceptSocketProc->Parent->Internal = FALSE;
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
    (void)CxPlatSocketStartAccept(ListenerSocketProc, DatapathProc);
}

void
CxPlatDataPathConnectComplete(
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc,
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG IoResult
    )
{
    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;
    }

    // TODO - Upcall to the app

    if (IoResult == QUIC_STATUS_SUCCESS) {

        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            0,
            "ConnectEx Completed!");

        SocketProc->Parent->ConnectComplete = TRUE;
        SocketProc->Parent->Datapath->TcpHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            TRUE);

        //
        // Try to start a new receive.
        //
        (void)CxPlatSocketStartReceive(SocketProc, DatapathProc);

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
}

void
CxPlatSocketHandleUnreachableError(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG ErrorCode
    )
{
    PSOCKADDR_INET RemoteAddr =
        &SocketProc->CurrentRecvContext->Tuple.RemoteAddress;
    UNREFERENCED_PARAMETER(ErrorCode);

    CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

#if QUIC_CLOG
    QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[data][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketProc->Parent,
        ErrorCode,
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

    SocketProc->Parent->Datapath->UdpHandlers.Unreachable(
        SocketProc->Parent,
        SocketProc->Parent->ClientContext,
        RemoteAddr);
}

QUIC_STATUS
CxPlatSocketStartReceive(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc
    )
{
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    int Result;
    DWORD BytesRecv = 0;

    CXPLAT_DBG_ASSERT(SocketProc->Parent->Type != CXPLAT_SOCKET_TCP_LISTENER);

    //
    // Get a receive buffer we can pass to WinSock.
    //
    if (SocketProc->CurrentRecvContext == NULL) {
        SocketProc->CurrentRecvContext =
            CxPlatSocketAllocRecvContext(
                Datapath,
                DatapathProc->Index);
        if (SocketProc->CurrentRecvContext == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
    }

    RtlZeroMemory(
        &SocketProc->Overlapped,
        sizeof(SocketProc->Overlapped));

    SocketProc->RecvWsaBuf.buf =
        ((CHAR*)SocketProc->CurrentRecvContext) + Datapath->RecvPayloadOffset;

    RtlZeroMemory(
        &SocketProc->RecvWsaMsgHdr,
        sizeof(SocketProc->RecvWsaMsgHdr));

    SocketProc->RecvWsaMsgHdr.name =
        (PSOCKADDR)&SocketProc->CurrentRecvContext->Tuple.RemoteAddress;
    SocketProc->RecvWsaMsgHdr.namelen =
        sizeof(SocketProc->CurrentRecvContext->Tuple.RemoteAddress);

    SocketProc->RecvWsaMsgHdr.lpBuffers = &SocketProc->RecvWsaBuf;
    SocketProc->RecvWsaMsgHdr.dwBufferCount = 1;

    SocketProc->RecvWsaMsgHdr.Control.buf = SocketProc->RecvWsaMsgControlBuf;
    SocketProc->RecvWsaMsgHdr.Control.len = sizeof(SocketProc->RecvWsaMsgControlBuf);

Retry_recv:

    if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP) {
        Result =
            SocketProc->Parent->Datapath->WSARecvMsg(
                SocketProc->Socket,
                &SocketProc->RecvWsaMsgHdr,
                &BytesRecv,
                &SocketProc->Overlapped,
                NULL);
    } else {
        DWORD Flags = 0;
        Result =
            WSARecv(
                SocketProc->Socket,
                &SocketProc->RecvWsaBuf,
                1,
                &BytesRecv,
                &Flags,
                &SocketProc->Overlapped,
                NULL);
    }
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP &&
                WsaError == WSAECONNRESET) {
                CxPlatSocketHandleUnreachableError(SocketProc, (ULONG)WsaError);
                goto Retry_recv;
            } else {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketProc->Parent,
                    WsaError,
                    "WSARecvMsg");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }
        }
    } else {
        //
        // Manually post IO completion if receive completed synchronously.
        //
        if (!PostQueuedCompletionStatus(
                DatapathProc->IOCP,
                BytesRecv,
                (ULONG_PTR)SocketProc,
                &SocketProc->Overlapped)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                LastError,
                "PostQueuedCompletionStatus");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    return Status;
}

void
CxPlatDataPathUdpRecvComplete(
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc,
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG IoResult,
    _In_ UINT16 NumberOfBytesTransferred
    )
{
    //
    // Copy the current receive buffer locally. On error cases, we leave the
    // buffer set as the current receive buffer because we are only using it
    // inline. Otherwise, we remove it as the current because we are giving
    // it to the client.
    //
    CXPLAT_DBG_ASSERT(SocketProc->CurrentRecvContext != NULL);
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = SocketProc->CurrentRecvContext;
    if (IoResult == NO_ERROR) {
        SocketProc->CurrentRecvContext = NULL;
    }

    PSOCKADDR_INET RemoteAddr = &RecvContext->Tuple.RemoteAddress;
    PSOCKADDR_INET LocalAddr = &RecvContext->Tuple.LocalAddress;

    if (IoResult == WSAENOTSOCK || IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;

    } else if (IsUnreachableErrorCode(IoResult)) {

        CxPlatSocketHandleUnreachableError(SocketProc, IoResult);

    } else if (IoResult == ERROR_MORE_DATA ||
        (IoResult == NO_ERROR && SocketProc->RecvWsaBuf.len < NumberOfBytesTransferred)) {

        CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

#if QUIC_CLOG
        QuicTraceLogVerbose(
            DatapathTooLarge,
            "[data][%p] Received larger than expected datagram from %!ADDR!",
            SocketProc->Parent,
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
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

        for (WSACMSGHDR *CMsg = WSA_CMSG_FIRSTHDR(&SocketProc->RecvWsaMsgHdr);
            CMsg != NULL;
            CMsg = WSA_CMSG_NXTHDR(&SocketProc->RecvWsaMsgHdr, CMsg)) {

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
#ifdef UDP_RECV_MAX_COALESCED_SIZE
            } else if (CMsg->cmsg_level == IPPROTO_UDP) {
                if (CMsg->cmsg_type == UDP_COALESCED_INFO) {
                    CXPLAT_DBG_ASSERT(*(PDWORD)WSA_CMSG_DATA(CMsg) <= MAX_URO_PAYLOAD_LENGTH);
                    MessageLength = (UINT16)*(PDWORD)WSA_CMSG_DATA(CMsg);
                    IsCoalesced = TRUE;
                }
#endif
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
            CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= SocketProc->RecvWsaBuf.len);

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
            Datagram->Tuple = &RecvContext->Tuple;
            Datagram->PartitionIndex = DatapathProc->Index;
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

        SocketProc->Parent->Datapath->UdpHandlers.Receive(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            RecvDataChain);

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSARecvMsg completion");
    }

Drop:
    //
    // Try to start a new receive.
    //
    (void)CxPlatSocketStartReceive(SocketProc, DatapathProc);
}

void
CxPlatDataPathTcpRecvComplete(
    _In_ CXPLAT_DATAPATH_PROC* DatapathProc,
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG IoResult,
    _In_ UINT16 NumberOfBytesTransferred
    )
{
    //
    // Copy the current receive buffer locally. On error cases, we leave the
    // buffer set as the current receive buffer because we are only using it
    // inline. Otherwise, we remove it as the current because we are giving
    // it to the client.
    //
    CXPLAT_DBG_ASSERT(SocketProc->CurrentRecvContext != NULL);
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = SocketProc->CurrentRecvContext;
    if (IoResult == NO_ERROR) {
        SocketProc->CurrentRecvContext = NULL;
    }

    PSOCKADDR_INET RemoteAddr = &RecvContext->Tuple.RemoteAddress;
    PSOCKADDR_INET LocalAddr = &RecvContext->Tuple.LocalAddress;

    if (IoResult == WSAENOTSOCK ||
        IoResult == WSA_OPERATION_ABORTED ||
        IoResult == ERROR_NETNAME_DELETED) {
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
        return;

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
            CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= SocketProc->RecvWsaBuf.len);

        CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
        CXPLAT_RECV_DATA* Data = (CXPLAT_RECV_DATA*)(RecvContext + 1);

        CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext =
            CxPlatDataPathDatagramToInternalDatagramContext(Data);
        InternalDatagramContext->RecvContext = RecvContext;

        Data->Next = NULL;
        Data->Buffer = ((PUCHAR)RecvContext) + Datapath->RecvPayloadOffset;
        Data->BufferLength = NumberOfBytesTransferred;
        Data->Tuple = &RecvContext->Tuple;
        Data->PartitionIndex = DatapathProc->Index;
        Data->TypeOfService = 0;
        Data->Allocated = TRUE;
        Data->QueuedOnConnection = FALSE;
        RecvContext->ReferenceCount++;

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
    //
    // Try to start a new receive.
    //
    (void)CxPlatSocketStartReceive(SocketProc, DatapathProc);
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
                CxPlatPoolFree(
                    BatchedInternalContext->OwningPool,
                    BatchedInternalContext);
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
        CxPlatPoolFree(
            BatchedInternalContext->OwningPool,
            BatchedInternalContext);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);

    CXPLAT_DATAPATH_PROC* DatapathProc =
        &Socket->Datapath->Processors[GetCurrentProcessorNumber()];

    CXPLAT_SEND_DATA* SendContext =
        CxPlatPoolAlloc(&DatapathProc->SendContextPool);

    if (SendContext != NULL) {
        SendContext->Owner = DatapathProc;
        SendContext->ECN = ECN;
        SendContext->SegmentSize =
            (Socket->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)
                ? MaxPacketSize : 0;
        SendContext->TotalSize = 0;
        SendContext->WsaBufferCount = 0;
        SendContext->ClientBuffer.len = 0;
        SendContext->ClientBuffer.buf = NULL;
    }

    return SendContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendContext
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc = SendContext->Owner;
    CXPLAT_POOL* BufferPool =
        SendContext->SegmentSize > 0 ?
            &DatapathProc->LargeSendBufferPool : &DatapathProc->SendBufferPool;

    for (UINT8 i = 0; i < SendContext->WsaBufferCount; ++i) {
        CxPlatPoolFree(BufferPool, SendContext->WsaBuffers[i].buf);
    }

    CxPlatPoolFree(&DatapathProc->SendContextPool, SendContext);
}

static
BOOLEAN
CxPlatSendContextCanAllocSendSegment(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendContext->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(SendContext->WsaBufferCount > 0);
    CXPLAT_DBG_ASSERT(SendContext->WsaBufferCount <= SendContext->Owner->Datapath->MaxSendBatchSize);

    ULONG BytesAvailable =
        CXPLAT_LARGE_SEND_BUFFER_SIZE -
            SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len -
            SendContext->ClientBuffer.len;

    return MaxBufferLength <= BytesAvailable;
}

static
BOOLEAN
CxPlatSendContextCanAllocSend(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    return
        (SendContext->WsaBufferCount < SendContext->Owner->Datapath->MaxSendBatchSize) ||
        ((SendContext->SegmentSize > 0) &&
            CxPlatSendContextCanAllocSendSegment(SendContext, MaxBufferLength));
}

static
void
CxPlatSendContextFinalizeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ BOOLEAN IsSendingImmediately
    )
{
    if (SendContext->ClientBuffer.len == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendContext->WsaBufferCount > 0) {
            CXPLAT_DBG_ASSERT(SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len < UINT16_MAX);
            SendContext->TotalSize +=
                SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len;
        }
        return;
    }

    CXPLAT_DBG_ASSERT(SendContext->SegmentSize > 0 && SendContext->WsaBufferCount > 0);
    CXPLAT_DBG_ASSERT(SendContext->ClientBuffer.len > 0 && SendContext->ClientBuffer.len <= SendContext->SegmentSize);
    CXPLAT_DBG_ASSERT(CxPlatSendContextCanAllocSendSegment(SendContext, 0));

    //
    // Append the client's buffer segment to our internal send buffer.
    //
    SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len +=
        SendContext->ClientBuffer.len;
    SendContext->TotalSize += SendContext->ClientBuffer.len;

    if (SendContext->ClientBuffer.len == SendContext->SegmentSize) {
        SendContext->ClientBuffer.buf += SendContext->SegmentSize;
        SendContext->ClientBuffer.len = 0;
    } else {
        //
        // The next segment allocation must create a new backing buffer.
        //
        CXPLAT_DBG_ASSERT(IsSendingImmediately); // Future: Refactor so it's impossible to hit this.
        UNREFERENCED_PARAMETER(IsSendingImmediately);
        SendContext->ClientBuffer.buf = NULL;
        SendContext->ClientBuffer.len = 0;
    }
}

_Success_(return != NULL)
static
WSABUF*
CxPlatSendContextAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ CXPLAT_POOL* BufferPool
    )
{
    CXPLAT_DBG_ASSERT(SendContext->WsaBufferCount < SendContext->Owner->Datapath->MaxSendBatchSize);

    WSABUF* WsaBuffer = &SendContext->WsaBuffers[SendContext->WsaBufferCount];
    WsaBuffer->buf = CxPlatPoolAlloc(BufferPool);
    if (WsaBuffer->buf == NULL) {
        return NULL;
    }
    ++SendContext->WsaBufferCount;

    return WsaBuffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendContextAllocPacketBuffer(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    WSABUF* WsaBuffer =
        CxPlatSendContextAllocBuffer(SendContext, &SendContext->Owner->SendBufferPool);
    if (WsaBuffer != NULL) {
        WsaBuffer->len = MaxBufferLength;
    }
    return (QUIC_BUFFER*)WsaBuffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendContextAllocSegmentBuffer(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendContext->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= SendContext->SegmentSize);

    CXPLAT_DATAPATH_PROC* DatapathProc = SendContext->Owner;
    WSABUF* WsaBuffer;

    if (SendContext->ClientBuffer.buf != NULL &&
        CxPlatSendContextCanAllocSendSegment(SendContext, MaxBufferLength)) {

        //
        // All clear to return the next segment of our contiguous buffer.
        //
        SendContext->ClientBuffer.len = MaxBufferLength;
        return (QUIC_BUFFER*)&SendContext->ClientBuffer;
    }

    WsaBuffer = CxPlatSendContextAllocBuffer(SendContext, &DatapathProc->LargeSendBufferPool);
    if (WsaBuffer == NULL) {
        return NULL;
    }

    //
    // Provide a virtual WSABUF to the client. Once the client has committed
    // to a final send size, we'll append it to our internal backing buffer.
    //
    WsaBuffer->len = 0;
    SendContext->ClientBuffer.buf = WsaBuffer->buf;
    SendContext->ClientBuffer.len = MaxBufferLength;

    return (QUIC_BUFFER*)&SendContext->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendContext != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

    CxPlatSendContextFinalizeSendBuffer(SendContext, FALSE);

    if (!CxPlatSendContextCanAllocSend(SendContext, MaxBufferLength)) {
        return NULL;
    }

    if (SendContext->SegmentSize == 0) {
        return CxPlatSendContextAllocPacketBuffer(SendContext, MaxBufferLength);
    } else {
        return CxPlatSendContextAllocSegmentBuffer(SendContext, MaxBufferLength);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
{
    //
    // This must be the final send buffer; intermediate buffers cannot be freed.
    //
    CXPLAT_DATAPATH_PROC* DatapathProc = SendContext->Owner;
    PCHAR TailBuffer = SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].buf;

    if (SendContext->SegmentSize == 0) {
        CXPLAT_DBG_ASSERT(Datagram->Buffer == (uint8_t*)TailBuffer);

        CxPlatPoolFree(&DatapathProc->SendBufferPool, Datagram->Buffer);
        --SendContext->WsaBufferCount;
    } else {
        TailBuffer += SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len;
        CXPLAT_DBG_ASSERT(Datagram->Buffer == (uint8_t*)TailBuffer);

        if (SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len == 0) {
            CxPlatPoolFree(&DatapathProc->LargeSendBufferPool, Datagram->Buffer);
            --SendContext->WsaBufferCount;
        }

        SendContext->ClientBuffer.buf = NULL;
        SendContext->ClientBuffer.len = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendContext
    )
{
    return !CxPlatSendContextCanAllocSend(SendContext, SendContext->SegmentSize);
}

void
CxPlatSendContextComplete(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ ULONG IoResult
    )
{
    UNREFERENCED_PARAMETER(SocketProc);
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSASendMsg completion");
    }

    CxPlatSendDataFree(SendContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendContext
    )
{
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath;
    CXPLAT_SOCKET_PROC* SocketProc;
    int Result;
    DWORD BytesSent;

    CXPLAT_DBG_ASSERT(
        Socket != NULL && LocalAddress != NULL &&
        RemoteAddress != NULL && SendContext != NULL);

    if (SendContext->WsaBufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    CxPlatSendContextFinalizeSendBuffer(SendContext, TRUE);

    Datapath = Socket->Datapath;
    SocketProc = &Socket->Processors[Socket->HasFixedRemoteAddress ? 0 : GetCurrentProcessorNumber()];

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendContext->TotalSize,
        SendContext->WsaBufferCount,
        SendContext->SegmentSize,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

    //
    // Map V4 address to dual-stack socket format.
    //
    SOCKADDR_INET MappedRemoteAddress = { 0 };
    CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

    BYTE CtrlBuf[
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(INT)) +           // IP_ECN
#ifdef UDP_SEND_MSG_SIZE
        WSA_CMSG_SPACE(sizeof(DWORD))           // UDP_SEND_MSG_SIZE
#endif
        ];

    WSAMSG WSAMhdr;
    WSAMhdr.dwFlags = 0;
    if (Socket->HasFixedRemoteAddress) {
        WSAMhdr.name = NULL;
        WSAMhdr.namelen = 0;
    } else {
        WSAMhdr.name = (LPSOCKADDR)&MappedRemoteAddress;
        WSAMhdr.namelen = sizeof(MappedRemoteAddress);
    }
    WSAMhdr.lpBuffers = SendContext->WsaBuffers;
    WSAMhdr.dwBufferCount = SendContext->WsaBufferCount;
    WSAMhdr.Control.buf = (PCHAR)CtrlBuf;
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
        *(PINT)WSA_CMSG_DATA(CMsg) = SendContext->ECN;

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
        *(PINT)WSA_CMSG_DATA(CMsg) = SendContext->ECN;
    }

#ifdef UDP_SEND_MSG_SIZE
    if (SendContext->SegmentSize > 0) {
        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(DWORD));
        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
        CXPLAT_DBG_ASSERT(CMsg != NULL);
        CMsg->cmsg_level = IPPROTO_UDP;
        CMsg->cmsg_type = UDP_SEND_MSG_SIZE;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD));
        *(PDWORD)WSA_CMSG_DATA(CMsg) = SendContext->SegmentSize;
    }
#endif

    //
    // Start the async send.
    //
    RtlZeroMemory(&SendContext->Overlapped, sizeof(OVERLAPPED));
    if (Socket->Type == CXPLAT_SOCKET_UDP) {
        Result =
            Datapath->WSASendMsg(
                SocketProc->Socket,
                &WSAMhdr,
                0,
                &BytesSent,
                &SendContext->Overlapped,
                NULL);
    } else {
        Result =
            WSASend(
                SocketProc->Socket,
                SendContext->WsaBuffers,
                SendContext->WsaBufferCount,
                &BytesSent,
                0,
                &SendContext->Overlapped,
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
        CxPlatSendContextComplete(
            SocketProc,
            SendContext,
            QUIC_STATUS_SUCCESS);
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        CxPlatSendDataFree(SendContext);
    }

    return Status;
}

DWORD
WINAPI
CxPlatDataPathWorkerThread(
    _In_ void* CompletionContext
    )
{
    CXPLAT_DATAPATH_PROC* DatapathProc = (CXPLAT_DATAPATH_PROC*)CompletionContext;

    QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[data][%p] Worker start",
        DatapathProc);

    CXPLAT_DBG_ASSERT(DatapathProc != NULL);
    CXPLAT_DBG_ASSERT(DatapathProc->Datapath != NULL);

    CXPLAT_SOCKET_PROC* SocketProc;
    LPOVERLAPPED Overlapped;
    DWORD NumberOfBytesTransferred;
    ULONG IoResult;

    DatapathProc->ThreadId = GetCurrentThreadId();

    while (TRUE) {

        BOOL Result =
            GetQueuedCompletionStatus(
                DatapathProc->IOCP,
                &NumberOfBytesTransferred,
                (PULONG_PTR)&SocketProc,
                &Overlapped,
                INFINITE);

        if (DatapathProc->Datapath->Shutdown) {
            break;
        }

        CXPLAT_DBG_ASSERT(Overlapped != NULL);
        CXPLAT_DBG_ASSERT(SocketProc != NULL);

        IoResult = Result ? NO_ERROR : GetLastError();

        //
        // Overlapped either points to the socket's overlapped or a send
        // overlapped struct.
        //
        if (Overlapped == &SocketProc->Overlapped) {

            /*QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                IoResult,
                "Overlapped Complete");*/

            if (NumberOfBytesTransferred == UINT32_MAX) {
                //
                // The socket context is being shutdown. Run the clean up logic.
                //
                CxPlatDataPathSocketContextShutdown(SocketProc);

            } else if (CxPlatRundownAcquire(&SocketProc->UpcallRundown)) {

                if (SocketProc->Parent->Type == CXPLAT_SOCKET_UDP) {
                    //
                    // We only allow for receiving UINT16 worth of bytes at a time,
                    // which should be plenty for an IPv4 or IPv6 UDP datagram.
                    //
                    CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= 0xFFFF); // TODO - Not true for TCP
                    if (NumberOfBytesTransferred > 0xFFFF &&
                        IoResult == NO_ERROR) {
                        IoResult = ERROR_INVALID_PARAMETER;
                    }

                    //
                    // Handle the receive indication and queue a new receive.
                    //
                    CxPlatDataPathUdpRecvComplete(
                        DatapathProc,
                        SocketProc,
                        IoResult,
                        (UINT16)NumberOfBytesTransferred);

                } else if (SocketProc->Parent->Type == CXPLAT_SOCKET_TCP_LISTENER) {
                    //
                    // Handle the accept indication and queue a new accept.
                    //
                    CxPlatDataPathAcceptComplete(
                        DatapathProc,
                        SocketProc,
                        IoResult);

                } else if (!SocketProc->Parent->ConnectComplete) {

                    //
                    // Handle the accept indication and queue a new accept.
                    //
                    CxPlatDataPathConnectComplete(
                        DatapathProc,
                        SocketProc,
                        IoResult);
                } else {

                    //
                    // Handle the receive indication and queue a new receive.
                    //
                    CxPlatDataPathTcpRecvComplete(
                        DatapathProc,
                        SocketProc,
                        IoResult,
                        (UINT16)NumberOfBytesTransferred);
                }

                CxPlatRundownRelease(&SocketProc->UpcallRundown);
            }

        } else {

            /*QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                IoResult,
                "Overlapped Complete (send)");*/

            CXPLAT_SEND_DATA* SendContext =
                CONTAINING_RECORD(
                    Overlapped,
                    CXPLAT_SEND_DATA,
                    Overlapped);

            CxPlatSendContextComplete(
                SocketProc,
                SendContext,
                IoResult);
        }
    }

    QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[data][%p] Worker stop",
        DatapathProc);

    return NO_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketSetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketGetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ PUINT32 BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
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
        CxPlatSocketAllocRecvContext(
            Socket->Socket->Datapath,
            (UINT16)GetCurrentProcessorNumber());

    if (!RecvContext) {
        return;
    }

    RecvContext->Tuple.RemoteAddress = *SourceAddress;

    CXPLAT_RECV_DATA* Datagram = (CXPLAT_RECV_DATA*)(RecvContext + 1);

    Datagram->Next = NULL;
    Datagram->BufferLength = PacketLength;
    Datagram->Tuple = &RecvContext->Tuple;
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
