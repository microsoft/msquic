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
QuicFuzzerSendMsg(
    _In_ SOCKET s,
    _In_ LPWSAMSG lpMsg,
    _In_ DWORD dwFlags,
    _Out_ LPDWORD lpNumberOfBytesSent,
    _In_ LPWSAOVERLAPPED lpOverlapped,
    _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );

int
QuicFuzzerRecvMsg(
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
#define QUIC_MAX_BATCH_SEND                 7

//
// The maximum UDP receive coalescing payload.
//
#define MAX_URO_PAYLOAD_LENGTH              (UINT16_MAX - QUIC_UDP_HEADER_SIZE)

//
// The maximum single buffer size for sending coalesced payloads.
//
#define QUIC_LARGE_SEND_BUFFER_SIZE         0xFFFF

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

typedef struct QUIC_DATAPATH_PROC QUIC_DATAPATH_PROC;   // Per-processor datapath state.
typedef struct QUIC_SOCKET_PROC QUIC_SOCKET_PROC;       // Per-processor socket state.

//
// Internal receive context.
//
typedef struct QUIC_DATAPATH_INTERNAL_RECV_CONTEXT {

    //
    // The owning datagram pool.
    //
    QUIC_POOL* OwningPool;

    //
    // The reference count of the receive buffer.
    //
    ULONG ReferenceCount;

    //
    // Contains the 4 tuple.
    //
    QUIC_TUPLE Tuple;

} QUIC_DATAPATH_INTERNAL_RECV_CONTEXT;

//
// Internal receive context.
//
typedef struct QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT {

    //
    // The owning allocation.
    //
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext;

} QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT;

//
// Send context.
//
typedef struct QUIC_SEND_DATA {

    //
    // The Overlapped structure for I/O completion.
    //
    OVERLAPPED Overlapped;

    //
    // The owning processor context.
    //
    QUIC_DATAPATH_PROC* Owner;

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
    QUIC_ECN_TYPE ECN;

    //
    // The current number of WsaBuffers used.
    //
    UINT8 WsaBufferCount;

    //
    // Contains all the datagram buffers to pass to the socket.
    //
    WSABUF WsaBuffers[QUIC_MAX_BATCH_SEND];

    //
    // The WSABUF returned to the client for segmented sends.
    //
    WSABUF ClientBuffer;

} QUIC_SEND_DATA;

//
// Per-processor socket state.
//
typedef struct QUIC_SOCKET_PROC {

    //
    // Parent QUIC_SOCKET.
    //
    QUIC_SOCKET* Parent;

    //
    // Socket handle to the networking stack.
    //
    SOCKET Socket;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    QUIC_RUNDOWN_REF UpcallRundown;

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
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* CurrentRecvContext;
    };
    //
    // TCP Listener socket data
    //
    QUIC_SOCKET* AcceptSocket;
    };
    OVERLAPPED RecvOverlapped;

} QUIC_SOCKET_PROC;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct QUIC_SOCKET {

    //
    // Flag indicates the binding has a default remote destination.
    //
    uint8_t Connected : 1;

    //
    // Socket type.
    //
    uint8_t Type : 2; // QUIC_SOCKET_TYPE

    //
    // The index of the affinitized receive processor for a connected socket.
    //
    uint16_t ConnectedProcessorAffinity;

    //
    // Parent datapath.
    //
    QUIC_DATAPATH* Datapath;

    //
    // The local address and UDP port.
    //
    SOCKADDR_INET LocalAddress;

    //
    // The remote address and UDP port.
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
    QUIC_SOCKET_PROC Processors[0];

} QUIC_SOCKET;

//
// Represents a single IO completion port and thread for processing work that
// is completed on a single processor.
//
typedef struct QUIC_DATAPATH_PROC {

    //
    // Parent datapath.
    //
    QUIC_DATAPATH* Datapath;

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
    QUIC_POOL SendContextPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //
    QUIC_POOL SendBufferPool;

    //
    // Pool of large segmented send buffers to be shared by all sockets on this
    // core.
    //
    QUIC_POOL LargeSendBufferPool;

    //
    // Pool of receive datagram contexts and buffers to be shared by all sockets
    // on this core.
    //
    QUIC_POOL RecvDatagramPool;

} QUIC_DATAPATH_PROC;

//
// Main structure for tracking all UDP abstractions.
//
typedef struct QUIC_DATAPATH {

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
    // Function pointer to WSASendMsg.
    //
    LPFN_WSASENDMSG WSASendMsg;

    //
    // Function pointer to WSARecvMsg.
    //
    LPFN_WSARECVMSG WSARecvMsg;

    //
    // Function pointer to AcceptEx.
    //
    LPFN_ACCEPTEX AcceptEx;

    //
    // Rundown for waiting on binding cleanup.
    //
    QUIC_RUNDOWN_REF SocketsRundown;

    //
    // The client callback function pointers.
    //
    QUIC_DATAPATH_ACCEPT_CALLBACK_HANDLER AcceptHandler;
    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvHandler;
    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableHandler;

    //
    // Size of the client's QUIC_RECV_PACKET.
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
    QUIC_DATAPATH_PROC Processors[0];

} QUIC_DATAPATH;

QUIC_RECV_DATA*
QuicDataPathRecvPacketToRecvData(
    _In_ const QUIC_RECV_PACKET* const Context
    )
{
    return (QUIC_RECV_DATA*)
        (((PUCHAR)Context) -
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) -
            sizeof(QUIC_RECV_DATA));
}

QUIC_RECV_PACKET*
QuicDataPathRecvDataToRecvPacket(
    _In_ const QUIC_RECV_DATA* const Datagram
    )
{
    return (QUIC_RECV_PACKET*)
        (((PUCHAR)Datagram) +
            sizeof(QUIC_RECV_DATA) +
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT));
}

QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*
QuicDataPathDatagramToInternalDatagramContext(
    _In_ QUIC_RECV_DATA* Datagram
    )
{
    return (QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*)
        (((PUCHAR)Datagram) + sizeof(QUIC_RECV_DATA));
}

//
// Callback function for IOCP Worker Thread.
//
DWORD
WINAPI
QuicDataPathWorkerThread(
    _In_ void* Context
    );

void
QuicDataPathQueryRssScalabilityInfo(
    _Inout_ QUIC_DATAPATH* Datapath
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
            "[ udp] RSS helper socket failed to open, 0x%x",
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
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            WsaError);
        goto Error;
    }

    if (RssInfo.RssEnabled) {
        Datapath->Features |= QUIC_DATAPATH_FEATURE_RECV_SIDE_SCALING;
    }

Error:

    if (RssSocket != INVALID_SOCKET) {
        closesocket(RssSocket);
    }
}

QUIC_STATUS
QuicDataPathQuerySockoptSupport(
    _Inout_ QUIC_DATAPATH* Datapath
    )
{
    int Result;
    int OptionLength;
    DWORD BytesReturned;
    GUID WSASendMsgGuid = WSAID_WSASENDMSG;
    GUID WSARecvMsgGuid = WSAID_WSARECVMSG;
    GUID AcceptExGuid = WSAID_ACCEPTEX;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    SOCKET UdpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (UdpSocket == INVALID_SOCKET) {
        int WsaError = WSAGetLastError();
        QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[ udp] UDP send segmentation helper socket failed to open, 0x%x",
            WsaError);
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
            "[ udp] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
            WsaError);
    } else {
        Datapath->Features |= QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION;
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
            "[ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
            WsaError);
    } else {
        Datapath->Features |= QUIC_DATAPATH_FEATURE_RECV_COALESCING;
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
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ const QUIC_DATAPATH_CALLBACKS* Callbacks,
    _Out_ QUIC_DATAPATH* *NewDataPath
    )
{
    int WsaError;
    QUIC_STATUS Status;
    WSADATA WsaData;
    QUIC_DATAPATH* Datapath;
    uint32_t DatapathLength;

    uint32_t MaxProcCount = QuicProcActiveCount();
    QUIC_DBG_ASSERT(MaxProcCount <= UINT16_MAX - 1);
    if (MaxProcCount >= UINT16_MAX) {
        MaxProcCount = UINT16_MAX - 1;
    }

    if (Callbacks == NULL ||
        Callbacks->Receive == NULL ||
        Callbacks->Unreachable == NULL ||
        NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        Datapath = NULL;
        goto Exit;
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
        sizeof(QUIC_DATAPATH) +
        MaxProcCount * sizeof(QUIC_DATAPATH_PROC);

    Datapath = (QUIC_DATAPATH*)QUIC_ALLOC_PAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    RtlZeroMemory(Datapath, DatapathLength);
    Datapath->AcceptHandler = Callbacks->Accept;
    Datapath->RecvHandler = Callbacks->Receive;
    Datapath->UnreachableHandler = Callbacks->Unreachable;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = (uint16_t)MaxProcCount;
    QuicRundownInitialize(&Datapath->SocketsRundown);

    QuicDataPathQueryRssScalabilityInfo(Datapath);
    Status = QuicDataPathQuerySockoptSupport(Datapath);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION) {
        //
        // UDP send batching is actually supported on even earlier Windows
        // versions than USO, but we have no good way to dynamically query
        // support level. So we just couple the two features' support level
        // together, since send batching is guaranteed to be supported if USO
        // is.
        //
        Datapath->MaxSendBatchSize = QUIC_MAX_BATCH_SEND;
    } else {
        Datapath->MaxSendBatchSize = 1;
    }

    uint32_t MessageCount =
        (Datapath->Features & QUIC_DATAPATH_FEATURE_RECV_COALESCING)
            ? URO_MAX_DATAGRAMS_PER_INDICATION : 1;

    Datapath->DatagramStride =
        ALIGN_UP(
            sizeof(QUIC_RECV_DATA) +
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) +
            ClientRecvContextLength,
            PVOID);
    Datapath->RecvPayloadOffset =
        sizeof(QUIC_DATAPATH_INTERNAL_RECV_CONTEXT) +
        MessageCount * Datapath->DatagramStride;

    uint32_t RecvDatagramLength =
        Datapath->RecvPayloadOffset +
            ((Datapath->Features & QUIC_DATAPATH_FEATURE_RECV_COALESCING) ?
                MAX_URO_PAYLOAD_LENGTH : MAX_UDP_PAYLOAD_LENGTH);

    for (uint16_t i = 0; i < Datapath->ProcCount; i++) {

        //
        // This creates a per processor IO completion port and thread. It
        // explicitly affinitizes the thread to a processor. This is so that
        // our per UDP socket receives maintain their RSS core all the way up.
        //

        Datapath->Processors[i].Datapath = Datapath;
        Datapath->Processors[i].Index = i;

        QuicPoolInitialize(
            FALSE,
            sizeof(QUIC_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            &Datapath->Processors[i].SendContextPool);

        QuicPoolInitialize(
            FALSE,
            MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            &Datapath->Processors[i].SendBufferPool);

        QuicPoolInitialize(
            FALSE,
            QUIC_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            &Datapath->Processors[i].LargeSendBufferPool);

        QuicPoolInitialize(
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
                QuicDataPathWorkerThread,
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

        const QUIC_PROCESSOR_INFO* ProcInfo = &QuicProcessorInfo[i];
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
        SetThreadDescription(Datapath->Processors[i].CompletionThread, L"quic_datapath");
#else
        THREAD_NAME_INFORMATION ThreadNameInfo;
        RtlInitUnicodeString(&ThreadNameInfo.ThreadName, L"quic_datapath");
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
                QuicPoolUninitialize(&Datapath->Processors[i].SendContextPool);
                QuicPoolUninitialize(&Datapath->Processors[i].SendBufferPool);
                QuicPoolUninitialize(&Datapath->Processors[i].LargeSendBufferPool);
                QuicPoolUninitialize(&Datapath->Processors[i].RecvDatagramPool);
            }
            QuicRundownUninitialize(&Datapath->SocketsRundown);
            QUIC_FREE(Datapath, QUIC_POOL_DATAPATH);
        }
        (void)WSACleanup();
    }

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }

    //
    // Wait for all outstanding binding to clean up.
    //
    QuicRundownReleaseAndWait(&Datapath->SocketsRundown);

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
        QuicPoolUninitialize(&Datapath->Processors[i].SendContextPool);
        QuicPoolUninitialize(&Datapath->Processors[i].SendBufferPool);
        QuicPoolUninitialize(&Datapath->Processors[i].LargeSendBufferPool);
        QuicPoolUninitialize(&Datapath->Processors[i].RecvDatagramPool);
    }

    QuicRundownUninitialize(&Datapath->SocketsRundown);
    QUIC_FREE(Datapath, QUIC_POOL_DATAPATH);

    WSACleanup();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return Datapath->Features;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return !!(Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

void
QuicDataPathPopulateTargetAddress(
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
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
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

    HostNameW = QUIC_ALLOC_PAGED(sizeof(WCHAR) * Result, QUIC_POOL_PLATFORM_TMP_ALLOC);
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
        QuicDataPathPopulateTargetAddress((ADDRESS_FAMILY)Hints.ai_family, Ai, Address);
        FreeAddrInfoW(Ai);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    if (GetAddrInfoW(HostNameW, NULL, &Hints, &Ai) == 0) {
        QuicDataPathPopulateTargetAddress((ADDRESS_FAMILY)Hints.ai_family, Ai, Address);
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
        QUIC_FREE(HostNameW, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

    return Status;
}

QUIC_STATUS
QuicSocketStartReceive(
    _In_ QUIC_SOCKET_PROC* SocketProc,
    _In_ QUIC_DATAPATH_PROC* DatapathProc
    );

QUIC_STATUS
QuicSocketStartAccept(
    _In_ QUIC_SOCKET_PROC* SocketProc,
    _In_ QUIC_DATAPATH_PROC* DatapathProc
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ QUIC_SOCKET_TYPE Type,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status;
    int Result;
    int Option;
    BOOLEAN IsUdpSocket = Type == QUIC_SOCKET_UDP;
    BOOLEAN IsServerSocket = RemoteAddress == NULL;
    uint16_t SocketCount = (IsUdpSocket && IsServerSocket) ? Datapath->ProcCount : 1;

    QUIC_DBG_ASSERT(Type != QUIC_SOCKET_TCP_LISTENER || RemoteAddress == NULL);
    QUIC_DBG_ASSERT(Type != QUIC_SOCKET_TCP_LISTENER || Datapath->AcceptHandler != NULL);

    uint32_t SocketLength =
        sizeof(QUIC_SOCKET) + SocketCount * sizeof(QUIC_SOCKET_PROC);
    QUIC_SOCKET* Socket = QUIC_ALLOC_PAGED(SocketLength, QUIC_POOL_SOCKET);
    if (Socket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_SOCKET",
            SocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicTraceEvent(
        DatapathCreated,
        "[ udp][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    ZeroMemory(Socket, SocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->Connected = (RemoteAddress != NULL);
    Socket->Type = Type;
    if (LocalAddress) {
        QuicConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = QUIC_MAX_MTU;
    QuicRundownAcquire(&Datapath->SocketsRundown);

    for (uint16_t i = 0; i < SocketCount; i++) {
        Socket->Processors[i].Parent = Socket;
        Socket->Processors[i].Socket = INVALID_SOCKET;
        Socket->Processors[i].RecvWsaBuf.len =
            (Datapath->Features & QUIC_DATAPATH_FEATURE_RECV_COALESCING) ?
                MAX_URO_PAYLOAD_LENGTH :
                Socket->Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
        QuicRundownInitialize(&Socket->Processors[i].UpcallRundown);
    }

    for (uint16_t i = 0; i < SocketCount; i++) {

        QUIC_SOCKET_PROC* SocketProc = &Socket->Processors[i];
        uint16_t AffinitizedProcessor = (uint16_t)i;
        DWORD BytesReturned;

        SocketProc->Socket =
            WSASocketW(
                AF_INET6,
                IsUdpSocket ? SOCK_DGRAM : SOCK_STREAM,
                IsUdpSocket ? IPPROTO_UDP : IPPROTO_TCP,
                NULL,
                0,
                WSA_FLAG_OVERLAPPED);
        if (SocketProc->Socket == INVALID_SOCKET) {
            int WsaError = WSAGetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
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
                "[ udp][%p] ERROR, %u, %s.",
                Socket,
                WsaError,
                "Set IPV6_V6ONLY");
            Status = HRESULT_FROM_WIN32(WsaError);
            goto Error;
        }

        if (IsUdpSocket) {
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
                        "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
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
                    "[ udp][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "Set SO_RCVBUF");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

#ifdef UDP_RECV_MAX_COALESCED_SIZE
            if (Datapath->Features & QUIC_DATAPATH_FEATURE_RECV_COALESCING) {
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
                        "[ udp][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "Set UDP_RECV_MAX_COALESCED_SIZE");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Error;
                }
            }
#endif
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
                "[ udp][%p] ERROR, %u, %s.",
                Socket,
                LastError,
                "SetFileCompletionNotificationModes");
            Status = HRESULT_FROM_WIN32(LastError);
            goto Error;
        }

        if (Type != QUIC_SOCKET_TCP_SERVER) {
QUIC_DISABLED_BY_FUZZER_START;

            Result =
                bind(
                    SocketProc->Socket,
                    (PSOCKADDR)&Socket->LocalAddress,
                    sizeof(Socket->LocalAddress));
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "bind");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

QUIC_DISABLED_BY_FUZZER_END;

            if (RemoteAddress != NULL) {
                SOCKADDR_INET MappedRemoteAddress = { 0 };
                QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

QUIC_DISABLED_BY_FUZZER_START;

                Result =
                    connect(
                        SocketProc->Socket,
                        (PSOCKADDR)&MappedRemoteAddress,
                        sizeof(MappedRemoteAddress));
                if (Result == SOCKET_ERROR) {
                    int WsaError = WSAGetLastError();
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[ udp][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "connect");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Error;
                }

QUIC_DISABLED_BY_FUZZER_END;

                //
                // RSS affinitization has some problems:
                //
                // 1. The RSS indirection table can change at any time. There is no
                //    notification API for RSS rebalancing, so static assignment at
                //    binding time is the closest approximation.
                // 2. There may be no RSS capability at all, in which case we must
                //    choose a processor index. We fall back to the current
                //    processor index: the caller of this routine is already a load
                //    balanced connection worker.
                //

                AffinitizedProcessor =
                    ((uint16_t)QuicProcCurrentNumber()) % Datapath->ProcCount;

#if 0
                //
                // Several miniport drivers that are capable of hashing UDP 4-tuples
                // are incorrectly reporting themselves as IP 2-tuple capable only.
                // This leads to poor load distribution if we have traffic over many
                // unique UDP port pairs. Until hardware vendors provide updated
                // drivers, always fall back to non-RSS receive worker affinity.
                //

                if (Datapath->RssMode != QUIC_RSS_NONE) {
                    SOCKET_PROCESSOR_AFFINITY RssAffinity = { 0 };

                    Result =
                        WSAIoctl(
                            SocketProc->Socket,
                            SIO_QUERY_RSS_PROCESSOR_INFO,
                            NULL,
                            0,
                            &RssAffinity,
                            sizeof(RssAffinity),
                            &BytesReturned,
                            NULL,
                            NULL);
                    if (Result == SOCKET_ERROR) {
                        int WsaError = WSAGetLastError();
                        QuicTraceLogWarning(
                            DatapathQueryProcessorAffinityFailed,
                            "[ udp][%p] WSAIoctl for SIO_QUERY_RSS_PROCESSOR_INFO failed, 0x%x",
                            Socket,
                            WsaError);
                    } else {
                        AffinitizedProcessor =
                            (RssAffinity.Processor.Number % Datapath->ProcCount);
                    }
                }
#endif

                Socket->ConnectedProcessorAffinity = AffinitizedProcessor;
            }

            if (Datapath->Processors[AffinitizedProcessor].IOCP !=
                CreateIoCompletionPort(
                    (HANDLE)SocketProc->Socket,
                    Datapath->Processors[AffinitizedProcessor].IOCP,
                    (ULONG_PTR)SocketProc,
                    0)) {
                DWORD LastError = GetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Socket,
                    LastError,
                    "CreateIoCompletionPort");
                Status = HRESULT_FROM_WIN32(LastError);
                goto Error;
            }

            if (i == 0) {

                //
                // If no specific local port was indicated, then the stack just
                // assigned this socket a port. We need to query it and use it for
                // all the other sockets we are going to create.
                //

QUIC_DISABLED_BY_FUZZER_START;

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
                        "[ udp][%p] ERROR, %u, %s.",
                        Socket,
                        WsaError,
                        "getsockaddress");
                    Status = HRESULT_FROM_WIN32(WsaError);
                    goto Error;
                }

                if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
                    QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
                }

QUIC_DISABLED_BY_FUZZER_END;

            }
        }
    }

    QuicConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    if (RemoteAddress != NULL) {
        Socket->RemoteAddress = *RemoteAddress;
    } else {
        Socket->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewSocket = Socket;

    Socket->ProcsOutstanding = (short)SocketCount;
    for (uint16_t i = 0; i < SocketCount; i++) {
        uint16_t Processor =
            Socket->Connected ? Socket->ConnectedProcessorAffinity : i;

        if (Type == QUIC_SOCKET_TCP_LISTENER) {
            Result =
                listen(
                    Socket->Processors[i].Socket,
                    100);
            if (Result == SOCKET_ERROR) {
                int WsaError = WSAGetLastError();
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
                    Socket,
                    WsaError,
                    "listen");
                Status = HRESULT_FROM_WIN32(WsaError);
                goto Error;
            }

            Status =
                QuicSocketStartAccept(
                    &Socket->Processors[i],
                    &Datapath->Processors[Processor]);
            if (QUIC_FAILED(Status)) {
                goto Error;
            }

        } else if (Type != QUIC_SOCKET_TCP_SERVER) {
            Status =
                QuicSocketStartReceive(
                    &Socket->Processors[i],
                    &Datapath->Processors[Processor]);
            if (QUIC_FAILED(Status)) {
                goto Error;
            }
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Socket != NULL) {
            QuicTraceEvent(
                DatapathDestroyed,
                "[ udp][%p] Destroyed",
                Socket);
            if (Socket->ProcsOutstanding != 0) {
                for (uint16_t i = 0; i < SocketCount; i++) {
                    QUIC_SOCKET_PROC* SocketProc = &Socket->Processors[i];
                    uint16_t Processor =
                         Socket->Connected ? Socket->ConnectedProcessorAffinity : i;

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
                        &SocketProc->RecvOverlapped);
                }
            } else {
                for (uint16_t i = 0; i < SocketCount; i++) {
                    QUIC_SOCKET_PROC* SocketProc = &Socket->Processors[i];

QUIC_DISABLED_BY_FUZZER_START;

                    if (SocketProc->Socket != INVALID_SOCKET) {
                        closesocket(SocketProc->Socket);
                    }

QUIC_DISABLED_BY_FUZZER_END;

                    QuicRundownUninitialize(&SocketProc->UpcallRundown);
                }
                QuicRundownRelease(&Datapath->SocketsRundown);
                QUIC_FREE(Socket, QUIC_POOL_SOCKET);
            }
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicSocketDelete(
    _In_ QUIC_SOCKET* Socket
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    QuicTraceEvent(
        DatapathDestroyed,
        "[ udp][%p] Destroyed",
        Socket);

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    QUIC_DATAPATH* Datapath = Socket->Datapath;

    if (Socket->Connected) {
        QUIC_SOCKET_PROC* SocketProc = &Socket->Processors[0];
        uint32_t Processor = Socket->ConnectedProcessorAffinity;
        QUIC_DBG_ASSERT(
            Datapath->Processors[Processor].ThreadId != GetCurrentThreadId());
        QuicRundownReleaseAndWait(&SocketProc->UpcallRundown);

QUIC_DISABLED_BY_FUZZER_START;

        CancelIo((HANDLE)SocketProc->Socket);
        closesocket(SocketProc->Socket);

QUIC_DISABLED_BY_FUZZER_END;

        PostQueuedCompletionStatus(
            Datapath->Processors[Processor].IOCP,
            UINT32_MAX,
            (ULONG_PTR)SocketProc,
            &SocketProc->RecvOverlapped);

    } else {
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            QUIC_SOCKET_PROC* SocketProc = &Socket->Processors[i];
            QUIC_DBG_ASSERT(
                Datapath->Processors[i].ThreadId != GetCurrentThreadId());
            QuicRundownReleaseAndWait(&SocketProc->UpcallRundown);
        }
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            QUIC_SOCKET_PROC* SocketProc = &Socket->Processors[i];
            uint32_t Processor = i;

QUIC_DISABLED_BY_FUZZER_START;

            CancelIo((HANDLE)SocketProc->Socket);
            closesocket(SocketProc->Socket);

QUIC_DISABLED_BY_FUZZER_END;

            PostQueuedCompletionStatus(
                Datapath->Processors[Processor].IOCP,
                UINT32_MAX,
                (ULONG_PTR)SocketProc,
                &SocketProc->RecvOverlapped);
        }
    }

    QuicTraceLogVerbose(
        DatapathShutDownReturn,
        "[ udp][%p] Shut down (return)",
        Socket);
}

void
QuicDataPathSocketContextShutdown(
    _In_ QUIC_SOCKET_PROC* SocketProc
    )
{
    if (SocketProc->Parent->Type == QUIC_SOCKET_TCP_LISTENER) {
        if (SocketProc->AcceptSocket != NULL) {
            QuicSocketDelete(SocketProc->AcceptSocket);
            SocketProc->AcceptSocket = NULL;
        }

    } else if (SocketProc->CurrentRecvContext != NULL) {
        QuicPoolFree(
            SocketProc->CurrentRecvContext->OwningPool,
            SocketProc->CurrentRecvContext);
        SocketProc->CurrentRecvContext = NULL;
    }

    QuicRundownUninitialize(&SocketProc->UpcallRundown);

    if (InterlockedDecrement16(
            &SocketProc->Parent->ProcsOutstanding) == 0) {
        //
        // Last socket context cleaned up, so now the binding can be freed.
        //
        QuicRundownRelease(&SocketProc->Parent->Datapath->SocketsRundown);
        QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[ udp][%p] Shut down (complete)",
            SocketProc->Parent);
        QUIC_FREE(SocketProc->Parent, QUIC_POOL_SOCKET);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
QuicSocketGetLocalMtu(
    _In_ QUIC_SOCKET* Socket
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    return Socket->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSocketGetLocalAddress(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    *Address = Socket->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSocketGetRemoteAddress(
    _In_ QUIC_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);
    *Address = Socket->RemoteAddress;
}

QUIC_DATAPATH_INTERNAL_RECV_CONTEXT*
QuicSocketAllocRecvContext(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ UINT16 ProcIndex
    )
{
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
        QuicPoolAlloc(&Datapath->Processors[ProcIndex].RecvDatagramPool);

    if (RecvContext != NULL) {
        RecvContext->OwningPool =
            &Datapath->Processors[ProcIndex].RecvDatagramPool;
        RecvContext->ReferenceCount = 0;
    }

    return RecvContext;
}

QUIC_STATUS
QuicSocketStartAccept(
    _In_ QUIC_SOCKET_PROC* SocketProc,
    _In_ QUIC_DATAPATH_PROC* DatapathProc
    )
{
    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    DWORD BytesRecv = 0;
    int Result;

    //
    // Initialize a server socket to accept.
    //
    if (SocketProc->AcceptSocket == NULL) {
        Status =
            QuicSocketCreate(
                Datapath,
                QUIC_SOCKET_TCP_SERVER,
                NULL,
                NULL,
                NULL,
                &SocketProc->AcceptSocket);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    RtlZeroMemory(
        &SocketProc->RecvOverlapped,
        sizeof(SocketProc->RecvOverlapped));

    Result =
        Datapath->AcceptEx(
            SocketProc->Socket,
            SocketProc->AcceptSocket->Processors[0].Socket,
            &SocketProc->AcceptSocket->LocalAddress,
            0,                                                  // dwReceiveDataLength
            sizeof(SocketProc->AcceptSocket->LocalAddress),     // dwLocalAddressLength
            sizeof(SocketProc->AcceptSocket->RemoteAddress),    // dwRemoteAddressLength
            &BytesRecv,
            &SocketProc->RecvOverlapped);
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketProc->Parent,
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
                (ULONG_PTR)SocketProc,
                &SocketProc->RecvOverlapped)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
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
QuicSocketHandleUnreachableError(
    _In_ QUIC_SOCKET_PROC* SocketProc,
    _In_ ULONG ErrorCode
    )
{
    PSOCKADDR_INET RemoteAddr =
        &SocketProc->CurrentRecvContext->Tuple.RemoteAddress;
    UNREFERENCED_PARAMETER(ErrorCode);

    QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

#if QUIC_CLOG
    QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[ udp][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketProc->Parent,
        ErrorCode,
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

    QUIC_DBG_ASSERT(SocketProc->Parent->Datapath->UnreachableHandler);
    SocketProc->Parent->Datapath->UnreachableHandler(
        SocketProc->Parent,
        SocketProc->Parent->ClientContext,
        RemoteAddr);
}

void
QuicDataPathAcceptComplete(
    _In_ QUIC_DATAPATH_PROC* DatapathProc,
    _In_ QUIC_SOCKET_PROC* SocketProc,
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
        QUIC_DBG_ASSERT(SocketProc->AcceptSocket != NULL);
        QUIC_SOCKET_PROC* AcceptSocketProc = &SocketProc->AcceptSocket->Processors[0];

        // TODO - Query for RSS info

        if (DatapathProc->IOCP !=
            CreateIoCompletionPort(
                (HANDLE)AcceptSocketProc->Socket,
                DatapathProc->IOCP,
                (ULONG_PTR)AcceptSocketProc,
                0)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                SocketProc->AcceptSocket,
                LastError,
                "CreateIoCompletionPort");
            goto Error;
        }

        if (QUIC_FAILED(
            QuicSocketStartReceive(
                AcceptSocketProc,
                DatapathProc))) {
            goto Error;
        }

        SocketProc->Parent->Datapath->AcceptHandler(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            SocketProc->AcceptSocket,
            &SocketProc->AcceptSocket->ClientContext);
        SocketProc->AcceptSocket = NULL;

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "AcceptEx completion");
    }

Error:

    if (SocketProc->AcceptSocket != NULL) {
        // TODO
    }

    //
    // Try to start a new accept.
    //
    (void)QuicSocketStartAccept(SocketProc, DatapathProc);
}

QUIC_STATUS
QuicSocketStartReceive(
    _In_ QUIC_SOCKET_PROC* SocketProc,
    _In_ QUIC_DATAPATH_PROC* DatapathProc
    )
{
    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    int Result;
    DWORD BytesRecv = 0;

    //
    // Get a receive buffer we can pass to WinSock.
    //
    if (SocketProc->CurrentRecvContext == NULL) {
        SocketProc->CurrentRecvContext =
            QuicSocketAllocRecvContext(
                Datapath,
                DatapathProc->Index);

        if (SocketProc->CurrentRecvContext == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
    }

    RtlZeroMemory(
        &SocketProc->RecvOverlapped,
        sizeof(SocketProc->RecvOverlapped));

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

    Result =
        SocketProc->Parent->Datapath->WSARecvMsg(
            SocketProc->Socket,
            &SocketProc->RecvWsaMsgHdr,
            &BytesRecv,
            &SocketProc->RecvOverlapped,
            NULL);
    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            if (WsaError == WSAECONNRESET) {
                QuicSocketHandleUnreachableError(SocketProc, (ULONG)WsaError);
                goto Retry_recv;
            } else {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[ udp][%p] ERROR, %u, %s.",
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
                &SocketProc->RecvOverlapped)) {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
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
QuicDataPathRecvComplete(
    _In_ QUIC_DATAPATH_PROC* DatapathProc,
    _In_ QUIC_SOCKET_PROC* SocketProc,
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
    QUIC_DBG_ASSERT(SocketProc->CurrentRecvContext != NULL);
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = SocketProc->CurrentRecvContext;
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

        QuicSocketHandleUnreachableError(SocketProc, IoResult);

    } else if (IoResult == ERROR_MORE_DATA ||
        (IoResult == NO_ERROR && SocketProc->RecvWsaBuf.len < NumberOfBytesTransferred)) {

        QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

#if QUIC_CLOG
        QuicTraceLogVerbose(
            DatapathTooLarge,
            "[ udp][%p] Received larger than expected datagram from %!ADDR!",
            SocketProc->Parent,
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

        //
        // TODO - Indicate to Core library.
        //

    } else if (IoResult == QUIC_STATUS_SUCCESS) {

        QUIC_RECV_DATA* RecvDataChain = NULL;
        QUIC_RECV_DATA** DatagramChainTail = &RecvDataChain;

        QUIC_DATAPATH* Datapath = SocketProc->Parent->Datapath;
        QUIC_RECV_DATA* Datagram;
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
                    QuicConvertFromMappedV6(LocalAddr, LocalAddr);
                    LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;
                } else if (CMsg->cmsg_type == IPV6_ECN) {
                    ECN = *(PINT)WSA_CMSG_DATA(CMsg);
                    QUIC_DBG_ASSERT(ECN < UINT8_MAX);
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
                    QUIC_DBG_ASSERT(ECN < UINT8_MAX);
                }
#ifdef UDP_RECV_MAX_COALESCED_SIZE
            } else if (CMsg->cmsg_level == IPPROTO_UDP) {
                if (CMsg->cmsg_type == UDP_COALESCED_INFO) {
                    QUIC_DBG_ASSERT(*(PDWORD)WSA_CMSG_DATA(CMsg) <= MAX_URO_PAYLOAD_LENGTH);
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
                "[ udp][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketProc->Parent);
            goto Drop;
        }

        if (NumberOfBytesTransferred == 0) {
            QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[ udp][%p] Dropping datagram with empty payload.",
                SocketProc->Parent);
            goto Drop;
        }

        QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

        QuicTraceEvent(
            DatapathRecv,
            "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketProc->Parent,
            NumberOfBytesTransferred,
            MessageLength,
            CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        QUIC_DBG_ASSERT(NumberOfBytesTransferred <= SocketProc->RecvWsaBuf.len);

        Datagram = (QUIC_RECV_DATA*)(RecvContext + 1);

        for ( ;
            NumberOfBytesTransferred != 0;
            NumberOfBytesTransferred -= MessageLength) {

            QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext =
                QuicDataPathDatagramToInternalDatagramContext(Datagram);
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

            Datagram = (QUIC_RECV_DATA*)
                (((PUCHAR)Datagram) +
                    SocketProc->Parent->Datapath->DatagramStride);

            if (IsCoalesced && ++MessageCount == URO_MAX_DATAGRAMS_PER_INDICATION) {
                QuicTraceLogWarning(
                    DatapathUroPreallocExceeded,
                    "[ udp][%p] Exceeded URO preallocation capacity.",
                    SocketProc->Parent);
                break;
            }
        }

        QUIC_DBG_ASSERT(SocketProc->Parent->Datapath->RecvHandler);
        QUIC_DBG_ASSERT(RecvDataChain);

#ifdef QUIC_FUZZER
        if (MsQuicFuzzerContext.RecvCallback) {
            QUIC_RECV_DATA *_DatagramIter = RecvDataChain;

            while (_DatagramIter) {
                MsQuicFuzzerContext.RecvCallback(
                    MsQuicFuzzerContext.CallbackContext,
                    _DatagramIter->Buffer,
                    _DatagramIter->BufferLength);
                _DatagramIter = _DatagramIter->Next;
            }
        }
#endif

        SocketProc->Parent->Datapath->RecvHandler(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            RecvDataChain);

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSARecvMsg completion");
    }

Drop:
    //
    // Try to start a new receive.
    //
    (void)QuicSocketStartReceive(SocketProc, DatapathProc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicRecvDataReturn(
    _In_opt_ QUIC_RECV_DATA* RecvDataChain
    )
{
    QUIC_RECV_DATA* Datagram;

    LONG BatchedBufferCount = 0;
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* BatchedInternalContext = NULL;

    while ((Datagram = RecvDataChain) != NULL) {
        RecvDataChain = RecvDataChain->Next;

        QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalBufferContext =
            QuicDataPathDatagramToInternalDatagramContext(Datagram);
        QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext =
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
                QuicPoolFree(
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
        QuicPoolFree(
            BatchedInternalContext->OwningPool,
            BatchedInternalContext);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_SEND_DATA*
QuicSendDataAlloc(
    _In_ QUIC_SOCKET* Socket,
    _In_ QUIC_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
    QUIC_DBG_ASSERT(Socket != NULL);

    QUIC_DATAPATH_PROC* DatapathProc =
        &Socket->Datapath->Processors[GetCurrentProcessorNumber()];

    QUIC_SEND_DATA* SendContext =
        QuicPoolAlloc(&DatapathProc->SendContextPool);

    if (SendContext != NULL) {
        SendContext->Owner = DatapathProc;
        SendContext->ECN = ECN;
        SendContext->SegmentSize =
            (Socket->Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION)
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
QuicSendDataFree(
    _In_ QUIC_SEND_DATA* SendContext
    )
{
    QUIC_DATAPATH_PROC* DatapathProc = SendContext->Owner;
    QUIC_POOL* BufferPool =
        SendContext->SegmentSize > 0 ?
            &DatapathProc->LargeSendBufferPool : &DatapathProc->SendBufferPool;

    for (UINT8 i = 0; i < SendContext->WsaBufferCount; ++i) {
        QuicPoolFree(BufferPool, SendContext->WsaBuffers[i].buf);
    }

    QuicPoolFree(&DatapathProc->SendContextPool, SendContext);
}

static
BOOLEAN
QuicSendContextCanAllocSendSegment(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0);
    QUIC_DBG_ASSERT(SendContext->WsaBufferCount > 0);
    QUIC_DBG_ASSERT(SendContext->WsaBufferCount <= SendContext->Owner->Datapath->MaxSendBatchSize);

    ULONG BytesAvailable =
        QUIC_LARGE_SEND_BUFFER_SIZE -
            SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len -
            SendContext->ClientBuffer.len;

    return MaxBufferLength <= BytesAvailable;
}

static
BOOLEAN
QuicSendContextCanAllocSend(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    return
        (SendContext->WsaBufferCount < SendContext->Owner->Datapath->MaxSendBatchSize) ||
        ((SendContext->SegmentSize > 0) &&
            QuicSendContextCanAllocSendSegment(SendContext, MaxBufferLength));
}

static
void
QuicSendContextFinalizeSendBuffer(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ BOOLEAN IsSendingImmediately
    )
{
    if (SendContext->ClientBuffer.len == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendContext->WsaBufferCount > 0) {
            QUIC_DBG_ASSERT(SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len < UINT16_MAX);
            SendContext->TotalSize +=
                SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len;
        }
        return;
    }

    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0 && SendContext->WsaBufferCount > 0);
    QUIC_DBG_ASSERT(SendContext->ClientBuffer.len > 0 && SendContext->ClientBuffer.len <= SendContext->SegmentSize);
    QUIC_DBG_ASSERT(QuicSendContextCanAllocSendSegment(SendContext, 0));

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
        QUIC_DBG_ASSERT(IsSendingImmediately); // Future: Refactor so it's impossible to hit this.
        UNREFERENCED_PARAMETER(IsSendingImmediately);
        SendContext->ClientBuffer.buf = NULL;
        SendContext->ClientBuffer.len = 0;
    }
}

_Success_(return != NULL)
static
WSABUF*
QuicSendContextAllocBuffer(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ QUIC_POOL* BufferPool
    )
{
    QUIC_DBG_ASSERT(SendContext->WsaBufferCount < SendContext->Owner->Datapath->MaxSendBatchSize);

    WSABUF* WsaBuffer = &SendContext->WsaBuffers[SendContext->WsaBufferCount];
    WsaBuffer->buf = QuicPoolAlloc(BufferPool);
    if (WsaBuffer->buf == NULL) {
        return NULL;
    }
    ++SendContext->WsaBufferCount;

    return WsaBuffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
QuicSendContextAllocPacketBuffer(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    WSABUF* WsaBuffer =
        QuicSendContextAllocBuffer(SendContext, &SendContext->Owner->SendBufferPool);
    if (WsaBuffer != NULL) {
        WsaBuffer->len = MaxBufferLength;
    }
    return (QUIC_BUFFER*)WsaBuffer;
}

_Success_(return != NULL)
static
QUIC_BUFFER*
QuicSendContextAllocSegmentBuffer(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0);
    QUIC_DBG_ASSERT(MaxBufferLength <= SendContext->SegmentSize);

    QUIC_DATAPATH_PROC* DatapathProc = SendContext->Owner;
    WSABUF* WsaBuffer;

    if (SendContext->ClientBuffer.buf != NULL &&
        QuicSendContextCanAllocSendSegment(SendContext, MaxBufferLength)) {

        //
        // All clear to return the next segment of our contiguous buffer.
        //
        SendContext->ClientBuffer.len = MaxBufferLength;
        return (QUIC_BUFFER*)&SendContext->ClientBuffer;
    }

    WsaBuffer = QuicSendContextAllocBuffer(SendContext, &DatapathProc->LargeSendBufferPool);
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
QuicSendDataAllocBuffer(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength > 0);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    QuicSendContextFinalizeSendBuffer(SendContext, FALSE);

    if (!QuicSendContextCanAllocSend(SendContext, MaxBufferLength)) {
        return NULL;
    }

    if (SendContext->SegmentSize == 0) {
        return QuicSendContextAllocPacketBuffer(SendContext, MaxBufferLength);
    } else {
        return QuicSendContextAllocSegmentBuffer(SendContext, MaxBufferLength);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicSendDataFreeBuffer(
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
{
    //
    // This must be the final send buffer; intermediate buffers cannot be freed.
    //
    QUIC_DATAPATH_PROC* DatapathProc = SendContext->Owner;
    PCHAR TailBuffer = SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].buf;

    if (SendContext->SegmentSize == 0) {
        QUIC_DBG_ASSERT(Datagram->Buffer == (uint8_t*)TailBuffer);

        QuicPoolFree(&DatapathProc->SendBufferPool, Datagram->Buffer);
        --SendContext->WsaBufferCount;
    } else {
        TailBuffer += SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len;
        QUIC_DBG_ASSERT(Datagram->Buffer == (uint8_t*)TailBuffer);

        if (SendContext->WsaBuffers[SendContext->WsaBufferCount - 1].len == 0) {
            QuicPoolFree(&DatapathProc->LargeSendBufferPool, Datagram->Buffer);
            --SendContext->WsaBufferCount;
        }

        SendContext->ClientBuffer.buf = NULL;
        SendContext->ClientBuffer.len = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicSendDataIsFull(
    _In_ QUIC_SEND_DATA* SendContext
    )
{
    return !QuicSendContextCanAllocSend(SendContext, SendContext->SegmentSize);
}

void
QuicSendContextComplete(
    _In_ QUIC_SOCKET_PROC* SocketProc,
    _In_ QUIC_SEND_DATA* SendContext,
    _In_ ULONG IoResult
    )
{
    UNREFERENCED_PARAMETER(SocketProc);
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSASendMsg completion");
    }

    QuicSendDataFree(SendContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicSocketSend(
    _In_ QUIC_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ QUIC_SEND_DATA* SendContext
    )
{
    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath;
    QUIC_SOCKET_PROC* SocketProc;
    int Result;
    DWORD BytesSent;

    QUIC_DBG_ASSERT(
        Socket != NULL && LocalAddress != NULL &&
        RemoteAddress != NULL && SendContext != NULL);

    if (SendContext->WsaBufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicSendContextFinalizeSendBuffer(SendContext, TRUE);

    Datapath = Socket->Datapath;
    SocketProc = &Socket->Processors[Socket->Connected ? 0 : GetCurrentProcessorNumber()];

    QuicTraceEvent(
        DatapathSend,
        "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
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
    QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

    BYTE CtrlBuf[
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(INT)) +           // IP_ECN
#ifdef UDP_SEND_MSG_SIZE
        WSA_CMSG_SPACE(sizeof(DWORD))           // UDP_SEND_MSG_SIZE
#endif
        ];

    WSAMSG WSAMhdr;
    WSAMhdr.dwFlags = 0;
    if (Socket->Connected) {
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

        if (!Socket->Connected) {
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
        QUIC_DBG_ASSERT(CMsg != NULL);
        CMsg->cmsg_level = IPPROTO_IP;
        CMsg->cmsg_type = IP_ECN;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
        *(PINT)WSA_CMSG_DATA(CMsg) = SendContext->ECN;

    } else {

        if (!Socket->Connected) {
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
        QUIC_DBG_ASSERT(CMsg != NULL);
        CMsg->cmsg_level = IPPROTO_IPV6;
        CMsg->cmsg_type = IPV6_ECN;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
        *(PINT)WSA_CMSG_DATA(CMsg) = SendContext->ECN;
    }

#ifdef UDP_SEND_MSG_SIZE
    if (SendContext->SegmentSize > 0) {
        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(DWORD));
        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
        QUIC_DBG_ASSERT(CMsg != NULL);
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
    Result =
        Datapath->WSASendMsg(
            SocketProc->Socket,
            &WSAMhdr,
            0,
            &BytesSent,
            &SendContext->Overlapped,
            NULL);

    if (Result == SOCKET_ERROR) {
        int WsaError = WSAGetLastError();
        if (WsaError != WSA_IO_PENDING) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
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
        QuicSendContextComplete(
            SocketProc,
            SendContext,
            QUIC_STATUS_SUCCESS);
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        QuicSendDataFree(SendContext);
    }

    return Status;
}

DWORD
WINAPI
QuicDataPathWorkerThread(
    _In_ void* CompletionContext
    )
{
    QUIC_DATAPATH_PROC* DatapathProc = (QUIC_DATAPATH_PROC*)CompletionContext;

    QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[ udp][%p] Worker start",
        DatapathProc);

    QUIC_DBG_ASSERT(DatapathProc != NULL);
    QUIC_DBG_ASSERT(DatapathProc->Datapath != NULL);

    QUIC_SOCKET_PROC* SocketProc;
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

        QUIC_DBG_ASSERT(Overlapped != NULL);
        QUIC_DBG_ASSERT(SocketProc != NULL);

        IoResult = Result ? NO_ERROR : GetLastError();

        //
        // Overlapped either points to the send or receive OVERLAPPED for this
        // socket.
        //
        if (Overlapped == &SocketProc->RecvOverlapped) {

            if (NumberOfBytesTransferred == UINT32_MAX) {
                //
                // The socket context is being shutdown. Run the clean up logic.
                //
                QuicDataPathSocketContextShutdown(SocketProc);

            } else if (QuicRundownAcquire(&SocketProc->UpcallRundown)) {
                //
                // We only allow for receiving UINT16 worth of bytes at a time,
                // which should be plenty for an IPv4 or IPv6 UDP datagram.
                //
                QUIC_DBG_ASSERT(NumberOfBytesTransferred <= 0xFFFF);
                if (NumberOfBytesTransferred > 0xFFFF &&
                    IoResult == NO_ERROR) {
                    IoResult = ERROR_INVALID_PARAMETER;
                }

                //
                // Handle the receive indication and queue a new receive.
                //
                QuicDataPathRecvComplete(
                    DatapathProc,
                    SocketProc,
                    IoResult,
                    (UINT16)NumberOfBytesTransferred);

                QuicRundownRelease(&SocketProc->UpcallRundown);
            }

        } else {

            QUIC_SEND_DATA* SendContext =
                CONTAINING_RECORD(
                    Overlapped,
                    QUIC_SEND_DATA,
                    Overlapped);

            QuicSendContextComplete(
                SocketProc,
                SendContext,
                IoResult);
        }
    }

    QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[ udp][%p] Worker stop",
        DatapathProc);

    return NO_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicSocketSetParam(
    _In_ QUIC_SOCKET* Socket,
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
QuicSocketGetParam(
    _In_ QUIC_SOCKET* Socket,
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
QuicFuzzerReceiveInject(
    _In_ const QUIC_ADDR *SourceAddress,
    _In_reads_(PacketLength) uint8_t *PacketData,
    _In_ uint16_t PacketLength
    )
{
    if (PacketLength > QUIC_FUZZ_BUFFER_MAX) {
        return;
    }

    QUIC_SOCKET_PROC* Socket = (QUIC_SOCKET_PROC*)MsQuicFuzzerContext.Socket;

    if (!Socket) {
        return;
    }

    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext =
        QuicSocketAllocRecvContext(
            Socket->Socket->Datapath,
            (UINT16)GetCurrentProcessorNumber());

    if (!RecvContext) {
        return;
    }

    RecvContext->Tuple.RemoteAddress = *SourceAddress;

    QUIC_RECV_DATA* Datagram = (QUIC_RECV_DATA*)(RecvContext + 1);

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
QuicFuzzerRecvMsg(
    _In_ SOCKET s,
    _Inout_ LPWSAMSG lpMsg,
    _Out_ LPDWORD lpdwNumberOfBytesRecvd,
    _In_ LPWSAOVERLAPPED lpOverlapped,
    _In_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
{
    if (!MsQuicFuzzerContext.RedirectDataPath) {
        QUIC_DBG_ASSERT(MsQuicFuzzerContext.RealRecvMsg);

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
QuicFuzzerSendMsg(
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
        QUIC_DBG_ASSERT(MsQuicFuzzerContext.RealSendMsg);

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
