/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#define __APPLE_USE_RFC_3542 1
// See netinet6/in6.h:46 for an explanation
#include "platform_internal.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/time.h>

#ifdef QUIC_CLOG
#include "datapath_kqueue.c.clog.h"
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
#define CXPLAT_MAX_BATCH_SEND                   7

//
// The maximum UDP receive coalescing payload.
//
#define MAX_URO_PAYLOAD_LENGTH                  (UINT16_MAX - CXPLAT_UDP_HEADER_SIZE)

//
// The maximum single buffer size for sending coalesced payloads.
//
#define CXPLAT_LARGE_SEND_BUFFER_SIZE           0xFFFF

//
// The maximum number of UDP datagrams to preallocate for URO.
//
#define URO_MAX_DATAGRAMS_PER_INDICATION    64

#define IsUnreachableErrorCode(ErrorCode) \
( \
    ErrorCode == ENETDOWN || \
    ErrorCode == ENETUNREACH || \
    ErrorCode == ECONNREFUSED || \
    ErrorCode == EHOSTDOWN \
)

typedef struct CXPLAT_UDP_SOCKET_CONTEXT CXPLAT_UDP_SOCKET_CONTEXT;
typedef struct CXPLAT_DATAPATH_PROC_CONTEXT CXPLAT_DATAPATH_PROC_CONTEXT;

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
    unsigned long ReferenceCount;

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
    // The owning processor context.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT* Owner;

    //
    // The total buffer size for Buffers.
    //
    uint32_t TotalSize;

    //
    // The send segmentation size; zero if segmentation is not performed.
    //
    uint16_t SegmentSize;

    //
    // The type of ECN markings needed for send.
    //
    CXPLAT_ECN_TYPE ECN;

    //
    // The current number of WsaBuffers used.
    //
    uint8_t BufferCount;

    //
    // Contains all the datagram buffers to pass to the socket.
    //
    QUIC_BUFFER Buffers[CXPLAT_MAX_BATCH_SEND];

    //
    // The WSABUF returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

} CXPLAT_SEND_DATA;

//
// Per-socket state.
//
typedef struct CXPLAT_UDP_SOCKET_CONTEXT {

    //
    // Parent CXPLAT_SOCKET.
    //
    CXPLAT_SOCKET* Binding;

    //
    // UDP socket used for sending/receiving datagrams.
    //
    int Socket;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    CXPLAT_RUNDOWN_REF UpcallRundown;

    //
    // The set of parameters/state passed to WsaRecvMsg for the IP stack to
    // populate to indicate the result of the receive.
    //

    struct iovec RecvIov;

    char RecvMsgControlBuf[
            CMSG_SPACE(sizeof(struct in6_pktinfo)) +
            CMSG_SPACE(sizeof(struct in_pktinfo))  +
            CMSG_SPACE(sizeof(int))
        ];

    struct msghdr RecvMsgHdr;
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* CurrentRecvContext;

} CXPLAT_UDP_SOCKET_CONTEXT;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct CXPLAT_SOCKET {

    //
    // Flag indicates the binding has a default remote destination.
    //
    BOOLEAN Connected : 1;

    //
    // The index of the affinitized receive processor for a connected socket.
    //
    uint8_t ConnectedProcessorAffinity;

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The local address and UDP port.
    //
    QUIC_ADDR LocalAddress;

    //
    // The remote address and UDP port.
    //
    QUIC_ADDR RemoteAddress;

    //
    // The local interface's MTU.
    //
    uint16_t Mtu;

    //
    // The number of socket contexts that still need to be cleaned up.
    //
    short volatile SocketContextsOutstanding;

    //
    // Client context pointer.
    //
    void *ClientContext;

    //
    // Socket contexts for this port.
    //
    CXPLAT_UDP_SOCKET_CONTEXT SocketContexts[0];

} CXPLAT_SOCKET;

//
// Represents a single IO completion port and thread for processing work that
// is completed on a single processor.
//
typedef struct CXPLAT_DATAPATH_PROC_CONTEXT {

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

    //
    // The kqueue to manage events
    //
    int Kqueue;

    //
    // Thread used for handling kqueue events.
    //
    pthread_t CompletionThread;

    //
    // The ID of the CompletionThread.
    //
    uint32_t ThreadId;

    //
    // The index of the context in the datapath's array.
    //
    uint32_t Index;

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

} CXPLAT_DATAPATH_PROC_CONTEXT;

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
    uint8_t MaxSendBatchSize;

    //
    // Rundown for waiting on binding cleanup.
    //
    CXPLAT_RUNDOWN_REF BindingsRundown;

    //
    // UDP handlers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

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
    uint32_t ProcCount;

    //
    // Per-processor completion contexts.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT ProcContexts[0];

} CXPLAT_DATAPATH;

CXPLAT_RECV_DATA* CxPlatDataPathRecvPacketToRecvData(_In_ const CXPLAT_RECV_PACKET* const Context) {
    return (CXPLAT_RECV_DATA*) (((uint8_t *)Context) - sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) - sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_RECV_PACKET* CxPlatDataPathRecvDataToRecvPacket(_In_ const CXPLAT_RECV_DATA* const Datagram) {
    return (CXPLAT_RECV_PACKET*) (((uint8_t *)Datagram) + sizeof(CXPLAT_RECV_DATA) + sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT));
}

CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* CxPlatDataPathDatagramToInternalDatagramContext(_In_ CXPLAT_RECV_DATA* Datagram) {
    return (CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*) (((uint8_t *)Datagram) + sizeof(CXPLAT_RECV_DATA));
}

void CxPlatDataPathWakeWorkerThread(_In_ CXPLAT_DATAPATH_PROC_CONTEXT *ProcContext, _In_ CXPLAT_UDP_SOCKET_CONTEXT *SocketContext);
//
// Callback function for IOCP Worker Thread.
//
void *CxPlatDataPathWorkerThread(_In_ void* Context);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ CXPLAT_DATAPATH* *NewDataPath
    )
{
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath;
    uint32_t DatapathLength;
    uint32_t MaxProcCount = 1;

    UNREFERENCED_PARAMETER(TcpCallbacks);

    if (NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        Datapath = NULL;
        goto Exit;
    }

    if (UdpCallbacks != NULL) {
        if (UdpCallbacks->Receive == NULL || UdpCallbacks->Unreachable == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    DatapathLength = sizeof(CXPLAT_DATAPATH) + MaxProcCount * sizeof(CXPLAT_DATAPATH_PROC_CONTEXT);

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

    CxPlatZeroMemory(Datapath, DatapathLength);
    if (UdpCallbacks) {
        Datapath->UdpHandlers = *UdpCallbacks;
    }
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = MaxProcCount;
    CxPlatRundownInitialize(&Datapath->BindingsRundown);

    Datapath->MaxSendBatchSize = 1;

    uint32_t MessageCount = 1;

    Datapath->DatagramStride =
        ALIGN_UP(
            sizeof(CXPLAT_RECV_DATA) +
            sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) +
            ClientRecvContextLength,
            void *);

    Datapath->RecvPayloadOffset = sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT) + MessageCount * Datapath->DatagramStride;

    uint32_t RecvDatagramLength = Datapath->RecvPayloadOffset + MAX_UDP_PAYLOAD_LENGTH;

    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {

        //
        // This creates a per processor IO completion port and thread. It
        // explicitly affinitizes the thread to a processor. This is so that
        // our per UDP socket receives maintain their RSS core all the way up.
        //

        Datapath->ProcContexts[i].Datapath = Datapath;
        Datapath->ProcContexts[i].Index = i;
        Datapath->ProcContexts[i].Kqueue = INVALID_SOCKET;

        CxPlatPoolInitialize(FALSE, sizeof(CXPLAT_SEND_DATA), QUIC_POOL_GENERIC, &Datapath->ProcContexts[i].SendContextPool);
        CxPlatPoolInitialize(FALSE, MAX_UDP_PAYLOAD_LENGTH, QUIC_POOL_DATA, &Datapath->ProcContexts[i].SendBufferPool);
        CxPlatPoolInitialize(FALSE, CXPLAT_LARGE_SEND_BUFFER_SIZE, QUIC_POOL_DATA, &Datapath->ProcContexts[i].LargeSendBufferPool);
        CxPlatPoolInitialize(FALSE, RecvDatagramLength, QUIC_POOL_DATA, &Datapath->ProcContexts[i].RecvDatagramPool);

        int KqueueFd = kqueue();

        if (KqueueFd == INVALID_SOCKET) {
            Status = errno;
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "kqueue() failed");
            goto Error;
        }

        Datapath->ProcContexts[i].Kqueue = KqueueFd;

        CXPLAT_THREAD_CONFIG ThreadConfig = {
            0,
            0,
            NULL,
            CxPlatDataPathWorkerThread,
            &Datapath->ProcContexts[i]
        };

        Status = CxPlatThreadCreate(&ThreadConfig, &Datapath->ProcContexts[i].CompletionThread);

        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "CreateThread");
            goto Error;
        }
    }

    *NewDataPath = Datapath;
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (Datapath != NULL) {
            for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
                if (Datapath->ProcContexts[i].Kqueue != INVALID_SOCKET) {
                    close(Datapath->ProcContexts[i].Kqueue);
                }
                if (Datapath->ProcContexts[i].CompletionThread) {
                    // TODO: pthread_kill / pthread_cancel this..
                    // or find a better way to cancel the thread
                }
                CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
                CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
                CxPlatPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
                CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPool);
            }
            CxPlatRundownUninitialize(&Datapath->BindingsRundown);
            CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
        }
    }

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void CxPlatDataPathUninitialize(_In_ CXPLAT_DATAPATH* Datapath) {
    if (Datapath == NULL) { return; }

    //
    // Wait for all outstanding binding to clean up.
    //
    CxPlatRundownReleaseAndWait(&Datapath->BindingsRundown);

    //
    // Disable processing on the completion threads and kick the IOCPs to make
    // sure the threads knows they are disabled.
    //
    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatDataPathWakeWorkerThread(&Datapath->ProcContexts[i], NULL);
    }

    //
    // Wait for the worker threads to finish up. Then clean it up.
    //
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        pthread_join(Datapath->ProcContexts[i].CompletionThread, NULL);
        //WaitForSingleObject(Datapath->ProcContexts[i].CompletionThread, INFINITE);
        //CloseHandle(Datapath->ProcContexts[i].CompletionThread);
    }

    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        close(Datapath->ProcContexts[i].Kqueue);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPool);
    }

    CxPlatRundownUninitialize(&Datapath->BindingsRundown);
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
}

void CxPlatDataPathWakeWorkerThread(_In_ CXPLAT_DATAPATH_PROC_CONTEXT *ProcContext, _In_ CXPLAT_UDP_SOCKET_CONTEXT *SocketContext) {
    struct kevent Event = { };
    EV_SET(&Event, 42, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, (void *)SocketContext);
    kevent(ProcContext->Kqueue, &Event, 1, NULL, 0, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t CxPlatDataPathGetSupportedFeatures(_In_ CXPLAT_DATAPATH* Datapath) {
    return Datapath->Features;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN CxPlatDataPathIsPaddingPreferred(_In_ CXPLAT_DATAPATH* Datapath) {
    return !!(Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

void CxPlatDataPathPopulateTargetAddress(_In_ QUIC_ADDRESS_FAMILY Family, _In_ ADDRINFO *AddrInfo, _Out_ QUIC_ADDR* Address) {
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

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
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        CXPLAT_FRE_ASSERT(FALSE);
    }

    //if (Ai->ai_addr->sa_family == AF_INET6) {
    //    //
    //    // Is this a mapped ipv4 one?
    //    //
    //    struct sockaddr_in6 *SockAddr6 = (struct sockaddr_in6 *)Ai->ai_addr;

    //    if (Family == AF_UNSPEC && IN6_IS_ADDR_V4MAPPED(SockAddr6)) {
    //        struct sockaddr_in *SockAddr4 = &Address->Ipv4;
    //        //
    //        // Get the ipv4 address from the mapped address.
    //        //
    //        SockAddr4->sin_family = AF_INET;
    //        SockAddr4->sin_addr = *(IN_ADDR UNALIGNED *) IN6_GET_ADDR_V4MAPPED(&SockAddr6->sin6_addr);
    //        SockAddr4->sin_port = SockAddr6->sin6_port;
    //        return;
    //    }
    //}

    //memcpy(Address, Ai->ai_addr, Ai->ai_addrlen);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS CxPlatDataPathResolveAddress(_In_ CXPLAT_DATAPATH* Datapath, _In_z_ const char* HostName, _Inout_ QUIC_ADDR * Address) {
    QUIC_STATUS Status;
    ADDRINFO Hints = { 0 };
    ADDRINFO *Ai;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(HostName, NULL, &Hints, &Ai) == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, Ai, Address);
        freeaddrinfo(Ai);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(HostName, NULL, &Hints, &Ai) == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, Ai, Address);
        freeaddrinfo(Ai);
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
    Status = QUIC_STATUS_DNS_RESOLUTION_ERROR;

Exit:

    return Status;
}

QUIC_STATUS CxPlatDataPathBindingStartReceive(_In_ CXPLAT_UDP_SOCKET_CONTEXT* SocketContext, _In_ int KqueueFd);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR *LocalAddress,
    _In_opt_ const QUIC_ADDR *RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status;
    CXPLAT_SOCKET* Binding = NULL;
    uint32_t BindingLength;
    uint32_t SocketCount = (RemoteAddress == NULL) ? Datapath->ProcCount : 1;
    int Result;
    int Option;

    BindingLength = sizeof(CXPLAT_SOCKET) + SocketCount * sizeof(CXPLAT_UDP_SOCKET_CONTEXT);

    Binding = (CXPLAT_SOCKET *)CXPLAT_ALLOC_PAGED(BindingLength, QUIC_POOL_SOCKET);
    if (Binding == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            BindingLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->Connected = (RemoteAddress != NULL);
    Binding->Mtu = CXPLAT_MAX_MTU;

    if (LocalAddress) {
        memcpy(&Binding->LocalAddress, LocalAddress, sizeof(QUIC_ADDR));
        //CxPlatConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else if (RemoteAddress) {
        // We have no local address, but we have a remote address.
        // Let's match up AF types with the remote.
        Binding->LocalAddress.Ip.sa_family = RemoteAddress->Ip.sa_family;
    } else {
        // This indicates likely that the application wants a listener with a random port.
        // Since we can't dual-stack socket, fall back to AF_INET6
        Binding->LocalAddress.Ip.sa_family = AF_INET6;
    }

    CxPlatRundownAcquire(&Datapath->BindingsRundown);

    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].Socket = INVALID_SOCKET;
        Binding->SocketContexts[i].RecvIov.iov_len = Binding->Mtu - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE;
        CxPlatRundownInitialize(&Binding->SocketContexts[i].UpcallRundown);
    }

    sa_family_t AfFamily = Binding->LocalAddress.Ip.sa_family;
    socklen_t AddrSize = AfFamily == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    for (uint32_t i = 0; i < SocketCount; i++) {

        CXPLAT_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

        SocketContext->Socket = socket(AfFamily, SOCK_DGRAM, 0);
        if (SocketContext->Socket == INVALID_SOCKET) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "socket");
            goto Error;
        }


        if (AfFamily == AF_INET) {
            Option = TRUE;
            Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_PKTINFO, &Option, sizeof(Option));
            if (Result == SOCKET_ERROR) {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Binding,
                    Status,
                    "setsockopt(IP_PKTINFO) failed");
                goto Error;
            }
        }
        else {
            Option = TRUE;
            Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &Option, sizeof(Option));

            Option = TRUE;
            Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_PKTINFO, &Option, sizeof(Option));
        }

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_DONTFRAGMENT, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set IP_DONTFRAGMENT");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_DONTFRAG, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set IPV6_DONTFRAG");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set IPV6_PKTINFO");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_PKTINFO, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set IP_PKTINFO");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_ECN, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set IPV6_ECN");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_ECN, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set IP_ECN");
        //    goto Error;
        //}

        ////
        //// The socket is shared by multiple endpoints, so increase the receive
        //// buffer size.
        ////
        //Option = MAXINT32;
        //Result = setsockopt(SocketContext->Socket, SOL_SOCKET, SO_RCVBUF, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[data][%p] ERROR, %u, %s.", Binding, Status, "Set SO_RCVBUF");
        //    goto Error;
        //}

        Result = bind(SocketContext->Socket, (struct sockaddr *)&Binding->LocalAddress, AddrSize);
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "bind");
            goto Error;
        }

        if (RemoteAddress != NULL) {
            Result = connect(SocketContext->Socket, (struct sockaddr *)RemoteAddress, AddrSize);
            if (Result == SOCKET_ERROR) {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Binding,
                    Status,
                    "connect");
                goto Error;
            }
        }

        if (i == 0) {

            //
            // If no specific local port was indicated, then the stack just
            // assigned this socket a port. We need to query it and use it for
            // all the other sockets we are going to create.
            //

            socklen_t AssignedLocalAddressLength = (socklen_t)sizeof(Binding->LocalAddress);
            Result = getsockname(SocketContext->Socket, (struct sockaddr *)&Binding->LocalAddress, &AssignedLocalAddressLength);
            if (Result == SOCKET_ERROR) {
                Status = errno;
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Binding,
                    Status,
                    "getsockaddress");
                goto Error;
            }

            if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
                CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
            }
        }
    }

    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    Binding->SocketContextsOutstanding = (short)SocketCount;
    for (uint32_t i = 0; i < SocketCount; i++) {
        Status = CxPlatDataPathBindingStartReceive(&Binding->SocketContexts[i], Datapath->ProcContexts[i].Kqueue);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        printf("ERROR: FAILED TO CREATE BINDING...\n");
        if (Binding != NULL) {
            if (Binding->SocketContextsOutstanding != 0) {
                for (uint32_t i = 0; i < SocketCount; i++) {
                    CXPLAT_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

                    close(SocketContext->Socket);

                    //
                    // Queue a completion to clean up the socket context.
                    //
                    CxPlatDataPathWakeWorkerThread(&Binding->Datapath->ProcContexts[i], SocketContext);
                }
            } else {
                for (uint32_t i = 0; i < SocketCount; i++) {
                    CXPLAT_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

                    if (SocketContext->Socket != INVALID_SOCKET) {
                        close(SocketContext->Socket);
                    }

                    CxPlatRundownUninitialize(&SocketContext->UpcallRundown);
                }
                CxPlatRundownRelease(&Datapath->BindingsRundown);
                CXPLAT_FREE(Binding, QUIC_POOL_SOCKET);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void CxPlatSocketDelete(_In_ CXPLAT_SOCKET* Binding)
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
    QuicTraceLogVerbose(
        DatapathShuttingDown,
        "[data][%p] Shutting down",
        Binding);

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    CXPLAT_DATAPATH* Datapath = Binding->Datapath;

    if (Binding->Connected) {
        CXPLAT_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[0];
        //uint32_t Processor = Binding->ConnectedProcessorAffinity;
        CxPlatRundownReleaseAndWait(&SocketContext->UpcallRundown);

        close(SocketContext->Socket);
        CxPlatDataPathWakeWorkerThread(&Datapath->ProcContexts[0], SocketContext);

    } else {
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            CXPLAT_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];
            CxPlatRundownReleaseAndWait(&SocketContext->UpcallRundown);
        }
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            CXPLAT_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

            close(SocketContext->Socket);

            CxPlatDataPathWakeWorkerThread(&Datapath->ProcContexts[i], SocketContext);
        }
    }

    QuicTraceLogVerbose(
        DatapathShutDownReturn,
        "[data][%p] Shut down (return)",
        Binding);
}

void CxPlatDataPathSocketContextShutdown(_In_ CXPLAT_UDP_SOCKET_CONTEXT* SocketContext) {
    if (SocketContext->CurrentRecvContext != NULL) {
        CxPlatPoolFree(SocketContext->CurrentRecvContext->OwningPool, SocketContext->CurrentRecvContext);
        SocketContext->CurrentRecvContext = NULL;
    }

    CxPlatRundownUninitialize(&SocketContext->UpcallRundown);

    if (InterlockedDecrement16(&SocketContext->Binding->SocketContextsOutstanding) == 0) {
        //
        // Last socket context cleaned up, so now the binding can be freed.
        //
        CxPlatRundownRelease(&SocketContext->Binding->Datapath->BindingsRundown);
        QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            SocketContext->Binding);
        CXPLAT_FREE(SocketContext->Binding, QUIC_POOL_SOCKET);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t CxPlatDataPathBindingGetLocalMtu(_In_ CXPLAT_SOCKET* Binding) {
    CXPLAT_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void CxPlatDataPathBindingGetLocalAddress(_In_ CXPLAT_SOCKET* Binding, _Out_ QUIC_ADDR * Address) {
    CXPLAT_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void CxPlatDataPathBindingGetRemoteAddress(_In_ CXPLAT_SOCKET* Binding, _Out_ QUIC_ADDR * Address) {
    CXPLAT_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
}

CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* CxPlatDataPathBindingAllocRecvContext(_In_ CXPLAT_DATAPATH* Datapath, _In_ uint16_t ProcIndex) {
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = CxPlatPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvDatagramPool);

    if (RecvContext != NULL) {
        RecvContext->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvDatagramPool;
        RecvContext->ReferenceCount = 0;
    }

    return RecvContext;
}

void CxPlatDataPathBindingHandleUnreachableError(_In_ CXPLAT_UDP_SOCKET_CONTEXT* SocketContext, _In_ unsigned long ErrorCode) {
    QUIC_ADDR *RemoteAddr = &SocketContext->CurrentRecvContext->Tuple.RemoteAddress;
    UNREFERENCED_PARAMETER(ErrorCode);

#if CXPLAT_CLOG
    QuicTraceLogVerbose(
        DatapathUnreachableWithError,
        "[data][%p] Received unreachable error (0x%x) from %!ADDR!",
        SocketContext->Binding,
        ErrorCode,
        CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

    CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath->UdpHandlers.Unreachable);
    SocketContext->Binding->Datapath->UdpHandlers.Unreachable(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RemoteAddr);
}

QUIC_STATUS CxPlatDataPathPrepareReceive(_In_ CXPLAT_UDP_SOCKET_CONTEXT *SocketContext) {
    if (SocketContext->CurrentRecvContext == NULL) {
        SocketContext->CurrentRecvContext = CxPlatDataPathBindingAllocRecvContext(SocketContext->Binding->Datapath, 0);
        if (SocketContext->CurrentRecvContext == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_DATAPATH_RECV_BLOCK",
                0);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    CxPlatZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    CxPlatZeroMemory(&SocketContext->RecvMsgControlBuf, sizeof(SocketContext->RecvMsgControlBuf));

    SocketContext->RecvIov.iov_base = (char *)SocketContext->CurrentRecvContext + SocketContext->Binding->Datapath->RecvPayloadOffset;

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvContext->Tuple.RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvContext->Tuple.RemoteAddress);

    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;

    SocketContext->RecvMsgHdr.msg_control = SocketContext->RecvMsgControlBuf;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControlBuf);

    SocketContext->RecvMsgHdr.msg_flags = 0;

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS CxPlatDataPathBindingStartReceive(_In_ CXPLAT_UDP_SOCKET_CONTEXT* SocketContext, _In_ int KqueueFd) {
    QUIC_STATUS Status = CxPlatDataPathPrepareReceive(SocketContext);

    if (QUIC_FAILED(Status)) goto Error;

    struct kevent Event = { };
    EV_SET(&Event, SocketContext->Socket, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, (void *)SocketContext);
    if (kevent(KqueueFd, &Event, 1, NULL, 0, NULL) < 0)  {
        // Should be QUIC_STATUS_KQUEUE_ERROR
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "kevent(..., sockfd EV_ADD, ...) failed");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        close(SocketContext->Socket);
        SocketContext->Socket = INVALID_SOCKET;
    }

    return Status;
}

void
CxPlatDataPathRecvComplete(
    _In_ CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ CXPLAT_UDP_SOCKET_CONTEXT* SocketContext,
    _In_ unsigned long IoResult,
    _In_ uint16_t NumberOfBytesTransferred
    )
{
    //
    // Copy the current receive buffer locally. On error cases, we leave the
    // buffer set as the current receive buffer because we are only using it
    // inline. Otherwise, we remove it as the current because we are giving
    // it to the client.
    //
    CXPLAT_DBG_ASSERT(SocketContext->CurrentRecvContext != NULL);
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = SocketContext->CurrentRecvContext;
    if (IoResult == NO_ERROR) {
        SocketContext->CurrentRecvContext = NULL;
    }

    QUIC_ADDR *RemoteAddr = &RecvContext->Tuple.RemoteAddress;
    QUIC_ADDR *LocalAddr = &RecvContext->Tuple.LocalAddress;

    if (IoResult == ENOTSOCK || IoResult == ECONNABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;

    } else if (IsUnreachableErrorCode(IoResult)) {
        CxPlatDataPathBindingHandleUnreachableError(SocketContext, IoResult);
    } else if (IoResult == QUIC_STATUS_SUCCESS) {

        CXPLAT_RECV_DATA* DatagramChain = NULL;
        CXPLAT_RECV_DATA** DatagramChainTail = &DatagramChain;

        CXPLAT_DATAPATH* Datapath = SocketContext->Binding->Datapath;
        CXPLAT_RECV_DATA* Datagram;
        uint8_t *RecvPayload = ((uint8_t *)RecvContext) + Datapath->RecvPayloadOffset;

        BOOLEAN FoundLocalAddr = FALSE;
        uint16_t MessageLength = NumberOfBytesTransferred;
        unsigned long MessageCount = 0;
        BOOLEAN IsCoalesced = FALSE;
        int ECN = 0;

        for (struct cmsghdr *CMsg = CMSG_FIRSTHDR(&SocketContext->RecvMsgHdr);
            CMsg != NULL;
            CMsg = CMSG_NXTHDR(&SocketContext->RecvMsgHdr, CMsg)) {

            if (CMsg->cmsg_level == IPPROTO_IPV6) {
                if (CMsg->cmsg_type == IPV6_PKTINFO) {
                    struct in6_pktinfo *PktInfo6 = (struct in6_pktinfo *)CMSG_DATA(CMsg);
                    LocalAddr->Ip.sa_family = AF_INET6;
                    LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                    LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                    //CxPlatConvertFromMappedV6(LocalAddr, LocalAddr);

                    LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;
                }
                // else if (CMsg->cmsg_type == IPV6_ECN) {
                //    ECN = *(int *)CMSG_DATA(CMsg);
                //    CXPLAT_DBG_ASSERT(ECN < UINT8_MAX);
                //}
            } else if (CMsg->cmsg_level == IPPROTO_IP) {
                if (CMsg->cmsg_type == IP_PKTINFO) {
                    struct in_pktinfo *PktInfo = (struct in_pktinfo *)CMSG_DATA(CMsg);
                    LocalAddr->Ip.sa_family = AF_INET;
                    LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
                    LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                    LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                    FoundLocalAddr = TRUE;
                }
                //else if (CMsg->cmsg_type == IP_ECN) {
                //    ECN = *(int *)CMSG_DATA(CMsg);
                //    CXPLAT_DBG_ASSERT(ECN < UINT8_MAX);
                //}
            }
        }

        if (!FoundLocalAddr) {
            //
            // The underlying data path does not guarantee ancillary data for
            // enabled socket options when the system is under memory pressure.
            //
            __asm__("int3");
            QuicTraceLogWarning(
                DatapathMissingInfo,
                "[data][%p] WSARecvMsg completion is missing IP_PKTINFO",
                SocketContext->Binding);
            goto Drop;
        }

        if (NumberOfBytesTransferred == 0) {
            __asm__("int3");
            QuicTraceLogWarning(
                DatapathRecvEmpty,
                "[data][%p] Dropping datagram with empty payload.",
                SocketContext->Binding);
            goto Drop;
        }

        // CxPlatConvertFromMappedV6(RemoteAddr, RemoteAddr);

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            SocketContext->Binding,
            NumberOfBytesTransferred,
            MessageLength,
            CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr),
            CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= SocketContext->RecvIov.iov_len);

        Datagram = (CXPLAT_RECV_DATA*)(RecvContext + 1);

        for ( ; NumberOfBytesTransferred != 0; NumberOfBytesTransferred -= MessageLength) {

            CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext = CxPlatDataPathDatagramToInternalDatagramContext(Datagram);
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
            Datagram->PartitionIndex = (uint8_t)ProcContext->Index;
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

            Datagram = (CXPLAT_RECV_DATA*) (((uint8_t *)Datagram) + SocketContext->Binding->Datapath->DatagramStride);

            if (IsCoalesced && ++MessageCount == URO_MAX_DATAGRAMS_PER_INDICATION) {
                QuicTraceLogWarning(
                    DatapathUroPreallocExceeded,
                    "[data][%p] Exceeded URO preallocation capacity.",
                    SocketContext->Binding);
                break;
            }
        }

        CXPLAT_DBG_ASSERT(SocketContext->Binding->Datapath->UdpHandlers.Receive);
        CXPLAT_DBG_ASSERT(DatagramChain);

        SocketContext->Binding->Datapath->UdpHandlers.Receive(SocketContext->Binding, SocketContext->Binding->ClientContext, DatagramChain);

    } else {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            IoResult,
            "WSARecvMsg completion");
    }

Drop:

    QUIC_STATUS Status = CxPlatDataPathPrepareReceive(SocketContext);
    //
    // Try to start a new receive.
    //
    UNREFERENCED_PARAMETER(Status);
    return;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void CxPlatRecvDataReturn(_In_opt_ CXPLAT_RECV_DATA* DatagramChain) {
    UNREFERENCED_PARAMETER(DatagramChain);
    //CXPLAT_RECV_DATA* Datagram;

    //long BatchedBufferCount = 0;
    //CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* BatchedInternalContext = NULL;

    //while ((Datagram = DatagramChain) != NULL) {
    //    DatagramChain = DatagramChain->Next;

    //    CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalBufferContext = CxPlatDataPathDatagramToInternalDatagramContext(Datagram);
    //    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext = InternalBufferContext->RecvContext;

    //    if (BatchedInternalContext == InternalContext) {
    //        BatchedBufferCount++;
    //    } else {
    //        if (BatchedInternalContext != NULL &&
    //            InterlockedAdd(
    //                (long *)&BatchedInternalContext->ReferenceCount,
    //                -BatchedBufferCount) == 0) {
    //            //
    //            // Clean up the data indication.
    //            //
    //            CxPlatPoolFree(BatchedInternalContext->OwningPool, BatchedInternalContext);
    //        }

    //        BatchedInternalContext = InternalContext;
    //        BatchedBufferCount = 1;
    //    }
    //}

    //if (BatchedInternalContext != NULL &&
    //    InterlockedAdd(
    //        (PLONG)&BatchedInternalContext->ReferenceCount,
    //        -BatchedBufferCount) == 0) {
    //    //
    //    // Clean up the data indication.
    //    //
    //    CxPlatPoolFree(BatchedInternalContext->OwningPool, BatchedInternalContext);
    //}
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA* CxPlatSendDataAlloc(_In_ CXPLAT_SOCKET* Binding, _In_ CXPLAT_ECN_TYPE ECN, _In_ uint16_t MaxPacketSize) {
    CXPLAT_DBG_ASSERT(Binding != NULL);
    UNREFERENCED_PARAMETER(MaxPacketSize);

    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = &Binding->Datapath->ProcContexts[0];

    CXPLAT_SEND_DATA* SendContext = CxPlatPoolAlloc(&ProcContext->SendContextPool);

    if (SendContext != NULL) {
        SendContext->Owner = ProcContext;
        SendContext->ECN = ECN;
        SendContext->SegmentSize = 0;
        SendContext->TotalSize = 0;
        SendContext->BufferCount = 0;
        SendContext->ClientBuffer.Length = 0;
        SendContext->ClientBuffer.Buffer = NULL;
    }

    return SendContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void CxPlatDataPathBindingFreeSendContext(_In_ CXPLAT_SEND_DATA* SendContext) {
    size_t i = 0;
    for (i = 0; i < SendContext->BufferCount; ++i) {
        CxPlatPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    CxPlatPoolFree(&SendContext->Owner->SendContextPool, SendContext);
}

static
BOOLEAN CxPlatSendContextCanAllocSendSegment(_In_ CXPLAT_SEND_DATA* SendContext, _In_ uint16_t MaxBufferLength) {
    CXPLAT_DBG_ASSERT(SendContext->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(SendContext->BufferCount > 0);
    CXPLAT_DBG_ASSERT(SendContext->BufferCount <= SendContext->Owner->Datapath->MaxSendBatchSize);

    unsigned long BytesAvailable = CXPLAT_LARGE_SEND_BUFFER_SIZE - SendContext->Buffers[SendContext->BufferCount - 1].Length - SendContext->ClientBuffer.Length;

    return MaxBufferLength <= BytesAvailable;
}

//static
//BOOLEAN CxPlatSendContextCanAllocSend(_In_ CXPLAT_SEND_DATA* SendContext, _In_ UINT16 MaxBufferLength) {
//    return (SendContext->BufferCount < SendContext->Owner->Datapath->MaxSendBatchSize) ||
//        ((SendContext->SegmentSize > 0) &&
//            CxPlatSendContextCanAllocSendSegment(SendContext, MaxBufferLength));
//}

static
void CxPlatSendContextFinalizeSendBuffer(_In_ CXPLAT_SEND_DATA* SendContext, _In_ BOOLEAN IsSendingImmediately) {
    if (SendContext->ClientBuffer.Length == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendContext->BufferCount > 0) {
            CXPLAT_DBG_ASSERT(SendContext->Buffers[SendContext->BufferCount - 1].Length < UINT16_MAX);
            SendContext->TotalSize += SendContext->Buffers[SendContext->BufferCount - 1].Length;
        }
        return;
    }

    CXPLAT_DBG_ASSERT(SendContext->SegmentSize > 0 && SendContext->BufferCount > 0);
    CXPLAT_DBG_ASSERT(SendContext->ClientBuffer.Length > 0 && SendContext->ClientBuffer.Length <= SendContext->SegmentSize);
    CXPLAT_DBG_ASSERT(CxPlatSendContextCanAllocSendSegment(SendContext, 0));

    //
    // Append the client's buffer segment to our internal send buffer.
    //
    SendContext->Buffers[SendContext->BufferCount - 1].Length += SendContext->ClientBuffer.Length;
    SendContext->TotalSize += SendContext->ClientBuffer.Length;

    if (SendContext->ClientBuffer.Length == SendContext->SegmentSize) {
        SendContext->ClientBuffer.Buffer += SendContext->SegmentSize;
        SendContext->ClientBuffer.Length = 0;
    } else {
        //
        // The next segment allocation must create a new backing buffer.
        //
        CXPLAT_DBG_ASSERT(IsSendingImmediately); // Future: Refactor so it's impossible to hit this.
        UNREFERENCED_PARAMETER(IsSendingImmediately);
        SendContext->ClientBuffer.Buffer = NULL;
        SendContext->ClientBuffer.Length = 0;
    }
}

//_Success_(return != NULL)
//static
//WSABUF* CxPlatSendContextAllocBuffer(_In_ CXPLAT_SEND_DATA* SendContext, _In_ CXPLAT_POOL* BufferPool) {
//    CXPLAT_DBG_ASSERT(SendContext->BufferCount < SendContext->Owner->Datapath->MaxSendBatchSize);
//
//    WSABUF* WsaBuffer = &SendContext->Buffers[SendContext->BufferCount];
//    WsaBuffer->buf = CxPlatPoolAlloc(BufferPool);
//    if (WsaBuffer->buf == NULL) {
//        return NULL;
//    }
//    ++SendContext->BufferCount;
//
//    return WsaBuffer;
//}

//_Success_(return != NULL)
//static
//QUIC_BUFFER* CxPlatSendContextAllocPacketBuffer(_In_ CXPLAT_SEND_DATA* SendContext, _In_ UINT16 MaxBufferLength) {
//    WSABUF* WsaBuffer = CxPlatSendContextAllocBuffer(SendContext, &SendContext->Owner->SendBufferPool);
//    if (WsaBuffer != NULL) {
//        WsaBuffer->len = MaxBufferLength;
//    }
//    return (QUIC_BUFFER *)WsaBuffer;
//}
//
//_Success_(return != NULL)
//static
//QUIC_BUFFER* CxPlatSendContextAllocSegmentBuffer(_In_ CXPLAT_SEND_DATA* SendContext, _In_ UINT16 MaxBufferLength) {
//    CXPLAT_DBG_ASSERT(SendContext->SegmentSize > 0);
//    CXPLAT_DBG_ASSERT(MaxBufferLength <= SendContext->SegmentSize);
//
//    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = SendContext->Owner;
//    WSABUF* WsaBuffer;
//
//    if (SendContext->ClientBuffer.buf != NULL &&
//        CxPlatSendContextCanAllocSendSegment(SendContext, MaxBufferLength)) {
//
//        //
//        // All clear to return the next segment of our contiguous buffer.
//        //
//        SendContext->ClientBuffer.len = MaxBufferLength;
//        return (QUIC_BUFFER*)&SendContext->ClientBuffer;
//    }
//
//    WsaBuffer = CxPlatSendContextAllocBuffer(SendContext, &ProcContext->LargeSendBufferPool);
//    if (WsaBuffer == NULL) {
//        return NULL;
//    }
//
//    //
//    // Provide a virtual WSABUF to the client. Once the client has committed
//    // to a final send size, we'll append it to our internal backing buffer.
//    //
//    WsaBuffer->len = 0;
//    SendContext->ClientBuffer.buf = WsaBuffer->buf;
//    SendContext->ClientBuffer.len = MaxBufferLength;
//
//    return (QUIC_BUFFER*)&SendContext->ClientBuffer;
//}
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER* CxPlatDataPathBindingAllocSendDatagram(_In_ CXPLAT_SEND_DATA* SendContext, _In_ uint16_t MaxBufferLength) {
    CXPLAT_DBG_ASSERT(SendContext != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

    QUIC_BUFFER* Buffer = NULL;

    CXPLAT_DBG_ASSERT(SendContext != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Max batch size limit hit");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    CxPlatZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = CxPlatPoolAlloc(&SendContext->Owner->SendBufferPool);
    if (Buffer->Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Send Buffer",
            0);
        Buffer = NULL;
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    //SendContext->Iovs[SendContext->BufferCount].iov_base = Buffer->Buffer;
    //SendContext->Iovs[SendContext->BufferCount].iov_len = Buffer->Length;

    ++SendContext->BufferCount;

Exit:

    return Buffer;
    //CxPlatSendContextFinalizeSendBuffer(SendContext, FALSE);

    //if (!CxPlatSendContextCanAllocSend(SendContext, MaxBufferLength)) {
    //    return NULL;
    //}

    //if (SendContext->SegmentSize == 0) {
    //    return CxPlatSendContextAllocPacketBuffer(SendContext, MaxBufferLength);
    //} else {
    //    return CxPlatSendContextAllocSegmentBuffer(SendContext, MaxBufferLength);
    //}
}
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDataPathBindingFreeSendDatagram(
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
{
    CxPlatPoolFree(&SendContext->Owner->SendBufferPool, Datagram->Buffer);
    Datagram->Buffer = NULL;

    CXPLAT_DBG_ASSERT(Datagram == &SendContext->Buffers[SendContext->BufferCount - 1]);

    --SendContext->BufferCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathBindingIsSendContextFull(
    _In_ CXPLAT_SEND_DATA* SendContext
    )
{
    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
}

void
CxPlatSendContextComplete(
    _In_ CXPLAT_UDP_SOCKET_CONTEXT* SocketContext,
    _In_ CXPLAT_SEND_DATA* SendContext,
    _In_ unsigned long IoResult
    )
{
    UNREFERENCED_PARAMETER(SendContext);
    UNREFERENCED_PARAMETER(SocketContext);
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            IoResult,
            "sendmsg completion");
    }

    // CxPlatDataPathBindingFreeSendContext(SendContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    QUIC_STATUS Status;
    CXPLAT_DATAPATH* Datapath;
    CXPLAT_UDP_SOCKET_CONTEXT* SocketContext;
    QUIC_ADDR MappedRemoteAddress = {0};
    int Socket;
    int Result;

    CXPLAT_DBG_ASSERT(Binding != NULL && RemoteAddress != NULL && SendData != NULL);

    if (SendData->BufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    CxPlatSendContextFinalizeSendBuffer(SendData, TRUE);

    Datapath = Binding->Datapath;
    SocketContext = &Binding->SocketContexts[0];
    Socket = SocketContext->Socket;

    //struct cmsghdr CMsg;
    //uint8_t CtrlBuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int))];

    struct iovec Iovs[CXPLAT_MAX_BATCH_SEND];

    uint32_t TotalSize = 0;
    for (int i = 0; i < SendData->BufferCount; i++) {
        Iovs[i].iov_base = SendData->Buffers[i].Buffer;
        Iovs[i].iov_len = SendData->Buffers[i].Length;
        TotalSize += SendData->Buffers[i].Length;
    }

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        TotalSize,
        SendData->BufferCount,
        SendData->Buffers[0].Length,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

    //
    // Map V4 address to dual-stack socket format.
    //
    CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

    if (MappedRemoteAddress.Ipv6.sin6_family == QUIC_ADDRESS_FAMILY_INET6) {
        MappedRemoteAddress.Ipv6.sin6_family = AF_INET6;
    }

    struct msghdr WSAMhdr;
    WSAMhdr.msg_flags = 0;
    WSAMhdr.msg_name = NULL;
    WSAMhdr.msg_namelen = 0;
    WSAMhdr.msg_iov = (struct iovec *)Iovs;
    WSAMhdr.msg_iovlen = SendData->BufferCount;
    WSAMhdr.msg_control = NULL;
    WSAMhdr.msg_controllen = 0;

    // XXX: high level of confidence that ECN wont work on macos
    // Find out if this is true later
    //if (RemoteAddress->si_family == AF_INET) {
    //    WSAMhdr.Control.len += CMSG_SPACE(sizeof(INT));
    //    CMsg = CMSG_FIRSTHDR(&WSAMhdr);
    //    CMsg->cmsg_level = IPPROTO_IP;
    //    CMsg->cmsg_type = IP_ECN;
    //    CMsg->cmsg_len = CMSG_LEN(sizeof(INT));
    //    *(int *)CMSG_DATA(CMsg) = SendData->ECN;

    //} else {
    //    WSAMhdr.Control.len += CMSG_SPACE(sizeof(INT));
    //    CMsg = CMSG_FIRSTHDR(&WSAMhdr);
    //    CMsg->cmsg_level = IPPROTO_IPV6;
    //    CMsg->cmsg_type = IPV6_ECN;
    //    CMsg->cmsg_len = CMSG_LEN(sizeof(INT));
    //    *(int *)CMSG_DATA(CMsg) = SendData->ECN;
    //}
    CXPLAT_DBG_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

    //
    // Start the async send.
    //
    Result = sendmsg(Socket, &WSAMhdr, 0);

    if (Result == SOCKET_ERROR) {
        // TODO: Fix this check to be more concise for POSIX-like platforms
        Status = errno;
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketContext->Binding,
            Status,
            "sendmsg");
        goto Exit;

    } else {
        //
        // Completed synchronously.
        //
        // TODO: Always call send complete, probably. the status code here may
        // be useful if the send didnt succeed but we dont want to queue it up
        // at this layer
        CxPlatSendContextComplete(SocketContext, SendData, QUIC_STATUS_SUCCESS);
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        CxPlatDataPathBindingFreeSendContext(SendData);
    }

    return Status;
}

void*
CxPlatDataPathWorkerThread(
    _In_ void* CompletionContext
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = (CXPLAT_DATAPATH_PROC_CONTEXT*)CompletionContext;

    QuicTraceLogInfo(
        DatapathWorkerThreadStart,
        "[data][%p] Worker start",
        ProcContext);

    CXPLAT_DBG_ASSERT(ProcContext != NULL);
    CXPLAT_DBG_ASSERT(ProcContext->Datapath != NULL);

    int Kqueue = ProcContext->Kqueue;
    struct kevent EventList[32];

    while (TRUE) {
        size_t NumberOfBytesTransferred = 0;
        unsigned long IoResult = 0;

        int EventCount = kevent(Kqueue, NULL, 0, EventList, 32, NULL);

        if (ProcContext->Datapath->Shutdown) break;

        for (int i = 0; i < EventCount; i++) {
            struct kevent *Event = &EventList[i];
            CXPLAT_DBG_ASSERT(Event->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));

            CXPLAT_UDP_SOCKET_CONTEXT *SocketContext = (CXPLAT_UDP_SOCKET_CONTEXT *)Event->udata;

            if (Event->filter == EVFILT_USER || Event->flags & EV_EOF) {
                CxPlatDataPathSocketContextShutdown(SocketContext);
            }
            else if (Event->filter == EVFILT_READ) {
                NumberOfBytesTransferred = recvmsg(SocketContext->Socket, &SocketContext->RecvMsgHdr, 0);
                if (NumberOfBytesTransferred == (size_t)-1) IoResult = errno;

                // XXX: Do we need the SocketContext->UpcallRundown if we only have one worker?
                // Handle the receive indication and queue a new receive.
                CxPlatDataPathRecvComplete(ProcContext, SocketContext, IoResult, (uint16_t)NumberOfBytesTransferred);
            }
            else if (Event->filter == EVFILT_WRITE) {
                // This indicates that there is buffer available for sending. Try
                // to empty the send queue
                // XXX: It seems in winuser we don't handle any failed sends, the
                // core probably just notices the missed-ack and handles it
                // accordingly
            }
        }
    }

    QuicTraceLogInfo(
        DatapathWorkerThreadStop,
        "[data][%p] Worker stop",
        ProcContext);

    return NO_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathBindingSetParam(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* Buffer
    )
{
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathBindingGetParam(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        uint8_t* Buffer
    )
{
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}
