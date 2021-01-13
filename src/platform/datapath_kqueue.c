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
    QUIC_POOL* OwningPool;

    //
    // The reference count of the receive buffer.
    //
    unsigned long ReferenceCount;

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
typedef struct QUIC_DATAPATH_SEND_CONTEXT {
    //
    // The owning processor context.
    //
    QUIC_DATAPATH_PROC_CONTEXT* Owner;

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
    QUIC_ECN_TYPE ECN;

    //
    // The current number of WsaBuffers used.
    //
    uint8_t BufferCount;

    //
    // Contains all the datagram buffers to pass to the socket.
    //
    QUIC_BUFFER Buffers[QUIC_MAX_BATCH_SEND];

    //
    // The WSABUF returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

} QUIC_DATAPATH_SEND_CONTEXT;

//
// Per-socket state.
//
typedef struct QUIC_UDP_SOCKET_CONTEXT {

    //
    // Parent QUIC_DATAPATH_BINDING.
    //
    QUIC_DATAPATH_BINDING* Binding;

    //
    // UDP socket used for sending/receiving datagrams.
    //
    int Socket;

    //
    // Rundown for synchronizing clean up with upcalls.
    //
    QUIC_RUNDOWN_REF UpcallRundown;

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
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* CurrentRecvContext;

} QUIC_UDP_SOCKET_CONTEXT;

//
// Per-port state. Multiple sockets are created on each port.
//
typedef struct QUIC_DATAPATH_BINDING {

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
    QUIC_DATAPATH* Datapath;

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
    QUIC_UDP_SOCKET_CONTEXT SocketContexts[0];

} QUIC_DATAPATH_BINDING;

//
// Represents a single IO completion port and thread for processing work that
// is completed on a single processor.
//
typedef struct QUIC_DATAPATH_PROC_CONTEXT {

    //
    // Parent datapath.
    //
    QUIC_DATAPATH* Datapath;

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

} QUIC_DATAPATH_PROC_CONTEXT;

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
    uint8_t MaxSendBatchSize;

    //
    // Rundown for waiting on binding cleanup.
    //
    QUIC_RUNDOWN_REF BindingsRundown;

    //
    // The client callback function pointers.
    //
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
    uint32_t ProcCount;

    //
    // Per-processor completion contexts.
    //
    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[0];

} QUIC_DATAPATH;

QUIC_RECV_DATAGRAM* QuicDataPathRecvPacketToRecvDatagram(_In_ const QUIC_RECV_PACKET* const Context) {
    return (QUIC_RECV_DATAGRAM*) (((uint8_t *)Context) - sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) - sizeof(QUIC_RECV_DATAGRAM));
}

QUIC_RECV_PACKET* QuicDataPathRecvDatagramToRecvPacket(_In_ const QUIC_RECV_DATAGRAM* const Datagram) {
    return (QUIC_RECV_PACKET*) (((uint8_t *)Datagram) + sizeof(QUIC_RECV_DATAGRAM) + sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT));
}

QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* QuicDataPathDatagramToInternalDatagramContext(_In_ QUIC_RECV_DATAGRAM* Datagram) {
    return (QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*) (((uint8_t *)Datagram) + sizeof(QUIC_RECV_DATAGRAM));
}

void QuicDataPathWakeWorkerThread(_In_ QUIC_DATAPATH_PROC_CONTEXT *ProcContext, _In_ QUIC_UDP_SOCKET_CONTEXT *SocketContext);
//
// Callback function for IOCP Worker Thread.
//
void *QuicDataPathWorkerThread(_In_ void* Context);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDataPath
    )
{
    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath;
    uint32_t DatapathLength;
    uint32_t MaxProcCount = 1;

    if (RecvCallback == NULL || UnreachableCallback == NULL || NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        Datapath = NULL;
        goto Exit;
    }

    DatapathLength = sizeof(QUIC_DATAPATH) + MaxProcCount * sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    Datapath = (QUIC_DATAPATH*)QUIC_ALLOC_PAGED(DatapathLength);
    if (Datapath == NULL) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)", "QUIC_DATAPATH", DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicZeroMemory(Datapath, DatapathLength);
    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachableHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = MaxProcCount;
    QuicRundownInitialize(&Datapath->BindingsRundown);

    Datapath->MaxSendBatchSize = 1;

    uint32_t MessageCount = 1;

    Datapath->DatagramStride =
        ALIGN_UP(
            sizeof(QUIC_RECV_DATAGRAM) +
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) +
            ClientRecvContextLength,
            void *);

    Datapath->RecvPayloadOffset = sizeof(QUIC_DATAPATH_INTERNAL_RECV_CONTEXT) + MessageCount * Datapath->DatagramStride;

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

        QuicPoolInitialize(FALSE, sizeof(QUIC_DATAPATH_SEND_CONTEXT), QUIC_POOL_GENERIC, &Datapath->ProcContexts[i].SendContextPool);
        QuicPoolInitialize(FALSE, MAX_UDP_PAYLOAD_LENGTH, QUIC_POOL_DATA, &Datapath->ProcContexts[i].SendBufferPool);
        QuicPoolInitialize(FALSE, QUIC_LARGE_SEND_BUFFER_SIZE, QUIC_POOL_DATA, &Datapath->ProcContexts[i].LargeSendBufferPool);
        QuicPoolInitialize(FALSE, RecvDatagramLength, QUIC_POOL_DATA, &Datapath->ProcContexts[i].RecvDatagramPool);

        int KqueueFd = kqueue();

        if (KqueueFd == INVALID_SOCKET) {
            Status = errno;
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.", Status, "kqueue() failed");
            goto Error;
        }

        Datapath->ProcContexts[i].Kqueue = KqueueFd;

        QUIC_THREAD_CONFIG ThreadConfig = {
            0,
            0,
            NULL,
            QuicDataPathWorkerThread,
            &Datapath->ProcContexts[i]
        };

        Status = QuicThreadCreate(&ThreadConfig, &Datapath->ProcContexts[i].CompletionThread);

        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(LibraryErrorStatus, "[ lib] ERROR, %u, %s.", Status, "CreateThread");
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
                QuicPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
                QuicPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
                QuicPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
                QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPool);
            }
            QuicRundownUninitialize(&Datapath->BindingsRundown);
            QUIC_FREE(Datapath);
        }
    }

Exit:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void QuicDataPathUninitialize(_In_ QUIC_DATAPATH* Datapath) {
    if (Datapath == NULL) { return; }

    //
    // Wait for all outstanding binding to clean up.
    //
    QuicRundownReleaseAndWait(&Datapath->BindingsRundown);

    //
    // Disable processing on the completion threads and kick the IOCPs to make
    // sure the threads knows they are disabled.
    //
    Datapath->Shutdown = TRUE;
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        QuicDataPathWakeWorkerThread(&Datapath->ProcContexts[i], NULL);
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
        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPool);
    }

    QuicRundownUninitialize(&Datapath->BindingsRundown);
    QUIC_FREE(Datapath);
}

void QuicDataPathWakeWorkerThread(_In_ QUIC_DATAPATH_PROC_CONTEXT *ProcContext, _In_ QUIC_UDP_SOCKET_CONTEXT *SocketContext) {
    struct kevent Event = { };
    EV_SET(&Event, 42, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0, (void *)SocketContext);
    kevent(ProcContext->Kqueue, &Event, 1, NULL, 0, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t QuicDataPathGetSupportedFeatures(_In_ QUIC_DATAPATH* Datapath) {
    return Datapath->Features;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN QuicDataPathIsPaddingPreferred(_In_ QUIC_DATAPATH* Datapath) {
    return !!(Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION);
}

void QuicDataPathPopulateTargetAddress(_In_ QUIC_ADDRESS_FAMILY Family, _In_ ADDRINFO *AddrInfo, _Out_ QUIC_ADDR* Address) {
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    QuicZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

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
        QUIC_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        QUIC_FRE_ASSERT(FALSE);
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
QUIC_STATUS QuicDataPathResolveAddress(_In_ QUIC_DATAPATH* Datapath, _In_z_ const char* HostName, _Inout_ QUIC_ADDR * Address) {
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
        QuicDataPathPopulateTargetAddress(Hints.ai_family, Ai, Address);
        freeaddrinfo(Ai);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(HostName, NULL, &Hints, &Ai) == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, Ai, Address);
        freeaddrinfo(Ai);
        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "Resolving hostname to IP");
    QuicTraceLogError(DatapathResolveHostNameFailed, "[%p] Couldn't resolve hostname '%s' to an IP address", Datapath, HostName);
    Status = QUIC_STATUS_DNS_RESOLUTION_ERROR;

Exit:

    return Status;
}

QUIC_STATUS QuicDataPathBindingStartReceive(_In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext, _In_ int KqueueFd);

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR *LocalAddress,
    _In_opt_ const QUIC_ADDR *RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** NewBinding
    )
{
    QUIC_STATUS Status;
    QUIC_DATAPATH_BINDING* Binding = NULL;
    uint32_t BindingLength;
    uint32_t SocketCount = (RemoteAddress == NULL) ? Datapath->ProcCount : 1;
    int Result;
    int Option;

    BindingLength = sizeof(QUIC_DATAPATH_BINDING) + SocketCount * sizeof(QUIC_UDP_SOCKET_CONTEXT);

    Binding = (QUIC_DATAPATH_BINDING *)QUIC_ALLOC_PAGED(BindingLength);
    if (Binding == NULL) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)", "QUIC_DATAPATH_BINDING", BindingLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QuicZeroMemory(Binding, BindingLength);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->Connected = (RemoteAddress != NULL);
    Binding->Mtu = QUIC_MAX_MTU;

    if (LocalAddress) {
        memcpy(&Binding->LocalAddress, LocalAddress, sizeof(QUIC_ADDR));
        //QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else if (RemoteAddress) {
        // We have no local address, but we have a remote address.
        // Let's match up AF types with the remote.
        Binding->LocalAddress.Ip.sa_family = RemoteAddress->Ip.sa_family;
    } else {
        // This indicates likely that the application wants a listener with a random port.
        // Since we can't dual-stack socket, fall back to AF_INET6
        Binding->LocalAddress.Ip.sa_family = AF_INET6;
    }

    QuicRundownAcquire(&Datapath->BindingsRundown);

    for (uint32_t i = 0; i < SocketCount; i++) {
        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].Socket = INVALID_SOCKET;
        Binding->SocketContexts[i].RecvIov.iov_len = Binding->Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;
        QuicRundownInitialize(&Binding->SocketContexts[i].UpcallRundown);
    }

    sa_family_t AfFamily = Binding->LocalAddress.Ip.sa_family;
    socklen_t AddrSize = AfFamily == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    for (uint32_t i = 0; i < SocketCount; i++) {

        QUIC_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

        SocketContext->Socket = socket(AfFamily, SOCK_DGRAM, 0);
        if (SocketContext->Socket == INVALID_SOCKET) {
            Status = errno;
            QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "socket");
            goto Error;
        }


        if (AfFamily == AF_INET) {
            Option = TRUE;
            Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_PKTINFO, &Option, sizeof(Option));
            if (Result == SOCKET_ERROR) {
                Status = errno;
                QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "setsockopt(IP_PKTINFO) failed");
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
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set IP_DONTFRAGMENT");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_DONTFRAG, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set IPV6_DONTFRAG");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set IPV6_PKTINFO");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_PKTINFO, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set IP_PKTINFO");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IPV6, IPV6_ECN, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set IPV6_ECN");
        //    goto Error;
        //}

        //Option = TRUE;
        //Result = setsockopt(SocketContext->Socket, IPPROTO_IP, IP_ECN, (char *)&Option, sizeof(Option));
        //if (Result == SOCKET_ERROR) {
        //    Status = errno;
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set IP_ECN");
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
        //    QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "Set SO_RCVBUF");
        //    goto Error;
        //}

        Result = bind(SocketContext->Socket, (struct sockaddr *)&Binding->LocalAddress, AddrSize);
        if (Result == SOCKET_ERROR) {
            Status = errno;
            QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "bind");
            goto Error;
        }

        if (RemoteAddress != NULL) {
            Result = connect(SocketContext->Socket, (struct sockaddr *)RemoteAddress, AddrSize);
            if (Result == SOCKET_ERROR) {
                Status = errno;
                QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "connect");
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
                QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", Binding, Status, "getsockaddress");
                goto Error;
            }

            if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
                QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
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
        Status = QuicDataPathBindingStartReceive(&Binding->SocketContexts[i], Datapath->ProcContexts[i].Kqueue);
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
                    QUIC_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

                    close(SocketContext->Socket);

                    //
                    // Queue a completion to clean up the socket context.
                    //
                    QuicDataPathWakeWorkerThread(&Binding->Datapath->ProcContexts[i], SocketContext);
                }
            } else {
                for (uint32_t i = 0; i < SocketCount; i++) {
                    QUIC_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

                    if (SocketContext->Socket != INVALID_SOCKET) {
                        close(SocketContext->Socket);
                    }

                    QuicRundownUninitialize(&SocketContext->UpcallRundown);
                }
                QuicRundownRelease(&Datapath->BindingsRundown);
                QUIC_FREE(Binding);
            }
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void QuicDataPathBindingDelete(_In_ QUIC_DATAPATH_BINDING* Binding)
{
    QUIC_DBG_ASSERT(Binding != NULL);
    QuicTraceLogVerbose(DatapathShuttingDown, "[ udp][%p] Shutting down", Binding);

    //
    // The function is called by the upper layer when it is completely done
    // with the UDP binding. It expects that after this call returns there will
    // be no additional upcalls related to this binding, and all outstanding
    // upcalls on different threads will be completed.
    //

    QUIC_DATAPATH* Datapath = Binding->Datapath;

    if (Binding->Connected) {
        QUIC_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[0];
        uint32_t Processor = Binding->ConnectedProcessorAffinity;
        QuicRundownReleaseAndWait(&SocketContext->UpcallRundown);

        close(SocketContext->Socket);
        QuicDataPathWakeWorkerThread(&Datapath->ProcContexts[0], SocketContext);

    } else {
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            QUIC_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];
            QuicRundownReleaseAndWait(&SocketContext->UpcallRundown);
        }
        for (uint32_t i = 0; i < Datapath->ProcCount; ++i) {
            QUIC_UDP_SOCKET_CONTEXT* SocketContext = &Binding->SocketContexts[i];

            close(SocketContext->Socket);

            QuicDataPathWakeWorkerThread(&Datapath->ProcContexts[i], SocketContext);
        }
    }

    QuicTraceLogVerbose(DatapathShutDownReturn, "[ udp][%p] Shut down (return)", Binding);
}

void QuicDataPathSocketContextShutdown(_In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext) {
    if (SocketContext->CurrentRecvContext != NULL) {
        QuicPoolFree(SocketContext->CurrentRecvContext->OwningPool, SocketContext->CurrentRecvContext);
        SocketContext->CurrentRecvContext = NULL;
    }

    QuicRundownUninitialize(&SocketContext->UpcallRundown);

    if (InterlockedDecrement16(&SocketContext->Binding->SocketContextsOutstanding) == 0) {
        //
        // Last socket context cleaned up, so now the binding can be freed.
        //
        QuicRundownRelease(&SocketContext->Binding->Datapath->BindingsRundown);
        QuicTraceLogVerbose(DatapathShutDownComplete, "[ udp][%p] Shut down (complete)", SocketContext->Binding);
        QUIC_FREE(SocketContext->Binding);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t QuicDataPathBindingGetLocalMtu(_In_ QUIC_DATAPATH_BINDING* Binding) {
    QUIC_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void QuicDataPathBindingGetLocalAddress(_In_ QUIC_DATAPATH_BINDING* Binding, _Out_ QUIC_ADDR * Address) {
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void QuicDataPathBindingGetRemoteAddress(_In_ QUIC_DATAPATH_BINDING* Binding, _Out_ QUIC_ADDR * Address) {
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
}

QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* QuicDataPathBindingAllocRecvContext(_In_ QUIC_DATAPATH* Datapath, _In_ uint16_t ProcIndex) {
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = QuicPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvDatagramPool);

    if (RecvContext != NULL) {
        RecvContext->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvDatagramPool;
        RecvContext->ReferenceCount = 0;
    }

    return RecvContext;
}

void QuicDataPathBindingHandleUnreachableError(_In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext, _In_ unsigned long ErrorCode) {
    QUIC_ADDR *RemoteAddr = &SocketContext->CurrentRecvContext->Tuple.RemoteAddress;
    UNREFERENCED_PARAMETER(ErrorCode);

#if QUIC_CLOG
    QuicTraceLogVerbose(DatapathUnreachableWithError, "[ udp][%p] Received unreachable error (0x%x) from %!ADDR!", SocketContext->Binding, ErrorCode, CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));
#endif

    QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->UnreachableHandler);
    SocketContext->Binding->Datapath->UnreachableHandler(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RemoteAddr);
}

QUIC_STATUS QuicDataPathPrepareReceive(_In_ QUIC_UDP_SOCKET_CONTEXT *SocketContext) {
    if (SocketContext->CurrentRecvContext == NULL) {
        SocketContext->CurrentRecvContext = QuicDataPathBindingAllocRecvContext(SocketContext->Binding->Datapath, 0);
        if (SocketContext->CurrentRecvContext == NULL) {
            QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)", "QUIC_DATAPATH_RECV_BLOCK", 0);
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    QuicZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    QuicZeroMemory(&SocketContext->RecvMsgControlBuf, sizeof(SocketContext->RecvMsgControlBuf));

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

QUIC_STATUS QuicDataPathBindingStartReceive(_In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext, _In_ int KqueueFd) {
    QUIC_STATUS Status = QuicDataPathPrepareReceive(SocketContext);

    if (QUIC_FAILED(Status)) goto Error;

    struct kevent Event = { };
    EV_SET(&Event, SocketContext->Socket, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, (void *)SocketContext);
    if (kevent(KqueueFd, &Event, 1, NULL, 0, NULL) < 0)  {
        // Should be QUIC_STATUS_KQUEUE_ERROR
        QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", SocketContext->Binding, Status, "kevent(..., sockfd EV_ADD, ...) failed");
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
QuicDataPathRecvComplete(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext,
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
    QUIC_DBG_ASSERT(SocketContext->CurrentRecvContext != NULL);
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = SocketContext->CurrentRecvContext;
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
        QuicDataPathBindingHandleUnreachableError(SocketContext, IoResult);
    } else if (IoResult == QUIC_STATUS_SUCCESS) {

        QUIC_RECV_DATAGRAM* DatagramChain = NULL;
        QUIC_RECV_DATAGRAM** DatagramChainTail = &DatagramChain;

        QUIC_DATAPATH* Datapath = SocketContext->Binding->Datapath;
        QUIC_RECV_DATAGRAM* Datagram;
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
                    //QuicConvertFromMappedV6(LocalAddr, LocalAddr);

                    LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;
                }
                // else if (CMsg->cmsg_type == IPV6_ECN) {
                //    ECN = *(int *)CMSG_DATA(CMsg);
                //    QUIC_DBG_ASSERT(ECN < UINT8_MAX);
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
                //    QUIC_DBG_ASSERT(ECN < UINT8_MAX);
                //}
            }
        }

        if (!FoundLocalAddr) {
            //
            // The underlying data path does not guarantee ancillary data for
            // enabled socket options when the system is under memory pressure.
            //
            __asm__("int3");
            QuicTraceLogWarning(DatapathMissingInfo, "[ udp][%p] WSARecvMsg completion is missing IP_PKTINFO", SocketContext->Binding);
            goto Drop;
        }

        if (NumberOfBytesTransferred == 0) {
            __asm__("int3");
            QuicTraceLogWarning(DatapathRecvEmpty, "[ udp][%p] Dropping datagram with empty payload.", SocketContext->Binding);
            goto Drop;
        }

        // QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

        QuicTraceEvent(DatapathRecv, "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!", SocketContext->Binding, NumberOfBytesTransferred, MessageLength, CLOG_BYTEARRAY(sizeof(*LocalAddr), LocalAddr), CLOG_BYTEARRAY(sizeof(*RemoteAddr), RemoteAddr));

        QUIC_DBG_ASSERT(NumberOfBytesTransferred <= SocketContext->RecvIov.iov_len);

        Datagram = (QUIC_RECV_DATAGRAM*)(RecvContext + 1);

        for ( ; NumberOfBytesTransferred != 0; NumberOfBytesTransferred -= MessageLength) {

            QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext = QuicDataPathDatagramToInternalDatagramContext(Datagram);
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

            Datagram = (QUIC_RECV_DATAGRAM*) (((uint8_t *)Datagram) + SocketContext->Binding->Datapath->DatagramStride);

            if (IsCoalesced && ++MessageCount == URO_MAX_DATAGRAMS_PER_INDICATION) {
                QuicTraceLogWarning(DatapathUroPreallocExceeded, "[ udp][%p] Exceeded URO preallocation capacity.", SocketContext->Binding);
                break;
            }
        }

        QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->RecvHandler);
        QUIC_DBG_ASSERT(DatagramChain);

        SocketContext->Binding->Datapath->RecvHandler(SocketContext->Binding, SocketContext->Binding->ClientContext, DatagramChain);

    } else {
        QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", SocketContext->Binding, IoResult, "WSARecvMsg completion");
    }

Drop:

    QUIC_STATUS Status = QuicDataPathPrepareReceive(SocketContext);
    //
    // Try to start a new receive.
    //
    return;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void QuicDataPathBindingReturnRecvDatagrams(_In_opt_ QUIC_RECV_DATAGRAM* DatagramChain) {
    QUIC_RECV_DATAGRAM* Datagram;

    long BatchedBufferCount = 0;
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* BatchedInternalContext = NULL;

    //while ((Datagram = DatagramChain) != NULL) {
    //    DatagramChain = DatagramChain->Next;

    //    QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalBufferContext = QuicDataPathDatagramToInternalDatagramContext(Datagram);
    //    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext = InternalBufferContext->RecvContext;

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
    //            QuicPoolFree(BatchedInternalContext->OwningPool, BatchedInternalContext);
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
    //    QuicPoolFree(BatchedInternalContext->OwningPool, BatchedInternalContext);
    //}
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_DATAPATH_SEND_CONTEXT* QuicDataPathBindingAllocSendContext(_In_ QUIC_DATAPATH_BINDING* Binding, _In_ QUIC_ECN_TYPE ECN, _In_ uint16_t MaxPacketSize) {
    QUIC_DBG_ASSERT(Binding != NULL);

    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = &Binding->Datapath->ProcContexts[0];

    QUIC_DATAPATH_SEND_CONTEXT* SendContext = QuicPoolAlloc(&ProcContext->SendContextPool);

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
void QuicDataPathBindingFreeSendContext(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext) {
    size_t i = 0;
    for (i = 0; i < SendContext->BufferCount; ++i) {
        QuicPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    QuicPoolFree(&SendContext->Owner->SendContextPool, SendContext);
}

static
BOOLEAN QuicSendContextCanAllocSendSegment(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ uint16_t MaxBufferLength) {
    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0);
    QUIC_DBG_ASSERT(SendContext->BufferCount > 0);
    QUIC_DBG_ASSERT(SendContext->BufferCount <= SendContext->Owner->Datapath->MaxSendBatchSize);

    unsigned long BytesAvailable = QUIC_LARGE_SEND_BUFFER_SIZE - SendContext->Buffers[SendContext->BufferCount - 1].Length - SendContext->ClientBuffer.Length;

    return MaxBufferLength <= BytesAvailable;
}

//static
//BOOLEAN QuicSendContextCanAllocSend(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ UINT16 MaxBufferLength) {
//    return (SendContext->BufferCount < SendContext->Owner->Datapath->MaxSendBatchSize) ||
//        ((SendContext->SegmentSize > 0) &&
//            QuicSendContextCanAllocSendSegment(SendContext, MaxBufferLength));
//}

static
void QuicSendContextFinalizeSendBuffer(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ BOOLEAN IsSendingImmediately) {
    if (SendContext->ClientBuffer.Length == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendContext->BufferCount > 0) {
            QUIC_DBG_ASSERT(SendContext->Buffers[SendContext->BufferCount - 1].Length < UINT16_MAX);
            SendContext->TotalSize += SendContext->Buffers[SendContext->BufferCount - 1].Length;
        }
        return;
    }

    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0 && SendContext->BufferCount > 0);
    QUIC_DBG_ASSERT(SendContext->ClientBuffer.Length > 0 && SendContext->ClientBuffer.Length <= SendContext->SegmentSize);
    QUIC_DBG_ASSERT(QuicSendContextCanAllocSendSegment(SendContext, 0));

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
        QUIC_DBG_ASSERT(IsSendingImmediately); // Future: Refactor so it's impossible to hit this.
        UNREFERENCED_PARAMETER(IsSendingImmediately);
        SendContext->ClientBuffer.Buffer = NULL;
        SendContext->ClientBuffer.Length = 0;
    }
}

//_Success_(return != NULL)
//static
//WSABUF* QuicSendContextAllocBuffer(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ QUIC_POOL* BufferPool) {
//    QUIC_DBG_ASSERT(SendContext->BufferCount < SendContext->Owner->Datapath->MaxSendBatchSize);
//
//    WSABUF* WsaBuffer = &SendContext->Buffers[SendContext->BufferCount];
//    WsaBuffer->buf = QuicPoolAlloc(BufferPool);
//    if (WsaBuffer->buf == NULL) {
//        return NULL;
//    }
//    ++SendContext->BufferCount;
//
//    return WsaBuffer;
//}

//_Success_(return != NULL)
//static
//QUIC_BUFFER* QuicSendContextAllocPacketBuffer(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ UINT16 MaxBufferLength) {
//    WSABUF* WsaBuffer = QuicSendContextAllocBuffer(SendContext, &SendContext->Owner->SendBufferPool);
//    if (WsaBuffer != NULL) {
//        WsaBuffer->len = MaxBufferLength;
//    }
//    return (QUIC_BUFFER *)WsaBuffer;
//}
//
//_Success_(return != NULL)
//static
//QUIC_BUFFER* QuicSendContextAllocSegmentBuffer(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ UINT16 MaxBufferLength) {
//    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0);
//    QUIC_DBG_ASSERT(MaxBufferLength <= SendContext->SegmentSize);
//
//    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = SendContext->Owner;
//    WSABUF* WsaBuffer;
//
//    if (SendContext->ClientBuffer.buf != NULL &&
//        QuicSendContextCanAllocSendSegment(SendContext, MaxBufferLength)) {
//
//        //
//        // All clear to return the next segment of our contiguous buffer.
//        //
//        SendContext->ClientBuffer.len = MaxBufferLength;
//        return (QUIC_BUFFER*)&SendContext->ClientBuffer;
//    }
//
//    WsaBuffer = QuicSendContextAllocBuffer(SendContext, &ProcContext->LargeSendBufferPool);
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
QUIC_BUFFER* QuicDataPathBindingAllocSendDatagram(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ uint16_t MaxBufferLength) {
    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength > 0);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    QUIC_BUFFER* Buffer = NULL;

    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Max batch size limit hit");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    QuicZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = QuicPoolAlloc(&SendContext->Owner->SendBufferPool);
    if (Buffer->Buffer == NULL) {
        QuicTraceEvent(AllocFailure, "Allocation of '%s' failed. (%llu bytes)", "Send Buffer", 0);
        Buffer = NULL;
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    //SendContext->Iovs[SendContext->BufferCount].iov_base = Buffer->Buffer;
    //SendContext->Iovs[SendContext->BufferCount].iov_len = Buffer->Length;

    ++SendContext->BufferCount;

Exit:

    return Buffer;
    //QuicSendContextFinalizeSendBuffer(SendContext, FALSE);

    //if (!QuicSendContextCanAllocSend(SendContext, MaxBufferLength)) {
    //    return NULL;
    //}

    //if (SendContext->SegmentSize == 0) {
    //    return QuicSendContextAllocPacketBuffer(SendContext, MaxBufferLength);
    //} else {
    //    return QuicSendContextAllocSegmentBuffer(SendContext, MaxBufferLength);
    //}
}
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void QuicDataPathBindingFreeSendDatagram(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ QUIC_BUFFER* Datagram) {
    QuicPoolFree(&SendContext->Owner->SendBufferPool, Datagram->Buffer);
    Datagram->Buffer = NULL;

    QUIC_DBG_ASSERT(Datagram == &SendContext->Buffers[SendContext->BufferCount - 1]);

    --SendContext->BufferCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN QuicDataPathBindingIsSendContextFull(_In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext) {
    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
}

void QuicSendContextComplete(_In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext, _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext, _In_ unsigned long IoResult)
{
    UNREFERENCED_PARAMETER(SocketContext);
    if (IoResult != QUIC_STATUS_SUCCESS) {
        QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", SocketContext->Binding, IoResult, "sendmsg completion");
    }

    // QuicDataPathBindingFreeSendContext(SendContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS QuicDataPathBindingSendTo(_In_ QUIC_DATAPATH_BINDING* Binding, _In_ const QUIC_ADDR *RemoteAddress, _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext)
{
    QUIC_STATUS Status;
    QUIC_DATAPATH* Datapath;
    QUIC_UDP_SOCKET_CONTEXT* SocketContext;
    int Socket;
    int Result;

    QUIC_DBG_ASSERT(Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    if (SendContext->BufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicSendContextFinalizeSendBuffer(SendContext, TRUE);

    Datapath = Binding->Datapath;
    SocketContext = &Binding->SocketContexts[0];
    Socket = SocketContext->Socket;

    QuicTraceEvent(DatapathSendTo, "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!", Binding, SendContext->TotalSize, SendContext->BufferCount, SendContext->SegmentSize, CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress));

    struct cmsghdr CMsg;
    uint8_t CtrlBuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int))];

    struct iovec Iovs[QUIC_MAX_BATCH_SEND];

    for (int i = 0; i < SendContext->BufferCount; i++) {
        Iovs[i].iov_base = SendContext->Buffers[i].Buffer;
        Iovs[i].iov_len = SendContext->Buffers[i].Length;
    }

    struct msghdr WSAMhdr;
    WSAMhdr.msg_flags = 0;
    WSAMhdr.msg_name = NULL;
    WSAMhdr.msg_namelen = 0;
    WSAMhdr.msg_iov = (struct iovec *)Iovs;
    WSAMhdr.msg_iovlen = SendContext->BufferCount;
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
    //    *(int *)CMSG_DATA(CMsg) = SendContext->ECN;

    //} else {
    //    WSAMhdr.Control.len += CMSG_SPACE(sizeof(INT));
    //    CMsg = CMSG_FIRSTHDR(&WSAMhdr);
    //    CMsg->cmsg_level = IPPROTO_IPV6;
    //    CMsg->cmsg_type = IPV6_ECN;
    //    CMsg->cmsg_len = CMSG_LEN(sizeof(INT));
    //    *(int *)CMSG_DATA(CMsg) = SendContext->ECN;
    //}
    QUIC_DBG_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

    //
    // Start the async send.
    //
    Result = sendmsg(Socket, &WSAMhdr, 0);

    if (Result == SOCKET_ERROR) {
        // TODO: Fix this check to be more concise for POSIX-like platforms
        Status = errno;
        QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", SocketContext->Binding, Status, "sendmsg");
        goto Exit;
    } else {
        //
        // Completed synchronously.
        //
        // TODO: Always call send complete, probably. the status code here may
        // be useful if the send didnt succeed but we dont want to queue it up
        // at this layer
        QuicSendContextComplete(SocketContext, SendContext, QUIC_STATUS_SUCCESS);
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        QuicDataPathBindingFreeSendContext(SendContext);
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR *LocalAddress,
    _In_ const QUIC_ADDR *RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    return QUIC_STATUS_SUCCESS;
//    QUIC_STATUS Status;
//    QUIC_DATAPATH* Datapath;
//    QUIC_UDP_SOCKET_CONTEXT* SocketContext;
//    SOCKET Socket;
//    int Result;
//    DWORD BytesSent;
//
//    QUIC_DBG_ASSERT(Binding != NULL && LocalAddress != NULL && RemoteAddress != NULL && SendContext != NULL);
//
//    if (SendContext->BufferCount == 0) {
//        Status = QUIC_STATUS_INVALID_PARAMETER;
//        goto Exit;
//    }
//
//    QuicSendContextFinalizeSendBuffer(SendContext, TRUE);
//
//    Datapath = Binding->Datapath;
//    SocketContext = &Binding->SocketContexts[Binding->Connected ? 0 : GetCurrentProcessorNumber()];
//    Socket = SocketContext->Socket;
//
//    QuicTraceEvent(DatapathSendFromTo, "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!", Binding, SendContext->TotalSize, SendContext->BufferCount, SendContext->SegmentSize, CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress), CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));
//
//    //
//    // Map V4 address to dual-stack socket format.
//    //
//    SOCKADDR_INET MappedRemoteAddress = { 0 };
//    QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);
//
//    PWSACMSGHDR CMsg;
//    BYTE CtrlBuf[
//        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
//        WSA_CMSG_SPACE(sizeof(INT)) +           // IP_ECN
//#ifdef UDP_SEND_MSG_SIZE
//        WSA_CMSG_SPACE(sizeof(DWORD))    // UDP_SEND_MSG_SIZE
//#endif
//        ];
//
//    WSAMSG WSAMhdr;
//    WSAMhdr.dwFlags = 0;
//    WSAMhdr.name = (LPSOCKADDR)&MappedRemoteAddress;
//    WSAMhdr.namelen = sizeof(MappedRemoteAddress);
//    WSAMhdr.lpBuffers = SendContext->Buffers;
//    WSAMhdr.dwBufferCount = SendContext->BufferCount;
//    WSAMhdr.Control.buf = (PCHAR)CtrlBuf;
//    WSAMhdr.Control.len = 0;
//
//    if (LocalAddress->si_family == AF_INET) {
//        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(IN_PKTINFO));
//        CMsg = WSA_CMSG_FIRSTHDR(&WSAMhdr);
//        CMsg->cmsg_level = IPPROTO_IP;
//        CMsg->cmsg_type = IP_PKTINFO;
//        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));
//        PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
//        PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
//        PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
//
//        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(INT));
//        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
//        QUIC_DBG_ASSERT(CMsg != NULL);
//        CMsg->cmsg_level = IPPROTO_IP;
//        CMsg->cmsg_type = IP_ECN;
//        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
//        *(PINT)WSA_CMSG_DATA(CMsg) = SendContext->ECN;
//
//    } else {
//        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(IN6_PKTINFO));
//        CMsg = WSA_CMSG_FIRSTHDR(&WSAMhdr);
//        CMsg->cmsg_level = IPPROTO_IPV6;
//        CMsg->cmsg_type = IPV6_PKTINFO;
//        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));
//        PIN6_PKTINFO PktInfo6 = (PIN6_PKTINFO)WSA_CMSG_DATA(CMsg);
//        PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
//        PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
//
//        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(INT));
//        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
//        QUIC_DBG_ASSERT(CMsg != NULL);
//        CMsg->cmsg_level = IPPROTO_IPV6;
//        CMsg->cmsg_type = IPV6_ECN;
//        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));
//        *(PINT)WSA_CMSG_DATA(CMsg) = SendContext->ECN;
//    }
//
//#ifdef UDP_SEND_MSG_SIZE
//    if (SendContext->SegmentSize > 0) {
//        WSAMhdr.Control.len += WSA_CMSG_SPACE(sizeof(DWORD));
//        CMsg = WSA_CMSG_NXTHDR(&WSAMhdr, CMsg);
//        QUIC_DBG_ASSERT(CMsg != NULL);
//        CMsg->cmsg_level = IPPROTO_UDP;
//        CMsg->cmsg_type = UDP_SEND_MSG_SIZE;
//        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD));
//        *(PDWORD)WSA_CMSG_DATA(CMsg) = SendContext->SegmentSize;
//    }
//#endif
//
//    //
//    // Start the async send.
//    //
//    RtlZeroMemory(&SendContext->Overlapped, sizeof(OVERLAPPED));
//    Result = sendmsg(Socket, &WSAMhdr, 0);
//
//    if (Result == SOCKET_ERROR) {
//        // TODO: Update this result check to be more posix-y
//        int WsaError = WSAGetLastError();
//        if (WsaError != WSA_IO_PENDING) {
//            QuicTraceEvent(DatapathErrorStatus, "[ udp][%p] ERROR, %u, %s.", SocketContext->Binding, WsaError, "sendmsg");
//            Status = HRESULT_FROM_WIN32(WsaError);
//            goto Exit;
//        }
//    } else {
//        //
//        // Completed synchronously.
//        //
//        QuicSendContextComplete(SocketContext, SendContext, QUIC_STATUS_SUCCESS);
//    }
//
//    Status = QUIC_STATUS_SUCCESS;
//
//Exit:
//
//    if (QUIC_FAILED(Status)) {
//        QuicDataPathBindingFreeSendContext(SendContext);
//    }
//
//    return Status;
}

void *QuicDataPathWorkerThread(_In_ void* CompletionContext) {
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*)CompletionContext;

    QuicTraceLogInfo(DatapathWorkerThreadStart, "[ udp][%p] Worker start", ProcContext);

    QUIC_DBG_ASSERT(ProcContext != NULL);
    QUIC_DBG_ASSERT(ProcContext->Datapath != NULL);

    int Kqueue = ProcContext->Kqueue;
    struct kevent EventList[32];

    while (TRUE) {
        size_t NumberOfBytesTransferred = 0;
        unsigned long IoResult = 0;

        int EventCount = kevent(Kqueue, NULL, 0, EventList, 32, NULL);

        if (ProcContext->Datapath->Shutdown) break;

        for (int i = 0; i < EventCount; i++) {
            struct kevent *Event = &EventList[i];
            QUIC_DBG_ASSERT(Event->filter & (EVFILT_READ | EVFILT_WRITE | EVFILT_USER));

            QUIC_UDP_SOCKET_CONTEXT *SocketContext = (QUIC_UDP_SOCKET_CONTEXT *)Event->udata;

            if (Event->filter == EVFILT_USER || Event->flags & EV_EOF) {
                QuicDataPathSocketContextShutdown(SocketContext);
            }
            else if (Event->filter == EVFILT_READ) {
                NumberOfBytesTransferred = recvmsg(SocketContext->Socket, &SocketContext->RecvMsgHdr, 0);
                if (NumberOfBytesTransferred == (size_t)-1) IoResult = errno;

                // XXX: Do we need the SocketContext->UpcallRundown if we only have one worker?
                // Handle the receive indication and queue a new receive.
                QuicDataPathRecvComplete(ProcContext, SocketContext, IoResult, (uint16_t)NumberOfBytesTransferred);
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

    QuicTraceLogInfo(DatapathWorkerThreadStop, "[ udp][%p] Worker stop", ProcContext);
    return NO_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS QuicDataPathBindingSetParam(_In_ QUIC_DATAPATH_BINDING* Binding, _In_ uint32_t Param, _In_ uint32_t BufferLength, _In_reads_bytes_(BufferLength) const uint8_t * Buffer) {
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS QuicDataPathBindingGetParam(_In_ QUIC_DATAPATH_BINDING* Binding, _In_ uint32_t Param, _Inout_ uint32_t * BufferLength, _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer) {
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}
