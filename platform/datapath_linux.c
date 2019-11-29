/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Linux

--*/

#define _GNU_SOURCE
#include "platform_internal.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <inttypes.h>
#include <linux/in6.h>
#include <arpa/inet.h>
#include "quic_platform_dispatch.h"

QUIC_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Length) <= sizeof(size_t)), "(sizeof(QUIC_BUFFER.Length) == sizeof(size_t) must be true.");
QUIC_STATIC_ASSERT((SIZEOF_STRUCT_MEMBER(QUIC_BUFFER, Buffer) == sizeof(void*)), "(sizeof(QUIC_BUFFER.Buffer) == sizeof(void*) must be true.");

#define MAX_UDP_PAYLOAD_LENGTH  (QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE)

//
// LINUX_TODO: Support batching.
//

#define QUIC_MAX_BATCH_SEND 1

//
// Type of workitem queued on the epoll thread.
//

typedef enum QUIC_DATAPATH_WORKITEM_TYPE {
    QUIC_DATAPATH_WORKITEM_TYPE_SHUTDOWN
} QUIC_DATAPATH_WORKITEM_TYPE;

//
// A datapath workitem.
//

typedef struct QUIC_DATAPATH_WORKITEM {
    //
    // A linkage to the work queue.
    //

    QUIC_LIST_ENTRY Link;

    //
    // The workitem type.
    //

    QUIC_DATAPATH_WORKITEM_TYPE Type;

    //
    // Work context based on the workitem type.
    //

    union {
        struct {
            struct QUIC_SOCKET_CONTEXT *SocketContext;
            QUIC_EVENT Completed;
        } Shutdown;
    };
} QUIC_DATAPATH_WORKITEM;

//
// Datapath work queue.
//

typedef struct QUIC_DATAPATH_WORK_QUEUE {
    //
    // Synchronizes the access to the list.
    //

    QUIC_DISPATCH_LOCK Lock;

    //
    // List of workitems.
    //

    QUIC_LIST_ENTRY List;

    //
    // Pool for workitem allocation.
    //

    QUIC_POOL Pool;

} QUIC_DATAPATH_WORK_QUEUE;

//
// A receive block to receive a UDP packet over the sockets.
//

typedef struct QUIC_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //

    QUIC_POOL* OwningPool;

    //
    // The recv buffer used by MsQuic.
    //

    QUIC_RECV_DATAGRAM RecvPacket;

    //
    // Represents the address (source and destination) information of the
    // packet.
    //

    QUIC_TUPLE Tuple;

    //
    // Buffer that actually stores the UDP payload.
    //

    uint8_t Buffer[MAX_UDP_PAYLOAD_LENGTH];

    //
    // This follows the recv block.
    //
    // QUIC_RECV_PACKET RecvContext;

} QUIC_DATAPATH_RECV_BLOCK;

//
// Send context.
//

typedef struct QUIC_DATAPATH_SEND_CONTEXT {
    //
    // Indicates if the send should be bound to a local address.
    //

    BOOLEAN Bind;

    //
    // The local address to bind to.
    //

    QUIC_ADDR LocalAddress;

    //
    // The remote address to send to.
    //

    QUIC_ADDR RemoteAddress;

    //
    // Linkage to pending send list.
    //

    QUIC_LIST_ENTRY PendingSendLinkage;

    //
    // Indicates if the send is pending.
    //

    BOOLEAN Pending;

    //
    // The proc context owning this send context.
    //

    struct QUIC_DATAPATH_PROC_CONTEXT *Owner;

    //
    // BufferCount - The buffer count in use.
    //
    // CurrentIndex - The current index of the Buffers to be sent.
    //
    // Buffers - Send buffers.
    //
    // Iovs - IO vectors used for doing sends on the socket.
    //
    // LINUX_TODO: Better way to reconcile layout difference
    // between QUIC_BUFFER and struct iovec?
    //

    size_t BufferCount;
    size_t CurrentIndex;
    QUIC_BUFFER Buffers[QUIC_MAX_BATCH_SEND];
    struct iovec Iovs[QUIC_MAX_BATCH_SEND];

} QUIC_DATAPATH_SEND_CONTEXT;

//
// Socket context.
//

typedef struct QUIC_SOCKET_CONTEXT {
    //
    // The datapath binding this socket context belongs to.
    //

    QUIC_DATAPATH_BINDING* Binding;

    //
    // The socket FD used by this socket context.
    //

    int SocketFd;

    //
    // Indicates if sends are waiting for the socket to be write ready.
    //

    BOOLEAN SendWaiting;

    //
    // The I/O vector for receive datagrams.
    //

    struct iovec RecvIov;

    //
    // The control buffer used in RecvMsgHdr.
    //

    char RecvMsgControl[CMSG_SPACE(sizeof(struct in6_pktinfo))];

    //
    // The buffer used to receive msg headers on socket.
    //

    struct msghdr RecvMsgHdr;

    //
    // The receive block currently being used for receives on this socket.
    //

    QUIC_DATAPATH_RECV_BLOCK* CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //

    QUIC_LIST_ENTRY PendingSendContextHead;

    //
    // A pre-allocated workitem used during the shudown.
    //

    QUIC_DATAPATH_WORKITEM* ShutdownWorkitem;

} QUIC_SOCKET_CONTEXT;

//
// Datapath binding.
//

typedef struct QUIC_DATAPATH_BINDING {
    //
    // Indicates if datapath binding is shut down.
    //

    BOOLEAN volatile Shutdown;

    //
    // A pointer to datapth object.
    //

    QUIC_DATAPATH* Datapath;

    //
    // local_address - The local address for the binding.
    // remote_address - The remote address for the binding.
    //

    SOCKADDR_INET LocalAddress;
    SOCKADDR_INET RemoteAddress;

    //
    // The MTU for this datapath binding.
    //

    uint16_t Mtu;

    //
    // Number of outstanding sends on this binding.
    //

    long volatile SocketContextsOutstanding;

    //
    // The client context for this binding.
    //

    void *ClientContext;

    //
    // Number of outstanding sends.
    //

    long volatile SendOutstanding;

    //
    // Set of socket contexts one per proc.
    //

    QUIC_SOCKET_CONTEXT SocketContexts[];

} QUIC_DATAPATH_BINDING;

//
// A per proc datapath context.
//

typedef struct QUIC_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //

    QUIC_DATAPATH* Datapath;

    //
    // The Epoll FD for this proc context.
    //

    int EpollFd;

    //
    // The event FD for this proc context.
    //

    int EventFd;

    //
    // The work queue for this proc context.
    //

    QUIC_DATAPATH_WORK_QUEUE WorkQueue;

    //
    // The epoll wait thread.
    //

    QUIC_THREAD EpollWaitThread;

    //
    // Pool of receive packet contexts and buffers to be shared by all sockets
    // on this core.
    //

    QUIC_POOL RecvBlockPool;

    //
    // Pool of send buffers to be shared by all sockets on this core.
    //

    QUIC_POOL SendBufferPool;

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //

    QUIC_POOL SendContextPool;

} QUIC_DATAPATH_PROC_CONTEXT;

//
// Represents a datapath object.
//

typedef struct QUIC_DATAPATH {
    //
    // If datapath is shutting down.
    //

    BOOLEAN volatile Shutdown;

    //
    // The max send batch size.
    // LINUX_TODO: See how send batching can be enabled.
    //

    uint8_t MaxSendBatchSize;

    //
    // The RSS mode (4-tuple, 2-tuple or connectionid) in use.
    // LINUX_TODO: See how to set and use this.
    //

    QUIC_RSS_MODE RssMode;

    //
    // A reference rundown on the datapath binding.
    //

    QUIC_RUNDOWN_REF BindingsRundown;

    //
    // The MsQuic receive handler.
    //

    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvHandler;

    //
    // The MsQuic unreachable handler.
    //

    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachHandler;

    //
    // The length of recv context used by MsQuic.
    //

    size_t ClientRecvContextLength;

    //
    // The proc count to create per proc datapath state.
    // LINUX_TODO: For now this is hardcoded to 1 and we maintain a single proc
    // state per datapath binding.
    //

    uint32_t ProcCount;

    //
    // The per proc datapath contexts.
    //

    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[];

} QUIC_DATAPATH;

static
QUIC_STATUS
QuicDataPathProcContextInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _Out_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    );

static
void
QuicDatapathWorkQueueInitialize(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    );

static
void
QuicDatapathWorkQueueUninitialize(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    );

static
QUIC_STATUS
QuicDatapathSocketContextOpen(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ QUIC_ADDR *LocalAddress,
    _In_ QUIC_ADDR *RemoteAddress,
    _In_ uint32_t ProcIndex,
    _Out_ QUIC_SOCKET_CONTEXT* SocketContext
    );

static
QUIC_STATUS
QuicDataPathBindingStartReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ int EpollFd
    );

static
QUIC_STATUS
QuicDataPathBindingPrepareForReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    );

static
void
QuicDataPathRecvComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ ssize_t NumberOfBytesTransferred
    );

static
void
QuicSendContextComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ int IoResult,
    _In_ int SentByteCount
    );

static
void
QuicDataPathSendBufferInitIov(
    _Inout_ struct iovec *Iov,
    _In_ QUIC_BUFFER* Buffer
    );

static
void
QuicDataPathUninitializeNotifyWorker(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT*  ProcContext
    );

static
void*
QuicDataPathWorkerThread(
    _In_ void* Context
    );

static
void
QuicDatapathSocketContextShutdownBegin(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext
    );

static
void
QuicDatapathSocketContextShutdownEnd(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext
    );

static
QUIC_STATUS
QuicDataPathBindingSend(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    );

static
void
QuicDatapathWorkQueueInitialize(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    )
{
    QuicDispatchLockInitialize(&WorkQueue->Lock);
    QuicListInitializeHead(&WorkQueue->List);
    QuicPoolInitialize(FALSE, sizeof(QUIC_DATAPATH_WORKITEM), &WorkQueue->Pool);
}

static
void
QuicDatapathWorkQueueUninitialize(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    )
{
    QUIC_DBG_ASSERT(QuicListIsEmpty(&WorkQueue->List));
    QuicDispatchLockUninitialize(&WorkQueue->Lock);
    QuicPoolUninitialize(&WorkQueue->Pool);
}

static
QUIC_DATAPATH_WORKITEM*
QuicDatapathWorkitemAlloc(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    )
{
    QUIC_DATAPATH_WORKITEM* Workitem = QuicPoolAlloc(&WorkQueue->Pool);
    if (Workitem == NULL) {
        LogError("[ dal] Workitem allocation failure.");
    }
    return Workitem;
}

static
void
QuicDatapathWorkitemFree(
    _In_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue,
    _Inout_ QUIC_DATAPATH_WORKITEM* Workitem
    )
{
    if (Workitem != NULL) {
        QuicPoolFree(&WorkQueue->Pool, Workitem);
        Workitem = NULL;
    }
}

static
void
QuicDatapathWorkQueuePush(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue,
    _Inout_ QUIC_DATAPATH_WORKITEM* Workitem
    )
{
    QuicDispatchLockAcquire(&WorkQueue->Lock);
    QuicListInsertTail(&WorkQueue->List, &Workitem->Link);
    QuicDispatchLockRelease(&WorkQueue->Lock);
}

static
QUIC_DATAPATH_WORKITEM*
QuicDatapathWorkQueuePop(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    )
{
    QUIC_DATAPATH_WORKITEM* Workitem = NULL;

    QuicDispatchLockAcquire(&WorkQueue->Lock);
    if (!QuicListIsEmpty(&WorkQueue->List)) {
        Workitem =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&WorkQueue->List),
                QUIC_DATAPATH_WORKITEM,
                Link);
    }
    QuicDispatchLockRelease(&WorkQueue->Lock);

    return Workitem;
}

static
void
QuicDatapathWorkQueueClear(
    _Inout_ QUIC_DATAPATH_WORK_QUEUE* WorkQueue
    )
{
    QUIC_LIST_ENTRY OldList = {0};
    QuicListInitializeHead(&OldList);

    QuicDispatchLockAcquire(&WorkQueue->Lock);
    QuicListMoveItems(&WorkQueue->List, &OldList);
    QuicDispatchLockRelease(&WorkQueue->Lock);

    while (!QuicListIsEmpty(&OldList)) {
        QuicDatapathWorkitemFree(
            WorkQueue,
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&OldList),
                QUIC_DATAPATH_WORKITEM,
                Link));
    }
}

static
void
QuicDatapathNotifyEvent(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    const eventfd_t Value = 1;

    //
    // Poke the worker by writing to the event FD.
    //
    int Ret = eventfd_write(ProcContext->EventFd, Value);
    QUIC_DBG_ASSERT(Ret == 0);
    UNREFERENCED_PARAMETER(Ret);
}

static
void
QuicDatapathProcessWorkitem(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _Inout_ QUIC_DATAPATH_WORKITEM* Workitem
    )
{
    switch (Workitem->Type) {
    case QUIC_DATAPATH_WORKITEM_TYPE_SHUTDOWN:
        QuicDatapathSocketContextShutdownEnd(
            ProcContext,
            Workitem->Shutdown.SocketContext);
        QuicEventSet(Workitem->Shutdown.Completed);
        break;
    default:
        QUIC_FRE_ASSERT(false);
        break;
    }
}

void
QuicDatapathProcessWorkQueue(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_DATAPATH_WORKITEM* Workitem;
    while ((Workitem = QuicDatapathWorkQueuePop(&ProcContext->WorkQueue)) != NULL) {
        QuicDatapathProcessWorkitem(ProcContext, Workitem);
        QuicDatapathWorkitemFree(&ProcContext->WorkQueue, Workitem);
    }
}

void
QuicDatapathHandleWorkerNotification(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    eventfd_t Value = 0;
    ssize_t ReadByteCt = read(ProcContext->EventFd, &Value, sizeof(Value));
    QUIC_DBG_ASSERT(ReadByteCt == sizeof(Value));
    UNREFERENCED_PARAMETER(ReadByteCt);
    QuicDatapathProcessWorkQueue(ProcContext);
}

static
void
QuicDataPathUninitializeNotifyWorker(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QuicDatapathNotifyEvent(ProcContext);
}

void
QuicDataPathUninitializeWaitForWorker(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT*  ProcContext
    )
{
    QUIC_DBG_ASSERT(!pthread_equal(pthread_self(), ProcContext->EpollWaitThread));

    int Thread_Ret = 0;
    int Ret = pthread_join(ProcContext->EpollWaitThread, (void **)&Thread_Ret);
    QUIC_DBG_ASSERT(Ret == 0);
    UNREFERENCED_PARAMETER(Ret);
    UNREFERENCED_PARAMETER(Thread_Ret);
}

void
QuicDataPathHandleShutdownEvent(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    int Ret = 0;

    Ret = epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, ProcContext->EventFd, NULL);
    if (Ret != 0) {
        LogError("[ dal] epoll_ctl() failed, ret %d.", Ret);
    }

    Ret = close(ProcContext->EventFd);
    if (Ret != 0) {
        LogError("[ dal] close(EventFd) failed, ret %d.", Ret);
    }

    ProcContext->EventFd = INVALID_SOCKET_FD;

    Ret = close(ProcContext->EpollFd);
    if (Ret != 0) {
        LogError("[ dal] close(EpollFd) failed, ret %d.", Ret);
    }

    ProcContext->EpollFd = INVALID_SOCKET_FD;

    QuicDatapathWorkQueueClear(&ProcContext->WorkQueue);
    QuicDatapathWorkQueueUninitialize(&ProcContext->WorkQueue);
}

static
QUIC_STATUS
QuicDataPathProcContextInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _Out_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int EpollFd = INVALID_SOCKET_FD;
    int EventFd = INVALID_SOCKET_FD;
    int Ret = 0;
    uint32_t RecvPacketLength = 0;
    BOOLEAN EventFdAdded = FALSE;

    QUIC_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(QUIC_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    QuicPoolInitialize(TRUE, RecvPacketLength, &ProcContext->RecvBlockPool);
    QuicPoolInitialize(TRUE, MAX_UDP_PAYLOAD_LENGTH, &ProcContext->SendBufferPool);
    QuicPoolInitialize(
        TRUE,
        sizeof(QUIC_DATAPATH_SEND_CONTEXT),
        &ProcContext->SendContextPool);

    QuicDatapathWorkQueueInitialize(&ProcContext->WorkQueue);

    EpollFd = epoll_create1(EPOLL_CLOEXEC);
    if (EpollFd == INVALID_SOCKET_FD) {
        Status = errno;
        LogError("[ dal] epoll_create1(EPOLL_CLOEXEC) failed, status %u.", Status);
        goto Exit;
    }

    EventFd = eventfd(0, EFD_CLOEXEC);
    if (EventFd == INVALID_SOCKET_FD) {
        Status = errno;
        LogError("[ dal] eventfd() failed, status %u.", Status);
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = &ProcContext->EventFd
        }
    };

    Ret = epoll_ctl(EpollFd, EPOLL_CTL_ADD, EventFd, &EvtFdEpEvt);
    if (Ret != 0) {
        Status = errno;
        LogError("[ dal] epoll_ctl(EPOLL_CTL_ADD) failed, status %u.", Status);
        goto Exit;
    }

    EventFdAdded = TRUE;

    ProcContext->Datapath = Datapath;
    ProcContext->EpollFd = EpollFd;
    ProcContext->EventFd = EventFd;

    //
    // Starting the thread must be done after the rest of the ProcContext
    // members have been initialized. Because the thread start routine accesses
    // ProcContext members.
    //

    QUIC_THREAD_CONFIG ThreadConfig = {
        0,
        0,
        NULL,
        QuicDataPathWorkerThread,
        ProcContext
    };

    Status = QuicThreadCreate(&ThreadConfig, &ProcContext->EpollWaitThread);
    if (QUIC_FAILED(Status)) {
        LogError("[ dal] QuicThreadCreate() failed, status %u.", Status);
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {

        if (EventFdAdded) {
            epoll_ctl(EpollFd, EPOLL_CTL_DEL, EventFd, NULL);
        }

        if (EventFd != INVALID_SOCKET_FD) {
            close(EventFd);
        }

        if (EpollFd != INVALID_SOCKET_FD) {
            close(EpollFd);
        }

        QuicPoolUninitialize(&ProcContext->RecvBlockPool);
        QuicPoolUninitialize(&ProcContext->SendBufferPool);
        QuicPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}

QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDataPath
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathInitialize(
            ClientRecvContextLength,
            RecvCallback,
            UnreachableCallback,
            NewDataPath);
#else
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_DATAPATH* Datapath = NULL;
    size_t DatapathLength = 0;
    uint32_t i = 0;

    if (RecvCallback == NULL ||
        UnreachableCallback == NULL ||
        NewDataPath == NULL) {
        LogError("[ dal] Invalid parameter.");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    DatapathLength =
        sizeof(QUIC_DATAPATH) +
            QuicProcMaxCount() * sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    Datapath = (QUIC_DATAPATH*)QUIC_ALLOC_PAGED(DatapathLength);

    if (Datapath == NULL) {
        LogError("[ dal] Datapath allocation failure.");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(Datapath, DatapathLength);

    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = QuicProcMaxCount();

    QuicRundownInitialize(&Datapath->BindingsRundown);

    Datapath->MaxSendBatchSize = QUIC_MAX_BATCH_SEND;

    //
    // Initialize the per proc context.
    //

    for (i = 0; i < Datapath->ProcCount; i++) {

        Status =
            QuicDataPathProcContextInitialize(
                Datapath,
                &Datapath->ProcContexts[i]);

        if (QUIC_FAILED(Status)) {
            LogError("[ dal] QuicDataPathProcContextInitialize() failure, Status %u.", Status);

            //
            // LINUX_TODO: Right now, loop size is 1. Future: clean up earlier items in this loop.
            //

            goto Exit;
        }
    }

    *NewDataPath = Datapath;
    Datapath = NULL;

Exit:

    if (Datapath != NULL) {
        QuicRundownUninitialize(&Datapath->BindingsRundown);
        QUIC_FREE(Datapath);
        Datapath = NULL;
    }

    return Status;
#endif
}

void
QuicDataPathUninitialize(
    _Inout_ QUIC_DATAPATH* Datapath
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathUninitialize(Datapath);
#else
    uint32_t i = 0;

    if (Datapath == NULL) {
        goto Exit;
    }

    QuicRundownReleaseAndWait(&Datapath->BindingsRundown);

    Datapath->Shutdown = TRUE;

    for (i = 0; i < Datapath->ProcCount; i++) {
        QuicDataPathUninitializeNotifyWorker(&Datapath->ProcContexts[i]);
    }

    for (i = 0; i < Datapath->ProcCount; i++) {

        QuicDataPathUninitializeWaitForWorker(&Datapath->ProcContexts[i]);

        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvBlockPool);

        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);

        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
    }

    QuicRundownUninitialize(&Datapath->BindingsRundown);
    QUIC_FREE(Datapath);
    Datapath = NULL;

Exit:

    return;
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    return 0;
}

QUIC_RSS_MODE
QuicDataPathGetRssMode(
    _In_ QUIC_DATAPATH* Datapath
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathGetRssMode(Datapath);
#else
    return QUIC_RSS_NONE;
#endif
}

BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathIsPaddingPreferred(Datapath);
#else
    //
    // The windows implementation returns TRUE only if GSO is supported and
    // this DAL implementation doesn't support GSO currently.
    //
    return FALSE;
#endif
}

void
QuicDataPathPopulateTargetAddress(
    _In_ ADDRESS_FAMILY Family,
    _In_ PADDRINFO AddrInfo,
    _Out_ SOCKADDR_INET * Address
    )
{
    PSOCKADDR_IN6 SockAddrIn6 = NULL;
    PSOCKADDR_IN SockAddrIn = NULL;

    QuicZeroMemory(Address, sizeof(SOCKADDR_INET));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        QUIC_DBG_ASSERT(sizeof(SOCKADDR_IN6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //

        SockAddrIn6 = (PSOCKADDR_IN6)AddrInfo->ai_addr;

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
        QUIC_DBG_ASSERT(sizeof(SOCKADDR_IN) == AddrInfo->ai_addrlen);
        SockAddrIn = (PSOCKADDR_IN)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        QUIC_FRE_ASSERT(false);
    }
}

QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathResolveAddress(Datapath, HostName, Address);
#else
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    PADDRINFO AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //

    Hints.ai_family = Address->si_family;

    //
    // Try numeric name first.
    //

    Hints.ai_flags = AI_NUMERICHOST;

    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);

    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    LogWarning("[ dal] getaddrinfo(AI_NUMERICHOST) failed, result %d.", Result);

    //
    // Try canonical host name.
    //

    Hints.ai_flags = AI_CANONNAME;

    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);

    if (Result == 0) {
        QuicDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    LogError("[ dal] getaddrinfo(AI_CANONNAME) failed, result %d.", Result);

    Status = QUIC_STATUS_DNS_RESOLUTION_ERROR;

Exit:

    return Status;
#endif
}

static
QUIC_STATUS
QuicDatapathSocketContextOpen(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ QUIC_ADDR * LocalAddress,
    _In_ QUIC_ADDR * RemoteAddress,
    _In_ uint32_t ProcIndex,
    _Out_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_DATAPATH_BINDING* Binding = SocketContext->Binding;
    int Result = 0;
    int Option = 0;
    SOCKADDR_INET MappedRemoteAddress = {0};
    socklen_t AssignedLocalAddressLength = 0;

    //
    // Create datagram socket.
    //

    SocketContext->SocketFd =
        socket(
            AF_INET6,
            SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, // LINUX_TODO check if SOCK_CLOEXEC is required?
            IPPROTO_UDP);

    if (SocketContext->SocketFd == INVALID_SOCKET_FD) {
        Status = errno;
        LogError("[ dal] socket() failed, status %u.", Status);
        goto Exit;
    }

    //
    // Set dual (IPv4 & IPv6) socket mode.
    //

    Option = false;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            (const void*)&Option,
            sizeof(Option));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("[ dal] setsockopt(IPV6_V6ONLY) failed, status %u.", Status);
        goto Exit;
    }

    //
    // Set DON'T FRAG socket option.
    //

    //
    // Windows: setsockopt IPPROTO_IP IP_DONTFRAGMENT true.
    // linux: IP_DONTFRAGMENT option is not available. IPV6_MTU_DISCOVER is the
    // apparent alternative.
    // LINUX_TODO: Verify this.
    //

    Option = IP_PMTUDISC_DO;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_MTU_DISCOVER,
            (const void*)&Option,
            sizeof(Option));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("[ dal] setsockopt(IP_MTU_DISCOVER) failed, status %u.", Status);
        goto Exit;
    }

    Option = true;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_DONTFRAG,
            (const void*)&Option,
            sizeof(Option));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("[ dal] setsockopt(IPV6_DONTFRAG) failed, status %u.", Status);
        goto Exit;
    }

    //
    // Set socket option to receive ancillary data about the incoming packets.
    //

    //
    // Windows: setsockopt IPPROTO_IPV6 IPV6_PKTINFO true.
    // Android: Returns EINVAL. IPV6_PKTINFO option is not present in documentation.
    // IPV6_RECVPKTINFO seems like is the alternative.
    // LINUX_TODO: Check if this works as expected?
    //

    Option = true;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IPV6,
            IPV6_RECVPKTINFO,
            (const void*)&Option,
            sizeof(Option));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("[ dal] setsockopt(IPV6_RECVPKTINFO) failed, status %u.", Status);
        goto Exit;
    }

    Option = true;
    Result =
        setsockopt(
            SocketContext->SocketFd,
            IPPROTO_IP,
            IP_PKTINFO,
            (const void*)&Option,
            sizeof(Option));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("[ dal] setsockopt(IP_PKTINFO) failed, status %u.", Status);
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
        LogError("[ dal] setsockopt(SO_RCVBUF) failed, status %u.", Status);
        goto Exit;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            (const struct sockaddr *)&Binding->LocalAddress,
            sizeof(Binding->LocalAddress));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("[ dal] bind() failed, status %u.", Status);
        goto Exit;
    }

    if (RemoteAddress != NULL) {
        QuicZeroMemory(&MappedRemoteAddress, sizeof(MappedRemoteAddress));
        QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        Result =
            connect(
                SocketContext->SocketFd,
                (const struct sockaddr *)&MappedRemoteAddress,
                sizeof(MappedRemoteAddress));

        if (Result == SOCKET_ERROR) {
            Status = errno;
            LogError("[ dal] connect() failed, status %u.", Status);
            goto Exit;
        }

        //
        // LINUX_TODO: TODO Rss affinity. See Windows implementation.
        //
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
        LogError("[ dal] getsockname() failed, status %u.", Status);
        goto Exit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    SocketContext->ShutdownWorkitem =
        QuicDatapathWorkitemAlloc(&Datapath->ProcContexts[ProcIndex].WorkQueue);

    if (SocketContext->ShutdownWorkitem == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        LogError("[ dal] ShutdownWorkitem allocation failed.");
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {
        Result = close(SocketContext->SocketFd);

        if (Result != 0)
        {
            LogError("[ dal] close() failed, err: %d.", errno);
        }

        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}


QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** NewBinding
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingCreate(
            Datapath,
            LocalAddress,
            RemoteAddress,
            RecvCallbackContext,
            NewBinding);
#else
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_DATAPATH_BINDING* Binding = NULL;
    int Result = 0;
    int Option = 0;
    uint32_t i = 0;
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;
    size_t BindingLength = 0;

    BindingLength = sizeof(QUIC_DATAPATH_BINDING) +
            Datapath->ProcCount * sizeof(QUIC_SOCKET_CONTEXT);

    Binding = (QUIC_DATAPATH_BINDING*)QUIC_ALLOC_PAGED(BindingLength);

    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        LogError("[ dal] Binding allocation failed");
        goto Exit;
    }

    QuicZeroMemory(Binding, BindingLength);

    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    Binding->Mtu = QUIC_MAX_MTU;

    if (LocalAddress) {
        QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.si_family = AF_INET6;
    }

    QuicRundownAcquire(&Datapath->BindingsRundown);

    for (i = 0; i < Binding->Datapath->ProcCount; i++) {

        Binding->SocketContexts[i].Binding = Binding;
        Binding->SocketContexts[i].SocketFd = INVALID_SOCKET_FD;
        Binding->SocketContexts[i].RecvIov.iov_len =
            Binding->Mtu - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE;

        QuicListInitializeHead(&Binding->SocketContexts[i].PendingSendContextHead);
    }

    for (i = 0; i < Binding->Datapath->ProcCount; i++) {

        SocketContext = &Binding->SocketContexts[i];

        Status =
            QuicDatapathSocketContextOpen(
                Datapath,
                (QUIC_ADDR *)LocalAddress,
                (QUIC_ADDR *)RemoteAddress,
                i,
                SocketContext);

        if (QUIC_FAILED(Status)) {
            //
            // LINUX_TODO: Right now, loop size is 1. Future: Clean up earlier items in this loop.
            //

            LogError("[ dal] QuicDatapathSocketContextOpen failed, status:%u", Status);
            goto Exit;
        }
    }

    QuicConvertFromMappedV6(
        (const SOCKADDR_INET *)&Binding->LocalAddress,
        &Binding->LocalAddress);
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

    for (i = 0; i < Binding->Datapath->ProcCount; i++) {
        Status =
            QuicDataPathBindingStartReceive(
                &Binding->SocketContexts[i],
                Datapath->ProcContexts[i].EpollFd);

        if (QUIC_FAILED(Status)) {
            //
            // LINUX_TODO: Right now, loop size is 1. Future: clean up earlier items in this loop.
            //

            LogError("[ dal] QuicDataPathBindingStartReceive() failed, status:%u", Status);
            goto Exit;
        }
    }

    Binding->SocketContextsOutstanding = (short)Binding->Datapath->ProcCount;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            QuicRundownRelease(&Datapath->BindingsRundown);
            QUIC_FREE(Binding);
            Binding == NULL;
        }
    }

    return Status;
#endif
}

static
void
QuicDatapathSocketContextShutdownBegin(
    _Inout_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_EVENT Completed = {0};
    QUIC_DATAPATH_WORKITEM* Workitem = NULL;

    //
    // Queue a workitem to cleanup the socket context. It is important to not do
    // this inline because binding delete can get called in context of a receive
    // from the epoll thread and the unwind path might have references to the
    // socket context so it shouldn't be freed here.
    //

    QUIC_DBG_ASSERT(SocketContext->ShutdownWorkitem != NULL);

    //
    // This workitem would be freed after its processing.
    //

    Workitem = SocketContext->ShutdownWorkitem;
    SocketContext->ShutdownWorkitem = NULL;

    Workitem->Type = QUIC_DATAPATH_WORKITEM_TYPE_SHUTDOWN;
    Workitem->Shutdown.SocketContext = SocketContext;

    QuicEventInitialize(&Completed, FALSE, FALSE);
    Workitem->Shutdown.Completed = Completed;

    QuicDatapathWorkQueuePush(&ProcContext->WorkQueue, Workitem);
    QuicDatapathNotifyEvent(ProcContext);

    //
    // LINUX_TODO: DataPath.ProcCount is only one, at present.
    // In future, if it becomes more than, the 'wait' should happen
    // after all workers have been notified.
    //

    QuicEventWaitForever(Completed);
    QuicEventUninitialize(Completed);

}

static
void
QuicDatapathSocketContextShutdownEnd(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _Inout_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    int Ret = 0;
    QUIC_DATAPATH_SEND_CONTEXT* SendContext = NULL;

    Ret = epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

    if (Ret != 0)
    {
        LogError("[ dal] epoll_ctl() failed, ret %d.", Ret);
    }

    Ret = close(SocketContext->SocketFd);

    if (Ret != 0)
    {
        LogError("[ dal] close() failed, ret %d.", Ret);
    }

    SocketContext->SocketFd = INVALID_SOCKET_FD;

    if (SocketContext->CurrentRecvBlock != NULL) {
        QuicDataPathBindingReturnRecvDatagrams(&SocketContext->CurrentRecvBlock->RecvPacket);
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendContextHead)) {
        SendContext =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendContextHead),
                QUIC_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage);

        QuicSendContextComplete(
            SocketContext,
            SendContext,
            QUIC_STATUS_ABORTED,
            0);

        SendContext = NULL;
    }

    if (SocketContext->ShutdownWorkitem != NULL) {
        QuicDatapathWorkitemFree(
            &ProcContext->WorkQueue, SocketContext->ShutdownWorkitem);
        SocketContext->ShutdownWorkitem = NULL;
    }

    if (InterlockedDecrement(
            &SocketContext->Binding->SocketContextsOutstanding) == 0) {
        //
        // Last socket context cleaned up, so now the binding can be freed.
        //

        QuicRundownRelease(&SocketContext->Binding->Datapath->BindingsRundown);
        QuicFree(SocketContext->Binding);
    }
}

void
QuicDataPathBindingDelete(
    _Inout_ QUIC_DATAPATH_BINDING* Binding
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingDelete(Binding);
#else
    QUIC_DATAPATH* Datapath = NULL;
    uint32_t i = 0;

    QUIC_DBG_ASSERT(Binding != NULL);

    Datapath = Binding->Datapath;
    Binding->Shutdown = true;

    for (i = 0; i < Datapath->ProcCount; ++i) {
        QuicDatapathSocketContextShutdownBegin(
            &Datapath->ProcContexts[i],
            &Binding->SocketContexts[i]);
    }
#endif
}

QUIC_DATAPATH_RECV_BLOCK*
QuicDataPathAllocRecvBlock(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t ProcIndex
    )
{
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QuicPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvBlockPool);

    if (RecvBlock == NULL) {
        LogError("[ dal] RecvBlock allocation failed.");
        goto Exit;
    }

    QuicZeroMemory(RecvBlock, sizeof(*RecvBlock));
    RecvBlock->OwningPool = &Datapath->ProcContexts[ProcIndex].RecvBlockPool;
    RecvBlock->RecvPacket.Buffer = RecvBlock->Buffer;
    RecvBlock->RecvPacket.Allocated = TRUE;

Exit:

    return RecvBlock;
}

void
QuicDataPathBindingGetLocalAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingGetLocalAddress(Binding, Address);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
#endif
}

void
QuicDataPathBindingGetRemoteAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingGetRemoteAddress(Binding, Address);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
#endif
}

QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSetParam(
            Binding,
            Param,
            BufferLength,
            Buffer);
#else
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

QUIC_STATUS
QuicDataPathBindingGetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingGetParam(
            Binding,
            Param,
            BufferLength,
            Buffer);
#else
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const RecvContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathRecvContextToRecvPacket(RecvContext);
#else
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        (QUIC_DATAPATH_RECV_BLOCK*)
            ((char *)RecvContext - sizeof(QUIC_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
#endif
}

QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const RecvPacket
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathRecvPacketToRecvContext(RecvPacket);
#else
    QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
        QUIC_CONTAINING_RECORD(RecvPacket, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

    return (QUIC_RECV_PACKET*)(RecvBlock + 1);
#endif
}

void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* RecvPacket
    )
{
    if (RecvPacket != NULL) {
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
        PlatDispatch->DatapathBindingReturnRecvPacket(RecvPacket);
#else
        QUIC_DATAPATH_RECV_BLOCK* RecvBlock =
            QUIC_CONTAINING_RECORD(RecvPacket, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

        QuicPoolFree(RecvBlock->OwningPool, RecvBlock);
#endif
    }
}

static
QUIC_STATUS
QuicDataPathBindingPrepareForReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            QuicDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                QuicProcCurrentNumber());

        if (SocketContext->CurrentRecvBlock == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            LogError("[ dal] Recv block allocation failed.");
            goto Error;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.BufferLength = SocketContext->RecvIov.iov_len;
    SocketContext->CurrentRecvBlock->RecvPacket.Tuple = (QUIC_TUPLE*)&SocketContext->CurrentRecvBlock->Tuple;

    QuicZeroMemory(&SocketContext->RecvMsgHdr, sizeof(SocketContext->RecvMsgHdr));
    QuicZeroMemory(&SocketContext->RecvMsgControl, sizeof(SocketContext->RecvMsgControl));

    SocketContext->RecvMsgHdr.msg_name = &SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress;
    SocketContext->RecvMsgHdr.msg_namelen = sizeof(SocketContext->CurrentRecvBlock->RecvPacket.Tuple->RemoteAddress);
    SocketContext->RecvMsgHdr.msg_iov = &SocketContext->RecvIov;
    SocketContext->RecvMsgHdr.msg_iovlen = 1;
    SocketContext->RecvMsgHdr.msg_control = SocketContext->RecvMsgControl;
    SocketContext->RecvMsgHdr.msg_controllen = sizeof(SocketContext->RecvMsgControl);
    SocketContext->RecvMsgHdr.msg_flags = 0;

Error:

    return Status;
}

static
QUIC_STATUS
QuicDataPathBindingStartReceive(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ int EpollFd
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;

    Status = QuicDataPathBindingPrepareForReceive(SocketContext);

    if (QUIC_FAILED(Status)) {
        LogError("[ dal] QuicDataPathBindingPrepareForReceive() failed, status %u.", Status);
        goto Error;
    }

    struct epoll_event SockFdEpEvt = {
        .events = EPOLLIN | EPOLLET,
        .data = {
            .ptr = &SocketContext->SocketFd
        }
    };

    Ret =
        epoll_ctl(
            EpollFd,
            EPOLL_CTL_ADD,
            SocketContext->SocketFd,
            &SockFdEpEvt);

    if (Ret != 0) {
        Status = Ret;
        LogError("[ dal] epoll_ctl() failed, status %u.", Status);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        Ret = close(SocketContext->SocketFd);

        if (Ret != 0) {
            LogError("[ dal] close() failed, status %u.", Status);
        }
    }

    return Status;
}

static
QUIC_STATUS
QuicDataPathBindingPendSend(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ const QUIC_ADDR *LocalAddress,
    _In_ const QUIC_ADDR *RemoteAddress
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    struct epoll_event SockFdEpEvt = {0};

    LogInfo("[ dal] Pending sends");

    if (!SocketContext->SendWaiting) {

        SockFdEpEvt.events = EPOLLIN | EPOLLOUT | EPOLLET;
        SockFdEpEvt.data.ptr = &SocketContext->SocketFd;

        Ret =
            epoll_ctl(
                ProcContext->EpollFd,
                EPOLL_CTL_MOD,
                SocketContext->SocketFd,
                &SockFdEpEvt);

        if (Ret != 0) {
            Status = Ret;
            LogError("[ dal] epoll_ctl() failed, status %u.", Status);
            goto Exit;
        }

        if (LocalAddress != NULL) {
            QuicCopyMemory(
                &SendContext->LocalAddress,
                LocalAddress,
                sizeof(*LocalAddress));

            SendContext->Bind = TRUE;
        }

        QuicCopyMemory(
            &SendContext->RemoteAddress,
            RemoteAddress,
            sizeof(*RemoteAddress));

        SocketContext->SendWaiting = TRUE;
    }

    if (!SendContext->Pending) {
        QuicListInsertTail(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);

        SendContext->Pending = TRUE;
    } else {
        QuicListInsertHead(
            &SocketContext->PendingSendContextHead,
            &SendContext->PendingSendLinkage);
    }

    QUIC_DBG_ASSERT(SocketContext->SendWaiting);

    Status = QUIC_STATUS_SUCCESS;

Exit:

    return Status;
}

static
QUIC_STATUS
QuicDataPathBindingCompletePendingSend(
    _In_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext,
    _In_ QUIC_SOCKET_CONTEXT* SocketContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    struct epoll_event SockFdEpEvt = {0};
    QUIC_DATAPATH_SEND_CONTEXT* SendContext = NULL;

    if (SocketContext->SendWaiting) {

        SockFdEpEvt.events = EPOLLIN | EPOLLET;
        SockFdEpEvt.data.ptr = &SocketContext->SocketFd;

        Ret =
            epoll_ctl(
                ProcContext->EpollFd,
                EPOLL_CTL_MOD,
                SocketContext->SocketFd,
                &SockFdEpEvt);

        if (Ret != 0) {
            Status = Ret;
            LogError("[ dal] epoll_ctl() failed, status %u.", Status);
            goto Exit;
        }

        SocketContext->SendWaiting = FALSE;
    }

    while (!QuicListIsEmpty(&SocketContext->PendingSendContextHead)) {
        SendContext =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&SocketContext->PendingSendContextHead),
                QUIC_DATAPATH_SEND_CONTEXT,
                PendingSendLinkage);

        Status =
            QuicDataPathBindingSend(
                SocketContext->Binding,
                SendContext->Bind ? &SendContext->LocalAddress : NULL,
                &SendContext->RemoteAddress,
                SendContext);

        if (QUIC_FAILED(Status)) {
            LogError("[ dal] QuicDataPathBindingSend() failed, status %u.", Status);
        }

        if (SocketContext->SendWaiting) {
            break;
        }
    }

Exit:

    return Status;
}

QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingAllocSendContext(
            Binding,
            MaxPacketSize);
#else
    QUIC_DATAPATH_SEND_CONTEXT* SendContext = NULL;
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = NULL;

    QUIC_DBG_ASSERT(Binding != NULL);

    ProcContext = &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];

    SendContext = QuicPoolAlloc(&ProcContext->SendContextPool);

    if (SendContext == NULL) {
        LogError("[ dal] QuicPoolAlloc() failed.");
        goto Exit;
    }

    QuicZeroMemory(SendContext, sizeof(*SendContext));

    SendContext->Owner = ProcContext;

Exit:

    return SendContext;
#endif
}

void
QuicDataPathBindingFreeSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingFreeSendContext(SendContext);
#else
    size_t i = 0;
    for (i = 0; i < SendContext->BufferCount; ++i) {
        QuicPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    QuicPoolFree(&SendContext->Owner->SendContextPool, SendContext);
#endif
}

static
void
QuicDataPathSendBufferInitIov(
    _Inout_ struct iovec *Iov,
    _In_ QUIC_BUFFER* Buffer
    )
{
    Iov->iov_base = Buffer->Buffer;
    Iov->iov_len = Buffer->Length;
}

QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingAllocSendBuffer(
            SendContext,
            MaxBufferLength);
#else
    QUIC_BUFFER* Buffer = NULL;

    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        LogError("[ dal] Max batch size limit hit.");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    QuicZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = QuicPoolAlloc(&SendContext->Owner->SendBufferPool);

    if (Buffer->Buffer == NULL) {
        LogError("[ dal] Send buffer allocation failed.");
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    QuicDataPathSendBufferInitIov(
        &SendContext->Iovs[SendContext->BufferCount],
        Buffer);

    ++SendContext->BufferCount;

Exit:

    return Buffer;
#endif
}

void
QuicDataPathBindingFreeSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    PlatDispatch->DatapathBindingFreeSendBuffer(SendContext, Datagram);
#else
    QuicPoolFree(&SendContext->Owner->SendBufferPool, Datagram->Buffer);
    Datagram->Buffer == NULL;

    QUIC_DBG_ASSERT(Datagram == &SendContext->Buffers[SendContext->BufferCount - 1]);

    --SendContext->BufferCount;
#endif
}

static
void
QuicSendContextComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ int IoResult,
    _In_ int SentByteCount
    )
{
    if (IoResult != QUIC_STATUS_SUCCESS) {
        LogWarning(
            "[sock][%p] Send (%p) completion failed, 0x%x",
            SocketContext, SendContext, IoResult);
    }

    QuicDataPathBindingFreeSendContext(SendContext);

    InterlockedDecrement(&SocketContext->Binding->SendOutstanding);
}

QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSendTo(
            Binding,
            RemoteAddress,
            SendContext);
#else
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    socklen_t RemoteAddrLen = 0;
    size_t i = 0;
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;
    char Inet6AddrStr[INET6_ADDRSTRLEN] = {0};

    SocketContext = &Binding->SocketContexts[QuicProcCurrentNumber()];

    QUIC_DBG_ASSERT(
        Binding != NULL &&
        RemoteAddress != NULL &&
        SendContext != NULL);

    for (i = 0; i < SendContext->BufferCount; ++i) {
        if (RemoteAddress->si_family == AF_INET) {
            LogVerbose("[sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Dst=[%s:%" PRIu16 "] (%p)",
                       SocketContext,
                       SocketContext->SocketFd,
                       SendContext->Buffers[i].Length,
                       inet_ntop(AF_INET, &RemoteAddress->Ipv4.sin_addr, Inet6AddrStr, INET_ADDRSTRLEN),
                       ntohs(RemoteAddress->Ipv4.sin_port),
                       SendContext);
        } else {
            LogVerbose("[sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Dst=[%s:%" PRIu16 "] (%p)",
                       SocketContext,
                       SocketContext->SocketFd,
                       SendContext->Buffers[i].Length,
                       inet_ntop(AF_INET6, &RemoteAddress->Ipv6.sin6_addr, Inet6AddrStr, INET6_ADDRSTRLEN),
                       ntohs(RemoteAddress->Ipv6.sin6_port),
                       SendContext);
        }
    }

    InterlockedIncrement(&Binding->SendOutstanding);

    QUIC_DBG_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

    Status =
        QuicDataPathBindingSend(
            Binding,
            NULL,
            RemoteAddress,
            SendContext);

    SendContext = NULL;

    if (QUIC_FAILED(Status)) {
        LogError("[ dal] QuicDataPathBindingSend failed, status: %u.", Status);
        goto Exit;
    }

Exit:

    if (SendContext != NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
        SendContext = NULL;
    }

    return Status;
#endif
}

QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return
        PlatDispatch->DatapathBindingSendFromTo(
            Binding,
            LocalAddress,
            RemoteAddress,
            SendContext);
#else
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    char LocalInet6AddrStr[INET6_ADDRSTRLEN] = {0};
    char RemoteInet6AddrStr[INET6_ADDRSTRLEN] = {0};
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;

    QUIC_DBG_ASSERT(
        Binding != NULL &&
        LocalAddress != NULL &&
        RemoteAddress != NULL &&
        SendContext != NULL);

    if (SendContext->BufferCount == 0) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    SocketContext = &Binding->SocketContexts[QuicProcCurrentNumber()];

    for (size_t i = 0; i < SendContext->BufferCount; ++i) {
        if (RemoteAddress->si_family == AF_INET) {
            LogVerbose("[sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Src=[%s:%" PRIu16 "%%%" PRIu32 "] Dst=[%s:%" PRIu16 "] (%p)",
                       SocketContext,
                       SocketContext->SocketFd,
                       SendContext->Buffers[i].Length,
                       inet_ntop(AF_INET, &LocalAddress->Ipv4.sin_addr, LocalInet6AddrStr, INET_ADDRSTRLEN),
                       ntohs(LocalAddress->Ipv4.sin_port),
                       LocalAddress->Ipv6.sin6_scope_id,
                       inet_ntop(AF_INET, &RemoteAddress->Ipv4.sin_addr, RemoteInet6AddrStr, INET_ADDRSTRLEN),
                       ntohs(RemoteAddress->Ipv4.sin_port),
                       SendContext);
        } else {
            LogVerbose("[sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Src=[%s:%" PRIu16 "%%%" PRIu32 "] Dst=[%s:%" PRIu16 "] (%p)",
                       SocketContext,
                       SocketContext->SocketFd,
                       SendContext->Buffers[i].Length,
                       inet_ntop(AF_INET6, &LocalAddress->Ipv6.sin6_addr, LocalInet6AddrStr, INET6_ADDRSTRLEN),
                       ntohs(LocalAddress->Ipv6.sin6_port),
                       LocalAddress->Ipv6.sin6_scope_id,
                       inet_ntop(AF_INET6, &RemoteAddress->Ipv6.sin6_addr, RemoteInet6AddrStr, INET6_ADDRSTRLEN),
                       ntohs(RemoteAddress->Ipv6.sin6_port),
                       SendContext);
        }
    }

    InterlockedIncrement(&Binding->SendOutstanding);

    Status =
        QuicDataPathBindingSend(
            Binding,
            LocalAddress,
            RemoteAddress,
            SendContext);

    SendContext = NULL;

Exit:

    if (SendContext != NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
        SendContext = NULL;
    }

    return Status;
#endif
}

static
QUIC_STATUS
QuicDataPathBindingSend(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_SOCKET_CONTEXT* SocketContext = NULL;
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = NULL;
    ssize_t SentByteCount = 0;
    size_t i = 0;
    socklen_t RemoteAddrLen = 0;
    SOCKADDR_INET MappedRemoteAddress = {0};
    struct cmsghdr *CMsg = NULL;
    struct in_pktinfo *PktInfo = NULL;
    struct in6_pktinfo *PktInfo6 = NULL;
    BOOLEAN SendPending = FALSE;

    static_assert(CMSG_SPACE(sizeof(struct in6_pktinfo)) >= CMSG_SPACE(sizeof(struct in_pktinfo)), "sizeof(struct in6_pktinfo) >= sizeof(struct in_pktinfo) failed");
    char ControlBuffer[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};

    QUIC_DBG_ASSERT(Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    SocketContext = &Binding->SocketContexts[QuicProcCurrentNumber()];
    ProcContext = &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];

    RemoteAddrLen =
        (AF_INET == RemoteAddress->si_family) ?
            sizeof(RemoteAddress->Ipv4) : sizeof(RemoteAddress->Ipv6);

    if (LocalAddress == NULL) {
        QUIC_DBG_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

        for (i = SendContext->CurrentIndex;
            i < SendContext->BufferCount;
            ++i, SendContext->CurrentIndex++) {

            SentByteCount =
                sendto(
                    SocketContext->SocketFd,
                    SendContext->Buffers[i].Buffer,
                    SendContext->Buffers[i].Length,
                    0,
                    (struct sockaddr *)RemoteAddress,
                    RemoteAddrLen);

            if (SentByteCount < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    LogVerbose("[ dal] sendto() blocked.");

                    Status =
                        QuicDataPathBindingPendSend(
                            ProcContext,
                            SocketContext,
                            SendContext,
                            LocalAddress,
                            RemoteAddress);

                    if (QUIC_FAILED(Status)) {
                        LogError("[ dal] QuicDataPathBindingPendSend failed, status: %u.", Status);
                        goto Exit;
                    }

                    SendPending = TRUE;
                    goto Exit;
                } else {
                    //
                    // Completed with error.
                    //

                    Status = errno;
                    LogError("[ dal] sendto() failed, status: %u.", Status);
                    goto Exit;
                }
            } else {
                //
                // Completed synchronously.
                //

                LogVerbose(
                    "[sock][%p] Send (%p) completion succeeded, bytes transferred %d",
                    SocketContext, SendContext, SentByteCount);
            }
        }
    } else {
        //
        // Map V4 address to dual-stack socket format.
        //

        QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        struct msghdr Mhdr = {
            .msg_name = &MappedRemoteAddress,
            .msg_namelen = sizeof(MappedRemoteAddress),
            .msg_iov = SendContext->Iovs,
            .msg_iovlen = SendContext->BufferCount,
            .msg_flags = 0
        };

        for (i = 0; i < SendContext->BufferCount; ++i) {
            QuicDataPathSendBufferInitIov(
                &SendContext->Iovs[i],
                &SendContext->Buffers[i]);
        }

        // TODO: Avoid allocating both.

        if (LocalAddress->si_family == AF_INET) {
            Mhdr.msg_control = ControlBuffer;
            Mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

            CMsg = CMSG_FIRSTHDR(&Mhdr);
            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

            PktInfo = (struct in_pktinfo*) CMSG_DATA(CMsg);
            // TODO: Use Ipv4 instead of Ipv6.
            PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;
        } else {
            Mhdr.msg_control = ControlBuffer;
            Mhdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

            CMsg = CMSG_FIRSTHDR(&Mhdr);
            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

            PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
        }

        SentByteCount = sendmsg(SocketContext->SocketFd, &Mhdr, 0);

        if (SentByteCount < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                Status =
                    QuicDataPathBindingPendSend(
                        ProcContext,
                        SocketContext,
                        SendContext,
                        LocalAddress,
                        RemoteAddress);

                if (QUIC_FAILED(Status)) {
                    LogError("[ dal] QuicDataPathBindingPendSend() failed.");
                    goto Exit;
                }

                SendPending = TRUE;
                goto Exit;
            } else {
                Status = errno;
                LogError("[ dal] sendmsg() failed, status %u.", Status);
                goto Exit;
            }
        } else {
            //
            // Completed synchronously.
            //

            LogVerbose(
                "[sock][%p] Send (%p) completion succeeded, bytes transferred %d",
                SocketContext, SendContext, SentByteCount);
        }
    }

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (!SendPending) {
        QuicSendContextComplete(
            SocketContext,
            SendContext,
            Status,
            0);
    }

    return Status;
}

uint16_t
QuicDataPathBindingGetLocalMtu(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingGetLocalMtu(Binding);
#else
    QUIC_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
#endif
}

static
void
QuicDataPathRecvComplete(
    _In_ QUIC_SOCKET_CONTEXT* SocketContext,
    _In_ ssize_t BytesTransferred
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_RECV_DATAGRAM* RecvPacket = NULL;
    PSOCKADDR_INET LocalAddr = NULL;
    PSOCKADDR_INET RemoteAddr = NULL;
    BOOLEAN FoundLocalAddr = FALSE;
    struct in6_pktinfo *PktInfo6 = NULL;
    struct in_pktinfo * PktInfo = NULL;
    struct cmsghdr *CMsg = NULL;
    char LocalInet6AddrStr[INET6_ADDRSTRLEN] = {0};
    char RemoteInet6AddrStr[INET6_ADDRSTRLEN] = {0};

    QUIC_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);

    RecvPacket = &SocketContext->CurrentRecvBlock->RecvPacket;
    SocketContext->CurrentRecvBlock = NULL;
    LocalAddr = &RecvPacket->Tuple->LocalAddress;
    RemoteAddr = &RecvPacket->Tuple->RemoteAddress;

    for (CMsg = CMSG_FIRSTHDR(&SocketContext->RecvMsgHdr);
         CMsg != NULL;
         CMsg = CMSG_NXTHDR(&SocketContext->RecvMsgHdr, CMsg)) {

        if (CMsg->cmsg_level == IPPROTO_IPV6 &&
            CMsg->cmsg_type == IPV6_PKTINFO) {
            PktInfo6 = (struct in6_pktinfo*) CMSG_DATA(CMsg);
            LocalAddr->si_family = AF_INET6;
            LocalAddr->Ipv6.sin6_addr = PktInfo6->ipi6_addr;
            LocalAddr->Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
            QuicConvertFromMappedV6(LocalAddr, LocalAddr);

            LocalAddr->Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
            FoundLocalAddr = true;
            break;

        }

        if (CMsg->cmsg_level == IPPROTO_IP && CMsg->cmsg_type == IP_PKTINFO) {
            PktInfo = (struct in_pktinfo *)CMSG_DATA(CMsg);
            LocalAddr->si_family = AF_INET;
            LocalAddr->Ipv4.sin_addr = PktInfo->ipi_addr;
            LocalAddr->Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
            LocalAddr->Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
            FoundLocalAddr = TRUE;
            break;
        }
    }

    QUIC_FRE_ASSERT(FoundLocalAddr);

    QuicConvertFromMappedV6(RemoteAddr, RemoteAddr);

    if (RemoteAddr->si_family == AF_INET) {
        LogVerbose("[sock][%p] Received [%zd] (buflen=[%" PRIu16 "]) bytes Src=[%s:%" PRIu16 "] Dst=[%s:%" PRIu16 "], bind=[%p].",
            SocketContext, BytesTransferred,
            RecvPacket->BufferLength,
            inet_ntop(AF_INET, &RemoteAddr->Ipv4.sin_addr, RemoteInet6AddrStr, INET_ADDRSTRLEN),
            ntohs(RemoteAddr->Ipv4.sin_port),
            inet_ntop(AF_INET, &LocalAddr->Ipv4.sin_addr, LocalInet6AddrStr, INET_ADDRSTRLEN),
            ntohs(LocalAddr->Ipv4.sin_port),
            SocketContext->Binding);
    } else {
        LogVerbose("[sock][%p] Received [%zd] (buflen=[%" PRIu16 "]) bytes Src=[%s:%" PRIu16 "] Dst=[%s:%" PRIu16 "%%%" PRIu32 "], bind=[%p].",
            SocketContext, BytesTransferred,
            RecvPacket->BufferLength,
            inet_ntop(AF_INET6, &RemoteAddr->Ipv6.sin6_addr, RemoteInet6AddrStr, INET6_ADDRSTRLEN),
            ntohs(RemoteAddr->Ipv6.sin6_port),
            inet_ntop(AF_INET6, &LocalAddr->Ipv6.sin6_addr, LocalInet6AddrStr, INET6_ADDRSTRLEN),
            ntohs(LocalAddr->Ipv6.sin6_port),
            LocalAddr->Ipv6.sin6_scope_id,
            SocketContext->Binding);
    }

    QUIC_DBG_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->RecvHandler);
    SocketContext->Binding->Datapath->RecvHandler(
        SocketContext->Binding,
        SocketContext->Binding->ClientContext,
        RecvPacket);

    Status = QuicDataPathBindingPrepareForReceive(SocketContext);

    //
    // Prepare can only fail under low memory condition. Treat it as a fatal
    // error.
    //

    QUIC_FRE_ASSERT(QUIC_SUCCEEDED(Status));
}

static
void*
QuicDataPathWorkerThread(
    _In_ void* Context
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*) Context;
    const size_t EpollEventCtMax = 4; // TODO: Experiment.
    struct epoll_event EpollEvents[EpollEventCtMax];
    BOOLEAN ShouldPoll = TRUE;
    ssize_t Ret = 0;
    int ErrNum = 0;
    socklen_t OptLen = 0;

    QUIC_DBG_ASSERT(ProcContext != NULL);
    QUIC_DBG_ASSERT(ProcContext->Datapath != NULL);

    while (ShouldPoll) {
        int ReadyFdCount =
            TEMP_FAILURE_RETRY(
                epoll_wait(
                    ProcContext->EpollFd,
                    EpollEvents,
                    EpollEventCtMax,
                    -1));

        QUIC_FRE_ASSERT(ReadyFdCount >= 0);
        for (int i = 0; i < ReadyFdCount; i++) {
            void* ReadyFdPtr = EpollEvents[i].data.ptr;
            if (ReadyFdPtr == &ProcContext->EventFd) {

                if (EPOLLERR & EpollEvents[i].events) {
                    LogError("[ dal] EpollEvents failed, status %u.", errno);
                    continue;
                }

                if (EPOLLIN & EpollEvents[i].events) {
                    if (ProcContext->Datapath->Shutdown) {
                        QuicDataPathHandleShutdownEvent(ProcContext);
                        ShouldPoll = FALSE;
                        break;
                    }

                    QuicDatapathHandleWorkerNotification(ProcContext);
                    continue;
                }

                QUIC_FRE_ASSERT(FALSE);
                break;

            } else {
                int SocketFd = *((int*)ReadyFdPtr);
                QUIC_SOCKET_CONTEXT* SocketContext =
                    QUIC_CONTAINING_RECORD(ReadyFdPtr, QUIC_SOCKET_CONTEXT, SocketFd);

                if (SocketContext->Binding->Shutdown) {
                    continue;
                }

                if (EPOLLIN & EpollEvents[i].events) {

                    while (TRUE) {
                        QUIC_DBG_ASSERT(SocketContext->CurrentRecvBlock != NULL);

                        Ret = recvmsg(SocketFd, &SocketContext->RecvMsgHdr, 0);

                        if (Ret < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                //
                                // Need to wait again for readiness.
                                //
                                break;
                            } else {
                                LogError("[ dal] recvmsg() failed, status %u.", errno);
                                break;
                            }
                        } else {
                            //
                            // LINUX_TODO: Handle msg_flags properly.
                            //

                            //QUIC_DBG_ASSERT(SocketContext->RecvMsgHdr.msg_flags == MSG_EOR);

                            QuicDataPathRecvComplete(SocketContext, Ret);
                        }
                    }
                } else if (EPOLLOUT & EpollEvents[i].events) {
                    QuicDataPathBindingCompletePendingSend(
                        ProcContext,
                        SocketContext);
                } else if (EPOLLERR & EpollEvents[i].events) {
                    ErrNum = 0;
                    OptLen = sizeof(ErrNum);

                    Ret = getsockopt(SocketFd, SOL_SOCKET, SO_ERROR, &ErrNum, &OptLen);
                    if (Ret < 0) {
                        LogError("[ dal] getsockopt(SO_ERROR) failed.");
                    } else {
                        LogError("[ dal] Socket event failed, status %u (%s).", ErrNum, strerror(ErrNum));
                    }

                    //
                    // Send unreachable notification to MsQuic if any related
                    // errors were received.
                    //

                    if (ErrNum == ECONNREFUSED ||
                        ErrNum == EHOSTUNREACH ||
                        ErrNum == ENETUNREACH) {
                        SocketContext->Binding->Datapath->UnreachHandler(
                            SocketContext->Binding,
                            SocketContext->Binding->ClientContext,
                            &SocketContext->Binding->RemoteAddress);
                    }
                } else {
                    QUIC_FRE_ASSERT(FALSE);
                }
            }
        }
    }

    return NO_ERROR;
}

BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
#ifdef QUIC_PLATFORM_DISPATCH_TABLE
    return PlatDispatch->DatapathBindingIsSendContextFull(SendContext);
#else
    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
#endif
}
