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

typedef enum _QUIC_DATAPATH_WORKITEM_TYPE {
    QUIC_DATAPATH_WORKITEM_TYPE_SHUTDOWN
} QUIC_DATAPATH_WORKITEM_TYPE;


//
// A datapath workitem.
//

typedef struct _QUIC_DATAPATH_WORKITEM {
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
            struct _QUIC_SOCKET_CONTEXT *SocketContext;
            QUIC_EVENT Completed;
        } Shutdown;
    };
} QUIC_DATAPATH_WORKITEM, *PQUIC_DATAPATH_WORKITEM;


//
// Datapath work queue.
//

typedef struct _QUIC_DATAPATH_WORK_QUEUE {
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

} QUIC_DATAPATH_WORK_QUEUE, *PQUIC_DATAPATH_WORK_QUEUE;


//
// A receive block to receive a UDP packet over the sockets.
//

typedef struct _QUIC_DATAPATH_RECV_BLOCK {
    //
    // The pool owning this recv block.
    //

    PQUIC_POOL OwningPool;

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

} QUIC_DATAPATH_RECV_BLOCK, *PQUIC_DATAPATH_RECV_BLOCK;


//
// Send context.
//

typedef struct _QUIC_DATAPATH_SEND_CONTEXT {
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

    struct _QUIC_DATAPATH_PROC_CONTEXT *Owner;

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

} QUIC_DATAPATH_SEND_CONTEXT, *PQUIC_DATAPATH_SEND_CONTEXT;


//
// Socket context.
//

typedef struct _QUIC_SOCKET_CONTEXT {
    //
    // The datapath binding this socket context belongs to.
    //

    PQUIC_DATAPATH_BINDING Binding;

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

    PQUIC_DATAPATH_RECV_BLOCK CurrentRecvBlock;

    //
    // The head of list containg all pending sends on this socket.
    //

    QUIC_LIST_ENTRY PendingSendContextHead;

    //
    // A pre-allocated workitem used during the shudown.
    //

    PQUIC_DATAPATH_WORKITEM ShutdownWorkitem;

} QUIC_SOCKET_CONTEXT, *PQUIC_SOCKET_CONTEXT;


//
// Datapath binding.
//

typedef struct _QUIC_DATAPATH_BINDING {
    //
    // Indicates if datapath binding is shut down.
    //

    BOOLEAN volatile Shutdown;

    //
    // A pointer to datapth object.
    //

    PQUIC_DATAPATH Datapath;

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

    LONG volatile SocketContextsOutstanding;

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

} QUIC_DATAPATH_BINDING, *PQUIC_DATAPATH_BINDING;


//
// A per proc datapath context.
//

typedef struct _QUIC_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //

    PQUIC_DATAPATH Datapath;

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

    PQUIC_THREAD EpollWaitThread;

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

} QUIC_DATAPATH_PROC_CONTEXT, *PQUIC_DATAPATH_PROC_CONTEXT;


//
// Represents a datapath object.
//

typedef struct _QUIC_DATAPATH {
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

} QUIC_DATAPATH, *PQUIC_DATAPATH;


static
QUIC_STATUS
QuicDataPathProcContextInitialize(
    _In_ PQUIC_DATAPATH Datapath,
    _Out_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    );

static
void
QuicDatapathWorkQueueInitialize(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    );

static
void
QuicDatapathWorkQueueUninitialize(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    );

static
QUIC_STATUS
QuicDatapathSocketContextOpen(
    _In_ PQUIC_DATAPATH Datapath,
    _In_ QUIC_ADDR *LocalAddress,
    _In_ QUIC_ADDR *RemoteAddress,
    _In_ uint32_t ProcIndex,
    _Out_ PQUIC_SOCKET_CONTEXT SocketContext
    );

static
QUIC_STATUS
QuicDataPathBindingStartReceive(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ int EpollFd
    );

static
QUIC_STATUS
QuicDataPathBindingPrepareForReceive(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext
    );

static
void
QuicDataPathRecvComplete(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ ssize_t NumberOfBytesTransferred
    );

static
void
QuicSendContextComplete(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext,
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
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT  ProcContext
    );

static
void*
QuicDataPathWorkerThread(
    _In_ void* Context
    );

static
void
QuicDatapathSocketContextShutdownBegin(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _Inout_ PQUIC_SOCKET_CONTEXT SocketContext
    );

static
void
QuicDatapathSocketContextShutdownEnd(
    _In_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _Inout_ PQUIC_SOCKET_CONTEXT SocketContext
    );

static
QUIC_STATUS
QuicDataPathBindingSend(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    );


static
void
QuicDatapathWorkQueueInitialize(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    )
/*++

Routine Description:

    Initializes a work queue.

Arguments:

    WorkQueue - The work queue to be initialized.

Return Value:

    None.

--*/
{
    QuicDispatchLockInitialize(&WorkQueue->Lock);

    QuicListInitializeHead(&WorkQueue->List);

    QuicPoolInitialize(FALSE, sizeof(QUIC_DATAPATH_WORKITEM), &WorkQueue->Pool);
}


static
void
QuicDatapathWorkQueueUninitialize(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    )
/*++

Routine Description:

    Uninitializes a work queue.

Arguments:

    WorkQueue - The work queue to be uninitialized.

Return Value:

    None.

--*/
{
    QUIC_FRE_ASSERT(QuicListIsEmpty(&WorkQueue->List));

    QuicDispatchLockUninitialize(&WorkQueue->Lock);

    QuicPoolUninitialize(&WorkQueue->Pool);
}


static
PQUIC_DATAPATH_WORKITEM
QuicDatapathWorkitemAlloc(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    )
/*++

Routine Description:

    Allocates a workitem from pool.

Arguments:

    WorkQueue - The work queue for which the workitem needs to be allocated.

Return Value:

    Workitem if successful, NULL otherwise.

--*/
{
    PQUIC_DATAPATH_WORKITEM Workitem = QuicPoolAlloc(&WorkQueue->Pool);

    if (Workitem == NULL) {
        LogError("DAL: Workitem allocation failure.");
    }

    return Workitem;
}


static
void
QuicDatapathWorkitemFree(
    _In_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue,
    _Inout_ PQUIC_DATAPATH_WORKITEM Workitem
    )
/*++

Routine Description:

    Frees a workitem.

Arguments:

    WorkQueue - The work queue to which the workitem belongs to.

    Workitem - The workitem to free.

Return Value:

    None.

--*/
{
    if (Workitem != NULL) {
        QuicPoolFree(&WorkQueue->Pool, Workitem);
        Workitem = NULL;
    }
}


static
void
QuicDatapathWorkQueuePush(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue,
    _Inout_ PQUIC_DATAPATH_WORKITEM Workitem
    )
/*++

Routine Description:

    Inserts a workitem into the tail of a work queue.

Arguments:

    WorkQueue - The work queue.

    Workitem - The workitem to be inserted.

Return Value:

    None.

--*/
{
    QuicDispatchLockAcquire(&WorkQueue->Lock);

    QuicListInsertTail(&WorkQueue->List, &Workitem->Link);

    QuicDispatchLockRelease(&WorkQueue->Lock);
}


static
PQUIC_DATAPATH_WORKITEM
QuicDatapathWorkQueuePop(
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    )
/*++

Routine Description:

    Pops a workitem from the head of the work queue.

Arguments:

    WorkQueue - The work queue.

Return Value:

    The poped workitem.

--*/
{
    PQUIC_DATAPATH_WORKITEM Workitem = NULL;

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
    _Inout_ PQUIC_DATAPATH_WORK_QUEUE WorkQueue
    )
/*++

Routine Description:

    Clears a work queue.

Arguments:

    WorkQueue - The work queue to be cleared.

Return Value:

    None.

--*/
{
    QUIC_LIST_ENTRY OldList = {0};
    PQUIC_DATAPATH_WORKITEM Workitem = NULL;

    QuicListInitializeHead(&OldList);

    QuicDispatchLockAcquire(&WorkQueue->Lock);

    QuicListMoveItems(&WorkQueue->List, &OldList);

    QuicDispatchLockRelease(&WorkQueue->Lock);

    while (!QuicListIsEmpty(&OldList)) {
        Workitem =
            QUIC_CONTAINING_RECORD(
                QuicListRemoveHead(&OldList),
                QUIC_DATAPATH_WORKITEM,
                Link);

        QuicDatapathWorkitemFree(WorkQueue, Workitem);
        Workitem = NULL;
    }
}


static
void
QuicDatapathNotifyEvent(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    )
/*++

Routine Description:

    Notifies the worker about a datapath proc context shutdown or about new
    workitem in the work queue.

Arguments:

    ProcContext - The proc context whose worker needs to be notified.

Return Value:

    None.

--*/
{
    const eventfd_t Value = 1;
    int Ret = 0;

    //
    // Poke the worker by writing to the event FD.
    //

    Ret = eventfd_write(ProcContext->EventFd, Value);

    if (Ret != 0) {
        LogError("DAL: Write event failure, ret %d.", Ret);
    }
}


static
void
QuicDatapathProcessWorkitem(
    _In_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _Inout_ PQUIC_DATAPATH_WORKITEM Workitem
    )
/*++

Routine Description:

    Process a workitem.

Arguments:

    ProcContext - The proc context whose workitem needs to be processed.

    Workitem - The workitem to be processed.

Return Value:

    None.

--*/
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
    }
}


void
QuicDatapathProcessWorkQueue(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    )
/*++

Routine Description:

    Processes all workitems in a work queue.

Arguments:

    ProcContext - The ProcContext whose work queue needs to be processed.

Return Value:

    None.

--*/
{
    PQUIC_DATAPATH_WORKITEM Workitem = NULL;

    Workitem = QuicDatapathWorkQueuePop(&ProcContext->WorkQueue);

    while (Workitem != NULL) {

        QuicDatapathProcessWorkitem(ProcContext, Workitem);

        QuicDatapathWorkitemFree(&ProcContext->WorkQueue, Workitem);

        Workitem = QuicDatapathWorkQueuePop(&ProcContext->WorkQueue);
    }
}


void
QuicDatapathHandleWorkerNotification(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    )
/*++

Routine Description:

    Handles notification to process all workitems in the proc context.

Arguments:

    ProcContext - The ProcContext which got notified.

Return Value:

    None.

--*/
{
    eventfd_t Value = 0;
    ssize_t ReadByteCt = 0;

    ReadByteCt = read(ProcContext->EventFd, &Value, sizeof(Value));
    QUIC_FRE_ASSERT(ReadByteCt == sizeof(Value));

    QuicDatapathProcessWorkQueue(ProcContext);
}


static
void
QuicDataPathUninitializeNotifyWorker(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    )
/*++

Routine Description:

    Notifies a per proc epoll worker about datapath shutdown.

Arguments:

    ProcContext - A pointer to Quic datapath proc context which got unitialized.

Return Value:

    None.

--*/
{
    QuicDatapathNotifyEvent(ProcContext);
}


void
QuicDataPathUninitializeWaitForWorker(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT  ProcContext
    )
/*++

Routine Description:

    Waits for a per proc worker to finish uninitialization.

Arguments:

    ProcContext - A pointer to Quic datapath proc context.

Return Value:

    None.

--*/
{
    int Thread_Ret = 0;
    int Ret = 0;

    QUIC_FRE_ASSERT(!pthread_equal(pthread_self(), ProcContext->EpollWaitThread->Thread));

    Ret = pthread_join(ProcContext->EpollWaitThread->Thread, (void **)&Thread_Ret);

    if (Ret != 0) {
        LogError("DAL: pthread_join() failed, ret %d, retval %d.", Ret, Thread_Ret);
    }

    QuicThreadDelete(ProcContext->EpollWaitThread);
    ProcContext->EpollWaitThread = NULL;
}


void
QuicDataPathHandleShutdownEvent(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    )
/*++

Routine Description:

    Handles datapath shutdown event for a proc.

Arguments:

    ProcContext - A pointer to Quic datapath proc context.

Return Value:

    None.

--*/
{
    int Ret = 0;

    Ret = epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, ProcContext->EventFd, NULL);

    if (Ret != 0) {
        LogError("DAL: epoll_ctl() failed, ret %d.", Ret);
    }

    Ret = close(ProcContext->EventFd);

    if (Ret != 0) {
        LogError("DAL: close(EventFd) failed, ret %d.", Ret);
    }

    ProcContext->EventFd = INVALID_SOCKET_FD;

    Ret = close(ProcContext->EpollFd);

    if (Ret != 0) {
        LogError("DAL: close(EpollFd) failed, ret %d.", Ret);
    }

    ProcContext->EpollFd = INVALID_SOCKET_FD;

    QuicDatapathWorkQueueClear(&ProcContext->WorkQueue);
    QuicDatapathWorkQueueUninitialize(&ProcContext->WorkQueue);
}


static
QUIC_STATUS
QuicDataPathProcContextInitialize(
    _In_ PQUIC_DATAPATH Datapath,
    _Out_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext
    )
/*++

Routine Description:

    Initializes a datapath proc context.

Arguments:

    Datapath - A pointer to quic datapath.

    ProcContext - The proc context to initilize.

Return Value:

    Status - QUIC Status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int EpollFd = INVALID_SOCKET_FD;
    int EventFd = INVALID_SOCKET_FD;
    int Ret = 0;
    UINT32 RecvPacketLength = 0;
    BOOLEAN EventFdAdded = FALSE;

    QUIC_FRE_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(QUIC_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    //
    // Initialize the receive block pool.
    //

    QuicPoolInitialize(TRUE, RecvPacketLength, &ProcContext->RecvBlockPool);

    //
    // Initialize the send buffer pool.
    //

    QuicPoolInitialize(TRUE, MAX_UDP_PAYLOAD_LENGTH, &ProcContext->SendBufferPool);

    //
    // Initialize the send context pool.
    //

    QuicPoolInitialize(
        TRUE,
        sizeof(QUIC_DATAPATH_SEND_CONTEXT),
        &ProcContext->SendContextPool);

    //
    // Initialize the work queue.
    //

    QuicDatapathWorkQueueInitialize(&ProcContext->WorkQueue);

    //
    // Create the Epoll FD.
    //

    EpollFd = epoll_create1(EPOLL_CLOEXEC);

    if (EpollFd == INVALID_SOCKET_FD) {
        Status = errno;
        LogError("DAL: epoll_create1(EPOLL_CLOEXEC) failed, status %u.", Status);
        goto Exit;
    }

    //
    // Create a event fd.
    //

    EventFd = eventfd(0, EFD_CLOEXEC);

    if (EventFd == INVALID_SOCKET_FD) {
        Status = errno;
        LogError("DAL: eventfd() failed, status %u.", Status);
        goto Exit;
    }

    struct epoll_event EvtFdEpEvt = {
        .events = EPOLLIN,
        .data = {
            .ptr = &ProcContext->EventFd
        }
    };

    //
    // Add the eventfd to the epoll FD.
    //

    Ret = epoll_ctl(EpollFd, EPOLL_CTL_ADD, EventFd, &EvtFdEpEvt);

    if (Ret != 0) {
        Status = errno;
        LogError("DAL: epoll_ctl(EPOLL_CTL_ADD) failed, status %u.", Status);
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

    Status =
        QuicThreadCreate(
            &ThreadConfig,
            &ProcContext->EpollWaitThread);

    if (QUIC_FAILED(Status)) {
        LogError("DAL: QuicThreadCreate() failed, status %u.", Status);
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {

        if (EventFdAdded) {
            Ret = epoll_ctl(EpollFd, EPOLL_CTL_DEL, EventFd, NULL);

            if (Ret != 0) {
                LogError("DAL: epoll_ctl(EPOLL_CTL_DEL) failed, ret %d.", Ret);
            }
        }

        if (EventFd != INVALID_SOCKET_FD) {
            Ret = close(EventFd);

            if (Ret != 0) {
                LogError("DAL: close(EventFd) failed, ret %d.", Ret);
            }

            EventFd = INVALID_SOCKET_FD;
        }

        if (EpollFd != INVALID_SOCKET_FD) {
            Ret = close(EpollFd);

            if (Ret != 0) {
                LogError("DAL: close(EpollFd) failed, ret %d.", Ret);
            }

            EpollFd = INVALID_SOCKET_FD;
        }

        QuicPoolUninitialize(&ProcContext->RecvBlockPool);
        QuicPoolUninitialize(&ProcContext->SendBufferPool);
        QuicPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}


QUIC_STATUS
QuicDataPathInitialize(
    _In_ UINT32 ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ PQUIC_DATAPATH *NewDataPath
    )
/*++

Routine Description:

    Allocates and initializes a datapath.

Arguments:

    ClientRecvContextLength - The client recv context size used by MsQuic.

    RecvCallback - Receive callback for MsQuic.

    UnreachableCallback - Unreachable callback for MsQuic.

    NewDataPath - Size of the client receive context used by the
        MsQuic.

    NewDataPath - The allocated datapath.

Return Value:

    Status - QUIC Status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PQUIC_DATAPATH Datapath = NULL;
    size_t DatapathLength = 0;
    uint32_t i = 0;

    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathInitialize(
                ClientRecvContextLength,
                RecvCallback,
                UnreachableCallback,
                NewDataPath);
    }

    if (RecvCallback == NULL ||
        UnreachableCallback == NULL ||
        NewDataPath == NULL) {
        LogError("DAL: Invalid parameter.");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    DatapathLength =
        sizeof(QUIC_DATAPATH) +
            QuicProcMaxCount() * sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    Datapath = (PQUIC_DATAPATH)QUIC_ALLOC_PAGED(DatapathLength);

    if (Datapath == NULL) {
        LogError("DAL: Datapath allocation failure.");
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
            LogError("DAL: QuicDataPathProcContextInitialize() failure, Status %u.", Status);

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
}


void
QuicDataPathUninitialize(
    _Inout_ PQUIC_DATAPATH Datapath
    )
/*++

Routine Description:

    Uninitializes the datapath.

Arguments:

    Datapath - A pointer to Quic datapath.

Return Value:

    None.

--*/
{
    uint32_t i = 0;

    if (PlatDispatch != NULL) {
        PlatDispatch->DatapathUninitialize(Datapath);
        return;
    }

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
}


_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ PQUIC_DATAPATH Datapath
    )
/*++

Routine Description:

    Gets supported datapath features.

Arguments:

    Datapath - A pointer to Quic datapath.

Return Value:

    Supported features.

--*/
{
    return 0;
}


QUIC_RSS_MODE
QuicDataPathGetRssMode(
    _In_ PQUIC_DATAPATH Datapath
    )
/*++

Routine Description:

    Gets RSS mode.

Arguments:

    Datapath - A pointer to Quic datapath.

Return Value:

    RSS mode.

--*/
{
    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathGetRssMode(Datapath);
    }

    return QUIC_RSS_NONE;
}


BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ PQUIC_DATAPATH Datapath
    )
/*++

Routine Description:

    Gets whether the datapath prefers UDP datagrams padded to path MTU.

Arguments:

    Datapath - A pointer to Quic datapath.

Return Value:

    TRUE if padding is preferred, FALSE otherwise.

--*/
{
    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathIsPaddingPreferred(Datapath);
    }

    //
    // The windows implementation returns TRUE only if GSO is supported and
    // this DAL implementation doesn't support GSO currently.
    //

    return FALSE;
}


void
QuicDataPathPopulateTargetAddress(
    _In_ ADDRESS_FAMILY Family,
    _In_ PADDRINFO AddrInfo,
    _Out_ SOCKADDR_INET * Address
    )
/*++

Routine Description:

    Populates the address from an addrinfo struct to a sockaddr_inet struct.

Arguments:

    Family - Address family.

    AddrInfo - The address info struct.

    Address - A pointer to the output sockaddr_inet address.

Return Value:

    None.

--*/
{
    PSOCKADDR_IN6 SockAddrIn6 = NULL;
    PSOCKADDR_IN SockAddrIn = NULL;

    QuicZeroMemory(Address, sizeof(SOCKADDR_INET));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        QUIC_FRE_ASSERT(sizeof(SOCKADDR_IN6) == AddrInfo->ai_addrlen);

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
        QUIC_FRE_ASSERT(sizeof(SOCKADDR_IN) == AddrInfo->ai_addrlen);
        SockAddrIn = (PSOCKADDR_IN)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        return;
    } else {
        QUIC_FRE_ASSERT(false);
    }
}


QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ PQUIC_DATAPATH Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    )
/*++

Routine Description:

    Resolves a hostname.

Arguments:

    Datapath - The datapath object.

    Hostname - The hostname to resolve.

    Address - The resolved address.

Return Value:

    QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    PADDRINFO AddrInfo = NULL;
    int Result = 0;

    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathResolveAddress(Datapath, HostName, Address);
    }

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

    LogWarning("DAL: getaddrinfo(AI_NUMERICHOST) failed, result %d.", Result);

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

    LogError("DAL: getaddrinfo(AI_CANONNAME) failed, result %d.", Result);

    Status = QUIC_STATUS_DNS_RESOLUTION_ERROR;

Exit:

    return Status;
}


static
QUIC_STATUS
QuicDatapathSocketContextOpen(
    _In_ PQUIC_DATAPATH Datapath,
    _In_ QUIC_ADDR * LocalAddress,
    _In_ QUIC_ADDR * RemoteAddress,
    _In_ uint32_t ProcIndex,
    _Out_ PQUIC_SOCKET_CONTEXT SocketContext
    )
/*++

Routine Description:

    Opens a socket context.

Arguments:

    LocalAddress - The local address.

    RemoteAddress - The remote address.

    ProcIndex - The proc index whose socket context needs to be created.

    SocketContext - The created socket context.

Return Value:

    Status - QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PQUIC_DATAPATH_BINDING Binding = SocketContext->Binding;
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
        LogError("DAL: socket() failed, status %u.", Status);
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
        LogError("DAL: setsockopt(IPV6_V6ONLY) failed, status %u.", Status);
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
        LogError("DAL: setsockopt(IP_MTU_DISCOVER) failed, status %u.", Status);
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
        LogError("DAL: setsockopt(IPV6_DONTFRAG) failed, status %u.", Status);
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
        LogError("DAL: setsockopt(IPV6_RECVPKTINFO) failed, status %u.", Status);
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
        LogError("DAL: setsockopt(IP_PKTINFO) failed, status %u.", Status);
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
        LogError("DAL: setsockopt(SO_RCVBUF) failed, status %u.", Status);
        goto Exit;
    }

    Result =
        bind(
            SocketContext->SocketFd,
            (const struct sockaddr *)&Binding->LocalAddress,
            sizeof(Binding->LocalAddress));

    if (Result == SOCKET_ERROR) {
        Status = errno;
        LogError("DAL: bind() failed, status %u.", Status);
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
            LogError("DAL: connect() failed, status %u.", Status);
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
        LogError("DAL: getsockname() failed, status %u.", Status);
        goto Exit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_FRE_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    SocketContext->ShutdownWorkitem =
        QuicDatapathWorkitemAlloc(&Datapath->ProcContexts[ProcIndex].WorkQueue);

    if (SocketContext->ShutdownWorkitem == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        LogError("DAL: ShutdownWorkitem allocation failed.");
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {
        Result = close(SocketContext->SocketFd);

        if (Result != 0)
        {
            LogError("DAL: close() failed, err: %d.", errno);
        }

        SocketContext->SocketFd = INVALID_SOCKET_FD;
    }

    return Status;
}



QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ PQUIC_DATAPATH Datapath,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ PQUIC_DATAPATH_BINDING* NewBinding
    )
/*++

Routine Description:

    Creates datapath binding.

Arguments:

    Datapath - The datapath to create binding for.

    LocalAddress - The local address to bind to.

    RemoteAddress - The remote address to send to.

    RecvCallbackContext - The callback context to be passed in the receive'
        callback.

    NewBinding -  Returns the new binding.

Return Value:

    Status - QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PQUIC_DATAPATH_BINDING Binding = NULL;
    int Result = 0;
    int Option = 0;
    uint32_t i = 0;
    PQUIC_SOCKET_CONTEXT SocketContext = NULL;
    size_t BindingLength = 0;

    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingCreate(
                Datapath,
                LocalAddress,
                RemoteAddress,
                RecvCallbackContext,
                NewBinding);
    }

    BindingLength = sizeof(QUIC_DATAPATH_BINDING) +
            Datapath->ProcCount * sizeof(QUIC_SOCKET_CONTEXT);

    Binding = (PQUIC_DATAPATH_BINDING)QUIC_ALLOC_PAGED(BindingLength);

    if (Binding == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        LogError("DAL: Binding allocation failed");
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

            LogError("DAL: QuicDatapathSocketContextOpen failed, status:%u", Status);
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

            LogError("DAL: QuicDataPathBindingStartReceive() failed, status:%u", Status);
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
}


static
void
QuicDatapathSocketContextShutdownBegin(
    _Inout_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _Inout_ PQUIC_SOCKET_CONTEXT SocketContext
    )
/*++

Routine Description:

    Begins the shutdown of a socket context.

Arguments:

    ProcContext - The proc context whose socketcontext needs to shutdown.

    SocketContext - The socketcontext to shutdown.

Return Value:

    None.

--*/
{
    QUIC_EVENT Completed = {0};
    PQUIC_DATAPATH_WORKITEM Workitem = NULL;

    //
    // Queue a workitem to cleanup the socket context. It is important to not do
    // this inline because binding delete can get called in context of a receive
    // from the epoll thread and the unwind path might have references to the
    // socket context so it shouldn't be freed here.
    //

    QUIC_FRE_ASSERT(SocketContext->ShutdownWorkitem != NULL);

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
    _In_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _Inout_ PQUIC_SOCKET_CONTEXT SocketContext
    )
/*++

Routine Description:

    Ends the shutdown of a socket context.

Arguments:

    ProcContext - The proc context whose socketcontext needs to shutdown.

    SocketContext - The socketcontext to shutdown.

Return Value:

    None.

--*/
{
    int Ret = 0;
    PQUIC_DATAPATH_SEND_CONTEXT SendContext = NULL;

    Ret = epoll_ctl(ProcContext->EpollFd, EPOLL_CTL_DEL, SocketContext->SocketFd, NULL);

    if (Ret != 0)
    {
        LogError("DAL: epoll_ctl() failed, ret %d.", Ret);
    }

    Ret = close(SocketContext->SocketFd);

    if (Ret != 0)
    {
        LogError("DAL: close() failed, ret %d.", Ret);
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
    _Inout_ PQUIC_DATAPATH_BINDING Binding
    )
/*++

Routine Description:

    Deletes datapath binding.

Arguments:

    Binding - The binding to be deleted.

Return Value:

    None.

--*/
{
    PQUIC_DATAPATH Datapath = NULL;
    uint32_t i = 0;

    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathBindingDelete(Binding);
    }

    QUIC_FRE_ASSERT(Binding != NULL);

    Datapath = Binding->Datapath;
    Binding->Shutdown = true;

    for (i = 0; i < Datapath->ProcCount; ++i) {
        QuicDatapathSocketContextShutdownBegin(
            &Datapath->ProcContexts[i],
            &Binding->SocketContexts[i]);
    }
}


PQUIC_DATAPATH_RECV_BLOCK
QuicDataPathAllocRecvBlock(
    _In_ PQUIC_DATAPATH Datapath,
    _In_ uint32_t ProcIndex
    )
/*++

Routine Description:

    Allocates a recv block.

Arguments:

    Datapath - The datapath to allocate recv block for.

    ProcIndex - The proc index to allocated recv block.

Return Value:

    Recv block if successful, NULL if unsuccessful.

--*/
{
    PQUIC_DATAPATH_RECV_BLOCK RecvBlock =
        QuicPoolAlloc(&Datapath->ProcContexts[ProcIndex].RecvBlockPool);

    if (RecvBlock == NULL) {
        LogError("DAL: RecvBlock allocation failed.");
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
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _Out_ QUIC_ADDR * Address
    )
/*++

Routine Description:

    Gets the local address for a binding.

Arguments:

    Binding - The datapath binding object.

    Address - Returns the local address.

Return Value:

    None.

--*/
{
    if (PlatDispatch != NULL) {
        PlatDispatch->DatapathBindingGetLocalAddress(Binding, Address);
        return;
    }

    QUIC_FRE_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
}


void
QuicDataPathBindingGetRemoteAddress(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _Out_ QUIC_ADDR * Address
    )
/*++

Routine Description:

    Gets the remote address for a binding.

Arguments:

    Binding - The datapath binding object.

    Address - Returns the remote address.

Return Value:

    None.

--*/
{
    if (PlatDispatch != NULL) {
        PlatDispatch->DatapathBindingGetRemoteAddress(Binding, Address);
        return;
    }

    QUIC_FRE_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
}


QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
/*++

Routine Description:

    Sets a parameter on a binding.

Arguments:

    Binding - The datapath binding object.

    Param - The param to set.

    BufferLength - The buffer length of param value.

    Buffer - The buffer containing param value.

Return Value:

    QUIC status.

--*/
{
    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingSetParam(
                Binding,
                Param,
                BufferLength,
                Buffer);
    }

    return QUIC_STATUS_NOT_SUPPORTED;
}


QUIC_STATUS
QuicDataPathBindingGetParam(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
/*++

Routine Description:

    Gets a parameter on a binding.

Arguments:

    Binding - The datapath binding object.

    Param - The param to set.

    BufferLength - The buffer length of param value.

    Buffer - The buffer containing param value.

Return Value:

    QUIC status.

--*/
{
    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingGetParam(
                Binding,
                Param,
                BufferLength,
                Buffer);
    }

    return QUIC_STATUS_NOT_SUPPORTED;
}


QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const RecvContext
    )

/*++

Routine Description:

    Gets the receive buffer from the receive context.

Arguments:

    RecvContext - The receive context.

Return Value:

    Receive buffer.

--*/
{
    PQUIC_DATAPATH_RECV_BLOCK RecvBlock = NULL;

    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathRecvContextToRecvPacket(RecvContext);
    }

    RecvBlock =
        (PQUIC_DATAPATH_RECV_BLOCK)
            ((char *)RecvContext - sizeof(QUIC_DATAPATH_RECV_BLOCK));

    return &RecvBlock->RecvPacket;
}


QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const RecvPacket
    )
/*++

Routine Description:

    Gets the receive context from the receive buffer.

Arguments:

    RecvPacket - The receive buffer.

Return Value:

    Receive context.

--*/
{
    PQUIC_DATAPATH_RECV_BLOCK RecvBlock = NULL;

    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathRecvPacketToRecvContext(RecvPacket);
    }

    RecvBlock =
        QUIC_CONTAINING_RECORD(RecvPacket, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

    return (QUIC_RECV_PACKET*)(RecvBlock + 1);
}


void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* RecvPacket
    )
/*++

Routine Description:

    Returns the receive buffer to DAL.

Arguments:

    RecvPacket - The receive buffer.

Return Value:

    None.

--*/
{
    PQUIC_DATAPATH_RECV_BLOCK RecvBlock = NULL;

    if (RecvPacket == NULL) {
        return;
    }

    if (PlatDispatch != NULL) {
        PlatDispatch->DatapathBindingReturnRecvPacket(RecvPacket);
        return;
    }

    RecvBlock =
        QUIC_CONTAINING_RECORD(RecvPacket, QUIC_DATAPATH_RECV_BLOCK, RecvPacket);

    QuicPoolFree(RecvBlock->OwningPool, RecvBlock);

    RecvBlock = NULL;
}


static
QUIC_STATUS
QuicDataPathBindingPrepareForReceive(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext
    )
/*++

Routine Description:

    Prepares a socket context for receive.

Arguments:

    SocketContext - The socket context.

Return Value:

    QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (SocketContext->CurrentRecvBlock == NULL) {
        SocketContext->CurrentRecvBlock =
            QuicDataPathAllocRecvBlock(
                SocketContext->Binding->Datapath,
                QuicProcCurrentNumber());

        if (SocketContext->CurrentRecvBlock == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            LogError("DAL: Recv block allocation failed.");
            goto Error;
        }
    }

    SocketContext->RecvIov.iov_base = SocketContext->CurrentRecvBlock->RecvPacket.Buffer;
    SocketContext->CurrentRecvBlock->RecvPacket.BufferLength = SocketContext->RecvIov.iov_len;
    SocketContext->CurrentRecvBlock->RecvPacket.Tuple = (PQUIC_TUPLE)&SocketContext->CurrentRecvBlock->Tuple;

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
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ int EpollFd
    )
/*++

Routine Description:

    Start receives on a socket context.

Arguments:

    SocketContext - The socket context to start receive on.

    EpollFd - The epoll FD.

Return Value:

    QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;

    Status = QuicDataPathBindingPrepareForReceive(SocketContext);

    if (QUIC_FAILED(Status)) {
        LogError("DAL: QuicDataPathBindingPrepareForReceive() failed, status %u.", Status);
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
        LogError("DAL: epoll_ctl() failed, status %u.", Status);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        Ret = close(SocketContext->SocketFd);

        if (Ret != 0) {
            LogError("DAL: close() failed, status %u.", Status);
        }
    }

    return Status;
}


static
QUIC_STATUS
QuicDataPathBindingPendSend(
    _In_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext,
    _In_ const QUIC_ADDR *LocalAddress,
    _In_ const QUIC_ADDR *RemoteAddress
    )
/*++

Routine Description:

    Pends sends until the socket context is writeable.

Arguments:

    ProcContext - The proc context.

    SocketContext - The socket context to wait on.

    SendContext - The send context.

    LocalAddress - The local address to use for send.

    RemoteAddress - The remote address to send to.

Return Value:

    QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    struct epoll_event SockFdEpEvt = {0};

    LogInfo("DAL: Pending sends");

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
            LogError("DAL: epoll_ctl() failed, status %u.", Status);
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

    QUIC_FRE_ASSERT(SocketContext->SendWaiting);

    Status = QUIC_STATUS_SUCCESS;

Exit:

    return Status;
}


static
QUIC_STATUS
QuicDataPathBindingCompletePendingSend(
    _In_ PQUIC_DATAPATH_PROC_CONTEXT ProcContext,
    _In_ PQUIC_SOCKET_CONTEXT SocketContext
    )
/*++

Routine Description:

    Pends sends until the socket context is writeable.

Arguments:

    ProcContext - The proc context.

    SocketContext - The socket context to wait on.

Return Value:

    QUIC status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    struct epoll_event SockFdEpEvt = {0};
    PQUIC_DATAPATH_SEND_CONTEXT SendContext = NULL;

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
            LogError("DAL: epoll_ctl() failed, status %u.", Status);
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
            LogError("DAL: QuicDataPathBindingSend() failed, status %u.", Status);
        }

        if (SocketContext->SendWaiting) {
            break;
        }
    }

Exit:

    return Status;
}


PQUIC_DATAPATH_SEND_CONTEXT
QuicDataPathBindingAllocSendContext(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ uint16_t MaxPacketSize
    )
/*++

Routine Description:

    Allocates a send context.

Arguments:

    Binding - The datapath binding.

    MaxPacketSize - Max send packet size.

Return Value:

    SendContext if successful, NULL otherwise.

--*/
{
    PQUIC_DATAPATH_SEND_CONTEXT SendContext = NULL;
    PQUIC_DATAPATH_PROC_CONTEXT ProcContext = NULL;

    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingAllocSendContext(
                Binding,
                MaxPacketSize);
    }

    QUIC_FRE_ASSERT(Binding != NULL);

    ProcContext = &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];

    SendContext = QuicPoolAlloc(&ProcContext->SendContextPool);

    if (SendContext == NULL) {
        LogError("DAL: QuicPoolAlloc() failed.");
        goto Exit;
    }

    QuicZeroMemory(SendContext, sizeof(*SendContext));

    SendContext->Owner = ProcContext;

Exit:

    return SendContext;
}


void
QuicDataPathBindingFreeSendContext(
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    )
/*++

Routine Description:

    Frees a send context.

Arguments:

    SendContext - The send context to be freed.

Return Value:

    None.

--*/
{
    size_t i = 0;

    if (PlatDispatch != NULL) {
        PlatDispatch->DatapathBindingFreeSendContext(SendContext);
        return;
    }

    for (i = 0; i < SendContext->BufferCount; ++i) {
        QuicPoolFree(
            &SendContext->Owner->SendBufferPool,
            SendContext->Buffers[i].Buffer);
        SendContext->Buffers[i].Buffer = NULL;
    }

    QuicPoolFree(&SendContext->Owner->SendContextPool, SendContext);
    SendContext = NULL;
}


static
void
QuicDataPathSendBufferInitIov(
    _Inout_ struct iovec *Iov,
    _In_ QUIC_BUFFER* Buffer
    )
/*++

Routine Description:

    Inits IO vector for a send.

Arguments:

    Iov - The IO vector to initialize.

    Buffer - The QUIC buffer to be used for send.

Return Value:

    None.

--*/
{
    Iov->iov_base = Buffer->Buffer;
    Iov->iov_len = Buffer->Length;
}


QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext,
    _In_ uint16_t MaxBufferLength
    )
/*++

Routine Description:

    Allocates a send buffer.

Arguments:

    SendContext - The send context for which buffer needs to be allocated.

    MaxBufferLength - Max buffer length required.

Return Value:

    Send buffer if successful, NULL otherwise.

--*/
{
    QUIC_BUFFER* Buffer = NULL;

    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingAllocSendBuffer(
                SendContext,
                MaxBufferLength);
    }

    QUIC_FRE_ASSERT(SendContext != NULL);
    QUIC_FRE_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    if (SendContext->BufferCount ==
            SendContext->Owner->Datapath->MaxSendBatchSize) {
        LogError("DAL: Max batch size limit hit.");
        goto Exit;
    }

    Buffer = &SendContext->Buffers[SendContext->BufferCount];
    QuicZeroMemory(Buffer, sizeof(*Buffer));

    Buffer->Buffer = QuicPoolAlloc(&SendContext->Owner->SendBufferPool);

    if (Buffer->Buffer == NULL) {
        LogError("DAL: Send buffer allocation failed.");
        goto Exit;
    }

    Buffer->Length = MaxBufferLength;

    QuicDataPathSendBufferInitIov(
        &SendContext->Iovs[SendContext->BufferCount],
        Buffer);

    ++SendContext->BufferCount;

Exit:

    return Buffer;
}


void
QuicDataPathBindingFreeSendDatagram(
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
/*++

Routine Description:

    Frees a send buffer.

Arguments:

    SendContext - The send context for which buffer needs to be free.

    Datagram - Datagram buffer to be freed.

Return Value:

    None.

--*/
{
    if (PlatDispatch != NULL) {
        PlatDispatch->DatapathBindingFreeSendBuffer(SendContext, Datagram);
        return;
    }

    QuicPoolFree(&SendContext->Owner->SendBufferPool, Datagram->Buffer);
    Datagram->Buffer == NULL;

    QUIC_FRE_ASSERT(Datagram == &SendContext->Buffers[SendContext->BufferCount - 1]);

    --SendContext->BufferCount;
}


static
void
QuicSendContextComplete(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext,
    _In_ int IoResult,
    _In_ int SentByteCount
    )
/*++

Routine Description:

    Completes and frees a send context.

Arguments:

    SocketContext - The socketcontext to which the sendcontext belongs.

    SendContext - The send context which needs to be completed.

    IoResult - The IO result.

    SentByteCount - Number of bytes sent.

Return Value:

    None.

--*/
{
    if (IoResult != QUIC_STATUS_SUCCESS) {
        LogWarning(
            "DAL: [sock][%p] Send (%p) completion failed, 0x%x",
            SocketContext, SendContext, IoResult);
    }

    QuicDataPathBindingFreeSendContext(SendContext);

    InterlockedDecrement(&SocketContext->Binding->SendOutstanding);
}


QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    )
/*++

Routine Description:

    Sends QUIC packets to a remote address.

Arguments:

    Binding - The dapath binding.

    RemoteAddress - The remote address to send.

    SendContext - The send context.

Return Value:

    Quic status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    socklen_t RemoteAddrLen = 0;
    size_t i = 0;
    PQUIC_SOCKET_CONTEXT SocketContext = NULL;
    char Inet6AddrStr[INET6_ADDRSTRLEN] = {0};

    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingSendTo(
                Binding,
                RemoteAddress,
                SendContext);
    }

    SocketContext = &Binding->SocketContexts[QuicProcCurrentNumber()];

    QUIC_FRE_ASSERT(
        Binding != NULL &&
        RemoteAddress != NULL &&
        SendContext != NULL);

    for (i = 0; i < SendContext->BufferCount; ++i) {
        if (RemoteAddress->si_family == AF_INET) {
            LogVerbose("DAL: [sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Dst=[%s:%" PRIu16 "] (%p)",
                       SocketContext,
                       SocketContext->SocketFd,
                       SendContext->Buffers[i].Length,
                       inet_ntop(AF_INET, &RemoteAddress->Ipv4.sin_addr, Inet6AddrStr, INET_ADDRSTRLEN),
                       ntohs(RemoteAddress->Ipv4.sin_port),
                       SendContext);
        } else {
            LogVerbose("DAL: [sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Dst=[%s:%" PRIu16 "] (%p)",
                       SocketContext,
                       SocketContext->SocketFd,
                       SendContext->Buffers[i].Length,
                       inet_ntop(AF_INET6, &RemoteAddress->Ipv6.sin6_addr, Inet6AddrStr, INET6_ADDRSTRLEN),
                       ntohs(RemoteAddress->Ipv6.sin6_port),
                       SendContext);
        }
    }

    InterlockedIncrement(&Binding->SendOutstanding);

    QUIC_FRE_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

    Status =
        QuicDataPathBindingSend(
            Binding,
            NULL,
            RemoteAddress,
            SendContext);

    SendContext = NULL;

    if (QUIC_FAILED(Status)) {
        LogError("DAL: QuicDataPathBindingSend failed, status: %u.", Status);
        goto Exit;
    }

Exit:

    if (SendContext != NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
        SendContext = NULL;
    }

    return Status;
}


QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    )
/*++

Routine Description:

    Sends QUIC packets from a local address to a remote address.

Arguments:

    Binding - The dapath binding.

    LocalAddress - The local address to use to send from.

    RemoteAddress - The remote address to send to.

    SendContext - The send context.

Return Value:

    Quic status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    char LocalInet6AddrStr[INET6_ADDRSTRLEN] = {0};
    char RemoteInet6AddrStr[INET6_ADDRSTRLEN] = {0};
    PQUIC_SOCKET_CONTEXT SocketContext = NULL;

    if (PlatDispatch != NULL) {
        return
            PlatDispatch->DatapathBindingSendFromTo(
                Binding,
                LocalAddress,
                RemoteAddress,
                SendContext);
    }

    QUIC_FRE_ASSERT(
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
            LogVerbose("DAL: [sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Src=[%s:%" PRIu16 "%%%" PRIu32 "] Dst=[%s:%" PRIu16 "] (%p)",
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
            LogVerbose("DAL: [sock][%p] SocketFd=[%d], sending %" PRIu32 " bytes Src=[%s:%" PRIu16 "%%%" PRIu32 "] Dst=[%s:%" PRIu16 "] (%p)",
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
}


static
QUIC_STATUS
QuicDataPathBindingSend(
    _In_ PQUIC_DATAPATH_BINDING Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    )
/*++

Routine Description:

    Sends QUIC packets to a remote address.

Arguments:

    Binding - The dapath binding.

    RemoteAddress - The remote address to send.

    SendContext - The send context.

Return Value:

    Quic status.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PQUIC_SOCKET_CONTEXT SocketContext = NULL;
    PQUIC_DATAPATH_PROC_CONTEXT ProcContext = NULL;
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

    QUIC_FRE_ASSERT(Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    SocketContext = &Binding->SocketContexts[QuicProcCurrentNumber()];
    ProcContext = &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];

    RemoteAddrLen =
        (AF_INET == RemoteAddress->si_family) ?
            sizeof(RemoteAddress->Ipv4) : sizeof(RemoteAddress->Ipv6);

    if (LocalAddress == NULL) {
        QUIC_FRE_ASSERT(Binding->RemoteAddress.Ipv4.sin_port != 0);

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
                    LogVerbose("DAL: sendto() blocked.");

                    Status =
                        QuicDataPathBindingPendSend(
                            ProcContext,
                            SocketContext,
                            SendContext,
                            LocalAddress,
                            RemoteAddress);

                    if (QUIC_FAILED(Status)) {
                        LogError("DAL: QuicDataPathBindingPendSend failed, status: %u.", Status);
                        goto Exit;
                    }

                    SendPending = TRUE;
                    goto Exit;
                } else {
                    //
                    // Completed with error.
                    //

                    Status = errno;
                    LogError("DAL: sendto() failed, status: %u.", Status);
                    goto Exit;
                }
            } else {
                //
                // Completed synchronously.
                //

                LogVerbose(
                    "DAL:  [sock][%p] Send (%p) completion succeeded, bytes transferred %d",
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
                    LogError("DAL: QuicDataPathBindingPendSend() failed.");
                    goto Exit;
                }

                SendPending = TRUE;
                goto Exit;
            } else {
                Status = errno;
                LogError("DAL: sendmsg() failed, status %u.", Status);
                goto Exit;
            }
        } else {
            //
            // Completed synchronously.
            //

            LogVerbose(
                "DAL:  [sock][%p] Send (%p) completion succeeded, bytes transferred %d",
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
    _In_ PQUIC_DATAPATH_BINDING Binding
    )
/*++

Routine Description:

    Gets the local MTU got a datapath binding.

Arguments:

    Binding - The datapath binding.

Return Value:

    Returns the MTU.

--*/
{
    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathBindingGetLocalMtu(Binding);
    }

    QUIC_FRE_ASSERT(Binding != NULL);
    return Binding->Mtu;
}


static
void
QuicDataPathRecvComplete(
    _In_ PQUIC_SOCKET_CONTEXT SocketContext,
    _In_ ssize_t BytesTransferred
    )
/*++

Routine Description:

    Completes a receive.

Arguments:

    QuicDataPathRecvComplete - The socket context used for receive.

    BytesTransferred - The bytes transferred.

Return Value:

    QUIC status.

--*/
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

    QUIC_FRE_ASSERT(SocketContext->CurrentRecvBlock != NULL);

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
        LogVerbose("DAL: [sock][%p] Received [%zd] (buflen=[%" PRIu16 "]) bytes Src=[%s:%" PRIu16 "] Dst=[%s:%" PRIu16 "], bind=[%p].",
                   SocketContext, BytesTransferred,
                   RecvPacket->BufferLength,
                   inet_ntop(AF_INET, &RemoteAddr->Ipv4.sin_addr, RemoteInet6AddrStr, INET_ADDRSTRLEN),
                   ntohs(RemoteAddr->Ipv4.sin_port),
                   inet_ntop(AF_INET, &LocalAddr->Ipv4.sin_addr, LocalInet6AddrStr, INET_ADDRSTRLEN),
                   ntohs(LocalAddr->Ipv4.sin_port),
                   SocketContext->Binding);
    } else {
        LogVerbose("DAL: [sock][%p] Received [%zd] (buflen=[%" PRIu16 "]) bytes Src=[%s:%" PRIu16 "] Dst=[%s:%" PRIu16 "%%%" PRIu32 "], bind=[%p].",
                   SocketContext, BytesTransferred,
                   RecvPacket->BufferLength,
                   inet_ntop(AF_INET6, &RemoteAddr->Ipv6.sin6_addr, RemoteInet6AddrStr, INET6_ADDRSTRLEN),
                   ntohs(RemoteAddr->Ipv6.sin6_port),
                   inet_ntop(AF_INET6, &LocalAddr->Ipv6.sin6_addr, LocalInet6AddrStr, INET6_ADDRSTRLEN),
                   ntohs(LocalAddr->Ipv6.sin6_port),
                   LocalAddr->Ipv6.sin6_scope_id,
                   SocketContext->Binding);
    }

    QUIC_FRE_ASSERT(BytesTransferred <= RecvPacket->BufferLength);
    RecvPacket->BufferLength = BytesTransferred;

    QUIC_FRE_ASSERT(SocketContext->Binding->Datapath->RecvHandler);
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
/*++

Routine Description:

    Worker thread routine.

Arguments:

    Context - The proc context.

Return Value:

    None.

--*/
{
    PQUIC_DATAPATH_PROC_CONTEXT ProcContext = (PQUIC_DATAPATH_PROC_CONTEXT) Context;
    const size_t EpollEventCtMax = 4; // TODO: Experiment.
    struct epoll_event EpollEvents[EpollEventCtMax];
    BOOLEAN ShouldPoll = TRUE;
    int ReadyFdCount = 0;
    int i = 0;
    void* ReadyFdPtr = NULL;
    int SocketFd = 0;
    ssize_t Ret = 0;
    PQUIC_SOCKET_CONTEXT SocketContext = NULL;
    int ErrNum = 0;
    socklen_t OptLen = 0;

    QUIC_FRE_ASSERT(ProcContext != NULL);
    QUIC_FRE_ASSERT(ProcContext->Datapath != NULL);

    while (ShouldPoll) {
        ReadyFdCount =
            TEMP_FAILURE_RETRY(
                epoll_wait(
                    ProcContext->EpollFd,
                    EpollEvents,
                    EpollEventCtMax,
                    -1));

        if (ReadyFdCount < 0) {
            LogError("DAL: epoll_wait() failed, status %u.", errno);

            //
            // Treat this as a fatal error.
            //

            QUIC_FRE_ASSERT((FALSE));
            break;
        }

        for (i = 0; i < ReadyFdCount; i++) {
            ReadyFdPtr = EpollEvents[i].data.ptr;

            if (ReadyFdPtr == &ProcContext->EventFd) {

                if (EPOLLERR & EpollEvents[i].events) {
                    LogError("DAL: EpollEvents failed, status %u.", errno);
                    continue;
                }

                if (EPOLLIN & EpollEvents[i].events) {
                    if (ProcContext->Datapath->Shutdown) {
                        QuicDataPathHandleShutdownEvent(ProcContext);
                        ShouldPoll = (FALSE);
                        break;
                    }

                    QuicDatapathHandleWorkerNotification(ProcContext);
                    continue;
                }

                QUIC_FRE_ASSERT((FALSE));
                break;

            } else {
                SocketFd = *((int*)ReadyFdPtr);
                SocketContext = QUIC_CONTAINING_RECORD(ReadyFdPtr, QUIC_SOCKET_CONTEXT, SocketFd);

                if (SocketContext->Binding->Shutdown) {
                    continue;
                }

                if (EPOLLIN & EpollEvents[i].events) {

                    while (TRUE) {
                        QUIC_FRE_ASSERT(SocketContext->CurrentRecvBlock != NULL);

                        Ret = recvmsg(SocketFd, &SocketContext->RecvMsgHdr, 0);

                        if (Ret < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                //
                                // Need to wait again for readiness.
                                //
                                break;
                            } else {
                                LogError("DAL: recvmsg() failed, status %u.", errno);
                                break;
                            }
                        } else {
                            //
                            // LINUX_TODO: Handle msg_flags properly.
                            //

                            //QUIC_FRE_ASSERT(SocketContext->RecvMsgHdr.msg_flags == MSG_EOR);

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
                        LogError("DAL: getsockopt(SO_ERROR) failed.");
                    } else {
                        LogError("DAL: Socket event failed, status %u(%s).", ErrNum, strerror(ErrNum));
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
    _In_ PQUIC_DATAPATH_SEND_CONTEXT SendContext
    )
/*++

Routine Description:

    Checks if send context buffer is full.

Arguments:

    SendContext - The send context to check for.

Return Value:

    TRUE if full, FALSE otherwise .

--*/
{
    if (PlatDispatch != NULL) {
        return PlatDispatch->DatapathBindingIsSendContextFull(SendContext);
    }

    return SendContext->BufferCount == SendContext->Owner->Datapath->MaxSendBatchSize;
}

