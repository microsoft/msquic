/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC datapath Abstraction Layer.

Environment:

    Darwin

--*/

#include "platform_internal.h"
#include "quic_platform_dispatch.h"

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/time.h>

#define QUIC_MAX_BATCH_SEND                 10

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
    // TODO: Better way to reconcile layout difference
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
    // The cleanup event FD used by this socket context.
    //
    int CleanupFd;

    //
    // Used to register different event FD with epoll.
    //
#define QUIC_SOCK_EVENT_CLEANUP 0
#define QUIC_SOCK_EVENT_SOCKET  1
    uint8_t EventContexts[2];

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

} QUIC_SOCKET_CONTEXT;

//
// Datapath binding.
//
typedef struct QUIC_DATAPATH_BINDING {

    //
    // A pointer to datapath object.
    //
    QUIC_DATAPATH* Datapath;

    //
    // The client context for this binding.
    //
    void *ClientContext;

    //
    // The local address for the binding.
    //
    QUIC_ADDR LocalAddress;

    //
    //  The remote address for the binding.
    //
    QUIC_ADDR RemoteAddress;

    //
    // Synchronization mechanism for cleanup.
    //
    QUIC_RUNDOWN_REF Rundown;

    //
    // Indicates the binding connected to a remote IP address.
    //
    BOOLEAN Connected : 1;

    //
    // Indicates the binding is shut down.
    //
    BOOLEAN Shutdown : 1;

    //
    // The MTU for this binding.
    //
    uint16_t Mtu;

    //
    // Set of socket contexts one per proc.
    //
    QUIC_SOCKET_CONTEXT SocketContexts[];

} QUIC_DATAPATH_BINDING;

//
// A per processor datapath context.
//
typedef struct QUIC_DATAPATH_PROC_CONTEXT {

    //
    // A pointer to the datapath.
    //
    QUIC_DATAPATH* Datapath;

    //
    // The Kqueue FD for this proc context.
    //
    int KqueueFd;

    //
    // The index of the context in the datapath's array.
    //
    uint32_t Index;

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
    // TODO: See how send batching can be enabled.
    //
    uint8_t MaxSendBatchSize;

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
    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableHandler;

    //
    // The length of recv context used by MsQuic.
    //
    size_t ClientRecvContextLength;

    //
    // The proc count to create per proc datapath state.
    //
    uint32_t ProcCount;

    //
    // The per proc datapath contexts.
    //
    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[];

} QUIC_DATAPATH;

//
// Gets the corresponding recv datagram from its context pointer.
//
QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const Packet
    ) {
    QUIC_FRE_ASSERT(FALSE);
    return NULL;
}

//
// Gets the corresponding client context from its recv datagram pointer.
//
QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const Datagram
    ) {
    QUIC_FRE_ASSERT(FALSE);
    return NULL;
}

uint32_t QuicGetNumLogicalCores(void) {
    int num_cores = 0;
    size_t param_size = sizeof(num_cores);
    QUIC_FRE_ASSERT(sysctlbyname("hw.logicalcpu", &num_cores, &param_size, NULL, 0) == 0);
    return num_cores;
}

void*
QuicDataPathWorkerThread(
    _In_ void* Context
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = (QUIC_DATAPATH_PROC_CONTEXT*)Context;
    QUIC_DBG_ASSERT(ProcContext != NULL && ProcContext->Datapath != NULL);

    while (!ProcContext->Datapath->Shutdown) {
        //for (int i = 0; i < ReadyEventCount; i++) {
        //    if (EpollEvents[i].data.ptr == NULL) {
        //        //
        //        // The processor context is shutting down and the worker thread
        //        // needs to clean up.
        //        //
        //        QUIC_DBG_ASSERT(ProcContext->Datapath->Shutdown);
        //        break;
        //    }

        //    QuicSocketContextProcessEvents(
        //        EpollEvents[i].data.ptr,
        //        ProcContext,
        //        EpollEvents[i].events);
        //}
    }

    return NO_ERROR;
}

QUIC_STATUS
QuicProcessorContextInitialize(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ uint32_t Index,
    _Out_ QUIC_DATAPATH_PROC_CONTEXT* ProcContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    uint32_t RecvPacketLength = 0;

    QUIC_DBG_ASSERT(Datapath != NULL);

    RecvPacketLength =
        sizeof(QUIC_DATAPATH_RECV_BLOCK) + Datapath->ClientRecvContextLength;

    ProcContext->Index = Index;
    QuicPoolInitialize(TRUE, RecvPacketLength, &ProcContext->RecvBlockPool);
    QuicPoolInitialize(TRUE, MAX_UDP_PAYLOAD_LENGTH, &ProcContext->SendBufferPool);
    QuicPoolInitialize(TRUE, sizeof(QUIC_DATAPATH_SEND_CONTEXT), &ProcContext->SendContextPool);

    int KqueueFd = kqueue();

    if (KqueueFd == INVALID_SOCKET_FD) {
        Status = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "kqueue() failed");
        goto Exit;
    }

    ProcContext->Datapath = Datapath;
    ProcContext->KqueueFd = KqueueFd;

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
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicThreadCreate failed");
        goto Exit;
    }

Exit:

    if (QUIC_FAILED(Status)) {
        if (KqueueFd != INVALID_SOCKET_FD) {
            close(KqueueFd);
        }
        QuicPoolUninitialize(&ProcContext->RecvBlockPool);
        QuicPoolUninitialize(&ProcContext->SendBufferPool);
        QuicPoolUninitialize(&ProcContext->SendContextPool);
    }

    return Status;
}
//
// Opens a new handle to the QUIC Datapath library.
//
QUIC_STATUS
QuicDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_ QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvCallback,
    _In_ QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableCallback,
    _Out_ QUIC_DATAPATH* *NewDataPath
    ) {

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (RecvCallback == NULL ||
        UnreachableCallback == NULL ||
        NewDataPath == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    size_t DatapathObjectSize = sizeof(QUIC_DATAPATH) + sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    QUIC_DATAPATH *Datapath = (QUIC_DATAPATH *)QUIC_ALLOC_PAGED(DatapathObjectSize);
    // Should this be QUIC_ALLOC_PAGED? this is usermode? QUIC_ALLOC instead?
    
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);

        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    QuicZeroMemory(Datapath, DatapathObjectSize);
    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachableHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = 1;
    
    // Using kqueue so batch UDP sending is enabled
    Datapath->MaxSendBatchSize = QUIC_MAX_BATCH_SEND;
    QuicRundownInitialize(&Datapath->BindingsRundown);

    Status = QuicProcessorContextInitialize(Datapath, 0, &Datapath->ProcContexts[0]);
    if (QUIC_FAILED(Status)) {
        Datapath->Shutdown = TRUE;
        goto Exit;
    }

    // As far as I can tell, there's no way to enable RSS in macOS.
    
    *NewDataPath = Datapath;
    Datapath = NULL;
Exit:
    if (Datapath != NULL) {
        QuicRundownUninitialize(&Datapath->BindingsRundown);
        QUIC_FREE(Datapath);
    }

    return Status;
}

//
// Closes a QUIC Datapath library handle.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathUninitialize(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    QUIC_FRE_ASSERT(FALSE);
}

//
// Queries the currently supported features of the datapath.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
QuicDataPathGetSupportedFeatures(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return 0;
}

//
// Gets whether the datapath prefers UDP datagrams padded to path MTU.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathIsPaddingPreferred(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return FALSE;
}

//
// Resolves a hostname to an IP address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    ) {
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

//
// Creates a datapath binding handle for the given local address and/or remote
// address. This function immediately registers for receive upcalls from the
// UDP layer below.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR * LocalAddress,
    _In_opt_ const QUIC_ADDR * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** Binding
    ) {
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

//
// Deletes a UDP binding. This function blocks on all outstandind upcalls and on
// return guarantees no further callbacks will occur. DO NOT call this function
// on an upcall!
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDelete(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_FRE_ASSERT(FALSE);
}

//
// Queries the locally bound interface's MTU. Returns QUIC_MIN_MTU if not
// already bound.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
uint16_t
QuicDataPathBindingGetLocalMtu(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return 0;
}

//
// Queries the locally bound IP address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetLocalAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
    QUIC_FRE_ASSERT(FALSE);
}

//
// Queries the connected remote IP address. Only valid if the binding was
// initially created with a remote address.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetRemoteAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ QUIC_ADDR * Address
    )
{
    QUIC_FRE_ASSERT(FALSE);
}

//
// Called to return a chain of datagrams received from the registered receive
// callback.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{
    QUIC_FRE_ASSERT(FALSE);
}

//
// Allocates a new send context to be used to call QuicDataPathBindingSendTo. It
// can be freed with QuicDataPathBindingFreeSendContext too.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint16_t MaxPacketSize
    )
{ 
    QUIC_FRE_ASSERT(FALSE);
    return NULL;
}

//
// Frees a send context returned from a previous call to
// QuicDataPathBindingAllocSendContext.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{ 
    QUIC_FRE_ASSERT(FALSE);
}

//
// Allocates a new UDP datagram buffer for sending.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ uint16_t MaxBufferLength
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return NULL;
}

//
// Frees a datagram buffer returned from a previous call to
// QuicDataPathBindingAllocSendDatagram.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* SendDatagram
    )
{ 
    QUIC_FRE_ASSERT(FALSE);
}

//
// Returns whether the send context buffer limit has been reached.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return FALSE;
}

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

//
// Sends data to a remote host. Note, the buffer must remain valid for
// the duration of the send operation.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const QUIC_ADDR * LocalAddress,
    _In_ const QUIC_ADDR * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

//
// Sets a parameter on the binding.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingGetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) uint8_t * Buffer
    )
{
    QUIC_FRE_ASSERT(FALSE);
    return QUIC_STATUS_SUCCESS;
}

