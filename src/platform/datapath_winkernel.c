/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (Kernel Mode)

--*/

#include "platform_internal.h"

//
// Not yet available in the WDK. When available this code can be removed.
//
#if 1
#define UDP_SEND_MSG_SIZE           2
#define UDP_RECV_MAX_COALESCED_SIZE 3
#define UDP_COALESCED_INFO          3
#endif

typedef enum {
    ICMP4_ECHO_REPLY        =  0, // Echo Reply.
    ICMP4_DST_UNREACH       =  3, // Destination Unreachable.
    ICMP4_SOURCE_QUENCH     =  4, // Source Quench.
    ICMP4_REDIRECT          =  5, // Redirect.
    ICMP4_ECHO_REQUEST      =  8, // Echo Request.
    ICMP4_ROUTER_ADVERT     =  9, // Router Advertisement.
    ICMP4_ROUTER_SOLICIT    = 10, // Router Solicitation.
    ICMP4_TIME_EXCEEDED     = 11, // Time Exceeded.
    ICMP4_PARAM_PROB        = 12, // Parameter Problem.
    ICMP4_TIMESTAMP_REQUEST = 13, // Timestamp Request.
    ICMP4_TIMESTAMP_REPLY   = 14, // Timestamp Reply.
    ICMP4_MASK_REQUEST      = 17, // Address Mask Request.
    ICMP4_MASK_REPLY        = 18, // Address Mask Reply.
} ICMP4_TYPE, *PICMP4_TYPE;

typedef enum {
    ICMP6_DST_UNREACH          =   1,
    ICMP6_PACKET_TOO_BIG       =   2,
    ICMP6_TIME_EXCEEDED        =   3,
    ICMP6_PARAM_PROB           =   4,
    ICMP6_ECHO_REQUEST         = 128,
    ICMP6_ECHO_REPLY           = 129,
    ICMP6_MEMBERSHIP_QUERY     = 130,
    ICMP6_MEMBERSHIP_REPORT    = 131,
    ICMP6_MEMBERSHIP_REDUCTION = 132,
    ND_ROUTER_SOLICIT          = 133,
    ND_ROUTER_ADVERT           = 134,
    ND_NEIGHBOR_SOLICIT        = 135,
    ND_NEIGHBOR_ADVERT         = 136,
    ND_REDIRECT                = 137,
    ICMP6_V2_MEMBERSHIP_REPORT = 143,
} ICMP6_TYPE, *PICMP6_TYPE;

//
// The maximum UDP receive coalescing payload.
//
#define MAX_URO_PAYLOAD_LENGTH              (UINT16_MAX - QUIC_UDP_HEADER_SIZE)

//
// 60K is the largest buffer most NICs can offload without any software
// segmentation. Current generation NICs advertise (60K < limit <= 64K).
//
#define QUIC_LARGE_SEND_BUFFER_SIZE         0xF000

//
// The maximum number of pages that memory allocated for our UDP payload
// buffers might span.
//
#define MAX_BUFFER_PAGE_USAGE               ((QUIC_LARGE_SEND_BUFFER_SIZE / PAGE_SIZE) + 2)

//
// The maximum size of the MDL to accomodate the maximum UDP payload buffer.
//
#define MDL_SIZE                            (sizeof(MDL) + (sizeof(PFN_NUMBER) * MAX_BUFFER_PAGE_USAGE))

//
// The maximum number of UDP datagrams that can be sent with one call.
//
#define QUIC_MAX_BATCH_SEND                 6

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

typedef struct QUIC_UDP_SOCKET_CONTEXT QUIC_UDP_SOCKET_CONTEXT;
typedef struct QUIC_DATAPATH_PROC_CONTEXT QUIC_DATAPATH_PROC_CONTEXT;

//
// Internal receive allocation context.
//
typedef struct QUIC_DATAPATH_INTERNAL_RECV_CONTEXT {

    //
    // The owning datagram pool.
    //
    QUIC_POOL* OwningPool;

    QUIC_UDP_SOCKET_CONTEXT* SocketContext;
    PWSK_DATAGRAM_INDICATION DataIndication;
    ULONG ReferenceCount;

    //
    // Contains the 4 tuple.
    //
    QUIC_TUPLE Tuple;
} QUIC_DATAPATH_INTERNAL_RECV_CONTEXT;

BOOLEAN
QuicMdlMapChain(
    _In_ PMDL Mdl
    )
{
    do {
        if (!(Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))) {
            if (MmMapLockedPagesSpecifyCache(
                    Mdl, KernelMode, MmCached, NULL, FALSE, LowPagePriority | MdlMappingNoExecute)) {
            } else {
                return FALSE;
            }
            QUIC_DBG_ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        }
        QUIC_DBG_ASSERT(Mdl->MappedSystemVa != NULL);
    } while ((Mdl = Mdl->Next) != NULL);
    return TRUE;
}

//
// Internal receive buffer context.
//
typedef struct QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT {

    //
    // The internal receive context owning the data indication and allocation
    // chain.
    //
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext;

} QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT;

typedef struct QUIC_DATAPATH_SEND_BUFFER {

    //
    // A link in the Send Context's list of WSK buffers.
    //
    WSK_BUF_LIST Link;

    //
    // The MDL buffer.
    //
    union {
        MDL Mdl;
        UCHAR MdlBuffer[MDL_SIZE];
    };

    //
    // Storage for the raw bytes.
    //
    UINT8 RawBuffer[0];

} QUIC_DATAPATH_SEND_BUFFER;

//
// Send context.
//
typedef struct QUIC_DATAPATH_SEND_CONTEXT {

    QUIC_UDP_SOCKET_CONTEXT* SocketContext;

    //
    // The owning processor context.
    //
    QUIC_DATAPATH_PROC_CONTEXT* Owner;

    //
    // The IRP buffer for the async WskSendTo call.
    //
    union {
        IRP Irp;
        UCHAR IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    };

    //
    // Contains the list of QUIC_DATAPATH_SEND_BUFFER.
    //
    PWSK_BUF_LIST WskBufs;

    //
    // The tail of the buffer list.
    //
    QUIC_DATAPATH_SEND_BUFFER* TailBuf;

    //
    // The total buffer size for WsaBuffers.
    //
    uint32_t TotalSize;

    //
    // The number of WSK buffers allocated.
    //
    UINT8 WskBufferCount;

    //
    // The send segmentation size; zero if segmentation is not performed.
    //
    UINT16 SegmentSize;

    //
    // The QUIC_BUFFER returned to the client for segmented sends.
    //
    QUIC_BUFFER ClientBuffer;

} QUIC_DATAPATH_SEND_CONTEXT;

//
// WSK Client version
//
const WSK_CLIENT_DISPATCH WskAppDispatch = {
    MAKE_WSK_VERSION(1,0), // Use WSK version 1.0
    0,    // Reserved
    NULL  // WskClientEvent callback not required for WSK version 1.0
};

//
// Callback for WSK to indicate received datagrams.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
QUIC_STATUS
NTAPI
QuicDataPathSocketReceive(
    _In_opt_ void* SocketContext,
    _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication
    );

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
    PWSK_SOCKET Socket;

    //
    // Event used to wait for completion of socket functions.
    //
    QUIC_EVENT WskCompletionEvent;

    //
    // IRP used for socket functions.
    //
    union {
        IRP Irp;
        UCHAR IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    };

} QUIC_UDP_SOCKET_CONTEXT;

//
// Per-port state.
//
typedef struct QUIC_DATAPATH_BINDING {

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
    // Rundown for client calls.
    //
    QUIC_RUNDOWN_REF ClientRundown;

    //
    // Client context pointer.
    //
    void *ClientContext;

    //
    // The number of outstanding sends.
    //
    long volatile SendOutstanding;

    //
    // Socket context for this port.
    //
    QUIC_UDP_SOCKET_CONTEXT SocketContext;

} QUIC_DATAPATH_BINDING;

//
// Represents the per-processor state of the datapath context.
//
typedef struct QUIC_DATAPATH_PROC_CONTEXT {

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

    //
    // Pool of receive datagram contexts and buffers to be shared by all sockets
    // on this core for URO.
    //
    QUIC_POOL UroRecvDatagramPool;

} QUIC_DATAPATH_PROC_CONTEXT;

//
// Structure that maintains all the internal state for the
// QuicDataPath interface.
//
typedef struct QUIC_DATAPATH {

    //
    // Set of supported features.
    //
    uint32_t Features;

    //
    // The registration with WinSock Kernel.
    //
    WSK_REGISTRATION WskRegistration;
    WSK_PROVIDER_NPI WskProviderNpi;
    WSK_CLIENT_DATAGRAM_DISPATCH WskDispatch;

    //
    // The client callback function pointers.
    //
    QUIC_DATAPATH_RECEIVE_CALLBACK_HANDLER RecvHandler;
    QUIC_DATAPATH_UNREACHABLE_CALLBACK_HANDLER UnreachableHandler;

    //
    // The size of the buffer to allocate for client's receive context structure.
    //
    uint32_t ClientRecvContextLength;

    //
    // The size of each receive datagram array element, including client context,
    // internal context, and padding.
    //
    uint32_t DatagramStride;

    //
    // The number of processors.
    //
    uint32_t ProcCount;

    //
    // Per-processor completion contexts.
    //
    QUIC_DATAPATH_PROC_CONTEXT ProcContexts[0];

} QUIC_DATAPATH;

_IRQL_requires_same_
_Function_class_(ALLOCATE_FUNCTION_EX)
PVOID
QuicSendBufferPoolAlloc(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _Inout_ PLOOKASIDE_LIST_EX Lookaside
    );

#define QuicSendBufferPoolInitialize(Size, Pool) \
    ExInitializeLookasideListEx( \
        Pool, \
        QuicSendBufferPoolAlloc, \
        NULL, \
        NonPagedPoolNx, \
        0, \
        Size, \
        QUIC_POOL_TAG, \
        0)

QUIC_RECV_DATAGRAM*
QuicDataPathRecvPacketToRecvDatagram(
    _In_ const QUIC_RECV_PACKET* const Context
    )
{
    return (QUIC_RECV_DATAGRAM*)
        (((PUCHAR)Context) -
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) -
            sizeof(QUIC_RECV_DATAGRAM));
}

QUIC_RECV_PACKET*
QuicDataPathRecvDatagramToRecvPacket(
    _In_ const QUIC_RECV_DATAGRAM* const Datagram
    )
{
    return (QUIC_RECV_PACKET*)
        (((PUCHAR)Datagram) +
            sizeof(QUIC_RECV_DATAGRAM) +
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT));
}

QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*
QuicDataPathDatagramToInternalDatagramContext(
    _In_ QUIC_RECV_DATAGRAM* Datagram
    )
{
    return (QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT*)
        (((PUCHAR)Datagram) + sizeof(QUIC_RECV_DATAGRAM));
}

IO_COMPLETION_ROUTINE QuicDataPathIoCompletion;

//
// Used for all WSK IoCompletion routines
//
_Use_decl_annotations_
QUIC_STATUS
QuicDataPathIoCompletion(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    void* Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned) {
        QUIC_EVENT* CompletionEvent = (QUIC_EVENT*)Context;
        NT_ASSERT(CompletionEvent);

        //
        // Set the event to indicate we have completed the operation.
        //
#pragma prefast(suppress: 28182, "SAL doesn't understand this callback parameter")
        QuicEventSet(*CompletionEvent);
    }

    //
    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

void
QuicDataPathQueryRssScalabilityInfo(
    _In_ QUIC_DATAPATH* Datapath
    )
{
    NTSTATUS Status;
    PWSK_SOCKET RssSocket = NULL;
    PWSK_PROVIDER_BASIC_DISPATCH Dispatch = NULL;
    SIZE_T OutputSizeReturned;
    RSS_SCALABILITY_INFO RssInfo = { 0 };

    QUIC_EVENT CompletionEvent;
    QuicEventInitialize(&CompletionEvent, FALSE, FALSE);

    uint8_t IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    PIRP Irp = (PIRP)IrpBuffer;

    QuicZeroMemory(Irp, sizeof(IrpBuffer));

    IoInitializeIrp(Irp, sizeof(IrpBuffer), 1);
    IoSetCompletionRoutine(
        Irp,
        QuicDataPathIoCompletion,
        &CompletionEvent,
        TRUE,
        TRUE,
        TRUE);

    Status =
        Datapath->WskProviderNpi.Dispatch->
        WskSocket(
            Datapath->WskProviderNpi.Client,
            AF_INET6,
            SOCK_STREAM,
            IPPROTO_TCP,
            WSK_FLAG_BASIC_SOCKET,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(CompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ dal] RSS helper socket failed to open, 0x%x", Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ dal] RSS helper socket failed to open (async), 0x%x", Status);
        goto Error;
    }

    RssSocket = (PWSK_SOCKET)(Irp->IoStatus.Information);
    Dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)(RssSocket->Dispatch);

    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        Irp,
        QuicDataPathIoCompletion,
        &CompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(CompletionEvent);

    Status =
        Dispatch->WskControlSocket(
            RssSocket,
            WskIoctl,
            SIO_QUERY_RSS_SCALABILITY_INFO,
            SOL_SOCKET,
            0,
            NULL,
            sizeof(RssInfo),
            &RssInfo,
            &OutputSizeReturned,
            Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(CompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ dal] Query for SIO_QUERY_RSS_PROCESSOR_INFO failed, 0x%x", Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ dal] Query for SIO_QUERY_RSS_PROCESSOR_INFO failed (async), 0x%x", Status);
        goto Error;
    }

    if (RssInfo.RssEnabled) {
        Datapath->Features |= QUIC_DATAPATH_FEATURE_RECV_SIDE_SCALING;
    }

Error:

    if (RssSocket != NULL) {
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            QuicDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        QuicEventReset(CompletionEvent);
        Status = Dispatch->WskCloseSocket(RssSocket, Irp);
        QUIC_DBG_ASSERT(NT_SUCCESS(Status));
        if (Status == STATUS_PENDING) {
            QuicEventWaitForever(CompletionEvent);
        }
    }

    IoCleanupIrp(Irp);
}

VOID
QuicDataPathQuerySockoptSupport(
    _Inout_ QUIC_DATAPATH* Datapath
    )
{
    NTSTATUS Status;
    PWSK_SOCKET UdpSocket = NULL;
    PWSK_PROVIDER_BASIC_DISPATCH Dispatch = NULL;
    SIZE_T OutputSizeReturned;

    QUIC_EVENT CompletionEvent;
    QuicEventInitialize(&CompletionEvent, FALSE, FALSE);

    uint8_t IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    PIRP Irp = (PIRP)IrpBuffer;

    QuicZeroMemory(Irp, sizeof(IrpBuffer));

    IoInitializeIrp(Irp, sizeof(IrpBuffer), 1);
    IoSetCompletionRoutine(
        Irp,
        QuicDataPathIoCompletion,
        &CompletionEvent,
        TRUE,
        TRUE,
        TRUE);

    Status =
        Datapath->WskProviderNpi.Dispatch->
        WskSocket(
            Datapath->WskProviderNpi.Client,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_UDP,
            WSK_FLAG_BASIC_SOCKET,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(CompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ dal] UDP send segmentation helper socket failed to open, 0x%x", Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning("[ dal] UDP send segmentation helper socket failed to open (async), 0x%x", Status);
        goto Error;
    }

    UdpSocket = (PWSK_SOCKET)(Irp->IoStatus.Information);
    Dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)(UdpSocket->Dispatch);

    do {
        DWORD SegmentSize;

        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            QuicDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        QuicEventReset(CompletionEvent);

        Status =
            Dispatch->WskControlSocket(
                UdpSocket,
                WskGetOption,
                UDP_SEND_MSG_SIZE,
                IPPROTO_UDP,
                0,
                NULL,
                sizeof(SegmentSize),
                &SegmentSize,
                &OutputSizeReturned,
                Irp);
        if (Status == STATUS_PENDING) {
            QuicEventWaitForever(CompletionEvent);
        } else if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning("[ dal] Query for UDP_SEND_MSG_SIZE failed, 0x%x", Status);
            break;
        }

        Status = Irp->IoStatus.Status;
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning("[ dal] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x", Status);
            break;
        }

        Datapath->Features |= QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION;

    } while (FALSE);

    do {
        DWORD UroMaxCoalescedMsgSize;

        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            QuicDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        QuicEventReset(CompletionEvent);

        Status =
            Dispatch->WskControlSocket(
                UdpSocket,
                WskGetOption,
                UDP_RECV_MAX_COALESCED_SIZE,
                IPPROTO_UDP,
                0,
                NULL,
                sizeof(UroMaxCoalescedMsgSize),
                &UroMaxCoalescedMsgSize,
                &OutputSizeReturned,
                Irp);
        if (Status == STATUS_PENDING) {
            QuicEventWaitForever(CompletionEvent);
        } else if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning("[ dal] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x", Status);
            break;
        }

        Status = Irp->IoStatus.Status;
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning("[ dal] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x", Status);
            break;
        }

        Datapath->Features |= QUIC_DATAPATH_FEATURE_RECV_COALESCING;

    } while (FALSE);

Error:

    if (UdpSocket != NULL) {
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            QuicDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        QuicEventReset(CompletionEvent);
        Status = Dispatch->WskCloseSocket(UdpSocket, Irp);
        QUIC_DBG_ASSERT(NT_SUCCESS(Status));
        if (Status == STATUS_PENDING) {
            QuicEventWaitForever(CompletionEvent);
        }
    }

    IoCleanupIrp(Irp);
}

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
    WSK_CLIENT_NPI WskClientNpi = { NULL, &WskAppDispatch };
    uint32_t DatapathLength;
    QUIC_DATAPATH* Datapath;
    BOOLEAN WskRegistered = FALSE;

    if (RecvCallback == NULL || UnreachableCallback == NULL || NewDataPath == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        Datapath = NULL;
        goto Exit;
    }

    DatapathLength =
        sizeof(QUIC_DATAPATH) +
        QuicProcMaxCount() * sizeof(QUIC_DATAPATH_PROC_CONTEXT);

    Datapath = QUIC_ALLOC_NONPAGED(DatapathLength);
    if (Datapath == NULL) {
        QuicTraceEvent(AllocFailure, "QUIC_DATAPATH", DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    RtlZeroMemory(Datapath, DatapathLength);
    Datapath->RecvHandler = RecvCallback;
    Datapath->UnreachableHandler = UnreachableCallback;
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = (uint32_t)QuicProcMaxCount();
    Datapath->WskDispatch.WskReceiveFromEvent = QuicDataPathSocketReceive;
    Datapath->DatagramStride =
        ALIGN_UP(
            sizeof(QUIC_RECV_DATAGRAM) +
            sizeof(QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) +
            ClientRecvContextLength,
            PVOID);

    uint32_t RecvDatagramLength =
        sizeof(QUIC_DATAPATH_INTERNAL_RECV_CONTEXT) +
        Datapath->DatagramStride;
    uint32_t UroDatagramLength =
        sizeof(QUIC_DATAPATH_INTERNAL_RECV_CONTEXT) +
        URO_MAX_DATAGRAMS_PER_INDICATION * Datapath->DatagramStride;

    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {

        QuicPoolInitialize(
            FALSE,
            sizeof(QUIC_DATAPATH_SEND_CONTEXT),
            &Datapath->ProcContexts[i].SendContextPool);

        QuicSendBufferPoolInitialize(
            sizeof(QUIC_DATAPATH_SEND_BUFFER) + MAX_UDP_PAYLOAD_LENGTH,
            &Datapath->ProcContexts[i].SendBufferPool);

        QuicSendBufferPoolInitialize(
            sizeof(QUIC_DATAPATH_SEND_BUFFER) + QUIC_LARGE_SEND_BUFFER_SIZE,
            &Datapath->ProcContexts[i].LargeSendBufferPool);

        QuicPoolInitialize(
            FALSE,
            RecvDatagramLength,
            &Datapath->ProcContexts[i].RecvDatagramPool);

        QuicPoolInitialize(
            FALSE,
            UroDatagramLength,
            &Datapath->ProcContexts[i].UroRecvDatagramPool);
    }

    Status = WskRegister(&WskClientNpi, &Datapath->WskRegistration);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(LibraryErrorStatus, Status, "WskRegister");
        goto Error;
    }
    WskRegistered = TRUE;

    //
    // Capture the WSK Provider NPI. If WSK subsystem is not ready yet,
    // wait until it becomes ready.
    //
    Status =
        WskCaptureProviderNPI(
            &Datapath->WskRegistration,
            WSK_INFINITE_WAIT,
            &Datapath->WskProviderNpi);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(LibraryErrorStatus, Status, "WskCaptureProviderNPI");
        goto Error;
    }

    QuicDataPathQueryRssScalabilityInfo(Datapath);
    QuicDataPathQuerySockoptSupport(Datapath);

    *NewDataPath = Datapath;

    goto Exit;

Error:

    if (WskRegistered) {
        WskDeregister(&Datapath->WskRegistration);
    }

    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].UroRecvDatagramPool);
    }
    QUIC_FREE(Datapath);

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

    WskReleaseProviderNPI(&Datapath->WskRegistration);
    WskDeregister(&Datapath->WskRegistration);
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendContextPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPool);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].UroRecvDatagramPool);
    }
    QUIC_FREE(Datapath);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathResolveAddressWithHint(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ PUNICODE_STRING UniHostName,
    _In_ PADDRINFOEXW Hints,
    _Inout_ PADDRINFOEXW *Ai
    )
{
    QUIC_STATUS Status;

    QUIC_EVENT CompletionEvent;
    QuicEventInitialize(&CompletionEvent, FALSE, FALSE);

    PIRP Irp = IoAllocateIrp(1, FALSE);

    if (Irp == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    IoSetCompletionRoutine(
        Irp,
        QuicDataPathIoCompletion,
        &CompletionEvent,
        TRUE,
        TRUE,
        TRUE);

    Status =
        Datapath->WskProviderNpi.Dispatch->
        WskGetAddressInfo(
            Datapath->WskProviderNpi.Client,
            UniHostName,
            NULL,                           // No service
            NS_ALL,                         // namespace
            NULL,                           // No specific provider
            Hints,                          // Hints
            Ai,
            NULL,                           // Process (none)
            NULL,                           // Thread (none)
            Irp);

    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(CompletionEvent);

    } else if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    if (Irp != NULL) {
        IoFreeIrp(Irp);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathResolveAddress(
    _In_ QUIC_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR * Address
    )
{
    QUIC_STATUS Status = STATUS_SUCCESS;
    UNICODE_STRING UniHostName = { 0 };

    ADDRINFOEXW Hints = { 0 };
    ADDRINFOEXW *Ai = NULL;

    size_t HostNameLength = strnlen(HostName, 1024);
    if (HostNameLength >= 1024) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    UniHostName.MaximumLength = (USHORT)(sizeof(WCHAR) * HostNameLength);
    UniHostName.Buffer = QUIC_ALLOC_PAGED(UniHostName.MaximumLength);
    if (UniHostName.Buffer == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(AllocFailure, "Unicode Hostname", UniHostName.MaximumLength);
        goto Error;
    }

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->si_family;

    //
    // Convert the UTF8 string to unicode.
    //
    ULONG UniHostNameLength = 0;
    Status =
        RtlUTF8ToUnicodeN(
            UniHostName.Buffer,
            UniHostName.MaximumLength,
            &UniHostNameLength,
            HostName,
            (ULONG)HostNameLength);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(LibraryErrorStatus, Status, "Convert hostname to unicode");
        goto Error;
    }

    UniHostName.Length = (USHORT)UniHostNameLength;

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Status =
        QuicDataPathResolveAddressWithHint(
            Datapath,
            &UniHostName,
            &Hints,
            &Ai);

    if (NT_SUCCESS(Status)) {
        memcpy(Address, Ai->ai_addr, Ai->ai_addrlen);
        goto Error;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Status =
        QuicDataPathResolveAddressWithHint(
            Datapath,
            &UniHostName,
            &Hints,
            &Ai);

    if (NT_SUCCESS(Status)) {
        memcpy(Address, Ai->ai_addr, Ai->ai_addrlen);
        goto Error;
    }

    QuicTraceEvent(LibraryError, "Resolving hostname to IP");
    QuicTraceLogError("[%p] Couldn't resolve hostname '%s' to an IP address", Datapath, HostName);
    Status = STATUS_NOT_FOUND;

Error:

    if (Ai != NULL) {
        Datapath->WskProviderNpi.Dispatch->
            WskFreeAddressInfo(
                Datapath->WskProviderNpi.Client,
                Ai);
    }

    if (UniHostName.Buffer != NULL) {
        QUIC_FREE(UniHostName.Buffer);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
QuicDataPathSetControlSocket(
    _In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext,
    _In_ WSK_CONTROL_SOCKET_TYPE RequestType,
    _In_ ULONG ControlCode,
    _In_ ULONG Level,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize)
         void* InputBuffer
    )
{
    QUIC_STATUS Status = STATUS_SUCCESS;

    //
    // Get pointer to the socket's provider dispatch structure
    //
    PWSK_PROVIDER_BASIC_DISPATCH Dispatch =
        (PWSK_PROVIDER_BASIC_DISPATCH)(SocketContext->Socket->Dispatch);

    IoReuseIrp(&SocketContext->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &SocketContext->Irp,
        QuicDataPathIoCompletion,
        &SocketContext->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(SocketContext->WskCompletionEvent);

    SIZE_T OutputSizeReturned;
    Status =
        Dispatch->WskControlSocket(
            SocketContext->Socket,
            RequestType,
            ControlCode,
            Level,
            InputSize,
            InputBuffer,
            0,
            NULL,
            &OutputSizeReturned,
            &SocketContext->Irp);

    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(SocketContext->WskCompletionEvent);

    } else if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status = SocketContext->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    return Status;
}

IO_COMPLETION_ROUTINE QuicDataPathCloseSocketIoCompletion;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingSocketClosed(
    _In_ QUIC_DATAPATH_BINDING* Binding
    );

//
// Completion callbacks for IRP used with WskCloseSocket
//
_Use_decl_annotations_
QUIC_STATUS
QuicDataPathCloseSocketIoCompletion(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    void* Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp->PendingReturned) {
        QUIC_UDP_SOCKET_CONTEXT* SocketContext = (QUIC_UDP_SOCKET_CONTEXT*)Context;
        NT_ASSERT(SocketContext);

#pragma prefast(suppress: 28182, "SAL doesn't understand how callbacks work.")
        if (QUIC_FAILED(SocketContext->Irp.IoStatus.Status)) {
            QuicTraceEvent(DatapathErrorStatus, SocketContext->Binding,
                SocketContext->Irp.IoStatus.Status, "WskCloseSocket completion");
        }

        QuicDataPathBindingSocketClosed(SocketContext->Binding);
    }

    //
    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathCleanupSocketContext(
    _In_ QUIC_UDP_SOCKET_CONTEXT* SocketContext
    )
{
    NTSTATUS Status;

    if (SocketContext->Socket != NULL) {

        WSK_EVENT_CALLBACK_CONTROL EventControl =
        {
            &NPI_WSK_INTERFACE_ID,
            WSK_EVENT_DISABLE | WSK_EVENT_RECEIVE_FROM
        };

        //
        // Disable receive callbacks.
        //
        (void)QuicDataPathSetControlSocket(
                SocketContext,
                WskSetOption,
                SO_WSK_EVENT_CALLBACK,
                SOL_SOCKET,
                sizeof(EventControl),
                &EventControl);

        //
        // Close the socket.
        //

        PWSK_PROVIDER_BASIC_DISPATCH Dispatch =
            (PWSK_PROVIDER_BASIC_DISPATCH)(SocketContext->Socket->Dispatch);

        IoReuseIrp(&SocketContext->Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            &SocketContext->Irp,
            QuicDataPathCloseSocketIoCompletion,
            SocketContext,
            TRUE,
            TRUE,
            TRUE);

        Status =
            Dispatch->WskCloseSocket(
                SocketContext->Socket,
                &SocketContext->Irp);

        QUIC_DBG_ASSERT(NT_SUCCESS(Status));
        if (Status == STATUS_PENDING) {
            return;
        }

        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(DatapathErrorStatus, SocketContext->Binding, Status, "WskCloseSocket");
        }
    }

    QuicDataPathBindingSocketClosed(SocketContext->Binding);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingCreate(
    _In_ QUIC_DATAPATH* Datapath,
    _In_opt_ const SOCKADDR_INET * LocalAddress,
    _In_opt_ const SOCKADDR_INET * RemoteAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ QUIC_DATAPATH_BINDING** NewBinding
    )
{
    QUIC_STATUS Status = STATUS_SUCCESS;
    QUIC_DATAPATH_BINDING* Binding = NULL;
    QUIC_UDP_SOCKET_CONTEXT* SocketContext = NULL;
    uint32_t Option;
    WSK_EVENT_CALLBACK_CONTROL EventControl =
    {
        &NPI_WSK_INTERFACE_ID,
        WSK_EVENT_RECEIVE_FROM
    };

    if (Datapath == NULL || NewBinding == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Binding = (QUIC_DATAPATH_BINDING*)QUIC_ALLOC_NONPAGED(sizeof(QUIC_DATAPATH_BINDING));
    if (Binding == NULL) {
        QuicTraceEvent(AllocFailure, "QUIC_DATAPATH_BINDING", sizeof(QUIC_DATAPATH_BINDING));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    RtlZeroMemory(Binding, sizeof(QUIC_DATAPATH_BINDING));
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    if (LocalAddress != NULL) {
        QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.si_family = AF_INET6;
    }
    Binding->Mtu = QUIC_MAX_MTU;
    QuicRundownInitialize(&Binding->ClientRundown);

    //
    // Initialize the socket context.
    //

    SocketContext = &Binding->SocketContext;

    SocketContext->Binding = Binding;
    QuicEventInitialize(&SocketContext->WskCompletionEvent, FALSE, FALSE);
    IoInitializeIrp(
        &SocketContext->Irp,
        sizeof(SocketContext->Irp),
        1);
    IoSetCompletionRoutine(
        &SocketContext->Irp,
        QuicDataPathIoCompletion,
        &SocketContext->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);

    Status =
        Datapath->WskProviderNpi.Dispatch->
        WskSocket(
            Datapath->WskProviderNpi.Client,
            AF_INET6,
            SOCK_DGRAM,
            IPPROTO_UDP,
            WSK_FLAG_DATAGRAM_SOCKET,
            SocketContext,
            &Datapath->WskDispatch,
            NULL,
            NULL,
            NULL,
            &SocketContext->Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(SocketContext->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "WskSocket");
        goto Error;
    }

    Status = SocketContext->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "WskSocket completion");
        goto Error;
    }

    SocketContext->Socket = (PWSK_SOCKET)(SocketContext->Irp.IoStatus.Information);

    //
    // Enable Dual-Stack mode.
    //
    Option = FALSE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IPV6_V6ONLY,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IPV6_V6ONLY");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IP_DONTFRAGMENT,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IP_DONTFRAGMENT");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IPV6_DONTFRAG,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IPV6_DONTFRAG");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IPV6_PKTINFO,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IPV6_PKTINFO");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IP_PKTINFO,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IP_PKTINFO");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IPV6_RECVERR,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IPV6_RECVERR");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            IP_RECVERR,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set IP_RECVERR");
        goto Error;
    }

    if (Datapath->Features & QUIC_DATAPATH_FEATURE_RECV_COALESCING) {
        Option = MAX_URO_PAYLOAD_LENGTH;
        Status =
            QuicDataPathSetControlSocket(
                SocketContext,
                WskSetOption,
                UDP_RECV_MAX_COALESCED_SIZE,
                IPPROTO_UDP,
                sizeof(Option),
                &Option);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set UDP_RECV_MAX_COALESCED_SIZE");
            goto Error;
        }
    }

    PWSK_PROVIDER_DATAGRAM_DISPATCH Dispatch =
        (PWSK_PROVIDER_DATAGRAM_DISPATCH)(SocketContext->Socket->Dispatch);

    IoReuseIrp(&SocketContext->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &SocketContext->Irp,
        QuicDataPathIoCompletion,
        &SocketContext->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(SocketContext->WskCompletionEvent);

    Status =
        Dispatch->WskBind(
            SocketContext->Socket,
            (PSOCKADDR)&Binding->LocalAddress,
            0,  // No flags
            &SocketContext->Irp
            );
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(SocketContext->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "WskBind");
        goto Error;
    }

    Status = SocketContext->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "WskBind completion");
        goto Error;
    }

    if (RemoteAddress) {
        SOCKADDR_INET MappedRemoteAddress = { 0 };
        QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        Status =
            QuicDataPathSetControlSocket(
                SocketContext,
                WskIoctl,
                (ULONG)SIO_WSK_SET_REMOTE_ADDRESS,
                SOL_SOCKET,
                sizeof(MappedRemoteAddress),
                &MappedRemoteAddress);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set SIO_WSK_SET_REMOTE_ADDRESS");
            goto Error;
        }
    }

    //
    // Must set output pointer before starting receive path, as the receive path
    // will try to use the output.
    //
    *NewBinding = Binding;

    Status =
        QuicDataPathSetControlSocket(
            SocketContext,
            WskSetOption,
            SO_WSK_EVENT_CALLBACK,
            SOL_SOCKET,
            sizeof(EventControl),
            &EventControl);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "Set SO_WSK_EVENT_CALLBACK");
        goto Error;
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //

    IoReuseIrp(&SocketContext->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &SocketContext->Irp,
        QuicDataPathIoCompletion,
        &SocketContext->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(SocketContext->WskCompletionEvent);

    Status =
        Dispatch->WskGetLocalAddress(
            SocketContext->Socket,
            (PSOCKADDR)&Binding->LocalAddress,
            &SocketContext->Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(SocketContext->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "WskGetLocalAddress");
        goto Error;
    }

    Status = SocketContext->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, Binding, Status, "WskGetLocalAddress completion");
        goto Error;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        QUIC_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    QuicConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);
    Binding->LocalAddress.Ipv6.sin6_scope_id = 0;

    if (RemoteAddress != NULL) {
        Binding->RemoteAddress = *RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            QuicDataPathBindingDelete(Binding);
        }
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingSocketClosed(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    IoCleanupIrp(&Binding->SocketContext.Irp);
    QuicRundownUninitialize(&Binding->ClientRundown);
    QUIC_FREE(Binding);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDelete(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    //
    // Close the socket (asynchronously) which will call the above function,
    // QuicDataPathBindingSocketClosed, when it completes to finish.
    //
    QuicDataPathCleanupSocketContext(&Binding->SocketContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathBindingSetContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_opt_ void* Context
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    if (Context != NULL) {
        void* OrigContext =
            InterlockedCompareExchangePointer(&Binding->ClientContext, Context, NULL);
        return OrigContext == NULL;
    } else {
        InterlockedExchangePointer(&Binding->ClientContext, NULL);
        return TRUE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void*
QuicDataPathBindingGetContext(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    return Binding->ClientContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
QuicDataPathBindingGetLocalMtu(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetLocalAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ SOCKADDR_INET * Address
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingGetRemoteAddress(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _Out_ SOCKADDR_INET * Address
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
}

QUIC_DATAPATH_INTERNAL_RECV_CONTEXT*
QuicDataPathBindingAllocRecvContext(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ UINT16 ProcIndex,
    _In_ BOOLEAN IsUro
    )
{
    QUIC_POOL* Pool =
        IsUro ?
            &Datapath->ProcContexts[ProcIndex].UroRecvDatagramPool :
            &Datapath->ProcContexts[ProcIndex].RecvDatagramPool;

    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext = QuicPoolAlloc(Pool);

    if (InternalContext != NULL) {
        InternalContext->OwningPool = Pool;
    }

    return InternalContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
QUIC_STATUS
NTAPI
QuicDataPathSocketReceive(
    _In_opt_ void* Context,
    _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndicationHead
    )
{
    //
    // Check to see if the DataIndicate is NULL, which indicates that the
    // socket has been closed
    //
    if (DataIndicationHead == NULL) {
        return STATUS_SUCCESS;
    }

    QUIC_UDP_SOCKET_CONTEXT* SocketContext = (QUIC_UDP_SOCKET_CONTEXT*)Context;
    PWSK_DATAGRAM_INDICATION ReleaseChain = NULL;
    PWSK_DATAGRAM_INDICATION* ReleaseChainTail = &ReleaseChain;
    QUIC_RECV_DATAGRAM* DatagramChain = NULL;
    QUIC_RECV_DATAGRAM** DatagramChainTail = &DatagramChain;

    PWSK_PROVIDER_DATAGRAM_DISPATCH Dispatch =
        (PWSK_PROVIDER_DATAGRAM_DISPATCH)(SocketContext->Socket->Dispatch);

    UNREFERENCED_PARAMETER(Flags);

    //
    // Process all the data indicated by the callback.
    //
    while (DataIndicationHead != NULL) {

        PWSK_DATAGRAM_INDICATION DataIndication = DataIndicationHead;
        DataIndicationHead = DataIndicationHead->Next;
        DataIndication->Next = NULL;

        QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = NULL;
        QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext;
        QUIC_RECV_DATAGRAM* Datagram = NULL;

        if (DataIndication->Buffer.Mdl == NULL ||
            DataIndication->Buffer.Length == 0) {
            QuicTraceLogWarning("[%p] Dropping datagram with empty mdl.", SocketContext);
            goto Drop;
        }

        BOOLEAN FoundLocalAddr = FALSE;
        BOOLEAN IsUnreachableError = FALSE;
        BOOLEAN IsCoalesced = FALSE;
        SOCKADDR_INET LocalAddr = { 0 };
        SOCKADDR_INET RemoteAddr;
        UINT16 MessageLength = 0;

        //
        // Parse the ancillary data for all the per datagram information that we
        // require.
        //
        WSAMSG WsaMsgHdr = { 0 };
        WsaMsgHdr.Control.len = DataIndication->ControlInfoLength;
        WsaMsgHdr.Control.buf = (char*)DataIndication->ControlInfo;
        for (WSACMSGHDR *CMsg = WSA_CMSG_FIRSTHDR(&WsaMsgHdr);
            CMsg != NULL;
            CMsg = WSA_CMSG_NXTHDR(&WsaMsgHdr, CMsg)) {

            if (CMsg->cmsg_level == IPPROTO_IPV6) {
                if (CMsg->cmsg_type == IPV6_PKTINFO) {
                    PIN6_PKTINFO PktInfo6 = (PIN6_PKTINFO)WSA_CMSG_DATA(CMsg);
                    LocalAddr.si_family = AF_INET6;
                    LocalAddr.Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                    LocalAddr.Ipv6.sin6_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                    QuicConvertFromMappedV6(&LocalAddr, &LocalAddr);

                    LocalAddr.Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;

                } else if (CMsg->cmsg_type == IPV6_RECVERR) {
                    IN_RECVERR* RecvErr = (IN_RECVERR*)WSA_CMSG_DATA(CMsg);
                    if (RecvErr->type == ICMP6_DST_UNREACH) {
                        IsUnreachableError = TRUE;
                        break;
                    }
                }
            } else if (CMsg->cmsg_level == IPPROTO_IP) {
                if (CMsg->cmsg_type == IP_PKTINFO) {
                    PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
                    LocalAddr.si_family = AF_INET;
                    LocalAddr.Ipv4.sin_addr = PktInfo->ipi_addr;
                    LocalAddr.Ipv4.sin_port = SocketContext->Binding->LocalAddress.Ipv6.sin6_port;
                    LocalAddr.Ipv6.sin6_scope_id = PktInfo->ipi_ifindex;
                    FoundLocalAddr = TRUE;

                } else if (CMsg->cmsg_type == IP_RECVERR) {
                    IN_RECVERR* RecvErr = (IN_RECVERR*)WSA_CMSG_DATA(CMsg);
                    if (RecvErr->type == ICMP4_DST_UNREACH) {
                        IsUnreachableError = TRUE;
                        break;
                    }
                }
            } else if (CMsg->cmsg_level == IPPROTO_UDP) {
                if (CMsg->cmsg_type == UDP_COALESCED_INFO) {
                    QUIC_DBG_ASSERT(*(PDWORD)WSA_CMSG_DATA(CMsg) <= MAX_URO_PAYLOAD_LENGTH);
                    MessageLength = (UINT16)*(PDWORD)WSA_CMSG_DATA(CMsg);
                    IsCoalesced = TRUE;

                    QUIC_DBG_ASSERT(MessageLength > 0);
                }
            }
        }

        if (!FoundLocalAddr && !IsUnreachableError) {
            //
            // The underlying data path does not guarantee ancillary data for
            // enabled socket options when the system is under memory pressure.
            //
            QuicTraceLogWarning("[%p] Dropping datagram missing IP_PKTINFO/IP_RECVERR.", SocketContext);
            goto Drop;
        }

        QuicConvertFromMappedV6(
            (SOCKADDR_INET*)DataIndication->RemoteAddress,
            &RemoteAddr);

        if (IsUnreachableError) {
#ifdef 0 // TODO - Change to ETW event
            if (RemoteAddr.si_family == AF_INET) {
                QuicTraceLogVerbose("[sock][%p] Unreachable error from %!IPV4ADDR!:%hu",
                    SocketContext,
                    &RemoteAddr.Ipv4.sin_addr,
                    RtlUshortByteSwap(RemoteAddr.Ipv4.sin_port));
            } else {
                QuicTraceLogVerbose("[sock][%p] Unreachable error from [%!IPV6ADDR!]:%hu",
                    SocketContext,
                    &RemoteAddr.Ipv6.sin6_addr,
                    RtlUshortByteSwap(RemoteAddr.Ipv6.sin6_port));
            }
#endif

            QUIC_DBG_ASSERT(SocketContext->Binding->Datapath->UnreachableHandler);
            SocketContext->Binding->Datapath->UnreachableHandler(
                SocketContext->Binding,
                SocketContext->Binding->ClientContext,
                &RemoteAddr);

            goto Drop;
        }

        PMDL Mdl = DataIndication->Buffer.Mdl;
        ULONG MdlOffset = DataIndication->Buffer.Offset;
        SIZE_T DataLength = DataIndication->Buffer.Length;

        if (MessageLength == 0) {
            //
            // If there was no explicit message length provided, then the entire
            // datagram constitutes a single message.
            //
            QUIC_DBG_ASSERT(DataLength <= MAXUINT16);
            if (DataLength > MAXUINT16) {
                QuicTraceLogWarning("[%p] Dropping datagram with too many bytes (%llu).",
                    SocketContext, (uint64_t)DataLength);
                goto Drop;
            }
            MessageLength = (UINT16)DataLength;
        }

        if (!QuicMdlMapChain(DataIndication->Buffer.Mdl)) {
            QuicTraceLogWarning("[%p] Failed to map MDL chain", SocketContext);
            goto Drop;
        }

        QuicTraceEvent(DatapathRecv,
            SocketContext->Binding,
            (uint32_t)DataLength,
            MessageLength,
            LOG_ADDR_LEN(LocalAddr), LOG_ADDR_LEN(RemoteAddr),
            (UINT8*)&LocalAddr, (UINT8*)&RemoteAddr);

        for ( ; DataLength != 0; DataLength -= MessageLength) {

            QUIC_DBG_ASSERT(Mdl != NULL);
            QUIC_DBG_ASSERT(MdlOffset <= Mdl->ByteCount);

            if ((SIZE_T)MessageLength > DataLength) {
                //
                // The last message is smaller than all the rest.
                //
                MessageLength = (UINT16)DataLength;
            }

            //
            // We require contiguous buffers.
            //
            if ((SIZE_T)MessageLength > Mdl->ByteCount - MdlOffset) {
                QuicTraceLogWarning("[%p] Dropping datagram with fragmented MDL.", SocketContext);
                QUIC_DBG_ASSERT(FALSE);
                goto Drop;
            }

            if (RecvContext == NULL) {
                RecvContext =
                    QuicDataPathBindingAllocRecvContext(
                        SocketContext->Binding->Datapath,
                        (UINT16)QuicProcCurrentNumber(),
                        IsCoalesced);
                if (RecvContext == NULL) {
                    QuicTraceLogWarning("[%p] Couldn't allocate receive context.", SocketContext);
                    goto Drop;
                }

                RecvContext->SocketContext = SocketContext;
                RecvContext->DataIndication = DataIndication;
                RecvContext->ReferenceCount = 0;
                RecvContext->Tuple.LocalAddress = LocalAddr;
                RecvContext->Tuple.RemoteAddress = RemoteAddr;
                Datagram = (QUIC_RECV_DATAGRAM*)(RecvContext + 1);
            }

            QUIC_DBG_ASSERT(Datagram != NULL);
            Datagram->Next = NULL;
            Datagram->PartitionIndex = (uint8_t)QuicProcCurrentNumber();
            Datagram->Allocated = TRUE;
            Datagram->QueuedOnConnection = FALSE;

            InternalDatagramContext =
                QuicDataPathDatagramToInternalDatagramContext(Datagram);
            InternalDatagramContext->RecvContext = RecvContext;

            Datagram->Buffer = (uint8_t*)Mdl->MappedSystemVa + MdlOffset;
            Datagram->BufferLength = MessageLength;
            Datagram->Tuple = &RecvContext->Tuple;

            //
            // Add the datagram to the end of the current chain.
            //
            *DatagramChainTail = Datagram;
            DatagramChainTail = &Datagram->Next;
            if (++RecvContext->ReferenceCount == URO_MAX_DATAGRAMS_PER_INDICATION) {
                QuicTraceLogWarning("[%p] Exceeded URO preallocation capacity.", SocketContext);
                break;
            }

            //
            // Walk the MDL chain.
            //
            MdlOffset += MessageLength;
            if (MdlOffset == Mdl->ByteCount) {
                if (Mdl->Next == NULL) {
                    break;
                }
                Mdl = Mdl->Next;
                MdlOffset = 0;
            }

            Datagram = (QUIC_RECV_DATAGRAM*)
                (((PUCHAR)Datagram) +
                    SocketContext->Binding->Datapath->DatagramStride);
        }

        continue;

    Drop:

        if (RecvContext != NULL && RecvContext->ReferenceCount == 0) {
            //
            // No receive buffers were generated, so clean up now and return the
            // indication back to WSK. If the reference count is nonzero, then
            // the indication will be returned only after the binding client has
            // returned the buffers.
            //
            QuicPoolFree(RecvContext->OwningPool, RecvContext);
            RecvContext = NULL;
        }

        if (RecvContext == NULL) {
            *ReleaseChainTail = DataIndication;
            ReleaseChainTail = &DataIndication->Next;
        }
    }

    if (DatagramChain != NULL) {
        //
        // Indicate all accepted datagrams.
        //
        SocketContext->Binding->Datapath->RecvHandler(
            SocketContext->Binding,
            SocketContext->Binding->ClientContext,
            DatagramChain);
    }

    if (ReleaseChain != NULL) {
        //
        // Release any dropped datagrams.
        //
        Dispatch->WskRelease(SocketContext->Socket, ReleaseChain);
    }

    return STATUS_PENDING;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{
    QUIC_UDP_SOCKET_CONTEXT* SocketContext = NULL;
    PWSK_DATAGRAM_INDICATION DataIndications = NULL;
    PWSK_DATAGRAM_INDICATION* DataIndicationTail = &DataIndications;

    LONG BatchedBufferCount = 0;
    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* BatchedInternalContext = NULL;

    QUIC_RECV_DATAGRAM* Datagram;
    while ((Datagram = DatagramChain) != NULL) {

        QUIC_DBG_ASSERT(Datagram->Allocated);
        QUIC_DBG_ASSERT(!Datagram->QueuedOnConnection);
        DatagramChain = DatagramChain->Next;

        QUIC_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalBufferContext =
            QuicDataPathDatagramToInternalDatagramContext(Datagram);
        QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext =
            InternalBufferContext->RecvContext;

        QUIC_DBG_ASSERT(SocketContext == NULL || SocketContext == InternalContext->SocketContext);
        SocketContext = InternalContext->SocketContext;
        Datagram->Allocated = FALSE;

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
                QUIC_DBG_ASSERT(BatchedInternalContext->DataIndication->Next == NULL);
                *DataIndicationTail = BatchedInternalContext->DataIndication;
                DataIndicationTail = &BatchedInternalContext->DataIndication->Next;

                QuicPoolFree(BatchedInternalContext->OwningPool, BatchedInternalContext);
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
        QUIC_DBG_ASSERT(BatchedInternalContext->DataIndication->Next == NULL);
        *DataIndicationTail = BatchedInternalContext->DataIndication;
        DataIndicationTail = &BatchedInternalContext->DataIndication->Next;

        QuicPoolFree(BatchedInternalContext->OwningPool, BatchedInternalContext);
    }

    if (DataIndications != NULL) {
        //
        // Return the datagram indications back to Wsk.
        //
        PWSK_PROVIDER_DATAGRAM_DISPATCH Dispatch =
            (PWSK_PROVIDER_DATAGRAM_DISPATCH)(SocketContext->Socket->Dispatch);
        Dispatch->WskRelease(SocketContext->Socket, DataIndications);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ UINT16 MaxPacketSize
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);

    QUIC_DATAPATH_PROC_CONTEXT* ProcContext =
        &Binding->Datapath->ProcContexts[QuicProcCurrentNumber()];

    QUIC_DATAPATH_SEND_CONTEXT* SendContext =
        QuicPoolAlloc(&ProcContext->SendContextPool);

    if (SendContext != NULL) {
        SendContext->Owner = ProcContext;
        SendContext->WskBufs = NULL;
        SendContext->TailBuf = NULL;
        SendContext->TotalSize = 0;
        SendContext->WskBufferCount = 0;
        SendContext->SegmentSize =
            (Binding->Datapath->Features & QUIC_DATAPATH_FEATURE_SEND_SEGMENTATION)
                ? MaxPacketSize : 0;
        SendContext->ClientBuffer.Length = 0;
        SendContext->ClientBuffer.Buffer = NULL;
    }

    return SendContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = SendContext->Owner;

    QUIC_POOL* BufferPool =
        SendContext->SegmentSize > 0 ?
            &ProcContext->LargeSendBufferPool : &ProcContext->SendBufferPool;

    while (SendContext->WskBufs != NULL) {
        PWSK_BUF_LIST WskBufList = SendContext->WskBufs;
        SendContext->WskBufs = SendContext->WskBufs->Next;
        QUIC_DBG_ASSERT(WskBufList->Buffer.Mdl->Next == NULL);

        QUIC_DATAPATH_SEND_BUFFER* SendBuffer =
            CONTAINING_RECORD(WskBufList, QUIC_DATAPATH_SEND_BUFFER, Link);

        QuicPoolFree(BufferPool, SendBuffer);
    }

    QuicPoolFree(&ProcContext->SendContextPool, SendContext);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
BOOLEAN
QuicSendContextCanAllocSendSegment(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0);
    QUIC_DBG_ASSERT(SendContext->WskBufferCount > 0);

    ULONG BytesAvailable =
        QUIC_LARGE_SEND_BUFFER_SIZE -
        (ULONG)SendContext->TailBuf->Link.Buffer.Length -
        SendContext->ClientBuffer.Length;

    return MaxBufferLength <= BytesAvailable;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
BOOLEAN
QuicSendContextCanAllocSend(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    return
        (SendContext->WskBufferCount < QUIC_MAX_BATCH_SEND) ||
        ((SendContext->SegmentSize > 0) &&
            QuicSendContextCanAllocSendSegment(SendContext, MaxBufferLength));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
QuicSendContextFinalizeSendBuffer(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    if (SendContext->ClientBuffer.Length == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendContext->WskBufferCount > 0) {
            SendContext->TotalSize +=
                (uint32_t)SendContext->TailBuf->Link.Buffer.Length;
        }
        return;
    }

    if (SendContext->SegmentSize == 0) {
        SendContext->TailBuf->Link.Buffer.Length = SendContext->ClientBuffer.Length;
        SendContext->ClientBuffer.Length = 0;
        return;
    }

    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0 && SendContext->WskBufferCount > 0);
    QUIC_DBG_ASSERT(SendContext->ClientBuffer.Length > 0 && SendContext->ClientBuffer.Length <= SendContext->SegmentSize);
    QUIC_DBG_ASSERT(QuicSendContextCanAllocSendSegment(SendContext, 0));

    //
    // Append the client's buffer segment to our internal send buffer.
    //
    SendContext->TailBuf->Link.Buffer.Length += SendContext->ClientBuffer.Length;
    SendContext->TotalSize += SendContext->ClientBuffer.Length;

    if (SendContext->ClientBuffer.Length == SendContext->SegmentSize) {
        SendContext->ClientBuffer.Buffer += SendContext->SegmentSize;
        SendContext->ClientBuffer.Length = 0;
    } else {
        //
        // The next segment allocation must create a new backing buffer.
        //
        SendContext->ClientBuffer.Buffer = NULL;
        SendContext->ClientBuffer.Length = 0;
    }
}

_IRQL_requires_same_
_Function_class_(ALLOCATE_FUNCTION_EX)
PVOID
QuicSendBufferPoolAlloc(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _Inout_ PLOOKASIDE_LIST_EX Lookaside
    )
{
    QUIC_DATAPATH_SEND_BUFFER* SendBuffer;

    UNREFERENCED_PARAMETER(Lookaside);
    QUIC_DBG_ASSERT(PoolType == NonPagedPoolNx);
    QUIC_DBG_ASSERT(NumberOfBytes > sizeof(*SendBuffer));

    SendBuffer = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
    if (SendBuffer == NULL) {
        return NULL;
    }

    //
    // Build the MDL for the entire buffer. The WSK_BUF's length will be updated
    // on each send.
    //
    SendBuffer->Link.Buffer.Offset = 0;
    SendBuffer->Link.Buffer.Mdl = &SendBuffer->Mdl;
    MmInitializeMdl(
        &SendBuffer->Mdl,
        SendBuffer->RawBuffer,
        NumberOfBytes - sizeof(*SendBuffer));
    MmBuildMdlForNonPagedPool(&SendBuffer->Mdl);

    return SendBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
UINT8*
QuicSendContextAllocBuffer(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_POOL* BufferPool
    )
{
    QUIC_DATAPATH_SEND_BUFFER* SendBuffer = QuicPoolAlloc(BufferPool);
    if (SendBuffer == NULL) {
        return NULL;
    }

    if (SendContext->WskBufs == NULL) {
        SendContext->WskBufs = &SendBuffer->Link;
    } else {
        SendContext->TailBuf->Link.Next = &SendBuffer->Link;
    }

    SendContext->TailBuf = SendBuffer;
    SendContext->TailBuf->Link.Next = NULL;
    ++SendContext->WskBufferCount;

    return SendBuffer->RawBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
static
QUIC_BUFFER*
QuicSendContextAllocPacketBuffer(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = SendContext->Owner;
    UINT8* Buffer;

    Buffer = QuicSendContextAllocBuffer(SendContext, &ProcContext->SendBufferPool);
    if (Buffer == NULL) {
        return NULL;
    }

    SendContext->ClientBuffer.Buffer = Buffer;
    SendContext->ClientBuffer.Length = MaxBufferLength;

    return &SendContext->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
static
QUIC_BUFFER*
QuicSendContextAllocSegmentBuffer(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendContext->SegmentSize > 0);
    QUIC_DBG_ASSERT(MaxBufferLength <= SendContext->SegmentSize);

    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = SendContext->Owner;
    UINT8* Buffer;

    if (SendContext->ClientBuffer.Buffer != NULL &&
        QuicSendContextCanAllocSendSegment(SendContext, MaxBufferLength)) {

        //
        // All clear to return the next segment of our contiguous buffer.
        //
        SendContext->ClientBuffer.Length = MaxBufferLength;
        return (QUIC_BUFFER*)&SendContext->ClientBuffer;
    }

    Buffer = QuicSendContextAllocBuffer(SendContext, &ProcContext->LargeSendBufferPool);
    if (Buffer == NULL) {
        return NULL;
    }

    //
    // Provide a virtual QUIC_BUFFER to the client. Once the client has committed
    // to a final send size, we'll append it to our internal backing buffer.
    //
    SendContext->TailBuf->Link.Buffer.Length = 0;
    SendContext->ClientBuffer.Buffer = Buffer;
    SendContext->ClientBuffer.Length = MaxBufferLength;

    return &SendContext->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
QuicDataPathBindingAllocSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ UINT16 MaxBufferLength
    )
{
    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_DBG_ASSERT(MaxBufferLength > 0);
    QUIC_DBG_ASSERT(MaxBufferLength <= QUIC_MAX_MTU - QUIC_MIN_IPV4_HEADER_SIZE - QUIC_UDP_HEADER_SIZE);

    QuicSendContextFinalizeSendBuffer(SendContext);

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
static
void
QuicSendContextFreeSendBuffer(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_POOL* BufferPool,
    _In_ QUIC_DATAPATH_SEND_BUFFER* SendBuffer
    )
{
    QUIC_DBG_ASSERT(SendBuffer->Link.Next == NULL);

    //
    // Remove the send buffer entry.
    //
    if (SendContext->WskBufs == &SendBuffer->Link) {
        SendContext->WskBufs = NULL;
        SendContext->TailBuf = NULL;
    } else {
        PWSK_BUF_LIST TailBuf = SendContext->WskBufs;
        while (TailBuf->Next != &SendBuffer->Link) {
            TailBuf = TailBuf->Next;
        }
        TailBuf->Next = NULL;
        SendContext->TailBuf = CONTAINING_RECORD(TailBuf, QUIC_DATAPATH_SEND_BUFFER, Link);
    }

    QuicPoolFree(BufferPool, SendBuffer);
    --SendContext->WskBufferCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingFreeSendDatagram(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext,
    _In_ QUIC_BUFFER* Datagram
    )
{
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext = SendContext->Owner;
    QUIC_DATAPATH_SEND_BUFFER* SendBuffer =
        CONTAINING_RECORD(&SendContext->TailBuf->Link, QUIC_DATAPATH_SEND_BUFFER, Link);

    UNREFERENCED_PARAMETER(Datagram);

    //
    // This must be the final send buffer; intermediate buffers cannot be freed.
    //
    QUIC_DBG_ASSERT(Datagram->Buffer != NULL);
    QUIC_DBG_ASSERT(Datagram->Buffer == SendContext->ClientBuffer.Buffer);

    if (SendContext->SegmentSize == 0) {
        QuicSendContextFreeSendBuffer(SendContext, &ProcContext->SendBufferPool, SendBuffer);
    } else {
        if (SendContext->TailBuf->Link.Buffer.Length == 0) {
            QuicSendContextFreeSendBuffer(SendContext, &ProcContext->LargeSendBufferPool, SendBuffer);
        }
    }

    SendContext->ClientBuffer.Buffer = NULL;
    SendContext->ClientBuffer.Length = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicDataPathBindingIsSendContextFull(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    return !QuicSendContextCanAllocSend(SendContext, SendContext->SegmentSize);
}

IO_COMPLETION_ROUTINE QuicDataPathSendComplete;

_Use_decl_annotations_
NTSTATUS
QuicDataPathSendComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    void* Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    QUIC_DATAPATH_SEND_CONTEXT* SendContext = Context;
    QUIC_DBG_ASSERT(SendContext != NULL);
    QUIC_UDP_SOCKET_CONTEXT* SocketContext = SendContext->SocketContext;

    if (!NT_SUCCESS(Irp->IoStatus.Status)) {
        QuicTraceEvent(DatapathErrorStatus, SocketContext->Binding,
            Irp->IoStatus.Status, "WskSendMessages completion");
    }

    IoCleanupIrp(&SendContext->Irp);
    QuicDataPathBindingFreeSendContext(SendContext);

    InterlockedDecrement(&SocketContext->Binding->SendOutstanding);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingPrepareSendContext(
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QuicSendContextFinalizeSendBuffer(SendContext);

    IoInitializeIrp(
        &SendContext->Irp,
        sizeof(SendContext->IrpBuffer),
        1);

    IoSetCompletionRoutine(
        &SendContext->Irp,
        QuicDataPathSendComplete,
        SendContext,
        TRUE,
        TRUE,
        TRUE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const SOCKADDR_INET * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_STATUS Status;
    QUIC_UDP_SOCKET_CONTEXT* SocketContext;
    PDWORD SegmentSize;

    QUIC_DBG_ASSERT(
        Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    if (!QuicRundownAcquire(&Binding->ClientRundown)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    //
    // Initialize IRP and MDLs for sending.
    //
    QuicDataPathBindingPrepareSendContext(SendContext);

    SocketContext = &Binding->SocketContext;
    SendContext->SocketContext = SocketContext;

    QuicTraceEvent(DatapathSendTo,
        Binding,
        SendContext->TotalSize,
        SendContext->WskBufferCount,
        SendContext->SegmentSize,
        LOG_ADDR_LEN(*RemoteAddress), (UINT8*)RemoteAddress);

    BYTE CMsgBuffer[WSA_CMSG_SPACE(sizeof(*SegmentSize))];
    PWSACMSGHDR CMsg = NULL;
    ULONG CMsgLen = 0;

    if (SendContext->SegmentSize > 0) {
        CMsg = (PWSACMSGHDR)CMsgBuffer;
        CMsgLen += WSA_CMSG_SPACE(sizeof(*SegmentSize));

        CMsg->cmsg_level = IPPROTO_UDP;
        CMsg->cmsg_type = UDP_SEND_MSG_SIZE;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(*SegmentSize));

        SegmentSize = (PDWORD)WSA_CMSG_DATA(CMsg);
        *SegmentSize = SendContext->SegmentSize;
    }

    InterlockedIncrement(&Binding->SendOutstanding);

    PWSK_PROVIDER_DATAGRAM_DISPATCH Dispatch =
        (PWSK_PROVIDER_DATAGRAM_DISPATCH)(SocketContext->Socket->Dispatch);

    Status =
        Dispatch->WskSendMessages(
            SocketContext->Socket,
            SendContext->WskBufs,
            0,
            NULL,
            CMsgLen,
            CMsg,
            &SendContext->Irp);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, SocketContext->Binding, Status, "WskSendMessages");
        //
        // Callback still gets invoked on failure to do the cleanup.
        //
    }

    Status = STATUS_SUCCESS;
    SendContext = NULL;

Exit:

    if (SendContext != NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDataPathBindingSendFromTo(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ const SOCKADDR_INET * LocalAddress,
    _In_ const SOCKADDR_INET * RemoteAddress,
    _In_ QUIC_DATAPATH_SEND_CONTEXT* SendContext
    )
{
    QUIC_STATUS Status;
    QUIC_UDP_SOCKET_CONTEXT* SocketContext;
    PDWORD SegmentSize;

    QUIC_DBG_ASSERT(
        Binding != NULL && LocalAddress != NULL &&
        RemoteAddress != NULL && SendContext != NULL);

    if (!QuicRundownAcquire(&Binding->ClientRundown)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Exit;
    }

    //
    // Initialize IRP and MDLs for sending.
    //
    QuicDataPathBindingPrepareSendContext(SendContext);

    SocketContext = &Binding->SocketContext;
    SendContext->SocketContext = SocketContext;

    QuicTraceEvent(DatapathSendFromTo,
        Binding,
        SendContext->TotalSize,
        SendContext->WskBufferCount,
        SendContext->SegmentSize,
        LOG_ADDR_LEN(*RemoteAddress), LOG_ADDR_LEN(*LocalAddress),
        (UINT8*)RemoteAddress, (UINT8*)LocalAddress);

    //
    // Map V4 address to dual-stack socket format.
    //
    SOCKADDR_INET MappedAddress = { 0 };
    QuicConvertToMappedV6(RemoteAddress, &MappedAddress);

    //
    // Build up message header to indicate local address to send from.
    //
    BYTE CMsgBuffer[WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) + WSA_CMSG_SPACE(sizeof(*SegmentSize))];
    PWSACMSGHDR CMsg = (PWSACMSGHDR)CMsgBuffer;
    ULONG CMsgLen;

    if (LocalAddress->si_family == AF_INET) {
        CMsgLen = WSA_CMSG_SPACE(sizeof(IN_PKTINFO));

        CMsg->cmsg_level = IPPROTO_IP;
        CMsg->cmsg_type = IP_PKTINFO;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));

        PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
        PktInfo->ipi_ifindex = LocalAddress->Ipv6.sin6_scope_id;
        PktInfo->ipi_addr = LocalAddress->Ipv4.sin_addr;

    } else {
        CMsgLen = WSA_CMSG_SPACE(sizeof(IN6_PKTINFO));

        CMsg->cmsg_level = IPPROTO_IPV6;
        CMsg->cmsg_type = IPV6_PKTINFO;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));

        PIN6_PKTINFO PktInfo6 = (PIN6_PKTINFO)WSA_CMSG_DATA(CMsg);
        PktInfo6->ipi6_ifindex = LocalAddress->Ipv6.sin6_scope_id;
        PktInfo6->ipi6_addr = LocalAddress->Ipv6.sin6_addr;
    }

    if (SendContext->SegmentSize > 0) {
        CMsg = (PWSACMSGHDR)&CMsgBuffer[CMsgLen];
        CMsgLen += WSA_CMSG_SPACE(sizeof(*SegmentSize));

        CMsg->cmsg_level = IPPROTO_UDP;
        CMsg->cmsg_type = UDP_SEND_MSG_SIZE;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(*SegmentSize));

        SegmentSize = (PDWORD)WSA_CMSG_DATA(CMsg);
        *SegmentSize = SendContext->SegmentSize;
    }

    InterlockedIncrement(&Binding->SendOutstanding);

    PWSK_PROVIDER_DATAGRAM_DISPATCH Dispatch =
        (PWSK_PROVIDER_DATAGRAM_DISPATCH)(SocketContext->Socket->Dispatch);

    Status =
        Dispatch->WskSendMessages(
            SocketContext->Socket,
            SendContext->WskBufs,
            0,
            (PSOCKADDR)&MappedAddress,
            CMsgLen,
            (PWSACMSGHDR)CMsgBuffer,
            &SendContext->Irp);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(DatapathErrorStatus, SocketContext->Binding, Status, "WskSendMessages");
        //
        // Callback still gets invoked on failure to do the cleanup.
        //
    }

    Status = STATUS_SUCCESS;
    SendContext = NULL;

Exit:

    if (SendContext != NULL) {
        QuicDataPathBindingFreeSendContext(SendContext);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicDataPathBindingSetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const UINT8 * Buffer
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
QuicDataPathBindingGetParam(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ uint32_t Param,
    _Inout_ PUINT32 BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}
