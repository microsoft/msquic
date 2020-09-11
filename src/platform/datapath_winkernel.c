/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (Kernel Mode)

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "datapath_winkernel.c.clog.h"
#endif

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

//
// The maximum allowed pending WSK buffers per proc before copying.
//
#define PENDING_BUFFER_LIMIT                256000

static_assert(
    sizeof(QUIC_BUFFER) == sizeof(WSABUF),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
static_assert(
    FIELD_OFFSET(QUIC_BUFFER, Length) == FIELD_OFFSET(WSABUF, len),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
static_assert(
    FIELD_OFFSET(QUIC_BUFFER, Buffer) == FIELD_OFFSET(WSABUF, buf),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");

typedef struct QUIC_DATAPATH_PROC_CONTEXT QUIC_DATAPATH_PROC_CONTEXT;

//
// Internal receive allocation context.
//
typedef struct QUIC_DATAPATH_INTERNAL_RECV_CONTEXT {

    //
    // The per proc context for this receive context.
    //
    QUIC_DATAPATH_PROC_CONTEXT* ProcContext;

    union {
        //
        // The start of the data buffer, or the cached data indication from wsk.
        //
        uint8_t* DataBufferStart;
        PWSK_DATAGRAM_INDICATION DataIndication;
    };

    QUIC_DATAPATH_BINDING* Binding;

    ULONG ReferenceCount;

    //
    // Contains the 4 tuple.
    //
    QUIC_TUPLE Tuple;

    int32_t DataIndicationSize;

    uint8_t DatagramPoolIndex   : 1;
    uint8_t BufferPoolIndex     : 1;
    uint8_t IsCopiedBuffer      : 1;
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

    QUIC_DATAPATH_BINDING* Binding;

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
    // The type of ECN markings needed for send.
    //
    QUIC_ECN_TYPE ECN;

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
    _In_opt_ void* Binding,
    _In_ ULONG Flags,
    _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication
    );

typedef struct _WSK_DATAGRAM_SOCKET {
    const WSK_PROVIDER_DATAGRAM_DISPATCH* Dispatch;
} WSK_DATAGRAM_SOCKET, * PWSK_DATAGRAM_SOCKET;

//
// Per-port state.
//
typedef struct QUIC_DATAPATH_BINDING {

    //
    // Parent datapath.
    //
    QUIC_DATAPATH* Datapath;

    //
    // UDP socket used for sending/receiving datagrams.
    //
    union {
        PWSK_SOCKET Socket;
        PWSK_DATAGRAM_SOCKET DgrmSocket;
    };

    //
    // Event used to wait for completion of socket functions.
    //
    QUIC_EVENT WskCompletionEvent;

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
    // Client context pointer.
    //
    void *ClientContext;

    //
    // The number of outstanding sends.
    //
    long volatile SendOutstanding;

    //
    // IRP used for socket functions.
    //
    union {
        IRP Irp;
        UCHAR IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    };

    QUIC_RUNDOWN_REF Rundown[0]; // Per-proc

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
    // on this core. Index 0 is regular, Index 1 is URO.
    //
    //
    QUIC_POOL RecvDatagramPools[2];

    //
    // Pool of receive data buffers. Index 0 is 4096, Index 1 is 65536.
    //
    QUIC_POOL RecvBufferPools[2];

    int64_t OutstandingPendingBytes;

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

#define QuicSendBufferPoolInitialize(Size, Tag, Pool) \
    ExInitializeLookasideListEx( \
        Pool, \
        QuicSendBufferPoolAlloc, \
        NULL, \
        NonPagedPoolNx, \
        0, \
        Size, \
        Tag, \
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
    UNREFERENCED_PARAMETER(Irp);

    QUIC_DBG_ASSERT(Context != NULL);
    KeSetEvent((KEVENT*)Context, IO_NO_INCREMENT, FALSE);

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
        QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[ udp] RSS helper socket failed to open, 0x%x",
            Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathOpenTcpSocketFailedAsync,
            "[ udp] RSS helper socket failed to open (async), 0x%x",
            Status);
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
        QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailed,
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailedAsync,
            "[ udp] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed (async), 0x%x",
            Status);
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
        QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[ udp] UDP send segmentation helper socket failed to open, 0x%x",
            Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathOpenUdpSocketFailedAsync,
            "[ udp] UDP send segmentation helper socket failed to open (async), 0x%x",
            Status);
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
            QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailed,
                "[ udp] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
                Status);
            break;
        }

        Status = Irp->IoStatus.Status;
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailedAsync,
                "[ udp] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x",
                Status);
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
            QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailed,
                "[ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
                Status);
            break;
        }

        Status = Irp->IoStatus.Status;
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailedAsync,
                "[ udp] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x",
                Status);
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
    WSK_EVENT_CALLBACK_CONTROL CallbackControl =
    {
        &NPI_WSK_INTERFACE_ID,
        WSK_EVENT_RECEIVE_FROM
    };

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
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH",
            DatapathLength);
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
            QUIC_POOL_GENERIC,
            &Datapath->ProcContexts[i].SendContextPool);

        QuicSendBufferPoolInitialize(
            sizeof(QUIC_DATAPATH_SEND_BUFFER) + MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].SendBufferPool);

        QuicSendBufferPoolInitialize(
            sizeof(QUIC_DATAPATH_SEND_BUFFER) + QUIC_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].LargeSendBufferPool);

        QuicPoolInitialize(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvDatagramPools[0]);

        QuicPoolInitialize(
            FALSE,
            UroDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvDatagramPools[1]);

        QuicPoolInitialize(
            FALSE,
            4096,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvBufferPools[0]);

        QuicPoolInitialize(
            FALSE,
            65536,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvBufferPools[1]);

        Datapath->ProcContexts[i].OutstandingPendingBytes = 0;
    }

    Status = WskRegister(&WskClientNpi, &Datapath->WskRegistration);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskRegister");
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
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskCaptureProviderNPI");
        goto Error;
    }

    Status =
        Datapath->WskProviderNpi.Dispatch->
        WskControlClient(
            Datapath->WskProviderNpi.Client,
            WSK_SET_STATIC_EVENT_CALLBACKS,
            sizeof(CallbackControl),
            &CallbackControl,
            0,
            NULL,
            NULL,
            NULL);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskControlClient WSK_SET_STATIC_EVENT_CALLBACKS");
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
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[0]);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[1]);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[0]);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[1]);
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
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[0]);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[1]);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[0]);
        QuicPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[1]);
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
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Unicode Hostname",
            UniHostName.MaximumLength);
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
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Convert hostname to unicode");
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

    QuicTraceEvent(
        LibraryError,
        "[ lib] ERROR, %s.",
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
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
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ WSK_CONTROL_SOCKET_TYPE RequestType,
    _In_ ULONG ControlCode,
    _In_ ULONG Level,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize)
         void* InputBuffer
    )
{
    IoReuseIrp(&Binding->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &Binding->Irp,
        QuicDataPathIoCompletion,
        &Binding->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(Binding->WskCompletionEvent);

    SIZE_T OutputSizeReturned;
    QUIC_STATUS Status =
        Binding->DgrmSocket->Dispatch->
        WskControlSocket(
            Binding->Socket,
            RequestType,
            ControlCode,
            Level,
            InputSize,
            InputBuffer,
            0,
            NULL,
            &OutputSizeReturned,
            &Binding->Irp);

    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(Binding->WskCompletionEvent);
        Status = Binding->Irp.IoStatus.Status;
    }

    return Status;
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
    size_t BindingSize;
    QUIC_DATAPATH_BINDING* Binding = NULL;
    uint32_t Option;

    if (Datapath == NULL || NewBinding == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    BindingSize =
        sizeof(QUIC_DATAPATH_BINDING) +
        QuicProcMaxCount() * sizeof(QUIC_RUNDOWN_REF);

    Binding = (QUIC_DATAPATH_BINDING*)QUIC_ALLOC_NONPAGED(BindingSize);
    if (Binding == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_DATAPATH_BINDING",
            BindingSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Must set output pointer first thing, as the receive path will try to
    // use the output.
    //
    *NewBinding = Binding;

    RtlZeroMemory(Binding, BindingSize);
    Binding->Datapath = Datapath;
    Binding->ClientContext = RecvCallbackContext;
    if (LocalAddress != NULL) {
        QuicConvertToMappedV6(LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.si_family = AF_INET6;
    }
    Binding->Mtu = QUIC_MAX_MTU;
    for (uint32_t i = 0; i < QuicProcMaxCount(); ++i) {
        QuicRundownInitialize(&Binding->Rundown[i]);
    }

    QuicEventInitialize(&Binding->WskCompletionEvent, FALSE, FALSE);
    IoInitializeIrp(
        &Binding->Irp,
        sizeof(Binding->IrpBuffer),
        1);
    IoSetCompletionRoutine(
        &Binding->Irp,
        QuicDataPathIoCompletion,
        &Binding->WskCompletionEvent,
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
            Binding,
            &Datapath->WskDispatch,
            NULL,
            NULL,
            NULL,
            &Binding->Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(Binding->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSocket");
        goto Error;
    }

    Status = Binding->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSocket completion");
        goto Error;
    }

    Binding->Socket = (PWSK_SOCKET)(Binding->Irp.IoStatus.Information);

    //
    // Enable Dual-Stack mode.
    //
    Option = FALSE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_V6ONLY,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_V6ONLY");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_DONTFRAGMENT,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_DONTFRAGMENT");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_DONTFRAG,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_DONTFRAG");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_PKTINFO,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_PKTINFO");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_PKTINFO,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_PKTINFO");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_RECVERR,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_RECVERR");
        goto Error;
    }

    Option = TRUE;
    Status =
        QuicDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_RECVERR,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_RECVERR");
        goto Error;
    }

    if (Datapath->Features & QUIC_DATAPATH_FEATURE_RECV_COALESCING) {
        Option = MAX_URO_PAYLOAD_LENGTH;
        Status =
            QuicDataPathSetControlSocket(
                Binding,
                WskSetOption,
                UDP_RECV_MAX_COALESCED_SIZE,
                IPPROTO_UDP,
                sizeof(Option),
                &Option);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set UDP_RECV_MAX_COALESCED_SIZE");
            goto Error;
        }
    }

    IoReuseIrp(&Binding->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &Binding->Irp,
        QuicDataPathIoCompletion,
        &Binding->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(Binding->WskCompletionEvent);

    Status =
        Binding->DgrmSocket->Dispatch->
        WskBind(
            Binding->Socket,
            (PSOCKADDR)&Binding->LocalAddress,
            0, // No flags
            &Binding->Irp
            );
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(Binding->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskBind");
        goto Error;
    }

    Status = Binding->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskBind completion");
        goto Error;
    }

    if (RemoteAddress) {
        SOCKADDR_INET MappedRemoteAddress = { 0 };
        QuicConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);

        Status =
            QuicDataPathSetControlSocket(
                Binding,
                WskIoctl,
                (ULONG)SIO_WSK_SET_REMOTE_ADDRESS,
                SOL_SOCKET,
                sizeof(MappedRemoteAddress),
                &MappedRemoteAddress);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set SIO_WSK_SET_REMOTE_ADDRESS");
            goto Error;
        }
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //

    IoReuseIrp(&Binding->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &Binding->Irp,
        QuicDataPathIoCompletion,
        &Binding->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    QuicEventReset(Binding->WskCompletionEvent);

    Status =
        Binding->DgrmSocket->Dispatch->
        WskGetLocalAddress(
            Binding->Socket,
            (PSOCKADDR)&Binding->LocalAddress,
            &Binding->Irp);
    if (Status == STATUS_PENDING) {
        QuicEventWaitForever(Binding->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskGetLocalAddress");
        goto Error;
    }

    Status = Binding->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskGetLocalAddress completion");
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDeleteComplete(
    _In_ QUIC_DATAPATH_BINDING* Binding
)
{
    IoCleanupIrp(&Binding->Irp);
    for (uint32_t i = 0; i < QuicProcMaxCount(); ++i) {
        QuicRundownUninitialize(&Binding->Rundown[i]);
    }
    QUIC_FREE(Binding);
}

IO_COMPLETION_ROUTINE QuicDataPathCloseSocketIoCompletion;

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
    NT_ASSERT(Context);

    if (Irp->PendingReturned) {
        QUIC_DATAPATH_BINDING* Binding = (QUIC_DATAPATH_BINDING*)Context;

#pragma prefast(suppress: 28182, "SAL doesn't understand how callbacks work.")
        if (QUIC_FAILED(Binding->Irp.IoStatus.Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Binding->Irp.IoStatus.Status,
                "WskCloseSocket completion");
        }

        QuicDataPathBindingDeleteComplete(Binding);
    }

    //
    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicDataPathBindingDelete(
    _In_ QUIC_DATAPATH_BINDING* Binding
    )
{
    QUIC_DBG_ASSERT(Binding != NULL);
    if (Binding->Socket != NULL) {

        for (uint32_t i = 0; i < QuicProcMaxCount(); ++i) {
            QuicRundownReleaseAndWait(&Binding->Rundown[i]);
        }

        IoReuseIrp(&Binding->Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            &Binding->Irp,
            QuicDataPathCloseSocketIoCompletion,
            Binding,
            TRUE,
            TRUE,
            TRUE);

        NTSTATUS Status =
            Binding->DgrmSocket->Dispatch->
            WskCloseSocket(
                Binding->Socket,
                &Binding->Irp);

        if (Status == STATUS_PENDING) {
            return; // The rest is handled asynchronously
        }

        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[ udp][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "WskCloseSocket");
        }
    }

    QuicDataPathBindingDeleteComplete(Binding);
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

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_DATAPATH_INTERNAL_RECV_CONTEXT*
QuicDataPathBindingAllocRecvContext(
    _In_ QUIC_DATAPATH* Datapath,
    _In_ UINT16 ProcIndex,
    _In_ BOOLEAN IsUro
    )
{
    QUIC_DBG_ASSERT(IsUro == 1 || IsUro == 0);
    QUIC_POOL* Pool = &Datapath->ProcContexts[ProcIndex].RecvDatagramPools[IsUro];

    QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext = QuicPoolAlloc(Pool);

    if (InternalContext != NULL) {
        InternalContext->DatagramPoolIndex = IsUro;
        InternalContext->ProcContext = &Datapath->ProcContexts[ProcIndex];
        InternalContext->DataBufferStart = NULL;
    }

    return InternalContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
PWSK_DATAGRAM_INDICATION
QuicDataPathFreeRecvContext(
    _In_ __drv_freesMem(Context) QUIC_DATAPATH_INTERNAL_RECV_CONTEXT* Context
    )
{
    PWSK_DATAGRAM_INDICATION DataIndication = NULL;
    if (Context->DataBufferStart != NULL) {
        if (Context->IsCopiedBuffer) {
            QuicPoolFree(
                &Context->ProcContext->RecvBufferPools[Context->BufferPoolIndex],
                Context->DataBufferStart);
        } else {
            DataIndication = Context->DataIndication;
            InterlockedAdd64(
                &Context->ProcContext->OutstandingPendingBytes,
                -Context->DataIndicationSize);
        }
    }

    QuicPoolFree(
        &Context->ProcContext->RecvDatagramPools[Context->DatagramPoolIndex],
        Context);
    return DataIndication;
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

    QUIC_DBG_ASSERT(Context != NULL);

    QUIC_DATAPATH_BINDING* Binding = (QUIC_DATAPATH_BINDING*)Context;

    uint32_t CurProcNumber = QuicProcCurrentNumber();
    if (!QuicRundownAcquire(&Binding->Rundown[CurProcNumber])) {
        return STATUS_DEVICE_NOT_READY;
    }

    PWSK_DATAGRAM_INDICATION ReleaseChain = NULL;
    PWSK_DATAGRAM_INDICATION* ReleaseChainTail = &ReleaseChain;
    QUIC_RECV_DATAGRAM* DatagramChain = NULL;
    QUIC_RECV_DATAGRAM** DatagramChainTail = &DatagramChain;

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
            QuicTraceLogWarning(
                DatapathDropEmptyMdl,
                "[%p] Dropping datagram with empty mdl.",
                Binding);
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
                    LocalAddr.Ipv6.sin6_port = Binding->LocalAddress.Ipv6.sin6_port;
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
                    LocalAddr.Ipv4.sin_port = Binding->LocalAddress.Ipv6.sin6_port;
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
            QuicTraceLogWarning(
                DatapathDropMissingInfo,
                "[%p] Dropping datagram missing IP_PKTINFO/IP_RECVERR.",
                Binding);
            goto Drop;
        }

        QuicConvertFromMappedV6(
            (SOCKADDR_INET*)DataIndication->RemoteAddress,
            &RemoteAddr);

        if (IsUnreachableError) {
#if QUIC_CLOG
            QuicTraceLogVerbose(
                DatapathUnreachable,
                "[sock][%p] Unreachable error from %!ADDR!",
                Binding,
                CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));
#endif

            QUIC_DBG_ASSERT(Binding->Datapath->UnreachableHandler);
            Binding->Datapath->UnreachableHandler(
                Binding,
                Binding->ClientContext,
                &RemoteAddr);

            goto Drop;
        }

        PMDL Mdl = DataIndication->Buffer.Mdl;
        ULONG MdlOffset = DataIndication->Buffer.Offset;
        SIZE_T DataLength = DataIndication->Buffer.Length;
        uint8_t* CurrentCopiedBuffer = NULL;

        if (MessageLength == 0) {
            //
            // If there was no explicit message length provided, then the entire
            // datagram constitutes a single message.
            //
            QUIC_DBG_ASSERT(DataLength <= MAXUINT16);
            if (DataLength > MAXUINT16) {
                QuicTraceLogWarning(
                    DatapathDropTooBig,
                    "[%p] Dropping datagram with too many bytes (%llu).",
                    Binding,
                    (uint64_t)DataLength);
                goto Drop;
            }
            MessageLength = (UINT16)DataLength;
        }

        if (!QuicMdlMapChain(DataIndication->Buffer.Mdl)) {
            QuicTraceLogWarning(
                DatapathDropMdlMapFailure,
                "[%p] Failed to map MDL chain",
                Binding);
            goto Drop;
        }

        QuicTraceEvent(
            DatapathRecv,
            "[ udp][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            Binding,
            (uint32_t)DataLength,
            MessageLength,
            CLOG_BYTEARRAY(sizeof(LocalAddr), &LocalAddr),
            CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));

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
                QuicTraceLogWarning(
                    DatapathFragmented,
                    "[%p] Dropping datagram with fragmented MDL.",
                    Binding);
                QUIC_DBG_ASSERT(FALSE);
                goto Drop;
            }

            if (RecvContext == NULL) {
                RecvContext =
                    QuicDataPathBindingAllocRecvContext(
                        Binding->Datapath,
                        (UINT16)CurProcNumber,
                        IsCoalesced);
                if (RecvContext == NULL) {
                    QuicTraceLogWarning(
                        DatapathDropAllocRecvContextFailure,
                        "[%p] Couldn't allocate receive context.",
                        Binding);
                    goto Drop;
                }

                if (RecvContext->ProcContext->OutstandingPendingBytes > PENDING_BUFFER_LIMIT) {
                    //
                    // Perform a copy
                    //
                    RecvContext->IsCopiedBuffer = TRUE;
                    RecvContext->BufferPoolIndex = DataLength > 4096 ? 1 : 0;
                    RecvContext->DataBufferStart =
                        (uint8_t*)QuicPoolAlloc(
                            &RecvContext->ProcContext->RecvBufferPools[RecvContext->BufferPoolIndex]);
                    if (RecvContext->DataBufferStart == NULL) {
                        QuicTraceLogWarning(
                            DatapathDropAllocRecvBufferFailure,
                            "[%p] Couldn't allocate receive buffers.",
                            Binding);
                        goto Drop;
                    }
                    CurrentCopiedBuffer = RecvContext->DataBufferStart;
                } else {
                    RecvContext->IsCopiedBuffer = FALSE;
                    RecvContext->DataIndication = DataIndication;
                    QUIC_DBG_ASSERT(DataIndication->Next == NULL);
                    RecvContext->DataIndicationSize = (int32_t)DataLength;
                    InterlockedAdd64(
                        &RecvContext->ProcContext->OutstandingPendingBytes,
                        RecvContext->DataIndicationSize);
                }

                RecvContext->Binding = Binding;
                RecvContext->ReferenceCount = 0;
                RecvContext->Tuple.LocalAddress = LocalAddr;
                RecvContext->Tuple.RemoteAddress = RemoteAddr;
                Datagram = (QUIC_RECV_DATAGRAM*)(RecvContext + 1);
            }

            QUIC_DBG_ASSERT(Datagram != NULL);
            Datagram->Next = NULL;
            Datagram->PartitionIndex = (uint8_t)CurProcNumber;
            Datagram->TypeOfService = 0; // TODO - Support ToS/ECN
            Datagram->Allocated = TRUE;
            Datagram->QueuedOnConnection = FALSE;

            InternalDatagramContext =
                QuicDataPathDatagramToInternalDatagramContext(Datagram);
            InternalDatagramContext->RecvContext = RecvContext;

            if (RecvContext->IsCopiedBuffer) {
                Datagram->Buffer = CurrentCopiedBuffer;
                QuicCopyMemory(Datagram->Buffer, (uint8_t*)Mdl->MappedSystemVa + MdlOffset, MessageLength);
                CurrentCopiedBuffer += MessageLength;
            } else {
                Datagram->Buffer = (uint8_t*)Mdl->MappedSystemVa + MdlOffset;
            }

            Datagram->BufferLength = MessageLength;
            Datagram->Tuple = &RecvContext->Tuple;

            //
            // Add the datagram to the end of the current chain.
            //
            *DatagramChainTail = Datagram;
            DatagramChainTail = &Datagram->Next;
            if (++RecvContext->ReferenceCount == URO_MAX_DATAGRAMS_PER_INDICATION) {
                QuicTraceLogWarning(
                    DatapathUroExceeded,
                    "[%p] Exceeded URO preallocation capacity.",
                    Binding);
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
                    Binding->Datapath->DatagramStride);
        }

    Drop:

        if (RecvContext != NULL && RecvContext->ReferenceCount == 0) {
            //
            // No receive buffers were generated, so clean up now and return the
            // indication back to WSK. If the reference count is nonzero, then
            // the indication will be returned only after the binding client has
            // returned the buffers.
            //
            PWSK_DATAGRAM_INDICATION FreeIndic =
                QuicDataPathFreeRecvContext(RecvContext);
            QUIC_DBG_ASSERT(FreeIndic == DataIndication);
            UNREFERENCED_PARAMETER(FreeIndic);
            RecvContext = NULL;
        }

        if (RecvContext == NULL || RecvContext->IsCopiedBuffer) {
            *ReleaseChainTail = DataIndication;
            ReleaseChainTail = &DataIndication->Next;
        }
    }

    if (DatagramChain != NULL) {
        //
        // Indicate all accepted datagrams.
        //
        Binding->Datapath->RecvHandler(
            Binding,
            Binding->ClientContext,
            DatagramChain);
    }

    if (ReleaseChain != NULL) {
        //
        // Release any dropped or copied datagrams.
        //
        Binding->DgrmSocket->Dispatch->WskRelease(Binding->Socket, ReleaseChain);
    }

    QuicRundownRelease(&Binding->Rundown[CurProcNumber]);

    return STATUS_PENDING;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicDataPathBindingReturnRecvDatagrams(
    _In_opt_ QUIC_RECV_DATAGRAM* DatagramChain
    )
{
    QUIC_DATAPATH_BINDING* Binding = NULL;
    PWSK_DATAGRAM_INDICATION DataIndication = NULL;
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

        QUIC_DBG_ASSERT(Binding == NULL || Binding == InternalContext->Binding);
        Binding = InternalContext->Binding;
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
                DataIndication =
                    QuicDataPathFreeRecvContext(BatchedInternalContext);

                if (DataIndication != NULL) {
                    QUIC_DBG_ASSERT(DataIndication->Next == NULL);
                    *DataIndicationTail = DataIndication;
                    DataIndicationTail = &DataIndication->Next;
                }
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
        DataIndication =
            QuicDataPathFreeRecvContext(BatchedInternalContext);

        if (DataIndication != NULL) {
            QUIC_DBG_ASSERT(DataIndication->Next == NULL);
            *DataIndicationTail = DataIndication;
            DataIndicationTail = &DataIndication->Next;
        }
    }

    if (DataIndications != NULL) {
        //
        // Return the datagram indications back to Wsk.
        //
        QUIC_DBG_ASSERT(Binding != NULL);
        Binding->DgrmSocket->Dispatch->WskRelease(Binding->Socket, DataIndications);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_DATAPATH_SEND_CONTEXT*
QuicDataPathBindingAllocSendContext(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ QUIC_ECN_TYPE ECN,
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
        SendContext->ECN = ECN;
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
    UNREFERENCED_PARAMETER(PoolType);
    QUIC_DBG_ASSERT(PoolType == NonPagedPoolNx);
    QUIC_DBG_ASSERT(NumberOfBytes > sizeof(*SendBuffer));

    //
    // ExAllocatePool2 requires a different set of flags, so the assert above must keep the pool sane.
    //
    SendBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, NumberOfBytes, Tag);
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
    QUIC_DATAPATH_BINDING* Binding = SendContext->Binding;

    if (!NT_SUCCESS(Irp->IoStatus.Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Irp->IoStatus.Status,
            "WskSendMessages completion");
    }

    IoCleanupIrp(&SendContext->Irp);
    QuicDataPathBindingFreeSendContext(SendContext);

    InterlockedDecrement(&Binding->SendOutstanding);

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
    PDWORD SegmentSize;

    QUIC_DBG_ASSERT(
        Binding != NULL && RemoteAddress != NULL && SendContext != NULL);

    //
    // Initialize IRP and MDLs for sending.
    //
    QuicDataPathBindingPrepareSendContext(SendContext);

    SendContext->Binding = Binding;

    QuicTraceEvent(
        DatapathSendTo,
        "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!",
        Binding,
        SendContext->TotalSize,
        SendContext->WskBufferCount,
        SendContext->SegmentSize,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress));

    BYTE CMsgBuffer[WSA_CMSG_SPACE(sizeof(*SegmentSize))];
    PWSACMSGHDR CMsg = NULL;
    ULONG CMsgLen = 0;

    // TODO - Use SendContext->ECN if not QUIC_ECN_NON_ECT

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

    Status =
        Binding->DgrmSocket->Dispatch->
        WskSendMessages(
            Binding->Socket,
            SendContext->WskBufs,
            0,
            NULL,
            CMsgLen,
            CMsg,
            &SendContext->Irp);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSendMessages");
        //
        // Callback still gets invoked on failure to do the cleanup.
        //
    }

    return STATUS_SUCCESS;
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
    PDWORD SegmentSize;

    QUIC_DBG_ASSERT(
        Binding != NULL && LocalAddress != NULL &&
        RemoteAddress != NULL && SendContext != NULL);

    //
    // Initialize IRP and MDLs for sending.
    //
    QuicDataPathBindingPrepareSendContext(SendContext);

    SendContext->Binding = Binding;

    QuicTraceEvent(
        DatapathSendFromTo,
        "[ udp][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        SendContext->TotalSize,
        SendContext->WskBufferCount,
        SendContext->SegmentSize,
        CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress),
        CLOG_BYTEARRAY(sizeof(*LocalAddress), LocalAddress));

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

    // TODO - Use SendContext->ECN if not QUIC_ECN_NON_ECT

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

    Status =
        Binding->DgrmSocket->Dispatch->
        WskSendMessages(
            Binding->Socket,
            SendContext->WskBufs,
            0,
            (PSOCKADDR)&MappedAddress,
            CMsgLen,
            (PWSACMSGHDR)CMsgBuffer,
            &SendContext->Irp);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[ udp][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSendMessages");
        //
        // Callback still gets invoked on failure to do the cleanup.
        //
    }

    return STATUS_SUCCESS;
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
