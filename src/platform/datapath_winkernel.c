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
#define MAX_URO_PAYLOAD_LENGTH              (UINT16_MAX - CXPLAT_UDP_HEADER_SIZE)

//
// 60K is the largest buffer most NICs can offload without any software
// segmentation. Current generation NICs advertise (60K < limit <= 64K).
//
#define CXPLAT_LARGE_SEND_BUFFER_SIZE         0xF000

//
// The maximum number of pages that memory allocated for our UDP payload
// buffers might span.
//
#define MAX_BUFFER_PAGE_USAGE               ((CXPLAT_LARGE_SEND_BUFFER_SIZE / PAGE_SIZE) + 2)

//
// The maximum size of the MDL to accomodate the maximum UDP payload buffer.
//
#define MDL_SIZE                            (sizeof(MDL) + (sizeof(PFN_NUMBER) * MAX_BUFFER_PAGE_USAGE))

//
// The maximum number of UDP datagrams that can be sent with one call.
//
#define CXPLAT_MAX_BATCH_SEND                 1

//
// The maximum number of UDP datagrams to preallocate for URO.
//
#define URO_MAX_DATAGRAMS_PER_INDICATION    64

//
// The maximum allowed pending WSK buffers per proc before copying.
//
#define PENDING_BUFFER_LIMIT                0

CXPLAT_STATIC_ASSERT(
    sizeof(QUIC_BUFFER) == sizeof(WSABUF),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_BUFFER, Length) == FIELD_OFFSET(WSABUF, len),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");
CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_BUFFER, Buffer) == FIELD_OFFSET(WSABUF, buf),
    "WSABUF is assumed to be interchangeable for QUIC_BUFFER");

typedef struct CXPLAT_DATAPATH_PROC_CONTEXT CXPLAT_DATAPATH_PROC_CONTEXT;

//
// Internal receive allocation context.
//
typedef struct CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT {

    //
    // The per proc context for this receive context.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext;

    union {
        //
        // The start of the data buffer, or the cached data indication from wsk.
        //
        uint8_t* DataBufferStart;
        PWSK_DATAGRAM_INDICATION DataIndication;
    };

    CXPLAT_SOCKET* Binding;

    ULONG ReferenceCount;

    //
    // Contains the network route.
    //
    CXPLAT_ROUTE Route;

    int32_t DataIndicationSize;

    uint8_t DatagramPoolIndex   : 1;
    uint8_t BufferPoolIndex     : 1;
    uint8_t IsCopiedBuffer      : 1;
} CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT;

BOOLEAN
CxPlatMdlMapChain(
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
            CXPLAT_DBG_ASSERT(Mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA);
        }
        CXPLAT_DBG_ASSERT(Mdl->MappedSystemVa != NULL);
    } while ((Mdl = Mdl->Next) != NULL);
    return TRUE;
}

//
// Internal receive buffer context.
//
typedef struct CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT {

    //
    // The internal receive context owning the data indication and allocation
    // chain.
    //
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext;

} CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT;

typedef struct CXPLAT_DATAPATH_SEND_BUFFER {

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

} CXPLAT_DATAPATH_SEND_BUFFER;

//
// Send context.
//
typedef struct CXPLAT_SEND_DATA {

    CXPLAT_SOCKET* Binding;

    //
    // The owning processor context.
    //
    CXPLAT_DATAPATH_PROC_CONTEXT* Owner;

    //
    // The IRP buffer for the async WskSendMessages call.
    //
    union {
        IRP Irp;
        UCHAR IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    };

    //
    // Contains the list of CXPLAT_DATAPATH_SEND_BUFFER.
    //
    PWSK_BUF_LIST WskBufs;

    //
    // The tail of the buffer list.
    //
    CXPLAT_DATAPATH_SEND_BUFFER* TailBuf;

    //
    // The total buffer size for WsaBuffers.
    //
    uint32_t TotalSize;

    //
    // The type of ECN markings needed for send.
    //
    CXPLAT_ECN_TYPE ECN;

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

} CXPLAT_SEND_DATA;

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
CxPlatDataPathSocketReceive(
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
typedef struct CXPLAT_SOCKET {

    //
    // Flag indicates the binding has a default remote destination.
    //
    BOOLEAN Connected : 1;

    //
    // Flag indicates the binding is being used for PCP.
    //
    BOOLEAN PcpBinding : 1;

    //
    // Parent datapath.
    //
    CXPLAT_DATAPATH* Datapath;

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
    CXPLAT_EVENT WskCompletionEvent;

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
    // IRP used for socket functions.
    //
    union {
        IRP Irp;
        UCHAR IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    };

    CXPLAT_RUNDOWN_REF Rundown[0]; // Per-proc

} CXPLAT_SOCKET;

//
// Represents the per-processor state of the datapath context.
//
typedef struct CXPLAT_DATAPATH_PROC_CONTEXT {

    //
    // Pool of send contexts to be shared by all sockets on this core.
    //
    CXPLAT_POOL SendDataPool;

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
    // on this core. Index 0 is regular, Index 1 is URO.
    //
    //
    CXPLAT_POOL RecvDatagramPools[2];

    //
    // Pool of receive data buffers. Index 0 is 4096, Index 1 is 65536.
    //
    CXPLAT_POOL RecvBufferPools[2];

    int64_t OutstandingPendingBytes;

} CXPLAT_DATAPATH_PROC_CONTEXT;

//
// Structure that maintains all the internal state for the
// CxPlatDataPath interface.
//
typedef struct CXPLAT_DATAPATH {

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
    // The UDP callback function pointers.
    //
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;

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
    CXPLAT_DATAPATH_PROC_CONTEXT ProcContexts[0];

} CXPLAT_DATAPATH;

_IRQL_requires_same_
_Function_class_(ALLOCATE_FUNCTION_EX)
PVOID
CxPlatSendBufferPoolAlloc(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _Inout_ PLOOKASIDE_LIST_EX Lookaside
    );

#define QuicSendBufferPoolInitialize(Size, Tag, Pool) \
    ExInitializeLookasideListEx( \
        Pool, \
        CxPlatSendBufferPoolAlloc, \
        NULL, \
        NonPagedPoolNx, \
        0, \
        Size, \
        Tag, \
        0)

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

IO_COMPLETION_ROUTINE CxPlatDataPathIoCompletion;

//
// Used for all WSK IoCompletion routines
//
_Use_decl_annotations_
QUIC_STATUS
CxPlatDataPathIoCompletion(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    void* Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    CXPLAT_DBG_ASSERT(Context != NULL);
    KeSetEvent((KEVENT*)Context, IO_NO_INCREMENT, FALSE);

    //
    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

void
CxPlatDataPathQueryRssScalabilityInfo(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    NTSTATUS Status;
    PWSK_SOCKET RssSocket = NULL;
    PWSK_PROVIDER_BASIC_DISPATCH Dispatch = NULL;
    SIZE_T OutputSizeReturned;
    RSS_SCALABILITY_INFO RssInfo = { 0 };

    CXPLAT_EVENT CompletionEvent;
    CxPlatEventInitialize(&CompletionEvent, FALSE, FALSE);

    uint8_t IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    PIRP Irp = (PIRP)IrpBuffer;

    CxPlatZeroMemory(Irp, sizeof(IrpBuffer));

    IoInitializeIrp(Irp, sizeof(IrpBuffer), 1);
    IoSetCompletionRoutine(
        Irp,
        CxPlatDataPathIoCompletion,
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
        CxPlatEventWaitForever(CompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathOpenTcpSocketFailed,
            "[data] RSS helper socket failed to open, 0x%x",
            Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathOpenTcpSocketFailedAsync,
            "[data] RSS helper socket failed to open (async), 0x%x",
            Status);
        goto Error;
    }

    RssSocket = (PWSK_SOCKET)(Irp->IoStatus.Information);
    Dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)(RssSocket->Dispatch);

    IoReuseIrp(Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        Irp,
        CxPlatDataPathIoCompletion,
        &CompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    CxPlatEventReset(CompletionEvent);

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
        CxPlatEventWaitForever(CompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailed,
            "[data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed, 0x%x",
            Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathQueryRssScalabilityInfoFailedAsync,
            "[data] Query for SIO_QUERY_RSS_SCALABILITY_INFO failed (async), 0x%x",
            Status);
        goto Error;
    }

    if (RssInfo.RssEnabled) {
        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_SIDE_SCALING;
    }

Error:

    if (RssSocket != NULL) {
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            CxPlatDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        CxPlatEventReset(CompletionEvent);
        Status = Dispatch->WskCloseSocket(RssSocket, Irp);
        CXPLAT_DBG_ASSERT(NT_SUCCESS(Status));
        if (Status == STATUS_PENDING) {
            CxPlatEventWaitForever(CompletionEvent);
        }
    }

    IoCleanupIrp(Irp);
}

VOID
CxPlatDataPathQuerySockoptSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    NTSTATUS Status;
    PWSK_SOCKET UdpSocket = NULL;
    PWSK_PROVIDER_BASIC_DISPATCH Dispatch = NULL;
    SIZE_T OutputSizeReturned;

    CXPLAT_EVENT CompletionEvent;
    CxPlatEventInitialize(&CompletionEvent, FALSE, FALSE);

    uint8_t IrpBuffer[sizeof(IRP) + sizeof(IO_STACK_LOCATION)];
    PIRP Irp = (PIRP)IrpBuffer;

    CxPlatZeroMemory(Irp, sizeof(IrpBuffer));

    IoInitializeIrp(Irp, sizeof(IrpBuffer), 1);
    IoSetCompletionRoutine(
        Irp,
        CxPlatDataPathIoCompletion,
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
        CxPlatEventWaitForever(CompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathOpenUdpSocketFailed,
            "[data] UDP send segmentation helper socket failed to open, 0x%x",
            Status);
        goto Error;
    }

    Status = Irp->IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            DatapathOpenUdpSocketFailedAsync,
            "[data] UDP send segmentation helper socket failed to open (async), 0x%x",
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
            CxPlatDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        CxPlatEventReset(CompletionEvent);

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
            CxPlatEventWaitForever(CompletionEvent);
        } else if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailed,
                "[data] Query for UDP_SEND_MSG_SIZE failed, 0x%x",
                Status);
            break;
        }

        Status = Irp->IoStatus.Status;
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                DatapathQueryUdpSendMsgFailedAsync,
                "[data] Query for UDP_SEND_MSG_SIZE failed (async), 0x%x",
                Status);
            break;
        }

        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION;

    } while (FALSE);

    do {
        DWORD UroMaxCoalescedMsgSize;

        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            CxPlatDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        CxPlatEventReset(CompletionEvent);

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
            CxPlatEventWaitForever(CompletionEvent);
        } else if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailed,
                "[data] Query for UDP_RECV_MAX_COALESCED_SIZE failed, 0x%x",
                Status);
            break;
        }

        Status = Irp->IoStatus.Status;
        if (QUIC_FAILED(Status)) {
            QuicTraceLogWarning(
                DatapathQueryRecvMaxCoalescedSizeFailedAsync,
                "[data] Query for UDP_RECV_MAX_COALESCED_SIZE failed (async), 0x%x",
                Status);
            break;
        }

        Datapath->Features |= CXPLAT_DATAPATH_FEATURE_RECV_COALESCING;

    } while (FALSE);

Error:

    if (UdpSocket != NULL) {
        IoReuseIrp(Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            Irp,
            CxPlatDataPathIoCompletion,
            &CompletionEvent,
            TRUE,
            TRUE,
            TRUE);
        CxPlatEventReset(CompletionEvent);
        Status = Dispatch->WskCloseSocket(UdpSocket, Irp);
        CXPLAT_DBG_ASSERT(NT_SUCCESS(Status));
        if (Status == STATUS_PENDING) {
            CxPlatEventWaitForever(CompletionEvent);
        }
    }

    IoCleanupIrp(Irp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _In_opt_ QUIC_EXECUTION_CONFIG* Config,
    _Out_ CXPLAT_DATAPATH* *NewDataPath
    )
{
    QUIC_STATUS Status;
    WSK_CLIENT_NPI WskClientNpi = { NULL, &WskAppDispatch };
    uint32_t DatapathLength;
    CXPLAT_DATAPATH* Datapath;
    BOOLEAN WskRegistered = FALSE;
    WSK_EVENT_CALLBACK_CONTROL CallbackControl =
    {
        &NPI_WSK_INTERFACE_ID,
        WSK_EVENT_RECEIVE_FROM
    };
    ULONG NoTdi = WSK_TDI_BEHAVIOR_BYPASS_TDI;

    UNREFERENCED_PARAMETER(TcpCallbacks);
    UNREFERENCED_PARAMETER(Config);

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

    DatapathLength =
        sizeof(CXPLAT_DATAPATH) +
        CxPlatProcMaxCount() * sizeof(CXPLAT_DATAPATH_PROC_CONTEXT);

    Datapath = CXPLAT_ALLOC_NONPAGED(DatapathLength, QUIC_POOL_DATAPATH);
    if (Datapath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            DatapathLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    RtlZeroMemory(Datapath, DatapathLength);
    if (UdpCallbacks) {
        Datapath->UdpHandlers = *UdpCallbacks;
    }
    Datapath->ClientRecvContextLength = ClientRecvContextLength;
    Datapath->ProcCount = (uint32_t)CxPlatProcMaxCount();
    Datapath->WskDispatch.WskReceiveFromEvent = CxPlatDataPathSocketReceive;
    Datapath->DatagramStride =
        ALIGN_UP(
            sizeof(CXPLAT_RECV_DATA) +
            sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT) +
            ClientRecvContextLength,
            PVOID);

    uint32_t RecvDatagramLength =
        sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT) +
        Datapath->DatagramStride;
    uint32_t UroDatagramLength =
        sizeof(CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT) +
        URO_MAX_DATAGRAMS_PER_INDICATION * Datapath->DatagramStride;

    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {

        CxPlatPoolInitialize(
            FALSE,
            sizeof(CXPLAT_SEND_DATA),
            QUIC_POOL_PLATFORM_SENDCTX,
            &Datapath->ProcContexts[i].SendDataPool);

        QuicSendBufferPoolInitialize(
            sizeof(CXPLAT_DATAPATH_SEND_BUFFER) + MAX_UDP_PAYLOAD_LENGTH,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].SendBufferPool);

        QuicSendBufferPoolInitialize(
            sizeof(CXPLAT_DATAPATH_SEND_BUFFER) + CXPLAT_LARGE_SEND_BUFFER_SIZE,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].LargeSendBufferPool);

        CxPlatPoolInitialize(
            FALSE,
            RecvDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvDatagramPools[0]);

        CxPlatPoolInitialize(
            FALSE,
            UroDatagramLength,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvDatagramPools[1]);

        CxPlatPoolInitialize(
            FALSE,
            4096,
            QUIC_POOL_DATA,
            &Datapath->ProcContexts[i].RecvBufferPools[0]);

        CxPlatPoolInitialize(
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
            WSK_TDI_BEHAVIOR,
            sizeof(NoTdi),
            &NoTdi,
            0,
            NULL,
            NULL,
            NULL);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WskControlClient WSK_TDI_BEHAVIOR");
        // We don't "goto Error;" here, because MSDN says that this may be removed
        // in the future, at which point it presumably won't be needed.
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

    CxPlatDataPathQueryRssScalabilityInfo(Datapath);
    CxPlatDataPathQuerySockoptSupport(Datapath);

    *NewDataPath = Datapath;

    goto Exit;

Error:

    if (WskRegistered) {
        WskDeregister(&Datapath->WskRegistration);
    }

    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendDataPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[0]);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[1]);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[0]);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[1]);
    }
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);

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

    WskReleaseProviderNPI(&Datapath->WskRegistration);
    WskDeregister(&Datapath->WskRegistration);
    for (uint32_t i = 0; i < Datapath->ProcCount; i++) {
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendDataPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].SendBufferPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].LargeSendBufferPool);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[0]);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvDatagramPools[1]);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[0]);
        CxPlatPoolUninitialize(&Datapath->ProcContexts[i].RecvBufferPools[1]);
    }
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);

    MIB_IPINTERFACE_TABLE* InterfaceTable = NULL;
    MIB_UNICASTIPADDRESS_TABLE* AddressTable = NULL;

    QUIC_STATUS Status = GetIpInterfaceTable(AF_UNSPEC, &InterfaceTable);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "GetIpInterfaceTable");
        goto Error;
    }

    Status = GetUnicastIpAddressTable(AF_UNSPEC, &AddressTable);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "GetUnicastIpAddressTable");
        goto Error;
    }

    *Addresses = CXPLAT_ALLOC_NONPAGED(AddressTable->NumEntries * sizeof(CXPLAT_ADAPTER_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
    if (*Addresses == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Addresses",
            AddressTable->NumEntries * sizeof(CXPLAT_ADAPTER_ADDRESS));
        goto Error;
    }
    *AddressesCount = (uint32_t)AddressTable->NumEntries;

    for (ULONG i = 0; i < AddressTable->NumEntries; ++i) {
        MIB_IPINTERFACE_ROW* Interface = NULL;
        for (ULONG j = 0; j < InterfaceTable->NumEntries; ++j) {
            if (InterfaceTable->Table[j].InterfaceIndex == AddressTable->Table[i].InterfaceIndex) {
                Interface = &InterfaceTable->Table[j];
                break;
            }
        }

        CXPLAT_ADAPTER_ADDRESS* AdapterAddress = &(*Addresses)[i];
        memcpy(&AdapterAddress->Address, &AddressTable->Table[i].Address, sizeof(QUIC_ADDR));
        AdapterAddress->InterfaceIndex = (uint32_t)AddressTable->Table[i].InterfaceIndex;
        AdapterAddress->InterfaceType = (uint16_t)AddressTable->Table[i].InterfaceLuid.Info.IfType;
        AdapterAddress->OperationStatus = Interface && Interface->Connected ? CXPLAT_OPERATION_STATUS_UP : CXPLAT_OPERATION_STATUS_DOWN;
    }

Error:

    if (AddressTable) {
        FreeMibTable(AddressTable);
    }

    if (InterfaceTable) {
        FreeMibTable(InterfaceTable);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *GatewayAddresses = NULL;
    *GatewayAddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddressWithHint(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ PUNICODE_STRING UniHostName,
    _In_ PADDRINFOEXW Hints,
    _Inout_ PADDRINFOEXW *Ai
    )
{
    QUIC_STATUS Status;

    CXPLAT_EVENT CompletionEvent;
    CxPlatEventInitialize(&CompletionEvent, FALSE, FALSE);

    PIRP Irp = IoAllocateIrp(1, FALSE);

    if (Irp == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    IoSetCompletionRoutine(
        Irp,
        CxPlatDataPathIoCompletion,
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
        CxPlatEventWaitForever(CompletionEvent);

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
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
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
    UniHostName.Buffer = CXPLAT_ALLOC_PAGED(UniHostName.MaximumLength, QUIC_POOL_PLATFORM_TMP_ALLOC);
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
        CxPlatDataPathResolveAddressWithHint(
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
        CxPlatDataPathResolveAddressWithHint(
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
        CXPLAT_FREE(UniHostName.Buffer, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
CxPlatDataPathSetControlSocket(
    _In_ CXPLAT_SOCKET* Binding,
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
        CxPlatDataPathIoCompletion,
        &Binding->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    CxPlatEventReset(Binding->WskCompletionEvent);

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
        CxPlatEventWaitForever(Binding->WskCompletionEvent);
        Status = Binding->Irp.IoStatus.Status;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewBinding
    )
{
    QUIC_STATUS Status = STATUS_SUCCESS;
    size_t BindingSize;
    CXPLAT_SOCKET* Binding = NULL;
    uint32_t Option;

    if (Datapath == NULL || NewBinding == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    BindingSize =
        sizeof(CXPLAT_SOCKET) +
        CxPlatProcMaxCount() * sizeof(CXPLAT_RUNDOWN_REF);

    Binding = (CXPLAT_SOCKET*)CXPLAT_ALLOC_NONPAGED(BindingSize, QUIC_POOL_SOCKET);
    if (Binding == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            BindingSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    //
    // Must set output pointer first thing, as the receive path will try to
    // use the output.
    //
    *NewBinding = Binding;

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Binding,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    RtlZeroMemory(Binding, BindingSize);
    Binding->Datapath = Datapath;
    Binding->ClientContext = Config->CallbackContext;
    Binding->Connected = (Config->RemoteAddress != NULL);
    if (Config->LocalAddress != NULL) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Binding->LocalAddress);
    } else {
        Binding->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Binding->Mtu = CXPLAT_MAX_MTU;
    for (uint32_t i = 0; i < CxPlatProcMaxCount(); ++i) {
        CxPlatRundownInitialize(&Binding->Rundown[i]);
    }
    if (Config->Flags & CXPLAT_SOCKET_FLAG_PCP) {
        Binding->PcpBinding = TRUE;
    }

    CxPlatEventInitialize(&Binding->WskCompletionEvent, FALSE, FALSE);
    IoInitializeIrp(
        &Binding->Irp,
        sizeof(Binding->IrpBuffer),
        1);
    IoSetCompletionRoutine(
        &Binding->Irp,
        CxPlatDataPathIoCompletion,
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
            Config->OwningProcess,
            NULL,
            NULL,
            &Binding->Irp);
    if (Status == STATUS_PENDING) {
        CxPlatEventWaitForever(Binding->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSocket");
        goto Error;
    }

    Status = Binding->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
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
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_V6ONLY,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_V6ONLY");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_DONTFRAGMENT,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_DONTFRAGMENT");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_DONTFRAG,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_DONTFRAG");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_PKTINFO,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_PKTINFO");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_PKTINFO,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_PKTINFO");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_ECN,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_ECN");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_ECN,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_ECN");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IPV6_RECVERR,
            IPPROTO_IPV6,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IPV6_RECVERR");
        goto Error;
    }

    Option = TRUE;
    Status =
        CxPlatDataPathSetControlSocket(
            Binding,
            WskSetOption,
            IP_RECVERR,
            IPPROTO_IP,
            sizeof(Option),
            &Option);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "Set IP_RECVERR");
        goto Error;
    }

    if (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) {
        Option = MAX_URO_PAYLOAD_LENGTH;
        Status =
            CxPlatDataPathSetControlSocket(
                Binding,
                WskSetOption,
                UDP_RECV_MAX_COALESCED_SIZE,
                IPPROTO_UDP,
                sizeof(Option),
                &Option);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set UDP_RECV_MAX_COALESCED_SIZE");
            goto Error;
        }
    }

    if (Config->InterfaceIndex != 0) {
        Option = (int)Config->InterfaceIndex;
        Status =
            CxPlatDataPathSetControlSocket(
                Binding,
                WskSetOption,
                IPV6_UNICAST_IF,
                IPPROTO_IPV6,
                sizeof(Option),
                &Option);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set IPV6_UNICAST_IF");
            goto Error;
        }
        Option = (int)RtlUlongByteSwap(Config->InterfaceIndex);
        Status =
            CxPlatDataPathSetControlSocket(
                Binding,
                WskSetOption,
                IP_UNICAST_IF,
                IPPROTO_IP,
                sizeof(Option),
                &Option);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "Set IP_UNICAST_IF");
            goto Error;
        }
    }

    IoReuseIrp(&Binding->Irp, STATUS_SUCCESS);
    IoSetCompletionRoutine(
        &Binding->Irp,
        CxPlatDataPathIoCompletion,
        &Binding->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    CxPlatEventReset(Binding->WskCompletionEvent);

    Status =
        Binding->DgrmSocket->Dispatch->
        WskBind(
            Binding->Socket,
            (PSOCKADDR)&Binding->LocalAddress,
            0, // No flags
            &Binding->Irp
            );
    if (Status == STATUS_PENDING) {
        CxPlatEventWaitForever(Binding->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskBind");
        goto Error;
    }

    Status = Binding->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskBind completion");
        goto Error;
    }

    if (Config->RemoteAddress) {
        SOCKADDR_INET MappedRemoteAddress = { 0 };
        CxPlatConvertToMappedV6(Config->RemoteAddress, &MappedRemoteAddress);

        Status =
            CxPlatDataPathSetControlSocket(
                Binding,
                WskIoctl,
                (ULONG)SIO_WSK_SET_REMOTE_ADDRESS,
                SOL_SOCKET,
                sizeof(MappedRemoteAddress),
                &MappedRemoteAddress);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
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
        CxPlatDataPathIoCompletion,
        &Binding->WskCompletionEvent,
        TRUE,
        TRUE,
        TRUE);
    CxPlatEventReset(Binding->WskCompletionEvent);

    Status =
        Binding->DgrmSocket->Dispatch->
        WskGetLocalAddress(
            Binding->Socket,
            (PSOCKADDR)&Binding->LocalAddress,
            &Binding->Irp);
    if (Status == STATUS_PENDING) {
        CxPlatEventWaitForever(Binding->WskCompletionEvent);
    } else if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskGetLocalAddress");
        goto Error;
    }

    Status = Binding->Irp.IoStatus.Status;

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskGetLocalAddress completion");
        goto Error;
    }

    if (Config->LocalAddress && Config->LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(Config->LocalAddress->Ipv4.sin_port == Binding->LocalAddress.Ipv4.sin_port);
    }

    CxPlatConvertFromMappedV6(&Binding->LocalAddress, &Binding->LocalAddress);

    if (Config->RemoteAddress != NULL) {
        Binding->RemoteAddress = *Config->RemoteAddress;
    } else {
        Binding->RemoteAddress.Ipv4.sin_port = 0;
    }

Error:

    if (QUIC_FAILED(Status)) {
        if (Binding != NULL) {
            CxPlatSocketDelete(Binding);
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
void
CxPlatSocketDeleteComplete(
    _In_ CXPLAT_SOCKET* Binding
)
{
    IoCleanupIrp(&Binding->Irp);
    for (uint32_t i = 0; i < CxPlatProcMaxCount(); ++i) {
        CxPlatRundownUninitialize(&Binding->Rundown[i]);
    }
    CXPLAT_FREE(Binding, QUIC_POOL_SOCKET);
}

IO_COMPLETION_ROUTINE CxPlatDataPathCloseSocketIoCompletion;

//
// Completion callbacks for IRP used with WskCloseSocket
//
_Use_decl_annotations_
QUIC_STATUS
CxPlatDataPathCloseSocketIoCompletion(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    void* Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NT_ASSERT(Context);

    if (Irp->PendingReturned) {
        CXPLAT_SOCKET* Binding = (CXPLAT_SOCKET*)Context;

#pragma prefast(suppress: 28182, "SAL doesn't understand how callbacks work.")
        if (QUIC_FAILED(Binding->Irp.IoStatus.Status)) {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Binding->Irp.IoStatus.Status,
                "WskCloseSocket completion");
        }

        CxPlatSocketDeleteComplete(Binding);
    }

    //
    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    //
    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Binding
    )
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
    QuicTraceEvent(
        DatapathDestroyed,
        "[data][%p] Destroyed",
        Binding);

    if (Binding->Socket != NULL) {

        for (uint32_t i = 0; i < CxPlatProcMaxCount(); ++i) {
            CxPlatRundownReleaseAndWait(&Binding->Rundown[i]);
        }

        IoReuseIrp(&Binding->Irp, STATUS_SUCCESS);
        IoSetCompletionRoutine(
            &Binding->Irp,
            CxPlatDataPathCloseSocketIoCompletion,
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
                "[data][%p] ERROR, %u, %s.",
                Binding,
                Status,
                "WskCloseSocket");
        }
    }

    CxPlatSocketDeleteComplete(Binding);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSocketSetContext(
    _In_ CXPLAT_SOCKET* Binding,
    _In_opt_ void* Context
    )
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
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
CxPlatSocketGetContext(
    _In_ CXPLAT_SOCKET* Binding
    )
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
    return Binding->ClientContext;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Binding
    )
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
    return Binding->Mtu;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Binding,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
    *Address = Binding->LocalAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Binding,
    _Out_ QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Binding != NULL);
    *Address = Binding->RemoteAddress;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT*
CxPlatSocketAllocRecvContext(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ UINT16 ProcIndex,
    _In_ BOOLEAN IsUro
    )
{
    CXPLAT_DBG_ASSERT(IsUro == 1 || IsUro == 0);
    CXPLAT_POOL* Pool = &Datapath->ProcContexts[ProcIndex].RecvDatagramPools[IsUro];

    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext = CxPlatPoolAlloc(Pool);

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
CxPlatDataPathFreeRecvContext(
    _In_ __drv_freesMem(Context) CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* Context
    )
{
    PWSK_DATAGRAM_INDICATION DataIndication = NULL;
    if (Context->DataBufferStart != NULL) {
        if (Context->IsCopiedBuffer) {
            CxPlatPoolFree(
                &Context->ProcContext->RecvBufferPools[Context->BufferPoolIndex],
                Context->DataBufferStart);
        } else {
            DataIndication = Context->DataIndication;
            InterlockedAdd64(
                &Context->ProcContext->OutstandingPendingBytes,
                -Context->DataIndicationSize);
        }
    }

    CxPlatPoolFree(
        &Context->ProcContext->RecvDatagramPools[Context->DatagramPoolIndex],
        Context);
    return DataIndication;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
QUIC_STATUS
NTAPI
CxPlatDataPathSocketReceive(
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

    CXPLAT_DBG_ASSERT(Context != NULL);

    CXPLAT_SOCKET* Binding = (CXPLAT_SOCKET*)Context;

    uint32_t CurProcNumber = CxPlatProcCurrentNumber();
    if (!CxPlatRundownAcquire(&Binding->Rundown[CurProcNumber])) {
        return STATUS_DEVICE_NOT_READY;
    }

    PWSK_DATAGRAM_INDICATION ReleaseChain = NULL;
    PWSK_DATAGRAM_INDICATION* ReleaseChainTail = &ReleaseChain;
    CXPLAT_RECV_DATA* RecvDataChain = NULL;
    CXPLAT_RECV_DATA** DatagramChainTail = &RecvDataChain;

    UNREFERENCED_PARAMETER(Flags);

    //
    // Process all the data indicated by the callback.
    //
    while (DataIndicationHead != NULL) {

        PWSK_DATAGRAM_INDICATION DataIndication = DataIndicationHead;
        DataIndicationHead = DataIndicationHead->Next;
        DataIndication->Next = NULL;

        CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* RecvContext = NULL;
        CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalDatagramContext;
        CXPLAT_RECV_DATA* Datagram = NULL;

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
        INT ECN = 0;

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
                    LocalAddr.si_family = QUIC_ADDRESS_FAMILY_INET6;
                    LocalAddr.Ipv6.sin6_addr = PktInfo6->ipi6_addr;
                    LocalAddr.Ipv6.sin6_port = Binding->LocalAddress.Ipv6.sin6_port;
                    CxPlatConvertFromMappedV6(&LocalAddr, &LocalAddr);
                    LocalAddr.Ipv6.sin6_scope_id = PktInfo6->ipi6_ifindex;
                    FoundLocalAddr = TRUE;

                } else if (CMsg->cmsg_type == IPV6_RECVERR) {
                    IN_RECVERR* RecvErr = (IN_RECVERR*)WSA_CMSG_DATA(CMsg);
                    if (RecvErr->type == ICMP6_DST_UNREACH) {
                        IsUnreachableError = TRUE;
                        break;
                    }
                } else if (CMsg->cmsg_type == IPV6_ECN) {
                    ECN = *(PINT)WSA_CMSG_DATA(CMsg);
                    CXPLAT_DBG_ASSERT(ECN < UINT8_MAX);
                }
            } else if (CMsg->cmsg_level == IPPROTO_IP) {
                if (CMsg->cmsg_type == IP_PKTINFO) {
                    PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
                    LocalAddr.si_family = QUIC_ADDRESS_FAMILY_INET;
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
                } else if (CMsg->cmsg_type == IP_ECN) {
                    ECN = *(PINT)WSA_CMSG_DATA(CMsg);
                    CXPLAT_DBG_ASSERT(ECN < UINT8_MAX);
                }
            } else if (CMsg->cmsg_level == IPPROTO_UDP) {
                if (CMsg->cmsg_type == UDP_COALESCED_INFO) {
                    CXPLAT_DBG_ASSERT(*(PDWORD)WSA_CMSG_DATA(CMsg) <= MAX_URO_PAYLOAD_LENGTH);
                    MessageLength = (UINT16)*(PDWORD)WSA_CMSG_DATA(CMsg);
                    IsCoalesced = TRUE;

                    CXPLAT_DBG_ASSERT(MessageLength > 0);
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

        CxPlatConvertFromMappedV6(
            (SOCKADDR_INET*)DataIndication->RemoteAddress,
            &RemoteAddr);

        if (IsUnreachableError) {
#if QUIC_CLOG
            QuicTraceLogVerbose(
                DatapathUnreachableMsg,
                "[sock][%p] Unreachable error from %!ADDR!",
                Binding,
                CASTED_CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));
#endif

            if (!Binding->PcpBinding) {
                CXPLAT_DBG_ASSERT(Binding->Datapath->UdpHandlers.Unreachable);
                Binding->Datapath->UdpHandlers.Unreachable(
                    Binding,
                    Binding->ClientContext,
                    &RemoteAddr);
            }

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
            CXPLAT_DBG_ASSERT(DataLength <= MAXUINT16);
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

        if (!CxPlatMdlMapChain(DataIndication->Buffer.Mdl)) {
            QuicTraceLogWarning(
                DatapathDropMdlMapFailure,
                "[%p] Failed to map MDL chain",
                Binding);
            goto Drop;
        }

        QuicTraceEvent(
            DatapathRecv,
            "[data][%p] Recv %u bytes (segment=%hu) Src=%!ADDR! Dst=%!ADDR!",
            Binding,
            (uint32_t)DataLength,
            MessageLength,
            CASTED_CLOG_BYTEARRAY(sizeof(LocalAddr), &LocalAddr),
            CASTED_CLOG_BYTEARRAY(sizeof(RemoteAddr), &RemoteAddr));

        for ( ; DataLength != 0; DataLength -= MessageLength) {

            CXPLAT_DBG_ASSERT(Mdl != NULL);
            CXPLAT_DBG_ASSERT(MdlOffset <= Mdl->ByteCount);

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
                CXPLAT_DBG_ASSERT(FALSE);
                goto Drop;
            }

            if (RecvContext == NULL) {
                RecvContext =
                    CxPlatSocketAllocRecvContext(
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

                if (RecvContext->ProcContext->OutstandingPendingBytes >= PENDING_BUFFER_LIMIT) {
                    //
                    // Perform a copy
                    //
                    RecvContext->IsCopiedBuffer = TRUE;
                    RecvContext->BufferPoolIndex = DataLength > 4096 ? 1 : 0;
                    RecvContext->DataBufferStart =
                        (uint8_t*)CxPlatPoolAlloc(
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
                    CXPLAT_DBG_ASSERT(DataIndication->Next == NULL);
                    RecvContext->DataIndicationSize = (int32_t)DataLength;
                    InterlockedAdd64(
                        &RecvContext->ProcContext->OutstandingPendingBytes,
                        RecvContext->DataIndicationSize);
                }

                RecvContext->Binding = Binding;
                RecvContext->ReferenceCount = 0;
                RecvContext->Route.LocalAddress = LocalAddr;
                RecvContext->Route.RemoteAddress = RemoteAddr;
                Datagram = (CXPLAT_RECV_DATA*)(RecvContext + 1);
            }

            CXPLAT_DBG_ASSERT(Datagram != NULL);
            Datagram->Next = NULL;
            Datagram->PartitionIndex = (uint8_t)CurProcNumber;
            Datagram->TypeOfService = (uint8_t)ECN;
            Datagram->Allocated = TRUE;
            Datagram->QueuedOnConnection = FALSE;

            InternalDatagramContext =
                CxPlatDataPathDatagramToInternalDatagramContext(Datagram);
            InternalDatagramContext->RecvContext = RecvContext;

            if (RecvContext->IsCopiedBuffer) {
                Datagram->Buffer = CurrentCopiedBuffer;
                CxPlatCopyMemory(Datagram->Buffer, (uint8_t*)Mdl->MappedSystemVa + MdlOffset, MessageLength);
                CurrentCopiedBuffer += MessageLength;
            } else {
                Datagram->Buffer = (uint8_t*)Mdl->MappedSystemVa + MdlOffset;
            }

            Datagram->BufferLength = MessageLength;
            Datagram->Route = &RecvContext->Route;

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

            Datagram = (CXPLAT_RECV_DATA*)
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
                CxPlatDataPathFreeRecvContext(RecvContext);
            CXPLAT_DBG_ASSERT(FreeIndic == DataIndication);
            UNREFERENCED_PARAMETER(FreeIndic);
            RecvContext = NULL;
        }

        if (RecvContext == NULL || RecvContext->IsCopiedBuffer) {
            *ReleaseChainTail = DataIndication;
            ReleaseChainTail = &DataIndication->Next;
        }
    }

    if (RecvDataChain != NULL) {
        //
        // Indicate all accepted datagrams.
        //
        if (!Binding->PcpBinding) {
            Binding->Datapath->UdpHandlers.Receive(
                Binding,
                Binding->ClientContext,
                RecvDataChain);
        } else {
            CxPlatPcpRecvCallback(
                Binding,
                Binding->ClientContext,
                RecvDataChain);
        }
    }

    if (ReleaseChain != NULL) {
        //
        // Release any dropped or copied datagrams.
        //
        Binding->DgrmSocket->Dispatch->WskRelease(Binding->Socket, ReleaseChain);
    }

    CxPlatRundownRelease(&Binding->Rundown[CurProcNumber]);

    return STATUS_PENDING;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    CXPLAT_SOCKET* Binding = NULL;
    PWSK_DATAGRAM_INDICATION DataIndication = NULL;
    PWSK_DATAGRAM_INDICATION DataIndications = NULL;
    PWSK_DATAGRAM_INDICATION* DataIndicationTail = &DataIndications;

    LONG BatchedBufferCount = 0;
    CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* BatchedInternalContext = NULL;

    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) {

        CXPLAT_DBG_ASSERT(Datagram->Allocated);
        CXPLAT_DBG_ASSERT(!Datagram->QueuedOnConnection);
        RecvDataChain = RecvDataChain->Next;

        CXPLAT_DATAPATH_INTERNAL_RECV_BUFFER_CONTEXT* InternalBufferContext =
            CxPlatDataPathDatagramToInternalDatagramContext(Datagram);
        CXPLAT_DATAPATH_INTERNAL_RECV_CONTEXT* InternalContext =
            InternalBufferContext->RecvContext;

        CXPLAT_DBG_ASSERT(Binding == NULL || Binding == InternalContext->Binding);
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
                    CxPlatDataPathFreeRecvContext(BatchedInternalContext);

                if (DataIndication != NULL) {
                    CXPLAT_DBG_ASSERT(DataIndication->Next == NULL);
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
            CxPlatDataPathFreeRecvContext(BatchedInternalContext);

        if (DataIndication != NULL) {
            CXPLAT_DBG_ASSERT(DataIndication->Next == NULL);
            *DataIndicationTail = DataIndication;
            DataIndicationTail = &DataIndication->Next;
        }
    }

    if (DataIndications != NULL) {
        //
        // Return the datagram indications back to Wsk.
        //
        CXPLAT_DBG_ASSERT(Binding != NULL);
        Binding->DgrmSocket->Dispatch->WskRelease(Binding->Socket, DataIndications);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ UINT16 MaxPacketSize,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    UNREFERENCED_PARAMETER(Route);
    CXPLAT_DBG_ASSERT(Binding != NULL);

    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext =
        &Binding->Datapath->ProcContexts[CxPlatProcCurrentNumber()];

    CXPLAT_SEND_DATA* SendData =
        CxPlatPoolAlloc(&ProcContext->SendDataPool);

    if (SendData != NULL) {
        SendData->Owner = ProcContext;
        SendData->ECN = ECN;
        SendData->WskBufs = NULL;
        SendData->TailBuf = NULL;
        SendData->TotalSize = 0;
        SendData->WskBufferCount = 0;
        SendData->SegmentSize =
            (Binding->Datapath->Features & CXPLAT_DATAPATH_FEATURE_SEND_SEGMENTATION)
                ? MaxPacketSize : 0;
        SendData->ClientBuffer.Length = 0;
        SendData->ClientBuffer.Buffer = NULL;
    }

    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = SendData->Owner;

    CXPLAT_POOL* BufferPool =
        SendData->SegmentSize > 0 ?
            &ProcContext->LargeSendBufferPool : &ProcContext->SendBufferPool;

    while (SendData->WskBufs != NULL) {
        PWSK_BUF_LIST WskBufList = SendData->WskBufs;
        SendData->WskBufs = SendData->WskBufs->Next;
        CXPLAT_DBG_ASSERT(WskBufList->Buffer.Mdl->Next == NULL);

        CXPLAT_DATAPATH_SEND_BUFFER* SendBuffer =
            CONTAINING_RECORD(WskBufList, CXPLAT_DATAPATH_SEND_BUFFER, Link);

        CxPlatPoolFree(BufferPool, SendBuffer);
    }

    CxPlatPoolFree(&ProcContext->SendDataPool, SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
BOOLEAN
CxPlatSendDataCanAllocSendSegment(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    if (!SendData->ClientBuffer.Buffer) {
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0);
    CXPLAT_DBG_ASSERT(SendData->WskBufferCount > 0);

    ULONG BytesAvailable =
        CXPLAT_LARGE_SEND_BUFFER_SIZE -
        (ULONG)SendData->TailBuf->Link.Buffer.Length -
        SendData->ClientBuffer.Length;

    return MaxBufferLength <= BytesAvailable;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
BOOLEAN
CxPlatSendDataCanAllocSend(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    return
        (SendData->WskBufferCount < CXPLAT_MAX_BATCH_SEND) ||
        ((SendData->SegmentSize > 0) &&
            CxPlatSendDataCanAllocSendSegment(SendData, MaxBufferLength));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static
void
CxPlatSendDataFinalizeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    if (SendData->ClientBuffer.Length == 0) {
        //
        // There is no buffer segment outstanding at the client.
        //
        if (SendData->WskBufferCount > 0) {
            SendData->TotalSize +=
                (uint32_t)SendData->TailBuf->Link.Buffer.Length;
        }
        return;
    }

    if (SendData->SegmentSize == 0) {
        SendData->TailBuf->Link.Buffer.Length = SendData->ClientBuffer.Length;
        SendData->TotalSize += SendData->ClientBuffer.Length;
        SendData->ClientBuffer.Length = 0;
        return;
    }

    CXPLAT_DBG_ASSERT(SendData->SegmentSize > 0 && SendData->WskBufferCount > 0);
    CXPLAT_DBG_ASSERT(SendData->ClientBuffer.Length > 0 && SendData->ClientBuffer.Length <= SendData->SegmentSize);
    CXPLAT_DBG_ASSERT(CxPlatSendDataCanAllocSendSegment(SendData, 0));

    //
    // Append the client's buffer segment to our internal send buffer.
    //
    SendData->TailBuf->Link.Buffer.Length += SendData->ClientBuffer.Length;
    SendData->TotalSize += SendData->ClientBuffer.Length;

    if (SendData->ClientBuffer.Length == SendData->SegmentSize) {
        SendData->ClientBuffer.Buffer += SendData->SegmentSize;
        SendData->ClientBuffer.Length = 0;
    } else {
        //
        // The next segment allocation must create a new backing buffer.
        //
        SendData->ClientBuffer.Buffer = NULL;
        SendData->ClientBuffer.Length = 0;
    }
}

_IRQL_requires_same_
_Function_class_(ALLOCATE_FUNCTION_EX)
PVOID
CxPlatSendBufferPoolAlloc(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _Inout_ PLOOKASIDE_LIST_EX Lookaside
    )
{
    CXPLAT_DATAPATH_SEND_BUFFER* SendBuffer;

    UNREFERENCED_PARAMETER(Lookaside);
    UNREFERENCED_PARAMETER(PoolType);
    CXPLAT_DBG_ASSERT(PoolType == NonPagedPoolNx);
    CXPLAT_DBG_ASSERT(NumberOfBytes > sizeof(*SendBuffer));

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
CxPlatSendDataAllocDataBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ CXPLAT_POOL* BufferPool
    )
{
    CXPLAT_DATAPATH_SEND_BUFFER* SendBuffer = CxPlatPoolAlloc(BufferPool);
    if (SendBuffer == NULL) {
        return NULL;
    }

    if (SendData->WskBufs == NULL) {
        SendData->WskBufs = &SendBuffer->Link;
    } else {
        SendData->TailBuf->Link.Next = &SendBuffer->Link;
    }

    SendData->TailBuf = SendBuffer;
    SendData->TailBuf->Link.Next = NULL;
    ++SendData->WskBufferCount;

    return SendBuffer->RawBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
static
QUIC_BUFFER*
CxPlatSendDataAllocPacketBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = SendData->Owner;
    UINT8* Buffer;

    Buffer = CxPlatSendDataAllocDataBuffer(SendData, &ProcContext->SendBufferPool);
    if (Buffer == NULL) {
        return NULL;
    }

    SendData->ClientBuffer.Buffer = Buffer;
    SendData->ClientBuffer.Length = MaxBufferLength;

    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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
        SendData->ClientBuffer.Length = MaxBufferLength;
        return (QUIC_BUFFER*)&SendData->ClientBuffer;
    }

    UINT8* Buffer = CxPlatSendDataAllocDataBuffer(SendData, &SendData->Owner->LargeSendBufferPool);
    if (Buffer == NULL) {
        return NULL;
    }

    //
    // Provide a virtual QUIC_BUFFER to the client. Once the client has committed
    // to a final send size, we'll append it to our internal backing buffer.
    //
    SendData->TailBuf->Link.Buffer.Length = 0;
    SendData->ClientBuffer.Buffer = Buffer;
    SendData->ClientBuffer.Length = MaxBufferLength;

    return &SendData->ClientBuffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ UINT16 MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);
    CXPLAT_DBG_ASSERT(MaxBufferLength <= CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE);

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
static
void
CxPlatSendDataFreeSendBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ CXPLAT_POOL* BufferPool,
    _In_ CXPLAT_DATAPATH_SEND_BUFFER* SendBuffer
    )
{
    CXPLAT_DBG_ASSERT(SendBuffer->Link.Next == NULL);

    //
    // Remove the send buffer entry.
    //
    if (SendData->WskBufs == &SendBuffer->Link) {
        SendData->WskBufs = NULL;
        SendData->TailBuf = NULL;
    } else {
        PWSK_BUF_LIST TailBuf = SendData->WskBufs;
        while (TailBuf->Next != &SendBuffer->Link) {
            TailBuf = TailBuf->Next;
        }
        TailBuf->Next = NULL;
        SendData->TailBuf = CONTAINING_RECORD(TailBuf, CXPLAT_DATAPATH_SEND_BUFFER, Link);
    }

    CxPlatPoolFree(BufferPool, SendBuffer);
    --SendData->WskBufferCount;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    CXPLAT_DATAPATH_PROC_CONTEXT* ProcContext = SendData->Owner;
    CXPLAT_DATAPATH_SEND_BUFFER* SendBuffer =
        CONTAINING_RECORD(&SendData->TailBuf->Link, CXPLAT_DATAPATH_SEND_BUFFER, Link);

    UNREFERENCED_PARAMETER(Buffer);

    //
    // This must be the final send buffer; intermediate buffers cannot be freed.
    //
    CXPLAT_DBG_ASSERT(Buffer->Buffer != NULL);
    CXPLAT_DBG_ASSERT(Buffer->Buffer == SendData->ClientBuffer.Buffer);

    if (SendData->SegmentSize == 0) {
        CxPlatSendDataFreeSendBuffer(SendData, &ProcContext->SendBufferPool, SendBuffer);
    } else {
        if (SendData->TailBuf->Link.Buffer.Length == 0) {
            CxPlatSendDataFreeSendBuffer(SendData, &ProcContext->LargeSendBufferPool, SendBuffer);
        }
    }

    SendData->ClientBuffer.Buffer = NULL;
    SendData->ClientBuffer.Length = 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return !CxPlatSendDataCanAllocSend(SendData, SendData->SegmentSize);
}

IO_COMPLETION_ROUTINE CxPlatDataPathSendComplete;

_Use_decl_annotations_
NTSTATUS
CxPlatDataPathSendComplete(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    void* Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    CXPLAT_SEND_DATA* SendData = Context;
    CXPLAT_DBG_ASSERT(SendData != NULL);
    CXPLAT_SOCKET* Binding = SendData->Binding;

    if (!NT_SUCCESS(Irp->IoStatus.Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Irp->IoStatus.Status,
            "WskSendMessages completion");
    }

    IoCleanupIrp(&SendData->Irp);
    CxPlatSendDataFree(SendData);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketPrepareSendData(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CxPlatSendDataFinalizeSendBuffer(SendData);

    IoInitializeIrp(
        &SendData->Irp,
        sizeof(SendData->IrpBuffer),
        1);

    IoSetCompletionRoutine(
        &SendData->Irp,
        CxPlatDataPathSendComplete,
        SendData,
        TRUE,
        TRUE,
        TRUE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Binding,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    QUIC_STATUS Status;
    PDWORD SegmentSize;

    UNREFERENCED_PARAMETER(IdealProcessor);
    CXPLAT_DBG_ASSERT(
        Binding != NULL && Route != NULL && SendData != NULL);

    //
    // Initialize IRP and MDLs for sending.
    //
    CxPlatSocketPrepareSendData(SendData);

    SendData->Binding = Binding;

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Binding,
        SendData->TotalSize,
        SendData->WskBufferCount,
        SendData->SegmentSize,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    //
    // Map V4 address to dual-stack socket format.
    //
    SOCKADDR_INET MappedAddress = { 0 };
    CxPlatConvertToMappedV6(&Route->RemoteAddress, &MappedAddress);

    //
    // Build up message header to indicate local address to send from.
    //
    BYTE CMsgBuffer[
        WSA_CMSG_SPACE(sizeof(IN6_PKTINFO)) +   // IP_PKTINFO
        WSA_CMSG_SPACE(sizeof(INT)) +           // IP_ECN
        WSA_CMSG_SPACE(sizeof(*SegmentSize))    // UDP_SEND_MSG_SIZE
        ];
    PWSACMSGHDR CMsg = (PWSACMSGHDR)CMsgBuffer;
    ULONG CMsgLen = 0;

    if (!Binding->Connected) {
        if (Route->LocalAddress.si_family == QUIC_ADDRESS_FAMILY_INET) {
            CMsgLen += WSA_CMSG_SPACE(sizeof(IN_PKTINFO));

            CMsg->cmsg_level = IPPROTO_IP;
            CMsg->cmsg_type = IP_PKTINFO;
            CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));

            PIN_PKTINFO PktInfo = (PIN_PKTINFO)WSA_CMSG_DATA(CMsg);
            PktInfo->ipi_ifindex = Route->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo->ipi_addr = Route->LocalAddress.Ipv4.sin_addr;

        } else {
            CMsgLen += WSA_CMSG_SPACE(sizeof(IN6_PKTINFO));

            CMsg->cmsg_level = IPPROTO_IPV6;
            CMsg->cmsg_type = IPV6_PKTINFO;
            CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));

            PIN6_PKTINFO PktInfo6 = (PIN6_PKTINFO)WSA_CMSG_DATA(CMsg);
            PktInfo6->ipi6_ifindex = Route->LocalAddress.Ipv6.sin6_scope_id;
            PktInfo6->ipi6_addr = Route->LocalAddress.Ipv6.sin6_addr;
        }
    }

    if (SendData->ECN != CXPLAT_ECN_NON_ECT) {
        CMsg = (PWSACMSGHDR)&CMsgBuffer[CMsgLen];
        CMsgLen += WSA_CMSG_SPACE(sizeof(INT));
        CMsg->cmsg_level =
            Route->LocalAddress.si_family == QUIC_ADDRESS_FAMILY_INET ?
                IPPROTO_IP : IPPROTO_IPV6;
        CMsg->cmsg_type = IP_ECN; // == IPV6_ECN
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(INT));

        *(PINT)WSA_CMSG_DATA(CMsg) = SendData->ECN;
    }

    if (SendData->SegmentSize > 0) {
        CMsg = (PWSACMSGHDR)&CMsgBuffer[CMsgLen];
        CMsgLen += WSA_CMSG_SPACE(sizeof(*SegmentSize));

        CMsg->cmsg_level = IPPROTO_UDP;
        CMsg->cmsg_type = UDP_SEND_MSG_SIZE;
        CMsg->cmsg_len = WSA_CMSG_LEN(sizeof(*SegmentSize));

        SegmentSize = (PDWORD)WSA_CMSG_DATA(CMsg);
        *SegmentSize = SendData->SegmentSize;
    }

    Status =
        Binding->DgrmSocket->Dispatch->
        WskSendMessages(
            Binding->Socket,
            SendData->WskBufs,
            0,
            Binding->Connected ? NULL : (PSOCKADDR)&MappedAddress,
            CMsgLen,
            (PWSACMSGHDR)CMsgBuffer,
            &SendData->Irp);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Binding,
            Status,
            "WskSendMessages");
        //
        // Callback still gets invoked on failure to do the cleanup.
        //
    }

    return STATUS_SUCCESS;
}
