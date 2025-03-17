/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC RDMA Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"
#include  "datapath_rdma_ring_buffer.h"
#include "ndstatus.h"
#include "ndsupport.h"

#ifdef QUIC_CLOG
#include "datapath_winuser.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses

//
// Maximum number of ND2_SGE objects in the pool per connection
//
#define MAX_SGE_POOL_SIZE 8192

//
// Maximum number of ND2_MANA_RESULT objects in the pool per connection
//
#define MAX_MANA_RESULT_POOL_SIZE 8192

//
// Maximum number of RDMA_CONNECTION objects in the pool per Adapter
//
#define MAX_RDMA_CONNECTION_POOL_SIZE 1024

//
// The maximum receive payload size.
//
#define MAX_RECV_PAYLOAD_LENGTH \
    (CXPLAT_MAX_MTU - CXPLAT_MIN_IPV4_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE)

//
// The maximum UDP receive coalescing payload.
//
#define MAX_URO_PAYLOAD_LENGTH (UINT16_MAX - CXPLAT_UDP_HEADER_SIZE)

//
// RDMA Adapter Context
//
typedef struct _RDMA_NDSPI_ADAPTER
{
    IND2Adapter*        Adapter;
    HANDLE              OverlappedFile;
    CXPLAT_POOL         ConnectionPool;
    CXPLAT_POOL         SendRingBufferPool;
    CXPLAT_POOL         RecvRingBufferPool;
    ND2_ADAPTER_INFO    AdapterInfo;
    OVERLAPPED          Ov;
} RDMA_NDSPI_ADAPTER;

//
// RDMA Listener Context
//
typedef struct _RDMA_NDSPI_LISTENER
{
    RDMA_NDSPI_ADAPTER* Adapter;
    HANDLE              OverlappedListenerFile;
    IND2Listener*       Listener;
    OVERLAPPED          Ov;
    CXPLAT_SOCKET*      ListenerSocket; // Socket associated with the listener
} RDMA_NDSPI_LISTENER;

//
// Enum to represent the state of the connection
//
typedef enum _RDMA_CONNECTION_STATE
{
    RdmaConnectionStateUninitialized = 0,
    RdmaConnectionStateRingBufferRegistered,
    RdmaConnectionStateConnecting,
    RdmaConnectionStateConnected,
    RdmaConnectionStateRingBufferInfoExchanged,
    RdmaConnectionStateClosing,
    RdmaConnectionStateClosed
} RDMA_CONNECTION_STATE;

//
// RDMA Connection Flags
//
#define RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED     0x00000001  // Offset Buffer Used, Ring buffer size > 64 KB
#define RDMA_CONNECTION_FLAG_SHARED_ENDPOINT        0x00000002  // Shared Endpoint
#define RDMA_CONNECTION_FLAG_SHARED_CQ              0x00000004  // Shared Completion Queue

//
// RDMA Connection Context
//
typedef struct _RDMA_NDSPI_CONNECTION {
    RDMA_NDSPI_ADAPTER*         Adapter;
    HANDLE                      OverlappedConnFile;
    IND2MemoryRegion*           MemoryRegion;
    IND2MemoryWindow*           MemoryWindow;
    IND2ManaCompletionQueue*    RecvCompletionQueue;
    IND2ManaCompletionQueue*    SendCompletionQueue;
    IND2ManaQueuePair*          QueuePair;
    IND2Connector*              Connector;
    RDMA_SEND_RING_BUFFER*      SendRingBuffer;
    RDMA_RECV_RING_BUFFER*      RecvRingBuffer;
    RDMA_RECV_RING_BUFFER*      PeerRingBuffer;
    RDMA_CONNECTION_STATE       State;
    OVERLAPPED                  Ov;
    CXPLAT_SOCKET*              Socket; // Socket associated with this connection
    ULONG                       Flags;
    CXPLAT_POOL                 SgePool;        
    CXPLAT_POOL                 ManaResultPool;
    uint8_t                     CibirIdLength;
    uint8_t                     CibirIdOffsetSrc;
    uint8_t                     CibirIdOffsetDst;  
    uint8_t                     CibirId[6];
} RDMA_CONNECTION;

typedef struct CXPLAT_SEND_DATA {
    CXPLAT_SEND_DATA_COMMON;

    QUIC_BUFFER Buffer;

} CXPLAT_SEND_DATA;

CXPLAT_EVENT_COMPLETION CxPlatIoRdmaRecvEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaSendEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaConnectEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaGetConnectionRequestEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaAcceptEventComplete;

QUIC_STATUS
CxPlatRdmaStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ const CXPLAT_RDMA_CONFIG* Config
    );

//
// Create an OverlappedfFile
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateOverlappedFile(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _Deref_out_ HANDLE* OverlappedFile
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (!NdAdapter || !NdAdapter->Adapter)
    {
        QuicTraceEvent(
            CreateOverlappedFileFailed,
            "CreateOverlappedFile failed, adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateOverlappedFile(NdAdapter->Adapter, OverlappedFile);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateOverlappedFileFailed,
            "CreateOverlappedFile failed, status:%d", Status);
    }

    return Status;
}

//
// Create a Memory Region
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateMemoryRegion(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _In_ HANDLE OverlappedFile,
    _Out_ IND2MemoryRegion** MemoryRegion
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *MemoryRegion = NULL;

    if (!NdAdapter || !NdAdapter->Adapter)
    {
        QuicTraceEvent(
            CreateMemoryRegionFailed,
            "CreateMemoryRegion failed, adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateMemoryRegion(
        NdAdapter->Adapter,
        &IID_IND2MemoryRegion,
        OverlappedFile,
        MemoryRegion);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateMemoryRegionFailed,
            "CreateMemoryRegion failed, status:%d", Status);
    }

    return Status;
}

//
// Register a Memory region
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiRegisterMemory(
    _In_ IND2MemoryRegion* MemoryRegion,
    _In_ void *Buffer,
    _In_ DWORD BufferLength,
    _In_ ULONG Flags,
    _In_ OVERLAPPED* Overlapped
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!MemoryRegion ||
        !Buffer ||
        !BufferLength ||
        !Overlapped)
    {
        QuicTraceEvent(
            RegisterDataBufferFailed,
            "RegisterDataBuffer failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = MemoryRegion->lpVtbl->Register(
        MemoryRegion,
        Buffer,
        BufferLength,
        Flags,
        Overlapped);

    if (Status == ND_PENDING)
    {
        Status = MemoryRegion->lpVtbl->GetOverlappedResult(
            MemoryRegion,
            Overlapped,
            TRUE);
    }

    return Status;
}

//
// DeRegister a Memory region
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiDeRegisterMemory(
    _In_ IND2MemoryRegion* MemoryRegion,
    _In_ OVERLAPPED* Overlapped
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!MemoryRegion || !Overlapped) {
        QuicTraceEvent(
            DeRegisterDataBufferFailed,
            "DeRegisterDataBuffer failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = MemoryRegion->lpVtbl->Deregister(MemoryRegion, Overlapped);
    if (Status == ND_PENDING)
    {
        Status = MemoryRegion->lpVtbl->GetOverlappedResult(MemoryRegion, Overlapped, TRUE);
    }

    return Status;
}

//
// Create a Memory Window
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateMemoryWindow(
     _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _Out_ IND2MemoryWindow **MemoryWindow
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *MemoryWindow = NULL;

    if (!NdAdapter || !NdAdapter->Adapter)
    {
        QuicTraceEvent(
            CreateMemoryWindowFailed,
            "CreateMemoryWindow failed, Adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateMemoryWindow(
        NdAdapter->Adapter,
        &IID_IND2MemoryWindow,
        MemoryWindow);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateMemoryWindowFailed,
            "CreateMemoryWindow failed, status:%d", Status);
    }

    return Status;
}

//
// Create a completion queue
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS 
NdspiCreateCompletionQueue(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _In_ HANDLE OverlappedFile,
    _In_ ULONG queueDepth,
    _In_ USHORT group,
    _In_ KAFFINITY affinity,
    _Deref_out_ IND2ManaCompletionQueue** CompletionQueue
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *CompletionQueue = NULL;

    if (!NdAdapter ||
        !NdAdapter->Adapter ||
        !queueDepth)
    {
        QuicTraceEvent(
            CreateCompletionQueueFailed,
            "CreateCompletionQueue failed, Adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateCompletionQueue(
        NdAdapter->Adapter,
        &IID_IND2ManaCompletionQueue,
        OverlappedFile,
        queueDepth,
        group,
        affinity,
        (VOID**)CompletionQueue);
}

//
// Create a connector
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateConnector(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _In_ HANDLE OverlappedFile,
    _Deref_out_ IND2Connector **Connector
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *Connector = NULL;

    if (!NdAdapter || !NdAdapter->Adapter)
    {
        QuicTraceEvent(
            CreateConnectorFailed,
            "CreateConnector failed, Adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateConnector(
        NdAdapter->Adapter,
        &IID_IND2Connector,
        OverlappedFile,
        (VOID**)Connector);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateConnectorFailed,
            "CreateConnector failed, status:%d", Status);
    }

    return Status;
}

//
// Create a listener
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateListener(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _In_ HANDLE OverlappedFile,
    _Deref_out_ IND2Listener** Listener
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *Listener = NULL;

    if (!NdAdapter ||
        !NdAdapter->Adapter)
    {
        QuicTraceEvent(
            CreateListenerFailed,
            "CreateListener failed, Adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateListener(
        NdAdapter->Adapter,
        &IID_IND2Listener,
        OverlappedFile,
        (VOID**)Listener);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateListenerFailed,
            "CreateListener failed, status:%d", Status);
    }

    return Status;
}

//
// Start a listener
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiStartListener(
    _In_ RDMA_NDSPI_LISTENER* NdListener,
    _In_bytecount_(AddressSize) const struct sockaddr* Address,
    _In_ ULONG AddressSize
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!NdListener ||
        !NdListener->Listener ||
        !Address ||
        !AddressSize)
    {
        QuicTraceEvent(
            StartListenerFailed,
            "StartListener failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = NdListener->Listener->lpVtbl->Bind(
        NdListener->Listener,
        Address,
        AddressSize);

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            StartListenerFailed,
            "StartListener Bind failed, status:%d", Status);
    }

    Status = NdListener->Listener->lpVtbl->Listen(
        NdListener->Listener,
        0);

    return Status;
}

//
// Create a queue pair
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateQueuePair(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _In_ IND2ManaCompletionQueue* ReceiveCompletionQueue,
    _In_ IND2ManaCompletionQueue* InitiatorCompletionQueue,
    _In_ VOID* Context,
    _In_ ULONG ReceiveQueueDepth,
    _In_ ULONG InitiatorQueueDepth,
    _In_ ULONG MaxReceiveRequestSge,
    _In_ ULONG MaxInitiatorRequestSge,
    _In_ ULONG InlineDataSize,
    _Deref_out_ IND2ManaQueuePair** QueuePair
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *QueuePair = NULL;

    if (!NdAdapter ||
        !NdAdapter->Adapter ||
        !ReceiveCompletionQueue ||
        !InitiatorCompletionQueue)
    {
        QuicTraceEvent(
            CreateQueuePairFailed,
            "CreateQueuePair failed, Adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateQueuePair(
        NdAdapter->Adapter,
        &IID_IND2ManaQueuePair,
        (IUnknown *)ReceiveCompletionQueue,
        (IUnknown *)InitiatorCompletionQueue,
        Context,
        ReceiveQueueDepth,
        InitiatorQueueDepth,
        MaxReceiveRequestSge,
        MaxInitiatorRequestSge,
        InlineDataSize,
        (VOID**)QueuePair);

    return Status;
}

//
// Accept a connection
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiAccept(
    _In_ IND2Connector* Connector,
    _In_ IND2ManaQueuePair *QueuePair,
    _In_ ULONG InboundReadLimit,
    _In_ ULONG OutboundReadLimit,
    _In_bytecount_(PrivateDataSize) const VOID* PrivateData,
    _In_ ULONG PrivateDataSize,
    _In_ OVERLAPPED Ov
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!Connector || !QueuePair ||
        !PrivateData || !PrivateDataSize)
    {
        QuicTraceEvent(
            AcceptFailed,
            "Accept failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = Connector->lpVtbl->Accept(
        Connector,
        (IUnknown *)QueuePair,
        InboundReadLimit,
        OutboundReadLimit,
        PrivateData,
        PrivateDataSize,
        &Ov);

    if (Status == ND_PENDING)
    {
        Status = Connector->lpVtbl->GetOverlappedResult(
            Connector,
            &Ov,
            TRUE);
    }

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            AcceptFailed,
            "Accept failed, status:%d", Status);
    }

    return Status;
}

//
// Perform a Bind
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiBind(
    _In_ IND2Connector* Connector,
    _In_bytecount_ (SrcAddressSize) const struct sockaddr* SrcAddress,
    _In_ ULONG SrcAddressSize)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!Connector ||
        !SrcAddress ||
        !SrcAddressSize)
    {
        QuicTraceEvent(
            BindFailed,
            "Bind failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Bind the connector to the source address
    //
    Status = Connector->lpVtbl->Bind(
        Connector,
        SrcAddress,
        SrcAddressSize);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            ConnectFailed,
            "Connect Bind failed, status:%d", Status);
        return Status;
    } 

    return Status;
}

//
// Perform a Bind for a listener
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiBindListener(
    _In_ IND2Listener* Listener,
    _In_bytecount_ (SrcAddressSize) const struct sockaddr* SrcAddress,
    _In_ ULONG SrcAddressSize)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!Listener ||
        !SrcAddress ||
        !SrcAddressSize)
    {
        QuicTraceEvent(
            BindListenerFailed,
            "BindListener failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Bind the listener to the source address
    //
    Status = Listener->lpVtbl->Bind(
        Listener,
        SrcAddress,
        SrcAddressSize);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            BindListenerFailed,
            "BindListener failed, status:%d", Status);
        return Status;
    }

    return Status;
}

//
// Perform a connect to a server
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiConnect(
    _In_ IND2Connector* Connector,
    _In_ IND2ManaQueuePair *QueuePair,
    _In_ OVERLAPPED Ov,
    _In_bytecount_ (SrcAddressSize) const struct sockaddr* SrcAddress,
    _In_ ULONG SrcAddressSize,
    _In_bytecount_ (DestAddressSize) const struct sockaddr* DestAddress,
    _In_ ULONG DestAddressSize,
    _In_ ULONG InboundReadLimit,
    _In_ ULONG OutboundReadLimit,
    _In_bytecount_(PrivateDataSize) const VOID* PrivateData,
    _In_ ULONG PrivateDataSize
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!Connector || !QueuePair ||
        !SrcAddress || !SrcAddressSize ||
        !DestAddress || !DestAddressSize ||
        !PrivateData || !PrivateDataSize)
    {
        QuicTraceEvent(
            ConnectFailed,
            "Connect failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }  

    //
    // Bind the connector to the source address
    //
    Status = Connector->lpVtbl->Bind(
        Connector,
        SrcAddress,
        SrcAddressSize);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            ConnectFailed,
            "Connect Bind failed, status:%d", Status);
        return Status;
    }

    //
    // Connect to the destination address
    //
    Status = Connector->lpVtbl->Connect(
        Connector,
        (IUnknown *)QueuePair,
        DestAddress,
        DestAddressSize,
        InboundReadLimit,
        OutboundReadLimit,
        PrivateData,
        PrivateDataSize,
        &Ov);
    if (Status == ND_PENDING)
    {
        Status = Connector->lpVtbl->GetOverlappedResult(
            Connector,
            &Ov,
            TRUE);
    }

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            ConnectFailed,
            "Connect failed, status:%d", Status);
    }

    return Status;
}

//
// Complete the connect to a server
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCompleteConnect(
    _In_ IND2Connector* Connector,
    _In_ OVERLAPPED Ov)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!Connector)
    {
        QuicTraceEvent(
            CompleteConnectFailed,
            "CompleteConnect failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = Connector->lpVtbl->CompleteConnect(
        Connector,
        &Ov);
    if (Status == ND_PENDING)
    {
        Status = Connector->lpVtbl->GetOverlappedResult(
            Connector,
            &Ov,
            TRUE);
    }

    if(QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CompleteConnectFailed,
            "CompleteConnect failed, status:%d", Status);
    }

    return Status;
}

//
// Bind a memory window to a buffer that is
// within the registered memory
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiBindMemoryWindow(
    _In_ IND2MemoryRegion* MemoryRegion,
    _In_ IND2ManaQueuePair* QueuePair,
    _In_ IND2MemoryWindow *MemoryWindow,
    _In_ void *Context,
    _In_bytecount_(cbBuffer) const VOID* Buffer,
    _In_ SIZE_T BufferSize,
    _In_ ULONG Flags
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!MemoryRegion ||
        !QueuePair ||
        !MemoryWindow ||
        !Buffer ||
        !BufferSize)
    {
        QuicTraceEvent(
            BindMemoryWindowFailed,
            "BindMemoryWindow failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = QueuePair->lpVtbl->Bind(
        QueuePair,
        Context,
        (IUnknown *)MemoryRegion,
        (IUnknown *)MemoryWindow,
        Buffer,
        BufferSize,
        Flags);

    return Status;
}

//
// Invalidate a Memory Window
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiInvalidateMemoryWindow(
    _In_ IND2ManaQueuePair* QueuePair,
    _In_ IND2MemoryWindow *MemoryWindow,
    _In_ void *Context,
    _In_ ULONG Flags
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!QueuePair ||
        !MemoryWindow)
    {
        QuicTraceEvent(
            InvalidateMemoryWindowFailed,
            "InvalidateMemoryWindow failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = QueuePair->lpVtbl->Invalidate(
        QueuePair,
        Context,
        (IUnknown *)MemoryWindow,
        Flags);

    return Status;
}


//
// RDMA Write
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiWrite(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ UINT64 RemoteAddress,
    _In_ UINT32 RemoteToken,
    _In_ ULONG Flags
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize ||
        !RemoteAddress || !RemoteToken)
    {
        QuicTraceEvent(
            NdspiWriteFailed,
            "Ndspi Write Failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->Write(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize,
        RemoteAddress,
        RemoteToken,
        Flags);

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            NDSPIWriteFailed,
            "NDSPI Write failed, status:%d", Status);
    }

    return Status;
}

//
// RDMA Write with immediate
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiWriteWithImmediate(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ UINT64 RemoteAddress,
    _In_ UINT32 RemoteToken,
    _In_ ULONG Flags,
    _In_ UINT32 ImmediateData
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize ||
        !RemoteAddress ||
        !RemoteToken ||
        !ImmediateData)
    {
        QuicTraceEvent(
            NdspiWriteWithImmediateFailed,
            "Ndspi WriteWithImmediate Failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->WriteWithImmediate(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize,
        RemoteAddress,
        RemoteToken,
        Flags,
        ImmediateData);

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            NDSPIWriteWithImmediateFailed,
            "NDSPI WriteWithImmediate failed, status:%d", Status);
    }

    return Status;
}

//
// RDMA Read
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiRead(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ UINT64 RemoteAddress,
    _In_ UINT32 RemoteToken,
    _In_ ULONG Flags,
    _In_ UINT32 ImmediateData
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize ||
        !RemoteAddress ||
        !RemoteToken ||
        !ImmediateData)
    {
        QuicTraceEvent(
            NdspiReadFailed,
            "Ndspi Read Failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->Read(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize,
        RemoteAddress,
        RemoteToken,
        Flags);

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            NDSPIReadFailed,
            "NDSPI Read failed, status:%d", Status);
    }

    return Status;
}

//
// RDMA Send
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiSend(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ ULONG Flags
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize)
    {
        QuicTraceEvent(
            NdspiSendFailed,
            "Ndspi Send Failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->Send(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize,
        Flags);

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            NDSPIReadFailed,
            "NDSPI Send failed, status:%d", Status);
    }

    return Status;
}

//
// Post RDMA Receive
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiPostReceive(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize)
    {
        QuicTraceEvent(
            NdspiPostReceiveFailed,
            "Ndspi PostReceive Failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->Receive(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize);

    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            NDSPIPostReceiveFailed,
            "NDSPI PostReceive failed, status:%d", Status);
    }

    return Status;
}

//
// Creates an RDMA  Initialization context
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaAdapterInitialize(
    _In_ const QUIC_ADDR*           LocalAddress,
    _Out_ void**                    Adapter           
    )

{
    *Adapter = NULL;

    SOCKADDR sockAddr = {0};
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    RDMA_NDSPI_ADAPTER* RdmaAdapter = NULL;

    if (LocalAddress->si_family == AF_INET) {
        // IPv4 address
        const SOCKADDR_IN* sockAddrIn = &LocalAddress->Ipv4;
        memcpy(&sockAddr, sockAddrIn, sizeof(SOCKADDR_IN));
    }
    else
    {
        // IPv6 address
        const SOCKADDR_IN6* sockAddrIn6 = &LocalAddress->Ipv6;
        memcpy(&sockAddr, sockAddrIn6, sizeof(SOCKADDR_IN6));
    }

    RdmaAdapter = (RDMA_NDSPI_ADAPTER*)CXPLAT_ALLOC_PAGED(sizeof(RDMA_NDSPI_ADAPTER), QUIC_POOL_DATAPATH);
    if (RdmaAdapter == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(RDMA_NDSPI_ADAPTER));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    Status = NdOpenAdapter(
        &IID_IND2Adapter,
        &sockAddr,
        sizeof(sockAddr),
        &RdmaAdapter->Adapter);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            NdOpenAdapterFailed,
            "NdOpenAdapter failed, status:%d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateOverlappedFile(RdmaAdapter, &RdmaAdapter->OverlappedFile);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            CreateAdapterOverlappedFileFailed,
            "CreateAdapterOverlappedFile failed, status:%d", Status);
        goto ErrorExit;
    }

    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(RDMA_CONNECTION),
        QUIC_POOL_SOCKET,
        MAX_RDMA_CONNECTION_POOL_SIZE,
        NULL,
        NULL,
        &RdmaAdapter->ConnectionPool);
    
    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(RDMA_SEND_RING_BUFFER),
        QUIC_POOL_SOCKET,
        MAX_RDMA_CONNECTION_POOL_SIZE,
        NULL,
        NULL,
        &RdmaAdapter->SendRingBufferPool);

    //
    // Populate the Adapter Info to get MAX values supported
    // for the adapter
    //
    ULONG AdapterInfoSize = sizeof(RdmaAdapter->AdapterInfo);
    Status = RdmaAdapter->Adapter->lpVtbl->Query(
        RdmaAdapter->Adapter,
        &RdmaAdapter->AdapterInfo,
        &AdapterInfoSize);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            QueryAdapterInfoFailed,
            "QueryAdapterInfo failed, status:%d", Status);
        goto ErrorExit;
    }

    return Status;

ErrorExit:

    CxPlatRdmaAdapterRelease(RdmaAdapter);

    return Status;
}

//
// Cleanup an RDMA context
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaAdapterRelease(
    _In_ void* Adapter)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    RDMA_NDSPI_ADAPTER* NdAdapter = (RDMA_NDSPI_ADAPTER*) Adapter;
    if (NdAdapter)
    {
        if (NdAdapter->Adapter)
        {
            NdAdapter->Adapter->lpVtbl->Release(NdAdapter->Adapter);
        }

        if (NdAdapter->OverlappedFile)
        {
            CloseHandle(NdAdapter->OverlappedFile);
        }

        CxPlatPoolUninitialize(&NdAdapter->ConnectionPool);
        CxPlatPoolUninitialize(&NdAdapter->SendRingBufferPool);
        CxPlatPoolUninitialize(&NdAdapter->RecvRingBufferPool);

        CXPLAT_FREE(NdAdapter, QUIC_POOL_DATAPATH);
    }

    return Status;
}



//
// Free Child Objects allocated within an RDMA_CONNECTION object
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
RdmaConnectionFree(
    _In_ RDMA_CONNECTION* RdmaConnection
)
{
    if (!RdmaConnection)
    {
        return;
    }
    
    if (RdmaConnection->QueuePair)
    {
        RdmaConnection->QueuePair->lpVtbl->Release(RdmaConnection->QueuePair);
    }

    if (RdmaConnection->RecvCompletionQueue)
    {
        RdmaConnection->RecvCompletionQueue->lpVtbl->Release(RdmaConnection->RecvCompletionQueue);
    }

    if (RdmaConnection->SendCompletionQueue)
    {
        RdmaConnection->SendCompletionQueue->lpVtbl->Release(RdmaConnection->SendCompletionQueue);
    }

    if (RdmaConnection->Connector)
    {
        RdmaConnection->Connector->lpVtbl->Release(RdmaConnection->Connector);
    }

    if (RdmaConnection->MemoryWindow)
    {
        RdmaConnection->MemoryWindow->lpVtbl->Release(RdmaConnection->MemoryWindow);
    }

    if (RdmaConnection->MemoryRegion)
    {
        RdmaConnection->MemoryRegion->lpVtbl->Release(RdmaConnection->MemoryRegion);
    }

    if (RdmaConnection->SendRingBuffer)
    {
        CxPlatPoolFree(&RdmaConnection->Adapter->SendRingBufferPool, RdmaConnection->SendRingBuffer);
    }

    if (RdmaConnection->RecvRingBuffer)
    {
        CxPlatPoolFree(&RdmaConnection->Adapter->RecvRingBufferPool, RdmaConnection->RecvRingBuffer);
    }

    if (RdmaConnection->PeerRingBuffer)
    {
        CxPlatPoolFree(&RdmaConnection->Adapter->RecvRingBufferPool, RdmaConnection->PeerRingBuffer);
    }

    CxPlatPoolUninitialize(&RdmaConnection->SgePool);

    CxPlatPoolUninitialize(&RdmaConnection->ManaResultPool);
    //
    // Free the connection
    //
    RDMA_NDSPI_ADAPTER* RdmaAdapter = RdmaConnection->Adapter;
    CXPLAT_DBG_ASSERT(RdmaAdapter != NULL);

    CxPlatPoolFree(&RdmaAdapter->ConnectionPool, RdmaConnection);
}

//
// Free Child Objects allocated within an RDMA_CONNECTION object
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
RdmaListenerFree(
    _In_ RDMA_NDSPI_LISTENER* RdmaListener
)
{
    if (!RdmaListener)
    {
        return;
    }

    if (RdmaListener->Listener)
    {
        RdmaListener->Listener->lpVtbl->Release(RdmaListener->Listener);
    }

    if (RdmaListener->OverlappedListenerFile)
    {
        CloseHandle(RdmaListener->OverlappedListenerFile);
    }

    CXPLAT_FREE(RdmaListener, QUIC_POOL_DATAPATH);
}

//
// Free Child Objects allocated within an RDMA_CONNECTION object
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ const CXPLAT_RDMA_CONFIG* Config
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!ListenerSocketProc ||
        !ListenerSocketProc->Parent ||
        !ListenerSocketProc->Parent->Datapath ||
        !ListenerSocketProc->Parent->RdmaContext ||
        !Config)
    {
        QuicTraceEvent(
            StartAcceptFailed,
            "StartAccept failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_DATAPATH* Datapath = ListenerSocketProc->Parent->Datapath;
    RDMA_NDSPI_LISTENER *RdmaListener = (RDMA_NDSPI_LISTENER *)ListenerSocketProc->Parent->RdmaContext;


    if (ListenerSocketProc->AcceptSocket == NULL) 
    {
        Status = SocketCreateRdmaInternal(
            Datapath,
            CXPLAT_SOCKET_RDMA_SERVER,
            Config,
            (CXPLAT_SOCKET**)&ListenerSocketProc->AcceptSocket);
        if (QUIC_FAILED(Status)) {
            goto ErrorExit;
        }
    }

    CxPlatStartDatapathIo(
        ListenerSocketProc,
        &ListenerSocketProc->IoSqe,
        CxPlatIoRdmaGetConnectionRequestEventComplete);

ErrorExit:

    return Status;
}

//
// Create an RDMA connection and associate a socket
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdmaInternal(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_TYPE Type,
    _In_ const CXPLAT_RDMA_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesReturned;
    uint16_t PartitionIndex;
    RDMA_CONNECTION* RdmaConnection = NULL;
    RDMA_NDSPI_ADAPTER* NdAdapter = NULL;
    uint8_t *Buffer = NULL;
    uint8_t *SendRingBuffer = NULL;
    uint8_t *RecvRingBuffer = NULL;
    uint8_t *OffsetBuffer = NULL;
    size_t BufferSize = 0;

    *NewSocket = NULL;

    if (!Datapath ||
        !Datapath->RdmaAdapter ||
        !Config ||
        !Config->SendRingBufferSize ||
        !Config->RecvRingBufferSize ||
        Config->SendRingBufferSize < MIN_RING_BUFFER_SIZE ||
        Config->RecvRingBufferSize < MIN_RING_BUFFER_SIZE)
    {
        QuicTraceEvent(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid address family");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_DBG_ASSERT(Datapath->RdmaHandlers.Receive != NULL);

    CXPLAT_SOCKET_PROC* SocketProc = NULL;
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET_RAW* RawSocket = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }
    CXPLAT_SOCKET* Socket = CxPlatRawToSocket(RawSocket);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(Config->RemoteAddress ? sizeof(*Config->RemoteAddress) : 0, Config->RemoteAddress));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = Config->CallbackContext;
    Socket->HasFixedRemoteAddress = TRUE;
    Socket->RdmaContext = NULL;
    Socket->Type = Type;
    Socket->UseRdma = TRUE;

    if (Config->LocalAddress) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    PartitionIndex =
    Config->RemoteAddress ?
            ((uint16_t)(CxPlatProcCurrentNumber() % Datapath->PartitionCount)) : 0;
    Socket->Mtu = CXPLAT_MAX_MTU;
    Socket->RecvBufLen =
        (Datapath->Features & CXPLAT_DATAPATH_FEATURE_RECV_COALESCING) ?
            MAX_URO_PAYLOAD_LENGTH : MAX_RECV_PAYLOAD_LENGTH;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);

    SocketProc = &Socket->PerProcSockets[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    CxPlatRundownInitialize(&SocketProc->RundownRef);
    SocketProc->RioCq = RIO_INVALID_CQ;
    SocketProc->RioRq = RIO_INVALID_RQ;

    //
    // Create a new RDMA connection object
    //
    NdAdapter = (RDMA_NDSPI_ADAPTER*) Datapath->RdmaAdapter;
    if (!NdAdapter)
    {
        QuicTraceEvent(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid RDMA adapter");
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

    CxPlatPoolAlloc(&NdAdapter->ConnectionPool);

    RdmaConnection = (RDMA_CONNECTION*) CxPlatPoolAlloc(&NdAdapter->ConnectionPool);
    if (RdmaConnection == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RDMA_CONNECTION",
            sizeof(RDMA_CONNECTION));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }
    memset(RdmaConnection, 0, sizeof(RDMA_CONNECTION));
    RdmaConnection->State = RdmaConnectionStateUninitialized;

    //
    // Create References between Socket and RdmaConnection
    //
    Socket->RdmaContext = RdmaConnection;
    RdmaConnection->Socket = Socket;
    RdmaConnection->Adapter = NdAdapter;

    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(ND2_SGE),
        QUIC_POOL_PLATFORM_GENERIC,
        MAX_SGE_POOL_SIZE,
        NULL,
        NULL,
        &RdmaConnection->SgePool);
    
    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(ND2_MANA_RESULT),
        QUIC_POOL_PLATFORM_GENERIC,
        MAX_MANA_RESULT_POOL_SIZE,
        NULL,
        NULL,
        &RdmaConnection->ManaResultPool);

    RdmaConnection->Flags = 0;

    //
    // Populate the Flags for the connection
    //
    if (Config->Flags & CXPLAT_RDMA_FLAG_SHARE_ENDPOINT)
    {
        RdmaConnection->Flags |= RDMA_CONNECTION_FLAG_SHARED_ENDPOINT;
    }

    if (Config->Flags & CXPLAT_RDMA_FLAG_SHARE_CQ)
    {
        RdmaConnection->Flags |= RDMA_CONNECTION_FLAG_SHARED_CQ;
    }

    //
    // Set the connection endpoint information
    //
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_SHARED_ENDPOINT)
    {
        memcpy(RdmaConnection->CibirId, Config->CibirId, sizeof(RdmaConnection->CibirId));
        RdmaConnection->CibirIdLength = Config->CibirIdLength;
        RdmaConnection->CibirIdOffsetSrc = Config->CibirIdOffsetSrc;
        RdmaConnection->CibirIdOffsetDst = Config->CibirIdOffsetDst;
    }

    //
    // Allocate memory for send and receive ring buffers
    //
    BufferSize = Config->SendRingBufferSize + Config->RecvRingBufferSize;

    if (Config->SendRingBufferSize > MAX_IMMEDIATE_RING_BUFFER_SIZE ||
        Config->RecvRingBufferSize > MAX_IMMEDIATE_RING_BUFFER_SIZE)
    {
        BufferSize += DEFAULT_OFFSET_BUFFER_SIZE;
        RdmaConnection->Flags |= RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED;
    }

    Buffer = CXPLAT_ALLOC_NONPAGED(BufferSize, QUIC_POOL_SOCKET);
    if (!SendRingBuffer)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "SendRingBuffer",
            Config->SendRingBufferSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    //
    // Create overlapped handle for connection
    //
    Status = NdspiCreateOverlappedFile(
        NdAdapter,
        &RdmaConnection->OverlappedConnFile);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateOverlappedConnFileFailed,
            "CreateOverConnlappedFile failed, status:%d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateMemoryRegion(
        NdAdapter,
        RdmaConnection->OverlappedConnFile,
        &RdmaConnection->MemoryRegion);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateMemoryRegionFailed,
            "CreateMemoryRegion failed, status:%d", Status);
        goto ErrorExit;
    }

    //
    // Register the send and receiver buffer sizes in memory region
    // 
    Status = NdspiRegisterMemory(
        RdmaConnection->MemoryRegion,
        Buffer,
        BufferSize,
        ND_MR_FLAG_ALLOW_LOCAL_WRITE | ND_MR_FLAG_ALLOW_REMOTE_WRITE,
        &RdmaConnection->Ov);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            RegisterSendBufferFailed,
            "RegisterSendBuffer failed, status:%d", Status);
        goto ErrorExit;
    }    

    RdmaConnection->State = RdmaConnectionStateRingBufferRegistered;
    SendRingBuffer = Buffer;
    RecvRingBuffer = Buffer + Config->SendRingBufferSize;
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        OffsetBuffer = RecvRingBuffer + Config->RecvRingBufferSize;
    }

    //
    // Create Send Ring Buffer object for connection
    //
    RdmaConnection->SendRingBuffer = CxPlatPoolAlloc(&NdAdapter->SendRingBufferPool);
    if (RdmaConnection->SendRingBuffer == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "SendRingBuffer",
            Config->SendRingBufferSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    Status = RdmaSendRingBufferInitialize(
        SendRingBuffer,
        Config->SendRingBufferSize,
        &RdmaConnection->SendRingBuffer);
    if (Status != QUIC_STATUS_SUCCESS)
    {
        QuicTraceEvent(
            SendRingBufferInitFailed,
            "SendRingBufferInit failed, status:%d", Status);
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }
    
    RdmaConnection->SendRingBuffer->LocalToken = RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion);

    //
    // Create Recv Ring Buffer object for connection
    //
    RdmaConnection->RecvRingBuffer = CxPlatPoolAlloc(&NdAdapter->RecvRingBufferPool);
    if (RdmaConnection->RecvRingBuffer == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RecvRingBuffer",
            Config->RecvRingBufferSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    Status = RdmaRecvRingBufferInitialize(
        RecvRingBuffer,
        Config->RecvRingBufferSize,
        OffsetBuffer,
        DEFAULT_OFFSET_BUFFER_SIZE,
        &RdmaConnection->RecvRingBuffer);
    if (Status != QUIC_STATUS_SUCCESS)
    {
        QuicTraceEvent(
            RecvRingBufferInitFailed,
            "RecvRingBufferInit failed, status:%d", Status);
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

    RdmaConnection->RecvRingBuffer->LocalToken = RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion);

    //
    // Create Peer Recv Ring Buffer
    //
    RdmaConnection->PeerRingBuffer = CxPlatPoolAlloc(&NdAdapter->RecvRingBufferPool);

    //
    // Create completion queue
    //
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_SHARED_CQ)
    {
        IND2ManaCompletionQueue* CompletionQueue = NULL;

        Status = NdspiCreateCompletionQueue(
            NdAdapter,
            RdmaConnection->OverlappedConnFile,
            NdAdapter->AdapterInfo.MaxCompletionQueueDepth,
            Config->ProcessorGroup,
            Config->Affinity,
            &CompletionQueue);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                CreateSharedCompletionQueueFailed,
                "Create Shared CompletionQueue failed, status:%d", Status);
            goto ErrorExit;
        }

        RdmaConnection->RecvCompletionQueue = CompletionQueue;
        RdmaConnection->SendCompletionQueue = CompletionQueue;
    }
    else
    {
        Status = NdspiCreateCompletionQueue(
            NdAdapter,
            RdmaConnection->OverlappedConnFile,
            NdAdapter->AdapterInfo.MaxCompletionQueueDepth,
            Config->ProcessorGroup,
            Config->Affinity,
            &RdmaConnection->RecvCompletionQueue);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                CreateRecvCompletionQueueFailed,
                "Create Recv CompletionQueue failed, status:%d", Status);
            goto ErrorExit;
        }

        Status = NdspiCreateCompletionQueue(
            NdAdapter,
            RdmaConnection->OverlappedConnFile,
            NdAdapter->AdapterInfo.MaxCompletionQueueDepth,
            Config->ProcessorGroup,
            Config->Affinity,
            &RdmaConnection->SendCompletionQueue);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                CreateSendCompletionQueueFailed,
                "Create Send CompletionQueue failed, status:%d", Status);
            goto ErrorExit;
        }
    }

    //
    // Create Queue Pair for the connection
    //
    Status = NdspiCreateQueuePair(
        NdAdapter,
        RdmaConnection->RecvCompletionQueue,
        RdmaConnection->SendCompletionQueue,
        RdmaConnection,
        NdAdapter->AdapterInfo.MaxReceiveQueueDepth,
        NdAdapter->AdapterInfo.MaxInitiatorQueueDepth,
        NdAdapter->AdapterInfo.MaxReceiveSge,
        NdAdapter->AdapterInfo.MaxInitiatorSge,
        NdAdapter->AdapterInfo.InlineRequestThreshold,
        &RdmaConnection->QueuePair);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateQueuePairFailed,
            "Create QueuePair failed, status:%d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateConnector(
        NdAdapter,
        RdmaConnection->OverlappedConnFile,
        &RdmaConnection->Connector);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateConnectorFailed,
            "Create Connector failed, status:%d", Status);
        goto ErrorExit;
    }

    //
    // Create Memory Window for the connection
    //
    Status = NdspiCreateMemoryWindow(NdAdapter, &RdmaConnection->MemoryWindow);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateMemoryWindowFailed,
            "Create MemoryWindow failed, status:%d", Status);
        goto ErrorExit;
    }

    SocketProc->RdmaHandle = RdmaConnection->OverlappedConnFile;

    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
        SocketProc->RdmaHandle,
        FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "SetFileCompletionNotificationModes");
        Status = HRESULT_FROM_WIN32(LastError);
        goto ErrorExit;
    }

    //
    // Finally Create Socket object
    //
    if (Type != CXPLAT_SOCKET_RDMA_SERVER)
    {
        SocketProc->DatapathProc = &Datapath->Partitions[PartitionIndex];
        CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

        if (!CxPlatEventQAssociateHandle(
            SocketProc->DatapathProc->EventQ,
            SocketProc->RdmaHandle)) 
        {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                LastError,
                "CreateIoCompletionPort");
            Status = HRESULT_FROM_WIN32(LastError);
            goto ErrorExit;
        }

        Status = NdspiBind(
            RdmaConnection->Connector,
            (PSOCKADDR)&Socket->LocalAddress,
            sizeof(Socket->LocalAddress));
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "bind");
            goto ErrorExit;
        }

        if (Config->RemoteAddress != NULL)
        {
            SOCKADDR_INET MappedRemoteAddress = { 0 };
            CxPlatConvertToMappedV6(Config->RemoteAddress, &MappedRemoteAddress);
            
            CxPlatStartDatapathIo(
                SocketProc,
                &SocketProc->IoSqe,
                CxPlatIoRdmaConnectEventComplete);
   
            Status = RdmaConnection->Connector->lpVtbl->Connect(
                RdmaConnection->Connector,
                (IUnknown *)RdmaConnection->QueuePair,
                (PSOCKADDR)&MappedRemoteAddress,
                sizeof(MappedRemoteAddress),
                RdmaConnection->Adapter->AdapterInfo.MaxInboundReadLimit,
                RdmaConnection->Adapter->AdapterInfo.MaxOutboundReadLimit,
                NULL,
                0,
                &SocketProc->IoSqe.Overlapped);
            if (QUIC_FAILED(Status))
            {
                if (Status != ND_PENDING)
                {
                    QuicTraceEvent(
                        DatapathErrorStatus,
                        "[data][%p] ERROR, %u, %s.",
                        Socket,
                        Status,
                        "IND2Connector::Connect");
                    goto ErrorExit;
                }
            }
            else
            {
                //
                // Manually post IO completion if connect completed synchronously.
                //
                Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesReturned);
                if (QUIC_FAILED(Status)) {
                    CxPlatCancelDatapathIo(SocketProc);
                    goto ErrorExit;
                }
            }
            

            SocketProc->IoStarted = TRUE;
        }

        //
        // If no specific local port was indicated, then the stack just
        // assigned this socket a port. We need to query it and use it for
        // all the other sockets we are going to create.
        //
        ULONG AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
        Status = RdmaConnection->Connector->lpVtbl->GetLocalAddress(
            RdmaConnection->Connector,
            (PSOCKADDR)&Socket->LocalAddress,
            &AssignedLocalAddressLength);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status, "IND2Connector::QueryLocalAddress");
            goto ErrorExit;
        }

        if (Config->LocalAddress && Config->LocalAddress->Ipv4.sin_port != 0) {
            CXPLAT_DBG_ASSERT(Config->LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
        }
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    if (Config->RemoteAddress != NULL) {
        Socket->RemoteAddress = *Config->RemoteAddress;
    } else {
        Socket->RemoteAddress.Ipv4.sin_port = 0;
    }

    *NewSocket = Socket;
    Socket = NULL;
    RawSocket = NULL;

    return QUIC_STATUS_SUCCESS;

ErrorExit:

    if (RdmaConnection)
    {
        RdmaConnectionFree(RdmaConnection);
    }

    if (SendRingBuffer)
    {
        CXPLAT_FREE(SendRingBuffer, QUIC_POOL_SOCKET);
    }

    if (RecvRingBuffer)
    {
        CXPLAT_FREE(RecvRingBuffer, QUIC_POOL_SOCKET);
    }

    if (RawSocket != NULL) {
        SocketDelete(CxPlatRawToSocket(RawSocket));
    }

    return Status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdma(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_RDMA_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return SocketCreateRdmaInternal(
        Datapath,
        CXPLAT_SOCKET_RDMA,
        Config,
        NewSocket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdmaListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_RDMA_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket   
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    RDMA_NDSPI_LISTENER* RdmaListener = NULL;
    RDMA_NDSPI_ADAPTER* NdAdapter = NULL;
    CXPLAT_DBG_ASSERT(Datapath->RdmaHandlers.Receive != NULL);

    CXPLAT_SOCKET_PROC* SocketProc = NULL;
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET_RAW* RawSocket = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawSocket == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SOCKET",
            RawSocketLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }
    CXPLAT_SOCKET* Socket = CxPlatRawToSocket(RawSocket);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(Config->LocalAddress ? sizeof(*Config->LocalAddress) : 0, Config->LocalAddress),
        CASTED_CLOG_BYTEARRAY(0, NULL));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = Config->CallbackContext;
    Socket->HasFixedRemoteAddress = FALSE;
    Socket->RdmaContext = NULL;
    Socket->Type = CXPLAT_SOCKET_RDMA_LISTENER;
    Socket->UseRdma = TRUE;

    if (Config->LocalAddress) {
        CxPlatConvertToMappedV6(Config->LocalAddress, &Socket->LocalAddress);
        if (Socket->LocalAddress.si_family == AF_UNSPEC)
        {
            Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
        }
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);

    SocketProc = &Socket->PerProcSockets[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    CxPlatRundownInitialize(&SocketProc->RundownRef);
    SocketProc->RioCq = RIO_INVALID_CQ;
    SocketProc->RioRq = RIO_INVALID_RQ;

        //
    // Create a new RDMA connection object
    //
    NdAdapter = (RDMA_NDSPI_ADAPTER*) Datapath->RdmaAdapter;
    if (!NdAdapter)
    {
        QuicTraceEvent(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid RDMA adapter");
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

    //
    // Create RDMA_LISTENER object
    //
    RdmaListener = (RDMA_NDSPI_LISTENER*) CXPLAT_ALLOC_PAGED(sizeof(RDMA_NDSPI_LISTENER), QUIC_POOL_DATAPATH);
    if (RdmaListener == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RDMA_NDSPI_LISTENER",
            sizeof(RDMA_NDSPI_LISTENER));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }
    memset(RdmaListener, 0, sizeof(RDMA_NDSPI_LISTENER));

    //
    // Create overlapped handle for Listener
    //
    Status = NdspiCreateOverlappedFile(
        NdAdapter,
        &RdmaListener->OverlappedListenerFile);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateOverlappedListenerFileFailed,
            "CreateOverlappedListenerFile failed, status:%d", Status);
        goto ErrorExit;
    }

    //
    // Create Listener object
    //
    Status = NdspiCreateListener(
        NdAdapter,
        RdmaListener->OverlappedListenerFile,
        &RdmaListener->Listener);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateListenerFailed,
            "CreateListener failed, status:%d", Status);
        goto ErrorExit;
    }

    SocketProc->RdmaHandle = RdmaListener->OverlappedListenerFile;

    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
        SocketProc->RdmaHandle,
        FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "SetFileCompletionNotificationModes");
        Status = HRESULT_FROM_WIN32(LastError);
        goto ErrorExit;
    }

    //
    // Create References between Socket and RdmaListener
    //
    Socket->RdmaContext = RdmaListener;
    RdmaListener->ListenerSocket = Socket;
    RdmaListener->Adapter = NdAdapter;

    SocketProc->DatapathProc = &Datapath->Partitions[0]; // TODO - Something better?
    CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

    if (!CxPlatEventQAssociateHandle(
            SocketProc->DatapathProc->EventQ,
            (HANDLE)SocketProc->RdmaHandle))
    {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            LastError,
            "CreateIoCompletionPort");
        Status = HRESULT_FROM_WIN32(LastError);
        goto ErrorExit;
    }

    Status = NdspiBindListener(
        RdmaListener->Listener,
        (PSOCKADDR)&Socket->LocalAddress,
        sizeof(Socket->LocalAddress));
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "bind");
        goto ErrorExit;
    }

    //
    // If no specific local port was indicated, then the stack just
    // assigned this socket a port. We need to query it and use it for
    // all the other sockets we are going to create.
    //
    ULONG AssignedLocalAddressLength = sizeof(Socket->LocalAddress);
    Status = RdmaListener->Listener->lpVtbl->GetLocalAddress(
        RdmaListener->Listener,
        (PSOCKADDR)&Socket->LocalAddress,
        &AssignedLocalAddressLength);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status, "IND2Connector::QueryLocalAddress");
        goto ErrorExit;
    }

    if (Config->LocalAddress && Config->LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(Config->LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    Status = RdmaListener->Listener->lpVtbl->Listen(RdmaListener->Listener, 100);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "listen");
        goto ErrorExit;
    }

    Status = CxPlatRdmaStartAccept(SocketProc, Config);
    if (QUIC_FAILED(Status)) {
        goto ErrorExit;
    }

    SocketProc->IoStarted = TRUE;

    *NewSocket = Socket;
    Socket = NULL;
    RawSocket = NULL;
    Status = QUIC_STATUS_SUCCESS;

ErrorExit:

    if (RdmaListener)
    {
        RdmaListenerFree(RdmaListener);
    }

    if (RawSocket != NULL)
    {
        SocketDelete(CxPlatRawToSocket(RawSocket));
    }
    return Status;
}


void
CxPlatDataPathRdmaProcessConnectCompletion(
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

    if (!CxPlatRundownAcquire(&SocketProc->RundownRef)) {
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS) {

        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            0,
            "ConnectEx Completed!");

        SocketProc->Parent->Datapath->TcpHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            TRUE);

        //
        // Try to start a new receive.
        //
        CxPlatDataPathStartReceiveAsync(SocketProc);

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

    CxPlatRundownRelease(&SocketProc->RundownRef);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaConnectEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);
    //CxPlatDataPathRdmaProcessConnectCompletion(SocketProc, IoResult);
    //CxPlatSocketContextRelease(SocketProc);
}
