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

typedef struct _RDMA_ADAPTER_INFO {
    UINT32 VendorId;
    UINT32 DeviceId;
    SIZE_T MaxInboundSge;
    SIZE_T MaxInboundRequests;
    SIZE_T MaxInboundLength;
    SIZE_T MaxOutboundSge;
    SIZE_T MaxOutboundRequests;
    SIZE_T MaxOutboundLength;
    SIZE_T MaxInlineData;
    SIZE_T MaxInboundReadLimit;
    SIZE_T MaxOutboundReadLimit;
    SIZE_T MaxCqEntries;
    SIZE_T MaxRegistrationSize;
    SIZE_T MaxWindowSize;
    SIZE_T LargeRequestThreshold;
    SIZE_T MaxCallerData;
    SIZE_T MaxCalleeData;
} RDMA_ADAPTER_INFO, *PRDMA_ADAPTER_INFO;

//
// RDMA Adapter Context
//
typedef struct _RDMA_NDSPI_ADAPTER
{
    IND2Adapter*        Adapter;
    HANDLE              OverlappedFile;
    IND2MemoryRegion*   MemoryRegion;
    CXPLAT_POOL         ConnectionPool;
    OVERLAPPED          Ov;
} RDMA_NDSPI_ADAPTER, *PRDMA_NDSPI_ADAPTER;

//
// RDMA Listener Context
//
typedef struct _RDMA_NDSPI_LISTENER
{
    IND2Listener*       Listener;
    OVERLAPPED          Ov;
    CXPLAT_SOCKET*      ListenerSocket; // Socket associated with the listener
} RDMA_NDSPI_LISTENER, *PRDMA_NDSPI_LISTENER;

//
// RDMA Connection Context
//
typedef struct _RDMA_NDSPI_CONNECTION {
    PRDMA_NDSPI_ADAPTER         Adapter;
    IND2MemoryRegion*           MemoryRegion;
    IND2MemoryWindow*           MemoryWindow;
    IND2ManaCompletionQueue*    RecvCompletionQueue;
    IND2ManaCompletionQueue*    SendCompletionQueue;
    IND2ManaQueuePair*          QueuePair;
    IND2Connector*              Connector;
    void*                       MemBuffer;
    size_t                      BufferSize;
    OVERLAPPED                  Ov;
    CXPLAT_SOCKET*              Socket; // Socket associated with this connection
    ULONG                       Flags;
    CXPLAT_POOL                 SgePool;        
    CXPLAT_POOL                 ManaResultPool;
} RDMA_CONNECTION, *PRDMA_CONNECTION;



//
// Create an OverlappedfFile
//
QUIC_STATUS
NdspiCreateOverlappedFile(
    _In_ IND2Adapter *Adapter,
    _Deref_out_ HANDLE* OverlappedFile
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (!Adapter)
    {
        QuicTraceEvent(
            CreateOverlappedFileFailed,
            "CreateOverlappedFile failed, adapter is NULL");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = Adapter->lpVtbl->CreateOverlappedFile(Adapter, OverlappedFile);
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
QUIC_STATUS
NdspiCreateMemoryRegion(
    _In_ PRDMA_NDSPI_ADAPTER NdAdapter,
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
        NdAdapter->OverlappedFile,
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

    if (!MemoryRegion || !Buffer || !BufferLength || !Overlapped)
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
QUIC_STATUS
NdspiCreateMemoryWindow(
     _In_ PRDMA_NDSPI_ADAPTER NdAdapter,
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
QUIC_STATUS 
NdspiCreateCompletionQueue(
    _In_ PRDMA_NDSPI_ADAPTER NdAdapter,
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
        NdAdapter->OverlappedFile,
        queueDepth,
        group,
        affinity,
        (VOID**)CompletionQueue);
}

//
// Create a connector
//
QUIC_STATUS
NdspiCreateConnector(
    _In_ PRDMA_NDSPI_ADAPTER NdAdapter,
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
        NdAdapter->OverlappedFile,
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
QUIC_STATUS
NdspiCreateListener(
    _In_ PRDMA_NDSPI_ADAPTER NdAdapter,
    _Deref_out_ PRDMA_NDSPI_LISTENER *NdListener
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    *NdListener = NULL;

    *NdListener = (PRDMA_NDSPI_LISTENER) CXPLAT_ALLOC_PAGED(sizeof(RDMA_NDSPI_LISTENER), QUIC_POOL_DATAPATH);
    if (*NdListener == NULL)
    {
        QuicTraceEvent(
            CreateNdListenerFailed,
            "CreateNdListener Mem Alloc failed, status:%d", Status);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateListener(
        NdAdapter->Adapter,
        &IID_IND2Listener,
        NdAdapter->OverlappedFile,
        (VOID**)(*NdListener)->Listener);
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
QUIC_STATUS
NdspiStartListener(
    _In_ PRDMA_NDSPI_LISTENER NdListener,
    _In_bytecount_(AddressSize) const struct sockaddr* Address,
    _In_ ULONG AddressSize
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!NdListener || !NdListener->Listener || !Address || !AddressSize)
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
QUIC_STATUS
NdspiCreateQueuePair(
    _In_ PRDMA_NDSPI_ADAPTER NdAdapter,
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
// Perform a connect to a server
//
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
// Perform a complete connect on a connector
//
QUIC_STATUS
CxPlatRdmaCompleteConnectConnector(
    _Inout_ PRDMA_CONNECTION rdmaConnection
    );

//
// Perform an accept on a connector
//
QUIC_STATUS
CxPlatRdmaAcceptConnector(
    _Inout_ PRDMA_CONNECTION rdmaConnection,
    _In_ ULONG inboundReadLimit,
    _In_ ULONG outboundReadLimit,
    __in_bcount_opt(cbPrivateData) const VOID* pPrivateData,
    _In_ ULONG cbPrivateData
    );


//
// Release a connector
//
QUIC_STATUS
CxPlatRdmaReleaseConnector(
    _Inout_ PRDMA_CONNECTION rdmaConnection
    );

//
// Get Result from a completion queue
//
QUIC_STATUS
CxPlatRdmaGetCompletionQueueResults(
    _Inout_ PRDMA_CONNECTION rdmaConnection,
    _In_ BOOL wait
    );

//
// RDMA Write
//
QUIC_STATUS
NdspiWrite(
    _Inout_ PRDMA_CONNECTION RdmaConnection,
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
QUIC_STATUS
NdspiWriteWithImmediate(
    _Inout_ PRDMA_CONNECTION RdmaConnection,
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
QUIC_STATUS
NdspiRead(
    _Inout_ PRDMA_CONNECTION RdmaConnection,
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
QUIC_STATUS
NdspiSend(
    _Inout_ PRDMA_CONNECTION RdmaConnection,
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
QUIC_STATUS
NdspiPostReceive(
    _Inout_ PRDMA_CONNECTION RdmaConnection,
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


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdma(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Config);
    *NewSocket = NULL;

    return S_OK;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdmaListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket   
)
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(LocalAddress);
    UNREFERENCED_PARAMETER(RecvCallbackContext);
    *NewSocket = NULL;
    
     return S_OK;
    /*
    QUIC_STATUS Status;
    int Result;
    int Option;

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

    }
    CXPLAT_SOCKET* Socket = CxPlatRawToSocket(RawSocket);

    QuicTraceEvent(
        DatapathCreated,
        "[data][%p] Created, local=%!ADDR!, remote=%!ADDR!",
        Socket,
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(0, NULL));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = FALSE;
    Socket->Type = CXPLAT_SOCKET_RDMA_LISTENER;
    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
        if (Socket->LocalAddress.si_family == AF_UNSPEC) {
            Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
        }
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);
    */
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

    PRDMA_NDSPI_ADAPTER RdmaAdapter = NULL;

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

    RdmaAdapter = (PRDMA_NDSPI_ADAPTER)CXPLAT_ALLOC_PAGED(sizeof(RDMA_NDSPI_ADAPTER), QUIC_POOL_DATAPATH);
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

    Status = NdspiCreateOverlappedFile(RdmaAdapter->Adapter, &RdmaAdapter->OverlappedFile);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            CreateOverlappedFileFailed,
            "CreateOverlappedFile failed, status:%d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateMemoryRegion(RdmaAdapter, &RdmaAdapter->MemoryRegion);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            CreateMemoryRegionFailed,
            "CreateMemoryRegion failed, status:%d", Status);
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

ErrorExit:

    CxPlatRdmaAdapterRelease(RdmaAdapter);

    return Status;
}

//
// Cleanup an RDMA context
//
QUIC_STATUS
CxPlatRdmaAdapterRelease(
    _In_ void* Adapter)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    PRDMA_NDSPI_ADAPTER NdAdapter = (PRDMA_NDSPI_ADAPTER) Adapter;
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

        if (NdAdapter->MemoryRegion)
        {
            NdAdapter->MemoryRegion->lpVtbl->Release(NdAdapter->MemoryRegion);
        }

        CxPlatPoolUninitialize(&NdAdapter->ConnectionPool);

        CXPLAT_FREE(NdAdapter, QUIC_POOL_DATAPATH);
    }

    return Status;
}

//
// get RDMA adapter information
//
QUIC_STATUS
CxPlatRdmaGetAdapterInfo(
    _In_ void* pAdapter,
    _Inout_ PRDMA_ADAPTER_INFO pAdapterInfo
    );