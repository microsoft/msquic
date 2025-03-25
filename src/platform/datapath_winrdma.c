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
    CXPLAT_POOL         PeerRingBufferPool;
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
    CXPLAT_RDMA_CONFIG* Config;
} RDMA_NDSPI_LISTENER;

//
// Enum to represent the state of the connection
//
typedef enum _RDMA_CONNECTION_STATE
{
    RdmaConnectionStateUninitialized = 0,
    RdmaConnectionStateRingBufferRegistered,
    RdmaConnectionStateConnecting,
    RdmaConnectionStateWaitingForGetConnRequest,
    RdmaConnectionStateWaitingForAccept,
    RdmaConnectionStateConnected,
    RdmaConnectionStateTokenExchangeInitiated,
    RdmaConnectionStateTokenExchangeComplete,
    RdmaConnectionStateReady,
    RdmaConnectionStateClosing,
    RdmaConnectionStateClosed
} RDMA_CONNECTION_STATE;

//
// RDMA Connection Flags
//
#define RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED     0x00000001  // Offset Buffer Used, Ring buffer size > 64 KB
#define RDMA_CONNECTION_FLAG_SHARED_ENDPOINT        0x00000002  // Shared Endpoint
#define RDMA_CONNECTION_FLAG_SHARED_CQ              0x00000004  // Shared Completion Queue
#define RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED     0x00000008  // Memory Window Enabled

//
// RDMA Connection Context
//
typedef struct _RDMA_NDSPI_CONNECTION {
    RDMA_NDSPI_ADAPTER*         Adapter;
    HANDLE                      OverlappedConnFile;
    IND2MemoryRegion*           MemoryRegion;
    IND2MemoryWindow*           RecvMemoryWindow;
    IND2MemoryWindow*           OffsetMemoryWindow;
    IND2ManaCompletionQueue*    CompletionQueue;
    IND2ManaQueuePair*          QueuePair;
    IND2Connector*              Connector;
    RDMA_SEND_RING_BUFFER*      SendRingBuffer;
    RDMA_RECV_RING_BUFFER*      RecvRingBuffer;
    RDMA_PEER_RING_BUFFER*      PeerRingBuffer;
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
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaTokenExchangeInitEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaTokenExchangeFinalEventComplete;

//
// RDMA I/O helper functions
//

inline
void
UInt32ToByteBuffer(
    _In_ UINT32 Value,
    _Inout_bytecount_(4) uint8_t* Buffer
    )
{
    Buffer[0] = (uint8_t)(Value & 0xFF); // Most significant byte
    Buffer[1] = (uint8_t)((Value >> 8) & 0xFF);
    Buffer[2] = (uint8_t)((Value >> 16) & 0xFF);
    Buffer[3] = (uint8_t)((Value >> 24) & 0xFF);  // Least significant byte
}

inline
UINT32 ByteBufferToUInt32(
    _In_reads_bytes_(4) uint8_t* Buffer
    )
{
    UINT32 Value = 0;

    Value |= (Buffer[0] << 24);
    Value |= (Buffer[1] << 16);
    Value |= (Buffer[2] << 8);
    Value |= Buffer[3];

    return Value;
}

inline
void
UInt64ToByteBuffer(
    _In_ UINT64 Value,
    _Inout_bytecount_(8) uint8_t* Buffer
    )
{
    for (int i = 0; i < 8; i++)
    {
        Buffer[i] = (Value >> (8 * i)) & 0xFF;
    }
}

inline
UINT64 ByteBufferToUInt64(
    _In_reads_bytes_(8) uint8_t* Buffer
    )
{
    UINT64 Value = 0;

    for (int i = 0; i < 8; i++)
    {
        Value |= (uint64_t)Buffer[i] << (8 * i);
    }

    return Value;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaExchangeTokensInit(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaProcessRemoteTokens(
    _In_ RDMA_CONNECTION* RdmaConnection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaSendRemoteTokens(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ RDMA_CONNECTION* RdmaConnection
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
    _In_ SIZE_T BufferLength,
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
    _In_ IND2ManaCompletionQueue* CompletionQueue,
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
        !CompletionQueue)
    {
        QuicTraceEvent(
            CreateQueuePairFailed,
            "CreateQueuePair failed, invalid parameters");
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateQueuePair(
        NdAdapter->Adapter,
        &IID_IND2ManaQueuePair,
        (IUnknown *)CompletionQueue,
        (IUnknown *)CompletionQueue,
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
    _In_bytecount_(BufferSize) const VOID* Buffer,
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

    return Status;
}

//
// RDMA Send
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiSendWithImmediate(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    _In_opt_ VOID *requestContext,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ ULONG Flags,
    _In_ UINT32 ImmediateData
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize)
    {
        QuicTraceEvent(
            NdspiSendWithImmediateFailed,
            "NdspiSendWithImmediate Failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->SendWithImmediate(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize,
        Flags,
        ImmediateData);

    return Status;
}

//
// Post RDMA Receive
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiPostReceive(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    __in_ecount_opt(SgeSize) const ND2_SGE *Sge,
    _In_ ULONG SgeSize
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair)
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
        CxPlatPoolUninitialize(&NdAdapter->PeerRingBufferPool);

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

    if (RdmaConnection->CompletionQueue)
    {
        RdmaConnection->CompletionQueue->lpVtbl->Release(RdmaConnection->CompletionQueue);
    }

    if (RdmaConnection->Connector)
    {
        RdmaConnection->Connector->lpVtbl->Release(RdmaConnection->Connector);
    }

    if (RdmaConnection->RecvMemoryWindow)
    {
        RdmaConnection->RecvMemoryWindow->lpVtbl->Release(RdmaConnection->RecvMemoryWindow);
    }

    if (RdmaConnection->OffsetMemoryWindow)
    {
        RdmaConnection->OffsetMemoryWindow->lpVtbl->Release(RdmaConnection->OffsetMemoryWindow);
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
        CxPlatPoolFree(&RdmaConnection->Adapter->PeerRingBufferPool, RdmaConnection->PeerRingBuffer);
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

    if (RdmaListener->Config)
    {
        if (CxPlatRefDecrement(&RdmaListener->Config->RefCount))
        {
            CXPLAT_FREE(RdmaListener->Config, QUIC_POOL_DATAPATH);
        }
    }

    CXPLAT_FREE(RdmaListener, QUIC_POOL_DATAPATH);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketRdmaRelease(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (!Socket)
    {
        return;
    }

    if (CxPlatRefDecrement(&Socket->RefCount))
    {

        if (Socket->RdmaContext)
        {
            switch (Socket->Type)
            {
                case CXPLAT_SOCKET_RDMA:
                case CXPLAT_SOCKET_RDMA_SERVER:
                    RdmaConnectionFree((RDMA_CONNECTION*)Socket->RdmaContext);
                    break;
                case CXPLAT_SOCKET_RDMA_LISTENER:
                    RdmaListenerFree((RDMA_NDSPI_LISTENER*)Socket->RdmaContext);
                    break;
                default:
                    CXPLAT_DBG_ASSERT(FALSE);
                    break;
            }
        }

        QuicTraceLogVerbose(
            DatapathShutDownComplete,
            "[data][%p] Shut down (complete)",
            Socket);
        CXPLAT_DBG_ASSERT(!Socket->Freed);
        CXPLAT_DBG_ASSERT(Socket->Uninitialized);
        Socket->Freed = TRUE;
        CXPLAT_FREE(CxPlatSocketToRaw(Socket), QUIC_POOL_SOCKET);
    }
}

//
// Create an RDMA connection and associate a socket
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdmaInternal(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_SOCKET_TYPE Type,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _In_ const CXPLAT_RDMA_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesReturned = 0;
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
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(RemoteAddress ? sizeof(*RemoteAddress) : 0, RemoteAddress));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = CallbackContext;
    Socket->HasFixedRemoteAddress = TRUE;
    Socket->RdmaContext = NULL;
    Socket->Type = Type;
    Socket->UseRdma = TRUE;

    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
    } else {
        Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
    }
    PartitionIndex =
        RemoteAddress ?
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

    if (Config->Flags & CXPLAT_RDMA_FLAG_USE_MEMORY_WINDOW)
    {
        RdmaConnection->Flags |= RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED;
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
    if (!Buffer)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Buffer",
            BufferSize);
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
    //
    // Create Peer Ring Buffer object for connection
    //
    RdmaConnection->PeerRingBuffer = CxPlatPoolAlloc(&NdAdapter->PeerRingBufferPool);
    if (RdmaConnection->RecvRingBuffer == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PeerRingBuffer",
            Config->RecvRingBufferSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }
    //
    // Create completion queue
    //
    Status = NdspiCreateCompletionQueue(
        NdAdapter,
        RdmaConnection->OverlappedConnFile,
        NdAdapter->AdapterInfo.MaxCompletionQueueDepth,
        Config->ProcessorGroup,
        Config->Affinity,
        &RdmaConnection->CompletionQueue);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            CreateSharedCompletionQueueFailed,
            "Create CompletionQueue failed, status:%d", Status);
        goto ErrorExit;
    }

    //
    // Create Queue Pair for the connection
    //
    Status = NdspiCreateQueuePair(
        NdAdapter,
        RdmaConnection->CompletionQueue,
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
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED)
    {
        Status = NdspiCreateMemoryWindow(NdAdapter, &RdmaConnection->RecvMemoryWindow);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                CreateRecvMemoryWindowFailed,
                "Create RecvMemoryWindow failed, status:%d", Status);
            goto ErrorExit;
        }
        
        if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
        {
            Status = NdspiCreateMemoryWindow(NdAdapter, &RdmaConnection->OffsetMemoryWindow);
            if (QUIC_FAILED(Status))
            {
                QuicTraceEvent(
                    CreateSendMemoryWindowFailed,
                    "Create SendMemoryWindow failed, status:%d", Status);
                goto ErrorExit;
            }
        }
    }
    else
    {
        RdmaConnection->RecvMemoryWindow = NULL;
        RdmaConnection->OffsetMemoryWindow = NULL;
    }

    SocketProc->RdmaHandle = RdmaConnection->OverlappedConnFile;

    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
        SocketProc->RdmaHandle,
        FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE))
    {
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

        if (RemoteAddress != NULL)
        {
            SOCKADDR_INET MappedRemoteAddress = { 0 };
            CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);
            
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

        if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
            CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
        }
    }

    CxPlatConvertFromMappedV6(&Socket->LocalAddress, &Socket->LocalAddress);

    if (RemoteAddress != NULL) {
        Socket->RemoteAddress = *RemoteAddress;
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
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _In_ CXPLAT_RDMA_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return SocketCreateRdmaInternal(
        Datapath,
        CXPLAT_SOCKET_RDMA,
        LocalAddress,
        RemoteAddress,
        CallbackContext, 
        Config,
        NewSocket);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
SocketCreateRdmaListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _In_ CXPLAT_RDMA_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket 
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    RDMA_NDSPI_LISTENER* RdmaListener = NULL;
    RDMA_NDSPI_ADAPTER* NdAdapter = NULL;

    if (!Datapath ||
        !LocalAddress ||
        !Datapath->RdmaAdapter ||
        !Config)
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
        CASTED_CLOG_BYTEARRAY(LocalAddress ? sizeof(*LocalAddress) : 0, LocalAddress),
        CASTED_CLOG_BYTEARRAY(0, NULL));

    ZeroMemory(RawSocket, RawSocketLength);
    Socket->Datapath = Datapath;
    Socket->ClientContext = RecvCallbackContext;
    Socket->HasFixedRemoteAddress = FALSE;
    Socket->RdmaContext = NULL;
    Socket->Type = CXPLAT_SOCKET_RDMA_LISTENER;
    Socket->UseRdma = TRUE;

    if (LocalAddress) {
        CxPlatConvertToMappedV6(LocalAddress, &Socket->LocalAddress);
        if (Socket->LocalAddress.si_family == AF_UNSPEC)
        {
            Socket->LocalAddress.si_family = QUIC_ADDRESS_FAMILY_INET6;
        }
    }
    else
    {
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
    RdmaListener->Config = Config;
    CxPlatRefIncrement(&RdmaListener->Config->RefCount);

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

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0) {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
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

    Status = CxPlatRdmaStartAccept(SocketProc);
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

//
// Free Child Objects allocated within an RDMA_CONNECTION object
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!ListenerSocketProc ||
        !ListenerSocketProc->Parent ||
        !ListenerSocketProc->Parent->Datapath ||
        !ListenerSocketProc->Parent->RdmaContext)
    {
        QuicTraceEvent(
            StartAcceptFailed,
            "StartAccept failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_DATAPATH* Datapath = ListenerSocketProc->Parent->Datapath;
    RDMA_NDSPI_LISTENER *RdmaListener = (RDMA_NDSPI_LISTENER *)ListenerSocketProc->Parent->RdmaContext;
    RDMA_CONNECTION *RdmaConnection = NULL;
    DWORD BytesRecv = 0;

    if (ListenerSocketProc->AcceptSocket == NULL) 
    {
        Status = SocketCreateRdmaInternal(
            Datapath,
            CXPLAT_SOCKET_RDMA_SERVER,
            NULL,
            NULL,
            NULL,
            RdmaListener->Config,
            &ListenerSocketProc->AcceptSocket);
        if (QUIC_FAILED(Status))
        {
            goto ErrorExit;
        }
    }

    CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket->RdmaContext != NULL);

    CxPlatStartDatapathIo(
        ListenerSocketProc,
        &ListenerSocketProc->IoSqe,
        CxPlatIoRdmaGetConnectionRequestEventComplete);

    RdmaConnection = (RDMA_CONNECTION*)ListenerSocketProc->AcceptSocket->RdmaContext;
    RdmaConnection->State = RdmaConnectionStateWaitingForGetConnRequest;

    Status = RdmaListener->Listener->lpVtbl->GetConnectionRequest(
        RdmaListener->Listener,
        (IUnknown *)RdmaConnection->Connector,
        &ListenerSocketProc->IoSqe.Overlapped);
    if (QUIC_FAILED(Status))
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                GetConnectionRequestFailed,
                "GetConnectionRequest failed, status:%d", Status);
            CxPlatCancelDatapathIo(ListenerSocketProc);
            goto ErrorExit;
        }
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(ListenerSocketProc, &ListenerSocketProc->IoSqe, BytesRecv);
        if (QUIC_FAILED(Status)) {
            CxPlatCancelDatapathIo(ListenerSocketProc);
            goto ErrorExit;
        }
    }

ErrorExit:

    return Status;
}

QUIC_STATUS
CxPlatRdmaExchangeTokensInit(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;
    ND2_SGE *RecvSge = NULL;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceEvent(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;
    CXPLAT_SOCKET *Socket = SocketProc->Parent;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateConnected);

    //
    // Bind Memory Window to Queue Pair
    //
    Status = NdspiBindMemoryWindow(
        RdmaConnection->MemoryRegion,
        RdmaConnection->QueuePair,
        RdmaConnection->RecvMemoryWindow,
        (void *)RdmaConnection,
        RdmaConnection->RecvRingBuffer->Buffer,
        RdmaConnection->RecvRingBuffer->Capacity,
        ND_OP_FLAG_ALLOW_WRITE | ND_OP_FLAG_ALLOW_READ);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            BindRecvMemoryWindowFailed,
            "BindRecvMemoryWindow failed, status:%d", Status);
        goto ErrorExit; 
    }

    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        //
        // For Offset buffer, a read only access is provided for the
        // remote peer
        //
        Status = NdspiBindMemoryWindow(
            RdmaConnection->MemoryRegion,
            RdmaConnection->QueuePair,
            RdmaConnection->OffsetMemoryWindow,
            (void *)RdmaConnection,
            RdmaConnection->RecvRingBuffer->OffsetBuffer,
            RdmaConnection->RecvRingBuffer->OffsetBufferSize,
            ND_OP_FLAG_ALLOW_READ);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                BindRecvMemoryWindowFailed,
                "BindRecvMemoryWindow failed, status:%d", Status);
            goto ErrorExit;
        }
    }

    CxPlatStartDatapathIo(
        SocketProc,
        &SocketProc->IoSqe,
        CxPlatIoRdmaTokenExchangeInitEventComplete);

    //
    // Post a receive to get the ring buffer tokens from the peer
    // This is common operation for both client and server
    //
    RecvSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    if (RecvSge == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "RecvSge Allocation of '%s' failed. (%llu bytes)",
            "ND2_SGE",
            sizeof(ND2_SGE));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    RecvSge->Buffer = RdmaConnection->RecvRingBuffer->Buffer;
    RecvSge->BufferLength = (ULONG) RdmaConnection->RecvRingBuffer->Capacity;
    memset(RdmaConnection->RecvRingBuffer->Buffer, 0, RdmaConnection->RecvRingBuffer->Capacity);

    Status = NdspiPostReceive(
        RdmaConnection,
        RecvSge,
        1);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "IND2QueuePair::Receive for fetching ring buffer tokens");

        goto ErrorExit;
    }

    if (Socket->Type == CXPLAT_SOCKET_RDMA_SERVER)
    {
        //
        // For server, first post a receive to get the ring buffer details from  client.
        // The server would then send the remote tokens for tis ring buffers
        //
        Status = RdmaConnection->CompletionQueue->lpVtbl->Notify(
            RdmaConnection->CompletionQueue,
            ND_CQ_NOTIFY_ANY,
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
                    "IND2CompletionQueue::Notify");
                goto ErrorExit;
            }
        }
        else
        {
            //
            // Manually post IO completion if accept completed synchronously.
            //
            Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesRecv);
            if (QUIC_FAILED(Status)) {
                CxPlatCancelDatapathIo(SocketProc);
                goto ErrorExit;
            }
        }        
    }
    else
    {
        Status = CxPlatRdmaSendRemoteTokens(SocketProc, RdmaConnection);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "CxPlatRdmaSendRemoteTokens");
            goto ErrorExit;
        } 
    }

ErrorExit:
    if (RecvSge)
    {
        CxPlatPoolFree(&RdmaConnection->SgePool, RecvSge);
    }
    
    return Status;
}

void
CxPlatDataPathRdmaProcessConnectCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG IoResult
    )

{
    if (IoResult == WSA_OPERATION_ABORTED) {
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
        //CxPlatDataPathStartReceiveAsync(SocketProc);

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

void
CxPlatDataPathRdmaProcessGetConnectionRequestCompletion(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ ULONG IoResult
    )
{
    CXPLAT_SOCKET_PROC* AcceptSocketProc = NULL;
    RDMA_CONNECTION* RdmaConnection = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;
    }

    if (!CxPlatRundownAcquire(&ListenerSocketProc->RundownRef))
    {
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS)
    {
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket != NULL);
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket->RdmaContext != NULL);
        AcceptSocketProc = &ListenerSocketProc->AcceptSocket->PerProcSockets[0];
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent);
        
        RdmaConnection = (RDMA_CONNECTION*)ListenerSocketProc->AcceptSocket->RdmaContext;
        RdmaConnection->State = RdmaConnectionStateWaitingForAccept;

        //
        // Before calling accept, post a receive to get the token information
        // from the client. In response, the server will send the token for its
        // ring buffer.
        //
        ND2_SGE *sge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
        if (sge == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "ND2_SGE",
                sizeof(ND2_SGE));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto ErrorExit;
        }

        sge->Buffer = RdmaConnection->RecvRingBuffer->Buffer;
        sge->BufferLength = (ULONG) RdmaConnection->RecvRingBuffer->Size;

        Status = NdspiPostReceive(
            RdmaConnection,
            sge,
            1);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                Status,
                "IND2QueuePair::Receive for fetching ring buffer tokens");

            goto ErrorExit;
        }

        //
        // Perform an accept operation on the connection
        //
        CxPlatStartDatapathIo(
            ListenerSocketProc,
            &ListenerSocketProc->IoSqe,
            CxPlatIoRdmaAcceptEventComplete);
            
        Status = RdmaConnection->Connector->lpVtbl->Accept(
            RdmaConnection->Connector,
            (IUnknown *)RdmaConnection->QueuePair,
            RdmaConnection->Adapter->AdapterInfo.MaxInboundReadLimit,
            RdmaConnection->Adapter->AdapterInfo.MaxOutboundReadLimit,
            NULL,
            0,
            &ListenerSocketProc->IoSqe.Overlapped);
        if (QUIC_FAILED(Status))
        {
            if (Status != ND_PENDING)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    ListenerSocketProc->Parent,
                    Status,
                    "IND2Connector::Accept");
            }
        }
        else
        {
            //
            // Manually post IO completion if accept completed synchronously.
            //
            Status = CxPlatSocketEnqueueSqe(ListenerSocketProc, &ListenerSocketProc->IoSqe, 0);
            if (QUIC_FAILED(Status))
            {
                CxPlatCancelDatapathIo(ListenerSocketProc);
            }
        }
    }

ErrorExit:
    
        if (QUIC_FAILED(Status))
        {
            if (RdmaConnection)
            {
                RdmaConnectionFree(RdmaConnection);
            }
    
            if (AcceptSocketProc)
            {
                SocketDelete(AcceptSocketProc->Parent);
            }
        }
    
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                Status,
                "CxPlatDataPathRdmaProcessGetConnectionRequestCompletion");
        }
    
        CxPlatRundownRelease(&ListenerSocketProc->RundownRef);
}

void
CxPlatDataPathRdmaProcessAcceptCompletion(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ ULONG IoResult
    )
{
    CXPLAT_SOCKET_PROC* AcceptSocketProc = NULL;
    RDMA_CONNECTION* RdmaConnection = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (IoResult == WSA_OPERATION_ABORTED) {
        //
        // Error from shutdown, silently ignore. Return immediately so the
        // receive doesn't get reposted.
        //
        return;
    }

    if (!CxPlatRundownAcquire(&ListenerSocketProc->RundownRef))
    {
        return;
    }

    if (IoResult == QUIC_STATUS_SUCCESS)
    {
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket != NULL);
        AcceptSocketProc = &ListenerSocketProc->AcceptSocket->PerProcSockets[0];
        CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent);
        uint16_t PartitionIndex = 0;

        RdmaConnection = (RDMA_CONNECTION*)ListenerSocketProc->AcceptSocket->RdmaContext;
        RdmaConnection->State = RdmaConnectionStateConnected;

        ULONG AssignedLocalAddressLength = sizeof(ListenerSocketProc->AcceptSocket->LocalAddress);
        Status = RdmaConnection->Connector->lpVtbl->GetLocalAddress(
            RdmaConnection->Connector,
            (PSOCKADDR)&ListenerSocketProc->AcceptSocket->LocalAddress,
            &AssignedLocalAddressLength);
        if (QUIC_FAILED(Status))
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    ListenerSocketProc->Parent,
                    Status,

                    " CxPlatDataPathRdmaProcessAcceptCompletion IND2Connector::GetLocalAddress");
                goto ErrorExit;
            }

        ULONG AssignedRemoteAddressLength = sizeof(ListenerSocketProc->AcceptSocket->RemoteAddress);
        Status = RdmaConnection->Connector->lpVtbl->GetPeerAddress(
            RdmaConnection->Connector,
            (PSOCKADDR)&ListenerSocketProc->AcceptSocket->RemoteAddress,
            &AssignedRemoteAddressLength);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                Status,
                " CxPlatDataPathRdmaProcessAcceptCompletion IND2Connector::GetRemoteAddress");
            goto ErrorExit;
        }

        CxPlatConvertFromMappedV6(
            &ListenerSocketProc->AcceptSocket->LocalAddress,
            &ListenerSocketProc->AcceptSocket->LocalAddress);
        CxPlatConvertFromMappedV6(
            &ListenerSocketProc->AcceptSocket->RemoteAddress,
            &ListenerSocketProc->AcceptSocket->RemoteAddress);

        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            ListenerSocketProc->Parent,
            0,
            "RDMA Accept Completed!");

        if (!CxPlatRundownAcquire(&AcceptSocketProc->RundownRef)) {
            goto ErrorExit;
        }

        CXPLAT_DATAPATH* Datapath = ListenerSocketProc->Parent->Datapath;
        
        PartitionIndex = (uint16_t)(CxPlatProcCurrentNumber() % Datapath->PartitionCount);
        AcceptSocketProc->DatapathProc = &Datapath->Partitions[PartitionIndex]; // TODO - Something better?
        CxPlatRefIncrement(&AcceptSocketProc->DatapathProc->RefCount);

        if (!CxPlatEventQAssociateHandle(
            AcceptSocketProc->DatapathProc->EventQ,
            (HANDLE)AcceptSocketProc->RdmaHandle))
        {
            DWORD LastError = GetLastError();
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                LastError,
                "CreateIoCompletionPort (accepted)");
            goto ErrorExit;
        }

        ListenerSocketProc->AcceptSocket = NULL;
        AcceptSocketProc->IoStarted = TRUE;

        if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED)
        {
            Status = CxPlatRdmaExchangeTokensInit(AcceptSocketProc);
            if (QUIC_FAILED(Status))
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    ListenerSocketProc->Parent,
                    Status,
                    "CxPlatRdmaExchangeTokensInit");
                goto ErrorExit;
            }
        }

        Status = Datapath->RdmaHandlers.Accept(
            ListenerSocketProc->Parent,
            ListenerSocketProc->Parent->ClientContext,
            ListenerSocketProc->AcceptSocket,
            &ListenerSocketProc->AcceptSocket->ClientContext);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                Status,
                "Accept callback");
            goto ErrorExit;
        }
    }
    else
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            ListenerSocketProc->Parent,
            IoResult,
            "RDMA Accept completion");
    }

ErrorExit:

    if (AcceptSocketProc != NULL) {
        CxPlatRundownRelease(&AcceptSocketProc->RundownRef);
    }

    if (ListenerSocketProc->AcceptSocket != NULL) {
        SocketDelete(ListenerSocketProc->AcceptSocket);
        ListenerSocketProc->AcceptSocket = NULL;
    }

    //
    // Try to start a new accept.
    //
    (void)CxPlatRdmaStartAccept(ListenerSocketProc);

    CxPlatRundownRelease(&ListenerSocketProc->RundownRef);

}

void
CxPlatDataPathRdmaProcessExchangeInitCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG IoResult
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;
    ND2_SGE *SendSge = NULL;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceEvent(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return;
    }

    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;
    CXPLAT_SOCKET *Socket = SocketProc->Parent;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateTokenExchangeInitiated);

    CxPlatStartDatapathIo(
        SocketProc,
        &SocketProc->IoSqe,
        CxPlatIoRdmaTokenExchangeFinalEventComplete);
    
    if (Socket->Type == CXPLAT_SOCKET_RDMA_SERVER)
    {
        //
        // Populate the peer ring buffer tokens
        //
        Status = CxPlatRdmaProcessRemoteTokens(RdmaConnection);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "CxPlatRdmaProcessRemoteTokens");
            goto ErrorExit;
        }

        //
        // Initiate a send to the client with the token for the
        // server's receive ring and offset buffers
        //
        Status = CxPlatRdmaSendRemoteTokens(SocketProc, RdmaConnection);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "CxPlatRdmaSendRemoteTokens");
            goto ErrorExit;
        }
    }
    else
    {
        //
        // Check if send to server was completed
        //
        ND2_MANA_RESULT Result;
        ULONG Count = RdmaConnection->CompletionQueue->lpVtbl->GetManaResults(
            RdmaConnection->CompletionQueue,
            &Result,
            1);
        CXPLAT_DBG_ASSERT(Count > 0);
        CXPLAT_DBG_ASSERT(Result.RequestType == Nd2ManaRequestTypeSend);

        //
        // Client has alreay posted a receive
        // wait for event notification from server
        //
        Status = RdmaConnection->CompletionQueue->lpVtbl->Notify(
            RdmaConnection->CompletionQueue,
            ND_CQ_NOTIFY_ANY,
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
                    "IND2CompletionQueue::Notify");
                goto ErrorExit;
            }
        }
        else
        {
            //
            // Manually post IO completion if accept completed synchronously.
            //
            Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesRecv);
            if (QUIC_FAILED(Status)) {
                CxPlatCancelDatapathIo(SocketProc);
                goto ErrorExit;
            }
        }   
    }

ErrorExit:

    return;
}

void
CxPlatDataPathRdmaProcessExchangeFinalCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ ULONG IoResult
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;
    ND2_SGE *SendSge = NULL;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceEvent(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return;
    }

    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;
    CXPLAT_SOCKET *Socket = SocketProc->Parent;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateTokenExchangeInitiated);

    if (Socket->Type == CXPLAT_SOCKET_RDMA_SERVER)
    {
        //
        // Check if send to client was completed
        //
        ND2_MANA_RESULT Result;
        ULONG Count = RdmaConnection->CompletionQueue->lpVtbl->GetManaResults(
            RdmaConnection->CompletionQueue,
            &Result,
            1);
        CXPLAT_DBG_ASSERT(Count > 0);
        CXPLAT_DBG_ASSERT(Result.RequestType == Nd2ManaRequestTypeSend);

    }
    else
    {
        //
        // Populate the peer ring buffer tokens received from the server
        //
        Status = CxPlatRdmaProcessRemoteTokens(RdmaConnection);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "CxPlatRdmaProcessRemoteTokens");
            return;
        }
    }
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
    CxPlatDataPathRdmaProcessConnectCompletion(SocketProc, IoResult);
    CxPlatSocketContextRelease(SocketProc);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaGetConnectionRequestEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);
    CxPlatDataPathRdmaProcessGetConnectionRequestCompletion(SocketProc, IoResult);
    CxPlatSocketContextRelease(SocketProc);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaAcceptEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);
    CxPlatDataPathRdmaProcessAcceptCompletion(SocketProc, IoResult);
    CxPlatSocketContextRelease(SocketProc);
}   

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaTokenExchangeInitEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);
    CxPlatDataPathRdmaProcessExchangeInitCompletion(SocketProc, IoResult);
    CxPlatSocketContextRelease(SocketProc);
} 

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaTokenExchangeFinalEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    ULONG IoResult = RtlNtStatusToDosError((NTSTATUS)Cqe->Internal);
    CxPlatDataPathRdmaProcessExchangeFinalCompletion(SocketProc, IoResult);
    CxPlatSocketContextRelease(SocketProc);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaProcessRemoteTokens(
    _In_ RDMA_CONNECTION* RdmaConnection
    )
{
    if (!RdmaConnection)
    {
        QuicTraceEvent(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    ND2_MANA_RESULT ManaResult;

    //
    // Check if the token was received from the client
    //
    ULONG Count = RdmaConnection->CompletionQueue->lpVtbl->GetManaResults(
        RdmaConnection->CompletionQueue,
        &ManaResult,
        1);

    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(ManaResult.RequestType == Nd2ManaRequestTypeRecvWithImmediate);
    CXPLAT_DBG_ASSERT(ManaResult.BytesTransferred == ManaResult.ImmediateDataOrRKey);
    CXPLAT_DBG_ASSERT(ManaResult.ImmediateDataOrRKey == 16 || ManaResult.ImmediateDataOrRKey == 28);

    RdmaConnection->PeerRingBuffer->Head = RdmaConnection->PeerRingBuffer->Tail = 0;
    RdmaConnection->PeerRingBuffer->RemoteAddress = ByteBufferToUInt64(&RdmaConnection->RecvRingBuffer->Buffer[0]);
    RdmaConnection->PeerRingBuffer->Capacity = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[8]);
    RdmaConnection->PeerRingBuffer->RemoteToken = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[12]);

    if (ManaResult.ImmediateDataOrRKey == 16)
    {
        RdmaConnection->PeerRingBuffer->RemoteOffsetBufferAddress = 0;
        RdmaConnection->PeerRingBuffer->OffsetRemotetoken = 0;
    }
    else
    {
        RdmaConnection->PeerRingBuffer->RemoteOffsetBufferAddress = ByteBufferToUInt64(&RdmaConnection->RecvRingBuffer->Buffer[16]);
        RdmaConnection->PeerRingBuffer->OffsetRemotetoken = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[24]);
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatRdmaSendRemoteTokens(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ RDMA_CONNECTION* RdmaConnection
    )
{
    ND2_SGE *SendSge = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;

    if (!SocketProc || !RdmaConnection)
    {
        QuicTraceEvent(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    
    SendSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    if (SendSge == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "ND2_SGE",
            sizeof(ND2_SGE));

        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateConnected);

    memset(RdmaConnection->SendRingBuffer->Buffer, 0, RdmaConnection->SendRingBuffer->Capacity);
    RdmaConnection->SendRingBuffer->LocalToken = RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion);

    uint64_t RecvRingBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->Buffer;
    uint32_t RecvRingBufferToken = RdmaConnection->RecvMemoryWindow->lpVtbl->GetRemoteToken(RdmaConnection->RecvMemoryWindow);

    SendSge->Buffer = RdmaConnection->SendRingBuffer->Buffer;
    SendSge->BufferLength = 0;

    UInt64ToByteBuffer(RecvRingBufferAdress, &RdmaConnection->SendRingBuffer->Buffer[0]);
    SendSge->BufferLength += sizeof(uint64_t);

    UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->Capacity, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
    SendSge->BufferLength += sizeof(uint32_t);

    UInt32ToByteBuffer(RecvRingBufferToken, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
    SendSge->BufferLength += sizeof(uint32_t);

    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        uint64_t OffsetBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->OffsetBuffer;
        uint32_t OffsetBufferToken = RdmaConnection->OffsetMemoryWindow->lpVtbl->GetRemoteToken(RdmaConnection->OffsetMemoryWindow);

        UInt64ToByteBuffer(OffsetBufferAdress, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
        SendSge->BufferLength += sizeof(uint64_t);

        UInt32ToByteBuffer(OffsetBufferToken, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
        SendSge->BufferLength += sizeof(uint32_t);
    }

    //
    // Send the token information to the server
    //
    Status = NdspiSendWithImmediate(
        RdmaConnection,
        RdmaConnection,
        SendSge,
        1,
        0,
        SendSge->BufferLength);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "IND2QueuePair::SendWithImmediate for sending ring buffer tokens");
        goto ErrorExit;
    }

    //
    // Call Notify on the completion queue to get send complete
    // notification
    //
    Status = RdmaConnection->CompletionQueue->lpVtbl->Notify(
        RdmaConnection->CompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &SocketProc->IoSqe.Overlapped);
    if (QUIC_FAILED(Status))
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                Status,
                "IND2CompletionQueue::Notify");
            goto ErrorExit;
        }
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesRecv);
        if (QUIC_FAILED(Status)) {
            CxPlatCancelDatapathIo(SocketProc);
            goto ErrorExit;
        }
    }

ErrorExit:
    if (SendSge)
    {
        CxPlatPoolFree(&RdmaConnection->SgePool, SendSge);
    }

    return Status;
}