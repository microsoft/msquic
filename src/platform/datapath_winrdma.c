/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC RDMA Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"
#include  "datapath_rdma_ring_buffer.h"
#include <ndstatus.h>
#include <ndsupport.h>
#include <initguid.h>
#include <mana_ndspi.h>

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
// Connector Private Data Size
//
#define DEFAULT_RDMA_REQ_PRIVATE_DATA_SIZE 56

//
// Listener Private Data Size
//
#define DEFAULT_RDMA_REP_PRIVATE_DATA_SIZE 196

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
    CXPLAT_POOL         RemoteRingBufferPool;
    ND2_ADAPTER_INFO    AdapterInfo;
    ADDRESS_FAMILY      AddressFamily;
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
    RdmaConnectionStateCompleteConnect,
    RdmaConnectionStateConnected,
    RdmaConnectionStateWaitingForGetConnRequest,
    RdmaConnectionStateWaitingForAccept,
    RdmaConnectionStateTokenExchangeInitiated,
    RdmaConnectionStateTokenExchangeComplete,
    RdmaConnectionStateReady,
    RdmaConnectionStateReceivedDisconnect,
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
    HANDLE                      ConnOverlappedFile;
    IND2MemoryRegion*           MemoryRegion;
    IND2MemoryWindow*           RecvMemoryWindow;
    IND2MemoryWindow*           OffsetMemoryWindow;
    IND2ManaCompletionQueue*    RecvCompletionQueue;
    IND2ManaCompletionQueue*    SendCompletionQueue;
    IND2ManaQueuePair*          QueuePair;
    IND2Connector*              Connector;
    RDMA_SEND_RING_BUFFER*      SendRingBuffer;
    RDMA_RECV_RING_BUFFER*      RecvRingBuffer;
    RDMA_REMOTE_RING_BUFFER*    RemoteRingBuffer;
    RDMA_CONNECTION_STATE       State;
    OVERLAPPED                  Ov;
    CXPLAT_SOCKET*              Socket; // Socket associated with this connection
    ULONG                       Flags;
    //CXPLAT_POOL                 SgePool;        
    CXPLAT_POOL                 ManaResultPool;
    uint8_t                     CibirIdLength;
    uint8_t                     CibirIdOffsetSrc;
    uint8_t                     CibirIdOffsetDst;  
    uint8_t                     CibirId[6];
    CXPLAT_LIST_ENTRY           SendQueue;
} RDMA_CONNECTION;

typedef struct CXPLAT_SEND_DATA
{
    CXPLAT_SEND_DATA_COMMON;

    //
    // The per-processor socket for this send data.
    //
    CXPLAT_SOCKET_PROC* SocketProc;

    //
    // The submission queue entry for the send completion.
    //
    CXPLAT_SQE Sqe;

    //
    // The owning processor context.
    //
    CXPLAT_DATAPATH_PARTITION* Owner;

    //
    // The pool for this send data.
    //
    CXPLAT_POOL* SendDataPool;

    //
    // Buffer to be sent. This is a pointer to an offset in the send ring buffer.
    //
    QUIC_BUFFER Buffer;

    //
    // Ring buffer offset for the send buffer.
    //
    uint32_t SendRingBufferOffset;

    //
    // Set of flags set to configure the send behavior.
    //
    uint8_t SendFlags; // CXPLAT_SEND_FLAGS

    //
    // Queue Entry to use to append to Send Queue.
    //
    CXPLAT_LIST_ENTRY SendQueueEntry;

} CXPLAT_SEND_DATA;

//
// Contains all the info for a single RX IO operation
//
typedef struct _RDMA_DATAPATH_RX_IO_BLOCK
{
    //
    // The owning datagram pool.
    //
    CXPLAT_POOL* OwningPool;

    //
    // The owning per-processor socket.
    //
    CXPLAT_SOCKET_PROC* SocketProc;

    //
    // The reference count of the receive buffer.
    //
    ULONG ReferenceCount;

    //
    // Contains the network route.
    //
    CXPLAT_ROUTE Route;

    //
    // The receive SQE.
    //
    CXPLAT_SQE Sqe;

} RDMA_DATAPATH_RX_IO_BLOCK;


typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) RDMA_DATAPATH_RX_PACKET
{
    //
    // The IO block that owns the packet.
    //
    RDMA_DATAPATH_RX_IO_BLOCK* IoBlock;

    //
    // Publicly visible receive data.
    //
    CXPLAT_RECV_DATA Data;

} RDMA_DATAPATH_RX_PACKET;

#pragma pack(push, 1)
typedef struct _RDMA_DATAPATH_PRIVATE_DATA
{
    uint64_t RemoteAddress;
    uint32_t Capacity;
    uint32_t RemoteToken;
    uint64_t RemoteOffsetBufferAdress;
    uint32_t RemoteOffsetBufferToken;
} RDMA_DATAPATH_PRIVATE_DATA;
#pragma pack(pop)

CXPLAT_EVENT_COMPLETION CxPlatIoRdmaRecvEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaSendEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaConnectEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaConnectCompletionEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaGetConnectionRequestEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaAcceptEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaDisconnectEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaTokenExchangeInitEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaTokenExchangeFinalEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaSendRingBufferOffsetsEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaRecvRingBufferOffsetsEventComplete;
CXPLAT_EVENT_COMPLETION CxPlatIoRdmaReadRingBufferOffsetsEventComplete;

//
// RDMA I/O helper functions
//

inline
void
UInt16ToByteBuffer(
    _In_ uint16_t Value,
    _Inout_bytecount_(2) uint8_t* Buffer
    )
{
    Buffer[0] = (uint8_t)(Value & 0xFF); // Most significant byte
    Buffer[1] = (uint8_t)((Value >> 8) & 0xFF); // Least significant byte
}

inline
uint16_t
ByteBufferToUInt16(
    _In_reads_bytes_(2) uint8_t* Buffer
    )
{
    uint16_t Value = 0;

    Value |= (Buffer[0] << 8);
    Value |= Buffer[1];

    return Value;
}

inline
void
UInt32ToByteBuffer(
    _In_ uint32_t Value,
    _Inout_bytecount_(4) uint8_t* Buffer
    )
{
    Buffer[0] = (uint8_t)(Value & 0xFF); // Most significant byte
    Buffer[1] = (uint8_t)((Value >> 8) & 0xFF);
    Buffer[2] = (uint8_t)((Value >> 16) & 0xFF);
    Buffer[3] = (uint8_t)((Value >> 24) & 0xFF);  // Least significant byte
}

inline
uint32_t
ByteBufferToUInt32(
    _In_reads_bytes_(4) uint8_t* Buffer
    )
{
    uint32_t Value = 0;

    Value |= (Buffer[0] << 24);
    Value |= (Buffer[1] << 16);
    Value |= (Buffer[2] << 8);
    Value |= Buffer[3];

    return Value;
}

inline
void
UInt64ToByteBuffer(
    _In_ uint64_t Value,
    _Inout_bytecount_(8) uint8_t* Buffer
    )
{
    for (int i = 0; i < 8; i++)
    {
        Buffer[i] = (Value >> (8 * i)) & 0xFF;
    }
}

inline
uint64_t
ByteBufferToUInt64(
    _In_reads_bytes_(8) uint8_t* Buffer
    )
{
    uint64_t Value = 0;

    for (int i = 0; i < 8; i++)
    {
        Value |= (uint64_t)Buffer[i] << (8 * i);
    }

    return Value;
}

inline
QUIC_STATUS
CopyRdmaConfig(CXPLAT_RDMA_CONFIG *src, CXPLAT_RDMA_CONFIG *dest)
{
    if (!src || !dest)
    {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    dest->Flags = src->Flags;
    dest->InterfaceIndex = src->InterfaceIndex;
    dest->PartitionIndex = src->PartitionIndex;
    dest->SendRingBufferSize = src->SendRingBufferSize;
    dest->RecvRingBufferSize = src->RecvRingBufferSize;
    dest->ProcessorGroup = src->ProcessorGroup;
    dest->Affinity = src->Affinity;
    dest->PostReceiveCount = src->PostReceiveCount;
    dest->CibirIdLength = src->CibirIdLength;
    dest->CibirIdOffsetSrc = src->CibirIdOffsetSrc;
    dest->CibirIdOffsetDst = src->CibirIdOffsetDst;
    memcpy_s(dest->CibirId, 6, src->CibirId, 6);


#ifdef QUIC_COMPARTMENT_ID
    dest->CompartmentId = src->CompartmentId;
#endif

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS
CxPlatRdmaStartAccept(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc
    );

QUIC_STATUS
CxPlatRdmaExchangeTokensInit(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

QUIC_STATUS
CxPlatRdmaRecvRemoteTokens(
    _In_ RDMA_CONNECTION* RdmaConnection
    );

QUIC_STATUS
CxPlatRdmaSendRemoteTokens(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ RDMA_CONNECTION* RdmaConnection
    );

QUIC_STATUS
CxPlatRdmaSendRingBufferOffsets(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

QUIC_STATUS
CxPlatRdmaRecvRingBufferOffsets(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

QUIC_STATUS
CxPlatRdmaReadRingBufferOffsets(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatCreateRdmaRecvPool(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvDataLength,
    _In_ uint16_t Index
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatCreateRdmaSendPool(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Index
    );


_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatCreateRdmaSendBufferPool(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Index
    );

void
CxPlatRdmaSendDataComplete(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ HRESULT IoResult
    );
//
// Try to start a new receive. Returns TRUE if the receive completed inline.
//
QUIC_STATUS
CxPlatDataPathRdmaStartReceiveAsync(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
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
    if (!NdAdapter ||
        !NdAdapter->Adapter)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateOverlappedFileFailed,
            "[ ndspi] CreateOverlappedFile failed, status: %d", Status);
             
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateOverlappedFile(NdAdapter->Adapter, OverlappedFile);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateOverlappedFileFailed,
            "[ ndspi] CreateOverlappedFile failed, status: %d", Status);
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
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateMemoryRegionFailed,
            "[ ndspi] CreateMemoryRegion failed, status: %d", Status);
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateMemoryRegion(
        NdAdapter->Adapter,
        &IID_IND2MemoryRegion,
        OverlappedFile,
        MemoryRegion);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateMemoryRegionFailed,
            "[ ndspi] CreateMemoryRegion failed, status: %d", Status);
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
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            RegisterMemoryFailed,
            "[ ndspi] RegisterMemory failed, status: %d", Status);
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
    else if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            RegisterMemoryFailed,
            "[ ndspi] RegisterMemory failed, status: %d", Status);
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

    if (!MemoryRegion || !Overlapped)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            DeRegisterMemoryFailed,
            "[ ndspi] DeRegisterMemory failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = MemoryRegion->lpVtbl->Deregister(MemoryRegion, Overlapped);
    if (Status == ND_PENDING)
    {
        Status = MemoryRegion->lpVtbl->GetOverlappedResult(
            MemoryRegion,
            Overlapped,
            TRUE);
    }
    else if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            DeRegisterMemoryFailed,
            "[ ndspi] DeRegisterMemory failed, status: %d", Status);
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
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateMemoryWindowFailed,
            "[ ndspi] CreateMemoryWindow failed, status: %d", Status);
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateMemoryWindow(
        NdAdapter->Adapter,
        &IID_IND2MemoryWindow,
        MemoryWindow);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateMemoryWindowFailed,
            "[ ndspi] CreateMemoryWindow failed, status: %d", Status);
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
    QUIC_STATUS Status = ND_SUCCESS;
    *CompletionQueue = NULL;

    if (!NdAdapter ||
        !NdAdapter->Adapter ||
        !queueDepth)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateCompletionQueueFailed,
            "[ ndspi] CreateCompletionQueueFailed failed, status: %d", Status);
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateCompletionQueueFailed,
            "[ ndspi] CreateCompletionQueueFailed failed, status: %d", Status);
    }

    return Status;
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
    QUIC_STATUS Status = ND_SUCCESS;
    *Connector = NULL;

    if (!NdAdapter || !NdAdapter->Adapter)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateConnectorFailed,
            "[ ndspi] CreateConnector failed, status: %d", Status);
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateConnector(
        NdAdapter->Adapter,
        &IID_IND2Connector,
        OverlappedFile,
        (VOID**)Connector);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateConnectorFailed,
            "[ ndspi] CreateConnector failed, status: %d", Status);
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
    QUIC_STATUS Status = ND_SUCCESS;
    *Listener = NULL;

    if (!NdAdapter ||
        !NdAdapter->Adapter)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateListenerFailed,
            "[ ndspi] CreateListener failed, status: %d", Status);
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateListener(
        NdAdapter->Adapter,
        &IID_IND2Listener,
        OverlappedFile,
        (VOID**)Listener);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateListenerFailed,
            "[ ndspi] CreateListener failed, status: %d", Status);
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
    _In_ ULONG Backlog
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!NdListener ||
        !NdListener->Listener)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            StartListenerFailed,
            "[ ndspi] StartListener failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = NdListener->Listener->lpVtbl->Listen(
        NdListener->Listener,
        Backlog);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            StartListenerFailed,
            "[ ndspi] StartListener failed, status: %d", Status);
    }

    return Status;
}

//
// Create a queue pair
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCreateQueuePair(
    _In_ RDMA_NDSPI_ADAPTER* NdAdapter,
    _In_ IND2ManaCompletionQueue* RecvCompletionQueue,
    _In_ IND2ManaCompletionQueue* SendCompletionQueue,
    _In_ VOID* Context,
    _In_ ULONG ReceiveQueueDepth,
    _In_ ULONG InitiatorQueueDepth,
    _In_ ULONG MaxReceiveRequestSge,
    _In_ ULONG MaxInitiatorRequestSge,
    _In_ ULONG InlineDataSize,
    _Deref_out_ IND2ManaQueuePair** QueuePair
)
{
    QUIC_STATUS Status = ND_SUCCESS;
    *QueuePair = NULL;

    if (!NdAdapter ||
        !NdAdapter->Adapter ||
        !SendCompletionQueue ||
        !RecvCompletionQueue)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CreateQueuePairFailed,
            "[ ndspi] CreateQueuePair failed, status: %d", Status);
        return QUIC_STATUS_INVALID_STATE;
    }

    Status = NdAdapter->Adapter->lpVtbl->CreateQueuePair(
        NdAdapter->Adapter,
        &IID_IND2ManaQueuePair,
        (IUnknown *)RecvCompletionQueue,
        (IUnknown *)SendCompletionQueue,
        Context,
        ReceiveQueueDepth,
        InitiatorQueueDepth,
        MaxReceiveRequestSge,
        MaxInitiatorRequestSge,
        InlineDataSize,
        (VOID**)QueuePair);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateQueuePairFailed,
            "[ ndspi] CreateQueuePair failed, status: %d", Status);
    }

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
    _In_ OVERLAPPED* Ov
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Connector || !QueuePair ||
        (PrivateData && !PrivateDataSize) ||
        (!PrivateData && PrivateDataSize))
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            AcceptFailed,
            "[ ndspi] Accept failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = Connector->lpVtbl->Accept(
        Connector,
        (IUnknown *)QueuePair,
        InboundReadLimit,
        OutboundReadLimit,
        PrivateData,
        PrivateDataSize,
        Ov);

    return Status;
}

//
// Perform a Bind
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiBindConnector(
    _In_ IND2Connector* Connector,
    _In_bytecount_ (SrcAddressSize) const struct sockaddr* SrcAddress,
    _In_ ULONG SrcAddressSize)
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Connector ||
        !SrcAddress ||
        !SrcAddressSize)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            ConnectorBindFailed,
            "[ ndspi]  Connector Bind failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Bind the connector to the source address
    //
    Status = Connector->lpVtbl->Bind(
        Connector,
        SrcAddress,
        SrcAddressSize);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            ConnectorBindFailed,
            "[ ndspi]  Connector Bind failed, status: %d", Status);
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
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Listener ||
        !SrcAddress ||
        !SrcAddressSize)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            ListenerBindFailed,
            "[ ndspi]  Listener Bind failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // Bind the listener to the source address
    //
    Status = Listener->lpVtbl->Bind(
        Listener,
        SrcAddress,
        SrcAddressSize);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            ListenerBindFailed,
            "[ ndspi]  Listener Bind failed, status: %d", Status);
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
    _In_bytecount_ (SrcAddressSize) const struct sockaddr* SrcAddress,
    _In_ ULONG SrcAddressSize,
    _In_bytecount_ (DestAddressSize) const struct sockaddr* DestAddress,
    _In_ ULONG DestAddressSize,
    _In_ ULONG InboundReadLimit,
    _In_ ULONG OutboundReadLimit,
    _In_bytecount_(PrivateDataSize) const VOID* PrivateData,
    _In_ ULONG PrivateDataSize,
    _In_ OVERLAPPED *Ov
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Connector || !QueuePair ||
        !SrcAddress || !SrcAddressSize ||
        !DestAddress || !DestAddressSize ||
        (PrivateData && !PrivateDataSize) ||
        (!PrivateData && PrivateDataSize))
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            ConnectFailed,
            "[ ndspi] Connect failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }  

    //
    // Bind the connector to the source address
    //
    Status = NdspiBindConnector(
        Connector,
        SrcAddress,
        SrcAddressSize);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            ConnectFailed,
            "[ ndspi] Connect failed, status: %d", Status);
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
        Ov);

    return Status;
}

//
// Complete the connect to a server
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiCompleteConnect(
    _In_ IND2Connector* Connector,
    _In_ OVERLAPPED *Ov)
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Connector)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            CompleteConnectFailed,
            "[ ndspi] CompleteConnect failed, status: %d", Status);
        return Status;
    }

    Status = Connector->lpVtbl->CompleteConnect(
        Connector,
        Ov);

    return Status;
}

//
// Disconnect the connector and associated queue pair from the peer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiDisconnect(
    _In_ IND2Connector* Connector,
    _In_ OVERLAPPED *Ov
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Connector ||
        !Ov)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            DisconnectFailed,
            "[ ndspi] Disconnect failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = Connector->lpVtbl->Disconnect(
        Connector,
        Ov);

    return Status;
}

//
// Disconnect the connector and associated queue pair from the peer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiNotifyDisconnect(
    _In_ IND2Connector* Connector,
    _In_ OVERLAPPED *Ov
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!Connector ||
        !Ov)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            DisconnectFailed,
            "[ ndspi] Disconnect failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = Connector->lpVtbl->NotifyDisconnect(
        Connector,
        Ov);
        
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
    QUIC_STATUS Status = ND_SUCCESS;

    if (!MemoryRegion ||
        !QueuePair ||
        !MemoryWindow ||
        !Buffer ||
        !BufferSize)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            BindMemoryWindowFailed,
            "[ ndspi] BindMemoryWindow failed, status: %d", Status);
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            BindMemoryWindowFailed,
            "[ ndspi] BindMemoryWindow failed, status: %d", Status);
    }

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
    QUIC_STATUS Status = ND_SUCCESS;

    if (!QueuePair ||
        !MemoryWindow)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            InvalidateMemoryWindowFailed,
            "[ ndspi] InvalidateMemoryWindow failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = QueuePair->lpVtbl->Invalidate(
        QueuePair,
        Context,
        (IUnknown *)MemoryWindow,
        Flags);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            InvalidateMemoryWindowFailed,
            "[ ndspi] InvalidateMemoryWindow failed, status: %d", Status);
    }

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
    QUIC_STATUS Status = ND_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize ||
        !RemoteAddress || !RemoteToken)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            NdspiWriteFailed,
            "[ ndspi] NdspiWrite failed, status: %d", Status);
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            NDSPIWriteFailed,
            "[ ndspi] NdspiWrite failed, status: %d", Status);
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
    _In_opt_ VOID *RequestContext,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ UINT64 RemoteAddress,
    _In_ UINT32 RemoteToken,
    _In_ ULONG Flags,
    _In_ UINT32 ImmediateData
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize ||
        !RemoteAddress ||
        !RemoteToken ||
        !ImmediateData)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            NdspiWriteWithImmediateFailed,
            "[ ndspi] NdspiWriteWithImmediate failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->WriteWithImmediate(
        RdmaConnection->QueuePair,
        RequestContext,
        Sge,
        SgeSize,
        RemoteAddress,
        RemoteToken,
        Flags,
        ImmediateData);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            NDSPIWriteWithImmediateFailed,
            "[ ndspi] NdspiWriteWithImmediate failed, status: %d", Status);
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
    _In_ ULONG Flags
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize ||
        !RemoteAddress ||
        !RemoteToken)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            NdspiReadFailed,
            "[ ndspi] NdspiRead failed, status: %d", Status);
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            NDSPIReadFailed,
            "NDSPI Read failed, status: %d", Status);
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
    QUIC_STATUS Status = ND_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            NdspiSendFailed,
            "[ ndspi] NdspiRead failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->Send(
        RdmaConnection->QueuePair,
        RdmaConnection,
        Sge,
        SgeSize,
        Flags);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            NDSPIReadFailed,
            "[ ndspi] NdspiSend failed, status: %d", Status);
    }

    return Status;
}

//
// RDMA Send
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
NdspiSendWithImmediate(
    _Inout_ RDMA_CONNECTION* RdmaConnection,
    _In_opt_ VOID *RequestContext,
    __in_ecount_opt(SgeSize) const void *Sge,
    _In_ ULONG SgeSize,
    _In_ ULONG Flags,
    _In_ UINT32 ImmediateData
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair ||
        !Sge ||
        !SgeSize)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            NdspiSendWithImmediateFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->SendWithImmediate(
        RdmaConnection->QueuePair,
        RequestContext,
        Sge,
        SgeSize,
        Flags,
        ImmediateData);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            NDSPIReadFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
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
    _In_opt_ VOID* Context,
    __in_ecount_opt(SgeSize) const ND2_SGE *Sge,
    _In_ ULONG SgeSize
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!RdmaConnection ||
        !RdmaConnection->QueuePair)
    {
        Status = ND_INVALID_PARAMETER;
        QuicTraceLogError(
            NdspiPostReceiveFailed,
            "[ ndspi] NdspiSendWithImmediate failed, status: %d", Status);
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    Status = RdmaConnection->QueuePair->lpVtbl->Receive(
        RdmaConnection->QueuePair,
        Context,
        Sge,
        SgeSize);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            NDSPIReadFailed,
            "[ ndspi] NdspiPostReceive failed, status: %d", Status);
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
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    RDMA_NDSPI_ADAPTER* RdmaAdapter = NULL;

    Status =  NdStartup();
    if (QUIC_FAILED(Status))
    {
        QuicTraceLogError(
            NdStartupFailed,
            "NdStartup failed, status: %d", Status);
    }

    // Check the Adapter Address
    //
    Status = NdCheckAddress((SOCKADDR *)LocalAddress, sizeof(QUIC_ADDR));
    if (QUIC_FAILED(Status))
    {
        QuicTraceLogError(
            NdCheckAddressFailed,
            "NdCheckAddress failed, status: %d", Status);
    }

    RdmaAdapter = (RDMA_NDSPI_ADAPTER*)CXPLAT_ALLOC_PAGED(sizeof(RDMA_NDSPI_ADAPTER), QUIC_POOL_DATAPATH);
    if (RdmaAdapter == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RDMA_NDSPI_ADAPTER",
            sizeof(RDMA_NDSPI_ADAPTER));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    RdmaAdapter->AddressFamily = LocalAddress->si_family;

    Status = NdOpenAdapter(
        &IID_IND2Adapter,
        (SOCKADDR *)LocalAddress,
        sizeof(QUIC_ADDR),
        (void**)&RdmaAdapter->Adapter);

    if (QUIC_FAILED(Status)) 
    {
        QuicTraceLogError(
            NdOpenAdapterFailed,
            "NdOpenAdapter failed, status: %d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateOverlappedFile(RdmaAdapter, &RdmaAdapter->OverlappedFile);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateOverlappedFile,
            "CreateAdapterOverlappedFile failed, status: %d", Status);
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

    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(RDMA_RECV_RING_BUFFER),
        QUIC_POOL_SOCKET,
        MAX_RDMA_CONNECTION_POOL_SIZE,
        NULL,
        NULL,
        &RdmaAdapter->RecvRingBufferPool);

    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(RDMA_RECV_RING_BUFFER),
        QUIC_POOL_SOCKET,
        MAX_RDMA_CONNECTION_POOL_SIZE,
        NULL,
        NULL,
        &RdmaAdapter->RemoteRingBufferPool);

    //
    // Populate the Adapter Info to get MAX values supported
    // for the adapter
    //
    ULONG AdapterInfoSize = sizeof(RdmaAdapter->AdapterInfo);
    Status = RdmaAdapter->Adapter->lpVtbl->Query(
        RdmaAdapter->Adapter,
        &RdmaAdapter->AdapterInfo,
        &AdapterInfoSize);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            QueryAdapterInfoFailed,
            "QueryAdapterInfo failed, status: %d", Status);
        goto ErrorExit;
    }

    *Adapter = RdmaAdapter;

    return Status;

ErrorExit:

    CxPlatRdmaAdapterRelease(RdmaAdapter);

    return Status;
}

//
// Cleanup an RDMA context
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
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
        CxPlatPoolUninitialize(&NdAdapter->RemoteRingBufferPool);

        CXPLAT_FREE(NdAdapter, QUIC_POOL_DATAPATH);
    }

    Status = NdCleanup();
    if (QUIC_FAILED(Status))
    {
        QuicTraceLogError(
            NdCleanupFailed,
            "NdCleanup failed, status: %d", Status);
    }
}

/*
//
// Build the Private Data to be shared with peer
// when Memory Window is not used
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RdmaBuildPrivateData(
    _In_ RDMA_CONNECTION* RdmaConnection,
    _In_Out_ ULONG *BufferLength)
{
    if (!RdmaConnection)
    {
        QuicTraceLogError(
            RdmaBuildPrivateDataFailed,
            "RdmaBuildPrivateData failed, NULL RdmaConnection");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    *BufferLength = 0;

    //
    // In this case, Memory Window will not be used
    //
    RdmaConnection->RecvMemoryWindow = NULL;
    RdmaConnection->OffsetMemoryWindow = NULL;

    // 
    // Use the send ring buffer allocated for the RDMA connection
    // to send the private data
    //
    memset(RdmaConnection->SendRingBuffer->Buffer, 0, RdmaConnection->SendRingBuffer->Capacity);
    RdmaConnection->SendRingBuffer->LocalToken = RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion);

    uint64_t RecvRingBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->Buffer;
    RdmaConnection->RecvRingBuffer->RemoteToken = RdmaConnection->MemoryRegion->lpVtbl->GetRemoteToken(RdmaConnection->MemoryRegion);

    UInt64ToByteBuffer(RecvRingBufferAdress, &RdmaConnection->SendRingBuffer->Buffer[0]);
    *BufferLength += sizeof(uint64_t);

    UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->Capacity, &RdmaConnection->SendRingBuffer->Buffer[*BufferLength]);
    *BufferLength += sizeof(uint32_t);

    UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->RemoteToken, &RdmaConnection->SendRingBuffer->Buffer[*BufferLength]);
    *BufferLength += sizeof(uint32_t);

    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        uint64_t OffsetBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->OffsetBuffer;
        RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken = RdmaConnection->MemoryRegion->lpVtbl->GetRemoteToken(RdmaConnection->MemoryRegion);

        UInt64ToByteBuffer(OffsetBufferAdress, &RdmaConnection->SendRingBuffer->Buffer[*BufferLength]);
        *BufferLength += sizeof(uint64_t);

        UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken, &RdmaConnection->SendRingBuffer->Buffer[*BufferLength]);
        *BufferLength += sizeof(uint32_t);
    }

    return QUIC_STATUS_SUCCESS;
}

//
// Build the Private Data to be shared with peer
// when Memory Window is not used
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RdmaParsePrivateData(
    _In_ RDMA_CONNECTION* RdmaConnection,
    _In_ uint16_t Type)
{
    ULONG BufferLength = 0;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (!RdmaConnection)
    {
        QuicTraceLogError(
            RdmaParsePrivateDataFailed,
            "RdmaParsePrivateData failed, NULL RdmaConnection");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    memset(RdmaConnection->RecvRingBuffer->Buffer, 0, RdmaConnection->RecvRingBuffer->Capacity);
    BufferLength = RdmaConnection->RecvRingBuffer->Capacity;
    Status = RdmaConnection->Connector->lpVtbl->GetPrivateData(
        RdmaConnection->Connector,
        RdmaConnection->RecvRingBuffer->Buffer,
        &BufferLength);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            RdmaParsePrivateDataFailed,
            "RdmaParsePrivateData failed, GetPrivateData Failed");
        return Status;
    }

    //
    // On the 
    //
    CXPLAT_DBG_ASSERT(
        (Type == CXPLAT_SOCKET_RDMA_SERVER && BufferLength == DEFAULT_RDMA_REQ_PRIVATE_DATA_SIZE) ||
        (Type == CXPLAT_SOCKET_RDMA && BufferLength == DEFAULT_RDMA_REP_PRIVATE_DATA_SIZE));

    RdmaConnection->RemoteRingBuffer->Head = RdmaConnection->RemoteRingBuffer->Tail = 0;
    RdmaConnection->RemoteRingBuffer->RemoteAddress = ByteBufferToUInt64(&RdmaConnection->RecvRingBuffer->Buffer[0]);
    RdmaConnection->RemoteRingBuffer->Capacity = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[8]);
    RdmaConnection->RemoteRingBuffer->RemoteToken = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[12]);

    if (RdmaConnection->RecvRingBuffer->Buffer[16] == 0)
    {
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferAddress = 0;
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferToken = 0;
    }
    else
    {
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferAddress = ByteBufferToUInt64(&RdmaConnection->RecvRingBuffer->Buffer[16]);
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferToken = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[24]);
    }

    memset(RdmaConnection->RecvRingBuffer->Buffer, 0, RdmaConnection->RecvRingBuffer->Capacity);

    return QUIC_STATUS_SUCCESS;
}
*/

//
// Build the Private Data to be shared with peer
// when Memory Window is not used
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RdmaBuildPrivateData(
    _In_ RDMA_CONNECTION* RdmaConnection,
    _Inout_ RDMA_DATAPATH_PRIVATE_DATA *PrivateData)
{
    if (!RdmaConnection)
    {
        QuicTraceLogError(
            RdmaBuildPrivateDataFailed,
            "RdmaBuildPrivateData failed, NULL RdmaConnection");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    //
    // In this case, Memory Window will not be used
    //
    RdmaConnection->RecvMemoryWindow = NULL;
    RdmaConnection->OffsetMemoryWindow = NULL;

    // 
    // Use the send ring buffer allocated for the RDMA connection
    // to send the private data
    //
    memset(RdmaConnection->SendRingBuffer->Buffer, 0, RdmaConnection->SendRingBuffer->Capacity);

    RdmaConnection->SendRingBuffer->LocalToken = RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion);

    uint64_t RecvRingBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->Buffer;
    RdmaConnection->RecvRingBuffer->RemoteToken = RdmaConnection->MemoryRegion->lpVtbl->GetRemoteToken(RdmaConnection->MemoryRegion);

    PrivateData->RemoteAddress = RecvRingBufferAdress;
    PrivateData->Capacity = RdmaConnection->RecvRingBuffer->Capacity;
    PrivateData->RemoteToken = RdmaConnection->RecvRingBuffer->RemoteToken;

    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        uint64_t OffsetBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->OffsetBuffer;
        RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken = RdmaConnection->MemoryRegion->lpVtbl->GetRemoteToken(RdmaConnection->MemoryRegion);

        PrivateData->RemoteOffsetBufferAdress = OffsetBufferAdress;
        PrivateData->RemoteOffsetBufferToken = RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken;
    }
    else
    {
        PrivateData->RemoteOffsetBufferAdress = 0;
        PrivateData->RemoteOffsetBufferToken = 0;
    }

    return QUIC_STATUS_SUCCESS;
}

//
// Build the Private Data to be shared with peer
// when Memory Window is not used
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RdmaParsePrivateData(
    _In_ RDMA_CONNECTION* RdmaConnection,
    _In_ uint16_t Type)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ULONG BufferLength = 0;
    RDMA_DATAPATH_PRIVATE_DATA* PrivateData = NULL;

    if (!RdmaConnection)
    {
        QuicTraceLogError(
            RdmaParsePrivateDataFailed,
            "RdmaParsePrivateData failed, NULL RdmaConnection");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    memset(RdmaConnection->RecvRingBuffer->Buffer, 0, RdmaConnection->RecvRingBuffer->Capacity);

    //
    // Create a buffer to parse the private data
    //
    Status = RdmaConnection->Connector->lpVtbl->GetPrivateData(
        RdmaConnection->Connector,
        NULL,
        &BufferLength);
    if (Status != ND_BUFFER_OVERFLOW)
    {
        QuicTraceLogError(
            RdmaParsePrivateDataFailed,
            "RdmaParsePrivateData failed, GetPrivateData to get len Failed");
        goto ErrorExit;
    }

    PrivateData = (RDMA_DATAPATH_PRIVATE_DATA*) CXPLAT_ALLOC_PAGED(BufferLength, QUIC_POOL_DATAPATH);
    if (PrivateData == NULL)
    {
        QuicTraceLogError(
            RdmaParsePrivateDataFailed,
            "RdmaParsePrivateData failed, PrivateData Allocation Failed");
        goto ErrorExit;  
    }

    Status = RdmaConnection->Connector->lpVtbl->GetPrivateData(
        RdmaConnection->Connector,
        PrivateData,
        &BufferLength);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            RdmaParsePrivateDataFailed,
            "RdmaParsePrivateData failed, GetPrivateData Failed");
        goto ErrorExit;
    }

    CXPLAT_DBG_ASSERT(
        (Type == CXPLAT_SOCKET_RDMA_SERVER && BufferLength == DEFAULT_RDMA_REQ_PRIVATE_DATA_SIZE) ||
        (Type == CXPLAT_SOCKET_RDMA && BufferLength == DEFAULT_RDMA_REP_PRIVATE_DATA_SIZE));

    RdmaConnection->RemoteRingBuffer->Head = RdmaConnection->RemoteRingBuffer->Tail = 0;
    RdmaConnection->RemoteRingBuffer->RemoteAddress = PrivateData->RemoteAddress;
    RdmaConnection->RemoteRingBuffer->Capacity = PrivateData->Capacity;
    RdmaConnection->RemoteRingBuffer->RemoteToken = PrivateData->RemoteToken;
    RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferAddress = PrivateData->RemoteOffsetBufferAdress;
    RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferToken = PrivateData->RemoteOffsetBufferToken;

ErrorExit:
    if (PrivateData)
    {
        CXPLAT_FREE(PrivateData, QUIC_POOL_DATAPATH);
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

    if (RdmaConnection->SendCompletionQueue)
    {
        RdmaConnection->SendCompletionQueue->lpVtbl->Release(RdmaConnection->SendCompletionQueue);
    }

    if (RdmaConnection->RecvCompletionQueue)
    {
        RdmaConnection->RecvCompletionQueue->lpVtbl->Release(RdmaConnection->RecvCompletionQueue);
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

    if (RdmaConnection->RemoteRingBuffer)
    {
        CxPlatPoolFree(&RdmaConnection->Adapter->RemoteRingBufferPool, RdmaConnection->RemoteRingBuffer);
    }

    if (RdmaConnection->ConnOverlappedFile)
    {
        CloseHandle(RdmaConnection->ConnOverlappedFile);
    }

    //CxPlatPoolUninitialize(&RdmaConnection->SgePool);

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
        CXPLAT_FREE(RdmaListener->Config, QUIC_POOL_DATAPATH);
    }

    CXPLAT_FREE(RdmaListener, QUIC_POOL_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatRdmaSocketRelease(
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

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatRdmaSocketCancelRequests(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (Socket->RdmaContext)
    {
        switch (Socket->Type)
        {
            case CXPLAT_SOCKET_RDMA:
            case CXPLAT_SOCKET_RDMA_SERVER:
                RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;
                RdmaConnection->Connector->lpVtbl->CancelOverlappedRequests(RdmaConnection->Connector);
                break;
            case CXPLAT_SOCKET_RDMA_LISTENER:
                RDMA_NDSPI_LISTENER* RdmaListener = (RDMA_NDSPI_LISTENER*)Socket->RdmaContext;
                RdmaListener->Listener->lpVtbl->CancelOverlappedRequests(RdmaListener->Listener);
                break;
            default:
                CXPLAT_DBG_ASSERT(FALSE);
                break;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatRdmaSocketContextRelease(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CXPLAT_DBG_ASSERT(!SocketProc->Freed);
    if (CxPlatRefDecrement(&SocketProc->RefCount))
    {
        if (SocketProc->Parent->Type == CXPLAT_SOCKET_RDMA_LISTENER)
        {
            if (SocketProc->AcceptSocket != NULL)
            {
                CxPlatRdmaSocketRelease(SocketProc->AcceptSocket);
                SocketProc->AcceptSocket = NULL;
            }
        }

        CxPlatRundownUninitialize(&SocketProc->RundownRef);

        QuicTraceLogVerbose(
            DatapathSocketContextComplete,
            "[data][%p] RDMA Socket context shutdown",
            SocketProc);

        if (SocketProc->DatapathProc)
        {
            CxPlatProcessorContextRelease(SocketProc->DatapathProc);
        }

        SocketProc->Freed = TRUE;
        CxPlatRdmaSocketRelease(SocketProc->Parent);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRdmaSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    if (!Socket)
    {
        return;
    }

    CxPlatRdmaSocketCancelRequests(Socket);

    CXPLAT_SOCKET_PROC* SocketProc = &Socket->PerProcSockets[0];
    CXPLAT_DBG_ASSERT(!SocketProc->Uninitialized);

    if (!SocketProc->IoStarted)
    {

        goto EarlyExit;
    }

    //
    // Block on all outstanding references. This ensure that there are no more
    // calls on the Socket, and that the app doesn't get any more upcalls after
    // this.
    //
    CxPlatRundownReleaseAndWait(&SocketProc->RundownRef);
    SocketProc->Uninitialized = TRUE;

EarlyExit:
    //
    // Finally, release the "main" reference on the context from the parent. If
    // there are no outstanding IOs, then the context will be cleaned up inline.
    //
    CxPlatRdmaSocketContextRelease(SocketProc);
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
    _In_opt_ const QUIC_ADDR* RemoteAddress,
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
    uint8_t *RemoteOffsetBuffer = NULL;
    size_t BufferSize = 0;
    RDMA_DATAPATH_PRIVATE_DATA PrivateData = {0};

    *NewSocket = NULL;

    if (!Datapath ||
        !Datapath->RdmaAdapter ||
        !Config ||
        !Config->SendRingBufferSize ||
        !Config->RecvRingBufferSize ||
        Config->SendRingBufferSize < MIN_RING_BUFFER_SIZE ||
        Config->RecvRingBufferSize < MIN_RING_BUFFER_SIZE ||
        (Type != CXPLAT_SOCKET_RDMA_SERVER && RemoteAddress == NULL) ||
        (Type == CXPLAT_SOCKET_RDMA_SERVER && LocalAddress == NULL))
    {
        QuicTraceLogError(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid parameters");
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
        return QUIC_STATUS_OUT_OF_MEMORY;
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

    if (LocalAddress)
    {
        memcpy_s(&Socket->LocalAddress, sizeof(QUIC_ADDR), LocalAddress, sizeof(QUIC_ADDR));
    }

    if (RemoteAddress != NULL)
    {
        memcpy_s(&Socket->RemoteAddress, sizeof(QUIC_ADDR), RemoteAddress, sizeof(QUIC_ADDR));
    }
    else
    {
        Socket->RemoteAddress.Ipv4.sin_port = 0;
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

    SocketProc->Parent = Socket; // should satisfy ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent
    SocketProc->Socket = INVALID_SOCKET;
    SocketProc->RdmaSocket = INVALID_HANDLE_VALUE;
    CxPlatRundownInitialize(&SocketProc->RundownRef);
    SocketProc->RioCq = RIO_INVALID_CQ;
    SocketProc->RioRq = RIO_INVALID_RQ;

    //
    // Create a new RDMA connection object
    //
    NdAdapter = (RDMA_NDSPI_ADAPTER*) Datapath->RdmaAdapter;
    if (!NdAdapter)
    {
        QuicTraceLogError(
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
    CxPlatListInitializeHead(&RdmaConnection->SendQueue);

    //
    // Create References between Socket and RdmaConnection
    //
    Socket->RdmaContext = RdmaConnection;
    RdmaConnection->Socket = Socket;
    RdmaConnection->Adapter = NdAdapter;

    /*
    CxPlatPoolInitializeEx(
        FALSE,
        sizeof(ND2_SGE),
        QUIC_POOL_PLATFORM_GENERIC,
        MAX_SGE_POOL_SIZE,
        NULL,
        NULL,
        &RdmaConnection->SgePool);
    */
    
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

    if (!(Config->Flags & CXPLAT_RDMA_FLAG_NO_MEMORY_WINDOW))
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
        BufferSize += (2 * DEFAULT_OFFSET_BUFFER_SIZE);
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
        &RdmaConnection->ConnOverlappedFile);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateConnOverlappedFileFailed,
            "CreateConnOverlappedFile failed, status:%d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateMemoryRegion(
        NdAdapter,
        RdmaConnection->ConnOverlappedFile,
        &RdmaConnection->MemoryRegion);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateMemoryRegionFailed,
            "CreateMemoryRegion failed, status: %d", Status);
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
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
        RemoteOffsetBuffer = OffsetBuffer + DEFAULT_OFFSET_BUFFER_SIZE;
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
        RdmaConnection->SendRingBuffer,
        SendRingBuffer,
        Config->SendRingBufferSize,
        RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion));
    if (Status != QUIC_STATUS_SUCCESS)
    {
        QuicTraceLogError(
            SendRingBufferInitFailed,
            "SendRingBufferInit failed, status: %d", Status);
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

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
        RdmaConnection->RecvRingBuffer,
        RecvRingBuffer,
        Config->RecvRingBufferSize,
        OffsetBuffer,
        OffsetBuffer != NULL ? DEFAULT_OFFSET_BUFFER_SIZE : 0,
        RdmaConnection->MemoryRegion->lpVtbl->GetLocalToken(RdmaConnection->MemoryRegion));
    if (Status != QUIC_STATUS_SUCCESS)
    {
        QuicTraceLogError(
            RecvRingBufferInitFailed,
            "RecvRingBufferInit failed, status:%d", Status);
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

    //
    // Create Remote Ring Buffer object for connection
    //
    RdmaConnection->RemoteRingBuffer = CxPlatPoolAlloc(&NdAdapter->RemoteRingBufferPool);
    if (RdmaConnection->RemoteRingBuffer == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RemoteRingBuffer",
            Config->RecvRingBufferSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    //
    // Initialize the remote ring buffer object
    //
    Status = RdmaRemoteRingBufferInitialize(
        RdmaConnection->RemoteRingBuffer,
        RemoteOffsetBuffer,
        RemoteOffsetBuffer != NULL ? DEFAULT_OFFSET_BUFFER_SIZE : 0);
    if (Status != QUIC_STATUS_SUCCESS)
    {
        QuicTraceLogError(
            RecvRingBufferInitFailed,
            "RemoteRingBufferInit failed, status:%d", Status);
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

    //
    // Create Send Completion queue
    //
    Status = NdspiCreateCompletionQueue(
        NdAdapter,
        RdmaConnection->ConnOverlappedFile,
        NdAdapter->AdapterInfo.MaxCompletionQueueDepth,
        Config->ProcessorGroup,
        Config->Affinity,
        &RdmaConnection->SendCompletionQueue);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateSendCompletionQueueFailed,
            "Create Send CompletionQueue failed, status: %d", Status);
        goto ErrorExit;
    }

    //
    // Create Recv Completion queue
    //
    Status = NdspiCreateCompletionQueue(
        NdAdapter,
        RdmaConnection->ConnOverlappedFile,
        NdAdapter->AdapterInfo.MaxCompletionQueueDepth,
        Config->ProcessorGroup,
        Config->Affinity,
        &RdmaConnection->RecvCompletionQueue);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateRecvCompletionQueueFailed,
            "Create Receive CompletionQueue failed, status: %d", Status);
        goto ErrorExit;
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
        NdAdapter->AdapterInfo.MaxInlineDataSize,
        &RdmaConnection->QueuePair);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateQueuePairFailed,
            "Create QueuePair failed, status:%d", Status);
        goto ErrorExit;
    }

    Status = NdspiCreateConnector(
        NdAdapter,
        RdmaConnection->ConnOverlappedFile,
        &RdmaConnection->Connector);
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
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
        if (Status != ND_SUCCESS)
        {
            QuicTraceLogError(
                CreateRecvMemoryWindowFailed,
                "Create RecvMemoryWindow failed, status:%d", Status);
            goto ErrorExit;
        }
        
        if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
        {
            Status = NdspiCreateMemoryWindow(NdAdapter, &RdmaConnection->OffsetMemoryWindow);
            if (Status != ND_SUCCESS)
            {
                QuicTraceLogError(
                    CreateSendMemoryWindowFailed,
                    "Create SendMemoryWindow failed, status: %d", Status);
                goto ErrorExit;
            }
        }
    }
    else if (Type != CXPLAT_SOCKET_RDMA_SERVER)
    {
        //
        // If Memory window is not configured, then share the remote
        // tokens with the peer using the private data
        //
        Status = RdmaBuildPrivateData(
            RdmaConnection,
            &PrivateData);
        if (QUIC_FAILED(Status))
        {
            QuicTraceLogError(
                RdmaBuildPrivateDataFailed,
                "RdmaBuildPrivateData failed, status:%d", Status);
            goto ErrorExit;
        }
    }

    SocketProc->RdmaSocket = RdmaConnection->ConnOverlappedFile;

    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
        SocketProc->RdmaSocket,
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
        SocketProc->DatapathProc = &Datapath->Partitions[0];
        CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

        if (!CxPlatEventQAssociateHandle(
            SocketProc->DatapathProc->EventQ,
            SocketProc->RdmaSocket)) 
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

        if (RemoteAddress != NULL)
        {
            /*
            SOCKADDR_INET MappedRemoteAddress = { 0 };
            CxPlatConvertToMappedV6(RemoteAddress, &MappedRemoteAddress);
            */

            CxPlatStartDatapathIo(
                SocketProc,
                &SocketProc->IoSqe,
                CxPlatIoRdmaConnectEventComplete);
   
            Status = NdspiConnect(
                RdmaConnection->Connector,
                RdmaConnection->QueuePair,
                (PSOCKADDR)&Socket->LocalAddress,
                sizeof(Socket->LocalAddress),
                (PSOCKADDR)RemoteAddress,
                sizeof(QUIC_ADDR),
                1,
                1,
                //RdmaConnection->Adapter->AdapterInfo.MaxInboundReadLimit,
                //RdmaConnection->Adapter->AdapterInfo.MaxOutboundReadLimit,
                &PrivateData,
                sizeof(PrivateData),
                &SocketProc->IoSqe.Overlapped);
            if (Status != ND_SUCCESS)
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
            RdmaConnection->State = RdmaConnectionStateConnecting;
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
        if (Status != ND_SUCCESS)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status, "IND2Connector::QueryLocalAddress");
            goto ErrorExit;
        }

        if (LocalAddress && LocalAddress->Ipv4.sin_port != 0)
        {
            CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
        }
    }

    *NewSocket = Socket;
    Socket = NULL;
    RawSocket = NULL;

    return ND_SUCCESS;
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

    if (RawSocket != NULL)
    {
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
    *NewSocket = NULL;

    if (!Datapath ||
        !LocalAddress ||
        !Datapath->RdmaAdapter ||
        !Config)
    {
        QuicTraceLogError(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CXPLAT_DBG_ASSERT(Datapath->RdmaHandlers.Receive != NULL);

    CXPLAT_SOCKET_PROC* SocketProc = NULL;
    uint32_t RawSocketLength = CxPlatGetRawSocketSize() + sizeof(CXPLAT_SOCKET_PROC);
    CXPLAT_SOCKET_RAW* RawSocket = CXPLAT_ALLOC_PAGED(RawSocketLength, QUIC_POOL_SOCKET);
    if (RawSocket == NULL)
    {
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
    memcpy_s(&Socket->LocalAddress, sizeof(QUIC_ADDR), LocalAddress, sizeof(QUIC_ADDR));

    Socket->Mtu = CXPLAT_MAX_MTU;
    CxPlatRefInitializeEx(&Socket->RefCount, 1);

    SocketProc = &Socket->PerProcSockets[0];
    CxPlatRefInitialize(&SocketProc->RefCount);
    SocketProc->Parent = Socket;
    SocketProc->Socket = INVALID_SOCKET;
    SocketProc->RdmaSocket = INVALID_HANDLE_VALUE;
    CxPlatRundownInitialize(&SocketProc->RundownRef);
    SocketProc->RioCq = RIO_INVALID_CQ;
    SocketProc->RioRq = RIO_INVALID_RQ;

    //
    // Create a new RDMA connection object
    //
    NdAdapter = (RDMA_NDSPI_ADAPTER*) Datapath->RdmaAdapter;
    if (!NdAdapter)
    {
        QuicTraceLogError(
            CreateRdmaSocketFailed,
            "CreateRdmaSocket failed, invalid RDMA adapter");
        Status = QUIC_STATUS_INVALID_STATE;
        goto ErrorExit;
    }

    //
    // Create RDMA_LISTENER object
    //
    RdmaListener = (RDMA_NDSPI_LISTENER*) CXPLAT_ALLOC_PAGED(sizeof(RDMA_NDSPI_LISTENER), QUIC_POOL_DATAPATH);
    if (RdmaListener == NULL)
    {
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
            CreateListenerFailed,
            "CreateListener failed, status:%d", Status);
        goto ErrorExit;
    }

    //
    // Associate the Lister OV object for IOCP use
    //
    SocketProc->RdmaSocket = RdmaListener->OverlappedListenerFile;
    //
    // Disable automatic IO completions being queued if the call completes
    // synchronously. This is because we want to be able to complete sends
    // inline, if possible.
    //
    if (!SetFileCompletionNotificationModes(
        SocketProc->RdmaSocket,
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
    // Create References between Socket and RdmaListener
    //
    Socket->RdmaContext = RdmaListener;
    RdmaListener->ListenerSocket = Socket;
    RdmaListener->Adapter = NdAdapter;
    RdmaListener->Config = (CXPLAT_RDMA_CONFIG*) CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_RDMA_CONFIG), QUIC_POOL_DATAPATH);

    if (RdmaListener->Config == NULL)
    {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        QuicTraceLogError(
            ListenerRdmaConfigInitFailed,
            "ListenerRdmaConfigInit Failed, status:%d", Status);
        goto ErrorExit;       
    }
    CopyRdmaConfig(Config, RdmaListener->Config);

    SocketProc->DatapathProc = &Datapath->Partitions[0];
    CxPlatRefIncrement(&SocketProc->DatapathProc->RefCount);

    if (!CxPlatEventQAssociateHandle(
            SocketProc->DatapathProc->EventQ,
            (HANDLE)SocketProc->RdmaSocket))
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "bind");
        goto ErrorExit;
    }

    if (LocalAddress && LocalAddress->Ipv4.sin_port != 0)
    {
        CXPLAT_DBG_ASSERT(LocalAddress->Ipv4.sin_port == Socket->LocalAddress.Ipv4.sin_port);
    }

    Status = NdspiStartListener(RdmaListener, 0);
    if (Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status,
            "listen");
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
    if (Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            Socket,
            Status, "IND2Connector::QueryLocalAddress");
        goto ErrorExit;
    }

    Status = CxPlatRdmaStartAccept(SocketProc);
    if (QUIC_FAILED(Status))
    {
        goto ErrorExit;
    }

    SocketProc->IoStarted = TRUE;

    *NewSocket = Socket;
    Socket = NULL;
    RawSocket = NULL;
    Status = QUIC_STATUS_SUCCESS;

    return Status;

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

QUIC_STATUS
RdmaSocketSendInline(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    ND2_SGE *SendSge = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_DBG_ASSERT(SocketProc != NULL && SendData != NULL);
    uint64_t RemoteRecvBuffer = 0;
    uint32_t RemoteRecvBufferOffset = 0;
    uint32_t RemoteRecvBufferLength = 0;
    uint32_t ImmediateData = 0;

    CXPLAT_DBG_ASSERT(SocketProc->Parent && SocketProc->Parent->RdmaContext);
    CXPLAT_SOCKET *Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

    //
    // Check if memory can be fetched to write to the peer buffer
    //
    Status = RdmaRemoteRecvRingBufferReserve(
        RdmaConnection->RemoteRingBuffer,
        SendData->Buffer.Length,
        &RemoteRecvBuffer,
        &RemoteRecvBufferOffset,
        &RemoteRecvBufferLength);

    if (QUIC_FAILED(Status))
    {
        if (Status == QUIC_STATUS_INVALID_PARAMETER)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "RdmaRemoteRecvRingBufferReserve");
        }
        else
        {
            CxPlatListInsertTail(&RdmaConnection->SendQueue, &SendData->SendQueueEntry);
        }

        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    CXPLAT_DBG_ASSERT(RemoteRecvBufferLength == SendData->Buffer.Length);

    //
    // When Offset buffer is used, the immediate data will contain the payload length.
    // In the normal case, the immediate data will contain the offset and the payload length.
    //
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        ImmediateData = RemoteRecvBufferLength;
    }
    else
    {
        ImmediateData = ((RemoteRecvBufferOffset << 16) & 0xFFFF0000);
        ImmediateData |= (RemoteRecvBufferLength & 0x0000FFFF);
    }

    //SendSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    SendSge = CXPLAT_ALLOC_PAGED(sizeof(ND2_SGE), QUIC_POOL_PLATFORM_GENERIC);
    if (SendSge == NULL)
    {
        QuicTraceEvent(
            AllocFailure,
            "SendSge Allocation of '%s' failed. (%llu bytes)",
            "ND2_SGE",
            sizeof(ND2_SGE));
        goto ErrorExit;
    }

    //
    // Populate ND2_SGE data structure
    //
    SendSge->Buffer = SendData->Buffer.Buffer;
    SendSge->BufferLength = SendData->Buffer.Length; 
    SendSge->MemoryRegionToken = RdmaConnection->SendRingBuffer->LocalToken; 

    //
    // Schedule an RDMA write to the peer
    //
    Status = NdspiWriteWithImmediate(
        RdmaConnection,
        SendData,
        SendSge,
        1,
        RemoteRecvBuffer,
        RdmaConnection->RemoteRingBuffer->RemoteToken,
        0,
        ImmediateData);
    if (Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "IND2QueuePair::WriteWithImmediate for data transfer");
        goto ErrorExit;
    }

    CxPlatStartDatapathIo(
        SendData->SocketProc,
        &SendData->Sqe,
        CxPlatIoRdmaSendEventComplete);

    //
    // Call Notify on the completion queue to get send complete
    // notification
    //
    Status = RdmaConnection->SendCompletionQueue->lpVtbl->Notify(
        RdmaConnection->SendCompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &SendData->Sqe.Overlapped);
    if (Status != ND_SUCCESS)
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                Status,
                "RdmaSocketSend IND2CompletionQueue::Notify");
            goto ErrorExit;
        }

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(
            SendData->SocketProc,
            &SendData->Sqe,
            0);
        if (QUIC_FAILED(Status))
        {
            CxPlatCancelDatapathIo(SocketProc);
            goto ErrorExit;
        }
    }

ErrorExit:
    if (Status != ND_SUCCESS)
    {
        if (RemoteRecvBuffer && RemoteRecvBufferLength)
        {
            RdmaRemoteReceiveRingBufferRelease(
                RdmaConnection->RemoteRingBuffer,
                SendData->Buffer.Length);
        }

        RdmaSendDataFree(SendData);
    }

    if (SendSge != NULL)
    {
        //CxPlatPoolFree(&RdmaConnection->SgePool, SendSge);
        CXPLAT_FREE(SendSge, QUIC_POOL_PLATFORM_GENERIC);
    }

    return Status;
}

QUIC_STATUS
RdmaSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const CXPLAT_ROUTE* Route,
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL && Route != NULL && SendData != NULL);
    CXPLAT_DBG_ASSERT(Route->Queue);
    CXPLAT_SOCKET_PROC* SocketProc = Route->Queue;

    CXPLAT_DBG_ASSERT(SocketProc->Parent && SocketProc->Parent->RdmaContext);
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

    //
    // Check if there are entries in the send queue
    // and if so, insert the new send data at the end of the queue.
    //
    if (!CxPlatListIsEmpty(&RdmaConnection->SendQueue))
    {
        CxPlatListInsertTail(&RdmaConnection->SendQueue, &SendData->SendQueueEntry);

        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    QuicTraceEvent(
        DatapathSend,
        "[data][%p] Send %u bytes in %hhu buffers (segment=%hu) Dst=%!ADDR!, Src=%!ADDR!",
        Socket,
        SendData->Buffer.Length,
        1,
        (uint16_t)SendData->Buffer.Length,
        CASTED_CLOG_BYTEARRAY(sizeof(Route->RemoteAddress), &Route->RemoteAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Route->LocalAddress), &Route->LocalAddress));

    return RdmaSocketSendInline(SocketProc, SendData);
}

void
RdmaSocketPendingSend(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "RdmaSocketPendingSend failed, invalid parameters");
        return;
    }

    CXPLAT_SOCKET *Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;
    QUIC_STATUS Status;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    while (!CxPlatListIsEmpty(&RdmaConnection->SendQueue))
    {
        CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&RdmaConnection->SendQueue);
        CXPLAT_SEND_DATA* SendData = CONTAINING_RECORD(Entry, CXPLAT_SEND_DATA, SendQueueEntry);

        Status = RdmaSocketSendInline(SocketProc, SendData);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "RdmaSocketPendingSend");

            //
            // Reinsert the entry to the head of the list to maintain order
            //
            CxPlatListInsertHead(&RdmaConnection->SendQueue, &SendData->SendQueueEntry);
            break;
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatCreateRdmaRecvPool(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvDataLength,
    _In_ uint16_t Index
    )
{
    Datapath->RdmaDatagramStride =
        ALIGN_UP(
            sizeof(RDMA_DATAPATH_RX_PACKET) +
            ClientRecvDataLength,
            PVOID);

    Datapath->RecvRdmaPayloadContext =
        sizeof(RDMA_DATAPATH_RX_IO_BLOCK) + Datapath->RdmaDatagramStride;

    CxPlatPoolInitialize(
        FALSE,
        Datapath->RecvRdmaPayloadContext,
        QUIC_POOL_DATA,
        &Datapath->Partitions[Index].RecvRdmaDatagramPool.Base);
    CxPlatAddDynamicPoolAllocator(
        Datapath->WorkerPool,
        &Datapath->Partitions[Index].RecvRdmaDatagramPool,
        Index); 
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
RdmaSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    CXPLAT_DBG_ASSERT(Socket != NULL);

    if (Config->Route->Queue == NULL) {
        Config->Route->Queue = &Socket->PerProcSockets[0];
    }

    CXPLAT_SOCKET_PROC* SocketProc = Config->Route->Queue;
    CXPLAT_DATAPATH_PARTITION* DatapathProc = SocketProc->DatapathProc;
    CXPLAT_POOL* SendDataPool = &DatapathProc->RdmaSendDataPool;

    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(SendDataPool);

    if (SendData != NULL)
    {
        SendData->Owner = DatapathProc;
        SendData->SendDataPool = SendDataPool;
        SendData->ECN = Config->ECN;
        SendData->DSCP = Config->DSCP;
        SendData->SendFlags = Config->Flags;   

        SendData->DatapathType = Config->Route->DatapathType = CXPLAT_DATAPATH_TYPE_RDMA;

        //
        // Capture the SocketProc to be used for sending this data
        //
        CxPlatRefIncrement(&SocketProc->RefCount);
        SendData->SocketProc = SocketProc;
    }

    return SendData;
}

void
RdmaSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    //
    // Release the memory by moving the Head pointer
    //
    if (SendData)
    {
        CxPlatPoolFree(SendData->SendDataPool, SendData);
        CxPlatRdmaSocketContextRelease(SendData->SocketProc);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
RdmaSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL && SendData->SocketProc != NULL && SendData->SocketProc->Parent != NULL);
    CXPLAT_DBG_ASSERT(MaxBufferLength > 0);

    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SendData->SocketProc->Parent->RdmaContext;
    CXPLAT_DBG_ASSERT(RdmaConnection != NULL);
    CXPLAT_DBG_ASSERT(RdmaConnection->SendRingBuffer != NULL);
    uint8_t* Buffer = NULL;
    uint32_t BufferLength = 0;
    uint32_t Offset = 0;

    QUIC_STATUS Status = RdmaSendRingBufferReserve(
        RdmaConnection->SendRingBuffer,
        MaxBufferLength,
        &Buffer,
        &Offset,
        &BufferLength);
    if (QUIC_FAILED(Status) || Buffer == NULL || BufferLength == 0)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SendData->SocketProc->Parent,
            Status,
            "RdmaSendDataAllocBuffer RdmaSendRingBufferReserve");
        return NULL;
    }

    SendData->Buffer.Buffer = Buffer;
    SendData->Buffer.Length = BufferLength;
    SendData->SendRingBufferOffset = Offset;

    return &SendData->Buffer;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RdmaSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL && SendData->SocketProc != NULL && SendData->SocketProc->Parent != NULL);
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SendData->SocketProc->Parent->RdmaContext;
    CXPLAT_DBG_ASSERT(RdmaConnection != NULL);
    CXPLAT_DBG_ASSERT(RdmaConnection->SendRingBuffer != NULL);

    RdmaSendRingBufferRelease(
        RdmaConnection->SendRingBuffer,
        Buffer->Buffer,
        SendData->SendRingBufferOffset,
        Buffer->Length);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
RdmaSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DBG_ASSERT(SendData != NULL && SendData->SocketProc != NULL && SendData->SocketProc->Parent != NULL);
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SendData->SocketProc->Parent->RdmaContext;
    CXPLAT_DBG_ASSERT(RdmaConnection != NULL);
    CXPLAT_DBG_ASSERT(RdmaConnection->SendRingBuffer != NULL);  

    uint32_t AvailableBytes = (RdmaConnection->SendRingBuffer->CurSize == RdmaConnection->SendRingBuffer->Capacity);

    return  AvailableBytes == 0 || AvailableBytes < MIN_FREE_BUFFER_THRESHOLD;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatCreateRdmaSendPool(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Index
    )
{
    CxPlatPoolInitialize(
        FALSE,
        sizeof(CXPLAT_SEND_DATA),
        QUIC_POOL_PLATFORM_SENDCTX,
        &Datapath->Partitions[Index].RdmaSendDataPool);
}

//
// Free Child Objects allocated within an RDMA_CONNECTION object
//
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
        QuicTraceLogError(
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
            &ListenerSocketProc->Parent->LocalAddress,
            NULL,
            ListenerSocketProc->Parent->ClientContext,
            RdmaListener->Config,
            &ListenerSocketProc->AcceptSocket);
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
    if (Status != ND_SUCCESS)
    {
        if (Status != ND_PENDING)
        {
            QuicTraceLogError(
                GetConnectionRequestFailed,
                "GetConnectionRequest failed, status:%d", Status);
            CxPlatCancelDatapathIo(ListenerSocketProc);
            goto ErrorExit;
        }

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
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
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

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
    if (Status != ND_SUCCESS)
    {
        QuicTraceLogError(
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
        if (Status != ND_SUCCESS)
        {
            QuicTraceLogError(
                BindRecvMemoryWindowFailed,
                "BindRecvMemoryWindow failed, status:%d", Status);
            goto ErrorExit;
        }
    }

    //
    // Post a receive to get the ring buffer tokens from the peer
    // This is common operation for both client and server
    //
    //RecvSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    RecvSge = CXPLAT_ALLOC_PAGED(sizeof(ND2_SGE), QUIC_POOL_PLATFORM_GENERIC);
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
    RecvSge->MemoryRegionToken = RdmaConnection->RecvRingBuffer->LocalToken;

    Status = NdspiPostReceive(
        RdmaConnection,
        NULL,
        RecvSge,
        1);
    if (Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "IND2QueuePair::Receive for fetching ring buffer tokens");

        goto ErrorExit;
    }

    CxPlatStartDatapathIo(
        SocketProc,
        &SocketProc->IoSqe,
        CxPlatIoRdmaTokenExchangeInitEventComplete);

    if (Socket->Type == CXPLAT_SOCKET_RDMA_SERVER)
    {
        //
        // For server, first post a receive to get the ring buffer details from  client.
        // The server would then send the remote tokens for tis ring buffers
        //
        Status = RdmaConnection->RecvCompletionQueue->lpVtbl->Notify(
            RdmaConnection->RecvCompletionQueue,
            ND_CQ_NOTIFY_ANY,
            &SocketProc->IoSqe.Overlapped);
        if (Status != ND_SUCCESS)   
        {
            if (Status != ND_PENDING)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    Status,
                    "RecvCompletionQueue::Notify");
                goto ErrorExit;
            }

            //
            // Reset Status to success when event is pending
            //
            Status = ND_SUCCESS;
        }
        else
        {
            //
            // Manually post IO completion if accept completed synchronously.
            //
            Status = CxPlatSocketEnqueueSqe(
                SocketProc,
                &SocketProc->IoSqe,
                BytesRecv);
            if (QUIC_FAILED(Status))
            {
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
        //CxPlatPoolFree(&RdmaConnection->SgePool, RecvSge);
        CXPLAT_FREE(RecvSge, QUIC_POOL_PLATFORM_GENERIC);
    }
    
    return Status;
}

QUIC_STATUS
CxPlatRdmaSendRingBufferOffsets(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;
    uint32_t ImmediateData = 0;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;
    CXPLAT_SOCKET *Socket = SocketProc->Parent;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    CxPlatStartDatapathIo(
        SocketProc,
        &SocketProc->IoSqe,
        CxPlatIoRdmaSendRingBufferOffsetsEventComplete);

    //
    // If the connection uses an offset buffer, the immediate value will be 0 and
    // the peer will then use a 1-sided RDMA read to get the offset information. If not,
    // then first 16 bits will carry the Head offset and the last 16 bits will carry
    // the Tail offset. The sender will use ths information to update the ring buffer
    // offsets and schedule pending writes
    //
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        ImmediateData = 0;
    }
    else
    {
        //
        // The Most significat bits will be zero while the least significant bits will carry
        // the updated Head offset. The tail offset will be managed by the sender locally.
        //
        ImmediateData = (RdmaConnection->RecvRingBuffer->Head & 0xFFFF);
    }

    //
    // Send the token information to the server
    //
    Status = NdspiSendWithImmediate(
        RdmaConnection,
        RdmaConnection,
        NULL,
        0,
        0,
        ImmediateData);
    if (Status != ND_SUCCESS)
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
    Status = RdmaConnection->SendCompletionQueue->lpVtbl->Notify(
        RdmaConnection->SendCompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &SocketProc->IoSqe.Overlapped);
    if (Status != ND_SUCCESS)
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                Status,
                "SendCompletionQueue::Notify");
            goto ErrorExit;
        }

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
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
    return Status;
}

QUIC_STATUS
CxPlatRdmaRecvRingBufferOffsets(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;
    CXPLAT_SOCKET *Socket = SocketProc->Parent;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    CxPlatStartDatapathIo(
        SocketProc,
        &SocketProc->IoSqe,
        CxPlatIoRdmaRecvRingBufferOffsetsEventComplete);

    Status = NdspiPostReceive(
        RdmaConnection,
        RdmaConnection,
        NULL,
        0);
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

    Status = RdmaConnection->RecvCompletionQueue->lpVtbl->Notify(
        RdmaConnection->RecvCompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &SocketProc->IoSqe.Overlapped);
    if (Status != ND_SUCCESS)
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "RecvCompletionQueue::Notify for CxPlatRdmaRecvRingBufferOffsets");
        }

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(
            SocketProc,
            &SocketProc->IoSqe,
            BytesRecv);
        if (QUIC_FAILED(Status))
        {
            CxPlatCancelDatapathIo(SocketProc);
        }
    }

ErrorExit:

    return Status;
}

QUIC_STATUS
CxPlatRdmaReadRingBufferOffsets(
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
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");

        return QUIC_STATUS_INVALID_PARAMETER;
    }

    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;
    CXPLAT_SOCKET *Socket = SocketProc->Parent;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    CxPlatStartDatapathIo(
        SocketProc,
        &SocketProc->IoSqe,
        CxPlatIoRdmaReadRingBufferOffsetsEventComplete);

    //RecvSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    RecvSge = CXPLAT_ALLOC_PAGED(sizeof(ND2_SGE), QUIC_POOL_PLATFORM_GENERIC);
    if (RecvSge == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "RecvSge Allocation of '%s' failed. (%llu bytes)",
            "ND2_SGE",
            sizeof(ND2_SGE));

        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    RecvSge->Buffer = RdmaConnection->RemoteRingBuffer->OffsetBuffer;
    RecvSge->BufferLength = (ULONG) RdmaConnection->RemoteRingBuffer->OffsetBufferSize;

    Status = NdspiRead(
        RdmaConnection,
        RecvSge,
        1,
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferAddress,
        RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken,
        0);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "IND2QueuePair::Read for fetching remote offset buffer tokens");

        goto ErrorExit;
    }

    Status = RdmaConnection->SendCompletionQueue->lpVtbl->Notify(
        RdmaConnection->SendCompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &SocketProc->IoSqe.Overlapped);
    if (Status != ND_SUCCESS)   
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "SendCompletionQueue::Notify for Reading remote offset buffer tokens");
            goto ErrorExit;
        }

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(
            SocketProc,
            &SocketProc->IoSqe,
            BytesRecv);
        if (QUIC_FAILED(Status)) {
            CxPlatCancelDatapathIo(SocketProc);
            goto ErrorExit;
        }
    }

ErrorExit:
    if (RecvSge)
    {
        //CxPlatPoolFree(&RdmaConnection->SgePool, RecvSge);
        CXPLAT_FREE(RecvSge, QUIC_POOL_PLATFORM_GENERIC);
    }

    return Status;
}

void
CxPlatDataPathRdmaProcessConnect(   
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult)
{
    QUIC_STATUS Status = ND_SUCCESS;
    DWORD BytesRecv = 0;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ProcessConnectFailed,
            "ProcessConnect failed, invalid parameters");
        return;
    }

    if (!CxPlatRundownAcquire(&SocketProc->RundownRef))
    {
        return;
    }

    if (IoResult == ND_SUCCESS)
    {
        CXPLAT_SOCKET *Socket = SocketProc->Parent;
        RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;
        CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA);
        CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateConnecting);

        //
        // For a connection that doesn't use memory window, Private data
        // will contain the remote token information
        //
        if (!(RdmaConnection->Flags & RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED))
        {
            Status = RdmaParsePrivateData(
                RdmaConnection,
                CXPLAT_SOCKET_RDMA);
            if (Status != ND_SUCCESS)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    Status,
                    "CxPlatDataPathRdmaProcessConnect::RdmaParsePrivateData");
                goto ErrorExit;
            }
        }

        CxPlatStartDatapathIo(
            SocketProc,
            &SocketProc->IoSqe,
            CxPlatIoRdmaConnectCompletionEventComplete);

        //
        // At this point the peer has acked the connection.
        // Invoke ConnectComplete to transition to connected state.
        //
        Status = NdspiCompleteConnect(
            RdmaConnection->Connector,
            &SocketProc->IoSqe.Overlapped);
        if (Status != ND_SUCCESS)   
        {
            if (Status != ND_PENDING)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketProc->Parent,
                    Status,
                    "CxPlatDataPathRdmaProcessConnect::Notify");
                goto ErrorExit;
            }

            //
            // Reset Status to success when event is pending
            //
            Status = ND_SUCCESS;
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

        RdmaConnection->State = RdmaConnectionStateCompleteConnect;
    }
    else
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            (unsigned long long)IoResult,
            "CxPlatDataPathRdmaProcessConnect");

        SocketProc->Parent->Datapath->RdmaHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            FALSE);

        Status = IoResult;
    }

ErrorExit:
    if (Status != ND_SUCCESS)
    {
        SocketDelete(SocketProc->Parent);
    }
    
    CxPlatRundownRelease(&SocketProc->RundownRef);

    return;
}

void
CxPlatDataPathRdmaProcessConnectCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
    )
{
    QUIC_STATUS Status = ND_SUCCESS;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "CxPlatDataPathRdmaProcessConnectCompletion invalid parameters");
        return;
    }

    if (!CxPlatRundownAcquire(&SocketProc->RundownRef))
    {
        return;
    }

    if (IoResult == ND_SUCCESS)
    {
        CXPLAT_SOCKET *Socket = SocketProc->Parent;
        RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

        CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
        CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateCompleteConnect);

        SocketProc->Parent->Datapath->RdmaHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            TRUE);

        //
        // Get notified when the connection disconnects
        //
        CxPlatStartDatapathIo(
            SocketProc,
            &SocketProc->DisconnectIoSqe,
            CxPlatIoRdmaDisconnectEventComplete);

        Status = NdspiNotifyDisconnect(RdmaConnection->Connector, &SocketProc->DisconnectIoSqe.Overlapped);
        if (Status != ND_SUCCESS)
        {
            if (Status != ND_PENDING)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketProc->Parent,
                    Status,
                    "IND2Connector::NotifyDisconnect");
                goto ErrorExit;
            }
            else
            {
                Status = ND_SUCCESS;
            }
        }
        else
        {
            //
            // Manually post IO completion if accept completed synchronously.
            //
            Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->DisconnectIoSqe, 0);
            if (QUIC_FAILED(Status))
            {
                CxPlatCancelDatapathIo(SocketProc);
                goto ErrorExit;
            }
            
            //
            // Set the connection state to disconnected to process ahead
            // with closing the queue pair
            //
            RdmaConnection->State = RdmaConnectionStateReceivedDisconnect;
        }

        if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED)
        {
            //
            // Initiatiate token exchange with peer before data can be sent
            //
            Status = CxPlatRdmaExchangeTokensInit(SocketProc);
            if (QUIC_FAILED(Status))
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    Socket,
                    Status,
                    "CxPlatRdmaExchangeTokensInit");
            }
        }
        else
        {
            //
            // Without memory window, the tokens are shared using private data.
            // So the connection can be transitioned to Ready State
            //
            RdmaConnection->State = RdmaConnectionStateReady;

            //
            // Post a receive to get the data from the peer
            //
            Status = CxPlatDataPathRdmaStartReceiveAsync(SocketProc);  
        }
    }
    else
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "CxPlatDataPathRdmaProcessConnectCompletion");

        SocketProc->Parent->Datapath->RdmaHandlers.Connect(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            FALSE);

        Status = IoResult;
    }

ErrorExit:
    if (Status != ND_SUCCESS)
    {
        SocketDelete(SocketProc->Parent);
    }

    CxPlatRundownRelease(&SocketProc->RundownRef);
}

void
CxPlatDataPathRdmaProcessGetConnectionRequestCompletion(
    _In_ CXPLAT_SOCKET_PROC* ListenerSocketProc,
    _In_ HRESULT IoResult
    )
{
    CXPLAT_SOCKET_PROC* AcceptSocketProc = NULL;
    RDMA_CONNECTION* RdmaConnection = NULL;
    QUIC_STATUS Status = ND_SUCCESS;
    RDMA_DATAPATH_PRIVATE_DATA PrivateData = {0};
    uint16_t PartitionIndex = 0;

    if (IoResult != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            ListenerSocketProc->Parent,
            IoResult,
            "CxPlatDataPathRdmaProcessGetConnectionRequestCompletion");

        return;
    }

    if (!CxPlatRundownAcquire(&ListenerSocketProc->RundownRef))
    {
        return;
    }

    CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket != NULL);
    CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket->RdmaContext != NULL);
    AcceptSocketProc = &ListenerSocketProc->AcceptSocket->PerProcSockets[0];

    if (!CxPlatRundownAcquire(&AcceptSocketProc->RundownRef))
    {
        goto ErrorExit;
    }

    CXPLAT_DBG_ASSERT(ListenerSocketProc->AcceptSocket == AcceptSocketProc->Parent);
    
    RdmaConnection = (RDMA_CONNECTION*)ListenerSocketProc->AcceptSocket->RdmaContext;
    RdmaConnection->State = RdmaConnectionStateWaitingForAccept;

    CXPLAT_DATAPATH* Datapath = ListenerSocketProc->Parent->Datapath;
    //RDMA_NDSPI_ADAPTER* NdAdapter = (RDMA_NDSPI_ADAPTER*) Datapath->RdmaAdapter;
    PartitionIndex = (uint16_t)(CxPlatProcCurrentNumber() % Datapath->PartitionCount);
    AcceptSocketProc->DatapathProc = &Datapath->Partitions[PartitionIndex];
    CxPlatRefIncrement(&AcceptSocketProc->DatapathProc->RefCount);

    //
    // Rest of the Accept Operations to complete the connection
    // will be done with AcceptSocketProc that is tagged to the connector
    //
    if (!CxPlatEventQAssociateHandle(
        AcceptSocketProc->DatapathProc->EventQ,
        (HANDLE)AcceptSocketProc->RdmaSocket))
    {
        DWORD LastError = GetLastError();
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            AcceptSocketProc->Parent,
            LastError,
            "TagIoCompletionPort (Accepted socket)");
        goto ErrorExit;
    }

    if (!(RdmaConnection->Flags & RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED))
    {
        //
        // If Memory window is not configured, then parse the remote
        // tokens with the peer using the private data
        //
        Status = RdmaParsePrivateData(
            RdmaConnection,
            CXPLAT_SOCKET_RDMA_SERVER);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                ListenerSocketProc->Parent,
                Status,
                "CxPlatDataPathRdmaProcessGetConnectionRequestCompletion::RdmaParsePrivateData");
            goto ErrorExit;
        }
        
        //
        // If Memory window is not configured, then share the remote
        // tokens with the peer using the private data provided to Accept
        //
        Status = RdmaBuildPrivateData(
            RdmaConnection,
            &PrivateData);
        if (QUIC_FAILED(Status))
        {
            QuicTraceLogError(
                RdmaBuildPrivateDataFailed,
                "RdmaBuildPrivateData failed, status:%d", Status);
            goto ErrorExit;
        }

        // Post a receive to fetch the data when accept completes
        //
        //for (DWORD i = 0; i < NdAdapter->AdapterInfo.MaxCompletionQueueDepth; i++)
        //{
            CxPlatDataPathRdmaStartReceiveAsync(AcceptSocketProc);
        //}
    }
    else
    {
        //
        // Before calling accept, post a receive to get the token information
        // from the client. In response, the server will send the token for its
        // ring buffer.
        //
        //ND2_SGE *sge = CxPlatPoolAlloc(&RdmaConnection->SgePool);

        ND2_SGE *sge = CXPLAT_ALLOC_PAGED(sizeof(ND2_SGE), QUIC_POOL_PLATFORM_GENERIC);
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
        sge->BufferLength = (ULONG) RdmaConnection->RecvRingBuffer->CurSize;

        Status = NdspiPostReceive(
            RdmaConnection,
            NULL,
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
    }

    //
    // Perform an accept operation on the connection
    //
    CxPlatStartDatapathIo(
        AcceptSocketProc,
        &AcceptSocketProc->IoSqe,
        CxPlatIoRdmaAcceptEventComplete);

    Status = NdspiAccept(
        RdmaConnection->Connector,
        RdmaConnection->QueuePair,
        1,
        1,
        //RdmaConnection->Adapter->AdapterInfo.MaxInboundReadLimit,
        //RdmaConnection->Adapter->AdapterInfo.MaxOutboundReadLimit,
        &PrivateData,
        sizeof(PrivateData),
        &AcceptSocketProc->IoSqe.Overlapped);
    if (Status != ND_SUCCESS)
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
        else
        {
            //
            // Set the AcceptSocket to NULL since the further steps for 
            // the connection will be performed by the connector
            ListenerSocketProc->AcceptSocket = NULL;
            AcceptSocketProc->IoStarted = TRUE;

            Status = ND_SUCCESS;
        }
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(AcceptSocketProc, &AcceptSocketProc->IoSqe, 0);
        if (QUIC_FAILED(Status))
        {
            CxPlatCancelDatapathIo(AcceptSocketProc);
        }
    }

ErrorExit:
    if (AcceptSocketProc != NULL)
    {
        CxPlatRundownRelease(&AcceptSocketProc->RundownRef);
    }

    if (ListenerSocketProc->AcceptSocket != NULL)
    {
        SocketDelete(ListenerSocketProc->AcceptSocket);
        ListenerSocketProc->AcceptSocket = NULL;
    }

    (void)CxPlatRdmaStartAccept(ListenerSocketProc);

    CxPlatRundownRelease(&ListenerSocketProc->RundownRef);
}

void
CxPlatDataPathRdmaProcessAcceptCompletion(
    _In_ CXPLAT_SOCKET_PROC* AcceptSocketProc,
    _In_ HRESULT IoResult
    )
{
    RDMA_CONNECTION* RdmaConnection = NULL;
    QUIC_STATUS Status = ND_SUCCESS;

    if (!AcceptSocketProc)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "CxPlatDataPathRdmaProcessAcceptCompletion invalid parameters");
        return;
    }

    if (!CxPlatRundownAcquire(&AcceptSocketProc->RundownRef))
    {
        return;
    }

    CXPLAT_DBG_ASSERT(AcceptSocketProc->DatapathProc != NULL);
    CXPLAT_DBG_ASSERT(AcceptSocketProc->Parent != NULL);
    CXPLAT_SOCKET* AcceptSocket = AcceptSocketProc->Parent;


    if (IoResult == ND_SUCCESS)
    {        
        RdmaConnection = (RDMA_CONNECTION*)AcceptSocket->RdmaContext;
        RdmaConnection->State = RdmaConnectionStateConnected;

        ULONG AssignedLocalAddressLength = sizeof(AcceptSocket->LocalAddress);
        Status = RdmaConnection->Connector->lpVtbl->GetLocalAddress(
            RdmaConnection->Connector,
            (PSOCKADDR)&AcceptSocket->LocalAddress,
            &AssignedLocalAddressLength);
        if (Status != ND_SUCCESS)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                AcceptSocket,
                Status,
                "CxPlatDataPathRdmaProcessAcceptCompletion IND2Connector::GetLocalAddress");
            goto ErrorExit;
        }

        ULONG AssignedRemoteAddressLength = sizeof(AcceptSocket->RemoteAddress);
        Status = RdmaConnection->Connector->lpVtbl->GetPeerAddress(
            RdmaConnection->Connector,
            (PSOCKADDR)&AcceptSocket->RemoteAddress,
            &AssignedRemoteAddressLength);
        if (Status != ND_SUCCESS)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                AcceptSocket,
                Status,
                "CxPlatDataPathRdmaProcessAcceptCompletion IND2Connector::GetRemoteAddress");
            goto ErrorExit;
        }

        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            AcceptSocket,
            0,
            "RDMA Accept Completed!");

        CXPLAT_DATAPATH* Datapath = AcceptSocket->Datapath;
        
        //
        // Invoke the Accept handlers. the actual callback semantics
        // needs to be address. this will only work for the datapath tests
        //
        Status = Datapath->RdmaHandlers.Accept(
            AcceptSocket,
            AcceptSocket->ClientContext,
            AcceptSocket,
            &AcceptSocket->ClientContext);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                AcceptSocket,
                Status,
                "Accept callback");
            goto ErrorExit;
        }

        //
        // Get notified when the connection disconnects
        //
        CxPlatStartDatapathIo(
            AcceptSocketProc,
            &AcceptSocketProc->DisconnectIoSqe,
            CxPlatIoRdmaDisconnectEventComplete);

        Status = NdspiNotifyDisconnect(RdmaConnection->Connector, &AcceptSocketProc->DisconnectIoSqe.Overlapped);
        if (Status != ND_SUCCESS)
        {
            if (Status != ND_PENDING)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    AcceptSocketProc->Parent,
                    Status,
                    "IND2Connector::NotifyDisconnect");
                goto ErrorExit;
            }
            else
            {
                Status = ND_SUCCESS;
            }
        }
        else
        {
            //
            // Manually post IO completion if accept completed synchronously.
            //
            Status = CxPlatSocketEnqueueSqe(AcceptSocketProc, &AcceptSocketProc->DisconnectIoSqe, 0);
            if (QUIC_FAILED(Status))
            {
                CxPlatCancelDatapathIo(AcceptSocketProc);
                goto ErrorExit;
            }
            
            //
            // Set the connection state to disconnected to process ahead
            // with closing the queue pair
            //
            RdmaConnection->State = RdmaConnectionStateReceivedDisconnect;
        }

        if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_MEMORY_WINDOW_USED)
        {
            Status = CxPlatRdmaExchangeTokensInit(AcceptSocketProc);
            if (QUIC_FAILED(Status))
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    AcceptSocket,
                    Status,
                    "CxPlatRdmaExchangeTokensInit");
                goto ErrorExit;
            }
        }
        else
        {
            //
            // Without memory window, the tokens are shared using private data.
            // So the connection can be transitioned to Ready State
            //
            RdmaConnection->State = RdmaConnectionStateReady;

            //
            // Post a receive to get the data from the peer
            //
            CxPlatDataPathRdmaStartReceiveAsync(AcceptSocketProc);
        }
    }
    else
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            AcceptSocket,
            IoResult,
            "RDMA Accept completion");

        Status = IoResult;
    }

ErrorExit:
    if (Status != ND_SUCCESS)
    {
        SocketDelete(AcceptSocketProc->Parent);
    }

    CxPlatRundownRelease(&AcceptSocketProc->RundownRef);
}

void
CxPlatDataPathRdmaProcessDisconnectCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
    )
{
    if (IoResult != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "RDMA Process Disconnect Completion");        
        return;
    }

    if (!SocketProc)
    {
        QuicTraceLogError(
            ProcessDisconnectFailed,
            "CxPlatDataPathRdmaProcessDisconnectCompletion invalid parameters");
        return;
    }

    
    if (!CxPlatRundownAcquire(&SocketProc->RundownRef))
    {
        return;
    }

    CxPlatRdmaSocketDelete(SocketProc->Parent);

    CxPlatRundownRelease(&SocketProc->RundownRef);
}

void
CxPlatDataPathRdmaProcessExchangeInitCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 0;

    if (IoResult != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "RDMA Exchange Init completion");        
        return;
    }

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return;
    }
    
    if (!CxPlatRundownAcquire(&SocketProc->RundownRef))
    {
        return;
    }

    CXPLAT_SOCKET *Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

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
        Status = CxPlatRdmaRecvRemoteTokens(RdmaConnection);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "CxPlatRdmaRecvRemoteTokens");
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
        ULONG Count = RdmaConnection->SendCompletionQueue->lpVtbl->GetManaResults(
            RdmaConnection->SendCompletionQueue,
            &Result,
            1);
        if (Result.Status != ND_SUCCESS)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                Result.Status,
                "CxPlatRdmaRecvRemoteTokens GetManaResults");
                goto ErrorExit;
        }
        
        CXPLAT_DBG_ASSERT(Count > 0);
        CXPLAT_DBG_ASSERT(Result.RequestType == Nd2ManaRequestTypeSend);

        //
        // Client has already posted a receive.
        // Wait for event notification from server
        //
        Status = RdmaConnection->RecvCompletionQueue->lpVtbl->Notify(
            RdmaConnection->RecvCompletionQueue,
            ND_CQ_NOTIFY_ANY,
            &SocketProc->IoSqe.Overlapped);
        if (Status != ND_SUCCESS)   
        {
            if (Status != ND_PENDING)
            {
                QuicTraceEvent(
                    DatapathErrorStatus,
                    "[data][%p] ERROR, %u, %s.",
                    SocketProc->Parent,
                    Status,
                    "RecvCompletionQueue::Notify");
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
    CxPlatRundownRelease(&SocketProc->RundownRef);

    return;
}

void
CxPlatDataPathRdmaProcessExchangeFinalCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(IoResult);

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return;
    }

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
        ULONG Count = RdmaConnection->SendCompletionQueue->lpVtbl->GetManaResults(
            RdmaConnection->SendCompletionQueue,
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
        Status = CxPlatRdmaRecvRemoteTokens(RdmaConnection);
        if (QUIC_FAILED(Status))
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                Socket,
                Status,
                "CxPlatRdmaRecvRemoteTokens");
            return;
        }
    }

    RdmaConnection->State = RdmaConnectionStateReady;

    //
    // Post a receive to get the data from the peer
    //
    CxPlatDataPathRdmaStartReceiveAsync(SocketProc);
}

void
CxPlatRdmaSocketFreeRxIoBlock(
    _In_ RDMA_DATAPATH_RX_IO_BLOCK* IoBlock
    )
{
    CxPlatPoolFree(IoBlock->OwningPool, IoBlock);
}

void
CxPlatRdmaSendDataComplete(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ HRESULT IoResult
    )
{
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;

    UNREFERENCED_PARAMETER(IoResult);

    if (IoResult != QUIC_STATUS_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            IoResult,
            "WSASendMsg completion");
    }

    if (CxPlatRundownAcquire(&SocketProc->RundownRef)) 
    {
        SocketProc->Parent->Datapath->RdmaHandlers.SendComplete(
            SocketProc->Parent,
            SocketProc->Parent->ClientContext,
            IoResult,
            SendData->TotalSize);

        CxPlatRundownRelease(&SocketProc->RundownRef);
    }
}

void
CxPlatRdmaDataPathSocketProcessReceive(
    _In_ RDMA_DATAPATH_RX_IO_BLOCK* RxIoBlock,
    _In_ HRESULT IoResult
)
{
    CXPLAT_SOCKET_PROC* SocketProc = RxIoBlock->SocketProc;
    CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    CXPLAT_SOCKET* Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

    UNREFERENCED_PARAMETER(IoResult);

    CXPLAT_DBG_ASSERT(!SocketProc->Uninitialized);
    CXPLAT_DBG_ASSERT(RdmaConnection != NULL && RdmaConnection->State == RdmaConnectionStateReady);

    CXPLAT_DBG_ASSERT(!SocketProc->Freed);
    if (!CxPlatRundownAcquire(&RxIoBlock->SocketProc->RundownRef))
    {
        CxPlatRdmaSocketContextRelease(SocketProc);
        return;
    }

    //
    // Fetch the MANA result object and invoke the RDMA callback handler
    //
    ND2_MANA_RESULT ManaResult;

    ULONG Count = RdmaConnection->RecvCompletionQueue->lpVtbl->GetManaResults(
        RdmaConnection->RecvCompletionQueue,
        &ManaResult,
        1);
    if (Count == 0)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            0,
            "CxPlatRdmaRecvRemoteTokens GetManaResults");
        goto ErrorExit;
    }

    if (ManaResult.Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            ManaResult.Status,
            "CxPlatRdmaRecvRemoteTokens GetManaResults");
        goto ErrorExit;
    }

    CXPLAT_DBG_ASSERT(ManaResult.RequestType == Nd2ManaRequestTypeRecvRdmaWithImmediate); 
    CXPLAT_DBG_ASSERT(ManaResult.ImmediateData != 0);    

    CXPLAT_RECV_DATA* Data = (CXPLAT_RECV_DATA*)(RxIoBlock + 1);

    CXPLAT_CONTAINING_RECORD(Data, RDMA_DATAPATH_RX_PACKET, Data)->IoBlock = RxIoBlock;
    Data->Next = NULL;
    uint32_t RecvOffset = 0;
    uint16_t NumberOfBytesTransferred = 0;
    Data->Allocated = TRUE;

    //
    // Fetch the data at the ring buffer offset and invoke the receive callback
    //
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        //
        // Fetch the offset for the new data from the offset buffer
        //
        CXPLAT_DBG_ASSERT(RdmaConnection->RecvRingBuffer->OffsetBuffer != NULL);

        RecvOffset = ByteBufferToUInt32(RdmaConnection->RecvRingBuffer->OffsetBuffer + 4);
        CXPLAT_DBG_ASSERT(RecvOffset < RdmaConnection->RecvRingBuffer->Capacity);

        //
        // Get the last 16 bits of the immediate data as
        // the number of bytes transferred
        //
        NumberOfBytesTransferred = (ManaResult.ImmediateData & 0xFFFF);

        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= RdmaConnection->RecvRingBuffer->Capacity - RecvOffset);
    }   
    else
    {
        CXPLAT_DBG_ASSERT(RdmaConnection->RecvRingBuffer->OffsetBuffer == NULL);

        //
        // Get the first 16 bits of the immediate data as receive offset
        //
        RecvOffset = ((ManaResult.ImmediateData >> 16) & 0xFFFF);
        CXPLAT_DBG_ASSERT(RecvOffset < RdmaConnection->RecvRingBuffer->Capacity);

        //
        // Get the last 16 bits of the immediate data as
        // the number of bytes transferred
        //
        NumberOfBytesTransferred = (ManaResult.ImmediateData & 0xFFFF);
        CXPLAT_DBG_ASSERT(NumberOfBytesTransferred <= RdmaConnection->RecvRingBuffer->Capacity - RecvOffset);
    }

    Data->Next = NULL;
    Data->Buffer = RdmaConnection->RecvRingBuffer->Buffer + RecvOffset;
    Data->BufferLength = NumberOfBytesTransferred;
    Data->Route = &RxIoBlock->Route;
    Data->Route->DatapathType = Data->DatapathType = CXPLAT_DATAPATH_TYPE_RDMA;
    Data->QueuedOnConnection = FALSE;
    Data->RingBufferOffset = RecvOffset;

    //
    // Update the offsets in the receive ring buffer
    //
    if (RecvOffset != RdmaConnection->RecvRingBuffer->Tail)
    {
        //
        // This situation can occur when the Tail offset has rolled over due to
        // lack of sufficient buffer space in the ring buffer. 
        //
        CXPLAT_DBG_ASSERT(RecvOffset < RdmaConnection->RecvRingBuffer->Tail);

        RDMA_IO_COMPLETION_BUFFER *buf = CxPlatPoolAlloc(&RdmaConnection->RecvRingBuffer->RecvCompletionPool);
        CXPLAT_DBG_ASSERT(buf != NULL);

        buf->Offset = RdmaConnection->RecvRingBuffer->Tail;
        buf->Length = RecvOffset - RdmaConnection->RecvRingBuffer->Tail;

        CxPlatHashtableInsert(
            RdmaConnection->RecvRingBuffer->RecvCompletionTable,
            &buf->TableEntry,
            (uint32_t)buf->Offset,
            NULL);
        
        RdmaConnection->RecvRingBuffer->Tail += buf->Length;
        RdmaConnection->RecvRingBuffer->CurSize += buf->Length;
    }

    RdmaConnection->RecvRingBuffer->Tail += NumberOfBytesTransferred;
    RdmaConnection->RecvRingBuffer->CurSize += NumberOfBytesTransferred;

    RxIoBlock->ReferenceCount++;
    RxIoBlock = NULL;

    Datapath->RdmaHandlers.Receive(
        SocketProc->Parent,
        SocketProc->Parent->ClientContext,
        Data);

ErrorExit:
    if (RxIoBlock != NULL)
    {
        CxPlatRdmaSocketFreeRxIoBlock(RxIoBlock);
        CxPlatRundownRelease(&RxIoBlock->SocketProc->RundownRef);
    }
}

void
CxPlatDataPathRdmaSendRingBufferOffsetsCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
    )
{
    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "CxPlatDataPathRdmaSendRingBufferOffsetsCompletion failed, invalid parameters");
        return;
    }

    UNREFERENCED_PARAMETER(IoResult);

    CXPLAT_SOCKET *Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    //
    // Fetch the MANA result object and invoke the RDMA callback handler
    //
    ND2_MANA_RESULT ManaResult;

    ULONG Count = RdmaConnection->SendCompletionQueue->lpVtbl->GetManaResults(
        RdmaConnection->SendCompletionQueue,
        &ManaResult,
        1);
    if (ManaResult.Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            ManaResult.Status,
            "CxPlatDataPathRdmaSendRingBufferOffsetsCompletion GetManaResults");
        return;
    }

    CXPLAT_DBG_ASSERT(ManaResult.RequestType == Nd2ManaRequestTypeSend && Count > 0 && ManaResult.ImmediateData != 0);  
}

void
CxPlatDataPathRdmaRecvRingBufferOffsetsCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
    )
{    
    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "CxPlatDataPathRdmaRecvRingBufferOffsetsCompletion failed, invalid parameters");
        return;
    }

    UNREFERENCED_PARAMETER(IoResult);

    CXPLAT_SOCKET *Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    //
    // Fetch the MANA result object and invoke the RDMA callback handler
    //
    ND2_MANA_RESULT ManaResult;

    ULONG Count = RdmaConnection->RecvCompletionQueue->lpVtbl->GetManaResults(
        RdmaConnection->RecvCompletionQueue,
        &ManaResult,
        1);
    if (ManaResult.Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            ManaResult.Status,
            "CxPlatDataPathRdmaRecvRingBufferOffsetsCompletion GetManaResults");
        return;
    }

    CXPLAT_DBG_ASSERT(ManaResult.RequestType == Nd2ManaRequestTypeRecvWithImmediate &&
                      Count > 0);
    
    //
    // If offset buffer is used by the connection, then the immediate value will be zero
    //
    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        CXPLAT_DBG_ASSERT(ManaResult.ImmediateData == 0);

        //
        // Schedule a 1-sided RDMA read to get the Head offset from the peer
        //
        CxPlatRdmaReadRingBufferOffsets(SocketProc);
    }
    else
    {
        //
        // Get the first 16 bits of the immediate data as receive offset
        //
        uint32_t OldHead = RdmaConnection->RemoteRingBuffer->Head;
        RdmaConnection->RemoteRingBuffer->Head = (ManaResult.ImmediateData & 0xFFFF);
        CXPLAT_DBG_ASSERT(RdmaConnection->RemoteRingBuffer->Head < RdmaConnection->RecvRingBuffer->Capacity); 

        //
        // Schedule any pending write operations to the peer after CurSize is updated
        //
        RdmaConnection->RemoteRingBuffer->CurSize -= RdmaConnection->RemoteRingBuffer->Head - OldHead;
        RdmaSocketPendingSend(SocketProc);
    }                  
}

void
CxPlatDataPathRdmaReadRingBufferOffsetsCompletion(
    _In_ CXPLAT_SOCKET_PROC* SocketProc,
    _In_ HRESULT IoResult
    )
{
    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "CxPlatDataPathRdmaRecvRingBufferOffsetsCompletion failed, invalid parameters");
        return;
    }

    UNREFERENCED_PARAMETER(IoResult);

    CXPLAT_SOCKET *Socket = SocketProc->Parent;
    RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*)Socket->RdmaContext;

    CXPLAT_DBG_ASSERT(Socket->Type == CXPLAT_SOCKET_RDMA || Socket->Type == CXPLAT_SOCKET_RDMA_SERVER);
    CXPLAT_DBG_ASSERT(RdmaConnection->State == RdmaConnectionStateReady);

    //
    // Fetch the MANA result object and invoke the RDMA callback handler
    //
    ND2_MANA_RESULT ManaResult;

    ULONG Count = RdmaConnection->RecvCompletionQueue->lpVtbl->GetManaResults(
        RdmaConnection->RecvCompletionQueue,
        &ManaResult,
        1);
    if (ManaResult.Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            ManaResult.Status,
            "CxPlatDataPathRdmaRecvRingBufferOffsetsCompletion GetManaResults");
        return;
    }

    CXPLAT_DBG_ASSERT(ManaResult.RequestType == Nd2ManaRequestTypeRead &&
                      Count > 0 &&
                      ManaResult.ImmediateData != 0);
    uint32_t OldHead = RdmaConnection->RemoteRingBuffer->Head;
    RdmaConnection->RemoteRingBuffer->Head = ByteBufferToUInt32(RdmaConnection->RemoteRingBuffer->OffsetBuffer);

    //
    // Schedule any pending write operations to the peer after CurSize is updated
    //
    RdmaConnection->RemoteRingBuffer->CurSize -= RdmaConnection->RemoteRingBuffer->Head - OldHead;
    RdmaSocketPendingSend(SocketProc);
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
    CxPlatDataPathRdmaProcessConnect(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaConnectCompletionEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    CxPlatDataPathRdmaProcessConnectCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
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
    CxPlatDataPathRdmaProcessGetConnectionRequestCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
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
    CxPlatDataPathRdmaProcessAcceptCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaDisconnectEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    CxPlatDataPathRdmaProcessDisconnectCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
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
    CxPlatDataPathRdmaProcessExchangeInitCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
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
    CxPlatDataPathRdmaProcessExchangeFinalCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaSendEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SEND_DATA* SendData = CONTAINING_RECORD(Sqe, CXPLAT_SEND_DATA, Sqe);
    CXPLAT_SOCKET_PROC* SocketProc = SendData->SocketProc;
    CxPlatRdmaSendDataComplete(
        SendData,
        (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaRecvEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_DBG_ASSERT(Cqe->dwNumberOfBytesTransferred <= UINT16_MAX);
    CxPlatRdmaDataPathSocketProcessReceive(
        CONTAINING_RECORD(Sqe, RDMA_DATAPATH_RX_IO_BLOCK, Sqe),
        (HRESULT)Sqe->Overlapped.Internal);  
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaSendRingBufferOffsetsEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    CxPlatDataPathRdmaSendRingBufferOffsetsCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc); 
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaRecvRingBufferOffsetsEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    CxPlatDataPathRdmaRecvRingBufferOffsetsCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc); 
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatIoRdmaReadRingBufferOffsetsEventComplete(
    _In_ CXPLAT_CQE* Cqe
    )
{
    CXPLAT_SQE* Sqe = CxPlatCqeGetSqe(Cqe);
    CXPLAT_DBG_ASSERT(Sqe->Overlapped.Internal != 0x103); // STATUS_PENDING
    CXPLAT_SOCKET_PROC* SocketProc = CONTAINING_RECORD(Sqe, CXPLAT_SOCKET_PROC, IoSqe);
    CxPlatDataPathRdmaReadRingBufferOffsetsCompletion(SocketProc, (HRESULT)Sqe->Overlapped.Internal);
    CxPlatRdmaSocketContextRelease(SocketProc); 
}

QUIC_STATUS
CxPlatRdmaRecvRemoteTokens(
    _In_ RDMA_CONNECTION* RdmaConnection
    )
{
    if (!RdmaConnection)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    ND2_MANA_RESULT ManaResult;

    //
    // Check if the token was received from the client
    //
    ULONG Count = RdmaConnection->RecvCompletionQueue->lpVtbl->GetManaResults(
        RdmaConnection->RecvCompletionQueue,
        &ManaResult,
        1);
    if (ManaResult.Status != ND_SUCCESS)
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            RdmaConnection->Socket,
            ManaResult.Status,
            "CxPlatRdmaRecvRemoteTokens GetManaResults");
        return QUIC_STATUS_INVALID_STATE;
    }

    CXPLAT_DBG_ASSERT(Count > 0);
    CXPLAT_DBG_ASSERT(ManaResult.RequestType == Nd2ManaRequestTypeRecvWithImmediate);
    CXPLAT_DBG_ASSERT(ManaResult.BytesTransferred == ManaResult.ImmediateData);
    CXPLAT_DBG_ASSERT(ManaResult.ImmediateData == 16 || ManaResult.ImmediateData == 28);

    RdmaConnection->RemoteRingBuffer->Head = RdmaConnection->RemoteRingBuffer->Tail = 0;
    RdmaConnection->RemoteRingBuffer->RemoteAddress = ByteBufferToUInt64(&RdmaConnection->RecvRingBuffer->Buffer[0]);
    RdmaConnection->RemoteRingBuffer->Capacity = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[8]);
    RdmaConnection->RemoteRingBuffer->RemoteToken = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[12]);

    if (ManaResult.ImmediateData == 16)
    {
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferAddress = 0;
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferToken = 0;
    }
    else
    {
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferAddress = ByteBufferToUInt64(&RdmaConnection->RecvRingBuffer->Buffer[16]);
        RdmaConnection->RemoteRingBuffer->RemoteOffsetBufferToken = ByteBufferToUInt32(&RdmaConnection->RecvRingBuffer->Buffer[24]);
    }

    return QUIC_STATUS_SUCCESS;
}

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
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    
    //SendSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    SendSge = CXPLAT_ALLOC_PAGED(sizeof(ND2_SGE), QUIC_POOL_PLATFORM_GENERIC);
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
    RdmaConnection->RecvRingBuffer->RemoteToken = RdmaConnection->RecvMemoryWindow->lpVtbl->GetRemoteToken(RdmaConnection->RecvMemoryWindow);

    SendSge->Buffer = RdmaConnection->SendRingBuffer->Buffer;
    SendSge->BufferLength = 0;

    UInt64ToByteBuffer(RecvRingBufferAdress, &RdmaConnection->SendRingBuffer->Buffer[0]);
    SendSge->BufferLength += sizeof(uint64_t);

    UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->Capacity, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
    SendSge->BufferLength += sizeof(uint32_t);

    UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->RemoteToken, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
    SendSge->BufferLength += sizeof(uint32_t);

    if (RdmaConnection->Flags & RDMA_CONNECTION_FLAG_OFFSET_BUFFER_USED)
    {
        uint64_t OffsetBufferAdress = (uint64_t)(uintptr_t)RdmaConnection->RecvRingBuffer->OffsetBuffer;
        RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken = RdmaConnection->OffsetMemoryWindow->lpVtbl->GetRemoteToken(RdmaConnection->OffsetMemoryWindow);

        UInt64ToByteBuffer(OffsetBufferAdress, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
        SendSge->BufferLength += sizeof(uint64_t);

        UInt32ToByteBuffer(RdmaConnection->RecvRingBuffer->RemoteOffsetBufferToken, &RdmaConnection->SendRingBuffer->Buffer[SendSge->BufferLength]);
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
    Status = RdmaConnection->SendCompletionQueue->lpVtbl->Notify(
        RdmaConnection->SendCompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &SocketProc->IoSqe.Overlapped);
    if (Status != ND_SUCCESS)
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

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
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
        //CxPlatPoolFree(&RdmaConnection->SgePool, SendSge);
        CXPLAT_FREE(SendSge, QUIC_POOL_PLATFORM_GENERIC);
    }

    return Status;
}

RDMA_DATAPATH_RX_IO_BLOCK*
CxPlatRdmaSocketAllocRxIoBlock(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    CXPLAT_DATAPATH_PARTITION* DatapathProc = NULL;
    RDMA_DATAPATH_RX_IO_BLOCK* IoBlock;
    CXPLAT_POOL* OwningPool;

    if(!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return NULL;
    }

    DatapathProc = SocketProc->DatapathProc;
    OwningPool = &DatapathProc->RecvRdmaDatagramPool.Base;

    IoBlock = CxPlatPoolAlloc(OwningPool);
    if (IoBlock != NULL)
    {
        IoBlock->Route.State = RouteResolved;
        IoBlock->OwningPool = OwningPool;
        IoBlock->ReferenceCount = 0;
        IoBlock->SocketProc = SocketProc;
    }

    return IoBlock;
}

//
// Try to start a new receive. Returns TRUE if the receive completed inline.
//
QUIC_STATUS
CxPlatDataPathRdmaStartReceiveAsync(
    _In_ CXPLAT_SOCKET_PROC* SocketProc
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DWORD BytesRecv = 1;
    RDMA_CONNECTION* RdmaConnection = NULL;
    ND2_SGE *RecvSge = NULL;

    if (!SocketProc ||
        !SocketProc->Parent ||
        !SocketProc->Parent->Datapath ||
        !SocketProc->Parent->RdmaContext)
    {
        QuicTraceLogError(
            ExchangeTokensFailed,
            "ExchangeTokens failed, invalid parameters");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const CXPLAT_DATAPATH* Datapath = SocketProc->Parent->Datapath;
    RdmaConnection = (RDMA_CONNECTION*)SocketProc->Parent->RdmaContext;

    CXPLAT_DBG_ASSERT(
        SocketProc->Parent->Type == CXPLAT_SOCKET_RDMA ||
        SocketProc->Parent->Type == CXPLAT_SOCKET_RDMA_SERVER);

    //
    // Get a receive buffer we can pass to WinSock.
    //
    RDMA_DATAPATH_RX_IO_BLOCK *IoBlock = CxPlatRdmaSocketAllocRxIoBlock(SocketProc);
    if (IoBlock == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Socket Receive Buffer",
            Datapath->RecvPayloadOffset + SocketProc->Parent->RecvBufLen);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    //
    // Post a receive to get the ring buffer tokens from the peer
    // This is common operation for both client and server
    //
    //RecvSge = CxPlatPoolAlloc(&RdmaConnection->SgePool);
    RecvSge = CXPLAT_ALLOC_PAGED(sizeof(ND2_SGE), QUIC_POOL_PLATFORM_GENERIC);
    if (RecvSge == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "RecvSge Allocation of '%s' failed. (%llu bytes)",
            "ND2_SGE",
            sizeof(ND2_SGE));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto ErrorExit;
    }

    RecvSge->Buffer = NULL;
    RecvSge->BufferLength = 0;
    RecvSge->MemoryRegionToken = RdmaConnection->RecvRingBuffer->LocalToken;

    Status = NdspiPostReceive(
        RdmaConnection,
        IoBlock,
        RecvSge,
        1);
    if (QUIC_FAILED(Status))
    {
        QuicTraceEvent(
            DatapathErrorStatus,
            "[data][%p] ERROR, %u, %s.",
            SocketProc->Parent,
            Status,
            "IND2QueuePair::Receive for getting data");

        goto ErrorExit;
    }

    CxPlatStartDatapathIo(
        SocketProc,
        &IoBlock->Sqe,
        CxPlatIoRdmaRecvEventComplete);

    Status = RdmaConnection->RecvCompletionQueue->lpVtbl->Notify(
        RdmaConnection->RecvCompletionQueue,
        ND_CQ_NOTIFY_ANY,
        &IoBlock->Sqe.Overlapped);
    if (Status != ND_SUCCESS)
    {
        if (Status != ND_PENDING)
        {
            QuicTraceEvent(
                DatapathErrorStatus,
                "[data][%p] ERROR, %u, %s.",
                SocketProc->Parent,
                Status,
                "RecvCompletionQueue::Notify"); 
            goto ErrorExit;
        }

        //
        // Reset Status to success when event is pending
        //
        Status = ND_SUCCESS;
    }
    else
    {
        //
        // Manually post IO completion if accept completed synchronously.
        //
        Status = CxPlatSocketEnqueueSqe(SocketProc, &SocketProc->IoSqe, BytesRecv);
        if (QUIC_FAILED(Status)) {
            CXPLAT_DBG_ASSERT(FALSE); // We don't expect tests to hit this.
            CxPlatCancelDatapathIo(SocketProc);
            CxPlatRdmaSocketFreeRxIoBlock(IoBlock);
            goto ErrorExit;
        }
    }  
        
ErrorExit:
    // 
    // SGE object is needed only till the post is completed  
    //
    if (RecvSge)
    {
        //CxPlatPoolFree(&RdmaConnection->SgePool, RecvSge);
        CXPLAT_FREE(RecvSge, QUIC_POOL_PLATFORM_GENERIC);
    }

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
RdmaRecvDataReturn(
    _In_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
    LONG BatchedBufferCount = 0;
    RDMA_DATAPATH_RX_IO_BLOCK* BatchIoBlock = NULL;

    CXPLAT_RECV_DATA* Datagram;
    while ((Datagram = RecvDataChain) != NULL) 
    {
        RecvDataChain = RecvDataChain->Next;

        RDMA_DATAPATH_RX_IO_BLOCK* IoBlock =
        CXPLAT_CONTAINING_RECORD(Datagram, RDMA_DATAPATH_RX_PACKET, Data)->IoBlock;

        if (BatchIoBlock == IoBlock)
        {
            BatchedBufferCount++;
        }
        else
        {
            if (BatchIoBlock != NULL &&
                InterlockedAdd(
                    (PLONG)&BatchIoBlock->ReferenceCount,
                    -BatchedBufferCount) == 0) {
                //
                // Clean up the data indication.
                //
                CXPLAT_DBG_ASSERT(BatchIoBlock->SocketProc->Parent->Type == CXPLAT_SOCKET_RDMA ||
                    BatchIoBlock->SocketProc->Parent->Type == CXPLAT_SOCKET_RDMA_SERVER);
                CXPLAT_DBG_ASSERT(BatchIoBlock->SocketProc->Parent->RdmaContext != NULL);
                
                RDMA_CONNECTION* RdmaConnection = (RDMA_CONNECTION*) BatchIoBlock->SocketProc->Parent->RdmaContext;

                RdmaLocalReceiveRingBufferRelease(
                    RdmaConnection->RecvRingBuffer,
                    Datagram->Buffer,
                    Datagram->RingBufferOffset,
                    Datagram->BufferLength
                );

                CxPlatRdmaSocketFreeRxIoBlock(BatchIoBlock);
            }

            BatchIoBlock = IoBlock;
            BatchedBufferCount = 1;
        }
    }

    if (BatchIoBlock != NULL &&
        InterlockedAdd(
            (PLONG)&BatchIoBlock->ReferenceCount,
            -BatchedBufferCount) == 0) {
        //
        // Clean up the data indication.
        //
        CxPlatRdmaSocketFreeRxIoBlock(BatchIoBlock);
    }
}

