/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_linux.h"
#include "datapath_raw_xdp.h"

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_linux.c.clog.h"
#endif

// TODO: remove this exception when finalizing members
typedef struct XDP_DATAPATH { // NOLINT(clang-analyzer-optin.performance.Padding)
    CXPLAT_DATAPATH_RAW;
    __attribute__((aligned(64)))
    //
    // Currently, all XDP interfaces share the same config.
    //
    CXPLAT_REF_COUNT RefCount;
    uint32_t PartitionCount;
    uint32_t RxBufferCount;
    uint32_t RxRingSize;
    uint32_t TxBufferCount;
    uint32_t TxRingSize;
    uint32_t PollingIdleTimeoutUs;
    BOOLEAN TxAlwaysPoke;
    BOOLEAN SkipXsum;
    BOOLEAN Running;        // Signal to stop workers.
    // const XDP_API_TABLE *XdpApi;

    XDP_PARTITION Partitions[0];
} XDP_DATAPATH;

typedef struct XDP_INTERFACE {
    CXPLAT_INTERFACE;
    uint16_t QueueCount;
    uint8_t RuleCount;
    CXPLAT_LOCK RuleLock;
    // XDP_RULE* Rules;
    XDP_QUEUE* Queues; // An array of queues.
    const struct XDP_DATAPATH* Xdp;
} XDP_INTERFACE;

typedef struct XDP_QUEUE {
    const XDP_INTERFACE* Interface;
    XDP_PARTITION* Partition;
    struct XDP_QUEUE* Next;
    uint8_t* RxBuffers;
    // HANDLE RxXsk;
    DATAPATH_IO_SQE RxIoSqe;
    // XSK_RING RxFillRing;
    // XSK_RING RxRing;
    // HANDLE RxProgram;
    uint8_t* TxBuffers;
    // HANDLE TxXsk;
    DATAPATH_IO_SQE TxIoSqe;
    // XSK_RING TxRing;
    // XSK_RING TxCompletionRing;
    BOOLEAN RxQueued;
    BOOLEAN TxQueued;
    BOOLEAN Error;

    CXPLAT_LIST_ENTRY PartitionTxQueue;
    CXPLAT_SLIST_ENTRY PartitionRxPool;

    // Move contended buffer pools to their own cache lines.
    // TODO: Use better (more scalable) buffer algorithms.
    // DECLSPEC_CACHEALIGN SLIST_HEADER RxPool;
    // DECLSPEC_CACHEALIGN SLIST_HEADER TxPool;

    // Move TX queue to its own cache line.
    // DECLSPEC_CACHEALIGN
    CXPLAT_LOCK TxLock;
    CXPLAT_LIST_ENTRY TxQueue;
} XDP_QUEUE;

// -> CxPlat
typedef struct __attribute__((aligned(64))) XDP_RX_PACKET {
    XDP_QUEUE* Queue;
    CXPLAT_ROUTE RouteStorage;
    CXPLAT_RECV_DATA RecvData;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct __attribute__((aligned(64))) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    UNREFERENCED_PARAMETER(InterfaceIndex);
    UNREFERENCED_PARAMETER(Count);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    //
    // Default config.
    //
    Xdp->RxBufferCount = 8192;
    Xdp->RxRingSize = 256;
    Xdp->TxBufferCount = 8192;
    Xdp->TxRingSize = 256;
    Xdp->TxAlwaysPoke = FALSE;

    // TODO
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUninitialize(
    _Inout_ XDP_INTERFACE* Interface
    )
{
    UNREFERENCED_PARAMETER(Interface);

}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    UNREFERENCED_PARAMETER(Interface);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);

    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
//_Requires_lock_held_(Interface->RuleLock)
void
CxPlatDpRawInterfaceUpdateRules(
    _In_ XDP_INTERFACE* Interface
    )
{
    UNREFERENCED_PARAMETER(Interface);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    const uint32_t PartitionCount =
        (Config && Config->ProcessorCount) ? Config->ProcessorCount : CxPlatProcCount();
    return sizeof(XDP_DATAPATH) + (PartitionCount * sizeof(XDP_PARTITION));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(ClientRecvContextLength);
    UNREFERENCED_PARAMETER(Config);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawRelease(
    _In_ XDP_DATAPATH* Xdp
    )
{
    UNREFERENCED_PARAMETER(Xdp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    UNREFERENCED_PARAMETER(Datapath);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(IsCreated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawAssignQueue(
    _In_ const CXPLAT_INTERFACE* _Interface,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    const XDP_INTERFACE* Interface = (const XDP_INTERFACE*)_Interface;
    Route->Queue = &Interface->Queues[0];
}

_IRQL_requires_max_(DISPATCH_LEVEL)
const CXPLAT_INTERFACE*
CxPlatDpRawGetInterfaceFromQueue(
    _In_ const void* Queue
    )
{
    return (const CXPLAT_INTERFACE*)((XDP_QUEUE*)Queue)->Interface;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    UNREFERENCED_PARAMETER(PacketChain);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Config);
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    UNREFERENCED_PARAMETER(SendData);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(State);
    return FALSE;
}

void
RawDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    UNREFERENCED_PARAMETER(Cqe);
}
