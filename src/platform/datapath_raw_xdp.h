/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include <stdio.h>
#include "platform_internal.h"
#include "datapath_raw.h"

#define RX_BATCH_SIZE 16
#define MAX_ETH_FRAME_SIZE 1514
#define ADAPTER_TAG   'ApdX' // XdpA
#define IF_TAG        'IpdX' // XdpI
#define QUEUE_TAG     'QpdX' // XdpQ
#define RULE_TAG      'UpdX' // XdpU
#define RX_BUFFER_TAG 'RpdX' // XdpR
#define TX_BUFFER_TAG 'TpdX' // XdpT
#define PORT_SET_TAG  'PpdX' // XdpP

typedef struct XDP_INTERFACE XDP_INTERFACE;
typedef struct XDP_PARTITION XDP_PARTITION;
typedef struct XDP_DATAPATH XDP_DATAPATH;

typedef struct XDP_INTERFACE_COMMON {
    CXPLAT_INTERFACE;
    uint16_t QueueCount;
    CXPLAT_QUEUE* Queues; // An array of queues.
    const struct XDP_DATAPATH* Xdp;
} XDP_INTERFACE_COMMON;

typedef struct XDP_QUEUE_COMMON {
    const XDP_INTERFACE* Interface;
    XDP_PARTITION* Partition;
    struct CXPLAT_QUEUE* Next;
    BOOLEAN RxQueued;
    BOOLEAN TxQueued;
    BOOLEAN Error;
} XDP_QUEUE_COMMON;

typedef struct QUIC_CACHEALIGN XDP_PARTITION {
    CXPLAT_EXECUTION_CONTEXT Ec;
    CXPLAT_SQE ShutdownSqe;
    const struct XDP_DATAPATH* Xdp;
    CXPLAT_EVENTQ* EventQ;
    CXPLAT_QUEUE* Queues; // A linked list of queues, accessed by Next.
    uint16_t PartitionIndex;
    uint16_t Processor;
} XDP_PARTITION;

void XdpWorkerAddQueue(_In_ XDP_PARTITION* Partition, _In_ CXPLAT_QUEUE* Queue) {
    XDP_QUEUE_COMMON** Tail = (XDP_QUEUE_COMMON**)&Partition->Queues;
    XDP_QUEUE_COMMON* QueueCommon = (XDP_QUEUE_COMMON*)Queue;
    while (*Tail != NULL) {
        Tail = (XDP_QUEUE_COMMON**)&(*Tail)->Next;
    }
    *Tail = QueueCommon;
    QueueCommon->Next = NULL;
    QueueCommon->Partition = Partition;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawAssignQueue(
    _In_ const CXPLAT_INTERFACE* _Interface,
    _Inout_ CXPLAT_ROUTE* Route
    )
{
    const XDP_INTERFACE_COMMON* Interface = (const XDP_INTERFACE_COMMON*)_Interface;
    XDP_QUEUE_COMMON* Queues = (XDP_QUEUE_COMMON*)Interface->Queues;
    CXPLAT_FRE_ASSERT(Queues[0].Partition != NULL); // What if there was no partition?
    Route->Queue = (CXPLAT_QUEUE*)&Queues[0]; // TODO - Can we do better than just the first queue?
}

_IRQL_requires_max_(DISPATCH_LEVEL)
const CXPLAT_INTERFACE*
CxPlatDpRawGetInterfaceFromQueue(
    _In_ const CXPLAT_QUEUE* Queue
    )
{
    return (const CXPLAT_INTERFACE*)((XDP_QUEUE_COMMON*)Queue)->Interface;
}
