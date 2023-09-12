/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include <wbemidl.h>
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <stdio.h>
#include "platform_internal.h"
#include "datapath_raw_xdp.h"

typedef struct XDP_DATAPATH {
    CXPLAT_DATAPATH;
    DECLSPEC_CACHEALIGN
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
    BOOLEAN Running;        // Signal to stop partitions.
    XDP_LOAD_API_CONTEXT XdpApiLoadContext;
    const XDP_API_TABLE *XdpApi;
    XDP_QEO_SET_FN *XdpQeoSet;

    XDP_PARTITION Partitions[0];
} XDP_DATAPATH;

typedef struct XDP_INTERFACE {
    CXPLAT_INTERFACE;
    HANDLE XdpHandle;
    uint16_t QueueCount;
    uint8_t RuleCount;
    CXPLAT_LOCK RuleLock;
    XDP_RULE* Rules;
    XDP_QUEUE* Queues; // An array of queues.
    const struct XDP_DATAPATH* Xdp;
} XDP_INTERFACE;

typedef struct XDP_QUEUE {
    const XDP_INTERFACE* Interface;
    XDP_PARTITION* Partition;
    struct XDP_QUEUE* Next;
    uint8_t* RxBuffers;
    HANDLE RxXsk;
    DATAPATH_IO_SQE RxIoSqe;
    XSK_RING RxFillRing;
    XSK_RING RxRing;
    HANDLE RxProgram;
    uint8_t* TxBuffers;
    HANDLE TxXsk;
    DATAPATH_IO_SQE TxIoSqe;
    XSK_RING TxRing;
    XSK_RING TxCompletionRing;
    BOOLEAN RxQueued;
    BOOLEAN TxQueued;
    BOOLEAN Error;

    CXPLAT_LIST_ENTRY PartitionTxQueue;
    CXPLAT_SLIST_ENTRY PartitionRxPool;

    // Move contended buffer pools to their own cache lines.
    // TODO: Use better (more scalable) buffer algorithms.
    DECLSPEC_CACHEALIGN SLIST_HEADER RxPool;
    DECLSPEC_CACHEALIGN SLIST_HEADER TxPool;

    // Move TX queue to its own cache line.
    DECLSPEC_CACHEALIGN
    CXPLAT_LOCK TxLock;
    CXPLAT_LIST_ENTRY TxQueue;
} XDP_QUEUE;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_RX_PACKET {
    // N.B. This struct is also put in a SLIST, so it must be aligned.
    XDP_QUEUE* Queue;
    CXPLAT_ROUTE RouteStorage;
    CXPLAT_RECV_DATA RecvData;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;
