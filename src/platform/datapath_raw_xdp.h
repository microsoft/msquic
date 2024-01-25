/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include <stdio.h>
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <xdpapi_experimental.h>
#include "platform_internal.h"

#define RX_BATCH_SIZE 16
#define MAX_ETH_FRAME_SIZE 1514
#define ADAPTER_TAG   'ApdX' // XdpA
#define IF_TAG        'IpdX' // XdpI
#define QUEUE_TAG     'QpdX' // XdpQ
#define RULE_TAG      'UpdX' // XdpU
#define RX_BUFFER_TAG 'RpdX' // XdpR
#define TX_BUFFER_TAG 'TpdX' // XdpT
#define PORT_SET_TAG  'PpdX' // XdpP
#define RSS_TAG       'SpdX' // XdpS

typedef struct XDP_INTERFACE XDP_INTERFACE;
typedef struct XDP_PARTITION XDP_PARTITION;
typedef struct XDP_DATAPATH XDP_DATAPATH;
typedef struct XDP_QUEUE XDP_QUEUE;

//
// IO header for SQE->CQE based completions.
//
typedef struct DATAPATH_XDP_IO_SQE {
    DATAPATH_XDP_IO_TYPE IoType;
    DATAPATH_SQE DatapathSqe;
} DATAPATH_XDP_IO_SQE;

typedef struct XDP_QUEUE {
    const XDP_INTERFACE* Interface;
    XDP_PARTITION* Partition;
    struct XDP_QUEUE* Next;
    uint8_t* RxBuffers;
    HANDLE RxXsk;
    DATAPATH_XDP_IO_SQE RxIoSqe;
    XSK_RING RxFillRing;
    XSK_RING RxRing;
    HANDLE RxProgram;
    uint8_t* TxBuffers;
    HANDLE TxXsk;
    DATAPATH_XDP_IO_SQE TxIoSqe;
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

typedef struct QUIC_CACHEALIGN XDP_PARTITION {
    CXPLAT_EXECUTION_CONTEXT Ec;
    DATAPATH_SQE ShutdownSqe;
    const struct XDP_DATAPATH* Xdp;
    CXPLAT_EVENTQ* EventQ;
    XDP_QUEUE* Queues; // A linked list of queues, accessed by Next.
    uint16_t PartitionIndex;
} XDP_PARTITION;

typedef struct XDP_DATAPATH {
    CXPLAT_DATAPATH_RAW;
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
#ifdef _KERNEL_MODE
    NPI Npi;
    HANDLE NmrBindingHandle;
    XDP_API_PROVIDER_DISPATCH *XdpApi;
    VOID *XdpApiProviderBindingContext;
    HANDLE NmrRegistrationHandle;
    KEVENT BoundToProvider;
#elif _WIN32
    XDP_LOAD_API_CONTEXT XdpApiLoadContext;
    const XDP_API_TABLE *XdpApi;
#endif
    XDP_QEO_SET_FN *XdpQeoSet;

    XDP_PARTITION Partitions[0];
} XDP_DATAPATH;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(*CXPLAT_XDP_CREATE_INTERFACE_FN)(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t IfIndex,
    _In_ uint32_t ActualIfIndex,
    _In_ uint8_t* PhysicalAddress,
    _In_ uint32_t ClientRecvContextLength
    );

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ XDP_DATAPATH* Xdp,
    _In_ HANDLE XdpHandle,
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    );

QUIC_STATUS
CxPlatXdpInitialize(
    _In_ XDP_DATAPATH* Xdp
    );

VOID
CxPlatXdpUninitialize(
    _In_ XDP_DATAPATH* Xdp
    );

QUIC_STATUS
CxPlatXdpDiscoverInterfaces(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_XDP_CREATE_INTERFACE_FN CreateInterface
    );


XDP_STATUS
CxPlatXdpCreateXsk(
    _In_ const XDP_DATAPATH* Xdp,
    _Out_ HANDLE* Xsk
    );

XDP_STATUS
CxPlatXdpXskSetSockopt(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t OptionName,
    _In_ void* OptionValue,
    _In_ uint32_t OptionLength
    );

XDP_STATUS
CxPlatXdpXskGetSockopt(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t OptionName,
    _Out_writes_bytes_(*OptionLength) void* OptionValue,
    _Inout_ uint32_t* OptionLength
    );

XDP_STATUS
CxPlatXdpXskBind(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t IfIndex,
    _In_ uint32_t QueueId,
    _In_ XSK_BIND_FLAGS Flags
    );

XDP_STATUS
CxPlatXdpXskActivate(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ XSK_ACTIVATE_FLAGS Flags
    );

XDP_STATUS
CxPlatXdpXskPokeTx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk
    );

XDP_STATUS
CxPlatXdpXskNotifyAsync(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ XSK_NOTIFY_FLAGS Flags,
    _Inout_ XSK_COMPLETION_CONTEXT CompletionContext,
    _Out_ XSK_NOTIFY_RESULT_FLAGS* Result
    );

VOID
CxPlatXdpCloseXsk(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk
    );

XDP_STATUS
CxPlatXdpCreateProgram(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ uint32_t InterfaceIndex,
    _In_ CONST XDP_HOOK_ID* HookId,
    _In_ uint32_t QueueId,
    _In_ XDP_CREATE_PROGRAM_FLAGS Flags,
    _In_reads_(RuleCount) CONST XDP_RULE* Rules,
    _In_ uint32_t RuleCount,
    _Out_ HANDLE* Program
    );

VOID
CxPlatXdpCloseProgram(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Program
    );

XDP_STATUS
CxPlatXdpOpenInterface(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ uint32_t IfIndex,
    _Out_ HANDLE* Interface
    );

VOID
CxPlatXdpCloseInterface(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Interface
    );
