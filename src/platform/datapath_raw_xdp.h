/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include <stdio.h>
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

typedef struct XDP_INTERFACE XDP_INTERFACE;
typedef struct XDP_WORKER XDP_WORKER;
typedef struct XDP_DATAPATH XDP_DATAPATH;
typedef struct XDP_QUEUE XDP_QUEUE;

//
// Type of IO.
//
typedef enum DATAPATH_IO_TYPE {
    DATAPATH_IO_SIGNATURE         = 'XDPD',
    DATAPATH_IO_RECV              = DATAPATH_IO_SIGNATURE + 1,
    DATAPATH_IO_SEND              = DATAPATH_IO_SIGNATURE + 2
} DATAPATH_IO_TYPE;

//
// IO header for SQE->CQE based completions.
//
typedef struct DATAPATH_IO_SQE {
    DATAPATH_IO_TYPE IoType;
    DATAPATH_SQE DatapathSqe;
} DATAPATH_IO_SQE;

typedef struct QUIC_CACHEALIGN XDP_WORKER {
    CXPLAT_EXECUTION_CONTEXT Ec;
    DATAPATH_SQE ShutdownSqe;
    const struct XDP_DATAPATH* Xdp;
    CXPLAT_EVENTQ* EventQ;
    XDP_QUEUE* Queues; // A linked list of queues, accessed by Next.
    uint16_t ProcIndex;
} XDP_WORKER;
