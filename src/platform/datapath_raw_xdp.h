/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#ifndef _DATAPATH_RAW_XDP_H_
#define _DATAPATH_RAW_XDP_H_

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

typedef struct QUIC_CACHEALIGN XDP_PARTITION {
    CXPLAT_EXECUTION_CONTEXT Ec;
    DATAPATH_SQE ShutdownSqe;
    const struct XDP_DATAPATH* Xdp;
    CXPLAT_EVENTQ* EventQ;
    XDP_QUEUE* Queues; // A linked list of queues, accessed by Next.
    uint16_t PartitionIndex;
} XDP_PARTITION;

#endif  //  _DATAPATH_RAW_XDP_H_