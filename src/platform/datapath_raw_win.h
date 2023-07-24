/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "datapath_raw.h"
#include "platform_internal.h"
#include "quic_hashtable.h"

typedef struct CXPLAT_ROUTE_RESOLUTION_OPERATION {
    //
    // Link in the worker's operation queue.
    // N.B. Multi-threaded access, synchronized by worker's operation lock.
    //
    CXPLAT_LIST_ENTRY WorkerLink;
    MIB_IPNET_ROW2 IpnetRow;
    void* Context;
    uint8_t PathId;
    CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback;
} CXPLAT_ROUTE_RESOLUTION_OPERATION;
