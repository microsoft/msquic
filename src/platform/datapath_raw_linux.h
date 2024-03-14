/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "datapath_raw.h"
#include "platform_internal.h"
#include "quic_hashtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>

#include <netlink/netlink.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>

QUIC_STATUS
ResolveBestL3Route(
    QUIC_ADDR* RemoteAddress,
    QUIC_ADDR* SourceAddress,
    QUIC_ADDR* GatewayAddress,
    int* oif
    );

typedef struct CXPLAT_ROUTE_RESOLUTION_OPERATION {
    //
    // Link in the worker's operation queue.
    // N.B. Multi-threaded access, synchronized by worker's operation lock.
    //
    CXPLAT_LIST_ENTRY WorkerLink;

    // TODO: MIB_IPNET_ROW2 IpnetRow;

    void* Context;
    uint8_t PathId;
    CXPLAT_ROUTE_RESOLUTION_CALLBACK_HANDLER Callback;
} CXPLAT_ROUTE_RESOLUTION_OPERATION;

