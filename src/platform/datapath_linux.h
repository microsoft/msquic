/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

#include <fcntl.h>
#include <linux/filter.h>
#include <linux/in6.h>
#include <netinet/udp.h>

//
// The maximum single buffer size for single packet/datagram IO payloads.
//
#define CXPLAT_SMALL_IO_BUFFER_SIZE         MAX_UDP_PAYLOAD_LENGTH

//
// The maximum single buffer size for coalesced IO payloads.
// Payload size: 65535 - 8 (UDP header) - 20 (IP header) = 65507 bytes.
//
#define CXPLAT_LARGE_IO_BUFFER_SIZE         0xFFE3

//
// The maximum batch size of IOs in that can use a single coalesced IO buffer.
// This is calculated base on the number of the smallest possible single
// packet/datagram payloads (i.e. IPv6) that can fit in the large buffer.
//
const uint16_t CXPLAT_MAX_IO_BATCH_SIZE =
    (CXPLAT_LARGE_IO_BUFFER_SIZE / (1280 - CXPLAT_MIN_IPV6_HEADER_SIZE - CXPLAT_UDP_HEADER_SIZE));

#ifdef DEBUG
#define CXPLAT_DBG_ASSERT_CMSG(CMsg, type) \
    if (CMsg->cmsg_len < CMSG_LEN(sizeof(type))) { \
        printf("%u: cmsg[%u:%u] len (%u) < exp_len (%u)\n", \
            (uint32_t)__LINE__, \
            (uint32_t)CMsg->cmsg_level, (uint32_t)CMsg->cmsg_type, \
            (uint32_t)CMsg->cmsg_len, (uint32_t)CMSG_LEN(sizeof(type))); \
    }
#else
#define CXPLAT_DBG_ASSERT_CMSG(CMsg, type)
#endif

void
CxPlatDataPathCalculateFeatureSupport(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvDataLength
    );
