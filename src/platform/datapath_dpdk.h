/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "quic_hashtable.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define MAX_BURST_SIZE 32

typedef struct CXPLAT_DATAPATH {

    BOOLEAN Running;
    CXPLAT_THREAD DpdkThread;
    QUIC_STATUS StartStatus;
    CXPLAT_EVENT StartComplete;

    uint16_t Port;
    uint8_t SourceMac[6];
    struct rte_mempool *MemoryPool;

    uint32_t ClientRecvContextLength;
    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpHandlers;

} CXPLAT_DATAPATH;

typedef enum PACKET_L2_TYPE {
    L2_TYPE_ETHERNET,
    L2_TYPE_WIFI,
} PACKET_L2_TYPE;

typedef enum PACKET_L3_TYPE {
    L3_TYPE_LLDP,
    L3_TYPE_ICMPV4,
    L3_TYPE_ICMPV6,
    L3_TYPE_IPV4,
    L3_TYPE_IPV6,
    L3_TYPE_QUIC,
} PACKET_L3_TYPE;

typedef enum PACKET_L4_TYPE {
    L4_TYPE_TCP,
    L4_TYPE_UDP,
} PACKET_L4_TYPE;

typedef struct PACKET_DESCRIPTOR {
    uint32_t IsValid : 1;
    uint32_t L2Type : 2;
    uint32_t L3Type : 3;
    uint32_t L4Type : 2;
    uint16_t Core;
    uint16_t PayloadLength;
    const uint8_t* Payload;
    union {
        struct {
            QUIC_ADDR Source;
            QUIC_ADDR Destination;
        } IP;
    };
} PACKET_DESCRIPTOR;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Datagram,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkRx(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_reads_(Count)
        const PACKET_DESCRIPTOR* Packets,
    _In_range_(1, MAX_BURST_SIZE)
        uint16_t Count
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpdkInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpdkUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    );
