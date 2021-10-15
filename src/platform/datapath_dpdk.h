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

    CXPLAT_POOL AdditionalInfoPool;

    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpHandlers;

    CXPLAT_RW_LOCK Lock;
    CXPLAT_HASHTABLE Sockets;

} CXPLAT_DATAPATH;

typedef enum PACKET_TYPE {
    L3_TYPE_LLDP,
    L3_TYPE_ICMPV4,
    L3_TYPE_ICMPV6,
    L4_TYPE_TCP,
    L4_TYPE_UDP,
} PACKET_TYPE;

typedef struct DPDK_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_TUPLE IP;
    struct rte_mbuf* Mbuf;
    CXPLAT_POOL* OwnerPool;
} DPDK_RX_PACKET;

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

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ DPDK_RX_PACKET* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkRx(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const DPDK_RX_PACKET* PacketChain
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkReturn(
    _In_opt_ const DPDK_RX_PACKET* PacketChain
    );
