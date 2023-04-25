#pragma once

#include "quic_datapath.h"
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <netinet/udp.h>

typedef enum PACKET_TYPE {
    L3_TYPE_ICMPV4,
    L3_TYPE_ICMPV6,
    L4_TYPE_UDP,
    L4_TYPE_TCP,
    L4_TYPE_TCP_SYN,
    L4_TYPE_TCP_SYNACK,
    L4_TYPE_TCP_FIN,
} PACKET_TYPE;

//
// Upcall from raw datapath to indicate a received chain of packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawParseEthernet(
    _In_ const CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_RECV_DATA* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    );

int framing_packet(
    const uint8_t *buffer, size_t size,
    const uint8_t src_mac[ETH_ALEN], const uint8_t dst_mac[ETH_ALEN],
    QUIC_ADDR* LocalAddress, QUIC_ADDR* RemoteAddress,
    uint16_t src_port, uint16_t dst_port,
    CXPLAT_ECN_TYPE ECN,
    struct ethhdr* eth, uint32_t* pkt_len);