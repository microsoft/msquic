/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"
#include "quic_hashtable.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_BURST_SIZE 16
#define TX_BURST_SIZE 16
#define TX_RING_SIZE 1024

typedef struct CXPLAT_DATAPATH {

    BOOLEAN Running;
    CXPLAT_THREAD DpdkThread;
    QUIC_STATUS StartStatus;
    CXPLAT_EVENT StartComplete;

    uint16_t CoreCount;

    // Constants
    uint8_t ServerMac[6];
    uint8_t ClientMac[6];
    QUIC_ADDR ServerIP;
    QUIC_ADDR ClientIP;
    uint16_t DpdkCpu;
    char DeviceName[32];

    uint16_t Port;
    CXPLAT_LOCK TxLock;
    uint8_t SourceMac[6];
    struct rte_mempool* MemoryPool;
    struct rte_ring* TxRingBuffer;

    uint16_t NextLocalPort;

    CXPLAT_POOL AdditionalInfoPool;

    CXPLAT_UDP_DATAPATH_CALLBACKS UdpHandlers;
    CXPLAT_TCP_DATAPATH_CALLBACKS TcpHandlers;

    CXPLAT_RW_LOCK SocketsLock;
    CXPLAT_HASHTABLE Sockets;

} CXPLAT_DATAPATH;

typedef enum PACKET_TYPE {
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

typedef struct CXPLAT_SEND_DATA {

    struct rte_mbuf* Mbuf;
    CXPLAT_DATAPATH* Datapath;
    QUIC_BUFFER Buffer;

} CXPLAT_SEND_DATA;

//
// Initializes the DPDK stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath
    );

//
// Cleans up the DPDK stack.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    );

//
// Upcall from DPDK to allow for parsing of a received Ethernet packet.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ DPDK_RX_PACKET* Packet,
    _In_reads_bytes_(Length)
        const uint8_t* Payload,
    _In_ uint16_t Length
    );

//
// Upcall from DPDK to indicate a received chain of packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_reads_(PacketCount)
        DPDK_RX_PACKET** Packets,
    _In_ uint16_t PacketCount
    );

//
// Frees a chain of previous received packets.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const DPDK_RX_PACKET* PacketChain
    );

//
// Allocates a new TX send object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t MaxPacketSize
    );

//
// Frees a previously allocated TX send object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    );

//
// Enqueues a TX send object to be sent out on the DPDK device.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    );
