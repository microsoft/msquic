/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "platform_internal.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define MAX_BURST_SIZE 32

//typedef struct rte_mempool;

typedef struct CXPLAT_DATAPATH {

    BOOLEAN Running;
    CXPLAT_THREAD WorkerThread;

    uint16_t Port;
    uint8_t SourceMac[6];
    struct rte_mempool *MemoryPool;

} CXPLAT_DATAPATH;

#pragma pack(push)
#pragma pack(1)

typedef struct ETHERNET_HEADER {
    uint8_t Destination[6];
    uint8_t Source[6];
    union {
        uint16_t Type;
        uint16_t Length;
    };
    uint8_t Data[0];
} ETHERNET_HEADER;

typedef struct IPV4_HEADER {
    uint8_t VersionAndHeaderLength;
    uint8_t TypeOfService;
    uint16_t TotalLength;
    uint16_t Identification;
    uint16_t FlagsAndFragmentOffset;
    uint8_t TimeToLive;
    uint8_t Protocol;
    uint16_t HeaderChecksum;
    uint8_t Source[4];
    uint8_t Destination[4];
    uint8_t Data[0];
} IPV4_HEADER;

typedef struct IPV6_HEADER {
    uint32_t VersionAndTrafficClass;
    uint16_t FlowLabel;
    uint16_t PayloadLength;
    uint8_t NextHeader;
    uint8_t HopLimit;
    uint8_t Source[16];
    uint8_t Destination[16];
    uint8_t Data[0];
} IPV6_HEADER;

typedef struct IPV6_EXTENSION {
    uint8_t NextHeader;
    uint8_t Length;
    uint16_t Reserved0;
    uint32_t Reserved1;
    uint8_t Data[0];
} IPV6_EXTENSION;

typedef struct UDP_HEADER {
    uint16_t SourcePort;
    uint16_t DestinationPort;
    uint16_t Length;
    uint16_t Checksum;
    uint8_t Data[0];
} UDP_HEADER;

#pragma pack(pop)

typedef struct DATAGRAM_DESCRIPTOR {
    QUIC_ADDR Source;
    QUIC_ADDR Destination;
    const uint8_t* Data;
    uint16_t Length;
} DATAGRAM_DESCRIPTOR;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ DATAGRAM_DESCRIPTOR* Datagram,
    _In_reads_bytes_(Length)
        const ETHERNET_HEADER* Ethernet,
    _In_ uint16_t Length
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkRxUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_reads_(Count)
        const DATAGRAM_DESCRIPTOR* Datagrams,
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
