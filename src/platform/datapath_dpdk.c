/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC DPDK Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "datapath_dpdk.c.clog.h"
#endif

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>

#pragma warning(disable:4116) // unnamed type definition in parentheses
#pragma warning(disable:4100) // unreferenced formal parameter

typedef struct CXPLAT_SEND_DATA {

    uint32_t Reserved;

} CXPLAT_SEND_DATA;

typedef struct CXPLAT_SOCKET {

    uint32_t Reserved;

} CXPLAT_SOCKET;

typedef struct CXPLAT_DATAPATH {

    uint16_t Port;
    struct rte_mempool *MemoryPool;

} CXPLAT_DATAPATH;

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)
        (((PUCHAR)Context) -
            sizeof(CXPLAT_RECV_DATA));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)
        (((PUCHAR)Datagram) +
            sizeof(CXPLAT_RECV_DATA));
}

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

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

typedef struct PACKET_DESCRIPTOR {
    QUIC_ADDR Source;
    QUIC_ADDR Destination;
    const uint8_t* Data;
    uint16_t Length;
} PACKET_DESCRIPTOR;

static
void
CxPlatDpdkParseUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const UDP_HEADER* Udp,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(UDP_HEADER)) {
        return;
    }
    Length -= sizeof(UDP_HEADER);

    Packet->Source.Ipv4.sin_port = Udp->SourcePort;
    Packet->Destination.Ipv4.sin_port = Udp->DestinationPort;

    Packet->Data = Udp->Data;
    Packet->Length = Length;
}

static
void
CxPlatDpdkParseIPv4(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const IPV4_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV4_HEADER)) {
        return;
    }
    Length -= sizeof(IPV4_HEADER);

    Packet->Source.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Source.Ipv4.sin_addr, IP->Source, sizeof(IP->Source));
    Packet->Destination.Ipv4.sin_family = AF_INET;
    CxPlatCopyMemory(&Packet->Destination.Ipv4.sin_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->Protocol == 17) {
        CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
    }
}

static
void
CxPlatDpdkParseIPv6(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const IPV6_HEADER* IP,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(IPV6_HEADER)) {
        return;
    }
    Length -= sizeof(IPV6_HEADER);

    Packet->Source.Ipv6.sin6_family = AF_INET;
    CxPlatCopyMemory(&Packet->Source.Ipv6.sin6_addr, IP->Source, sizeof(IP->Source));
    Packet->Destination.Ipv6.sin6_family = AF_INET;
    CxPlatCopyMemory(&Packet->Destination.Ipv6.sin6_addr, IP->Destination, sizeof(IP->Destination));

    if (IP->NextHeader == 17) {
        CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)IP->Data, Length);
    } else if (IP->NextHeader != 59) {
        const uint8_t* Data = IP->Data;
        do {
            if (Length < sizeof(IPV6_EXTENSION)) {
                return;
            }
            const IPV6_EXTENSION* Extension = (const IPV6_EXTENSION*)Data;
            const uint16_t ExtLength = sizeof(IPV6_EXTENSION) + Extension->Length * sizeof(IPV6_EXTENSION);
            if (Length < ExtLength) {
                return;
            }
            Length -= ExtLength;
            Data += ExtLength;
            if (Extension->NextHeader == 17) {
                CxPlatDpdkParseUdp(Datapath, Packet, (UDP_HEADER*)Extension->Data, Length);
            } else if (Extension->NextHeader == 59) {
                return;
            }
        } while (TRUE);
    }
}

static
void
CxPlatDpdkParseEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ PACKET_DESCRIPTOR* Packet,
    _In_reads_bytes_(Length)
        const ETHERNET_HEADER* Ethernet,
    _In_ uint16_t Length
    )
{
    if (Length < sizeof(ETHERNET_HEADER)) {
        return;
    }
    Length -= sizeof(ETHERNET_HEADER);

    if (Ethernet->Type == 0x0008) { // IPv4
        CxPlatDpdkParseIPv4(Datapath, Packet, (IPV4_HEADER*)Ethernet->Data, Length);
    } else if (Ethernet->Type == 0xDD86) { // IPv6
        CxPlatDpdkParseIPv6(Datapath, Packet, (IPV6_HEADER*)Ethernet->Data, Length);
    }
}

#define CXPLAT_MAX_PACKET_BATCH_SIZE 32

static
void
CxPlatDpdkRxUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_reads_(Count)
        const PACKET_DESCRIPTOR* Datagrams,
    _In_range_(1, CXPLAT_MAX_PACKET_BATCH_SIZE)
        uint16_t Count
    )
{
    for (uint16_t i = 0; i < Count; i++) {
        const PACKET_DESCRIPTOR* Datagram = &Datagrams[i];
        QUIC_ADDR_STR Source; QuicAddrToString(&Datagram->Source, &Source);
        QUIC_ADDR_STR Destination; QuicAddrToString(&Datagram->Destination, &Destination);
        printf("RX [%hu] [%s:%hu->%s:%hu]\n", Datagram->Length,
            Source.Address, CxPlatByteSwapUint16(Datagram->Source.Ipv4.sin_port),
            Destination.Address, CxPlatByteSwapUint16(Datagram->Destination.Ipv4.sin_port));
        // TODO - Process datagram
    }
}

static
uint16_t
CxPlatDpdkRxEthernet(
    _In_ uint16_t Port,
    _In_ uint16_t Queue,
    _In_reads_(PacketsCount)
        struct rte_mbuf** Packets,
    _In_ uint16_t PacketsCount,
    _In_ uint16_t PacketsMaxCount,
    _In_ void *Context
    )
{
    UNREFERENCED_PARAMETER(Port);
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(PacketsMaxCount);
    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)Context;
    PACKET_DESCRIPTOR Datagrams[CXPLAT_MAX_PACKET_BATCH_SIZE];
    uint16_t DatagramsCount = 0;
    for (uint16_t i = 0; i < PacketsCount; i++) {
        Datagrams[DatagramsCount].Length = 0;
        CxPlatDpdkParseEthernet(
            Datapath,
            &Datagrams[DatagramsCount],
            (ETHERNET_HEADER*)(((char*)Packets[i]->buf_addr)+Packets[i]->data_off),
            Packets[i]->pkt_len); // TODO - Subtract 'data_off`?

        if (Datagrams[DatagramsCount].Length != 0) {
            if (++DatagramsCount == CXPLAT_MAX_PACKET_BATCH_SIZE) {
                CxPlatDpdkRxUdp(Datapath, Datagrams, DatagramsCount);
                DatagramsCount = 0;
            }
        }
    }
    if (DatagramsCount != 0) {
        CxPlatDpdkRxUdp(Datapath, Datagrams, DatagramsCount);
    }
    return PacketsCount;
}

static void
lcore_main(void)
{
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u / Socket %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id(), rte_socket_id());
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;
			/*const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx);
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;

				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}*/
		}
	}
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathInitialize(
    _In_ uint32_t ClientRecvContextLength,
    _In_opt_ const CXPLAT_UDP_DATAPATH_CALLBACKS* UdpCallbacks,
    _In_opt_ const CXPLAT_TCP_DATAPATH_CALLBACKS* TcpCallbacks,
    _Out_ CXPLAT_DATAPATH** NewDataPath
    )
{
    const char* argv[] = {
        "msquic",
        "-n", "4",
        "-l", "3,4",
        "-d", "rte_mempool_ring-21.dll",
        "-d", "rte_bus_pci-21.dll",
        "-d", "rte_common_mlx5-21.dll",
        "-d", "rte_net_mlx5-21.dll"
    };
    const char* DeviceName = "0000:81:00.0";

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN CleanUpRte = FALSE;
    int ret;
    uint16_t Port;
    struct rte_eth_conf PortConfig = {
        .rxmode = {
            .max_rx_pkt_len = 2000, // RTE_ETHER_MAX_LEN,
        },
    };
	const uint16_t rx_rings = 1, tx_rings = 1;
    struct rte_eth_dev_info DeviceInfo;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;

    *NewDataPath = CXPLAT_ALLOC_PAGED(sizeof(CXPLAT_DATAPATH), QUIC_POOL_DATAPATH);
    if (*NewDataPath == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_DATAPATH",
            sizeof(CXPLAT_DATAPATH));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    printf("Calling rte_eal_init...\n");
    ret = rte_eal_init(ARRAYSIZE(argv), (char**)argv);
    if (ret < 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eal_init");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }
    CleanUpRte = TRUE;

	(*NewDataPath)->MemoryPool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if ((*NewDataPath)->MemoryPool == NULL) {
        printf("rte_pktmbuf_pool_create failed\n");
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            0,
            "rte_pktmbuf_pool_create");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    ret = rte_eth_dev_get_port_by_name(DeviceName, &Port);
    if (ret < 0) {
        printf("rte_eth_dev_count_avail failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_dev_get_port_by_name");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }
    (*NewDataPath)->Port = Port;

    ret = rte_eth_dev_info_get(Port, &DeviceInfo);
    if (ret < 0) {
        printf("rte_eth_dev_info_get failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_dev_info_get");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    ret = rte_eth_dev_configure(Port, rx_rings, tx_rings, &PortConfig);
    if (ret < 0) {
        printf("rte_eth_dev_configure failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_dev_configure");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(Port, &nb_rxd, &nb_txd);
    if (ret < 0) {
        printf("rte_eth_dev_adjust_nb_rx_tx_desc failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_dev_configure");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

	rxconf = DeviceInfo.default_rxconf;

	for (uint16_t q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(Port, q, nb_rxd, rte_eth_dev_socket_id(Port), &rxconf, (*NewDataPath)->MemoryPool);
        if (ret < 0) {
            printf("rte_eth_rx_queue_setup failed: %d\n", ret);
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ret,
                "rte_eth_rx_queue_setup");
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }
	}

	txconf = DeviceInfo.default_txconf;
	txconf.offloads = PortConfig.txmode.offloads;
	for (uint16_t q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(Port, q, nb_txd, rte_eth_dev_socket_id(Port), &txconf);
        if (ret < 0) {
            printf("rte_eth_tx_queue_setup failed: %d\n", ret);
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ret,
                "rte_eth_tx_queue_setup");
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }
	}

	ret  = rte_eth_dev_start(Port);
    if (ret < 0) {
        printf("rte_eth_dev_start failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_dev_start");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    {
        struct rte_ether_addr addr;
        ret = rte_eth_macaddr_get(Port, &addr);
        if (ret < 0) {
            printf("rte_eth_macaddr_get failed: %d\n", ret);
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ret,
                "rte_eth_macaddr_get");
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }
        printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
                " %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
                (unsigned)Port,
                addr.addr_bytes[0], addr.addr_bytes[1],
                addr.addr_bytes[2], addr.addr_bytes[3],
                addr.addr_bytes[4], addr.addr_bytes[5]);
    }

    ret = rte_eth_promiscuous_enable(Port);
    if (ret < 0) {
        printf("rte_eth_promiscuous_enable failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_promiscuous_enable");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

	rte_eth_add_rx_callback(Port, 0, CxPlatDpdkRxEthernet, *NewDataPath);

    lcore_main();

Error:

    if (QUIC_FAILED(Status)) {
        if (CleanUpRte) {
            rte_eal_cleanup();
        }
        if (*NewDataPath != NULL) {
            CXPLAT_FREE(*NewDataPath, QUIC_POOL_DATAPATH);
            *NewDataPath = NULL;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDataPathUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    if (Datapath == NULL) {
        return;
    }
    CXPLAT_FREE(Datapath, QUIC_POOL_DATAPATH);
	rte_eal_cleanup();
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint32_t
CxPlatDataPathGetSupportedFeatures(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatDataPathIsPaddingPreferred(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateUdp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_UDP_CONFIG* Config,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcp(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_opt_ void* CallbackContext,
    _Out_ CXPLAT_SOCKET** Socket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketCreateTcpListener(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ void* RecvCallbackContext,
    _Out_ CXPLAT_SOCKET** NewSocket
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSocketDelete(
    _In_ CXPLAT_SOCKET* Socket
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16
CxPlatSocketGetLocalMtu(
    _In_ CXPLAT_SOCKET* Socket
    )
{
    return 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetLocalAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSocketGetRemoteAddress(
    _In_ CXPLAT_SOCKET* Socket,
    _Out_ QUIC_ADDR* Address
    )
{
    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatRecvDataReturn(
    _In_opt_ CXPLAT_RECV_DATA* RecvDataChain
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
CXPLAT_SEND_DATA*
CxPlatSendDataAlloc(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ CXPLAT_ECN_TYPE ECN,
    _In_ uint16_t MaxPacketSize
    )
{
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != NULL)
QUIC_BUFFER*
CxPlatSendDataAllocBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t MaxBufferLength
    )
{
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatSendDataFreeBuffer(
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ QUIC_BUFFER* Buffer
    )
{
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
CxPlatSendDataIsFull(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    return TRUE;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatSocketSend(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _In_ CXPLAT_SEND_DATA* SendData,
    _In_ uint16_t IdealProcessor
    )
{
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketSetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength) const UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSocketGetParam(
    _In_ CXPLAT_SOCKET* Socket,
    _In_ uint32_t Param,
    _Inout_ PUINT32 BufferLength,
    _Out_writes_bytes_opt_(*BufferLength) UINT8 * Buffer
    )
{
    UNREFERENCED_PARAMETER(Socket);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}
