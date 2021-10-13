/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC DPDK Datapath Implementation (User Mode)
    (Parts that require Clang to build)

--*/

#include "datapath_dpdk.h"
#ifdef QUIC_CLOG
#include "datapath_dpdk_clang.c.clog.h"
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
    DATAGRAM_DESCRIPTOR Datagrams[MAX_BURST_SIZE];
    uint16_t DatagramsCount = 0;
    for (uint16_t i = 0; i < PacketsCount; i++) {
        Datagrams[DatagramsCount].Length = 0;
        CxPlatDpdkParseEthernet(
            Datapath,
            &Datagrams[DatagramsCount],
            (ETHERNET_HEADER*)(((char*)Packets[i]->buf_addr)+Packets[i]->data_off),
            Packets[i]->pkt_len); // TODO - Subtract 'data_off`?

        if (Datagrams[DatagramsCount].Length != 0) {
            if (++DatagramsCount == MAX_BURST_SIZE) {
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

CXPLAT_THREAD_CALLBACK(CxPlatDpdkWorkerThread, Context) {
    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)Context;
    if (rte_eth_dev_socket_id(Datapath->Port) > 0 &&
            rte_eth_dev_socket_id(Datapath->Port) !=
                    (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n", Datapath->Port);

	printf("\nCore %u / Socket %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id(), rte_socket_id());

	while (Datapath->Running) {
        struct rte_mbuf *bufs[MAX_BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(Datapath->Port, 0, bufs, MAX_BURST_SIZE);
        if (unlikely(nb_rx == 0))
            continue;
        /*const uint16_t nb_tx = rte_eth_tx_burst(Datapath->Port ^ 1, 0,
                bufs, nb_rx);
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;

            for (buf = nb_tx; buf < nb_rx; buf++)
                rte_pktmbuf_free(bufs[buf]);
        }*/
	}
    CXPLAT_THREAD_RETURN(0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpdkInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath
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
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;
	const uint16_t rx_rings = 1, tx_rings = 1;
    struct rte_eth_dev_info DeviceInfo;
	struct rte_eth_rxconf rxconf;
	struct rte_eth_txconf txconf;
    struct rte_ether_addr addr;
    CXPLAT_THREAD_CONFIG Config = {
        CXPLAT_THREAD_FLAG_NONE, // TODO - CXPLAT_THREAD_FLAG_SET_AFFINITIZE,
        0,
        NULL,
        CxPlatDpdkWorkerThread,
        NULL
    };

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

	Datapath->MemoryPool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (Datapath->MemoryPool == NULL) {
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
    Datapath->Port = Port;

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
		ret = rte_eth_rx_queue_setup(Port, q, nb_rxd, rte_eth_dev_socket_id(Port), &rxconf, Datapath->MemoryPool);
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

	ret = rte_eth_dev_start(Port);
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
    CxPlatCopyMemory(Datapath->SourceMac, &addr, sizeof(addr));

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

	rte_eth_add_rx_callback(Port, 0, CxPlatDpdkRxEthernet, Datapath);

    printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
            " %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
            (unsigned)Port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    Config.Context = Datapath;
    //Config.IdealProcessor = TODO;

    Datapath->Running = TRUE;
    Status = CxPlatThreadCreate(&Config, &Datapath->WorkerThread); // TODO - I think we're supposed to use rte to spawn the thread instead.
    if (QUIC_FAILED(Status)) {
        printf("CxPlatThreadCreate failed: 0x%x\n", Status);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }

    CxPlatSleep(10000);

Error:

    if (QUIC_FAILED(Status)) {
        if (CleanUpRte) {
            rte_eal_cleanup();
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpdkUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{

    Datapath->Running = FALSE;
    CxPlatThreadWait(&Datapath->WorkerThread);
    CxPlatThreadDelete(&Datapath->WorkerThread);
	rte_eal_cleanup();
}
