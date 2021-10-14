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

CXPLAT_THREAD_CALLBACK(CxPlatDpdkMainThread, Context);
static int CxPlatDpdkWorkerThread(_In_ void* Context);

static
uint16_t
CxPlatDpdkRxEthernet(
    _In_ uint16_t Port,
    _In_ uint16_t Queue,
    _In_reads_(BuffersCount)
        struct rte_mbuf** Buffers,
    _In_ uint16_t BuffersCount,
    _In_ uint16_t BuffersMaxCount,
    _In_ void *Context
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpdkInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    CXPLAT_THREAD_CONFIG Config = {
        0, 0, "DpdkMain", CxPlatDpdkMainThread, Datapath
    };

    BOOLEAN CleanUpThread = FALSE;
    CxPlatEventInitialize(&Datapath->StartComplete, TRUE, FALSE);

    //
    // This starts a new thread to do all the DPDK initialization because DPDK
    // effectively takes that thread over. It waits for the initialization part
    // to complete before returning. After that, the DPDK main thread starts
    // running the DPDK main loop until clean up.
    //

    QUIC_STATUS Status = CxPlatThreadCreate(&Config, &Datapath->DpdkThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }
    CleanUpThread = TRUE;

    CxPlatEventWaitForever(&Datapath->StartComplete);
    Status = Datapath->StartStatus;

Error:

    if (QUIC_FAILED(Status)) {
        if (CleanUpThread) {
            CxPlatThreadWait(&Datapath->DpdkThread);
            CxPlatThreadDelete(&Datapath->DpdkThread);
        }
        CxPlatEventUninitialize(&Datapath->StartComplete);
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
    CxPlatThreadWait(&Datapath->DpdkThread);
    CxPlatThreadDelete(&Datapath->DpdkThread);
}

CXPLAT_THREAD_CALLBACK(CxPlatDpdkMainThread, Context)
{
    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)Context;

    const char* argv[] = {
        "msquic",
        "-n", "4",
        "-l", "10-13",
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

    Datapath->MemoryPool =
        rte_pktmbuf_pool_create(
            "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, rte_eth_dev_socket_id(Port));
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
    printf("\nStarting Port %hu, MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
            Datapath->Port,
            Datapath->SourceMac[0], Datapath->SourceMac[1], Datapath->SourceMac[2],
            Datapath->SourceMac[3], Datapath->SourceMac[4], Datapath->SourceMac[5]);

    Datapath->Running = TRUE;
    ret = rte_eal_mp_remote_launch(CxPlatDpdkWorkerThread, Datapath, SKIP_MAIN);
    if (ret < 0) {
        printf("rte_eal_mp_remote_launch failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eal_mp_remote_launch");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Datapath->StartStatus = Status;
    CxPlatEventSet(Datapath->StartComplete);

    CxPlatDpdkWorkerThread(Datapath);

    rte_eal_mp_wait_lcore(); // Wait on the other cores/threads

Error:

    if (QUIC_FAILED(Status)) {
        Datapath->StartStatus = Status;
        CxPlatEventSet(Datapath->StartComplete);
    }

    if (CleanUpRte) {
        rte_eal_cleanup();
    }

    CXPLAT_THREAD_RETURN(0);
}

static
int
CxPlatDpdkWorkerThread(
    _In_ void* Context
    )
{
    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)Context;
    const uint16_t Core = (uint16_t)rte_lcore_id();

    printf("Core %u worker running...\n", Core);

    if (rte_eth_dev_socket_id(Datapath->Port) > 0 &&
            rte_eth_dev_socket_id(Datapath->Port) !=
                    (int)rte_socket_id())
        printf("\nWARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n\n", Datapath->Port);

    while (Datapath->Running) {
        struct rte_mbuf *bufs[MAX_BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(Datapath->Port, Core%4, bufs, MAX_BURST_SIZE);
        for (uint16_t buf = 0; buf < nb_rx; buf++)
            rte_pktmbuf_free(bufs[buf]);
        /*const uint16_t nb_tx = rte_eth_tx_burst(Datapath->Port ^ 1, 0,
                bufs, nb_rx);
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;

            for (buf = nb_tx; buf < nb_rx; buf++)
                rte_pktmbuf_free(bufs[buf]);
        }*/
    }

    return 0;
}

static
uint16_t
CxPlatDpdkRxEthernet(
    _In_ uint16_t Port,
    _In_ uint16_t Queue,
    _In_reads_(BuffersCount)
        struct rte_mbuf** Buffers,
    _In_ uint16_t BuffersCount,
    _In_ uint16_t BuffersMaxCount,
    _In_ void *Context
    )
{
    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)Context;
    const uint16_t Core = (uint16_t)rte_lcore_id();
    PACKET_DESCRIPTOR Packets[MAX_BURST_SIZE];
    uint16_t PacketsCount = 0;
    for (uint16_t i = 0; i < BuffersCount; i++) {
        Packets[PacketsCount].IsValid = FALSE;
        CxPlatDpdkParseEthernet(
            Datapath,
            &Packets[PacketsCount],
            ((uint8_t*)Buffers[i]->buf_addr)+Buffers[i]->data_off,
            Buffers[i]->pkt_len);

        if (Packets[PacketsCount].IsValid) {
            Packets[PacketsCount].Core = Core;
            ++PacketsCount;
            CXPLAT_DBG_ASSERT(PacketsCount <= MAX_BURST_SIZE);
        }
    }
    if (PacketsCount != 0) {
        CxPlatDpdkRx(Datapath, Packets, PacketsCount);
    }
    return BuffersCount;
}
