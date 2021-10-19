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

    CxPlatEventWaitForever(Datapath->StartComplete);
    Status = Datapath->StartStatus;

Error:

    if (QUIC_FAILED(Status)) {
        if (CleanUpThread) {
            CxPlatThreadWait(&Datapath->DpdkThread);
            CxPlatThreadDelete(&Datapath->DpdkThread);
        }
        CxPlatEventUninitialize(Datapath->StartComplete);
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
    CxPlatEventUninitialize(Datapath->StartComplete);
}

CXPLAT_THREAD_CALLBACK(CxPlatDpdkMainThread, Context)
{
    CXPLAT_DATAPATH* Datapath = (CXPLAT_DATAPATH*)Context;

    const char* argv[] = {
        "msquic",
        "-n", "4",
        "-l", "19",
        "-d", "rte_mempool_ring-21.dll",
        "-d", "rte_bus_pci-21.dll",
        "-d", "rte_common_mlx5-21.dll",
        "-d", "rte_net_mlx5-21.dll"
    };
    const char* DeviceName1 = "0000:81:00.0";
    const char* DeviceName2 = "0000:81:00.1";

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN CleanUpRte = FALSE;
    int ret;
    uint16_t Port;
    struct rte_eth_conf PortConfig = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
    };
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    const uint16_t rx_rings = 4, tx_rings = 1;
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

    ret = rte_eth_dev_get_port_by_name(DeviceName1, &Port);
    if (ret < 0) {
        ret = rte_eth_dev_get_port_by_name(DeviceName2, &Port);
    }
    if (ret < 0) {
        printf("rte_eth_dev_get_port_by_name failed: %d\n", ret);
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

    /*ret = rte_eth_promiscuous_enable(Port);
    if (ret < 0) {
        printf("rte_eth_promiscuous_enable failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_promiscuous_enable");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }*/

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
void
CxPlatDpdkRxEthernet(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const uint16_t Core,
    _In_reads_(BuffersCount)
        struct rte_mbuf** Buffers,
    _In_ uint16_t BuffersCount
    )
{
    DPDK_RX_PACKET* PacketChain = NULL;
    DPDK_RX_PACKET** PacketChainTail = &PacketChain;
    DPDK_RX_PACKET Packet; // Working space
    //printf("DPDK RX %hu packet(s)\n", BuffersCount);
    for (uint16_t i = 0; i < BuffersCount; i++) {
        CxPlatZeroMemory(&Packet, sizeof(DPDK_RX_PACKET));
        CxPlatDpdkParseEthernet(
            Datapath,
            &Packet,
            ((uint8_t*)Buffers[i]->buf_addr)+Buffers[i]->data_off,
            Buffers[i]->pkt_len);

        if (Packet.Buffer) {
            Packet.Allocated = TRUE;
            Packet.PartitionIndex = Core;
            Packet.Mbuf = Buffers[i];
            Packet.OwnerPool = &Datapath->AdditionalInfoPool;
            DPDK_RX_PACKET* NewPacket = CxPlatPoolAlloc(&Datapath->AdditionalInfoPool);
            if (NewPacket) {
                CxPlatCopyMemory(NewPacket, &Packet, sizeof(DPDK_RX_PACKET));
                *PacketChainTail = NewPacket;
                PacketChainTail = (DPDK_RX_PACKET**)&NewPacket->Next;
            } else {
                rte_pktmbuf_free(Buffers[i]);
            }
        } else {
            rte_pktmbuf_free(Buffers[i]);
        }
    }
    if (PacketChain) {
        CxPlatDpdkRx(Datapath, PacketChain);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkReturn(
    _In_opt_ const DPDK_RX_PACKET* PacketChain
    )
{
    while (PacketChain) {
        const DPDK_RX_PACKET* Packet = PacketChain;
        PacketChain =  (DPDK_RX_PACKET*)PacketChain->Next;
        rte_pktmbuf_free(Packet->Mbuf);
        CxPlatPoolFree(Packet->OwnerPool, (void*)Packet);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpdkAllocTx(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t MaxPacketSize
    )
{
    CXPLAT_SEND_DATA* SendData = CxPlatPoolAlloc(&Datapath->AdditionalInfoPool);
    if (SendData) {
        SendData->Mbuf = rte_pktmbuf_alloc(Datapath->MemoryPool);
        if (SendData->Mbuf) {
            SendData->Datapath = Datapath;
            SendData->Buffer.Length = 0;
            SendData->Buffer.Buffer =
                ((uint8_t*)SendData->Mbuf->buf_addr) + (RTE_ETHER_MAX_LEN - MaxPacketSize);
        } else {
            CxPlatPoolFree(&Datapath->AdditionalInfoPool, SendData);
            SendData = NULL;
        }
    }
    return SendData;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkFreeTx(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    rte_pktmbuf_free(SendData->Mbuf);
    CxPlatPoolFree(&SendData->Datapath->AdditionalInfoPool, SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpdkTx(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    CXPLAT_DATAPATH* Datapath = SendData->Datapath;
    SendData->Mbuf->data_len = SendData->Buffer.Length;
    SendData->Mbuf->data_off = (RTE_ETHER_MAX_LEN - SendData->Buffer.Length);
    uint16_t Index = (Datapath->TxBufferOffset + Datapath->TxBufferCount) % ARRAYSIZE(Datapath->TxBufferRing);
    Datapath->TxBufferRing[Index] = SendData->Mbuf;
    Datapath->TxBufferCount++;
    CxPlatPoolFree(&Datapath->AdditionalInfoPool, SendData);
}

static
void
CxPlatDpdkDrainTx(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ uint16_t Count
    )
{
    //printf("DPDK TX %hu packet(s)\n", Count);
    struct rte_mbuf** tx_bufs = Datapath->TxBufferRing + Datapath->TxBufferOffset;
    const uint16_t nb_tx = rte_eth_tx_burst(Datapath->Port, 0, tx_bufs, Count);
    if (nb_tx < Count) printf("DPDK TX %hu packet(s) failed\n", (uint16_t)(Count - nb_tx));
    for (uint16_t buf = nb_tx; buf < Count; buf++)
        rte_pktmbuf_free(tx_bufs[buf]);
    Datapath->TxBufferOffset = (Datapath->TxBufferOffset + Count) % ARRAYSIZE(Datapath->TxBufferRing);
    Datapath->TxBufferCount -= Count;
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
        {
            struct rte_mbuf *bufs[MAX_BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(Datapath->Port, 0, bufs, MAX_BURST_SIZE);
            if (nb_rx != 0) {
                CxPlatDpdkRxEthernet(Datapath, Core, bufs, nb_rx);
            }
        }
        if (Datapath->TxBufferCount) {
            if (Datapath->TxBufferCount + Datapath->TxBufferOffset > ARRAYSIZE(Datapath->TxBufferRing)) {
                CxPlatDpdkDrainTx(Datapath, ARRAYSIZE(Datapath->TxBufferRing) - Datapath->TxBufferOffset);
            }
            CxPlatDpdkDrainTx(Datapath, Datapath->TxBufferCount);
        }
    }

    return 0;
}
