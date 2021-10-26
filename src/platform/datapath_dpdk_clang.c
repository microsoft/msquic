/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC DPDK Datapath Implementation (User Mode)
    (Parts that require Clang to build)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

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

void ValueToMac(_In_z_ char* Value, _Out_ uint8_t Mac[6])
{
    uint8_t* MacPtr = Mac;
    uint8_t* End = Mac + 6;
    char* ValuePtr = Value;

    while (MacPtr < End) {
        if (*ValuePtr == '\0') {
            break;
        }

        if (*ValuePtr == ':') {
            ValuePtr++;
        }

        if (MacPtr < End) {
            *MacPtr = (uint8_t)strtoul(ValuePtr, &ValuePtr, 16);
            MacPtr++;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpdkReadConfig(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    // Default config
    const uint8_t DefaultServerMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x80 };
    CxPlatCopyMemory(Datapath->ServerMac, DefaultServerMac, 6);
    Datapath->ServerIP.si_family = AF_INET;
    Datapath->ServerIP.Ipv4.sin_addr.S_un.S_addr = 0x01FFFFFF;

    const uint8_t DefaultClientMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x59 };
    CxPlatCopyMemory(Datapath->ClientMac, DefaultClientMac, 6);
    Datapath->ClientIP.si_family = AF_INET;
    Datapath->ClientIP.Ipv4.sin_addr.S_un.S_addr = 0x02FFFFFF;

    Datapath->DpdkCpu = (uint16_t)(CxPlatProcMaxCount() - 1);

    FILE *File = fopen("dpdk.ini", "r");
    if (File == NULL) {
        return;
    }

    char Line[256];
    while (fgets(Line, sizeof(Line), File) != NULL) {
        char* Value = strchr(Line, '=');
        if (Value == NULL) {
            continue;
        }
        *Value++ = '\0';
        if (Value[strlen(Value) - 1] == '\n') {
            Value[strlen(Value) - 1] = '\0';
        }

        if (strcmp(Line, "ServerMac") == 0) {
            ValueToMac(Value, Datapath->ServerMac);
        } else if (strcmp(Line, "ClientMac") == 0) {
            ValueToMac(Value, Datapath->ClientMac);
        } else if (strcmp(Line, "ServerIP") == 0) {
             QuicAddrFromString(Value, 0, &Datapath->ServerIP);
        } else if (strcmp(Line, "ClientIP") == 0) {
             QuicAddrFromString(Value, 0, &Datapath->ClientIP);
        } else if (strcmp(Line, "CPU") == 0) {
             Datapath->DpdkCpu = (uint16_t)strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "DeviceName") == 0) {
             strcpy(Datapath->DeviceName, Value);
        }
    }

    fclose(File);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpdkInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath
    )
{
    CXPLAT_THREAD_CONFIG Config = {
        0, 0, "DpdkMain", CxPlatDpdkMainThread, Datapath
    };

    CxPlatDpdkReadConfig(Datapath);

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

    char DpdpCpuStr[16];
    sprintf(DpdpCpuStr, "%hu", Datapath->DpdkCpu);

    const char* argv[] = {
        "msquic",
        "-n", "4",
        "-l", DpdpCpuStr,
        "-d", "rte_mempool_ring-21.dll",
        "-d", "rte_bus_pci-21.dll",
        "-d", "rte_common_mlx5-21.dll",
        "-d", "rte_net_mlx5-21.dll"
    };

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

    if (Datapath->DeviceName[0] != '\0') {
        ret = rte_eth_dev_get_port_by_name(Datapath->DeviceName, &Port);
    } else {
        ret = rte_eth_dev_get_port_by_name("0000:81:00.0", &Port);
        if (ret < 0) {
            ret = rte_eth_dev_get_port_by_name("0000:81:00.1", &Port);
        }
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

    Datapath->TxRingBuffer =
        rte_ring_create(
            "TxRing", TX_RING_SIZE, rte_eth_dev_socket_id(Port),
            RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
    if (Datapath->TxRingBuffer == NULL) {
        printf("rte_ring_create failed: %d\n", ret);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_ring_create");
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

    if (DeviceInfo.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) {
        printf("TX IPv4 Checksum Offload Enabled\n");
        PortConfig.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
    }
    if (DeviceInfo.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) {
        printf("TX UDP Checksum Offload Enabled\n");
        PortConfig.txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
    }
    if (DeviceInfo.rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) {
        printf("RX IPv4 Checksum Offload Enabled\n");
        PortConfig.rxmode.offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;
    }
    if (DeviceInfo.rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) {
        printf("RX UDP Checksum Offload Enabled\n");
        PortConfig.rxmode.offloads |= DEV_RX_OFFLOAD_UDP_CKSUM;
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

    printf("\nStarting Port %hu, MAC: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
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

    if (Datapath->TxRingBuffer) {
        rte_ring_free(Datapath->TxRingBuffer);
    }

    if (Datapath->MemoryPool) {
        rte_mempool_free(Datapath->MemoryPool);
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
    _In_ const uint16_t Core
    )
{
    struct rte_mbuf* Buffers[RX_BURST_SIZE];
    const uint16_t BuffersCount =
        rte_eth_rx_burst(Datapath->Port, 0, Buffers, RX_BURST_SIZE);
    if (BuffersCount == 0) {
        return;
    }

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
                NewPacket->Tuple = &NewPacket->IP;
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
        PacketChain = (DPDK_RX_PACKET*)PacketChain->Next;
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
            //printf("DPDK TX alloc packet (len=%hu)\n", MaxPacketSize);
            SendData->Datapath = Datapath;
            SendData->Buffer.Length = MaxPacketSize;
            SendData->Mbuf->data_off = 0;
            SendData->Buffer.Buffer =
                ((uint8_t*)SendData->Mbuf->buf_addr) + 42; // Ethernet,IPv4,UDP
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
    SendData->Mbuf->data_len = (uint16_t)SendData->Buffer.Length;
    SendData->Mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    SendData->Mbuf->l2_len = 14;
    SendData->Mbuf->l3_len = 20;
    //printf("DPDK TX queue packet (len=%hu, off=%hu)\n", SendData->Mbuf->data_len, SendData->Mbuf->data_off);

    CXPLAT_DATAPATH* Datapath = SendData->Datapath;
    if (rte_ring_mp_enqueue(Datapath->TxRingBuffer, SendData->Mbuf) != 0) {
        printf("DPDK TX drop packet (no room)\n");
        rte_pktmbuf_free(SendData->Mbuf);
    }

    CxPlatPoolFree(&Datapath->AdditionalInfoPool, SendData);
}

static
void
CxPlatDpdkTxEthernet(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    struct rte_mbuf* Buffers[TX_BURST_SIZE];
    uint32_t Available = 0;
    do {
        uint16_t BufferCount =
            (uint16_t)rte_ring_sc_dequeue_burst(
                Datapath->TxRingBuffer, (void**)Buffers, TX_BURST_SIZE, &Available);
        if (!BufferCount) return;

        const uint16_t TxCount = rte_eth_tx_burst(Datapath->Port, 0, Buffers, BufferCount);
        for (uint16_t buf = TxCount; buf < BufferCount; buf++) {
            rte_pktmbuf_free(Buffers[buf]);
        }
    } while (Available);
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
        rte_eth_dev_socket_id(Datapath->Port) != (int)rte_socket_id()) {
        printf("\nWARNING, port %u is on remote NUMA node to  polling thread.\n"
               "\tPerformance will not be optimal.\n\n",
               Datapath->Port);
    }

    while (Datapath->Running) {
        CxPlatDpdkRxEthernet(Datapath, Core);
        CxPlatDpdkTxEthernet(Datapath);
    }

    return 0;
}
