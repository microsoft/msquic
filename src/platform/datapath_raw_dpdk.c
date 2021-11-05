/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC DPDK Datapath Implementation (User Mode)

    - Requires Clang to build
    - Leverages Mellanox PMD (requires CX4 or CX5)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw_dpdk.c.clog.h"
#endif

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_BURST_SIZE 16
#define TX_BURST_SIZE 16
#define TX_RING_SIZE 1024

typedef struct DPDK_DATAPATH {

    CXPLAT_DATAPATH;

    BOOLEAN Running;
    CXPLAT_THREAD DpdkThread;
    QUIC_STATUS StartStatus;
    CXPLAT_EVENT StartComplete;

    CXPLAT_POOL AdditionalInfoPool;

    uint16_t Port;
    CXPLAT_LOCK TxLock;
    struct rte_mempool* MemoryPool;
    struct rte_ring* TxRingBuffer;

    // Constants
    char DeviceName[32];

} DPDK_DATAPATH;

typedef struct DPDK_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_TUPLE IP;
    struct rte_mbuf* Mbuf;
    CXPLAT_POOL* OwnerPool;
} DPDK_RX_PACKET;

typedef struct DPDK_TX_PACKET {
    CXPLAT_SEND_DATA;
    struct rte_mbuf* Mbuf;
    DPDK_DATAPATH* Dpdk;
} DPDK_TX_PACKET;

CXPLAT_STATIC_ASSERT(
    sizeof(DPDK_TX_PACKET) <= sizeof(DPDK_RX_PACKET),
    "Code assumes memory allocated for RX is enough for TX");

CXPLAT_THREAD_CALLBACK(CxPlatDpdkMainThread, Context);
static int CxPlatDpdkWorkerThread(_In_ void* Context);

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(DPDK_RX_PACKET));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(DPDK_RX_PACKET));
}

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
    _Inout_ DPDK_DATAPATH* Dpdk
    )
{
    // Default config
    const uint8_t DefaultServerMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x80 };
    CxPlatCopyMemory(Dpdk->ServerMac, DefaultServerMac, 6);
    Dpdk->ServerIP.si_family = AF_INET;
    Dpdk->ServerIP.Ipv4.sin_addr.S_un.S_addr = 0x01FFFFFF;

    const uint8_t DefaultClientMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x59 };
    CxPlatCopyMemory(Dpdk->ClientMac, DefaultClientMac, 6);
    Dpdk->ClientIP.si_family = AF_INET;
    Dpdk->ClientIP.Ipv4.sin_addr.S_un.S_addr = 0x02FFFFFF;

    Dpdk->Cpu = (uint16_t)(CxPlatProcMaxCount() - 1);

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
            ValueToMac(Value, Dpdk->ServerMac);
        } else if (strcmp(Line, "ClientMac") == 0) {
            ValueToMac(Value, Dpdk->ClientMac);
        } else if (strcmp(Line, "ServerIP") == 0) {
             QuicAddrFromString(Value, 0, &Dpdk->ServerIP);
        } else if (strcmp(Line, "ClientIP") == 0) {
             QuicAddrFromString(Value, 0, &Dpdk->ClientIP);
        } else if (strcmp(Line, "CPU") == 0) {
             Dpdk->Cpu = (uint16_t)strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "DeviceName") == 0) {
             strcpy(Dpdk->DeviceName, Value);
        }
    }

    fclose(File);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDapathSize(
    void
    )
{
    return sizeof(DPDK_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength
    )
{
    DPDK_DATAPATH* Dpdk = (DPDK_DATAPATH*)Datapath;
    CXPLAT_THREAD_CONFIG Config = {
        0, 0, "DpdkMain", CxPlatDpdkMainThread, Dpdk
    };
    const uint32_t AdditionalBufferSize =
        sizeof(DPDK_RX_PACKET) + ClientRecvContextLength;

    CxPlatDpdkReadConfig(Dpdk);
    CxPlatDpRawGenerateCpuTable(Datapath);

    BOOLEAN CleanUpThread = FALSE;
    CxPlatEventInitialize(&Dpdk->StartComplete, TRUE, FALSE);
    CxPlatPoolInitialize(FALSE, AdditionalBufferSize, QUIC_POOL_DATAPATH, &Dpdk->AdditionalInfoPool);
    CxPlatLockInitialize(&Dpdk->TxLock);

    //
    // This starts a new thread to do all the DPDK initialization because DPDK
    // effectively takes that thread over. It waits for the initialization part
    // to complete before returning. After that, the DPDK main thread starts
    // running the DPDK main loop until clean up.
    //

    QUIC_STATUS Status = CxPlatThreadCreate(&Config, &Dpdk->DpdkThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }
    CleanUpThread = TRUE;

    CxPlatEventWaitForever(Dpdk->StartComplete);
    Status = Dpdk->StartStatus;

Error:

    if (QUIC_FAILED(Status)) {
        if (CleanUpThread) {
            CxPlatLockUninitialize(&Dpdk->TxLock);
            CxPlatPoolUninitialize(&Dpdk->AdditionalInfoPool);
            CxPlatThreadWait(&Dpdk->DpdkThread);
            CxPlatThreadDelete(&Dpdk->DpdkThread);
        }
        CxPlatEventUninitialize(Dpdk->StartComplete);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    DPDK_DATAPATH* Dpdk = (DPDK_DATAPATH*)Datapath;
    Dpdk->Running = FALSE;
    CxPlatLockUninitialize(&Dpdk->TxLock);
    CxPlatPoolUninitialize(&Dpdk->AdditionalInfoPool);
    CxPlatThreadWait(&Dpdk->DpdkThread);
    CxPlatThreadDelete(&Dpdk->DpdkThread);
    CxPlatEventUninitialize(Dpdk->StartComplete);
}

CXPLAT_THREAD_CALLBACK(CxPlatDpdkMainThread, Context)
{
    DPDK_DATAPATH* Dpdk = (DPDK_DATAPATH*)Context;

    char DpdpCpuStr[16];
    sprintf(DpdpCpuStr, "%hu", Dpdk->Cpu);

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
    uint16_t Port;
    struct rte_eth_conf PortConfig = {
        .rxmode = {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
    };
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    const uint16_t rx_rings = 1, tx_rings = 1;
    struct rte_eth_dev_info DeviceInfo;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    struct rte_ether_addr addr;

    int ret = rte_eal_init(ARRAYSIZE(argv), (char**)argv);
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

    if (Dpdk->DeviceName[0] != '\0') {
        ret = rte_eth_dev_get_port_by_name(Dpdk->DeviceName, &Port);
    } else {
        ret = rte_eth_dev_get_port_by_name("0000:81:00.0", &Port);
        if (ret < 0) {
            ret = rte_eth_dev_get_port_by_name("0000:81:00.1", &Port);
        }
    }
    if (ret < 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_dev_get_port_by_name");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }
    Dpdk->Port = Port;

    Dpdk->MemoryPool =
        rte_pktmbuf_pool_create(
            "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, rte_eth_dev_socket_id(Port));
    if (Dpdk->MemoryPool == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            0,
            "rte_pktmbuf_pool_create");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Dpdk->TxRingBuffer =
        rte_ring_create(
            "TxRing", TX_RING_SIZE, rte_eth_dev_socket_id(Port),
            RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
    if (Dpdk->TxRingBuffer == NULL) {
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
        ret = rte_eth_rx_queue_setup(Port, q, nb_rxd, rte_eth_dev_socket_id(Port), &rxconf, Dpdk->MemoryPool);
        if (ret < 0) {
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
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eth_macaddr_get");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    printf("\nStarting Port %hu, %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
            Dpdk->Port,
            addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
            addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    Dpdk->Running = TRUE;
    ret = rte_eal_mp_remote_launch(CxPlatDpdkWorkerThread, Dpdk, SKIP_MAIN);
    if (ret < 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eal_mp_remote_launch");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Dpdk->StartStatus = Status;
    CxPlatEventSet(Dpdk->StartComplete);

    CxPlatDpdkWorkerThread(Dpdk);

    rte_eal_mp_wait_lcore(); // Wait on the other cores/threads

Error:

    if (QUIC_FAILED(Status)) {
        Dpdk->StartStatus = Status;
        CxPlatEventSet(Dpdk->StartComplete);
    }

    if (Dpdk->TxRingBuffer) {
        rte_ring_free(Dpdk->TxRingBuffer);
    }

    if (Dpdk->MemoryPool) {
        rte_mempool_free(Dpdk->MemoryPool);
    }

    if (CleanUpRte) {
        rte_eal_cleanup();
    }

    CXPLAT_THREAD_RETURN(0);
}

static
void
CxPlatDpdkRx(
    _In_ DPDK_DATAPATH* Dpdk,
    _In_ const uint16_t Core
    )
{
    void* Buffers[RX_BURST_SIZE];
    const uint16_t BuffersCount =
        rte_eth_rx_burst(Dpdk->Port, 0, (struct rte_mbuf**)Buffers, RX_BURST_SIZE);
    if (unlikely(BuffersCount == 0)) {
        return;
    }

    DPDK_RX_PACKET Packet; // Working space
    CxPlatZeroMemory(&Packet, sizeof(DPDK_RX_PACKET));
    Packet.Tuple = &Packet.IP;

    uint16_t PacketCount = 0;
    for (uint16_t i = 0; i < BuffersCount; i++) {
        struct rte_mbuf* Buffer = (struct rte_mbuf*)Buffers[i];
        Packet.Buffer = NULL;
        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Dpdk,
            (CXPLAT_RECV_DATA*)&Packet,
            ((uint8_t*)Buffer->buf_addr) + Buffer->data_off,
            Buffer->pkt_len);

        DPDK_RX_PACKET* NewPacket;
        if (likely(Packet.Buffer && (NewPacket = CxPlatPoolAlloc(&Dpdk->AdditionalInfoPool)) != NULL)) {
            CxPlatCopyMemory(NewPacket, &Packet, sizeof(DPDK_RX_PACKET));
            NewPacket->Allocated = TRUE;
            NewPacket->Mbuf = Buffer;
            NewPacket->OwnerPool = &Dpdk->AdditionalInfoPool;
            NewPacket->Tuple = &NewPacket->IP;
            Buffers[PacketCount++] = NewPacket;
        } else {
            rte_pktmbuf_free(Buffer);
        }
    }

    if (likely(PacketCount)) {
        CxPlatDpRawRxEthernet((CXPLAT_DATAPATH*)Dpdk, (CXPLAT_RECV_DATA**)Buffers, PacketCount);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    while (PacketChain) {
        const DPDK_RX_PACKET* Packet = (DPDK_RX_PACKET*)PacketChain;
        PacketChain = PacketChain->Next;
        rte_pktmbuf_free(Packet->Mbuf);
        CxPlatPoolFree(Packet->OwnerPool, (void*)Packet);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ CXPLAT_ECN_TYPE ECN, // unused currently
    _In_ uint16_t MaxPacketSize
    )
{
    DPDK_DATAPATH* Dpdk = (DPDK_DATAPATH*)Datapath;
    DPDK_TX_PACKET* Packet = CxPlatPoolAlloc(&Dpdk->AdditionalInfoPool);
    if (likely(Packet)) {
        Packet->Mbuf = rte_pktmbuf_alloc(Dpdk->MemoryPool);
        if (likely(Packet->Mbuf)) {
            Packet->Dpdk = Dpdk;
            Packet->Buffer.Length = MaxPacketSize;
            Packet->Mbuf->data_off = 0;
            Packet->Buffer.Buffer =
                ((uint8_t*)Packet->Mbuf->buf_addr) + 42; // Ethernet,IPv4,UDP
        } else {
            CxPlatPoolFree(&Dpdk->AdditionalInfoPool, Packet);
            Packet = NULL;
        }
    }
    return (CXPLAT_SEND_DATA*)Packet;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxFree(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    DPDK_TX_PACKET* Packet = (DPDK_TX_PACKET*)SendData;
    rte_pktmbuf_free(Packet->Mbuf);
    CxPlatPoolFree(&Packet->Dpdk->AdditionalInfoPool, SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    DPDK_TX_PACKET* Packet = (DPDK_TX_PACKET*)SendData;
    Packet->Mbuf->data_len = (uint16_t)Packet->Buffer.Length;
    Packet->Mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    Packet->Mbuf->l2_len = 14;
    Packet->Mbuf->l3_len = 20;

    DPDK_DATAPATH* Dpdk = Packet->Dpdk;
    if (unlikely(rte_ring_mp_enqueue(Dpdk->TxRingBuffer, Packet->Mbuf) != 0)) {
        rte_pktmbuf_free(Packet->Mbuf);
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No room in DPDK TX ring buffer");
    }

    CxPlatPoolFree(&Dpdk->AdditionalInfoPool, Packet);
}

static
void
CxPlatDpdkTx(
    _In_ DPDK_DATAPATH* Dpdk
    )
{
    struct rte_mbuf* Buffers[TX_BURST_SIZE];
    const uint16_t BufferCount =
        (uint16_t)rte_ring_sc_dequeue_burst(
            Dpdk->TxRingBuffer, (void**)Buffers, TX_BURST_SIZE, NULL);
    if (unlikely(BufferCount == 0)) {
        return;
    }

    const uint16_t TxCount = rte_eth_tx_burst(Dpdk->Port, 0, Buffers, BufferCount);
    if (unlikely(TxCount < BufferCount)) {
        for (uint16_t buf = TxCount; buf < BufferCount; buf++) {
            rte_pktmbuf_free(Buffers[buf]);
        }
    }
}

static
int
CxPlatDpdkWorkerThread(
    _In_ void* Context
    )
{
    DPDK_DATAPATH* Dpdk = (DPDK_DATAPATH*)Context;
    const uint16_t Core = (uint16_t)rte_lcore_id();

    printf("Core %u worker running...\n", Core);
    if (rte_eth_dev_socket_id(Dpdk->Port) > 0 &&
        rte_eth_dev_socket_id(Dpdk->Port) != (int)rte_socket_id()) {
        printf("\nWARNING, port %u is on remote NUMA node to polling thread.\n"
               "\tPerformance will not be optimal.\n\n",
               Dpdk->Port);
    }

#ifdef QUIC_USE_EXECUTION_CONTEXTS
    const CXPLAT_THREAD_ID ThreadID = CxPlatCurThreadID();
#endif

    while (likely(Dpdk->Running)) {
        CxPlatDpdkRx(Dpdk, Core);
        CxPlatDpdkTx(Dpdk);

#ifdef QUIC_USE_EXECUTION_CONTEXTS
        (void)CxPlatRunExecutionContexts(ThreadID);
#endif
    }

#ifdef QUIC_USE_EXECUTION_CONTEXTS
    while (CxPlatRunExecutionContexts(ThreadID)) {
        // no-op
    }
#endif

    return 0;
}
