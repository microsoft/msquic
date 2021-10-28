/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw.h"
#ifdef QUIC_CLOG
#include "datapath_raw_xdp.c.clog.h"
#endif

#include <msxdp.h>
#include <stdio.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RX_BURST_SIZE 16
#define TX_BURST_SIZE 16
#define TX_RING_SIZE 1024

typedef struct XDP_DATAPATH {

    CXPLAT_DATAPATH;

    BOOLEAN Running;
    CXPLAT_THREAD XdpThread;
    QUIC_STATUS StartStatus;
    CXPLAT_EVENT StartComplete;

    CXPLAT_POOL AdditionalInfoPool;

    uint16_t Port;
    CXPLAT_LOCK TxLock;
    struct rte_mempool* MemoryPool;
    struct rte_ring* TxRingBuffer;

    // Constants
    uint16_t XdpCpu;
    char DeviceName[32];

} XDP_DATAPATH;

typedef struct XDP_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_TUPLE IP;
    struct rte_mbuf* Mbuf;
    CXPLAT_POOL* OwnerPool;
} XDP_RX_PACKET;

typedef struct XDP_TX_PACKET {

    CXPLAT_SEND_DATA;
    struct rte_mbuf* Mbuf;
    XDP_DATAPATH* Xdp;

} XDP_TX_PACKET;

CXPLAT_STATIC_ASSERT(
    sizeof(XDP_TX_PACKET) <= sizeof(XDP_RX_PACKET),
    "Code assumes memory allocated for RX is enough for TX");

CXPLAT_THREAD_CALLBACK(CxPlatXdpMainThread, Context);
static int CxPlatXdpWorkerThread(_In_ void* Context);

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
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    // Default config
    const uint8_t DefaultServerMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x80 };
    CxPlatCopyMemory(Xdp->ServerMac, DefaultServerMac, 6);
    Xdp->ServerIP.si_family = AF_INET;
    Xdp->ServerIP.Ipv4.sin_addr.S_un.S_addr = 0x01FFFFFF;

    const uint8_t DefaultClientMac[] = { 0x04, 0x3f, 0x72, 0xd8, 0x20, 0x59 };
    CxPlatCopyMemory(Xdp->ClientMac, DefaultClientMac, 6);
    Xdp->ClientIP.si_family = AF_INET;
    Xdp->ClientIP.Ipv4.sin_addr.S_un.S_addr = 0x02FFFFFF;

    Xdp->XdpCpu = (uint16_t)(CxPlatProcMaxCount() - 1);

    FILE *File = fopen("xdp.ini", "r");
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
            ValueToMac(Value, Xdp->ServerMac);
        } else if (strcmp(Line, "ClientMac") == 0) {
            ValueToMac(Value, Xdp->ClientMac);
        } else if (strcmp(Line, "ServerIP") == 0) {
             QuicAddrFromString(Value, 0, &Xdp->ServerIP);
        } else if (strcmp(Line, "ClientIP") == 0) {
             QuicAddrFromString(Value, 0, &Xdp->ClientIP);
        } else if (strcmp(Line, "CPU") == 0) {
             Xdp->XdpCpu = (uint16_t)strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "DeviceName") == 0) {
             strcpy(Xdp->DeviceName, Value);
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
    return sizeof(XDP_DATAPATH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH* Datapath,
    _In_ uint32_t ClientRecvContextLength
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    CXPLAT_THREAD_CONFIG Config = {
        0, 0, "XdpMain", CxPlatXdpMainThread, Xdp
    };
    const uint32_t AdditionalBufferSize =
        sizeof(CXPLAT_RECV_DATA) + ClientRecvContextLength;

    CxPlatXdpReadConfig(Xdp);

    BOOLEAN CleanUpThread = FALSE;
    CxPlatEventInitialize(&Xdp->StartComplete, TRUE, FALSE);
    CxPlatPoolInitialize(FALSE, AdditionalBufferSize, QUIC_POOL_DATAPATH, &Xdp->AdditionalInfoPool);
    CxPlatLockInitialize(&Xdp->TxLock);

    //
    // This starts a new thread to do all the XDP initialization because XDP
    // effectively takes that thread over. It waits for the initialization part
    // to complete before returning. After that, the Xdp main thread starts
    // running the Xdp main loop until clean up.
    //

    QUIC_STATUS Status = CxPlatThreadCreate(&Config, &Xdp->XdpThread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }
    CleanUpThread = TRUE;

    CxPlatEventWaitForever(Xdp->StartComplete);
    Status = Xdp->StartStatus;

Error:

    if (QUIC_FAILED(Status)) {
        if (CleanUpThread) {
            CxPlatLockUninitialize(&Xdp->TxLock);
            CxPlatPoolUninitialize(&Xdp->AdditionalInfoPool);
            CxPlatThreadWait(&Xdp->XdpThread);
            CxPlatThreadDelete(&Xdp->XdpThread);
        }
        CxPlatEventUninitialize(Xdp->StartComplete);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    Xdp->Running = FALSE;
    CxPlatLockUninitialize(&Xdp->TxLock);
    CxPlatPoolUninitialize(&Xdp->AdditionalInfoPool);
    CxPlatThreadWait(&Xdp->XdpThread);
    CxPlatThreadDelete(&Xdp->XdpThread);
    CxPlatEventUninitialize(Xdp->StartComplete);
}

CXPLAT_THREAD_CALLBACK(CxPlatXdpMainThread, Context)
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Context;

    char DpdpCpuStr[16];
    sprintf(DpdpCpuStr, "%hu", Xdp->XdpCpu);

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

    if (Xdp->DeviceName[0] != '\0') {
        ret = rte_eth_dev_get_port_by_name(Xdp->DeviceName, &Port);
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
    Xdp->Port = Port;

    Xdp->MemoryPool =
        rte_pktmbuf_pool_create(
            "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, rte_eth_dev_socket_id(Port));
    if (Xdp->MemoryPool == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            0,
            "rte_pktmbuf_pool_create");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Xdp->TxRingBuffer =
        rte_ring_create(
            "TxRing", TX_RING_SIZE, rte_eth_dev_socket_id(Port),
            RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);
    if (Xdp->TxRingBuffer == NULL) {
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
        ret = rte_eth_rx_queue_setup(Port, q, nb_rxd, rte_eth_dev_socket_id(Port), &rxconf, Xdp->MemoryPool);
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

    printf("\nStarting Port %hu, MAC: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
            Xdp->Port,
            addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
            addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    Xdp->Running = TRUE;
    ret = rte_eal_mp_remote_launch(CxPlatXdpWorkerThread, Xdp, SKIP_MAIN);
    if (ret < 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ret,
            "rte_eal_mp_remote_launch");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    Xdp->StartStatus = Status;
    CxPlatEventSet(Xdp->StartComplete);

    CxPlatXdpWorkerThread(Xdp);

    rte_eal_mp_wait_lcore(); // Wait on the other cores/threads

Error:

    if (QUIC_FAILED(Status)) {
        Xdp->StartStatus = Status;
        CxPlatEventSet(Xdp->StartComplete);
    }

    if (Xdp->TxRingBuffer) {
        rte_ring_free(Xdp->TxRingBuffer);
    }

    if (Xdp->MemoryPool) {
        rte_mempool_free(Xdp->MemoryPool);
    }

    if (CleanUpRte) {
        rte_eal_cleanup();
    }

    CXPLAT_THREAD_RETURN(0);
}

static
void
CxPlatXdpRx(
    _In_ XDP_DATAPATH* Xdp,
    _In_ const uint16_t Core
    )
{
    void* Buffers[RX_BURST_SIZE];
    const uint16_t BuffersCount =
        rte_eth_rx_burst(Xdp->Port, 0, (struct rte_mbuf**)Buffers, RX_BURST_SIZE);
    if (unlikely(BuffersCount == 0)) {
        return;
    }

    XDP_RX_PACKET Packet; // Working space
    CxPlatZeroMemory(&Packet, sizeof(XDP_RX_PACKET));
    Packet.Tuple = &Packet.IP;

    uint16_t PacketCount = 0;
    for (uint16_t i = 0; i < BuffersCount; i++) {
        struct rte_mbuf* Buffer = (struct rte_mbuf*)Buffers[i];
        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Xdp,
            (CXPLAT_RECV_DATA*)&Packet,
            ((uint8_t*)Buffer->buf_addr) + Buffer->data_off,
            Buffer->pkt_len);

        XDP_RX_PACKET* NewPacket;
        if (likely(Packet.Buffer && (NewPacket = CxPlatPoolAlloc(&Xdp->AdditionalInfoPool)) != NULL)) {
            CxPlatCopyMemory(NewPacket, &Packet, sizeof(XDP_RX_PACKET));
            NewPacket->Allocated = TRUE;
            NewPacket->PartitionIndex = Core;
            NewPacket->Mbuf = Buffer;
            NewPacket->OwnerPool = &Xdp->AdditionalInfoPool;
            NewPacket->Tuple = &NewPacket->IP;
            Buffers[PacketCount++] = NewPacket;
        } else {
            rte_pktmbuf_free(Buffer);
        }
    }

    if (likely(PacketCount)) {
        CxPlatDpRawRxEthernet((CXPLAT_DATAPATH*)Xdp, (CXPLAT_RECV_DATA**)Buffers, PacketCount);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    while (PacketChain) {
        const XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)PacketChain;
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
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    XDP_TX_PACKET* Packet = CxPlatPoolAlloc(&Xdp->AdditionalInfoPool);
    if (likely(Packet)) {
        Packet->Mbuf = rte_pktmbuf_alloc(Xdp->MemoryPool);
        if (likely(Packet->Mbuf)) {
            Packet->Xdp = Xdp;
            Packet->Buffer.Length = MaxPacketSize;
            Packet->Mbuf->data_off = 0;
            Packet->Buffer.Buffer =
                ((uint8_t*)Packet->Mbuf->buf_addr) + 42; // Ethernet,IPv4,UDP
        } else {
            CxPlatPoolFree(&Xdp->AdditionalInfoPool, Packet);
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
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    rte_pktmbuf_free(Packet->Mbuf);
    CxPlatPoolFree(&Packet->Xdp->AdditionalInfoPool, SendData);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    Packet->Mbuf->data_len = (uint16_t)Packet->Buffer.Length;
    Packet->Mbuf->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
    Packet->Mbuf->l2_len = 14;
    Packet->Mbuf->l3_len = 20;

    XDP_DATAPATH* Xdp = Packet->Xdp;
    if (unlikely(rte_ring_mp_enqueue(Xdp->TxRingBuffer, Packet->Mbuf) != 0)) {
        rte_pktmbuf_free(Packet->Mbuf);
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No room in Xdp TX ring buffer");
    }

    CxPlatPoolFree(&Xdp->AdditionalInfoPool, Packet);
}

static
void
CxPlatXdpTx(
    _In_ XDP_DATAPATH* Xdp
    )
{
    struct rte_mbuf* Buffers[TX_BURST_SIZE];
    const uint16_t BufferCount =
        (uint16_t)rte_ring_sc_dequeue_burst(
            Xdp->TxRingBuffer, (void**)Buffers, TX_BURST_SIZE, NULL);
    if (unlikely(BufferCount == 0)) {
        return;
    }

    const uint16_t TxCount = rte_eth_tx_burst(Xdp->Port, 0, Buffers, BufferCount);
    if (unlikely(TxCount < BufferCount)) {
        for (uint16_t buf = TxCount; buf < BufferCount; buf++) {
            rte_pktmbuf_free(Buffers[buf]);
        }
    }
}

static
int
CxPlatXdpWorkerThread(
    _In_ void* Context
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Context;
    const uint16_t Core = (uint16_t)rte_lcore_id();

    printf("Core %u worker running...\n", Core);
    if (rte_eth_dev_socket_id(Xdp->Port) > 0 &&
        rte_eth_dev_socket_id(Xdp->Port) != (int)rte_socket_id()) {
        printf("\nWARNING, port %u is on remote NUMA node to polling thread.\n"
               "\tPerformance will not be optimal.\n\n",
               Xdp->Port);
    }

    while (likely(Xdp->Running)) {
        CxPlatXdpRx(Xdp, Core);
        CxPlatXdpTx(Xdp);
    }

    return 0;
}
