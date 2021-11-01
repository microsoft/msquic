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

#include <afxdp_helper.h>
#include <xdpapi.h>
#include <stdio.h>

#define RX_BATCH_SIZE 16
#define TX_BATCH_SIZE 16
#define MAX_ETH_FRAME_SIZE 1514

#define RX_BUFFER_TAG 'RpdX' // XdpR
#define TX_BUFFER_TAG 'TpdX' // XdpT

typedef struct XDP_DATAPATH {
    CXPLAT_DATAPATH;

    // TODO: Use better (more scalable) buffer algorithms.
    SLIST_HEADER RxPool;
    uint8_t *RxBuffers;
    HANDLE RxXsk;
    XSK_RING RxFillRing;
    XSK_RING RxRing;
    HANDLE RxProgram;
    SLIST_HEADER TxPool;
    uint8_t *TxBuffers;
    HANDLE TxXsk;
    XSK_RING TxRing;
    XSK_RING TxCompletionRing;

    BOOLEAN Running;
    CXPLAT_THREAD WorkerThread;

    // Constants
    uint16_t IfIndex;
    uint32_t DatapathCpuGroup;
    uint32_t DatapathCpuNumber;
    uint32_t RxBufferCount;
    uint32_t RxRingSize;
    uint32_t TxBufferCount;
    uint32_t TxRingSize;
} XDP_DATAPATH;

typedef struct XDP_RX_PACKET {
    CXPLAT_RECV_DATA;
    CXPLAT_TUPLE IP;
    XDP_DATAPATH* Xdp;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    XDP_DATAPATH* Xdp;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;

CXPLAT_RECV_DATA*
CxPlatDataPathRecvPacketToRecvData(
    _In_ const CXPLAT_RECV_PACKET* const Context
    )
{
    return (CXPLAT_RECV_DATA*)(((uint8_t*)Context) - sizeof(XDP_RX_PACKET));
}

CXPLAT_RECV_PACKET*
CxPlatDataPathRecvDataToRecvPacket(
    _In_ const CXPLAT_RECV_DATA* const Datagram
    )
{
    return (CXPLAT_RECV_PACKET*)(((uint8_t*)Datagram) + sizeof(XDP_RX_PACKET));
}

CXPLAT_THREAD_CALLBACK(CxPlatXdpWorkerThread, Context);

// TODO: common with DPDK and/or UDP/IP/ETH lib.
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

    Xdp->DatapathCpuGroup = 0;
    Xdp->DatapathCpuNumber = 0;
    Xdp->RxBufferCount = 4096;
    Xdp->RxRingSize = 128;
    Xdp->TxBufferCount = 4096;
    Xdp->TxRingSize = 128;

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
        } else if (strcmp(Line, "CpuGroup") == 0) {
             Xdp->DatapathCpuGroup = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "CpuNumber") == 0) {
             Xdp->DatapathCpuNumber = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "IfIndex") == 0) {
            Xdp->IfIndex = (uint16_t)strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "RxBufferCount") == 0) {
             Xdp->RxBufferCount = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "RxRingSize") == 0) {
             Xdp->RxRingSize = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxBufferCount") == 0) {
             Xdp->TxBufferCount = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxRingSize") == 0) {
             Xdp->TxRingSize = strtoul(Value, NULL, 10);
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
        0, 0, "XdpDatapathWorker", CxPlatXdpWorkerThread, Xdp
    };
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ClientRecvContextLength;
    const uint32_t RxPacketSize = ALIGN_UP(RxHeadroom + MAX_ETH_FRAME_SIZE, XDP_RX_PACKET);
    QUIC_STATUS Status;

    InitializeSListHead(&Xdp->RxPool);
    InitializeSListHead(&Xdp->TxPool);

    CxPlatXdpReadConfig(Xdp);

    //
    // RX datapath.
    //

    Xdp->RxBuffers = CxPlatAlloc(Xdp->RxBufferCount * RxPacketSize, RX_BUFFER_TAG);
    if (Xdp->RxBuffers == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status = XskCreate(&Xdp->RxXsk);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    XSK_UMEM_REG RxUmem = {0};
    RxUmem.address = Xdp->RxBuffers;
    RxUmem.chunkSize = RxPacketSize;
    RxUmem.headroom = RxHeadroom;
    RxUmem.totalSize = Xdp->RxBufferCount * RxPacketSize;

    Status = XskSetSockopt(Xdp->RxXsk, XSK_SOCKOPT_UMEM_REG, &RxUmem, sizeof(RxUmem));
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        XskSetSockopt(
            Xdp->RxXsk, XSK_SOCKOPT_RX_FILL_RING_SIZE, &Xdp->RxRingSize, sizeof(Xdp->RxRingSize));
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        XskSetSockopt(
            Xdp->RxXsk, XSK_SOCKOPT_RX_RING_SIZE, &Xdp->RxRingSize, sizeof(Xdp->RxRingSize));
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    uint32_t QueueId = 0;   // TODO: support more than one RSS queue.
    uint32_t Flags = 0;     // TODO: support native/generic forced flags.
    Status = XskBind(Xdp->RxXsk, Xdp->IfIndex, QueueId, Flags, NULL);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    XSK_RING_INFO_SET RxRingInfo;
    uint32_t RxRingInfoSize = sizeof(RxRingInfo);
    Status = XskGetSockopt(Xdp->RxXsk, XSK_SOCKOPT_RING_INFO, &RxRingInfo, &RxRingInfoSize);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    XskRingInitialize(&Xdp->RxFillRing, &RxRingInfo.fill);
    XskRingInitialize(&Xdp->RxRing, &RxRingInfo.rx);

    XDP_RULE RxRule = {
        .Match = XDP_MATCH_ALL,
        .Action = XDP_PROGRAM_ACTION_REDIRECT,
        .Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK,
        .Redirect.Target = Xdp->RxXsk,
    };

    static const XDP_HOOK_ID RxHook = {
        .Layer = XDP_HOOK_L2,
        .Direction = XDP_HOOK_RX,
        .SubLayer = XDP_HOOK_INSPECT,
    };

    Flags = 0; // TODO: support native/generic forced flags.
    Status = XdpCreateProgram(Xdp->IfIndex, &RxHook, QueueId, Flags, &RxRule, 1, &Xdp->RxProgram);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    for (uint32_t i = 0; i < Xdp->RxBufferCount; i++) {
        InterlockedPushEntrySList(&Xdp->RxPool, (PSLIST_ENTRY)&Xdp->RxBuffers[i * RxPacketSize]);
    }

    //
    // TX datapath.
    //

    Xdp->TxBuffers = CxPlatAlloc(Xdp->TxBufferCount * sizeof(XDP_TX_PACKET), TX_BUFFER_TAG);
    if (Xdp->TxBuffers == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status = XskCreate(&Xdp->TxXsk);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    XSK_UMEM_REG TxUmem = {0};
    TxUmem.address = Xdp->TxBuffers;
    TxUmem.chunkSize = sizeof(XDP_TX_PACKET);
    TxUmem.headroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
    TxUmem.totalSize = Xdp->TxBufferCount * sizeof(XDP_TX_PACKET);

    Status = XskSetSockopt(Xdp->TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        XskSetSockopt(
            Xdp->TxXsk, XSK_SOCKOPT_TX_RING_SIZE, &Xdp->TxRingSize, sizeof(Xdp->TxRingSize));
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        XskSetSockopt(
            Xdp->TxXsk, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &Xdp->TxRingSize,
            sizeof(Xdp->TxRingSize));
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Flags = 0; // TODO: support native/generic forced flags.
    Status = XskBind(Xdp->TxXsk, Xdp->IfIndex, QueueId, Flags, NULL);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    XSK_RING_INFO_SET TxRingInfo;
    uint32_t TxRingInfoSize = sizeof(TxRingInfo);
    Status = XskGetSockopt(Xdp->TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    XskRingInitialize(&Xdp->TxRing, &TxRingInfo.tx);
    XskRingInitialize(&Xdp->TxCompletionRing, &TxRingInfo.completion);

    for (uint32_t i = 0; i < Xdp->TxBufferCount; i++) {
        InterlockedPushEntrySList(
            &Xdp->TxPool, (PSLIST_ENTRY)&Xdp->TxBuffers[i * sizeof(XDP_TX_PACKET)]);
    }

    Status = CxPlatThreadCreate(&Config, &Xdp->WorkerThread);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        CxPlatDpRawUninitialize(Datapath);
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

    if (Xdp->WorkerThread != NULL) {
        Xdp->Running = FALSE;
        CxPlatThreadWait(&Xdp->WorkerThread);
        CxPlatThreadDelete(&Xdp->WorkerThread);
    }

    if (Xdp->TxXsk != NULL) {
        CloseHandle(Xdp->TxXsk);
    }

    if (Xdp->TxBuffers != NULL) {
        CxPlatFree(Xdp->TxBuffers, TX_BUFFER_TAG);
    }

    if (Xdp->RxProgram != NULL) {
        CloseHandle(Xdp->RxProgram);
    }

    if (Xdp->RxXsk != NULL) {
        CloseHandle(Xdp->RxXsk);
    }

    if (Xdp->RxBuffers != NULL) {
        CxPlatFree(Xdp->RxBuffers, RX_BUFFER_TAG);
    }
}

static
void
CxPlatXdpRx(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint16_t PartitionIndex
    )
{
    void* Buffers[RX_BATCH_SIZE];
    uint32_t RxIndex;
    uint32_t FillIndex;
    uint32_t ProdCount = 0;
    uint16_t PacketCount = 0;
    const uint16_t BuffersCount = XskRingConsumerReserve(&Xdp->RxRing, RX_BATCH_SIZE, &RxIndex);

    for (uint16_t i = 0; i < BuffersCount; i++) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Xdp->RxRing, RxIndex++);
        XDP_RX_PACKET *Packet = Xdp->RxBuffers + XskDescriptorGetAddress(Buffer->address);
        uint8_t *FrameBuffer = (uint8_t*)Packet + XskDescriptorGetOffset(Buffer->address);

        CxPlatZeroMemory(Packet, sizeof(XDP_RX_PACKET));
        Packet->Tuple = &Packet->IP;

        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Xdp,
            (CXPLAT_RECV_DATA*)&Packet,
            FrameBuffer,
            Buffer->length);

        if (Packet->Buffer) {
            Packet->Allocated = TRUE;
            Packet->PartitionIndex = PartitionIndex;
            Packet->Xdp = Xdp;
            Buffers[PacketCount++] = Packet;
        } else {
            if (XskRingProducerReserve(&Xdp->RxFillRing, 1, &FillIndex) == 1) {
                uint64_t *FillDesc = XskRingGetElement(&Xdp->RxFillRing, FillIndex);
                *FillDesc = XskDescriptorGetAddress(Buffer->address);
                ProdCount++;
            } else {
                InterlockedPushEntrySList(&Xdp->RxPool, (PSLIST_ENTRY)Packet);
            }
        }
    }

    if (BuffersCount > 0) {
        XskRingConsumerRelease(&Xdp->RxRing, BuffersCount);
    }

    uint32_t FillAvailable = XskRingProducerReserve(&Xdp->RxFillRing, MAXUINT32, &FillIndex);
    if (FillAvailable > ProdCount) {
        FillAvailable -= ProdCount;
        FillIndex += ProdCount;

        while (FillAvailable-- > 0) {
            XDP_RX_PACKET *Packet = InterlockedPopEntrySList(&Xdp->RxPool);
            if (Packet == NULL) {
                break;
            }

            uint64_t *FillDesc = XskRingGetElement(&Xdp->RxFillRing, FillIndex++);
            *FillDesc = (uint8_t*)Packet - Xdp->RxBuffers;
            ProdCount++;
        }
    }

    if (ProdCount > 0) {
        XskRingProducerSubmit(&Xdp->RxFillRing, ProdCount);
    }

    if (PacketCount > 0) {
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
        InterlockedPushEntrySList(&Packet->Xdp->RxPool, (PSLIST_ENTRY)Packet);
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
    GROUP_AFFINITY Affinity = {0};
    uint16_t PartitionIndex = 0;

    Affinity.Group = Xdp->DatapathCpuGroup;
    Affinity.Mask = AFFINITY_MASK(Xdp->DatapathCpuNumber);
    SetThreadGroupAffinity(GetCurrentThread(), &Affinity, NULL);

    while (Xdp->Running) {
        CxPlatXdpRx(Xdp, PartitionIndex);
        CxPlatXdpTx(Xdp);
    }

    return 0;
}
