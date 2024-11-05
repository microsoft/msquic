/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_win.h"
#include "datapath_raw_xdp.h"
#include <wbemidl.h>
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <xdpapi_experimental.h>
#include <stdio.h>

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_win.c.clog.h"
#endif

#define XDP_MAX_SYNC_WAIT_TIMEOUT_MS 1000 // Used for querying XDP RSS capabilities.

typedef struct XDP_DATAPATH {
    CXPLAT_DATAPATH_RAW;
    DECLSPEC_CACHEALIGN

    //
    // Currently, all XDP interfaces share the same config.
    //
    CXPLAT_REF_COUNT RefCount;
    uint32_t PartitionCount;
    uint32_t RxBufferCount;
    uint32_t RxRingSize;
    uint32_t TxBufferCount;
    uint32_t TxRingSize;
    uint32_t PollingIdleTimeoutUs;
    BOOLEAN TxAlwaysPoke;
    BOOLEAN SkipXsum;
    BOOLEAN Running;        // Signal to stop partitions.
    XDP_LOAD_API_CONTEXT XdpApiLoadContext;
    const XDP_API_TABLE *XdpApi;
    XDP_QEO_SET_FN *XdpQeoSet;

    XDP_PARTITION Partitions[0];
} XDP_DATAPATH;

typedef struct XDP_INTERFACE {
    XDP_INTERFACE_COMMON;
    HANDLE XdpHandle;
    uint8_t RuleCount;
    CXPLAT_LOCK RuleLock;
    XDP_RULE* Rules;
} XDP_INTERFACE;

typedef struct XDP_QUEUE {
    XDP_QUEUE_COMMON;
    uint16_t RssProcessor;
    uint8_t* RxBuffers;
    HANDLE RxXsk;
    DATAPATH_XDP_IO_SQE RxIoSqe;
    XSK_RING RxFillRing;
    XSK_RING RxRing;
    HANDLE RxProgram;
    uint8_t* TxBuffers;
    HANDLE TxXsk;
    DATAPATH_XDP_IO_SQE TxIoSqe;
    XSK_RING TxRing;
    XSK_RING TxCompletionRing;

    CXPLAT_LIST_ENTRY PartitionTxQueue;
    CXPLAT_SLIST_ENTRY PartitionRxPool;

    // Move contended buffer pools to their own cache lines.
    // TODO: Use better (more scalable) buffer algorithms.
    DECLSPEC_CACHEALIGN SLIST_HEADER RxPool;
    DECLSPEC_CACHEALIGN SLIST_HEADER TxPool;

    // Move TX queue to its own cache line.
    DECLSPEC_CACHEALIGN
    CXPLAT_LOCK TxLock;
    CXPLAT_LIST_ENTRY TxQueue;
} XDP_QUEUE;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_RX_PACKET {
    // N.B. This struct is also put in a SLIST, so it must be aligned.
    XDP_QUEUE* Queue;
    CXPLAT_ROUTE RouteStorage;
    CXPLAT_RECV_DATA RecvData;
    // Followed by:
    // uint8_t ClientContext[...];
    // uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_RX_PACKET;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) XDP_TX_PACKET {
    CXPLAT_SEND_DATA;
    XDP_QUEUE* Queue;
    CXPLAT_LIST_ENTRY Link;
    uint8_t FrameBuffer[MAX_ETH_FRAME_SIZE];
} XDP_TX_PACKET;

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

void
CreateNoOpEthernetPacket(
    _Inout_ XDP_TX_PACKET* Packet
    )
{
    ETHERNET_HEADER* Ethernet = (ETHERNET_HEADER*)Packet->FrameBuffer;
    IPV4_HEADER* IPv4 = (IPV4_HEADER*)(Ethernet + 1);
    UDP_HEADER* UDP = (UDP_HEADER*)(IPv4 + 1);

    // Set Ethernet header
    memset(Ethernet->Destination, 0xFF, sizeof(Ethernet->Destination)); // Broadcast address
    memset(Ethernet->Source, 0x00, sizeof(Ethernet->Source)); // Source MAC address
    Ethernet->Type = htons(0x0800); // IPv4

    // Set IPv4 header
    IPv4->VersionAndHeaderLength = 0x45; // Version 4, Header length 20 bytes
    IPv4->TypeOfService = 0;
    IPv4->TotalLength = htons(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER));
    IPv4->Identification = 0;
    IPv4->FlagsAndFragmentOffset = 0;
    IPv4->TimeToLive = 64;
    IPv4->Protocol = 17; // UDP
    IPv4->HeaderChecksum = 0; // Will be calculated later
    *(uint32_t*)IPv4->Source = htonl(0xC0A80001); // 192.168.0.1
    *(uint32_t*)IPv4->Destination = htonl(0xC0A80002); // 192.168.0.2

    // Set UDP header
    UDP->SourcePort = htons(12345);
    UDP->DestinationPort = htons(80);
    UDP->Length = htons(sizeof(UDP_HEADER));
    UDP->Checksum = 0; // Optional for IPv4

    // Calculate IPv4 header checksum
    uint32_t sum = 0;
    uint16_t* header = (uint16_t*)IPv4;
    for (int i = 0; i < sizeof(IPV4_HEADER) / 2; ++i) {
        sum += header[i];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    IPv4->HeaderChecksum = (uint16_t)~sum;

    // Set packet length
    Packet->Buffer.Length = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER);
}

QUIC_STATUS
CxPlatGetRssQueueProcessors(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t InterfaceIndex,
    _Inout_ uint16_t* Count,
    _Out_writes_to_(*Count, *Count) uint32_t* Queues
    )
{
    uint32_t TxRingSize = 1;
    XDP_TX_PACKET TxPacket = { 0 };
    CreateNoOpEthernetPacket(&TxPacket);

    for (uint16_t i = 0; i < *Count; ++i) {
        HANDLE TxXsk = NULL;
        QUIC_STATUS Status = Xdp->XdpApi->XskCreate(&TxXsk);
        if (QUIC_FAILED(Status)) { return Status; }

        XSK_UMEM_REG TxUmem = {0};
        TxUmem.Address = &TxPacket;
        TxUmem.ChunkSize = sizeof(XDP_TX_PACKET);
        TxUmem.Headroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        TxUmem.TotalSize = sizeof(XDP_TX_PACKET);

        Status = Xdp->XdpApi->XskSetSockopt(TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
        if (QUIC_FAILED(Status)) { CloseHandle(TxXsk); return Status; }

        Status = Xdp->XdpApi->XskSetSockopt(TxXsk, XSK_SOCKOPT_TX_RING_SIZE, &TxRingSize, sizeof(TxRingSize));
        if (QUIC_FAILED(Status)) { CloseHandle(TxXsk); return Status; }

        Status = Xdp->XdpApi->XskSetSockopt(TxXsk, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &TxRingSize, sizeof(TxRingSize));
        if (QUIC_FAILED(Status)) { CloseHandle(TxXsk); return Status; }

        uint32_t Flags = XSK_BIND_FLAG_TX;
        Status = Xdp->XdpApi->XskBind(TxXsk, InterfaceIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            CloseHandle(TxXsk);
            if (Status == E_INVALIDARG) { // No more queues. Break out.
                *Count = i;
                break; // Expected failure if there is no more queue.
            }
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind (GetRssQueueProcessors)");
            return Status;
        }

        Status = Xdp->XdpApi->XskActivate(TxXsk, 0);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskActivate (GetRssQueueProcessors)");
            CloseHandle(TxXsk);
            return Status;
        }

        XSK_RING_INFO_SET TxRingInfo;
        uint32_t TxRingInfoSize = sizeof(TxRingInfo);
        Status = Xdp->XdpApi->XskGetSockopt(TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
        if (QUIC_FAILED(Status)) { CloseHandle(TxXsk); return Status; }

        XSK_RING TxRing, TxCompletionRing;
        XskRingInitialize(&TxRing, &TxRingInfo.Tx);
        XskRingInitialize(&TxCompletionRing, &TxRingInfo.Completion);

        uint32_t TxIndex;
        XskRingProducerReserve(&TxRing, MAXUINT32, &TxIndex);

        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&TxRing, TxIndex++);
        Buffer->Address.BaseAddress = 0;
        Buffer->Address.Offset = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        Buffer->Length = TxPacket.Buffer.Length;
        XskRingProducerSubmit(&TxRing, 1);

        XSK_NOTIFY_RESULT_FLAGS OutFlags;
        Status = Xdp->XdpApi->XskNotifySocket(TxXsk, XSK_NOTIFY_FLAG_POKE_TX|XSK_NOTIFY_FLAG_WAIT_TX, XDP_MAX_SYNC_WAIT_TIMEOUT_MS, &OutFlags);
        if (QUIC_FAILED(Status)) { CloseHandle(TxXsk); return Status; }

        uint32_t CompIndex;
        if (XskRingConsumerReserve(&TxCompletionRing, MAXUINT32, &CompIndex) == 0) {
            CloseHandle(TxXsk);
            return E_ABORT;
        }
        XskRingConsumerRelease(&TxCompletionRing, 1);

        PROCESSOR_NUMBER ProcNumber;
        uint32_t ProcNumberSize = sizeof(PROCESSOR_NUMBER);
        Status = Xdp->XdpApi->XskGetSockopt(TxXsk, XSK_SOCKOPT_TX_PROCESSOR_AFFINITY, &ProcNumber, &ProcNumberSize);
        if (QUIC_FAILED(Status)) { CloseHandle(TxXsk); return Status; }

        const CXPLAT_PROCESSOR_GROUP_INFO* Group = &CxPlatProcessorGroupInfo[ProcNumber.Group];
        Queues[i] = Group->Offset + (ProcNumber.Number % Group->Count);

        CloseHandle(TxXsk);
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatXdpReadConfig(
    _Inout_ XDP_DATAPATH* Xdp
    )
{
    //
    // Default config.
    //
    Xdp->RxBufferCount = 8192;
    Xdp->RxRingSize = 256;
    Xdp->TxBufferCount = 8192;
    Xdp->TxRingSize = 256;
    Xdp->TxAlwaysPoke = FALSE;

    //
    // Read config from config file.
    //
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

        if (strcmp(Line, "RxBufferCount") == 0) {
             Xdp->RxBufferCount = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "RxRingSize") == 0) {
             Xdp->RxRingSize = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxBufferCount") == 0) {
             Xdp->TxBufferCount = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxRingSize") == 0) {
             Xdp->TxRingSize = strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "TxAlwaysPoke") == 0) {
             Xdp->TxAlwaysPoke = !!strtoul(Value, NULL, 10);
        } else if (strcmp(Line, "SkipXsum") == 0) {
            BOOLEAN State = !!strtoul(Value, NULL, 10);
            Xdp->SkipXsum = State;
            printf("SkipXsum: %u\n", State);
        }
    }

    fclose(File);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceUninitialize(
    _Inout_ XDP_INTERFACE* Interface
    )
{
    #pragma warning(push)
    #pragma warning(disable:6001) // Using uninitialized memory

    for (uint32_t i = 0; Interface->Queues != NULL && i < Interface->QueueCount; i++) {
        XDP_QUEUE *Queue = &Interface->Queues[i];

        if (Queue->TxXsk != NULL) {
            CloseHandle(Queue->TxXsk);
        }

        if (Queue->TxBuffers != NULL) {
            CxPlatFree(Queue->TxBuffers, TX_BUFFER_TAG);
        }

        if (Queue->RxProgram != NULL) {
            CloseHandle(Queue->RxProgram);
        }

        if (Queue->RxXsk != NULL) {
            CloseHandle(Queue->RxXsk);
        }

        if (Queue->RxBuffers != NULL) {
            CxPlatFree(Queue->RxBuffers, RX_BUFFER_TAG);
        }

        CxPlatLockUninitialize(&Queue->TxLock);
    }

    if (Interface->Queues != NULL) {
        CxPlatFree(Interface->Queues, QUEUE_TAG);
    }

    if (Interface->Rules != NULL) {
        for (uint8_t i = 0; i < Interface->RuleCount; ++i) {
            if (Interface->Rules[i].Pattern.IpPortSet.PortSet.PortSet) {
                CxPlatFree(
                    (uint8_t*)Interface->Rules[i].Pattern.IpPortSet.PortSet.PortSet, PORT_SET_TAG);
            }
        }
        CxPlatFree(Interface->Rules, RULE_TAG);
    }

    if (Interface->XdpHandle) {
        CloseHandle(Interface->XdpHandle);
    }

    CxPlatLockUninitialize(&Interface->RuleLock);

    #pragma warning(pop)
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInterfaceInitialize(
    _In_ XDP_DATAPATH* Xdp,
    _Inout_ XDP_INTERFACE* Interface,
    _In_ uint32_t ClientRecvContextLength
    )
{
    const uint32_t RxHeadroom = sizeof(XDP_RX_PACKET) + ALIGN_UP(ClientRecvContextLength, uint32_t);
    const uint32_t RxPacketSize = ALIGN_UP(RxHeadroom + MAX_ETH_FRAME_SIZE, XDP_RX_PACKET);
    QUIC_STATUS Status;

    CxPlatLockInitialize(&Interface->RuleLock);
    Interface->OffloadStatus.Receive.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->OffloadStatus.Receive.TransportLayerXsum = Xdp->SkipXsum;
    Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->OffloadStatus.Transmit.NetworkLayerXsum = Xdp->SkipXsum;
    Interface->Xdp = Xdp;

    Interface->QueueCount = (uint16_t)CxPlatProcCount();
    uint32_t* Processors =
        CXPLAT_ALLOC_NONPAGED(
            Interface->QueueCount * sizeof(uint32_t),
            QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (Processors == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status = Xdp->XdpApi->XdpInterfaceOpen(Interface->ActualIfIndex, &Interface->XdpHandle);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "XdpInterfaceOpen");
        goto Error;
    }

    Status = CxPlatGetRssQueueProcessors(Xdp, Interface->ActualIfIndex, &Interface->QueueCount, Processors);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatGetRssQueueProcessors");
        goto Error;
    }

    if (Interface->QueueCount == 0) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatGetRssQueueProcessors");
        goto Error;
    }

    QuicTraceLogVerbose(
        XdpInterfaceQueues,
        "[ixdp][%p] Initializing %u queues on interface",
        Interface,
        Interface->QueueCount);

    Interface->Queues = CXPLAT_ALLOC_NONPAGED(Interface->QueueCount * sizeof(*Interface->Queues), QUEUE_TAG);
    if (Interface->Queues == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP Queues",
            Interface->QueueCount * sizeof(*Interface->Queues));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CxPlatZeroMemory(Interface->Queues, Interface->QueueCount * sizeof(*Interface->Queues));

    for (uint8_t i = 0; i < Interface->QueueCount; i++) {
        XDP_QUEUE* Queue = &Interface->Queues[i];

        Queue->RssProcessor = (uint16_t)Processors[i]; // TODO - Should memory be aligned with this?
        Queue->Interface = Interface;
        InitializeSListHead(&Queue->RxPool);
        InitializeSListHead(&Queue->TxPool);
        CxPlatLockInitialize(&Queue->TxLock);
        CxPlatListInitializeHead(&Queue->TxQueue);
        CxPlatListInitializeHead(&Queue->PartitionTxQueue);
        CxPlatDatapathSqeInitialize(&Queue->RxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        Queue->RxIoSqe.IoType = DATAPATH_XDP_IO_RECV;
        CxPlatDatapathSqeInitialize(&Queue->TxIoSqe.DatapathSqe, CXPLAT_CQE_TYPE_SOCKET_IO);
        Queue->TxIoSqe.IoType = DATAPATH_XDP_IO_SEND;

        //
        // RX datapath.
        //

        Queue->RxBuffers = CXPLAT_ALLOC_NONPAGED(Xdp->RxBufferCount * RxPacketSize, RX_BUFFER_TAG);
        if (Queue->RxBuffers == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP RX Buffers",
                Xdp->RxBufferCount * RxPacketSize);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = Xdp->XdpApi->XskCreate(&Queue->RxXsk);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskCreate");
            goto Error;
        }

        XSK_UMEM_REG RxUmem = {0};
        RxUmem.Address = Queue->RxBuffers;
        RxUmem.ChunkSize = RxPacketSize;
        RxUmem.Headroom = RxHeadroom;
        RxUmem.TotalSize = Xdp->RxBufferCount * RxPacketSize;

        Status = Xdp->XdpApi->XskSetSockopt(Queue->RxXsk, XSK_SOCKOPT_UMEM_REG, &RxUmem, sizeof(RxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            Xdp->XdpApi->XskSetSockopt(
                Queue->RxXsk, XSK_SOCKOPT_RX_FILL_RING_SIZE, &Xdp->RxRingSize,
                sizeof(Xdp->RxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_RX_FILL_RING_SIZE)");
            goto Error;
        }

        Status =
            Xdp->XdpApi->XskSetSockopt(
                Queue->RxXsk, XSK_SOCKOPT_RX_RING_SIZE, &Xdp->RxRingSize, sizeof(Xdp->RxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_RX_RING_SIZE)");
            goto Error;
        }

        uint32_t Flags = XSK_BIND_FLAG_RX;
        Status = Xdp->XdpApi->XskBind(Queue->RxXsk, Interface->ActualIfIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        Status = Xdp->XdpApi->XskActivate(Queue->RxXsk, 0);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskActivate");
            goto Error;
        }

        XSK_RING_INFO_SET RxRingInfo;
        uint32_t RxRingInfoSize = sizeof(RxRingInfo);
        Status = Xdp->XdpApi->XskGetSockopt(Queue->RxXsk, XSK_SOCKOPT_RING_INFO, &RxRingInfo, &RxRingInfoSize);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskGetSockopt(XSK_SOCKOPT_RING_INFO)");
            goto Error;
        }

        XskRingInitialize(&Queue->RxFillRing, &RxRingInfo.Fill);
        XskRingInitialize(&Queue->RxRing, &RxRingInfo.Rx);

        for (uint32_t j = 0; j < Xdp->RxBufferCount; j++) {
            InterlockedPushEntrySList(
                &Queue->RxPool, (PSLIST_ENTRY)&Queue->RxBuffers[j * RxPacketSize]);
        }

        //
        // Disable automatic IO completions being queued if the call completes
        // synchronously.
        //
        if (!SetFileCompletionNotificationModes(
                (HANDLE)Queue->RxXsk,
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "SetFileCompletionNotificationModes");
            goto Error;
        }

        //
        // TX datapath.
        //

        Queue->TxBuffers = CXPLAT_ALLOC_NONPAGED(Xdp->TxBufferCount * sizeof(XDP_TX_PACKET), TX_BUFFER_TAG);
        if (Queue->TxBuffers == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP TX Buffers",
                Xdp->TxBufferCount * sizeof(XDP_TX_PACKET));
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Status = Xdp->XdpApi->XskCreate(&Queue->TxXsk);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskCreate");
            goto Error;
        }

        XSK_UMEM_REG TxUmem = {0};
        TxUmem.Address = Queue->TxBuffers;
        TxUmem.ChunkSize = sizeof(XDP_TX_PACKET);
        TxUmem.Headroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        TxUmem.TotalSize = Xdp->TxBufferCount * sizeof(XDP_TX_PACKET);

        Status = Xdp->XdpApi->XskSetSockopt(Queue->TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            Xdp->XdpApi->XskSetSockopt(
                Queue->TxXsk, XSK_SOCKOPT_TX_RING_SIZE, &Xdp->TxRingSize, sizeof(Xdp->TxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_TX_RING_SIZE)");
            goto Error;
        }

        Status =
            Xdp->XdpApi->XskSetSockopt(
                Queue->TxXsk, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &Xdp->TxRingSize,
                sizeof(Xdp->TxRingSize));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_TX_COMPLETION_RING_SIZE)");
            goto Error;
        }

        Flags = XSK_BIND_FLAG_TX; // TODO: support native/generic forced flags.
        Status = Xdp->XdpApi->XskBind(Queue->TxXsk, Interface->ActualIfIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        Status = Xdp->XdpApi->XskActivate(Queue->TxXsk, 0);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskActivate");
            goto Error;
        }

        XSK_RING_INFO_SET TxRingInfo;
        uint32_t TxRingInfoSize = sizeof(TxRingInfo);
        Status = Xdp->XdpApi->XskGetSockopt(Queue->TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskGetSockopt(XSK_SOCKOPT_RING_INFO)");
            goto Error;
        }

        XskRingInitialize(&Queue->TxRing, &TxRingInfo.Tx);
        XskRingInitialize(&Queue->TxCompletionRing, &TxRingInfo.Completion);

        for (uint32_t j = 0; j < Xdp->TxBufferCount; j++) {
            InterlockedPushEntrySList(
                &Queue->TxPool, (PSLIST_ENTRY)&Queue->TxBuffers[j * sizeof(XDP_TX_PACKET)]);
        }

        //
        // Disable automatic IO completions being queued if the call completes
        // synchronously.
        //
        if (!SetFileCompletionNotificationModes(
                (HANDLE)Queue->TxXsk,
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "SetFileCompletionNotificationModes");
            goto Error;
        }
    }

    //
    // Add each queue to the correct partition.
    //
    uint16_t RoundRobinIndex = 0;
    for (uint16_t i = 0; i < Interface->QueueCount; i++) {
        BOOLEAN Found = FALSE;
        for (uint16_t j = 0; j < Xdp->PartitionCount; j++) {
            if (Xdp->Partitions[j].Processor == Interface->Queues[i].RssProcessor) {
                XdpWorkerAddQueue(&Xdp->Partitions[j], &Interface->Queues[i]);
                Found = TRUE;
                break;
            }
        }
        if (!Found) {
            //
            // Assign leftovers based on round robin.
            //
            XdpWorkerAddQueue(
                &Xdp->Partitions[RoundRobinIndex++ % Xdp->PartitionCount],
                &Interface->Queues[i]);
        }
    }

Error:
    if (QUIC_FAILED(Status)) {
        CxPlatDpRawInterfaceUninitialize(Interface);
    }
    if (Processors != NULL) {
        CXPLAT_FREE(Processors, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Requires_lock_held_(Interface->RuleLock)
void
CxPlatDpRawInterfaceUpdateRules(
    _In_ XDP_INTERFACE* Interface
    )
{
    static const XDP_HOOK_ID RxHook = {
        .Layer = XDP_HOOK_L2,
        .Direction = XDP_HOOK_RX,
        .SubLayer = XDP_HOOK_INSPECT,
    };

    for (uint32_t i = 0; i < Interface->QueueCount; i++) {

        XDP_QUEUE* Queue = &Interface->Queues[i];
        for (uint8_t j = 0; j < Interface->RuleCount; j++) {
            Interface->Rules[j].Redirect.Target = Queue->RxXsk;
        }

        HANDLE NewRxProgram;
        QUIC_STATUS Status =
            Interface->Xdp->XdpApi->XdpCreateProgram(
                Interface->ActualIfIndex,
                &RxHook,
                i,
                0,
                Interface->Rules,
                Interface->RuleCount,
                &NewRxProgram);
        if (QUIC_FAILED(Status)) {
            //
            // TODO - Figure out how to better handle failure and revert changes.
            // This will likely require working with XDP to get an improved API;
            // possibly to update all queues at once.
            //
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XdpCreateProgram");
            continue;
        }

        if (Queue->RxProgram != NULL) {
            CloseHandle(Queue->RxProgram);
        }

        Queue->RxProgram = NewRxProgram;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceAddRules(
    _In_ XDP_INTERFACE* Interface,
    _In_reads_(Count) const XDP_RULE* Rules,
    _In_ uint8_t Count
    )
{
#pragma warning(push)
#pragma warning(disable:6386) // Buffer overrun while writing to 'NewRules' - FALSE POSITIVE

    CxPlatLockAcquire(&Interface->RuleLock);
    // TODO - Don't always allocate a new array?

    if ((uint32_t)Interface->RuleCount + (uint32_t)Count > UINT8_MAX) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "No more room for rules");
        CxPlatLockRelease(&Interface->RuleLock);
        return;
    }

    const size_t OldSize = sizeof(XDP_RULE) * (size_t)Interface->RuleCount;
    const size_t NewSize = sizeof(XDP_RULE) * ((size_t)Interface->RuleCount + Count);

    XDP_RULE* NewRules = CXPLAT_ALLOC_NONPAGED(NewSize, RULE_TAG);
    if (NewRules == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "XDP_RULE",
            NewSize);
        CxPlatLockRelease(&Interface->RuleLock);
        return;
    }

    if (Interface->RuleCount > 0) {
        memcpy(NewRules, Interface->Rules, OldSize);
    }
    for (uint8_t i = 0; i < Count; i++) {
        NewRules[Interface->RuleCount++] = Rules[i];
    }

    if (Interface->Rules != NULL) {
        CxPlatFree(Interface->Rules, RULE_TAG);
    }
    Interface->Rules = NewRules;

    CxPlatDpRawInterfaceUpdateRules(Interface);

    CxPlatLockRelease(&Interface->RuleLock);

#pragma warning(pop)
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawInterfaceRemoveRules(
    _In_ XDP_INTERFACE* Interface,
    _In_reads_(Count) const XDP_RULE* Rules,
    _In_ uint8_t Count
    )
{
    CxPlatLockAcquire(&Interface->RuleLock);

    BOOLEAN UpdateRules = FALSE;

    for (uint8_t j = 0; j < Count; j++) {
        for (uint8_t i = 0; i < Interface->RuleCount; i++) {
            if (Interface->Rules[i].Match != Rules[j].Match) {
                continue;
            }

            if (Rules[j].Match == XDP_MATCH_UDP_DST || Rules[j].Match == XDP_MATCH_TCP_CONTROL_DST || Rules[j].Match == XDP_MATCH_TCP_DST) {
                if (Rules[j].Pattern.Port != Interface->Rules[i].Pattern.Port) {
                    continue;
                }
            } else if (Rules[j].Match == XDP_MATCH_QUIC_FLOW_SRC_CID || Rules[j].Match == XDP_MATCH_QUIC_FLOW_DST_CID ||
                       Rules[j].Match == XDP_MATCH_TCP_QUIC_FLOW_SRC_CID || Rules[j].Match == XDP_MATCH_TCP_QUIC_FLOW_DST_CID) {
                if (Rules[j].Pattern.QuicFlow.UdpPort != Interface->Rules[i].Pattern.QuicFlow.UdpPort ||
                    Rules[j].Pattern.QuicFlow.CidLength != Interface->Rules[i].Pattern.QuicFlow.CidLength ||
                    Rules[j].Pattern.QuicFlow.CidOffset != Interface->Rules[i].Pattern.QuicFlow.CidOffset ||
                    memcmp(Rules[j].Pattern.QuicFlow.CidData, Interface->Rules[i].Pattern.QuicFlow.CidData, Rules[j].Pattern.QuicFlow.CidLength) != 0) {
                    continue;
                }
            } else if (Rules[j].Match == XDP_MATCH_IPV4_UDP_TUPLE) {
                if (Rules[j].Pattern.Tuple.DestinationPort != Interface->Rules[i].Pattern.Tuple.DestinationPort ||
                    Rules[j].Pattern.Tuple.SourcePort != Interface->Rules[i].Pattern.Tuple.SourcePort ||
                    memcmp(&Rules[j].Pattern.Tuple.DestinationAddress.Ipv4, &Interface->Rules[i].Pattern.Tuple.DestinationAddress.Ipv4, sizeof(IN_ADDR)) != 0 ||
                    memcmp(&Rules[j].Pattern.Tuple.SourceAddress.Ipv4, &Interface->Rules[i].Pattern.Tuple.SourceAddress.Ipv4, sizeof(IN_ADDR)) != 0) {
                    continue;
                }
            } else if (Rules[j].Match == XDP_MATCH_IPV6_UDP_TUPLE) {
                if (Rules[j].Pattern.Tuple.DestinationPort != Interface->Rules[i].Pattern.Tuple.DestinationPort ||
                    Rules[j].Pattern.Tuple.SourcePort != Interface->Rules[i].Pattern.Tuple.SourcePort ||
                    memcmp(&Rules[j].Pattern.Tuple.DestinationAddress.Ipv6, &Interface->Rules[i].Pattern.Tuple.DestinationAddress.Ipv6, sizeof(IN6_ADDR)) != 0 ||
                    memcmp(&Rules[j].Pattern.Tuple.SourceAddress.Ipv6, &Interface->Rules[i].Pattern.Tuple.SourceAddress.Ipv6, sizeof(IN6_ADDR)) != 0) {
                    continue;
                }
            } else {
                CXPLAT_FRE_ASSERT(FALSE); // Should not be possible!
            }

            if (i < Interface->RuleCount - 1) {
                memmove(&Interface->Rules[i], &Interface->Rules[i + 1], sizeof(XDP_RULE) * (Interface->RuleCount - i - 1));
            }
            Interface->RuleCount--;
            UpdateRules = TRUE;
            break;
        }
    }

    if (UpdateRules) {
        CxPlatDpRawInterfaceUpdateRules(Interface);
    }

    CxPlatLockRelease(&Interface->RuleLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
size_t
CxPlatDpRawGetDatapathSize(
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    const uint32_t PartitionCount =
        (Config && Config->ProcessorCount) ? Config->ProcessorCount : CxPlatProcCount();
    return sizeof(XDP_DATAPATH) + (PartitionCount * sizeof(XDP_PARTITION));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDpRawInitialize(
    _Inout_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_WORKER_POOL* WorkerPool,
    _In_opt_ const QUIC_EXECUTION_CONFIG* Config
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QUIC_STATUS Status;

    if (WorkerPool == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CxPlatListInitializeHead(&Xdp->Interfaces);
    if (QUIC_FAILED(XdpLoadApi(XDP_API_VERSION_1, &Xdp->XdpApiLoadContext, &Xdp->XdpApi))) {
        Status = QUIC_STATUS_NOT_SUPPORTED;
        goto Error;
    }

    Xdp->XdpQeoSet = (XDP_QEO_SET_FN *)Xdp->XdpApi->XdpGetRoutine(XDP_QEO_SET_FN_NAME);

    CxPlatXdpReadConfig(Xdp);
    Xdp->PollingIdleTimeoutUs = Config ? Config->PollingIdleTimeoutUs : 0;

    if (Config && Config->ProcessorCount) {
        Xdp->PartitionCount = Config->ProcessorCount;
        for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
            Xdp->Partitions[i].Processor = Config->ProcessorList[i];
        }
    } else {
        Xdp->PartitionCount = CxPlatProcCount();
        for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
            Xdp->Partitions[i].Processor = (uint16_t)i;
        }
    }

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);

    PMIB_IF_TABLE2 pIfTable;
    if (GetIfTable2(&pIfTable) != NO_ERROR) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Error;
    }

    PIP_ADAPTER_ADDRESSES Adapters = NULL;
    ULONG Error;
    ULONG AdaptersBufferSize = 15000; // 15 KB buffer for GAA to start with.
    ULONG Iterations = 0;
    ULONG flags = // skip info that we don't need.
        GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_SKIP_UNICAST |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_DNS_INFO;

    do {
        Adapters = (IP_ADAPTER_ADDRESSES*)CXPLAT_ALLOC_NONPAGED(AdaptersBufferSize, ADAPTER_TAG);
        if (Adapters == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "XDP interface",
                AdaptersBufferSize);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }

        Error =
            GetAdaptersAddresses(AF_UNSPEC, flags, NULL, Adapters, &AdaptersBufferSize);
        if (Error == ERROR_BUFFER_OVERFLOW) {
            CxPlatFree(Adapters, ADAPTER_TAG);
            Adapters = NULL;
        } else {
            break;
        }

        Iterations++;
    } while ((Error == ERROR_BUFFER_OVERFLOW) && (Iterations < 3)); // retry up to 3 times.

    if (Error == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES Adapter = Adapters; Adapter != NULL; Adapter = Adapter->Next) {
            if (Adapter->IfType == IF_TYPE_ETHERNET_CSMACD &&
                Adapter->OperStatus == IfOperStatusUp &&
                Adapter->PhysicalAddressLength == ETH_MAC_ADDR_LEN) {
                XDP_INTERFACE* Interface = CXPLAT_ALLOC_NONPAGED(sizeof(XDP_INTERFACE), IF_TAG);
                if (Interface == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "XDP interface",
                        sizeof(*Interface));
                    Status = QUIC_STATUS_OUT_OF_MEMORY;
                    goto Error;
                }
                CxPlatZeroMemory(Interface, sizeof(*Interface));
                Interface->ActualIfIndex = Interface->IfIndex = Adapter->IfIndex;
                memcpy(
                    Interface->PhysicalAddress, Adapter->PhysicalAddress,
                    sizeof(Interface->PhysicalAddress));

                // Look for VF which associated with Adapter
                // It has same MAC address. and empirically these flags
                /* TODO - Currently causes issues some times
                for (int i = 0; i < (int) pIfTable->NumEntries; i++) {
                    MIB_IF_ROW2* pIfRow = &pIfTable->Table[i];
                    if (!pIfRow->InterfaceAndOperStatusFlags.FilterInterface &&
                         pIfRow->InterfaceAndOperStatusFlags.HardwareInterface &&
                         pIfRow->InterfaceAndOperStatusFlags.ConnectorPresent &&
                         pIfRow->PhysicalMediumType == NdisPhysicalMedium802_3 &&
                         memcmp(&pIfRow->PhysicalAddress, &Adapter->PhysicalAddress,
                                Adapter->PhysicalAddressLength) == 0) {
                        Interface->ActualIfIndex = pIfRow->InterfaceIndex;
                        QuicTraceLogInfo(
                            FoundVF,
                            "[ xdp][%p] Found NetSvc-VF interfaces. NetSvc IfIdx:%lu, VF IfIdx:%lu",
                            Xdp,
                            Interface->IfIndex,
                            Interface->ActualIfIndex);
                        break; // assuming there is 1:1 matching
                    }
                }*/

                QuicTraceLogVerbose(
                    XdpInterfaceInitialize,
                    "[ixdp][%p] Initializing interface %u",
                    Interface,
                    Interface->ActualIfIndex);

                Status =
                    CxPlatDpRawInterfaceInitialize(
                        Xdp, Interface, ClientRecvContextLength);
                if (QUIC_FAILED(Status)) {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        Status,
                        "CxPlatDpRawInterfaceInitialize");
                    CxPlatFree(Interface, IF_TAG);
                    continue;
                }
                CxPlatListInsertTail(&Xdp->Interfaces, &Interface->Link);
            }
        }
    } else {
        Status = HRESULT_FROM_WIN32(Error);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatThreadCreate");
        goto Error;
    }
    FreeMibTable(pIfTable);

    if (CxPlatListIsEmpty(&Xdp->Interfaces)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "no XDP capable interface");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Error;
    }

    Xdp->Running = TRUE;
    CxPlatRefInitialize(&Xdp->RefCount);
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {

        XDP_PARTITION* Partition = &Xdp->Partitions[i];
        if (Partition->Queues == NULL) { continue; } // No RSS queues for this partition.

        Partition->Xdp = Xdp;
        Partition->PartitionIndex = (uint16_t)i;
        Partition->Ec.Ready = TRUE;
        Partition->Ec.NextTimeUs = UINT64_MAX;
        Partition->Ec.Callback = CxPlatXdpExecute;
        Partition->Ec.Context = &Xdp->Partitions[i];
        Partition->ShutdownSqe.CqeType = CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN;
        CxPlatRefIncrement(&Xdp->RefCount);
        Partition->EventQ = CxPlatWorkerPoolGetEventQ(WorkerPool, (uint16_t)i);

        uint32_t QueueCount = 0;
        XDP_QUEUE* Queue = Partition->Queues;
        while (Queue) {
            if (!CxPlatEventQAssociateHandle(Partition->EventQ, Queue->RxXsk)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    GetLastError(),
                    "CreateIoCompletionPort(RX)");
            }
            if (!CxPlatEventQAssociateHandle(Partition->EventQ, Queue->TxXsk)) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    GetLastError(),
                    "CreateIoCompletionPort(TX)");
            }
            QuicTraceLogVerbose(
                XdpQueueStart,
                "[ xdp][%p] XDP queue start on partition %p",
                Queue,
                Partition);
            ++QueueCount;
            Queue = Queue->Next;
        }

        QuicTraceLogVerbose(
            XdpWorkerStart,
            "[ xdp][%p] XDP partition start, %u queues",
            Partition,
            QueueCount);
        UNREFERENCED_PARAMETER(QueueCount);

        CxPlatAddExecutionContext(WorkerPool, &Partition->Ec, Partition->PartitionIndex);
    }
    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CxPlatFree(Interface, IF_TAG);
        }

        if (Xdp->XdpApi) {
            XdpUnloadApi(Xdp->XdpApiLoadContext, Xdp->XdpApi);
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawRelease(
    _In_ XDP_DATAPATH* Xdp
    )
{
    QuicTraceLogVerbose(
        XdpRelease,
        "[ xdp][%p] XDP release",
        Xdp);
    if (CxPlatRefDecrement(&Xdp->RefCount)) {
        QuicTraceLogVerbose(
            XdpUninitializeComplete,
            "[ xdp][%p] XDP uninitialize complete",
            Xdp);
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface =
                CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CxPlatFree(Interface, IF_TAG);
        }
        XdpUnloadApi(Xdp->XdpApiLoadContext, Xdp->XdpApi);
        CxPlatDataPathUninitializeComplete((CXPLAT_DATAPATH_RAW*)Xdp);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUninitialize(
    _In_ CXPLAT_DATAPATH_RAW* Datapath
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    QuicTraceLogVerbose(
        XdpUninitialize,
        "[ xdp][%p] XDP uninitialize",
        Xdp);
    Xdp->Running = FALSE;
    for (uint32_t i = 0; i < Xdp->PartitionCount; i++) {
        if (Xdp->Partitions[i].Queues != NULL) {
            Xdp->Partitions[i].Ec.Ready = TRUE;
            CxPlatWakeExecutionContext(&Xdp->Partitions[i].Ec);
        }
    }
    CxPlatDpRawRelease(Xdp);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawUpdateConfig(
    _In_ CXPLAT_DATAPATH_RAW* Datapath,
    _In_ QUIC_EXECUTION_CONFIG* Config
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Datapath;
    Xdp->PollingIdleTimeoutUs = Config->PollingIdleTimeoutUs;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
RawSocketUpdateQeo(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_reads_(OffloadCount)
        const CXPLAT_QEO_CONNECTION* Offloads,
    _In_ uint32_t OffloadCount
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Socket->RawDatapath;

    XDP_QUIC_CONNECTION Connections[2];
    CXPLAT_FRE_ASSERT(OffloadCount == 2); // TODO - Refactor so upper layer struct matches XDP struct
                                          // so we don't need to copy to a different struct.

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    for (uint32_t i = 0; i < OffloadCount; i++) {
        XdpInitializeQuicConnection(&Connections[i], sizeof(Connections[i]));
        Connections[i].Operation = Offloads[i].Operation;
        Connections[i].Direction = Offloads[i].Direction;
        Connections[i].DecryptFailureAction = Offloads[i].DecryptFailureAction;
        Connections[i].KeyPhase = Offloads[i].KeyPhase;
        Connections[i].RESERVED = Offloads[i].RESERVED;
        Connections[i].CipherType = Offloads[i].CipherType;
        Connections[i].NextPacketNumber = Offloads[i].NextPacketNumber;
        if (Offloads[i].Address.si_family == AF_INET) {
            Connections[i].AddressFamily = XDP_QUIC_ADDRESS_FAMILY_INET4;
            memcpy(Connections[i].Address, &Offloads[i].Address.Ipv4.sin_addr, sizeof(IN_ADDR));
        } else if (Offloads[i].Address.si_family == AF_INET6) {
            Connections[i].AddressFamily = XDP_QUIC_ADDRESS_FAMILY_INET6;
            memcpy(Connections[i].Address, &Offloads[i].Address.Ipv6.sin6_addr, sizeof(IN6_ADDR));
        } else {
            CXPLAT_FRE_ASSERT(FALSE); // Should NEVER happen!
        }
        Connections[i].UdpPort = Offloads[i].Address.Ipv4.sin_port;
        Connections[i].ConnectionIdLength = Offloads[i].ConnectionIdLength;
        memcpy(Connections[i].ConnectionId, Offloads[i].ConnectionId, Offloads[i].ConnectionIdLength);
        memcpy(Connections[i].PayloadKey, Offloads[i].PayloadKey, sizeof(Connections[i].PayloadKey));
        memcpy(Connections[i].HeaderKey, Offloads[i].HeaderKey, sizeof(Connections[i].HeaderKey));
        memcpy(Connections[i].PayloadIv, Offloads[i].PayloadIv, sizeof(Connections[i].PayloadIv));
        Connections[i].Status = 0;
    }

    //
    // The following logic just tries all interfaces and if it's able to offload
    // to any of them, it considers it a success. Long term though, this should
    // only offload to the interface that the socket is bound to.
    //

    BOOLEAN AtLeastOneSucceeded = FALSE;
    for (CXPLAT_LIST_ENTRY* Entry = Xdp->Interfaces.Flink; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
        if (Xdp->XdpQeoSet != NULL) {
            Status =
                Xdp->XdpQeoSet(
                    CONTAINING_RECORD(Entry, XDP_INTERFACE, Link)->XdpHandle,
                    Connections,
                    sizeof(Connections));
        } else {
            Status = E_NOINTERFACE;
        }
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XdpQeoSet");
        } else {
            AtLeastOneSucceeded = TRUE; // TODO - Check individual connection status too.
        }
    }

    return AtLeastOneSucceeded ? QUIC_STATUS_SUCCESS : QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CxPlatDpRawSetPortBit(
    _Inout_ uint8_t *BitMap,
    _In_ uint16_t Port
    )
{
    BitMap[Port >> 3] |= (1 << (Port & 0x7));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CxPlatDpRawClearPortBit(
    _Inout_ uint8_t *BitMap,
    _In_ uint16_t Port
    )
{
    BitMap[Port >> 3] &= (uint8_t)~(1 << (Port & 0x7));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatDpRawPlumbRulesOnSocket(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _In_ BOOLEAN IsCreated
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*)Socket->RawDatapath;
    if (Socket->Wildcard) {
        XDP_RULE Rules[3] = {0};
        uint8_t RulesSize = 0;
        if (Socket->CibirIdLength) {
            Rules[0].Match = Socket->UseTcp ? XDP_MATCH_TCP_QUIC_FLOW_SRC_CID : XDP_MATCH_QUIC_FLOW_SRC_CID;
            Rules[0].Pattern.QuicFlow.UdpPort = Socket->LocalAddress.Ipv4.sin_port;
            Rules[0].Pattern.QuicFlow.CidLength = Socket->CibirIdLength;
            Rules[0].Pattern.QuicFlow.CidOffset = Socket->CibirIdOffsetSrc;
            Rules[0].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[0].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
            Rules[0].Redirect.Target = NULL;

            Rules[1].Match = Socket->UseTcp ? XDP_MATCH_TCP_QUIC_FLOW_DST_CID : XDP_MATCH_QUIC_FLOW_DST_CID;
            Rules[1].Pattern.QuicFlow.UdpPort = Socket->LocalAddress.Ipv4.sin_port;
            Rules[1].Pattern.QuicFlow.CidLength = Socket->CibirIdLength;
            Rules[1].Pattern.QuicFlow.CidOffset = Socket->CibirIdOffsetDst;
            Rules[1].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[1].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
            Rules[1].Redirect.Target = NULL;

            memcpy(Rules[0].Pattern.QuicFlow.CidData, Socket->CibirId, Socket->CibirIdLength);
            memcpy(Rules[1].Pattern.QuicFlow.CidData, Socket->CibirId, Socket->CibirIdLength);

            RulesSize = 2;
            if (Socket->UseTcp) {
                Rules[2].Match = XDP_MATCH_TCP_CONTROL_DST;
                Rules[2].Pattern.Port = Socket->LocalAddress.Ipv4.sin_port;
                Rules[2].Action = XDP_PROGRAM_ACTION_REDIRECT;
                Rules[2].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
                Rules[2].Redirect.Target = NULL;
                ++RulesSize;
            }
            CXPLAT_DBG_ASSERT(RulesSize <= RTL_NUMBER_OF(Rules));
        } else {
            Rules[0].Match = Socket->UseTcp ? XDP_MATCH_TCP_DST : XDP_MATCH_UDP_DST;
            Rules[0].Pattern.Port = Socket->LocalAddress.Ipv4.sin_port;
            Rules[0].Action = XDP_PROGRAM_ACTION_REDIRECT;
            Rules[0].Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
            Rules[0].Redirect.Target = NULL;

            RulesSize = 1;
        }

        CXPLAT_LIST_ENTRY* Entry;
        for (Entry = Xdp->Interfaces.Flink; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
            XDP_INTERFACE* Interface = CONTAINING_RECORD(Entry, XDP_INTERFACE, Link);
            if (IsCreated) {
                CxPlatDpRawInterfaceAddRules(Interface, Rules, RulesSize);
            } else {
                CxPlatDpRawInterfaceRemoveRules(Interface, Rules, RulesSize);
            }
        }
    } else {

        //
        // TODO - Optimization: apply only to the correct interface.
        //
        CXPLAT_LIST_ENTRY* Entry;
        XDP_MATCH_TYPE MatchType;
        uint8_t* IpAddress;
        size_t IpAddressSize;
        if (Socket->LocalAddress.si_family == QUIC_ADDRESS_FAMILY_INET) {
            MatchType = Socket->UseTcp ? XDP_MATCH_IPV4_TCP_PORT_SET : XDP_MATCH_IPV4_UDP_PORT_SET;
            IpAddress = (uint8_t*)&Socket->LocalAddress.Ipv4.sin_addr;
            IpAddressSize = sizeof(IN_ADDR);
        } else {
            MatchType = Socket->UseTcp ? XDP_MATCH_IPV6_TCP_PORT_SET : XDP_MATCH_IPV6_UDP_PORT_SET;
            IpAddress = (uint8_t*)&Socket->LocalAddress.Ipv6.sin6_addr;
            IpAddressSize = sizeof(IN6_ADDR);
        }
        for (Entry = Xdp->Interfaces.Flink; Entry != &Xdp->Interfaces; Entry = Entry->Flink) {
            XDP_INTERFACE* Interface = CONTAINING_RECORD(Entry, XDP_INTERFACE, Link);
            XDP_RULE* Rule = NULL;
            CxPlatLockAcquire(&Interface->RuleLock);
            for (uint8_t i = 0; i < Interface->RuleCount; ++i) {
                if (Interface->Rules[i].Match == MatchType &&
                    memcmp(
                        &Interface->Rules[i].Pattern.IpPortSet.Address,
                        IpAddress,
                        IpAddressSize) == 0) {
                    Rule = &Interface->Rules[i];
                    break;
                }
            }
            if (IsCreated) {
                if (Rule) {
                    CxPlatDpRawSetPortBit(
                        (uint8_t*)Rule->Pattern.IpPortSet.PortSet.PortSet,
                        Socket->LocalAddress.Ipv4.sin_port);
                    CxPlatLockRelease(&Interface->RuleLock);
                } else {
                    CxPlatLockRelease(&Interface->RuleLock);
                    XDP_RULE NewRule = {
                        .Match = MatchType,
                        .Pattern.IpPortSet.PortSet.PortSet = CXPLAT_ALLOC_NONPAGED(XDP_PORT_SET_BUFFER_SIZE, PORT_SET_TAG),
                        .Action = XDP_PROGRAM_ACTION_REDIRECT,
                        .Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK,
                        .Redirect.Target = NULL,
                    };
                    if (NewRule.Pattern.IpPortSet.PortSet.PortSet) {
                        CxPlatZeroMemory(
                            (uint8_t*)NewRule.Pattern.IpPortSet.PortSet.PortSet,
                            XDP_PORT_SET_BUFFER_SIZE);
                    } else {
                        QuicTraceEvent(
                            AllocFailure,
                            "Allocation of '%s' failed. (%llu bytes)",
                            "PortSet",
                            XDP_PORT_SET_BUFFER_SIZE);
                        return;
                    }
                    CxPlatDpRawSetPortBit(
                        (uint8_t*)NewRule.Pattern.IpPortSet.PortSet.PortSet,
                        Socket->LocalAddress.Ipv4.sin_port);
                    memcpy(
                        &NewRule.Pattern.IpPortSet.Address, IpAddress, IpAddressSize);
                    CxPlatDpRawInterfaceAddRules(Interface, &NewRule, 1);
                }
            } else {
                //
                // Due to memory allocation failures, we might not have this rule programmed on the interface.
                //
                if (Rule) {
                    CxPlatDpRawClearPortBit(
                        (uint8_t*)Rule->Pattern.IpPortSet.PortSet.PortSet,
                        Socket->LocalAddress.Ipv4.sin_port);
                }
                CxPlatLockRelease(&Interface->RuleLock);
            }
        }
    }
}

static
BOOLEAN // Did work?
CxPlatXdpRx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ XDP_QUEUE* Queue,
    _In_ uint16_t PartitionIndex
    )
{
    CXPLAT_RECV_DATA* Buffers[RX_BATCH_SIZE];
    uint32_t RxIndex;
    uint32_t FillIndex;
    uint32_t ProdCount = 0;
    uint32_t PacketCount = 0;
    const uint32_t BuffersCount = XskRingConsumerReserve(&Queue->RxRing, RX_BATCH_SIZE, &RxIndex);

    for (uint32_t i = 0; i < BuffersCount; i++) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Queue->RxRing, RxIndex++);
        XDP_RX_PACKET* Packet =
            (XDP_RX_PACKET*)(Queue->RxBuffers + Buffer->Address.BaseAddress);
        uint8_t* FrameBuffer = (uint8_t*)Packet + Buffer->Address.Offset;

        CxPlatZeroMemory(Packet, sizeof(XDP_RX_PACKET));
        Packet->Queue = Queue;
        Packet->RouteStorage.Queue = Queue;
        Packet->RecvData.Route = &Packet->RouteStorage;
        Packet->RecvData.Route->DatapathType = Packet->RecvData.DatapathType = CXPLAT_DATAPATH_TYPE_RAW;
        Packet->RecvData.PartitionIndex = PartitionIndex;

        CxPlatDpRawParseEthernet(
            (CXPLAT_DATAPATH*)Xdp,
            &Packet->RecvData,
            FrameBuffer,
            (uint16_t)Buffer->Length);

        //
        // The route has been filled in with the packet's src/dst IP and ETH addresses, so
        // mark it resolved. This allows stateless sends to be issued without performing
        // a route lookup.
        //
        Packet->RecvData.Route->State = RouteResolved;

        if (Packet->RecvData.Buffer) {
            Packet->RecvData.Allocated = TRUE;
            Buffers[PacketCount++] = &Packet->RecvData;
        } else {
            CxPlatListPushEntry(&Queue->PartitionRxPool, (CXPLAT_SLIST_ENTRY*)Packet);
        }
    }

    if (BuffersCount > 0) {
        XskRingConsumerRelease(&Queue->RxRing, BuffersCount);
    }

    uint32_t FillAvailable = XskRingProducerReserve(&Queue->RxFillRing, MAXUINT32, &FillIndex);
    while (FillAvailable-- > 0) {
        if (Queue->PartitionRxPool.Next == NULL) {
            Queue->PartitionRxPool.Next = (CXPLAT_SLIST_ENTRY*)InterlockedFlushSList(&Queue->RxPool);
        }

        XDP_RX_PACKET* Packet = (XDP_RX_PACKET*)CxPlatListPopEntry(&Queue->PartitionRxPool);
        if (Packet == NULL) {
            break;
        }

        uint64_t* FillDesc = XskRingGetElement(&Queue->RxFillRing, FillIndex++);
        *FillDesc = (uint8_t*)Packet - Queue->RxBuffers;
        ProdCount++;
    }

    if (ProdCount > 0) {
        XskRingProducerSubmit(&Queue->RxFillRing, ProdCount);
    }

    if (PacketCount > 0) {
        CxPlatDpRawRxEthernet((CXPLAT_DATAPATH_RAW*)Xdp, Buffers, (uint16_t)PacketCount);
    }

    if (XskRingError(&Queue->RxRing) && !Queue->Error) {
        XSK_ERROR ErrorStatus;
        QUIC_STATUS XskStatus;
        uint32_t ErrorSize = sizeof(ErrorStatus);
        XskStatus = Xdp->XdpApi->XskGetSockopt(Queue->RxXsk, XSK_SOCKOPT_RX_ERROR, &ErrorStatus, &ErrorSize);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SUCCEEDED(XskStatus) ? ErrorStatus : XskStatus,
            "XSK_SOCKOPT_RX_ERROR");
        Queue->Error = TRUE;
    }

    return ProdCount > 0 || PacketCount > 0;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawRxFree(
    _In_opt_ const CXPLAT_RECV_DATA* PacketChain
    )
{
    uint32_t Count = 0;
    SLIST_ENTRY* Head = NULL;
    SLIST_ENTRY** Tail = &Head;
    SLIST_HEADER* Pool = NULL;

    while (PacketChain) {
        const XDP_RX_PACKET* Packet =
            CXPLAT_CONTAINING_RECORD(PacketChain, XDP_RX_PACKET, RecvData);
        PacketChain = PacketChain->Next;
        // Packet->Allocated = FALSE; (other data paths don't clear this flag?)

        if (Pool != &Packet->Queue->RxPool) {
            if (Count > 0) {
                InterlockedPushListSList(
                    Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
                Head = NULL;
                Tail = &Head;
                Count = 0;
            }

            Pool = &Packet->Queue->RxPool;
        }

        *Tail = (SLIST_ENTRY*)Packet;
        Tail = &((SLIST_ENTRY*)Packet)->Next;
        Count++;
    }

    if (Count > 0) {
        InterlockedPushListSList(Pool, Head, CONTAINING_RECORD(Tail, SLIST_ENTRY, Next), Count);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CXPLAT_SEND_DATA*
CxPlatDpRawTxAlloc(
    _In_ CXPLAT_SOCKET_RAW* Socket,
    _Inout_ CXPLAT_SEND_CONFIG* Config
    )
{
    QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Config->Route->RemoteAddress);
    XDP_QUEUE* Queue = Config->Route->Queue;
    CXPLAT_DBG_ASSERT(Queue != NULL);
    CXPLAT_DBG_ASSERT(&Queue->TxPool != NULL);
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)InterlockedPopEntrySList(&Queue->TxPool);

    if (Packet) {
        HEADER_BACKFILL HeaderBackfill = CxPlatDpRawCalculateHeaderBackFill(Family, Socket->UseTcp); // TODO - Cache in Route?
        CXPLAT_DBG_ASSERT(Config->MaxPacketSize <= sizeof(Packet->FrameBuffer) - HeaderBackfill.AllLayer);
        Packet->Queue = Queue;
        Packet->Buffer.Length = Config->MaxPacketSize;
        Packet->Buffer.Buffer = &Packet->FrameBuffer[HeaderBackfill.AllLayer];
        Packet->ECN = Config->ECN;
        Packet->DatapathType = Config->Route->DatapathType = CXPLAT_DATAPATH_TYPE_RAW;
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
    InterlockedPushEntrySList(&Packet->Queue->TxPool, (PSLIST_ENTRY)Packet);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatDpRawTxEnqueue(
    _In_ CXPLAT_SEND_DATA* SendData
    )
{
    XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)SendData;
    XDP_PARTITION* Partition = Packet->Queue->Partition;

    CxPlatLockAcquire(&Packet->Queue->TxLock);
    CxPlatListInsertTail(&Packet->Queue->TxQueue, &Packet->Link);
    CxPlatLockRelease(&Packet->Queue->TxLock);

    Partition->Ec.Ready = TRUE;
    CxPlatWakeExecutionContext(&Partition->Ec);
}

static
BOOLEAN // Did work?
CxPlatXdpTx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ XDP_QUEUE* Queue
    )
{
    uint32_t ProdCount = 0;
    uint32_t CompCount = 0;
    SLIST_ENTRY* TxCompleteHead = NULL;
    SLIST_ENTRY** TxCompleteTail = &TxCompleteHead;

    if (CxPlatListIsEmpty(&Queue->PartitionTxQueue) &&
        ReadPointerNoFence(&Queue->TxQueue.Flink) != &Queue->TxQueue) {
        CxPlatLockAcquire(&Queue->TxLock);
        CxPlatListMoveItems(&Queue->TxQueue, &Queue->PartitionTxQueue);
        CxPlatLockRelease(&Queue->TxLock);
    }

    uint32_t CompIndex;
    uint32_t CompAvailable =
        XskRingConsumerReserve(&Queue->TxCompletionRing, MAXUINT32, &CompIndex);
    while (CompAvailable-- > 0) {
        uint64_t* CompDesc = XskRingGetElement(&Queue->TxCompletionRing, CompIndex++);
        XDP_TX_PACKET* Packet = (XDP_TX_PACKET*)(Queue->TxBuffers + *CompDesc);
        *TxCompleteTail = (PSLIST_ENTRY)Packet;
        TxCompleteTail = &((PSLIST_ENTRY)Packet)->Next;
        CompCount++;
    }

    if (CompCount > 0) {
        XskRingConsumerRelease(&Queue->TxCompletionRing, CompCount);
        InterlockedPushListSList(
            &Queue->TxPool, TxCompleteHead, CONTAINING_RECORD(TxCompleteTail, SLIST_ENTRY, Next),
            CompCount);
    }

    uint32_t TxIndex;
    uint32_t TxAvailable = XskRingProducerReserve(&Queue->TxRing, MAXUINT32, &TxIndex);
    while (TxAvailable-- > 0 && !CxPlatListIsEmpty(&Queue->PartitionTxQueue)) {
        XSK_BUFFER_DESCRIPTOR* Buffer = XskRingGetElement(&Queue->TxRing, TxIndex++);
        CXPLAT_LIST_ENTRY* Entry = CxPlatListRemoveHead(&Queue->PartitionTxQueue);
        XDP_TX_PACKET* Packet = CONTAINING_RECORD(Entry, XDP_TX_PACKET, Link);

        Buffer->Address.BaseAddress = (uint8_t*)Packet - Queue->TxBuffers;
        Buffer->Address.Offset = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        Buffer->Length = Packet->Buffer.Length;
        ProdCount++;
    }

    if ((ProdCount > 0 && (XskRingProducerSubmit(&Queue->TxRing, ProdCount), TRUE)) ||
        (CompCount > 0 && XskRingProducerReserve(&Queue->TxRing, MAXUINT32, &TxIndex) != Queue->TxRing.Size)) {
        MemoryBarrier();
        if (Xdp->TxAlwaysPoke || XskRingProducerNeedPoke(&Queue->TxRing)) {
            XSK_NOTIFY_RESULT_FLAGS OutFlags;
            QUIC_STATUS Status = Xdp->XdpApi->XskNotifySocket(Queue->TxXsk, XSK_NOTIFY_FLAG_POKE_TX, 0, &OutFlags);
            CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
            UNREFERENCED_PARAMETER(Status);
        }
    }

    if (XskRingError(&Queue->TxRing) && !Queue->Error) {
        XSK_ERROR ErrorStatus;
        QUIC_STATUS XskStatus;
        uint32_t ErrorSize = sizeof(ErrorStatus);
        XskStatus = Xdp->XdpApi->XskGetSockopt(Queue->TxXsk, XSK_SOCKOPT_TX_ERROR, &ErrorStatus, &ErrorSize);
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SUCCEEDED(XskStatus) ? ErrorStatus : XskStatus,
            "XSK_SOCKOPT_TX_ERROR");
        Queue->Error = TRUE;
    }

    return ProdCount > 0 || CompCount > 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    )
{
    XDP_PARTITION* Partition = (XDP_PARTITION*)Context;
    const XDP_DATAPATH* Xdp = Partition->Xdp;

    if (!Xdp->Running) {
        QuicTraceLogVerbose(
            XdpPartitionShutdown,
            "[ xdp][%p] XDP partition shutdown",
            Partition);
        XDP_QUEUE* Queue = Partition->Queues;
        while (Queue) {
            CancelIoEx(Queue->RxXsk, NULL);
            CloseHandle(Queue->RxXsk);
            Queue->RxXsk = NULL;
            CancelIoEx(Queue->TxXsk, NULL);
            CloseHandle(Queue->TxXsk);
            Queue->TxXsk = NULL;
            Queue = Queue->Next;
        }
        CxPlatEventQEnqueue(Partition->EventQ, &Partition->ShutdownSqe.Sqe, &Partition->ShutdownSqe);
        return FALSE;
    }

    const BOOLEAN PollingExpired =
        CxPlatTimeDiff64(State->LastWorkTime, State->TimeNow) >= Xdp->PollingIdleTimeoutUs;

    BOOLEAN DidWork = FALSE;
    XDP_QUEUE* Queue = Partition->Queues;
    while (Queue) {
        DidWork |= CxPlatXdpRx(Xdp, Queue, Partition->PartitionIndex);
        DidWork |= CxPlatXdpTx(Xdp, Queue);
        Queue = Queue->Next;
    }

    if (DidWork) {
        Partition->Ec.Ready = TRUE;
        State->NoWorkCount = 0;
    } else if (!PollingExpired) {
        Partition->Ec.Ready = TRUE;
    } else {
        Queue = Partition->Queues;
        while (Queue) {
            if (!Queue->RxQueued) {
                QuicTraceLogVerbose(
                    XdpQueueAsyncIoRx,
                    "[ xdp][%p] XDP async IO start (RX)",
                    Queue);
                CxPlatZeroMemory(
                    &Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped,
                    sizeof(Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped));
                HRESULT hr =
                    Xdp->XdpApi->XskNotifyAsync(
                        Queue->RxXsk, XSK_NOTIFY_FLAG_WAIT_RX,
                        &Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped);
                if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                    Queue->RxQueued = TRUE;
                } else if (hr == S_OK) {
                    Partition->Ec.Ready = TRUE;
                } else {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        hr,
                        "XskNotifyAsync(RX)");
                }
            }
            if (!Queue->TxQueued) {
                QuicTraceLogVerbose(
                    XdpQueueAsyncIoTx,
                    "[ xdp][%p] XDP async IO start (TX)",
                    Queue);
                CxPlatZeroMemory(
                    &Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped,
                    sizeof(Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped));
                HRESULT hr =
                    Xdp->XdpApi->XskNotifyAsync(
                        Queue->TxXsk, XSK_NOTIFY_FLAG_WAIT_TX,
                        &Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped);
                if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                    Queue->TxQueued = TRUE;
                } else if (hr == S_OK) {
                    Partition->Ec.Ready = TRUE;
                } else {
                    QuicTraceEvent(
                        LibraryErrorStatus,
                        "[ lib] ERROR, %u, %s.",
                        hr,
                        "XskNotifyAsync(TX)");
                }
            }
            Queue = Queue->Next;
        }
    }

    return TRUE;
}

void
RawDataPathProcessCqe(
    _In_ CXPLAT_CQE* Cqe
    )
{
    if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_IO) {
        DATAPATH_XDP_IO_SQE* Sqe =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), DATAPATH_XDP_IO_SQE, DatapathSqe);
        XDP_QUEUE* Queue;

        if (Sqe->IoType == DATAPATH_XDP_IO_RECV) {
            Queue = CONTAINING_RECORD(Sqe, XDP_QUEUE, RxIoSqe);
            QuicTraceLogVerbose(
                XdpQueueAsyncIoRxComplete,
                "[ xdp][%p] XDP async IO complete (RX)",
                Queue);
            Queue->RxQueued = FALSE;
        } else {
            CXPLAT_DBG_ASSERT(Sqe->IoType == DATAPATH_XDP_IO_SEND);
            Queue = CONTAINING_RECORD(Sqe, XDP_QUEUE, TxIoSqe);
            QuicTraceLogVerbose(
                XdpQueueAsyncIoTxComplete,
                "[ xdp][%p] XDP async IO complete (TX)",
                Queue);
            Queue->TxQueued = FALSE;
        }
        Queue->Partition->Ec.Ready = TRUE;
    } else if (CxPlatCqeType(Cqe) == CXPLAT_CQE_TYPE_SOCKET_SHUTDOWN) {
        XDP_PARTITION* Partition =
            CONTAINING_RECORD(CxPlatCqeUserData(Cqe), XDP_PARTITION, ShutdownSqe);
        QuicTraceLogVerbose(
            XdpPartitionShutdownComplete,
            "[ xdp][%p] XDP partition shutdown complete",
            Partition);
        CxPlatDpRawRelease((XDP_DATAPATH*)Partition->Xdp);
    }
}
