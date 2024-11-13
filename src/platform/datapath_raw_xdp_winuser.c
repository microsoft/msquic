/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_xdp_wincommon.h"
#include <wbemidl.h>

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_winuser.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
CxPlatXdpExecute(
    _Inout_ void* Context,
    _Inout_ CXPLAT_EXECUTION_STATE* State
    );

QUIC_STATUS
CxPlatGetRssQueueProcessors(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t InterfaceIndex,
    _Inout_ uint16_t* Count,
    _Out_writes_to_(*Count, *Count) uint32_t* Queues
    )
{
    UNREFERENCED_PARAMETER(Xdp);
    uint32_t TxRingSize = 1;
    XDP_TX_PACKET TxPacket = { 0 };
    CreateNoOpEthernetPacket(&TxPacket);

    for (uint16_t i = 0; i < *Count; ++i) {
        HANDLE TxXsk = NULL;
        QUIC_STATUS Status = XskCreate(&TxXsk);
        if (QUIC_FAILED(Status)) { return Status; }

        XSK_UMEM_REG TxUmem = {0};
        UINT32 EnableAffinity = 1;
        TxUmem.Address = &TxPacket;
        TxUmem.ChunkSize = sizeof(XDP_TX_PACKET);
        TxUmem.Headroom = FIELD_OFFSET(XDP_TX_PACKET, FrameBuffer);
        TxUmem.TotalSize = sizeof(XDP_TX_PACKET);

        Status = XskSetSockopt(TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

        Status = XskSetSockopt(TxXsk, XSK_SOCKOPT_TX_RING_SIZE, &TxRingSize, sizeof(TxRingSize));
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

        Status = XskSetSockopt(TxXsk, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &TxRingSize, sizeof(TxRingSize));
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

        Status = XskSetSockopt(TxXsk, XSK_SOCKOPT_TX_PROCESSOR_AFFINITY, &EnableAffinity, sizeof(EnableAffinity));
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

        uint32_t Flags = XSK_BIND_FLAG_TX;
        Status = XskBind(TxXsk, InterfaceIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            CxPlatCloseHandle(TxXsk);
            if (Status == QUIC_STATUS_INVALID_PARAMETER) { // No more queues. Break out.
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

        Status = XskActivate(TxXsk, 0);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskActivate (GetRssQueueProcessors)");
            CxPlatCloseHandle(TxXsk);
            return Status;
        }

        XSK_RING_INFO_SET TxRingInfo;
        uint32_t TxRingInfoSize = sizeof(TxRingInfo);
        Status = XskGetSockopt(TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

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
        Status = XskNotifySocket(TxXsk, XSK_NOTIFY_FLAG_POKE_TX|XSK_NOTIFY_FLAG_WAIT_TX, XDP_MAX_SYNC_WAIT_TIMEOUT_MS, &OutFlags);
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

        uint32_t CompIndex;
        if (XskRingConsumerReserve(&TxCompletionRing, MAXUINT32, &CompIndex) == 0) {
            CxPlatCloseHandle(TxXsk);
            return QUIC_STATUS_ABORTED;
        }
        XskRingConsumerRelease(&TxCompletionRing, 1);

        PROCESSOR_NUMBER ProcNumber;
        uint32_t ProcNumberSize = sizeof(PROCESSOR_NUMBER);
        Status = XskGetSockopt(TxXsk, XSK_SOCKOPT_TX_PROCESSOR_AFFINITY, &ProcNumber, &ProcNumberSize);
        if (QUIC_FAILED(Status)) { CxPlatCloseHandle(TxXsk); return Status; }

        const CXPLAT_PROCESSOR_GROUP_INFO* Group = &CxPlatProcessorGroupInfo[ProcNumber.Group];
        Queues[i] = Group->Offset + (ProcNumber.Number % Group->Count);

        CxPlatCloseHandle(TxXsk);
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

    Status = XdpInterfaceOpen(Interface->ActualIfIndex, &Interface->XdpHandle);
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

        Status = XskCreate(&Queue->RxXsk);
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

        Status = XskSetSockopt(Queue->RxXsk, XSK_SOCKOPT_UMEM_REG, &RxUmem, sizeof(RxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            XskSetSockopt(
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
            XskSetSockopt(
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
        Status = XskBind(Queue->RxXsk, Interface->ActualIfIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        Status = XskActivate(Queue->RxXsk, 0);
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
        Status = XskGetSockopt(Queue->RxXsk, XSK_SOCKOPT_RING_INFO, &RxRingInfo, &RxRingInfoSize);
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

        Status = XskCreate(&Queue->TxXsk);
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

        Status = XskSetSockopt(Queue->TxXsk, XSK_SOCKOPT_UMEM_REG, &TxUmem, sizeof(TxUmem));
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskSetSockopt(XSK_SOCKOPT_UMEM_REG)");
            goto Error;
        }

        Status =
            XskSetSockopt(
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
            XskSetSockopt(
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
        Status = XskBind(Queue->TxXsk, Interface->ActualIfIndex, i, Flags);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "XskBind");
            goto Error;
        }

        Status = XskActivate(Queue->TxXsk, 0);
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
        Status = XskGetSockopt(Queue->TxXsk, XSK_SOCKOPT_RING_INFO, &TxRingInfo, &TxRingInfoSize);
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
            CXPLAT_FREE(Adapters, ADAPTER_TAG);
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
                    CXPLAT_FREE(Interface, IF_TAG);
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
            CXPLAT_FREE(Interface, IF_TAG);
        }
    }

    return Status;
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
                    XskNotifyAsync(
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
                    XskNotifyAsync(
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
