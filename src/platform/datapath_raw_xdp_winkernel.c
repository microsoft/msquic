/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (User Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_xdp_wincommon.h"

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_winkernel.c.clog.h"
#endif

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

    // TODO: implement config reader

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
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    PMIB_IF_TABLE2 pIfTable = NULL;

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

    if (QUIC_FAILED(GetIfTable2(&pIfTable))) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    for (ULONG i = 0; i < pIfTable->NumEntries; i++) {
        MIB_IF_ROW2* pIfRow = &pIfTable->Table[i];

        if (pIfRow->Type == IF_TYPE_ETHERNET_CSMACD &&
            pIfRow->OperStatus == IfOperStatusUp &&
            pIfRow->PhysicalAddressLength == ETH_MAC_ADDR_LEN &&
            pIfRow->InterfaceAndOperStatusFlags.ConnectorPresent) {
            XDP_INTERFACE* Interface = CXPLAT_ALLOC_NONPAGED(sizeof(XDP_INTERFACE), IF_TAG);
            if (Interface == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "XDP interface",
                    sizeof(*Interface));
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }
            RtlZeroMemory(Interface, sizeof(XDP_INTERFACE));
            Interface->ActualIfIndex = Interface->IfIndex = pIfRow->InterfaceIndex;
            RtlCopyMemory(
                Interface->PhysicalAddress,
                pIfRow->PhysicalAddress,
                min(pIfRow->PhysicalAddressLength, sizeof(Interface->PhysicalAddress))
            );

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

    if (CxPlatListIsEmpty(&Xdp->Interfaces)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "no XDP capable interface");
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    FILE_IO_COMPLETION_NOTIFICATION_INFORMATION IoCompletion = {0};
    IoCompletion.Flags = FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE;
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

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);

Exit:
    if (pIfTable != NULL) {
        FreeMibTable(pIfTable);
    }

    if (!NT_SUCCESS(Status)) {
        while (!CxPlatListIsEmpty(&Xdp->Interfaces)) {
            XDP_INTERFACE* Interface = CONTAINING_RECORD(CxPlatListRemoveHead(&Xdp->Interfaces), XDP_INTERFACE, Link);
            CxPlatDpRawInterfaceUninitialize(Interface);
            CXPLAT_FREE(Interface, IF_TAG);
        }
    }

    return Status;
}
