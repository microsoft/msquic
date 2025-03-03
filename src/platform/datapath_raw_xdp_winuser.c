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

    QuicTraceLogVerbose(
        XdpInitialize,
        "[ xdp][%p] XDP initialized, %u procs",
        Xdp,
        Xdp->PartitionCount);

Error:
    if (pIfTable != NULL) {
        FreeMibTable(pIfTable);
    }

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
