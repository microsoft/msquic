/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC XDP Datapath Implementation (Kernel Mode)

--*/

#define _CRT_SECURE_NO_WARNINGS 1 // TODO - Remove

#include "datapath_raw_win.h"
#include <initguid.h>
#include "datapath_raw_xdp.h"
#include <afxdp_helper.h>
#include <xdpapi.h>
#include <xdpapi_experimental.h>
#include <stdio.h>

#ifdef QUIC_CLOG
#include "datapath_raw_xdp_winkernel.c.clog.h"
#endif

const NPI_MODULEID NPI_MSQUIC_MODULEID = {
    sizeof(NPI_MODULEID),
    MIT_GUID,
    { 0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

_IRQL_requires_max_(DISPATCH_LEVEL)
XDP_STATUS
XskNotifyCallback(
    _In_ VOID* ClientContext,
    _In_ XSK_NOTIFY_RESULT_FLAGS Result
    )
{
    CXPLAT_SQE* Sqe;
    DATAPATH_SQE* DpSqe;
    DATAPATH_XDP_IO_SQE* DpXdpIoSqe;
    XDP_QUEUE* Queue = NULL;

    Sqe = CXPLAT_CONTAINING_RECORD(ClientContext, CXPLAT_SQE, Overlapped);

    DpSqe = CXPLAT_CONTAINING_RECORD(Sqe, DATAPATH_SQE, Sqe);
    CXPLAT_DBG_ASSERT(DpSqe->CqeType == CXPLAT_CQE_TYPE_SOCKET_IO);

    DpXdpIoSqe = CXPLAT_CONTAINING_RECORD(DpSqe, DATAPATH_XDP_IO_SQE, DatapathSqe);

    if (Result == XSK_NOTIFY_RESULT_FLAG_RX_AVAILABLE) {
        // ClientContext = &Queue->RxIoSqe.DatapathSqe.Sqe.Overlapped

        CXPLAT_DBG_ASSERT(DpXdpIoSqe->IoType == DATAPATH_XDP_IO_RECV);

        Queue = CXPLAT_CONTAINING_RECORD(DpXdpIoSqe, XDP_QUEUE, RxIoSqe);

        // QuicTraceLogInfo(
        //     LogInfo,
        //     "[ xdp] INFO, Queueing RX IO.");
    } else if (Result == XSK_NOTIFY_RESULT_FLAG_TX_COMP_AVAILABLE) {
        // ClientContext = &Queue->TxIoSqe.DatapathSqe.Sqe.Overlapped

        CXPLAT_DBG_ASSERT(DpXdpIoSqe->IoType == DATAPATH_XDP_IO_SEND);

        Queue = CXPLAT_CONTAINING_RECORD(DpXdpIoSqe, XDP_QUEUE, TxIoSqe);

        // QuicTraceLogInfo(
        //     LogInfo,
        //     "[ xdp] INFO, Queueing TX IO.");
    } else {
        // RX and TX have their own XSKs, so we should only be getting notified for RX or TX (?).
        CXPLAT_DBG_ASSERT(FALSE);
    }

    CxPlatEventQEnqueue(Queue->Partition->EventQ, Sqe, DpSqe);

    return STATUS_SUCCESS;
}

static const XDP_API_CLIENT_DISPATCH NmrXdpApiClientDispatch = {
    XskNotifyCallback
};

//
// Notify provider attach code.
//
NTSTATUS
NmrAttachXdpApiProvider(
    HANDLE NmrBindingHandle,
    PVOID ClientContext,
    PNPI_REGISTRATION_INSTANCE ProviderRegistrationInstance
    )
{
    NTSTATUS Status;
    XDP_DATAPATH* Xdp = ClientContext;

    //
    // Check if this provider interface is suitable.
    //
    if (ProviderRegistrationInstance->Number != XDP_API_VERSION_1) {
        Status = STATUS_NOINTERFACE;
        goto Exit;
    }

    // Only bind to a single provider
    if (Xdp->XdpApi != NULL) {
        Status = STATUS_NOINTERFACE;
        goto Exit;
    }

    Xdp->NmrBindingHandle = NmrBindingHandle;

    //
    // Attach to the provider.
    //
    Status =
        NmrClientAttachProvider(
            Xdp->NmrBindingHandle,
            Xdp,                            // ClientBindingContext
            &NmrXdpApiClientDispatch,       // ClientDispatch
            &Xdp->Npi.Handle,    // ProviderBindingContext
            &Xdp->Npi.Dispatch); // ProviderDispatch
    if (!NT_SUCCESS(Status)) {
        goto Exit;
    }

    //
    // The client can now make calls into the provider.
    //
    Xdp->XdpApi = (XDP_API_PROVIDER_DISPATCH *)Xdp->Npi.Dispatch;
    Xdp->XdpApiProviderBindingContext = Xdp->Npi.Handle;
    KeSetEvent(&Xdp->BoundToProvider, 0, FALSE);

Exit:

    return Status;
}

//
// Notify provider detach code.
//
NTSTATUS
NmrDetachXdpApiProvider(
    PVOID ClientBindingContext
    )
{
    XDP_DATAPATH* Xdp = (XDP_DATAPATH*) ClientBindingContext;

    //
    // Initiate the closure of all XDPAPI handles.
    //

    // return STATUS_PENDING;

    Xdp->XdpApiProviderBindingContext = NULL;
    Xdp->XdpApi = NULL;
    KeResetEvent(&Xdp->BoundToProvider);

    return STATUS_SUCCESS;
}

VOID
NmrCleanupXdpApiBindingContext(
    PVOID ClientBindingContext
    )
{
    UNREFERENCED_PARAMETER(ClientBindingContext);
}

QUIC_STATUS
CxPlatGetInterfaceRssQueueCount(
    _In_ XDP_DATAPATH* Xdp,
    _In_ HANDLE XdpHandle,
    _In_ uint32_t InterfaceIndex,
    _Out_ uint16_t* Count
    )
{
    NTSTATUS Status;
    XDP_RSS_GET_FN* XdpRssGet;
    XDP_RSS_CONFIGURATION* RssConfig = NULL;
    UINT8* RssTable = NULL;

    *Count = 0;

    UNREFERENCED_PARAMETER(InterfaceIndex);

    XdpRssGet = (XDP_RSS_GET_FN*)Xdp->XdpApi->XdpGetRoutine(XDP_RSS_GET_FN_NAME);
    if (XdpRssGet == NULL) {
        return QUIC_STATUS_NOT_FOUND;
    }

    uint32_t RssConfigSize = 0;
    Status = XdpRssGet(XdpHandle, NULL, &RssConfigSize);
    if (Status != STATUS_BUFFER_OVERFLOW) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    RssConfig = CXPLAT_ALLOC_NONPAGED(RssConfigSize, RSS_TAG);
    if (RssConfig == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    Status = XdpRssGet(XdpHandle, RssConfig, &RssConfigSize);
    if (Status == STATUS_SUCCESS) {
        // Set up the RSS table according to number of procs and proc groups.
        ULONG NumberOfProcs = CxPlatProcCount();
        USHORT NumberOfProcGroups = KeQueryActiveGroupCount();
        ULONG RssTableSize = NumberOfProcs * NumberOfProcGroups;

        RssTable = CXPLAT_ALLOC_NONPAGED(RssTableSize, RSS_TAG);
        if (RssTable == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
        CxPlatZeroMemory(RssTable, RssTableSize);

        PROCESSOR_NUMBER* IndirectionTable = (PROCESSOR_NUMBER*)((UCHAR*)RssConfig + RssConfig->IndirectionTableOffset);
        for (int i = 0; i < RssConfig->IndirectionTableSize / sizeof(PROCESSOR_NUMBER); i++) {
            *(RssTable + IndirectionTable[i].Group * NumberOfProcs + IndirectionTable[i].Number) = 1;
        }

        for (ULONG i = 0; i < RssTableSize; i++) {
            *Count += RssTable[i];
        }
    }

Exit:

    if (RssTable != NULL) {
        CXPLAT_FREE(RssTable, RSS_TAG);
    }
    if (RssConfig != NULL) {
        CXPLAT_FREE(RssConfig, RSS_TAG);
    }

    return Status;
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
    Xdp->RxBufferCount = 8192 << 2; // temporarily increased to 32k
    Xdp->RxRingSize = 256;
    Xdp->TxBufferCount = 8192 << 2; // temporarily increased to 32k
    Xdp->TxRingSize = 256;
    Xdp->TxAlwaysPoke = FALSE;
}

const NPI_CLIENT_CHARACTERISTICS NmrXdpApiClientCharacteristics = {
    0, // Version
    sizeof(NPI_CLIENT_CHARACTERISTICS),
    (PNPI_CLIENT_ATTACH_PROVIDER_FN)NmrAttachXdpApiProvider,
    (PNPI_CLIENT_DETACH_PROVIDER_FN)NmrDetachXdpApiProvider,
    (PNPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN)NmrCleanupXdpApiBindingContext,
    {
        0, // Version
        sizeof(NPI_REGISTRATION_INSTANCE),
        &NPI_XDPAPI_INTERFACE_ID,
        &NPI_MSQUIC_MODULEID,
        XDP_API_VERSION_1, // Number
        NULL // NpiSpecificCharacteristics
    } // ClientRegistrationInstance
};

QUIC_STATUS
CxPlatXdpInitialize(
    _In_ XDP_DATAPATH* Xdp
    )
{
    NTSTATUS Status;

    KeInitializeEvent(&Xdp->BoundToProvider, NotificationEvent, FALSE);

    Status =
        NmrRegisterClient(
            &NmrXdpApiClientCharacteristics,
            Xdp,
            &Xdp->NmrRegistrationHandle);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    uint32_t TimeoutMs = 2000;
    LARGE_INTEGER Timeout100Ns;
    Timeout100Ns.QuadPart = Int32x32To64(TimeoutMs, -10000);
    Status = KeWaitForSingleObject(&Xdp->BoundToProvider, Executive, KernelMode, FALSE, &Timeout100Ns);
    if (!KeReadStateEvent(&Xdp->BoundToProvider)) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    return QUIC_STATUS_SUCCESS;
}

VOID
CxPlatXdpUninitialize(
    _In_ XDP_DATAPATH* Xdp
    )
{
    if (Xdp->NmrRegistrationHandle != NULL) {
        NTSTATUS Status = NmrDeregisterClient(Xdp->NmrRegistrationHandle);
        ASSERT(Status == STATUS_PENDING);

        if (Status == STATUS_PENDING) {
            Status = NmrWaitForClientDeregisterComplete(Xdp->NmrRegistrationHandle);
            ASSERT(Status == STATUS_SUCCESS);
        }

        Xdp->NmrRegistrationHandle = NULL;
    }
}

QUIC_STATUS
CxPlatXdpDiscoverInterfaces(
    _In_ XDP_DATAPATH* Xdp,
    _In_ uint32_t ClientRecvContextLength,
    _In_ CXPLAT_XDP_CREATE_INTERFACE_FN CreateInterface
    )
{
    QUIC_STATUS Status;
    NTSTATUS NtStatus;

    PMIB_IF_TABLE2 pIfTable = NULL;
    NtStatus = GetIfTable2(&pIfTable);
    if (NtStatus != STATUS_SUCCESS) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            NtStatus,
            "GetIfTable2");
        goto Error;
    }

    Status = QUIC_STATUS_SUCCESS;

    for (int i = 0; i < (int) pIfTable->NumEntries; i++) {
        MIB_IF_ROW2* pIfRow = &pIfTable->Table[i];
        if (pIfRow->Type == IF_TYPE_ETHERNET_CSMACD &&
            pIfRow->OperStatus == IfOperStatusUp &&
            pIfRow->PhysicalAddressLength == ETH_MAC_ADDR_LEN) {
            Status =
                CreateInterface(
                    Xdp, pIfRow->InterfaceIndex, pIfRow->InterfaceIndex, pIfRow->PhysicalAddress, ClientRecvContextLength);
            if (QUIC_FAILED(Status)) {
                goto Error;
            }
        }
    }

Error:

    if (pIfTable != NULL) {
        FreeMibTable(pIfTable);
    }

    return Status;
}


XDP_STATUS
CxPlatXdpCreateXsk(
    _In_ const XDP_DATAPATH* Xdp,
    _Out_ HANDLE* Xsk
    )
{
    return Xdp->XdpApi->XskCreate(Xdp->XdpApiProviderBindingContext, Xsk);
}

XDP_STATUS
CxPlatXdpXskSetSockopt(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t OptionName,
    _In_ void* OptionValue,
    _In_ uint32_t OptionLength
    )
{
    return Xdp->XdpApi->XskSetSockopt(Xsk, OptionName, OptionValue, OptionLength);
}

XDP_STATUS
CxPlatXdpXskGetSockopt(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t OptionName,
    _Out_writes_bytes_(*OptionLength) void* OptionValue,
    _Inout_ uint32_t* OptionLength
    )
{
    return Xdp->XdpApi->XskGetSockopt(Xsk, OptionName, OptionValue, OptionLength);
}

XDP_STATUS
CxPlatXdpXskBind(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ uint32_t IfIndex,
    _In_ uint32_t QueueId,
    _In_ XSK_BIND_FLAGS Flags
    )
{
    return Xdp->XdpApi->XskBind(Xsk, IfIndex, QueueId, Flags);
}

XDP_STATUS
CxPlatXdpXskActivate(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ XSK_ACTIVATE_FLAGS Flags
    )
{
    return Xdp->XdpApi->XskActivate(Xsk, Flags);
}

XDP_STATUS
CxPlatXdpXskPokeTx(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk
    )
{
    XSK_NOTIFY_RESULT_FLAGS OutFlags;
    return Xdp->XdpApi->XskNotifySocket(Xsk, XSK_NOTIFY_FLAG_POKE_TX, 0, &OutFlags);
}

XDP_STATUS
CxPlatXdpXskNotifyAsync(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk,
    _In_ XSK_NOTIFY_FLAGS Flags,
    _Inout_ XSK_COMPLETION_CONTEXT CompletionContext,
    _Out_ XSK_NOTIFY_RESULT_FLAGS* Result
    )
{
    return Xdp->XdpApi->XskNotifyAsync2(Xsk, Flags, CompletionContext, Result);
}

VOID
CxPlatXdpCloseXsk(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Xsk
    )
{
    Xdp->XdpApi->XskDelete(Xsk);
}

XDP_STATUS
CxPlatXdpCreateProgram(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ uint32_t InterfaceIndex,
    _In_ CONST XDP_HOOK_ID* HookId,
    _In_ uint32_t QueueId,
    _In_ XDP_CREATE_PROGRAM_FLAGS Flags,
    _In_reads_(RuleCount) CONST XDP_RULE* Rules,
    _In_ uint32_t RuleCount,
    _Out_ HANDLE* Program
    )
{
    return
        Xdp->XdpApi->XdpCreateProgram(
            Xdp->XdpApiProviderBindingContext,
            InterfaceIndex,
            HookId,
            QueueId,
            Flags,
            Rules,
            RuleCount,
            Program);
}

VOID
CxPlatXdpCloseProgram(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Program
    )
{
    Xdp->XdpApi->XdpDeleteProgram(Program);
}

XDP_STATUS
CxPlatXdpOpenInterface(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ uint32_t IfIndex,
    _Out_ HANDLE* Interface
    )
{
    return Xdp->XdpApi->XdpInterfaceOpen(IfIndex, Interface);
}

VOID
CxPlatXdpCloseInterface(
    _In_ const XDP_DATAPATH* Xdp,
    _In_ HANDLE Interface
    )
{
    Xdp->XdpApi->XdpInterfaceClose(Interface);
}