/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    NMR provider for MsQuic.

--*/

#include "quic_platform.h"
#include <wdm.h>
#include "msquic.h"
#include "msquicp.h"
#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "nmrprovider.c.clog.h"
#endif

typedef struct MSQUIC_NMR_PROVIDER {
    NPI_PROVIDER_CHARACTERISTICS NpiProviderCharacteristics;
    HANDLE NmrProviderHandle;
    NPI_MODULEID ModuleId;
} MSQUIC_NMR_PROVIDER;

MSQUIC_NMR_PROVIDER NmrProvider;

const MSQUIC_NMR_DISPATCH MsQuicNmrDispatch = {
    .Version = 0,
    .Reserved = 0,
    .OpenVersion = MsQuicOpenVersion,
    .Close = MsQuicClose,
};

NTSTATUS
MsQuicNmrProviderAttachClient(
    _In_ HANDLE NmrBindingHandle,
    _In_ void *ProviderContext,
    _In_ const NPI_REGISTRATION_INSTANCE *ClientRegistrationInstance,
    _In_ void *ClientBindingContext,
    _In_ const void *ClientDispatch,
    _Out_ void **ProviderBindingContext,
    _Out_ const void **ProviderDispatch
    )
{
    UNREFERENCED_PARAMETER(ClientBindingContext);
    UNREFERENCED_PARAMETER(ProviderContext);
    UNREFERENCED_PARAMETER(ClientDispatch);

    *ProviderBindingContext = NmrBindingHandle;
    *ProviderDispatch = &MsQuicNmrDispatch;

    QuicTraceLogInfo(
        ProviderAttachClient,
        "[ nmr][%p] Client attached Ver %hu Size %hu Number %u ModuleID { %x-%x-%x-%llx }",
        NmrBindingHandle,
        ClientRegistrationInstance->Version,
        ClientRegistrationInstance->Size,
        ClientRegistrationInstance->Number,
        ClientRegistrationInstance->ModuleId->Guid.Data1,
        ClientRegistrationInstance->ModuleId->Guid.Data2,
        ClientRegistrationInstance->ModuleId->Guid.Data3,
        *((uint64_t*)ClientRegistrationInstance->ModuleId->Guid.Data4));
    return STATUS_SUCCESS;
}

NTSTATUS
MsQuicNmrProviderDetachClient(
    _In_ void *ProviderBindingContext
    )
{
    QuicTraceLogInfo(
        ProviderDetachClient,
        "[ nmr][%p] Client detached",
        ProviderBindingContext);
    return STATUS_SUCCESS;
}

_No_competing_thread_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
MsQuicRegisterNmrProvider(
    void
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    NPI_REGISTRATION_INSTANCE *ProviderRegistrationInstance;

    NmrProvider.ModuleId.Length = sizeof(NmrProvider.ModuleId);
    NmrProvider.ModuleId.Type = MIT_GUID;
    NmrProvider.ModuleId.Guid = MSQUIC_MODULE_ID;

    NmrProvider.NpiProviderCharacteristics.Version = 0;
    NmrProvider.NpiProviderCharacteristics.Length = sizeof(NmrProvider.NpiProviderCharacteristics);
    NmrProvider.NpiProviderCharacteristics.ProviderAttachClient = MsQuicNmrProviderAttachClient;
    NmrProvider.NpiProviderCharacteristics.ProviderDetachClient = MsQuicNmrProviderDetachClient;

#ifdef QUIC_TEST_NMR_PROVIDER
    QUIC_ENABLE_PRIVATE_NMR_PROVIDER();
#endif

    ProviderRegistrationInstance = &NmrProvider.NpiProviderCharacteristics.ProviderRegistrationInstance;
    ProviderRegistrationInstance->Version = 0;
    ProviderRegistrationInstance->Size = sizeof(*ProviderRegistrationInstance);
    ProviderRegistrationInstance->NpiId = &MSQUIC_NPI_ID;
    ProviderRegistrationInstance->ModuleId = &NmrProvider.ModuleId;

    Status =
        NmrRegisterProvider(
            &NmrProvider.NpiProviderCharacteristics,
            &NmrProvider,
            &NmrProvider.NmrProviderHandle);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NmrRegisterProvider");
        goto Exit;
    }

Exit:
    return Status;
}

void
MsQuicDeregisterNmrProvider(
    void
    )
{
    if (NmrProvider.NmrProviderHandle != NULL) {
        NTSTATUS Status = NmrDeregisterProvider(NmrProvider.NmrProviderHandle);
        CXPLAT_FRE_ASSERTMSG(Status == STATUS_PENDING, "deregistration failed");
        NmrWaitForProviderDeregisterComplete(NmrProvider.NmrProviderHandle);
        NmrProvider.NmrProviderHandle = NULL;
    }
}
