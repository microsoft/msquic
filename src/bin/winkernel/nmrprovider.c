#include "quic_platform.h"
#include <wdm.h>
#include "msquic.h"
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

MSQUIC_NMR_DISPATCH MsQuicNmrDispatch = {
    .Version = 0,
    .Reserved = 0,
    .MsQuicOpenVersion = MsQuicOpenVersion,
    .MsQuicClose = MsQuicClose,
};

NTSTATUS
MsQuicNmrProviderAttachClient(
    _In_ HANDLE NmrBindingHandle,
    _In_ VOID *ProviderContext,
    _In_ CONST NPI_REGISTRATION_INSTANCE *ClientRegistrationInstance,
    _In_ VOID *ClientBindingContext,
    _In_ CONST VOID *ClientDispatch,
    _Out_ VOID **ProviderBindingContext,
    _Out_ CONST VOID **ProviderDispatch
    )
{
    UNREFERENCED_PARAMETER(NmrBindingHandle);
    UNREFERENCED_PARAMETER(ProviderContext);
    UNREFERENCED_PARAMETER(ClientRegistrationInstance);
    UNREFERENCED_PARAMETER(ClientBindingContext);
    UNREFERENCED_PARAMETER(ClientDispatch);

    *ProviderBindingContext = NULL;
    *ProviderDispatch = &MsQuicNmrDispatch;
    return STATUS_SUCCESS;
}

NTSTATUS
MsQuicNmrProviderDetachClient(
    _In_ VOID *ProviderBindingContext
    )
{
    UNREFERENCED_PARAMETER(ProviderBindingContext);
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
