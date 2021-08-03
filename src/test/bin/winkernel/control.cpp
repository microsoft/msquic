/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Test Driver

--*/

#define QUIC_TEST_CREATE 1

#include "quic_platform.h"
#include "MsQuicTests.h"
#include <new.h>

#include "quic_trace.h"
#ifdef QUIC_CLOG
#include "control.cpp.clog.h"
#endif

const MsQuicApi* MsQuic;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;
QUIC_CERTIFICATE_HASH SelfSignedCertHash;
QUIC_CERTIFICATE_HASH ClientCertHash;
QUIC_TEST_FN QuicTests::List[256];
uint32_t QuicTests::Count = 0;

#ifdef PRIVATE_LIBRARY
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceName, L"\\Device\\" QUIC_DRIVER_NAME_PRIVATE);
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceSymLink, L"\\DosDevices\\" QUIC_DRIVER_NAME_PRIVATE);
#else
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceName, L"\\Device\\" QUIC_DRIVER_NAME);
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceSymLink, L"\\DosDevices\\" QUIC_DRIVER_NAME);
#endif

typedef struct QUIC_DEVICE_EXTENSION {
    EX_PUSH_LOCK Lock;

    _Guarded_by_(Lock)
    LIST_ENTRY ClientList;
    ULONG ClientListSize;

} QUIC_DEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_DEVICE_EXTENSION, QuicTestCtlGetDeviceContext);

typedef struct QUIC_TEST_CLIENT
{
    LIST_ENTRY Link;
    bool TestFailure;

} QUIC_TEST_CLIENT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUIC_TEST_CLIENT, QuicTestCtlGetFileContext);

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL QuicTestCtlEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE QuicTestCtlEvtIoCanceled;

PAGEDX EVT_WDF_DEVICE_FILE_CREATE QuicTestCtlEvtFileCreate;
PAGEDX EVT_WDF_FILE_CLOSE QuicTestCtlEvtFileClose;
PAGEDX EVT_WDF_FILE_CLEANUP QuicTestCtlEvtFileCleanup;

WDFDEVICE QuicTestCtlDevice = nullptr;
QUIC_DEVICE_EXTENSION* QuicTestCtlExtension = nullptr;
QUIC_TEST_CLIENT* QuicTestClient = nullptr;

_No_competing_thread_
INITCODE
NTSTATUS
QuicTestCtlInitialize(
    _In_ WDFDRIVER Driver
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWDFDEVICE_INIT DeviceInit = nullptr;
    WDF_FILEOBJECT_CONFIG FileConfig;
    WDF_OBJECT_ATTRIBUTES Attribs;
    WDFDEVICE Device;
    QUIC_DEVICE_EXTENSION* DeviceContext;
    WDF_IO_QUEUE_CONFIG QueueConfig;
    WDFQUEUE Queue;

    MsQuic = new (std::nothrow) MsQuicApi();
    if (!MsQuic) {
        goto Error;
    }
    if (QUIC_FAILED(MsQuic->GetInitStatus())) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            MsQuic->GetInitStatus(),
            "MsQuicOpen");
        goto Error;
    }

    DeviceInit =
        WdfControlDeviceInitAllocate(
            Driver,
            &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (DeviceInit == nullptr) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfControlDeviceInitAllocate failed");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error;
    }

    Status =
        WdfDeviceInitAssignName(
            DeviceInit,
            &QuicTestCtlDeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceInitAssignName failed");
        goto Error;
    }

    WDF_FILEOBJECT_CONFIG_INIT(
        &FileConfig,
        QuicTestCtlEvtFileCreate,
        QuicTestCtlEvtFileClose,
        QuicTestCtlEvtFileCleanup);
    FileConfig.FileObjectClass = WdfFileObjectWdfCanUseFsContext2;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attribs, QUIC_TEST_CLIENT);
    WdfDeviceInitSetFileObjectConfig(
        DeviceInit,
        &FileConfig,
        &Attribs);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attribs, QUIC_DEVICE_EXTENSION);

    Status =
        WdfDeviceCreate(
            &DeviceInit,
            &Attribs,
            &Device);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreate failed");
        goto Error;
    }

    DeviceContext = QuicTestCtlGetDeviceContext(Device);
    RtlZeroMemory(DeviceContext, sizeof(QUIC_DEVICE_EXTENSION));
    ExInitializePushLock(&DeviceContext->Lock);
    InitializeListHead(&DeviceContext->ClientList);

    Status = WdfDeviceCreateSymbolicLink(Device, &QuicTestCtlDeviceSymLink);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfDeviceCreateSymbolicLink failed");
        goto Error;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);
    QueueConfig.EvtIoDeviceControl = QuicTestCtlEvtIoDeviceControl;
    QueueConfig.EvtIoCanceledOnQueue = QuicTestCtlEvtIoCanceled;

    __analysis_assume(QueueConfig.EvtIoStop != 0);
    Status =
        WdfIoQueueCreate(
            Device,
            &QueueConfig,
            WDF_NO_OBJECT_ATTRIBUTES,
            &Queue);
    __analysis_assume(QueueConfig.EvtIoStop == 0);

    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfIoQueueCreate failed");
        goto Error;
    }

    QuicTestCtlDevice = Device;
    QuicTestCtlExtension = DeviceContext;

    WdfControlFinishInitializing(Device);

    QuicTraceLogVerbose(
        TestControlInitialized,
        "[test] Control interface initialized");

Error:

    if (DeviceInit) {
        WdfDeviceInitFree(DeviceInit);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
QuicTestCtlUninitialize(
    )
{
    QuicTraceLogVerbose(
        TestControlUninitializing,
        "[test] Control interface uninitializing");

    if (QuicTestCtlDevice != nullptr) {
        NT_ASSERT(QuicTestCtlExtension != nullptr);
        QuicTestCtlExtension = nullptr;

        WdfObjectDelete(QuicTestCtlDevice);
        QuicTestCtlDevice = nullptr;
    }

    delete MsQuic;

    QuicTraceLogVerbose(
        TestControlUninitialized,
        "[test] Control interface uninitialized");
}

PAGEDX
_Use_decl_annotations_
VOID
QuicTestCtlEvtFileCreate(
    _In_ WDFDEVICE /* Device */,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    KeEnterGuardedRegion();
    ExfAcquirePushLockExclusive(&QuicTestCtlExtension->Lock);

    do
    {
        if (QuicTestCtlExtension->ClientListSize >= 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Already have max clients");
            Status = STATUS_TOO_MANY_SESSIONS;
            break;
        }

        QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
        if (Client == nullptr) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "nullptr File context in FileCreate");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Client, sizeof(QUIC_TEST_CLIENT));

        //
        // Insert into the client list
        //
        InsertTailList(&QuicTestCtlExtension->ClientList, &Client->Link);
        QuicTestCtlExtension->ClientListSize++;

        QuicTraceLogInfo(
            TestControlClientCreated,
            "[test] Client %p created",
            Client);

        //
        // TODO: Add multiple device client support?
        //
        QuicTestClient = Client;
    }
    while (false);

    ExfReleasePushLockExclusive(&QuicTestCtlExtension->Lock);
    KeLeaveGuardedRegion();

    WdfRequestComplete(Request, Status);
}

PAGEDX
_Use_decl_annotations_
VOID
QuicTestCtlEvtFileClose(
    _In_ WDFFILEOBJECT /* FileObject */
    )
{
    PAGED_CODE();
}

PAGEDX
_Use_decl_annotations_
VOID
QuicTestCtlEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
    )
{
    PAGED_CODE();

    KeEnterGuardedRegion();

    QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
    if (Client != nullptr) {

        ExfAcquirePushLockExclusive(&QuicTestCtlExtension->Lock);

        //
        // Remove the device client from the list
        //
        RemoveEntryList(&Client->Link);
        QuicTestCtlExtension->ClientListSize--;

        ExfReleasePushLockExclusive(&QuicTestCtlExtension->Lock);

        QuicTraceLogInfo(
            TestControlClientCleaningUp,
            "[test] Client %p cleaning up",
            Client);

        ServerSelfSignedCredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
        QuicTestClient = nullptr;
    }

    KeLeaveGuardedRegion();
}

VOID
QuicTestCtlEvtIoCanceled(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request
    )
{
    NTSTATUS Status;

    WDFFILEOBJECT FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto error;
    }

    QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        goto error;
    }

    QuicTraceLogWarning(
        TestControlClientCanceledRequest,
        "[test] Client %p canceled request %p",
        Client,
        Request);

    Status = STATUS_CANCELLED;

error:

    WdfRequestComplete(Request, Status);
}

VOID
QuicTestCtlEvtIoDeviceControl(
    _In_ WDFQUEUE /* Queue */,
    _In_ WDFREQUEST Request,
    _In_ size_t /* OutputBufferLength */,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    WDFFILEOBJECT FileObject = nullptr;
    QUIC_TEST_CLIENT* Client = nullptr;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        Status = STATUS_NOT_SUPPORTED;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "IOCTL not supported greater than PASSIVE_LEVEL");
        goto Error;
    }

    FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfRequestGetFileObject failed");
        goto Error;
    }

    Client = QuicTestCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "QuicTestCtlGetFileContext failed");
        goto Error;
    }

    if (IoControlCode == IOCTL_QUIC_SET_CERT_PARAMS) {
        QUIC_DRIVER_ARGS_SET_CERTIFICATE* Params = nullptr;
        Status =
            WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(QUIC_DRIVER_ARGS_SET_CERTIFICATE),
                (void**)&Params,
                nullptr);
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "WdfRequestRetrieveInputBuffer failed");
            goto Error;
        } else if (Params == nullptr) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "WdfRequestRetrieveInputBuffer failed to return parameter buffer");
            Status = STATUS_INVALID_PARAMETER;
            goto Error;
        }
        ServerSelfSignedCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ServerSelfSignedCredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        ServerSelfSignedCredConfig.CertificateHash = &SelfSignedCertHash;
        ServerSelfSignedCredConfigClientAuth.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ServerSelfSignedCredConfigClientAuth.Flags =
            QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
            QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
            QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
        ServerSelfSignedCredConfigClientAuth.CertificateHash = &SelfSignedCertHash;
        RtlCopyMemory(&SelfSignedCertHash.ShaHash, &Params->ServerCertHash, sizeof(QUIC_CERTIFICATE_HASH));
        ClientCertCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ClientCertCredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        ClientCertCredConfig.CertificateHash = &ClientCertHash;
        RtlCopyMemory(&ClientCertHash.ShaHash, &Params->ClientCertHash, sizeof(QUIC_CERTIFICATE_HASH));
        Status = QUIC_STATUS_SUCCESS;
        goto Error;
    }

    ULONG FunctionCode = IoGetFunctionCodeFromCtlCode(IoControlCode);
    if (FunctionCode > QUIC_CTL_COUNT) {
        Status = STATUS_NOT_IMPLEMENTED;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            FunctionCode,
            "Invalid FunctionCode");
        goto Error;
    }

    if (InputBufferLength < sizeof(QUIC_TEST_ARGS)) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            FunctionCode,
            "Invalid buffer size for FunctionCode");
        goto Error;
    }

    QUIC_TEST_ARGS* Params = nullptr;
    Status =
        WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(QUIC_TEST_ARGS),
            (void**)&Params,
            nullptr);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "WdfRequestRetrieveInputBuffer failed");
        goto Error;
    } else if (Params == nullptr) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "WdfRequestRetrieveInputBuffer failed to return parameter buffer");
        Status = STATUS_INVALID_PARAMETER;
        goto Error;
    }
    CXPLAT_FRE_ASSERT(Params != nullptr);

    QuicTraceLogInfo(
        TestControlClientIoctl,
        "[test] Client %p executing IOCTL %u",
        Client,
        FunctionCode);

    if (ServerSelfSignedCredConfig.Type == QUIC_CREDENTIAL_TYPE_NONE) {
        Status = STATUS_INVALID_DEVICE_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Client didn't set Security Config");
        goto Error;
    }

    if (IoControlCode == IOCTL_QUIC_ConnectExpiredServerCertificate ||
        IoControlCode == IOCTL_QUIC_ConnectValidServerCertificate ||
        IoControlCode == IOCTL_QUIC_ConnectValidClientCertificate ||
        IoControlCode == IOCTL_QUIC_ConnectExpiredClientCertificate) {
        switch (Params->CredValidation.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidation.CredConfig.Principal = (const char*)Params->CredValidation.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidation.CredConfig.CertificateHash = &Params->CredValidation.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidation.CredConfig.CertificateHashStore = &Params->CredValidation.CertHashStore;
            break;
        }
    }

    if (FunctionCode > QuicTests::Count) {
        Status = STATUS_NOT_IMPLEMENTED;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Client didn't set Security Config");
        goto Error;
    }

    Client->TestFailure = false;
    QuicTests::List[FunctionCode-1](Params);
    Status = Client->TestFailure ? STATUS_FAIL_FAST_EXCEPTION : STATUS_SUCCESS;

Error:

    QuicTraceLogInfo(
        TestControlClientIoctlComplete,
        "[test] Client %p completing request, 0x%x",
        Client,
        Status);

    WdfRequestComplete(Request, Status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
LogTestFailure(
    _In_z_ const char *File,
    _In_z_ const char *Function,
    int Line,
    _Printf_format_string_ const char *Format,
    ...
    )
/*++

Routine Description:

    Records a test failure from the platform independent test code.

Arguments:

    File - The file where the failure occurred.

    Function - The function where the failure occurred.

    Line - The line (in File) where the failure occurred.

Return Value:

    None

--*/
{
    char Buffer[128];

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    QuicTestClient->TestFailure = true;

    va_list Args;
    va_start(Args, Format);
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, Format, Args);
    va_end(Args);

    QuicTraceLogError(
        TestDriverFailureLocation,
        "[test] File: %s, Function: %s, Line: %d",
        File,
        Function,
        Line);
    QuicTraceLogError(
        TestDriverFailure,
        "[test] FAIL: %s",
        Buffer);

#if QUIC_BREAK_TEST
    NT_FRE_ASSERT(FALSE);
#endif
}
