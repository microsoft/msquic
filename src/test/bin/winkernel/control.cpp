/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Test Driver

--*/

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
bool UseDuoNic = false;

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
            "MsQuicApi Constructor");
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
    ExAcquirePushLockExclusive(&QuicTestCtlExtension->Lock);

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

    ExReleasePushLockExclusive(&QuicTestCtlExtension->Lock);
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

        ExAcquirePushLockExclusive(&QuicTestCtlExtension->Lock);

        //
        // Remove the device client from the list
        //
        RemoveEntryList(&Client->Link);
        QuicTestCtlExtension->ClientListSize--;

        ExReleasePushLockExclusive(&QuicTestCtlExtension->Lock);

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

size_t QUIC_IOCTL_BUFFER_SIZES[] =
{
    0,
    sizeof(QUIC_RUN_CERTIFICATE_PARAMS),
    0,
    0,
    0,
    0,
    sizeof(UINT8),
    0,
    0,
    sizeof(INT32),
    0,
    0,
    sizeof(INT32),
    0,
    sizeof(INT32),
    sizeof(INT32),
    sizeof(QUIC_RUN_CONNECT_PARAMS),
    sizeof(QUIC_RUN_CONNECT_AND_PING_PARAMS),
    sizeof(UINT8),
    sizeof(QUIC_CERTIFICATE_HASH_STORE),
    sizeof(INT32),
    sizeof(INT32),
    sizeof(INT32),
    0,
    sizeof(UINT8),
    sizeof(uint32_t),
    sizeof(uint32_t),
    sizeof(INT32),
    sizeof(QUIC_RUN_KEY_UPDATE_PARAMS),
    0,
    sizeof(INT32),
    sizeof(QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS),
    sizeof(QUIC_RUN_CID_UPDATE_PARAMS),
    sizeof(QUIC_RUN_RECEIVE_RESUME_PARAMS),
    sizeof(QUIC_RUN_RECEIVE_RESUME_PARAMS),
    0,
    sizeof(QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS),
    sizeof(INT32),
    0,
    sizeof(QUIC_RUN_DATAGRAM_NEGOTIATION),
    sizeof(INT32),
    sizeof(QUIC_RUN_REBIND_PARAMS),
    sizeof(QUIC_RUN_REBIND_PARAMS),
    sizeof(INT32),
    sizeof(INT32),
    0,
    sizeof(INT32),
    sizeof(QUIC_RUN_CUSTOM_CERT_VALIDATION),
    sizeof(INT32),
    sizeof(INT32),
    sizeof(QUIC_RUN_VERSION_NEGOTIATION_EXT),
    sizeof(QUIC_RUN_VERSION_NEGOTIATION_EXT),
    sizeof(QUIC_RUN_VERSION_NEGOTIATION_EXT),
    sizeof(INT32),
    sizeof(INT32),
    0,
    sizeof(QUIC_RUN_CONNECT_CLIENT_CERT),
    0,
    0,
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_ABORT_RECEIVE_TYPE),
    sizeof(QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS),
    0,
    0,
    0,
    sizeof(QUIC_RUN_MTU_DISCOVERY_PARAMS),
    sizeof(INT32),
    sizeof(INT32),
    0,
    0,
    sizeof(INT32),
    0,
    sizeof(UINT8),
    sizeof(INT32),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    sizeof(QUIC_RUN_CRED_VALIDATION),
    sizeof(QUIC_RUN_CIBIR_EXTENSION),
    0,
    0,
    sizeof(INT32),
    0,
};

CXPLAT_STATIC_ASSERT(
    QUIC_MAX_IOCTL_FUNC_CODE + 1 == (sizeof(QUIC_IOCTL_BUFFER_SIZES)/sizeof(size_t)),
    "QUIC_IOCTL_BUFFER_SIZES must be kept in sync with the IOTCLs");

typedef union {
    QUIC_RUN_CERTIFICATE_PARAMS CertParams;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    UINT8 Connect;
    INT32 Family;
    QUIC_RUN_CONNECT_PARAMS Params1;
    QUIC_RUN_CONNECT_AND_PING_PARAMS Params2;
    QUIC_RUN_KEY_UPDATE_PARAMS Params3;
    QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS Params4;
    QUIC_RUN_CID_UPDATE_PARAMS Params5;
    QUIC_RUN_RECEIVE_RESUME_PARAMS Params6;
    UINT8 EnableKeepAlive;
    UINT8 StopListenerFirst;
    QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS DrillParams;
    QUIC_RUN_DATAGRAM_NEGOTIATION DatagramNegotiationParams;
    QUIC_RUN_CUSTOM_CERT_VALIDATION CustomCertValidationParams;
    QUIC_RUN_VERSION_NEGOTIATION_EXT VersionNegotiationExtParams;
    QUIC_RUN_CONNECT_CLIENT_CERT ConnectClientCertParams;
    QUIC_RUN_CRED_VALIDATION CredValidationParams;
    QUIC_ABORT_RECEIVE_TYPE AbortReceiveType;
    QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS KeyUpdateRandomLossParams;
    QUIC_RUN_MTU_DISCOVERY_PARAMS MtuDiscoveryParams;
    uint32_t Test;
    QUIC_RUN_REBIND_PARAMS RebindParams;
    UINT8 RejectByClosing;
    QUIC_RUN_CIBIR_EXTENSION CibirParams;

} QUIC_IOCTL_PARAMS;

#define QuicTestCtlRun(X) \
    Client->TestFailure = false; \
    X; \
    Status = Client->TestFailure ? STATUS_FAIL_FAST_EXCEPTION : STATUS_SUCCESS;

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

    ULONG FunctionCode = IoGetFunctionCodeFromCtlCode(IoControlCode);
    if (FunctionCode == 0 || FunctionCode > QUIC_MAX_IOCTL_FUNC_CODE) {
        Status = STATUS_NOT_IMPLEMENTED;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            FunctionCode,
            "Invalid FunctionCode");
        goto Error;
    }

    if (InputBufferLength < QUIC_IOCTL_BUFFER_SIZES[FunctionCode]) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            FunctionCode,
            "Invalid buffer size for FunctionCode");
        goto Error;
    }

    QUIC_IOCTL_PARAMS* Params = nullptr;
    if (QUIC_IOCTL_BUFFER_SIZES[FunctionCode] != 0) {
        Status =
            WdfRequestRetrieveInputBuffer(
                Request,
                QUIC_IOCTL_BUFFER_SIZES[FunctionCode],
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
    }

    QuicTraceLogInfo(
        TestControlClientIoctl,
        "[test] Client %p executing IOCTL %u",
        Client,
        FunctionCode);

    if (IoControlCode != IOCTL_QUIC_SET_CERT_PARAMS &&
        ServerSelfSignedCredConfig.Type == QUIC_CREDENTIAL_TYPE_NONE) {
        Status = STATUS_INVALID_DEVICE_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Client didn't set Security Config");
        goto Error;
    }

    switch (IoControlCode) {

    case IOCTL_QUIC_SET_CERT_PARAMS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        ServerSelfSignedCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ServerSelfSignedCredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
        ServerSelfSignedCredConfig.CertificateHash = &SelfSignedCertHash;
        ServerSelfSignedCredConfigClientAuth.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ServerSelfSignedCredConfigClientAuth.Flags =
            QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
            QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
            QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
        ServerSelfSignedCredConfigClientAuth.CertificateHash = &SelfSignedCertHash;
        RtlCopyMemory(&SelfSignedCertHash.ShaHash, &Params->CertParams.ServerCertHash, sizeof(QUIC_CERTIFICATE_HASH));
        ClientCertCredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        ClientCertCredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        ClientCertCredConfig.CertificateHash = &ClientCertHash;
        RtlCopyMemory(&ClientCertHash.ShaHash, &Params->CertParams.ClientCertHash, sizeof(QUIC_CERTIFICATE_HASH));
        Status = QUIC_STATUS_SUCCESS;
        break;

    case IOCTL_QUIC_RUN_VALIDATE_REGISTRATION:
        QuicTestCtlRun(QuicTestValidateRegistration());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_CONFIGURATION:
        QuicTestCtlRun(QuicTestValidateConfiguration());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_LISTENER:
        QuicTestCtlRun(QuicTestValidateListener());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_CONNECTION:
        QuicTestCtlRun(QuicTestValidateConnection());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_STREAM:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateStream(Params->Connect != 0));
        break;

    case IOCTL_QUIC_RUN_CREATE_LISTENER:
        QuicTestCtlRun(QuicTestCreateListener());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER:
        QuicTestCtlRun(QuicTestStartListener());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestStartListenerImplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_START_TWO_LISTENERS:
        QuicTestCtlRun(QuicTestStartTwoListeners());
        break;
    case IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN:
        QuicTestCtlRun(QuicTestStartTwoListenersSameALPN());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestStartListenerExplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_CREATE_CONNECTION:
        QuicTestCtlRun(QuicTestCreateConnection());
        break;
    case IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestBindConnectionImplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestBindConnectionExplicit(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnect(
                Params->Params1.Family,
                Params->Params1.ServerStatelessRetry != 0,
                Params->Params1.ClientUsesOldVersion != 0,
                Params->Params1.MultipleALPNs != 0,
                (QUIC_TEST_ASYNC_CONFIG_MODE)Params->Params1.AsyncConfiguration,
                Params->Params1.MultiPacketClientInitial != 0,
                (QUIC_TEST_RESUMPTION_MODE)Params->Params1.SessionResumption,
                Params->Params1.RandomLossPercentage
                ));
        break;

    case IOCTL_QUIC_RUN_CONNECT_AND_PING:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnectAndPing(
                Params->Params2.Family,
                Params->Params2.Length,
                Params->Params2.ConnectionCount,
                Params->Params2.StreamCount,
                Params->Params2.StreamBurstCount,
                Params->Params2.StreamBurstDelayMs,
                Params->Params2.ServerStatelessRetry != 0,
                Params->Params2.ClientRebind != 0,
                Params->Params2.ClientZeroRtt != 0,
                Params->Params2.ServerRejectZeroRtt != 0,
                Params->Params2.UseSendBuffer != 0,
                Params->Params2.UnidirectionalStreams != 0,
                Params->Params2.ServerInitiatedStreams != 0,
                Params->Params2.FifoScheduling != 0
                ));
        break;

    case IOCTL_QUIC_RUN_CONNECT_AND_IDLE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectAndIdle(Params->EnableKeepAlive != 0));
        break;

    case IOCTL_QUIC_RUN_CONNECT_UNREACHABLE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectUnreachable(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_BAD_ALPN:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectBadAlpn(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_BAD_SNI:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectBadSni(Params->Family));
        break;

    case IOCTL_QUIC_RUN_SERVER_DISCONNECT:
        QuicTestCtlRun(QuicTestServerDisconnect());
        break;

    case IOCTL_QUIC_RUN_CLIENT_DISCONNECT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestClientDisconnect(Params->StopListenerFirst));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateConnectionEvents(Params->Test));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateStreamEvents(Params->Test));
        break;

    case IOCTL_QUIC_RUN_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestVersionNegotiation(Params->Family));
        break;

    case IOCTL_QUIC_RUN_KEY_UPDATE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestKeyUpdate(
                Params->Params3.Family,
                Params->Params3.Iterations,
                Params->Params3.KeyUpdateBytes,
                Params->Params3.UseKeyUpdateBytes != 0,
                Params->Params3.ClientKeyUpdate != 0,
                Params->Params3.ServerKeyUpdate != 0));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_API:
        QuicTestCtlRun(QuicTestValidateApi());
        break;

    case IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectServerRejected(Params->Family));
        break;

    case IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicAbortiveTransfers(
                Params->Params4.Family,
                Params->Params4.Flags));
        break;

    case IOCTL_QUIC_RUN_CID_UPDATE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCidUpdate(
                Params->Params5.Family,
                Params->Params5.Iterations));
        break;

    case IOCTL_QUIC_RUN_RECEIVE_RESUME:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestReceiveResume(
                Params->Params6.Family,
                Params->Params6.SendBytes,
                Params->Params6.ConsumeBytes,
                Params->Params6.ShutdownType,
                Params->Params6.PauseType,
                Params->Params6.PauseFirst));
        break;

    case IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestReceiveResumeNoData(
                Params->Params6.Family,
                Params->Params6.ShutdownType));
        break;

    case IOCTL_QUIC_RUN_DRILL_ENCODE_VAR_INT:
        QuicTestCtlRun(
            QuicDrillTestVarIntEncoder());
        break;

    case IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_CID:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicDrillTestInitialCid(
                Params->DrillParams.Family,
                Params->DrillParams.SourceOrDest,
                Params->DrillParams.ActualCidLengthValid,
                Params->DrillParams.ShortCidLength,
                Params->DrillParams.CidLengthFieldValid));
        break;

    case IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicDrillTestInitialToken(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_START_LISTENER_MULTI_ALPN:
        QuicTestCtlRun(QuicTestStartListenerMultiAlpns());
        break;

    case IOCTL_QUIC_RUN_DATAGRAM_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestDatagramNegotiation(
                Params->DatagramNegotiationParams.Family,
                Params->DatagramNegotiationParams.DatagramReceiveEnabled));
        break;

    case IOCTL_QUIC_RUN_DATAGRAM_SEND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestDatagramSend(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_NAT_PORT_REBIND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestNatPortRebind(
                Params->RebindParams.Family,
                Params->RebindParams.Padding));
        break;

    case IOCTL_QUIC_RUN_NAT_ADDR_REBIND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestNatAddrRebind(
                Params->RebindParams.Family,
                Params->RebindParams.Padding));
        break;

    case IOCTL_QUIC_RUN_CHANGE_MAX_STREAM_ID:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestChangeMaxStreamID(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_PATH_VALIDATION_TIMEOUT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestPathValidationTimeout(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_GET_PERF_COUNTERS:
        QuicTestCtlRun(QuicTestGetPerfCounters());
        break;

    case IOCTL_QUIC_RUN_ACK_SEND_DELAY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestAckSendDelay(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CUSTOM_CERT_VALIDATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCustomCertificateValidation(
                Params->CustomCertValidationParams.AcceptCert,
                Params->CustomCertValidationParams.AsyncValidation));
        break;

    case IOCTL_QUIC_RUN_VERSION_NEGOTIATION_RETRY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestVersionNegotiationRetry(Params->Family));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_RETRY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestCompatibleVersionNegotiationRetry(Params->Family));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCompatibleVersionNegotiation(
                Params->VersionNegotiationExtParams.Family,
                Params->VersionNegotiationExtParams.DisableVNEClient,
                Params->VersionNegotiationExtParams.DisableVNEServer));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_SERVER:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCompatibleVersionNegotiationDefaultServer(
                Params->VersionNegotiationExtParams.Family,
                Params->VersionNegotiationExtParams.DisableVNEClient,
                Params->VersionNegotiationExtParams.DisableVNEServer));
        break;

    case IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_CLIENT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCompatibleVersionNegotiationDefaultClient(
                Params->VersionNegotiationExtParams.Family,
                Params->VersionNegotiationExtParams.DisableVNEClient,
                Params->VersionNegotiationExtParams.DisableVNEServer));
        break;

    case IOCTL_QUIC_RUN_INCOMPATIBLE_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestIncompatibleVersionNegotiation(Params->Family));
        break;

    case IOCTL_QUIC_RUN_FAILED_VERSION_NEGOTIATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestFailedVersionNegotiation(Params->Family));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_VERSION_SETTINGS_SETTINGS:
        QuicTestCtlRun(QuicTestVersionSettings());
        break;

    case IOCTL_QUIC_RUN_CONNECT_CLIENT_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnectClientCertificate(
                Params->ConnectClientCertParams.Family,
                Params->ConnectClientCertParams.UseClientCert));
        break;

    case IOCTL_QUIC_RUN_VALID_ALPN_LENGTHS:
        QuicTestCtlRun(QuicTestValidAlpnLengths());
        break;

    case IOCTL_QUIC_RUN_INVALID_ALPN_LENGTHS:
        QuicTestCtlRun(QuicTestInvalidAlpnLengths());
        break;

    case IOCTL_QUIC_RUN_EXPIRED_SERVER_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        //
        // Fix up pointers for kernel mode
        //
        switch (Params->CredValidationParams.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidationParams.CredConfig.Principal = (const char*)Params->CredValidationParams.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidationParams.CredConfig.CertificateHash = &Params->CredValidationParams.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidationParams.CredConfig.CertificateHashStore = &Params->CredValidationParams.CertHashStore;
            break;
        }
        QuicTestCtlRun(
            QuicTestConnectExpiredServerCertificate(
                &Params->CredValidationParams.CredConfig));
        break;

    case IOCTL_QUIC_RUN_VALID_SERVER_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        //
        // Fix up pointers for kernel mode
        //
        switch (Params->CredValidationParams.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidationParams.CredConfig.Principal = (const char*)Params->CredValidationParams.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidationParams.CredConfig.CertificateHash = &Params->CredValidationParams.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidationParams.CredConfig.CertificateHashStore = &Params->CredValidationParams.CertHashStore;
            break;
        }
        QuicTestCtlRun(
            QuicTestConnectValidServerCertificate(
                &Params->CredValidationParams.CredConfig));
        break;

    case IOCTL_QUIC_RUN_VALID_CLIENT_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        //
        // Fix up pointers for kernel mode
        //
        switch (Params->CredValidationParams.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidationParams.CredConfig.Principal = (const char*)Params->CredValidationParams.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidationParams.CredConfig.CertificateHash = &Params->CredValidationParams.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidationParams.CredConfig.CertificateHashStore = &Params->CredValidationParams.CertHashStore;
            break;
        }
        QuicTestCtlRun(
            QuicTestConnectValidClientCertificate(
                &Params->CredValidationParams.CredConfig));
        break;

    case IOCTL_QUIC_RUN_EXPIRED_CLIENT_CERT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        //
        // Fix up pointers for kernel mode
        //
        switch (Params->CredValidationParams.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidationParams.CredConfig.Principal = (const char*)Params->CredValidationParams.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidationParams.CredConfig.CertificateHash = &Params->CredValidationParams.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidationParams.CredConfig.CertificateHashStore = &Params->CredValidationParams.CertHashStore;
            break;
        }
        QuicTestCtlRun(
            QuicTestConnectExpiredClientCertificate(
                &Params->CredValidationParams.CredConfig));
        break;

    case IOCTL_QUIC_RUN_ABORT_RECEIVE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestAbortReceive(Params->AbortReceiveType));
        break;

    case IOCTL_QUIC_RUN_KEY_UPDATE_RANDOM_LOSS:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestKeyUpdateRandomLoss(
                Params->KeyUpdateRandomLossParams.Family,
                Params->KeyUpdateRandomLossParams.RandomLossPercentage))
        break;

    case IOCTL_QUIC_RUN_SLOW_RECEIVE:
        QuicTestCtlRun(QuicTestSlowReceive());
        break;

    case IOCTL_QUIC_RUN_NTH_ALLOC_FAIL:
        QuicTestCtlRun(QuicTestNthAllocFail());
        break;

    case IOCTL_QUIC_RUN_MTU_SETTINGS:
        QuicTestCtlRun(QuicTestMtuSettings());
        break;

    case IOCTL_QUIC_RUN_MTU_DISCOVERY:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestMtuDiscovery(
                Params->MtuDiscoveryParams.Family,
                Params->MtuDiscoveryParams.DropClientProbePackets,
                Params->MtuDiscoveryParams.DropServerProbePackets,
                Params->MtuDiscoveryParams.RaiseMinimumMtu));
        break;

    case IOCTL_QUIC_RUN_LOAD_BALANCED_HANDSHAKE:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestLoadBalancedHandshake(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CLIENT_SHARED_LOCAL_PORT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestClientSharedLocalPort(Params->Family));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_PARAM_API:
        QuicTestCtlRun(QuicTestValidateParamApi());
        break;

    case IOCTL_QUIC_RUN_STREAM_PRIORITY:
        QuicTestCtlRun(QuicTestStreamPriority());
        break;

    case IOCTL_QUIC_RUN_CLIENT_LOCAL_PATH_CHANGES:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestLocalPathChanges(Params->Family));
        break;

    case IOCTL_QUIC_RUN_STREAM_DIFFERENT_ABORT_ERRORS:
        QuicTestCtlRun(QuicTestStreamDifferentAbortErrors());
        break;

    case IOCTL_QUIC_RUN_CONNECTION_REJECTION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectionRejection(Params->RejectByClosing));
        break;

    case IOCTL_QUIC_RUN_INTERFACE_BINDING:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestInterfaceBinding(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_INVALID_ADDRESS:
        QuicTestCtlRun(QuicTestConnectInvalidAddress());
        break;

    case IOCTL_QUIC_RUN_STREAM_ABORT_RECV_FIN_RACE:
        QuicTestCtlRun(QuicTestStreamAbortRecvFinRace());
        break;

    case IOCTL_QUIC_RUN_STREAM_ABORT_CONN_FLOW_CONTROL:
        QuicTestCtlRun(QuicTestStreamAbortConnFlowControl());
        break;

    case IOCTL_QUIC_RUN__REG_SHUTDOWN_BEFORE_OPEN:
        QuicTestCtlRun(QuicTestRegistrationShutdownBeforeConnOpen());
        break;

    case IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN:
        QuicTestCtlRun(QuicTestRegistrationShutdownAfterConnOpen());
        break;

    case IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN_BEFORE_START:
        QuicTestCtlRun(QuicTestRegistrationShutdownAfterConnOpenBeforeStart());
        break;

    case IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN_AND_START:
        QuicTestCtlRun(QuicTestRegistrationShutdownAfterConnOpenAndStart());
        break;

    case IOCTL_QUIC_RUN_CRED_TYPE_VALIDATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        //
        // Fix up pointers for kernel mode
        //
        switch (Params->CredValidationParams.CredConfig.Type) {
        case QUIC_CREDENTIAL_TYPE_NONE:
            Params->CredValidationParams.CredConfig.Principal =
                (const char*)Params->CredValidationParams.PrincipalString;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            Params->CredValidationParams.CredConfig.CertificateHash =
                &Params->CredValidationParams.CertHash;
            break;
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            Params->CredValidationParams.CredConfig.CertificateHashStore =
                &Params->CredValidationParams.CertHashStore;
            break;
        }
        QuicTestCtlRun(
            QuicTestCredentialLoad(
                &Params->CredValidationParams.CredConfig));
        break;

    case IOCTL_QUIC_RUN_CIBIR_EXTENSION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCibirExtension(
                Params->CibirParams.Family,
                Params->CibirParams.Mode));
        break;

    case IOCTL_QUIC_RUN_STREAM_PRIORITY_INFINITE_LOOP:
        QuicTestCtlRun(QuicTestStreamPriorityInfiniteLoop());
        break;

    case IOCTL_QUIC_RUN_RESUMPTION_ACROSS_VERSIONS:
        QuicTestCtlRun(QuicTestResumptionAcrossVersions());
        break;

    case IOCTL_QUIC_RUN_CLIENT_BLOCKED_SOURCE_PORT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestClientBlockedSourcePort(
                Params->Family));
        break;

    case IOCTL_QUIC_RUN_STORAGE:
        QuicTestCtlRun(QuicTestStorage());
        break;

    default:
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    }

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
