/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Kernel Mode Test Driver

--*/

#include <quic_platform.h>
#include <MsQuicTests.h>

#include "quic_trace.h"

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
#include "control.cpp.clog"
#endif

QUIC_API_V1* MsQuic;
HQUIC Registration;
QUIC_SEC_CONFIG* SecurityConfig;

QUIC_SEC_CONFIG_CREATE_COMPLETE QuicTestSecConfigCreated;

DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceName, L"\\Device\\msquictest");
DECLARE_CONST_UNICODE_STRING(QuicTestCtlDeviceSymLink, L"\\DosDevices\\msquictest");

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
    HQUIC Registration;
    QUIC_SEC_CONFIG* SecurityConfig;
    KEVENT SecConfigComplete;
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

    Status = MsQuicOpenV1(&MsQuic);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(FN_controld1d04f96d4a6d92e901529003169771a, "[test] MsQuicOpen failed: 0x%x",  Status);
        goto Error;
    }

    DeviceInit =
        WdfControlDeviceInitAllocate(
            Driver,
            &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (DeviceInit == nullptr) {
        QuicTraceLogError(FN_control65c950da4fc2d8f0c0251ef4a32c5b69, "[test] WdfControlDeviceInitAllocate failed");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error;
    }

    Status =
        WdfDeviceInitAssignName(
            DeviceInit,
            &QuicTestCtlDeviceName);
    if (!NT_SUCCESS(Status)) {
        QuicTraceLogError(FN_controlfbd2199c5659da13fdd4ef0a34e7d69b, "[test] WdfDeviceInitAssignName failed, 0x%x",  Status);
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
        QuicTraceLogError(FN_control57892440719b0f253a787d295eb3aa14, "[test] WdfDeviceCreate failed, 0x%x",  Status);
        goto Error;
    }

    DeviceContext = QuicTestCtlGetDeviceContext(Device);
    RtlZeroMemory(DeviceContext, sizeof(QUIC_DEVICE_EXTENSION));
    ExInitializePushLock(&DeviceContext->Lock);
    InitializeListHead(&DeviceContext->ClientList);

    Status = WdfDeviceCreateSymbolicLink(Device, &QuicTestCtlDeviceSymLink);
    if (!NT_SUCCESS(Status)) {
        QuicTraceLogError(FN_control48d9bd8b3c4a9b5ba78e9d9a361a33ef, "[test] WdfDeviceCreateSymbolicLink failed, 0x%x",  Status);
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
        QuicTraceLogError(FN_control1e3cd687a3261682179844826a48b06d, "[test] WdfIoQueueCreate failed, 0x%x",  Status);
        goto Error;
    }

    QuicTestCtlDevice = Device;
    QuicTestCtlExtension = DeviceContext;

    WdfControlFinishInitializing(Device);

    QuicTraceLogVerbose(FN_controle39f156e7c33ef5d449ba2a5b670f8dc, "[test] Control interface initialized.");

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
    QuicTraceLogVerbose(FN_control928f1e9265e07ac92d6f7f99f3350848, "[test] Control interface uninitializing.");

    if (QuicTestCtlDevice != nullptr) {
        NT_ASSERT(QuicTestCtlExtension != nullptr);
        QuicTestCtlExtension = nullptr;

        WdfObjectDelete(QuicTestCtlDevice);
        QuicTestCtlDevice = nullptr;
    }

    if (MsQuic != nullptr) {
        MsQuicClose(MsQuic);
        MsQuic = nullptr;
    }

    QuicTraceLogVerbose(FN_control79d5bb59ba655554979808ebcdfc4afc, "[test] Control interface uninitialized.");
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
            QuicTraceLogError(FN_controlfe649bf1be40d3d0e06cd0136c06d550, "[test] Already have max clients!");
            Status = STATUS_TOO_MANY_SESSIONS;
            break;
        }

        QUIC_TEST_CLIENT* Client = QuicTestCtlGetFileContext(FileObject);
        if (Client == nullptr) {
            QuicTraceLogError(FN_controlcf3f19640b86c07daab4605e17eed7e1, "[test] nullptr File context in FileCreate!");
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Client, sizeof(QUIC_TEST_CLIENT));
        KeInitializeEvent(&Client->SecConfigComplete, NotificationEvent, FALSE);

        Status = MsQuic->RegistrationOpen("MsQuicBvt", &Client->Registration);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogError(FN_control9dae8c6bd52734e00cb3e90451768212, "[test] RegistrationOpen failed: 0x%x",  Status);
            break;
        }

        //
        // Insert into the client list
        //
        InsertTailList(&QuicTestCtlExtension->ClientList, &Client->Link);
        QuicTestCtlExtension->ClientListSize++;

        QuicTraceLogInfo(FN_controld168b3f001f047843d6ecb1f3fcfd47a, "[test] Client %p created.",  Client);

        //
        // Update globals. (TODO: Add multiple device client support)
        //
        Registration = Client->Registration;
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

        QuicTraceLogInfo(FN_control9c07f2de2e6692d9bbc34ea2d43b3efd, "[test] Client %p cleaning up.",  Client);

        //
        // Clean up the tests.
        //
        QuicTestCleanup();

        //
        // Delete the security configuration.
        //
        if (Client->SecurityConfig != nullptr) {
            MsQuic->SecConfigDelete(Client->SecurityConfig);
        }

        //
        // Release the reference on the MsQuic Library.
        //
        MsQuic->RegistrationClose(Client->Registration);

        //
        // Clean up globals.
        //
        QuicTestClient = nullptr;
        SecurityConfig = nullptr;
        Registration = nullptr;
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

    QuicTraceLogWarning(FN_controlb6606769d9c978312eafa82a15a98139, "[test] Client %p cancelled request %p.",  Client,  Request);

    Status = STATUS_CANCELLED;

error:

    WdfRequestComplete(Request, Status);
}

NTSTATUS
QuicTestCtlSetSecurityConfig(
    _Inout_ QUIC_TEST_CLIENT* Client,
    _In_ const QUIC_CERTIFICATE_HASH* CertHash
    )
{
    QUIC_CERTIFICATE_HASH_STORE CertHashStore = { QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE, { 0 }, "My" };
    RtlCopyMemory(&CertHashStore.ShaHash, CertHash, sizeof(QUIC_CERTIFICATE_HASH));

    //
    // Create the security configuration (async).
    //
    NTSTATUS Status =
        MsQuic->SecConfigCreate(
            Registration,
            QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE,
            &CertHashStore,
            nullptr,
            Client,
            QuicTestSecConfigCreated);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError(FN_control9c740cde42b8116cfc95fe3797249a35, "[test] SecConfigCreate failed: 0x%x",  Status);
        goto Error;
    }

    //
    // Wait for security configuration to be completed.
    //
    KeWaitForSingleObject(&Client->SecConfigComplete, Executive, KernelMode, FALSE, NULL);
    if (Client->SecurityConfig == nullptr) {
        QuicTraceLogError(FN_controlc0479dcb8ee9e72085ba88d718e40e3d, "[test] SecConfigCreate failed to get certificate.");
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    //
    // Initialize the tests.
    //
    QuicTestInitialize();

    SecurityConfig = Client->SecurityConfig;
    Status = QUIC_STATUS_SUCCESS;

    QuicTraceLogInfo(FN_controldfa728711b714575e237abef49173c41, "[test] Client %p set security config and initialized.",  Client);

Error:

    if (QUIC_FAILED(Status)) {
        if (Client->SecurityConfig != nullptr) {
            MsQuic->SecConfigDelete(Client->SecurityConfig);
            Client->SecurityConfig = nullptr;
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
void
QUIC_API
QuicTestSecConfigCreated(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
/*++

Routine Description:

    QuicTestSecConfigCreated is the completion callback for the
    SecConfigCreate call in DriverEntry.

Arguments:

    Context - The application context pointer passed to SecConfigCreate.

    Status - The completion status.

    SecurityConfig - The security configuration, if successful.

Return Value:

    None

--*/
{
    QUIC_TEST_CLIENT* Client = (QUIC_TEST_CLIENT*)Context;
    QUIC_FRE_ASSERT(Client != nullptr);

    QuicTraceLogInfo(FN_control77c5a0adf44b5361c54147918d37e97b, "[test] SecConfigCreated: 0x%x",  Status);

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Client->SecurityConfig = SecConfig;
    KeSetEvent(&Client->SecConfigComplete, IO_NO_INCREMENT, FALSE);
}

size_t QUIC_IOCTL_BUFFER_SIZES[] =
{
    0,
    sizeof(QUIC_CERTIFICATE_HASH),
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
    0,
    0,
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
    sizeof(INT32)
};

static_assert(
    QUIC_MAX_IOCTL_FUNC_CODE + 1 == (sizeof(QUIC_IOCTL_BUFFER_SIZES)/sizeof(size_t)),
    "QUIC_IOCTL_BUFFER_SIZES must be kept in sync with the IOTCLs");

typedef union {
    QUIC_CERTIFICATE_HASH CertHash;
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
    QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS DrillParams1;

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
        QuicTraceLogError(FN_control2252efed476118adb31be54fe5829479, "[test] QuicTestCtlEvtIoDeviceControl not supported greater than PASSIVE_LEVEL");
        goto Error;
    }

    FileObject = WdfRequestGetFileObject(Request);
    if (FileObject == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceLogError(FN_control2f7b16fcedd0cad7f7d7d291e5565bf2, "[test] WdfRequestGetFileObject failed");
        goto Error;
    }

    Client = QuicTestCtlGetFileContext(FileObject);
    if (Client == nullptr) {
        Status = STATUS_DEVICE_NOT_READY;
        QuicTraceLogError(FN_controlad84e24e4d86ceaa678d3ad06c5d697f, "[test] QuicTestCtlGetFileContext failed");
        goto Error;
    }

    ULONG FunctionCode = IoGetFunctionCodeFromCtlCode(IoControlCode);
    if (FunctionCode == 0 || FunctionCode > QUIC_MAX_IOCTL_FUNC_CODE) {
        Status = STATUS_NOT_IMPLEMENTED;
        QuicTraceLogError(FN_controlf2cfcad1e01bd84dacc11ab018c83025, "[test] Invalid FunctionCode, %u",  FunctionCode);
        goto Error;
    }

    if (InputBufferLength < QUIC_IOCTL_BUFFER_SIZES[FunctionCode]) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        QuicTraceLogError(FN_control3af5d477ca51e451eb07856f832960c8, "[test] Invalid buffer size for FunctionCode %u, %u (expected %u)", 
            FunctionCode,  (UINT32)InputBufferLength,  (UINT32)QUIC_IOCTL_BUFFER_SIZES[FunctionCode]);
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
            QuicTraceLogError(FN_control11922ed65b74d9b846dec2af1ea27a37, "[test] WdfRequestRetrieveInputBuffer failed, 0x%x",  Status);
            goto Error;
        } else if (Params == nullptr) {
            QuicTraceLogError(FN_control2b3368fe49f36bc1446094ada9cd3930, "[test] WdfRequestRetrieveInputBuffer failed to return parameter buffer");
            Status = STATUS_INVALID_PARAMETER;
            goto Error;
        }
    }

    QuicTraceLogInfo(FN_controlb13dbc1a64995081e3cebf39b0f254de, "[test] Client %p executing IOCTL %u.",  Client,  FunctionCode);

    if (IoControlCode != IOCTL_QUIC_SEC_CONFIG &&
        Client->SecurityConfig == nullptr) {
        Status = STATUS_INVALID_DEVICE_STATE;
        QuicTraceLogError(FN_control29f33308baa8406e1d914675d6a80714, "[test] Client %p didn't set Security Config!",  Client);
        goto Error;
    }

    switch (IoControlCode) {

    case IOCTL_QUIC_SEC_CONFIG:
        QUIC_FRE_ASSERT(Params != nullptr);
        Status =
            QuicTestCtlSetSecurityConfig(
                Client,
                &Params->CertHash);
        break;

    case IOCTL_QUIC_RUN_VALIDATE_REGISTRATION:
        QuicTestCtlRun(QuicTestValidateRegistration());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_SESSION:
        QuicTestCtlRun(QuicTestValidateSession());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_LISTENER:
        QuicTestCtlRun(QuicTestValidateListener());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_CONNECTION:
        QuicTestCtlRun(QuicTestValidateConnection());
        break;
    case IOCTL_QUIC_RUN_VALIDATE_STREAM:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateStream(Params->Connect != 0));
        break;

    case IOCTL_QUIC_RUN_CREATE_LISTENER:
        QuicTestCtlRun(QuicTestCreateListener());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER:
        QuicTestCtlRun(QuicTestStartListener());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestStartListenerImplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_START_TWO_LISTENERS:
        QuicTestCtlRun(QuicTestStartTwoListeners());
        break;
    case IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN:
        QuicTestCtlRun(QuicTestStartTwoListenersSameALPN());
        break;
    case IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestStartListenerExplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_CREATE_CONNECTION:
        QuicTestCtlRun(QuicTestCreateConnection());
        break;
    case IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestBindConnectionImplicit(Params->Family));
        break;
    case IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestBindConnectionExplicit(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnect(
                Params->Params1.Family,
                Params->Params1.ServerStatelessRetry != 0,
                Params->Params1.ClientUsesOldVersion != 0,
                Params->Params1.ClientRebind != 0,
                Params->Params1.ChangeMaxStreamID != 0,
                Params->Params1.MultipleALPNs != 0,
                Params->Params1.AsyncSecConfig != 0,
                Params->Params1.MultiPacketClientInitial != 0,
                Params->Params1.SessionResumption != 0
                ));
        break;

    case IOCTL_QUIC_RUN_CONNECT_AND_PING:
        QUIC_FRE_ASSERT(Params != nullptr);
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
                Params->Params2.ServerInitiatedStreams != 0
                ));
        break;

    case IOCTL_QUIC_RUN_CONNECT_AND_IDLE:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectAndIdle(Params->EnableKeepAlive != 0));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_SECCONFIG:
        //
        // Make the string for Schannel
        //
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestValidateServerSecConfig(nullptr, &Params->CertHashStore, "localhost"));
        break;

    case IOCTL_QUIC_RUN_CONNECT_UNREACHABLE:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectUnreachable(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_BAD_ALPN:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectBadAlpn(Params->Family));
        break;

    case IOCTL_QUIC_RUN_CONNECT_BAD_SNI:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectBadSni(Params->Family));
        break;

    case IOCTL_QUIC_RUN_SERVER_DISCONNECT:
        QuicTestCtlRun(QuicTestServerDisconnect());
        break;

    case IOCTL_QUIC_RUN_CLIENT_DISCONNECT:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestClientDisconnect(Params->StopListenerFirst));
        break;

    case IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS:
        QuicTestCtlRun(QuicTestValidateConnectionEvents());
        break;

    case IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS:
        QuicTestCtlRun(QuicTestValidateStreamEvents());
        break;

    case IOCTL_QUIC_RUN_VERSION_NEGOTIATION:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestVersionNegotiation(Params->Family));
        break;

    case IOCTL_QUIC_RUN_KEY_UPDATE:
        QUIC_FRE_ASSERT(Params != nullptr);
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
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(QuicTestConnectServerRejected(Params->Family));
        break;

    case IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicAbortiveTransfers(
                Params->Params4.Family,
                Params->Params4.Flags));
        break;

    case IOCTL_QUIC_RUN_CID_UPDATE:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestCidUpdate(
                Params->Params5.Family,
                Params->Params5.Iterations));
        break;

    case IOCTL_QUIC_RUN_RECEIVE_RESUME:
        QUIC_FRE_ASSERT(Params != nullptr);
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
        QUIC_FRE_ASSERT(Params != nullptr);
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
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicDrillTestInitialCid(
                Params->DrillParams1.Family,
                Params->DrillParams1.SourceOrDest,
                Params->DrillParams1.ActualCidLengthValid,
                Params->DrillParams1.ShortCidLength,
                Params->DrillParams1.CidLengthFieldValid));
        break;

    case IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN:
        QUIC_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicDrillTestInitialToken(
                Params->Family));
        break;

    default:
        Status = STATUS_NOT_IMPLEMENTED;
        break;
    }

Error:

    QuicTraceLogInfo(FN_controle5193f6ebf266b970f1e50b1341490ac, "[test] Client %p completing request, 0x%x.",  Client,  Status);

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

    QuicTraceLogError(FN_controlaac546ec85a3233833360cd7ab640553, "[test] File: %s, Function: %s, Line: %d",  File,  Function,  Line);
    QuicTraceLogError(FN_controle873f8dcb3ed431fa02ef1c6e5c2c525, "[test] FAIL: %s",  Buffer);

#if QUIC_BREAK_TEST
    NT_FRE_ASSERT(FALSE);
#endif
}
