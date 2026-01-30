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

#include <ntdef.h>

#include "msquicp.h"

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
HANDLE NmrClient = nullptr;

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

#ifdef QUIC_TEST_NMR_PROVIDER
    QUIC_ENABLE_PRIVATE_NMR_PROVIDER();
#endif

    Status = MsQuicNmrClientRegister(&NmrClient, &MSQUIC_MODULE_ID, 5000);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "MsQuicNmrClientRegister failed");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(
        NmrClient != nullptr && QUIC_GET_DISPATCH(NmrClient) != nullptr);

    MsQuic =
        new (std::nothrow) MsQuicApi(
            QUIC_GET_DISPATCH(NmrClient)->OpenVersion,
            QUIC_GET_DISPATCH(NmrClient)->Close);
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

    if (NmrClient != nullptr) {
        MsQuicNmrClientDeregister(&NmrClient);
    }

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
    sizeof(QUIC_TEST_CONFIGURATION_PARAMS),
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
    sizeof(INT32),
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
    0,
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
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    sizeof(QUIC_RUN_VN_TP_ODD_SIZE_PARAMS),
    sizeof(UINT8),
    sizeof(UINT8),
    sizeof(UINT8),
    sizeof(BOOLEAN),
    sizeof(INT32),
    sizeof(QUIC_HANDSHAKE_LOSS_PARAMS),
    sizeof(QUIC_RUN_CUSTOM_CERT_VALIDATION),
    sizeof(QUIC_RUN_FEATURE_NEGOTIATION),
    sizeof(QUIC_RUN_FEATURE_NEGOTIATION),
    0,
    0,
    0,
    sizeof(INT32),
    0,
    sizeof(QUIC_RUN_CANCEL_ON_LOSS_PARAMS),
    sizeof(uint32_t),
    sizeof(BOOLEAN),
    0,
    0,
    0,
    0,
    sizeof(BOOLEAN),
    sizeof(INT32),
    sizeof(INT32),                           // IOCTL_QUIC_RUN_TEST_ADDR_FUNCTIONS
    0,
    0,
    sizeof(INT32),
    sizeof(INT32),
    sizeof(QUIC_RUN_CONNECTION_POOL_CREATE_PARAMS),
    0,
    0,
    0,
    0,
    0,
    sizeof(INT32),
};

CXPLAT_STATIC_ASSERT(
    QUIC_MAX_IOCTL_FUNC_CODE + 1 == (sizeof(QUIC_IOCTL_BUFFER_SIZES)/sizeof(size_t)),
    "QUIC_IOCTL_BUFFER_SIZES must be kept in sync with the IOCTLs");

typedef union {
    QUIC_TEST_CONFIGURATION_PARAMS TestConfigurationParams;
    QUIC_RUN_CERTIFICATE_PARAMS CertParams;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    UINT8 Connect;
    INT32 Family;
    QUIC_RUN_CONNECT_PARAMS Params1;
    QUIC_RUN_CONNECT_AND_PING_PARAMS Params2;
    QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS Params4;
    QUIC_RUN_CID_UPDATE_PARAMS Params5;
    QUIC_RUN_RECEIVE_RESUME_PARAMS Params6;
    QUIC_RUN_CANCEL_ON_LOSS_PARAMS Params7;
    UINT8 EnableKeepAlive;
    UINT8 StopListenerFirst;
    QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS DrillParams;
    QUIC_RUN_DATAGRAM_NEGOTIATION DatagramNegotiationParams;
    QUIC_RUN_CUSTOM_CERT_VALIDATION CustomCertValidationParams;
    QUIC_RUN_VERSION_NEGOTIATION_EXT VersionNegotiationExtParams;
    QUIC_RUN_CONNECT_CLIENT_CERT ConnectClientCertParams;
    QUIC_RUN_CRED_VALIDATION CredValidationParams;
    QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS KeyUpdateRandomLossParams;
    QUIC_RUN_MTU_DISCOVERY_PARAMS MtuDiscoveryParams;
    uint32_t Test;
    QUIC_RUN_REBIND_PARAMS RebindParams;
    UINT8 RejectByClosing;
    QUIC_RUN_CIBIR_EXTENSION CibirParams;
    QUIC_RUN_VN_TP_ODD_SIZE_PARAMS OddSizeVnTpParams;
    UINT8 TestServerVNTP;
    BOOLEAN Bidirectional;
    QUIC_RUN_FEATURE_NEGOTIATION FeatureNegotiationParams;
    QUIC_HANDSHAKE_LOSS_PARAMS HandshakeLossParams;
    BOOLEAN ClientShutdown;
    BOOLEAN EnableResumption;
    QUIC_RUN_CONNECTION_POOL_CREATE_PARAMS ConnPoolCreateParams;
} QUIC_IOCTL_PARAMS;

#define QuicTestCtlRun(X) \
    Client->TestFailure = false; \
    X; \
    Status = Client->TestFailure ? STATUS_FAIL_FAST_EXCEPTION : STATUS_SUCCESS;

// Base template providing a readable error for unsupported scenarios
template<class... Args>
QUIC_STATUS InvokeTestFunction(void(Args...), const uint8_t*, uint32_t) {
    static_assert(false, "Only functions with no argument or one constant reference argument are supported");
}

// Specialization for functions with one const reference argument
template<class Arg>
QUIC_STATUS InvokeTestFunction(void(*func)(const Arg&), const uint8_t* argBuffer, uint32_t argBufferSize) {
    if (sizeof(Arg) != argBufferSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Invalid parameter size for test function");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const Arg& arg = *reinterpret_cast<const Arg*>(argBuffer);
    func(arg);
    return QUIC_STATUS_SUCCESS;
}

// Specialization for functions with no arguments
template<>
QUIC_STATUS InvokeTestFunction(void(*func)(), const uint8_t*, uint32_t argBufferSize) {
    if (0 != argBufferSize) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Parameter provided for a test function expecting none");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    func();
    return QUIC_STATUS_SUCCESS;
}

#define RegisterTestFunction(Function) \
    do { \
        if (strcmp(Request->FunctionName, #Function) == 0) { \
            return InvokeTestFunction( \
                Function, \
                (const uint8_t*)(Request + 1), \
                Request->ParameterSize); \
        } \
    } while (false)

QUIC_STATUS
ExecuteTestRequest(
    _In_ QUIC_RUN_TEST_REQUEST* Request
    )
{
    // Ensure null termination
    Request->FunctionName[sizeof(Request->FunctionName) - 1] = '\0';

    // Register any test functions here
    RegisterTestFunction(QuicTestGlobalParam);
    RegisterTestFunction(QuicTestCommonParam);
    RegisterTestFunction(QuicTestRegistrationParam);
    RegisterTestFunction(QuicTestConfigurationParam);
    RegisterTestFunction(QuicTestListenerParam);
    RegisterTestFunction(QuicTestConnectionParam);
    RegisterTestFunction(QuicTestTlsParam);
    RegisterTestFunction(QuicTestTlsHandshakeInfo);
    RegisterTestFunction(QuicTestStreamParam);
    RegisterTestFunction(QuicTestGetPerfCounters);
    RegisterTestFunction(QuicTestValidateConfiguration);
    RegisterTestFunction(QuicTestValidateListener);
    RegisterTestFunction(QuicTestValidateConnection);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestValidateConnectionPoolCreate);
    RegisterTestFunction(QuicTestValidateExecutionContext);
    RegisterTestFunction(QuicTestValidatePartition);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestRegistrationShutdownBeforeConnOpen);
    RegisterTestFunction(QuicTestRegistrationShutdownAfterConnOpen);
    RegisterTestFunction(QuicTestRegistrationShutdownAfterConnOpenBeforeStart);
    RegisterTestFunction(QuicTestRegistrationShutdownAfterConnOpenAndStart);
    RegisterTestFunction(QuicTestConnectionCloseBeforeStreamClose);
    RegisterTestFunction(QuicTestValidateStream);
    RegisterTestFunction(QuicTestCloseConnBeforeStreamFlush);
    RegisterTestFunction(QuicTestValidateConnectionEvents);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestValidateNetStatsConnEvent);
#endif
    RegisterTestFunction(QuicTestValidateStreamEvents);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestVersionSettings);
#endif
    RegisterTestFunction(QuicTestValidateParamApi);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestRegistrationOpenClose);
#endif
    RegisterTestFunction(QuicTestCreateListener);
    RegisterTestFunction(QuicTestStartListener);
    RegisterTestFunction(QuicTestStartListenerMultiAlpns);
    RegisterTestFunction(QuicTestStartListenerImplicit);
    RegisterTestFunction(QuicTestStartTwoListeners);
    RegisterTestFunction(QuicTestStartTwoListenersSameALPN);
    RegisterTestFunction(QuicTestStartListenerExplicit);
    RegisterTestFunction(QuicTestCreateConnection);
    RegisterTestFunction(QuicTestConnectionCloseFromCallback);
    RegisterTestFunction(QuicTestConnectionRejection);
#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestEcn);
    RegisterTestFunction(QuicTestLocalPathChanges);
    RegisterTestFunction(QuicTestMtuSettings);
    RegisterTestFunction(QuicTestMtuDiscovery);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestValidAlpnLengths);
    RegisterTestFunction(QuicTestInvalidAlpnLengths);
    RegisterTestFunction(QuicTestChangeAlpn);
    RegisterTestFunction(QuicTestBindConnectionImplicit);
    RegisterTestFunction(QuicTestBindConnectionExplicit);
    RegisterTestFunction(QuicTestAddrFunctions);
    RegisterTestFunction(QuicTestConnect_Connect);
#ifndef QUIC_DISABLE_RESUMPTION
    RegisterTestFunction(QuicTestConnect_Resume);
    RegisterTestFunction(QuicTestConnect_ResumeAsync);
    RegisterTestFunction(QuicTestConnect_ResumeRejection);
    RegisterTestFunction(QuicTestConnect_ResumeRejectionByServerApp);
    RegisterTestFunction(QuicTestConnect_ResumeRejectionByServerAppAsync);
#endif // QUIC_DISABLE_RESUMPTION
#ifndef QUIC_DISABLE_SHARED_PORT_TESTS
    RegisterTestFunction(QuicTestClientSharedLocalPort);
#endif
    RegisterTestFunction(QuicTestInterfaceBinding);
    RegisterTestFunction(QuicTestRetryMemoryLimitConnect);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestConnect_OldVersion);
#endif
    RegisterTestFunction(QuicTestConnect_AsyncSecurityConfig);
    RegisterTestFunction(QuicTestConnect_AsyncSecurityConfig_Delayed);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestVersionNegotiation);
    RegisterTestFunction(QuicTestVersionNegotiationRetry);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiationRetry);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiation);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiationDefaultServer);
    RegisterTestFunction(QuicTestCompatibleVersionNegotiationDefaultClient);
    RegisterTestFunction(QuicTestIncompatibleVersionNegotiation);
    RegisterTestFunction(QuicTestFailedVersionNegotiation);
    RegisterTestFunction(QuicTestReliableResetNegotiation);
    RegisterTestFunction(QuicTestOneWayDelayNegotiation);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestCustomServerCertificateValidation);
    RegisterTestFunction(QuicTestCustomClientCertificateValidation);
    RegisterTestFunction(QuicTestConnectClientCertificate);
    RegisterTestFunction(QuicTestCibirExtension);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
    RegisterTestFunction(QuicTestVNTPOddSize);
    RegisterTestFunction(QuicTestVNTPChosenVersionMismatch);
    RegisterTestFunction(QuicTestVNTPChosenVersionZero);
    RegisterTestFunction(QuicTestVNTPOtherVersionZero);
#endif
#endif
    RegisterTestFunction(QuicTestConnectUnreachable);
    RegisterTestFunction(QuicTestConnectInvalidAddress);
    RegisterTestFunction(QuicTestConnectBadAlpn);
    RegisterTestFunction(QuicTestConnectBadSni);
    RegisterTestFunction(QuicTestConnectServerRejected);
    RegisterTestFunction(QuicTestClientBlockedSourcePort);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestPathValidationTimeout);
    RegisterTestFunction(QuicTestNatPortRebind_NoPadding);
    RegisterTestFunction(QuicTestNatPortRebind_WithPadding);
    RegisterTestFunction(QuicTestNatAddrRebind_NoPadding);
    RegisterTestFunction(QuicTestNatAddrRebind_WithPadding);
#endif
    RegisterTestFunction(QuicTestChangeMaxStreamID);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestLoadBalancedHandshake);
    RegisterTestFunction(QuicCancelOnLossSend);
    RegisterTestFunction(QuicTestConnect_RandomLoss);
#ifndef QUIC_DISABLE_RESUMPTION
    RegisterTestFunction(QuicTestConnect_RandomLossResume);
    RegisterTestFunction(QuicTestConnect_RandomLossResumeRejection);
#endif // QUIC_DISABLE_RESUMPTION
    RegisterTestFunction(QuicTestHandshakeSpecificLossPatterns);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestShutdownDuringHandshake);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestConnectionPoolCreate);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestConnectAndIdle);
    RegisterTestFunction(QuicTestConnectAndIdleForDestCidChange);
    RegisterTestFunction(QuicTestServerDisconnect);
    RegisterTestFunction(QuicTestClientDisconnect);
    RegisterTestFunction(QuicAbortiveTransfers);
    RegisterTestFunction(QuicTestStatelessResetKey);
    RegisterTestFunction(QuicTestForceKeyUpdate);
    RegisterTestFunction(QuicTestKeyUpdate);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestKeyUpdateRandomLoss);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestCidUpdate);
    RegisterTestFunction(QuicTestAckSendDelay);
    RegisterTestFunction(QuicTestReceiveResume);
    RegisterTestFunction(QuicTestReceiveResumeNoData);
    RegisterTestFunction(QuicTestAbortReceive_Paused);
    RegisterTestFunction(QuicTestAbortReceive_Pending);
    RegisterTestFunction(QuicTestAbortReceive_Incomplete);
    RegisterTestFunction(QuicTestSlowReceive);
#ifndef QUIC_DISABLE_0RTT_TESTS
    RegisterTestFunction(QuicTestConnectAndPing_Send0Rtt);
    RegisterTestFunction(QuicTestConnectAndPing_Reject0Rtt);
#endif // QUIC_DISABLE_0RTT_TESTS
    RegisterTestFunction(QuicTestConnectAndPing_SendLarge);
    RegisterTestFunction(QuicTestConnectAndPing_SendIntermittently);
    RegisterTestFunction(QuicTestConnectAndPing_Send);
#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL
    RegisterTestFunction(QuicTestNthAllocFail);
#endif // QUIC_TEST_OPENSSL_FLAGS
#endif // QUIC_TEST_ALLOC_FAILURES_ENABLED
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestNthPacketDrop);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
    RegisterTestFunction(QuicTestStreamPriority);
    RegisterTestFunction(QuicTestStreamPriorityInfiniteLoop);
    RegisterTestFunction(QuicTestStreamDifferentAbortErrors);
    RegisterTestFunction(QuicTestStreamAbortRecvFinRace);
#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
    RegisterTestFunction(QuicTestStreamReliableReset);
    RegisterTestFunction(QuicTestStreamReliableResetMultipleSends);
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestStreamMultiReceive);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffers_ClientSend);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffers_ServerSend);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream);
    RegisterTestFunction(QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestStreamBlockUnblockConnFlowControl_Bidi);
    RegisterTestFunction(QuicTestStreamBlockUnblockConnFlowControl_Unidi);
    RegisterTestFunction(QuicTestStreamAbortConnFlowControl);
    RegisterTestFunction(QuicTestOperationPriority);
    RegisterTestFunction(QuicTestConnectionPriority);
    RegisterTestFunction(QuicDrillTestVarIntEncoder);
    RegisterTestFunction(QuicDrillTestInitialCid);
    RegisterTestFunction(QuicDrillTestInitialToken);
    RegisterTestFunction(QuicDrillTestServerVNPacket);
    RegisterTestFunction(QuicDrillTestKeyUpdateDuringHandshake);
    RegisterTestFunction(QuicTestDatagramNegotiation);
    RegisterTestFunction(QuicTestDatagramSend);
    RegisterTestFunction(QuicTestDatagramDrop);
#ifdef _WIN32 // Storage tests only supported on Windows
    RegisterTestFunction(QuicTestStorage);
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    RegisterTestFunction(QuicTestVersionStorage);
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
#ifdef DEBUG // This test needs a GetParam API that is only available in debug builds.
    RegisterTestFunction(QuicTestRetryConfigSetting);
#endif // DEBUG
#endif // _WIN32

    // Fail if no function matched
    char Buffer[256];
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, "Unknown function name in IOCTL test request: %s", Request->FunctionName);

    QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", Buffer);

    return QUIC_STATUS_NOT_SUPPORTED;
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

    // For now, this IOCTL is handled separately since it has variable length input.
    // Eventually, when all tests are migrated, it can be unified with the remaining setup IOCTLs.
    if (IoControlCode == IOCTL_QUIC_RUN_TEST) {
        QUIC_RUN_TEST_REQUEST* TestRequest{};
        size_t Length{};
        Status =
            WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(QUIC_RUN_TEST_REQUEST),
                reinterpret_cast<void**>(&TestRequest),
                &Length);
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "WdfRequestRetrieveInputBuffer failed for run test request");
            goto Error;
        }

        if (Length < sizeof(QUIC_RUN_TEST_REQUEST) + TestRequest->ParameterSize) {
            Status = STATUS_INVALID_PARAMETER;
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "IOCTL buffer too small for test parameters");
            goto Error;
        }

        // Invoke the test function
        Client->TestFailure = false;
        Status = ExecuteTestRequest(TestRequest);
        if (Status == QUIC_STATUS_SUCCESS && Client->TestFailure) {
            Status = STATUS_FAIL_FAST_EXCEPTION;
        }
        goto Error;
    }

    ULONG FunctionCode = IoGetFunctionCodeFromCtlCode(IoControlCode);

    if (FunctionCode > QUIC_MAX_IOCTL_FUNC_CODE) {
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

    case IOCTL_QUIC_TEST_CONFIGURATION:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        UseDuoNic = Params->TestConfigurationParams.UseDuoNic;
        RtlCopyMemory(CurrentWorkingDirectory, "\\DosDevices\\", sizeof("\\DosDevices\\"));
        Status =
            RtlStringCbCatExA(
                CurrentWorkingDirectory,
                sizeof(CurrentWorkingDirectory),
                Params->TestConfigurationParams.CurrentDirectory,
                nullptr,
                nullptr,
                STRSAFE_NULL_ON_FAILURE);

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
        // TODO - XDP stuff, if/when supported
#endif
        {
            //
            // We don't want to hinge the result of 'Status = ' on this setparam call because
            // this SetParam will only succeed the first time, before the datapath initializes.
            // User mode tests already ensure at most 1 setparam call. But in Kernel mode, this IOCTL
            // can be invoked many times.
            // If the datapath is already initialized, this setparam call should fail silently.
            //
            BOOLEAN EnableDscpRecvOption = TRUE;
            MsQuic->SetParam(
                    nullptr,
                    QUIC_PARAM_GLOBAL_DATAPATH_DSCP_RECV_ENABLED,
                    sizeof(BOOLEAN),
                    &EnableDscpRecvOption);
        }
        break;

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

    case IOCTL_QUIC_RUN_CONNECT:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestConnect(
                Params->Params1.Family,
                Params->Params1.ServerStatelessRetry != 0,
                Params->Params1.ClientUsesOldVersion != 0,
                Params->Params1.MultipleALPNs != 0,
                Params->Params1.GreaseQuicBitExtension != 0,
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
                Params->Params2.FifoScheduling != 0,
                Params->Params2.SendUdpToQtipListener != 0
                ));
        break;

    case IOCTL_QUIC_RUN_NAT_ADDR_REBIND:
        CXPLAT_FRE_ASSERT(Params != nullptr);
        QuicTestCtlRun(
            QuicTestNatAddrRebind(
                Params->RebindParams.Family,
                Params->RebindParams.Padding,
                FALSE));
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

    case IOCTL_QUIC_RUN_STREAM_MULTI_RECEIVE:
        QuicTestCtlRun(QuicTestStreamMultiReceive());

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
