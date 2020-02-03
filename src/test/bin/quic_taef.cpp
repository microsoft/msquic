/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_taef.h"

#ifdef QUIC_LOGS_WPP
#include "quic_taef.tmh"
#endif

//
// The following TAEF test covers both the Windows user mode and kernel mode
// MsQuic APIs and all associated headers and libs.
//
BEGIN_MODULE()
    MODULE_PROPERTY(L"BinaryUnderTest", L"MsQuic.dll")
    MODULE_PROPERTY(L"BinaryUnderTest", L"MsQuic.sys")
    MODULE_PROPERTY(L"ArtifactUnderTest", L"onecore\\internal\\minwin\\priv_sdk\\inc\\net\\msquic.h")
    MODULE_PROPERTY(L"ArtifactUnderTest", L"onecore\\internal\\minwin\\priv_sdk\\inc\\net\\msquicp.h")
    MODULE_PROPERTY(L"ArtifactUnderTest", L"onecore\\internal\\minwin\\priv_sdk\\inc\\net\\msquic_winuser.h")
    MODULE_PROPERTY(L"ArtifactUnderTest", L"onecore\\private\\minwin\\priv_sdk\\inc\\net\\msquic_winkernel.h")
    MODULE_PROPERTY(L"ArtifactUnderTest", L"onecore\\internal\\minwin\\priv_sdk\\lib\\$ARCH\\net\\msquic.lib")
    MODULE_PROPERTY(L"ArtifactUnderTest", L"onecore\\private\\minwin\\priv_sdk\\lib\\$ARCH\\net\\msquic_kernel.lib")
    MODULE_PROPERTY(L"Owner", L"nibanks")
    MODULE_PROPERTY(L"Area", L"Networking")
    MODULE_PROPERTY(L"SubArea", L"MsQuic")
    MODULE_PROPERTY(L"EtwLogger:WPRProfileFile", L"MsQuic.wprp")
    MODULE_PROPERTY(L"EtwLogger:WPRProfile", L"Full.Light.File")
END_MODULE()

#define VERIFY_NO_ERROR(__actual, ...) \
    (bool)TestExecution::Private::MacroVerify::AreEqual( \
        0ul, (__actual), L"NO_ERROR", (L#__actual), \
        PRIVATE_VERIFY_ERROR_INFO, __VA_ARGS__)

QUIC_API_V1* MsQuic;
HQUIC Registration;
QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams;
QUIC_SEC_CONFIG* SecurityConfig;
LARGE_INTEGER TestStart;

QuicTestDriver TestDriver;
QuicTestClient TestClient;
bool TestCompartmentCreated = false;

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

void
LogTestFailure(
    _In_z_ const char *File,
    _In_z_ const char *Function,
    int Line,
    _Printf_format_string_ const char *Format,
    ...
    )
{
    char Buffer[128];

    va_list Args;
    va_start(Args, Format);
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, Format, Args);
    va_end(Args);

    QuicTraceLogError("[test]File: %s, Function: %s, Line: %d", File, Function, Line);
    QuicTraceLogError("[test]FAIL: %s", Buffer);

    Log::Error(
        String().Format(
            L"%S, Function: %S, Line: %d, %S",
            File, Function, Line, Buffer));

#if QUIC_BREAK_TEST
    NT_FRE_ASSERT(FALSE);
#endif
}

bool
IsTestingKernelMode() {
    //
    // If GlobalTestSetup initializes the TestClient then we are testing
    // kernel mode.
    //
    return TestClient.IsInitialized();
}

DWORD
QuicTestDriver::Initialize() {
    DWORD Error;
    ScmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (ScmHandle == nullptr) {
        Error = GetLastError();
        QuicTraceLogError("[test] GetFullPathName failed, 0x%x.", Error);
        return Error;
    }
QueryService:
    ServiceHandle =
        OpenService(
            ScmHandle,
            QUIC_TEST_DRIVER_NAME,
            SERVICE_ALL_ACCESS);
    if (ServiceHandle == nullptr) {
        QuicTraceLogError("[test] OpenService failed, 0x%x.", GetLastError());
        char DriverFilePath[MAX_PATH];
        Error =
            GetFullPathName(
                "msquic_bvt.sys",
                sizeof(DriverFilePath),
                DriverFilePath,
                nullptr);
        if (Error == 0) {
            Error = GetLastError();
            QuicTraceLogError("[test] GetFullPathName failed, 0x%x.", Error);
            return Error;
        }
        ServiceHandle =
            CreateService(
                ScmHandle,
                QUIC_TEST_DRIVER_NAME,
                QUIC_TEST_DRIVER_NAME,
                SC_MANAGER_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                DriverFilePath,
                nullptr,
                nullptr,
                "msquic\0",
                nullptr,
                nullptr);
        if (ServiceHandle == nullptr) {
            Error = GetLastError();
            if (Error == ERROR_SERVICE_EXISTS) {
                goto QueryService;
            }
            QuicTraceLogError("[test] CreateService failed, 0x%x.", Error);
            return Error;
        }
    }
    return ERROR_SUCCESS;
}

DWORD
QuicTestDriver::Start() {
    if (!StartService(ServiceHandle, 0, nullptr)) {
        DWORD Error = GetLastError();
        if (Error != ERROR_SERVICE_ALREADY_RUNNING) {
            QuicTraceLogError("[test] StartService failed, 0x%x.", Error);
            return Error;
        }
    }
    return ERROR_SUCCESS;
}

DWORD
QuicTestClient::Initialize(
    _In_ QUIC_CERTIFICATE_HASH* ServerCertHash
    )
{
    DWORD Error;
    DeviceHandle =
        CreateFile(
            QUIC_TEST_IOCTL_PATH,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,                // no SECURITY_ATTRIBUTES structure
            OPEN_EXISTING,          // No special create flags
            FILE_FLAG_OVERLAPPED,   // Allow asynchronous requests
            nullptr);
    if (DeviceHandle == INVALID_HANDLE_VALUE) {
        Error = GetLastError();
        QuicTraceLogError("[test] CreateFile failed, 0x%x.", Error);
        return Error;
    }
    Error = SendIOCTL(IOCTL_QUIC_SEC_CONFIG, *ServerCertHash);
    if (Error != NO_ERROR) {
        CloseHandle(DeviceHandle);
        DeviceHandle = INVALID_HANDLE_VALUE;
        Error = GetLastError();
        QuicTraceLogError("[test] SendIOCTL(IOCTL_QUIC_SEC_CONFIG) failed, 0x%x.", Error);
        return Error;
    }
    Initialized = true;
    return ERROR_SUCCESS;
}

#define IoGetFunctionCodeFromCtlCode( ControlCode ) (\
    ( ControlCode >> 2) & 0x00000FFF )

DWORD
QuicTestClient::SendIOCTL(
    _In_ DWORD IoControlCode,
    _In_reads_bytes_opt_(InBufferSize)
        LPVOID InBuffer,
    _In_ DWORD InBufferSize,
    _In_ DWORD TimeoutMs
    )
{
    DWORD Error;
    OVERLAPPED Overlapped = { 0 };
    Overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (Overlapped.hEvent == nullptr) {
        Error = GetLastError();
        QuicTraceLogError("[test] CreateEvent failed, 0x%x.", Error);
        return Error;
    }
    QuicTraceLogVerbose("[test] Sending IOCTL %u with %u bytes.",
        IoGetFunctionCodeFromCtlCode(IoControlCode), InBufferSize);
    if (!DeviceIoControl(
            DeviceHandle,
            IoControlCode,
            InBuffer, InBufferSize,
            nullptr, 0,
            nullptr,
            &Overlapped)) {
        Error = GetLastError();
        if (Error != ERROR_IO_PENDING) {
            CloseHandle(Overlapped.hEvent);
            QuicTraceLogError("[test] DeviceIoControl failed, 0x%x.", Error);
            return Error;
        }
    }
    DWORD dwBytesReturned;
    if (!GetOverlappedResultEx(
            DeviceHandle,
            &Overlapped,
            &dwBytesReturned,
            TimeoutMs,
            FALSE)) {
        Error = GetLastError();
        if (Error == WAIT_TIMEOUT) {
            Error = ERROR_TIMEOUT;
            CancelIoEx(DeviceHandle, &Overlapped);
        }
        QuicTraceLogError("[test] GetOverlappedResultEx failed, 0x%x.", Error);
    } else {
        Error = ERROR_SUCCESS;
    }
    CloseHandle(Overlapped.hEvent);
    return Error;
}

_Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
static void
QUIC_API
GetSecConfigComplete(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
{
    _Analysis_assume_(Context);
    auto Event = (HANDLE*)Context;
    if (QUIC_FAILED(Status)) {
        QuicTraceLogError("[test] GetSecConfigComplete failed, 0x%x.", Status);
    }
    SecurityConfig = SecConfig;
    SetEvent(*Event);
}

bool LoadSecConfig() {
    HANDLE Event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (QUIC_SUCCEEDED(
        MsQuic->SecConfigCreate(
            Registration,
            (QUIC_SEC_CONFIG_FLAGS)SelfSignedCertParams->Flags,
            SelfSignedCertParams->Certificate,
            SelfSignedCertParams->Principal,
            &Event,
            GetSecConfigComplete))) {
        WaitForSingleObject(Event, INFINITE);
    }
    CloseHandle(Event);
    return SecurityConfig != nullptr;
}

MODULE_SETUP(GlobalTestSetup) {
    QueryPerformanceCounter(&TestStart);
    QuicPlatformSystemLoad();
    QuicPlatformInitialize();
    int KernelMode = 0;
    SUCCEEDED(RuntimeParameters::TryGetValue(L"KernelMode", KernelMode));

    if ((SelfSignedCertParams =
        QuicPlatGetSelfSignedCert(
            KernelMode ?
                QUIC_SELF_SIGN_CERT_MACHINE :
                QUIC_SELF_SIGN_CERT_USER)) == nullptr) {
        QuicTraceLogError("[test] QuicPlatGetSelfSignedCert failed.");
        return false;
    }

    if (KernelMode == 1) {
        DWORD Error = TestDriver.Initialize();
        if (Error != NO_ERROR) {
            QuicTraceLogError("[test] TestDriver.Initialize failed, 0x%x.", Error);
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return false;
        }
        Error = TestDriver.Start();
        if (Error != NO_ERROR) {
            QuicTraceLogError("[test] TestDriver.Start failed, 0x%x.", Error);
            TestDriver.Uninitialize();
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return false;
        }
        Error = TestClient.Initialize((QUIC_CERTIFICATE_HASH*)SelfSignedCertParams->Thumbprint);
        if (Error != ERROR_SUCCESS) {
            QuicTraceLogError("[test] TestClient.Initialize failed, 0x%x.", Error);
            TestDriver.Uninitialize();
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return false;
        }
    } else {
        TestCompartmentCreated = false;
        if (!CompartmentHelper::CreateCompartment(TestCompartmentID)) {
            QuicTraceLogError("[test] CreateCompartment failed.");
            Log::Comment(L"CreateCompartment failed.");
            // Non-fatal (at least to tests that don't use it).
        } else {
            TestCompartmentCreated = true;
        }
        if (QUIC_FAILED(MsQuicOpenV1(&MsQuic))) {
            QuicTraceLogError("[test] MsQuicOpen failed.");
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return false;
        }
        if (QUIC_FAILED(MsQuic->RegistrationOpen("MsQuicBVT", &Registration))) {
            QuicTraceLogError("[test] RegistrationOpen failed.");
            MsQuicClose(MsQuic);
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return false;
        }
        if (!LoadSecConfig()) {
            QuicTraceLogError("[test] Failed to load the security config.");
            MsQuic->RegistrationClose(Registration);
            MsQuicClose(MsQuic);
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            return false;
        }
        QuicTestInitialize();
    }
    return true;
}

MODULE_CLEANUP(GlobalTestCleanup)
{
    if (!TestClient.IsInitialized()) {
        QuicTestCleanup();
        MsQuic->SecConfigDelete(SecurityConfig);
        SecurityConfig = nullptr;
        MsQuic->RegistrationClose(Registration);
        Registration = nullptr;
        MsQuicClose(MsQuic);
        MsQuic = nullptr;
        if (TestCompartmentCreated) {
            CompartmentHelper::DeleteCompartment(TestCompartmentID);
        }
    } else {
        TestClient.Uninitialize();
        TestDriver.Uninitialize();
    }
    QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
    SelfSignedCertParams = nullptr;
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    LARGE_INTEGER TestEnd, PerfFreq;
    QueryPerformanceCounter(&TestEnd);
    QueryPerformanceFrequency(&PerfFreq);

    LONGLONG elapsedMicroseconds = TestEnd.QuadPart - TestStart.QuadPart;
    elapsedMicroseconds *= 1000000;
    elapsedMicroseconds /= PerfFreq.QuadPart;

    Log::Comment(
        String().Format(
            L"Total Test Time: %lld.%d milliseconds",
            elapsedMicroseconds / 1000, (int)(elapsedMicroseconds % 1000)));
    return true;
}

class QuicParameterValidation : public TestClass<QuicParameterValidation>
{
    BEGIN_TEST_CLASS(QuicParameterValidation)
        TEST_CLASS_PROPERTY(L"BVT", L"true")
        TEST_CLASS_PROPERTY(L"BVT_KERNEL", L"true")
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(Api)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Passes invalid values to MsQuicOpen.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_API));
        } else {
            QuicTestValidateApi();
        }
    }

    TEST_METHOD(Registration)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Passes invalid values to RegistrationOpen.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_REGISTRATION));
        } else {
            QuicTestValidateRegistration();
        }
    }

    TEST_METHOD(Session)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Passes invalid values to SessionOpen and SessionClose.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_SESSION));
        } else {
            QuicTestValidateSession();
        }
    }

    TEST_METHOD(Listener)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Passes invalid values to MsQuic Listener APIs.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_LISTENER));
        } else {
            QuicTestValidateListener();
        }
    }

    TEST_METHOD(Connection)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Passes invalid values to MsQuic Connection APIs.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_CONNECTION));
        } else {
            QuicTestValidateConnection();
        }
    }

    TEST_METHOD(Stream)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Passes invalid values to MsQuic Stream APIs.")
            TEST_METHOD_PROPERTY(L"Data:Connected", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Connect;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Connected", Connect));

        if (IsTestingKernelMode()) {
            UINT8 Param = (UINT8)Connect;
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_STREAM,
                    Param));
        } else {
            QuicTestValidateStream(Connect != 0);
        }
    }

    TEST_METHOD(SecConfig)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates MsQuic Security Config APIs with both good and bad input.")
        END_TEST_METHOD_PROPERTIES()

        QUIC_CERTIFICATE_HASH_STORE CertHashStore = { QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE };
        memcpy(CertHashStore.ShaHash, SelfSignedCertParams->Thumbprint, sizeof(CertHashStore.ShaHash));
        memcpy(CertHashStore.StoreName, "My", 2);

        if (IsTestingKernelMode()) {
            /* Currently, these tests fail because they use the current user's My store.
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_SECCONFIG,
                    CertHashStore));*/
        } else {
            QuicTestValidateServerSecConfig(
                SelfSignedCertParams->Certificate,
                &CertHashStore,
                "localhost");
        }
    }
};

class QuicEventValidation : public TestClass<QuicEventValidation>
{
    BEGIN_TEST_CLASS(QuicEventValidation)
        TEST_CLASS_PROPERTY(L"BVT", L"true")
        TEST_CLASS_PROPERTY(L"BVT_KERNEL", L"true")
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(ConnectionEvents)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates event order for connections.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS));
        } else {
            QuicTestValidateConnectionEvents();
        }
    }

    TEST_METHOD(StreamEvents)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates event order for streams.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS));
        } else {
            QuicTestValidateStreamEvents();
        }
    }
};

class QuicBasic : public TestClass<QuicBasic>
{
    BEGIN_TEST_CLASS(QuicBasic)
        TEST_CLASS_PROPERTY(L"BVT", L"true")
        TEST_CLASS_PROPERTY(L"BVT_KERNEL", L"true")
        TEST_CLASS_PROPERTY(L"Data:Family", L"{4,6}")
#ifdef QUIC_COMPARTMENT_TESTS
        TEST_CLASS_PROPERTY(L"Data:CompartmentID", L"{1,2}")
#endif
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(CreateListener)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Creates a listener.")
        END_TEST_METHOD_PROPERTIES()

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CREATE_LISTENER));
        } else {
            QuicTestCreateListener();
        }
    }

    TEST_METHOD(StartListener)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Starts a listener with no supplied local address.")
        END_TEST_METHOD_PROPERTIES()

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_START_LISTENER));
        } else {
            QuicTestStartListener();
        }
    }

    TEST_METHOD(StartListenerImplicit)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Starts a listener with unspecified local address.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT,
                    Family));
        } else {
            QuicTestStartListenerImplicit(Family);
        }
    }

    TEST_METHOD(StartTwoListeners)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Starts two listeners with with different ALPNs.")
        END_TEST_METHOD_PROPERTIES()

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_START_TWO_LISTENERS));
        } else {
            QuicTestStartTwoListeners();
        }
    }

    TEST_METHOD(StartTwoListenersSameALPN)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Attempts to start two listeners with with the same ALPN.")
        END_TEST_METHOD_PROPERTIES()

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN));
        } else {
            QuicTestStartTwoListenersSameALPN();
        }
    }

    TEST_METHOD(StartListenerExplicit)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Starts a listener with explicit local address.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT,
                    Family));
        } else {
            QuicTestStartListenerExplicit(Family);
        }
    }

    TEST_METHOD(CreateConnection)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Creates a connection.")
        END_TEST_METHOD_PROPERTIES()

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CREATE_CONNECTION));
        } else {
            QuicTestCreateConnection();
        }
    }

    TEST_METHOD(BindConnectionImplicit)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Creates a connection and binds it to an unspecified local address.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT,
                    Family));
        } else {
            QuicTestBindConnectionImplicit(Family);
        }
    }

    TEST_METHOD(BindConnectionExplicit)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Creates a connection and binds it to an explicit local address.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT,
                    Family));
        } else {
            QuicTestBindConnectionExplicit(Family);
        }
    }
};

class QuicHandshake : public TestClass<QuicHandshake>
{
    BEGIN_TEST_CLASS(QuicHandshake)
        TEST_CLASS_PROPERTY(L"BVT", L"true")
        TEST_CLASS_PROPERTY(L"BVT_KERNEL", L"true")
        TEST_CLASS_PROPERTY(L"Data:Family", L"{4,6}")
#ifdef QUIC_COMPARTMENT_TESTS
        TEST_CLASS_PROPERTY(L"Data:CompartmentID", L"{1,2}")
#endif
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(Connect)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Connects a client and server.")
            TEST_METHOD_PROPERTY(L"Data:ServerStatelessRetry", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:MultipleALPNs", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:MultiPacketClientInitial", L"{0,1}")
#ifndef QUIC_DISABLE_RESUMPTION
            TEST_METHOD_PROPERTY(L"Data:SessionResumption", L"{0,1}")
#endif
        END_TEST_METHOD_PROPERTIES()

        int Family, ServerStatelessRetry, MultipleALPNs, MultiPacketClientInitial, SessionResumption;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ServerStatelessRetry", ServerStatelessRetry));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"MultipleALPNs", MultipleALPNs));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"MultiPacketClientInitial", MultiPacketClientInitial));
#ifndef QUIC_DISABLE_RESUMPTION
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"SessionResumption", SessionResumption));
#else
        SessionResumption = FALSE;
#endif

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_PARAMS Params = {
                Family,
                (UINT8)ServerStatelessRetry,
                0,  // ClientUsesOldVersion
                0,  // ClientRebind
                0,  // ChangeMaxStreamID
                (UINT8)MultipleALPNs,
                0,  // AsyncSecConfig
                (UINT8)MultiPacketClientInitial,
                (UINT8)SessionResumption
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT,
                    Params));
        } else {
            QuicTestConnect(
                Family,
                ServerStatelessRetry != 0,
                false,  // ClientUsesOldVersion
                false,  // ClientRebind
                false,  // ChangeMaxStreamID
                MultipleALPNs != 0,
                false,  // AsyncSecConfig
                MultiPacketClientInitial != 0,
                SessionResumption != 0
                );
        }
    }

    TEST_METHOD(OldVersion)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Connects a client and server with non-latest version.")
            TEST_METHOD_PROPERTY(L"Data:ServerStatelessRetry", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, ServerStatelessRetry;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ServerStatelessRetry", ServerStatelessRetry));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_PARAMS Params = {
                Family,
                (UINT8)ServerStatelessRetry,
                1,  // ClientUsesOldVersion
                0,  // ClientRebind
                0,  // ChangeMaxStreamID
                0,  // MultipleALPNs
                0,  // AsyncSecConfig
                0   // SessionResumption
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT,
                    Params));
        } else {
            QuicTestConnect(
                Family,
                ServerStatelessRetry != 0,
                true,   // ClientUsesOldVersion
                false,  // ClientRebind
                false,  // ChangeMaxStreamID
                false,  // MultipleALPNs
                false,  // AsyncSecConfig
                false,  // MultiPacketClientInitial
                false   // SessionResumption
                );
        }
    }

    TEST_METHOD(VersionNegotiation)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Connects a client and server with version negotiation.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_VERSION_NEGOTIATION,
                    Family));
        } else {
            QuicTestVersionNegotiation(
                Family
                );
        }
    }

    TEST_METHOD(Rebind)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Connects a client and server and changes the client's address.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            /* TODO - Currently broken (bugchecks) in kernel mode.
            QUIC_RUN_CONNECT_PARAMS Params = {
                Family,
                0,  // ServerStatelessRetry
                0,  // ClientUsesOldVersion
                1,  // ClientRebind
                0,  // ChangeMaxStreamID
                0,  // MultipleALPNs
                0,  // AsyncSecConfig
                0   // SessionResumption
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT,
                    Params));*/
        } else {
            QuicTestConnect(
                Family,
                false,  // ServerStatelessRetry
                false,  // ClientUsesOldVersion
                true,   // ClientRebind
                false,  // ChangeMaxStreamID
                false,  // MultipleALPNs
                false,  // AsyncSecConfig
                false,  // MultiPacketClientInitial
                false   // SessionResumption
                );
        }
    }

    TEST_METHOD(ChangeMaxStreamIDs)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Connects a client and server and changes max stream IDs.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_PARAMS Params = {
                Family,
                0,  // ServerStatelessRetry
                0,  // ClientUsesOldVersion
                0,  // ClientRebind
                1,  // ChangeMaxStreamID
                0,  // MultipleALPNs
                0,  // AsyncSecConfig
                0   // SessionResumption
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT,
                    Params));
        } else {
            QuicTestConnect(
                Family,
                false,  // ServerStatelessRetry
                false,  // ClientUsesOldVersion
                false,  // ClientRebind
                true,   // ChangeMaxStreamID
                false,  // MultipleALPNs
                false,  // AsyncSecConfig
                false,  // MultiPacketClientInitial
                false   // SessionResumption
                );
        }
    }

    TEST_METHOD(AsyncSecurityConfig)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Server asynchronously sets security config.")
            TEST_METHOD_PROPERTY(L"Data:ServerStatelessRetry", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:MultipleALPNs", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, ServerStatelessRetry, MultipleALPNs;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ServerStatelessRetry", ServerStatelessRetry));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"MultipleALPNs", MultipleALPNs));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_PARAMS Params = {
                Family,
                (UINT8)ServerStatelessRetry,
                0,  // ClientUsesOldVersion
                0,  // ClientRebind
                0,  // ChangeMaxStreamID
                (UINT8)MultipleALPNs,
                1,  // AsyncSecConfig
                0   // SessionResumption
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT,
                    Params));
        } else {
            QuicTestConnect(
                Family,
                ServerStatelessRetry != 0,
                false,  // ClientUsesOldVersion
                false,  // ClientRebind
                false,  // ChangeMaxStreamID
                MultipleALPNs != 0,
                true,   // AsyncSecConfig,
                false,  // MultiPacketClientInitial
                false   // SessionResumption
                );
        }
    }

    TEST_METHOD(Unreachable)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates a client fails to connect to unreachable server.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_UNREACHABLE,
                    Family));
        } else {
            QuicTestConnectUnreachable(
                Family
                );
        }
    }

    TEST_METHOD(BadALPN)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates a client fails to connect with an incorrect ALPN.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_BAD_ALPN,
                    Family));
        } else {
            QuicTestConnectBadAlpn(
                Family
                );
        }
    }

    TEST_METHOD(BadSNI)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates a client fails to connect with an incorrect SNI.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_BAD_SNI,
                    Family));
        } else {
            QuicTestConnectBadSni(
                Family
                );
        }
    }

    TEST_METHOD(ServerRejected)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Validates a client fails to connect with a particular App error code.")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        CompartmentIdScope compartmentIdScope;
        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED,
                    Family));
        } else {
            QuicTestConnectServerRejected(
                Family
                );
        }
    }
};

class QuicAppData : public TestClass<QuicAppData>
{
    BEGIN_TEST_CLASS(QuicAppData)
        TEST_CLASS_PROPERTY(L"Data:Family", L"{4,6}")
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(Send)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Sends stream data.")
            TEST_METHOD_PROPERTY(L"Data:Length", L"{0,1000,10000}")
            TEST_METHOD_PROPERTY(L"Data:ConnectionCount", L"{1,2,4}")
            TEST_METHOD_PROPERTY(L"Data:StreamCount", L"{1,2,4}")
            TEST_METHOD_PROPERTY(L"Data:UseSendBuffer", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:UnidirectionalStreams", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:ServerInitiatedStreams", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, ConnectionCount, StreamCount, UseSendBuffer, UnidirectionalStreams, ServerInitiatedStreams;
        uint64_t Length;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Length", Length));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ConnectionCount", ConnectionCount));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"StreamCount", StreamCount));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UseSendBuffer", UseSendBuffer));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UnidirectionalStreams", UnidirectionalStreams));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ServerInitiatedStreams", ServerInitiatedStreams));

        LARGE_INTEGER Start, End, PerfFreq;
        QueryPerformanceCounter(&Start);

        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
                Family,
                Length,
                ConnectionCount,
                StreamCount,
                1,  // StreamBurstCount
                0,  // StreamBurstDelayMs
                0,  // ServerStatelessRetry
                0,  // ClientRebind
                0,  // ClientZeroRtt,
                0,  // ServerRejectZeroRtt
                (UINT8)UseSendBuffer,
                (UINT8)UnidirectionalStreams,
                (UINT8)ServerInitiatedStreams
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_AND_PING,
                    Params));
        } else {
            QuicTestConnectAndPing(
                Family,
                Length,
                ConnectionCount,
                StreamCount,
                1,      // StreamBurstCount
                0,      // StreamBurstDelayMs
                false,  // ServerStatelessRetry
                false,  // ClientRebind
                false,  // ClientZeroRtt
                false,  // ServerRejectZeroRtt
                UseSendBuffer != 0,
                UnidirectionalStreams != 0,
                ServerInitiatedStreams != 0
                );
        }

        QueryPerformanceCounter(&End);
        QueryPerformanceFrequency(&PerfFreq);

        LONGLONG elapsedMicroseconds = End.QuadPart - Start.QuadPart;
        elapsedMicroseconds *= 1000000;
        elapsedMicroseconds /= PerfFreq.QuadPart;

        Log::Comment(
            String().Format(
                L"%lld.%d milliseconds elapsed. %llu bytes on %u connections with %u streams",
                elapsedMicroseconds / 1000, (int)(elapsedMicroseconds % 1000),
                Length, ConnectionCount, StreamCount));
    }

#ifndef QUIC_DISABLE_0RTT
    TEST_METHOD(Send0Rtt)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Sends stream data.")
            TEST_METHOD_PROPERTY(L"Data:Length", L"{0,100,1000,2000}")
            TEST_METHOD_PROPERTY(L"Data:ConnectionCount", L"{1,2,4}")
            TEST_METHOD_PROPERTY(L"Data:StreamCount", L"{1,2,4}")
            TEST_METHOD_PROPERTY(L"Data:UseSendBuffer", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:UnidirectionalStreams", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, ConnectionCount, StreamCount, UseSendBuffer, UnidirectionalStreams;
        uint64_t Length;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Length", Length));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ConnectionCount", ConnectionCount));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"StreamCount", StreamCount));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UseSendBuffer", UseSendBuffer));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UnidirectionalStreams", UnidirectionalStreams));

        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
                Family,
                Length,
                ConnectionCount,
                StreamCount,
                1,  // StreamBurstCount
                0,  // StreamBurstDelayMs
                0,  // ServerStatelessRetry
                0,  // ClientRebind
                1,  // ClientZeroRtt,
                0,  // ServerRejectZeroRtt
                (UINT8)UseSendBuffer,
                (UINT8)UnidirectionalStreams,
                0   // ServerInitiatedStreams
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_AND_PING,
                    Params));
        } else {
            QuicTestConnectAndPing(
                Family,
                Length,
                ConnectionCount,
                StreamCount,
                1,      // StreamBurstCount
                0,      // StreamBurstDelayMs
                false,  // ServerStatelessRetry
                false,  // ClientRebind
                true,   // ClientZeroRtt,
                false,  // ServerRejectZeroRtt
                UseSendBuffer != 0,
                UnidirectionalStreams != 0,
                false   // ServerInitiatedStreams
                );
        }
    }

    TEST_METHOD(Reject0Rtt)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Sends stream data.")
            TEST_METHOD_PROPERTY(L"Data:Length", L"{0,1000,10000,20000}")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        uint64_t Length;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Length", Length));
    
        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
                Family,
                Length,
                1,  // ConnectionCount
                1,  // StreamCount
                1,  // StreamBurstCount
                0,  // StreamBurstDelayMs
                0,  // ServerStatelessRetry
                0,  // ClientRebind
                1,  // ClientZeroRtt
                1,  // ServerRejectZeroRtt
                0,  // UseSendBuffer
                0,  // UnidirectionalStreams
                0   // ServerInitiatedStreams
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_AND_PING,
                    Params));
        } else {
            QuicTestConnectAndPing(
                Family,
                Length,
                1,      // ConnectionCount
                1,      // StreamCount
                1,      // StreamBurstCount
                0,      // StreamBurstDelayMs
                false,  // ServerStatelessRetry
                false,  // ClientRebind
                true,   // ClientZeroRtt,
                true,   // ServerRejectZeroRtt
                false,  // UseSendBuffer
                false,  // UnidirectionalStreams
                false   // ServerInitiatedStreams
                );
        }
    }
#endif // QUIC_DISABLE_0RTT

    TEST_METHOD(SendLarge)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Sends large amount of data.")
            TEST_METHOD_PROPERTY(L"PGO", L"true")
            TEST_METHOD_PROPERTY(L"PGO_KERNEL", L"true")
#ifndef QUIC_DISABLE_0RTT
            TEST_METHOD_PROPERTY(L"Data:UseZeroRtt", L"{0,1}")
#endif
            TEST_METHOD_PROPERTY(L"Data:UseSendBuffer", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, UseZeroRtt, UseSendBuffer;
        uint64_t Length = 100000000llu;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
#ifndef QUIC_DISABLE_0RTT
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UseZeroRtt", UseZeroRtt));
#else
        UseZeroRtt = 0;
#endif
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UseSendBuffer", UseSendBuffer));

        LARGE_INTEGER Start, End, PerfFreq;
        QueryPerformanceCounter(&Start);

        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
                Family,
                Length,
                1,  // ConnectionCount
                1,  // StreamCount
                1,  // StreamBurstCount
                0,  // StreamBurstDelayMs
                0,  // ServerStatelessRetry
                0,  // ClientRebind
                (UINT8)UseZeroRtt,
                0,  // ServerRejectZeroRtt
                (UINT8)UseSendBuffer,
                0,  // UnidirectionalStreams
                0   // ServerInitiatedStreams
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_AND_PING,
                    Params));
        } else {
            QuicTestConnectAndPing(
                Family,
                Length,
                1,      // ConnectionCount
                1,      // StreamCount
                1,      // StreamBurstCount
                0,      // StreamBurstDelayMs
                false,  // ServerStatelessRetry
                false,  // ClientRebind
                UseZeroRtt != 0,
                false,  // ServerRejectZeroRtt
                UseSendBuffer != 0,
                false,  // UnidirectionalStreams
                false   // ServerInitiatedStreams
                );
        }

        QueryPerformanceCounter(&End);
        QueryPerformanceFrequency(&PerfFreq);

        LONGLONG elapsedMicroseconds = End.QuadPart - Start.QuadPart;
        elapsedMicroseconds *= 1000000;
        elapsedMicroseconds /= PerfFreq.QuadPart;

        Log::Comment(
            String().Format(
                L"%lld.%d milliseconds elapsed. %llu bytes on %u connections with %u streams",
                elapsedMicroseconds / 1000, (int)(elapsedMicroseconds % 1000),
                Length, 1, 1));
    }

    TEST_METHOD(SendIntermittently)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Sends 1 RTT secured data with pauses between bursts.")
            TEST_METHOD_PROPERTY(L"Data:Length", L"{1000,10000}")
            TEST_METHOD_PROPERTY(L"Data:BurstCount", L"{2,4,8}")
            TEST_METHOD_PROPERTY(L"Data:BurstDelay", L"{100,500,1000}")
            TEST_METHOD_PROPERTY(L"Data:UseSendBuffer", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, Length, BurstCount, BurstDelay, UseSendBuffer;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Length", Length));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"BurstCount", BurstCount));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"BurstDelay", BurstDelay));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UseSendBuffer", UseSendBuffer));

        if (IsTestingKernelMode()) {
            QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
                Family,
                Length,
                1,  // ConnectionCount
                1,  // StreamCount
                BurstCount,
                BurstDelay,
                0,  // ServerStatelessRetry
                0,  // ClientRebind
                0,  // ClientZeroRtt
                0,  // ServerRejectZeroRtt
                (UINT8)UseSendBuffer,
                0,  // UnidirectionalStreams
                0   // ServerInitiatedStreams
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_AND_PING,
                    Params));
        } else {
            QuicTestConnectAndPing(
                Family,
                Length,
                1,      // ConnectionCount
                1,      // StreamCount
                BurstCount,
                BurstDelay,
                false,  // ServerStatelessRetry
                false,  // ClientRebind
                false,  // ClientZeroRtt
                false,  // ServerRejectZeroRtt
                UseSendBuffer != 0,
                false,  // UnidirectionalStreams
                false   // ServerInitiatedStreams
                );
        }
    }
};

class QuicMisc : public TestClass<QuicMisc>
{
    BEGIN_TEST_CLASS(QuicMisc)
        TEST_CLASS_PROPERTY(L"BVT", L"true")
        TEST_CLASS_PROPERTY(L"BVT_KERNEL", L"true")
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(IdleTimeout)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests idle timeout and keep alives.")
            TEST_METHOD_PROPERTY(L"Data:EnableKeepAlive", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int EnableKeepAlive;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"EnableKeepAlive", EnableKeepAlive));

        if (IsTestingKernelMode()) {
            UINT8 Param = (UINT8)EnableKeepAlive;
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CONNECT_AND_IDLE,
                    Param));
        } else {
            QuicTestConnectAndIdle(EnableKeepAlive != 0);
        }
    }

    TEST_METHOD(ServerDisconnect)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests server ack idle (disconnect) logic.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_SERVER_DISCONNECT));
        } else {
            QuicTestServerDisconnect();
        }
    }

    TEST_METHOD(ClientDisconnect)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests client ack idle (disconnect) logic.")
            TEST_METHOD_PROPERTY(L"Data:StopListenerFirst", L"{0}")
            //TEST_METHOD_PROPERTY(L"Data:StopListenerFirst", L"{0,1}") Can we fix the race conditions with '1'?
        END_TEST_METHOD_PROPERTIES()

        int StopListenerFirst;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"StopListenerFirst", StopListenerFirst));

        if (IsTestingKernelMode()) {
            UINT8 Param = (UINT8)StopListenerFirst;
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CLIENT_DISCONNECT,
                    Param));
        } else {
            QuicTestClientDisconnect(StopListenerFirst != 0);
        }
    }

    TEST_METHOD(KeyUpdate)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Forces key update and sends data.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4,6}")
            TEST_METHOD_PROPERTY(L"Data:KeyUpdate", L"{0,1,2,3}")
        END_TEST_METHOD_PROPERTIES()

        int Family, KeyUpdate;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"KeyUpdate", KeyUpdate));

        if (IsTestingKernelMode()) {
            QUIC_RUN_KEY_UPDATE_PARAMS Params = {
                Family,
                KeyUpdate == 0 ? 5 : 1, // Iterations
                0,                      // KeyUpdateBytes
                KeyUpdate == 0,         // UseKeyUpdateBytes
                KeyUpdate & 1,          // Client Key Update
                KeyUpdate & 2           // Server Key Update
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_KEY_UPDATE,
                    Params));
        } else {
            QuicTestKeyUpdate(
                Family,
                KeyUpdate == 0 ? 5 : 1, // Iterations
                0,                      // KeyUpdateBytes
                KeyUpdate == 0,         // UseKeyUpdateBytes
                KeyUpdate & 1,          // ClientKeyUpdate
                KeyUpdate & 2           // ServerKeyUpdate
                );
        }
    }

    TEST_METHOD(AbortiveShutdown)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests shutting down the stream, abruptly.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4,6}")
            TEST_METHOD_PROPERTY(L"Data:DelayStreamCreation", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:SendDataOnStream", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:ClientShutdown", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:DelayClientShutdown", L"{0,1}")
            TEST_METHOD_PROPERTY(L"Data:WaitForStream", L"{1}")
            TEST_METHOD_PROPERTY(L"Data:ShutdownDirection", L"{0,1,2}")
            TEST_METHOD_PROPERTY(L"Data:UnidirectionalStream", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int Family, DelayStreamCreation, SendDataOnStream, ClientShutdown, DelayClientShutdown,
            WaitForStream, ShutdownDirection, UnidirectionalStream;

        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"DelayStreamCreation", DelayStreamCreation));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"SendDataOnStream", SendDataOnStream));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ClientShutdown", ClientShutdown));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"DelayClientShutdown", DelayClientShutdown));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"WaitForStream", WaitForStream));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ShutdownDirection", ShutdownDirection));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"UnidirectionalStream", UnidirectionalStream));

        QUIC_ABORTIVE_TRANSFER_FLAGS Flags = { 0 };
        Flags.DelayStreamCreation = DelayStreamCreation;
        Flags.SendDataOnStream = SendDataOnStream;
        Flags.ClientShutdown = ClientShutdown;
        Flags.DelayClientShutdown = DelayClientShutdown;
        Flags.WaitForStream = WaitForStream;
        Flags.ShutdownDirection = (uint32_t) ShutdownDirection;
        Flags.UnidirectionalStream = UnidirectionalStream;

        if (IsTestingKernelMode()) {
            QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS Params = {
                Family,
                Flags
            };
            VERIFY_NO_ERROR(TestClient.SendIOCTL(
                IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN,
                Params));
        } else {
            QuicAbortiveTransfers(Family, Flags);
        }
    }

    TEST_METHOD(CidUpdate)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Forces CID update and sends data.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4,6}")
            TEST_METHOD_PROPERTY(L"Data:Iterations", L"{1,2,4}")
        END_TEST_METHOD_PROPERTIES()

        int Family, Iterations;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Iterations", Iterations));

        if (IsTestingKernelMode()) {
            QUIC_RUN_CID_UPDATE_PARAMS Params = {
                Family,
                (uint16_t)Iterations
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_CID_UPDATE,
                    Params));
        } else {
            QuicTestCidUpdate(
                Family,
                (uint16_t)Iterations
                );
        }
    }

    TEST_METHOD(ReceiveResume)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests resuming partial stream receives.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4, 6}")
            TEST_METHOD_PROPERTY(L"Data:ConsumeBytes", L"{0, 1, 99}")
            TEST_METHOD_PROPERTY(L"Data:SendBytes", L"{100}")
            TEST_METHOD_PROPERTY(L"Data:PauseFirst", L"{0, 1}")
            TEST_METHOD_PROPERTY(L"Data:ShutdownType", L"{0, 1, 2}")
            TEST_METHOD_PROPERTY(L"Data:PauseType", L"{0, 1, 2}")
        END_TEST_METHOD_PROPERTIES()

        int Family, ConsumeBytes, SendBytes, PauseFirst, ShutdownType, PauseType;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ConsumeBytes", ConsumeBytes));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"SendBytes", SendBytes));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"PauseFirst", PauseFirst));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ShutdownType", ShutdownType));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"PauseType", PauseType));

        if (IsTestingKernelMode()) {
            QUIC_RUN_RECEIVE_RESUME_PARAMS Params = {
                Family,
                SendBytes,
                ConsumeBytes,
                (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE) ShutdownType,
                (QUIC_RECEIVE_RESUME_TYPE) PauseType,
                (uint8_t) PauseFirst
            };
            VERIFY_NO_ERROR(TestClient.SendIOCTL(
                IOCTL_QUIC_RUN_RECEIVE_RESUME,
                Params));
        } else {
            QuicTestReceiveResume(
                Family,
                SendBytes,
                ConsumeBytes,
                (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE) ShutdownType,
                (QUIC_RECEIVE_RESUME_TYPE) PauseType,
                PauseFirst);
        }
    }

    TEST_METHOD(ReceiveResumeNoData)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests shutting down a paused stream.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4, 6}")
            TEST_METHOD_PROPERTY(L"Data:ShutdownType", L"{1, 2}")
        END_TEST_METHOD_PROPERTIES()

        int Family, ShutdownType;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ShutdownType", ShutdownType));
        if (IsTestingKernelMode()) {
            QUIC_RUN_RECEIVE_RESUME_PARAMS Params = {
                Family,
                0,
                0,
                (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE) ShutdownType,
                ReturnConsumedBytes,
                0
            };
            VERIFY_NO_ERROR(TestClient.SendIOCTL(
                IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA,
                Params));
        } else {
            QuicTestReceiveResumeNoData(
                Family,
                (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE) ShutdownType);
        }
    }
};

class QuicDrill : public TestClass<QuicDrill>
{
    BEGIN_TEST_CLASS(QuicDrill)
        TEST_CLASS_PROPERTY(L"BVT", L"true")
        TEST_CLASS_PROPERTY(L"BVT_KERNEL", L"true")
        TEST_CLASS_PROPERTY(L"Parallel", L"true")
    END_TEST_CLASS()

    TEST_METHOD(VarIntEncoder)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests the variable integer encoder in QuicDrill.")
        END_TEST_METHOD_PROPERTIES()

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(TestClient.SendIOCTL(IOCTL_QUIC_RUN_DRILL_ENCODE_VAR_INT));
        } else {
            QuicDrillTestVarIntEncoder();
        }
    }

    TEST_METHOD(InitialPacketCIDs)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests that Initial packets with invalid CIDs are rejected by MsQuic.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4, 6}")
            TEST_METHOD_PROPERTY(L"Data:SourceOrDestCid", L"{1, 0}")
            TEST_METHOD_PROPERTY(L"Data:ActualCidLengthValid", L"{1, 0}")
            TEST_METHOD_PROPERTY(L"Data:ShortCidLength", L"{1, 0}")
            TEST_METHOD_PROPERTY(L"Data:CidLengthFieldValid", L"{1, 0}")
        END_TEST_METHOD_PROPERTIES()

        int Family, SourceOrDestCid, ActualCidLengthValid, ShortCidLength, CidLengthFieldValid;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"SourceOrDestCid", SourceOrDestCid));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ActualCidLengthValid", ActualCidLengthValid));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"ShortCidLength", ShortCidLength));
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"CidLengthFieldValid", CidLengthFieldValid));

        if (IsTestingKernelMode()) {
            QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS Params = {
                Family,
                (BOOLEAN) SourceOrDestCid,
                (BOOLEAN) ActualCidLengthValid,
                (BOOLEAN) ShortCidLength,
                (BOOLEAN) CidLengthFieldValid
            };
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_CID,
                    Params));
        } else {
            QuicDrillTestInitialCid(
                Family,
                SourceOrDestCid,
                ActualCidLengthValid,
                ShortCidLength,
                CidLengthFieldValid);
        }
    }

    TEST_METHOD(InitialPacketToken)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Description", L"Tests that Initial packets with invalid Token field are rejected by MsQuic.")
            TEST_METHOD_PROPERTY(L"Data:Family", L"{4, 6}")
        END_TEST_METHOD_PROPERTIES()

        int Family;
        VERIFY_SUCCEEDED(TestData::TryGetValue(L"Family", Family));

        if (IsTestingKernelMode()) {
            VERIFY_NO_ERROR(
                TestClient.SendIOCTL(
                    IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN,
                    Family));
        } else {
            QuicDrillTestInitialToken(Family);
        }
    }
};
