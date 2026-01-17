/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.cpp.clog.h"
#endif

#include <MsQuicTests.h>

#include <array>

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
#pragma message("Test compiled with datapath hooks enabled")
#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#pragma message("Test compiled with preview features enabled")
#endif

bool TestingKernelMode = false;
bool PrivateTestLibrary = false;
bool UseDuoNic = false;
CXPLAT_WORKER_POOL* WorkerPool;
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
bool UseQTIP = false;
#endif
const MsQuicApi* MsQuic;
const char* OsRunner = nullptr;
uint32_t Timeout = UINT32_MAX;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;
QuicDriverClient DriverClient;

//
// These are explicitly passed in as the name of the GitHub/Azure runners.
//
bool IsWindows2019() { return OsRunner && strcmp(OsRunner, "windows-2019") == 0; }
bool IsWindows2022() { return OsRunner && strcmp(OsRunner, "windows-2022") == 0; }
bool IsWindows2025() { return OsRunner && strcmp(OsRunner, "windows-2025") == 0; }

class QuicTestEnvironment : public ::testing::Environment {
    QuicDriverService DriverService;
    const QUIC_CREDENTIAL_CONFIG* SelfSignedCertParams;
    const QUIC_CREDENTIAL_CONFIG* ClientCertParams;
    CxPlatWatchdog* watchdog {nullptr};
public:
    void SetUp() override {
        CxPlatSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatInitialize()));
        WorkerPool = CxPlatWorkerPoolCreate(nullptr, CXPLAT_WORKER_POOL_REF_TOOL);
        watchdog = new CxPlatWatchdog(Timeout);
        ASSERT_TRUE((SelfSignedCertParams =
            CxPlatGetSelfSignedCert(
                TestingKernelMode ?
                    CXPLAT_SELF_SIGN_CERT_MACHINE :
                    CXPLAT_SELF_SIGN_CERT_USER,
                FALSE, NULL
                )) != nullptr);

        ASSERT_TRUE((ClientCertParams =
            CxPlatGetSelfSignedCert(
                TestingKernelMode ?
                    CXPLAT_SELF_SIGN_CERT_MACHINE :
                    CXPLAT_SELF_SIGN_CERT_USER,
                TRUE, NULL
                )) != nullptr);

        if (TestingKernelMode) {
            printf("Initializing for Kernel Mode tests\n");
            const char* DriverName;
            const char* DependentDriverNames;
            QUIC_RUN_CERTIFICATE_PARAMS CertParams;
            CxPlatZeroMemory(&CertParams, sizeof(CertParams));
            CxPlatCopyMemory(
                &CertParams.ServerCertHash.ShaHash,
                (QUIC_CERTIFICATE_HASH*)(SelfSignedCertParams + 1),
                sizeof(QUIC_CERTIFICATE_HASH));
            CxPlatCopyMemory(
                &CertParams.ClientCertHash.ShaHash,
                (QUIC_CERTIFICATE_HASH*)(ClientCertParams + 1),
                sizeof(QUIC_CERTIFICATE_HASH));
            if (PrivateTestLibrary) {
                DriverName = QUIC_DRIVER_NAME_PRIVATE;
                DependentDriverNames = "msquicpriv\0";
            } else {
                DriverName = QUIC_DRIVER_NAME;
                DependentDriverNames = "msquic\0";
            }
            ASSERT_TRUE(DriverService.Initialize(DriverName, DependentDriverNames));
            ASSERT_TRUE(DriverService.Start());
            ASSERT_TRUE(DriverClient.Initialize(&CertParams, DriverName));

            QUIC_TEST_CONFIGURATION_PARAMS Params {
                UseDuoNic,
                0
            };

#ifdef _WIN32
            ASSERT_NE(GetCurrentDirectoryA(sizeof(Params.CurrentDirectory), Params.CurrentDirectory), 0);
            strcat_s(Params.CurrentDirectory, "\\");
#endif

            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_TEST_CONFIGURATION, Params));

        } else {
            printf("Initializing for User Mode tests\n");
            MsQuic = new(std::nothrow) MsQuicApi();
            ASSERT_TRUE(QUIC_SUCCEEDED(MsQuic->GetInitStatus()));
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            if (UseDuoNic) {
                MsQuicSettings Settings;
                Settings.SetXdpEnabled(true);
                ASSERT_TRUE(QUIC_SUCCEEDED(Settings.SetGlobal()));
            }
            if (UseQTIP) {
                MsQuicSettings Settings;
                Settings.SetQtipEnabled(true);
                ASSERT_TRUE(QUIC_SUCCEEDED(Settings.SetGlobal()));
            }
#endif
            //
            // Enable DSCP on the receive path. This is needed to test DSCP Send path.
            //
            BOOLEAN Option = TRUE;
            ASSERT_TRUE(QUIC_SUCCEEDED(MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_DATAPATH_DSCP_RECV_ENABLED,
                sizeof(BOOLEAN),
                &Option)));
            memcpy(&ServerSelfSignedCredConfig, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            memcpy(&ServerSelfSignedCredConfigClientAuth, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ServerSelfSignedCredConfigClientAuth.Flags |=
                QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
                QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
            memcpy(&ClientCertCredConfig, ClientCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ClientCertCredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
            QuicTestInitialize();

#ifdef _WIN32
            ASSERT_NE(GetCurrentDirectoryA(sizeof(CurrentWorkingDirectory), CurrentWorkingDirectory), 0);
#else
            ASSERT_NE(getcwd(CurrentWorkingDirectory, sizeof(CurrentWorkingDirectory)), nullptr);
#endif
        }
    }
    void TearDown() override {
        if (TestingKernelMode) {
            DriverClient.Uninitialize();
            DriverService.Uninitialize();
        } else {
            QuicTestUninitialize();
            delete MsQuic;
        }
        CxPlatFreeSelfSignedCert(SelfSignedCertParams);
        CxPlatFreeSelfSignedCert(ClientCertParams);

        CxPlatWorkerPoolDelete(WorkerPool, CXPLAT_WORKER_POOL_REF_TOOL);
        CxPlatUninitialize();
        CxPlatSystemUnload();
        delete watchdog;
    }
};

//
// This function is called by the platform independent test code when it
// encounters kind of failure. Note - It may be called on any thread.
//
void
LogTestFailure(
    _In_z_ const char* File,
    _In_z_ const char* Function,
    int Line,
    _Printf_format_string_ const char* Format,
    ...
    )
{
    UNREFERENCED_PARAMETER(Function);
    char Buffer[256];
    va_list Args;
    va_start(Args, Format);
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, Format, Args);
    va_end(Args);
    QuicTraceLogError(
        TestLogFailure,
        "[test] FAILURE - %s:%d - %s",
        File,
        Line,
        Buffer);
    GTEST_MESSAGE_AT_(File, Line, Buffer, ::testing::TestPartResult::kFatalFailure);
}

struct TestLogger {
    const char* TestName;
    TestLogger(const char* Name) : TestName(Name) {
        QuicTraceLogInfo(
            TestCaseStart,
            "[test] START %s",
            TestName);
    }
    ~TestLogger() {
        QuicTraceLogInfo(
            TestCaseEnd,
            "[test] END %s",
            TestName);
    }
};

template<class T>
struct TestLoggerT {
    const char* TestName;
    TestLoggerT(const char* Name, const T& Params) : TestName(Name) {
        std::ostringstream stream; stream << Params;
        QuicTraceLogInfo(
            TestCaseTStart,
            "[test] START %s, %s",
            TestName,
            stream.str().c_str());
    }
    ~TestLoggerT() {
        QuicTraceLogInfo(
            TestCaseTEnd,
            "[test] END %s",
            TestName);
    }
};

// Helpers to invoke a test in kernel mode through the test driver.

template<class FunType>
bool InvokeKernelTest(const std::string& Name, FunType) {
    static_assert(std::is_invocable_v<FunType>, "Invalid parameters for test function");
    QUIC_RUN_TEST_REQUEST Request{};
    Name.copy(Request.FunctionName, sizeof(Request.FunctionName));

    return DriverClient.Run(IOCTL_QUIC_RUN_TEST, (void*)&Request, (uint32_t)sizeof(Request));
}

template<class FunType, class ParamType>
bool InvokeKernelTest(const std::string& Name, FunType, const ParamType& Params) {
    static_assert(std::is_invocable_v<FunType, const ParamType&>, "Invalid parameters for test function");
    static_assert(std::is_pod_v<ParamType>, "ParamType must be POD");

    // Serialize the request header and arguments
    std::array<uint8_t, sizeof(QUIC_RUN_TEST_REQUEST) + sizeof(ParamType)> Buffer{};
    auto& Request = *reinterpret_cast<QUIC_RUN_TEST_REQUEST*>(Buffer.data());
    Name.copy(Request.FunctionName, sizeof(Request.FunctionName));
    Request.ParameterSize = sizeof(ParamType);
    std::copy_n(
        reinterpret_cast<const uint8_t*>(&Params),
        sizeof(ParamType), Buffer.data() + sizeof(QUIC_RUN_TEST_REQUEST));

    return DriverClient.Run(IOCTL_QUIC_RUN_TEST, (void*)Buffer.data(), (uint32_t)Buffer.size());
}

#define FUNC(TestFunction) \
    #TestFunction, TestFunction

TEST(ParameterValidation, ValidateGlobalParam) {
    TestLogger Logger("QuicTestValidateGlobalParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestGlobalParam)));
    } else {
        QuicTestGlobalParam();
    }
}

TEST(ParameterValidation, ValidateCommonParam) {
    TestLogger Logger("QuicTestValidateCommonParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCommonParam)));
    } else {
        QuicTestCommonParam();
    }
}

TEST(ParameterValidation, ValidateRegistrationParam) {
    TestLogger Logger("QuicTestValidateRegistrationParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRegistrationParam)));
    } else {
        QuicTestRegistrationParam();
    }
}

TEST(ParameterValidation, ValidateConfigurationParam) {
    TestLogger Logger("QuicTestValidateConfigurationParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConfigurationParam)));
    } else {
        QuicTestConfigurationParam();
    }
}

TEST(ParameterValidation, ValidateListenerParam) {
    TestLogger Logger("QuicTestValidateListenerParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestListenerParam)));
    } else {
        QuicTestListenerParam();
    }
}

TEST(ParameterValidation, ValidateConnectionParam) {
    TestLogger Logger("QuicTestValidateConnectionParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectionParam)));
    } else {
        QuicTestConnectionParam();
    }
}

TEST(ParameterValidation, ValidateTlsParam) {
    TestLogger Logger("QuicTestValidateTlsParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestTlsParam)));
    } else {
        QuicTestTlsParam();
    }
}

TEST_P(WithBool, ValidateTlsHandshakeInfo) {
    TestLoggerT<ParamType> Logger("QuicTestValidateTlsHandshakeInfo", GetParam());
    if (TestingKernelMode) {
        if (IsWindows2022() || IsWindows2019()) {
            GTEST_SKIP(); // Not supported on WS2019 or WS2022
        }
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestTlsHandshakeInfo), GetParam()));
    } else {
        QuicTestTlsHandshakeInfo(GetParam());
    }
}

TEST(ParameterValidation, ValidateStreamParam) {
    TestLogger Logger("QuicTestValidateStreamParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamParam)));
    } else {
        QuicTestStreamParam();
    }
}

TEST(ParameterValidation, ValidateGetPerfCounters) {
    TestLogger Logger("QuicTestGetPerfCounters");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestGetPerfCounters)));
    } else {
        QuicTestGetPerfCounters();
    }
}

TEST(ParameterValidation, ValidateConfiguration) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) {
        GTEST_SKIP(); // Not supported with Schannel on WS2022
    }
#endif
    TestLogger Logger("QuicTestValidateConfiguration");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateConfiguration)));
    } else {
        QuicTestValidateConfiguration();
    }
}

TEST(ParameterValidation, ValidateListener) {
    TestLogger Logger("QuicTestValidateListener");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateListener)));
    } else {
        QuicTestValidateListener();
    }
}

TEST(ParameterValidation, ValidateConnection) {
    TestLogger Logger("QuicTestValidateConnection");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateConnection)));
    } else {
        QuicTestValidateConnection();
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(ParameterValidation, ValidateConnectionPoolCreate) {
    TestLogger Logger("QuicTestValidateConnectionPoolCreate");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateConnectionPoolCreate)));
    } else {
        QuicTestValidateConnectionPoolCreate();
    }
}

TEST(ParameterValidation, ValidateExecutionContext) {
    TestLogger Logger("QuicTestValidateExecutionContext");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateExecutionContext)));
    } else {
        QuicTestValidateExecutionContext();
    }
}
TEST(ParameterValidation, ValidatePartition) {
    TestLogger Logger("QuicTestValidatePartition");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidatePartition)));
    } else {
        QuicTestValidatePartition();
    }
}
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

TEST(OwnershipValidation, RegistrationShutdownBeforeConnOpen) {
    TestLogger Logger("RegistrationShutdownBeforeConnOpen");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRegistrationShutdownBeforeConnOpen)));
    } else {
        QuicTestRegistrationShutdownBeforeConnOpen();
    }
}

TEST(OwnershipValidation, RegistrationShutdownAfterConnOpen) {
    TestLogger Logger("RegistrationShutdownAfterConnOpen");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRegistrationShutdownAfterConnOpen)));
    } else {
        QuicTestRegistrationShutdownAfterConnOpen();
    }
}

TEST(OwnershipValidation, RegistrationShutdownAfterConnOpenBeforeStart) {
    TestLogger Logger("RegistrationShutdownAfterConnOpenBeforeStart");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRegistrationShutdownAfterConnOpenBeforeStart)));
    } else {
        QuicTestRegistrationShutdownAfterConnOpenBeforeStart();
    }
}

TEST(OwnershipValidation, RegistrationShutdownAfterConnOpenAndStart) {
    TestLogger Logger("RegistrationShutdownAfterConnOpenAndStart");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRegistrationShutdownAfterConnOpenAndStart)));
    } else {
        QuicTestRegistrationShutdownAfterConnOpenAndStart();
    }
}

TEST(OwnershipValidation, ConnectionCloseBeforeStreamClose) {
    TestLogger Logger("ConnectionCloseBeforeStreamClose");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectionCloseBeforeStreamClose)));
    } else {
        QuicTestConnectionCloseBeforeStreamClose();
    }
}

TEST_P(WithBool, ValidateStream) {
    TestLoggerT<ParamType> Logger("QuicTestValidateStream", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateStream), GetParam()));
    } else {
        QuicTestValidateStream(GetParam());
    }
}

TEST(ParameterValidation, CloseConnBeforeStreamFlush) {
    TestLogger Logger("QuicTestCloseConnBeforeStreamFlush");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCloseConnBeforeStreamFlush)));
    } else {
        QuicTestCloseConnBeforeStreamFlush();
    }
}

TEST_P(WithValidateConnectionEventArgs, ValidateConnectionEvents) {
    TestLoggerT<ParamType> Logger("QuicTestValidateConnectionEvents", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateConnectionEvents), GetParam()));
    } else {
        QuicTestValidateConnectionEvents(GetParam());
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST_P(WithValidateNetStatsConnEventArgs, ValidateNetStatConnEvent) {
    TestLoggerT<ParamType> Logger("QuicTestValidateNetStatsConnEvent", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateNetStatsConnEvent), GetParam()));
    } else {
        QuicTestValidateNetStatsConnEvent(GetParam());
    }
}
#endif

TEST_P(WithValidateStreamEventArgs, ValidateStreamEvents) {
    TestLoggerT<ParamType> Logger("QuicTestValidateStreamEvents", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateStreamEvents), GetParam()));
    } else {
        QuicTestValidateStreamEvents(GetParam());
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(ParameterValidation, ValidateVersionSettings) {
    TestLogger Logger("QuicTestVersionSettings");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVersionSettings)));
    } else {
        QuicTestVersionSettings();
    }
}
#endif

TEST(ParameterValidation, ValidateParamApi) {
    TestLogger Logger("QuicTestValidateParamApi");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidateParamApi)));
    } else {
        QuicTestValidateParamApi();
    }
}

TEST_P(WithValidateTlsConfigArgs, ValidateTlsConfig) {
    TestLogger Logger("QuicTestCredentialLoad");
    if (TestingKernelMode &&
        GetParam().CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        GTEST_SKIP_("Cert Context not supported in kernel mode");
    }
    QUIC_RUN_CRED_VALIDATION Arg;
    CxPlatZeroMemory(&Arg, sizeof(Arg));
    ASSERT_TRUE(
        CxPlatGetTestCertificate(
            GetParam().CertType,
            TestingKernelMode ? CXPLAT_SELF_SIGN_CERT_MACHINE : CXPLAT_SELF_SIGN_CERT_USER,
            GetParam().CredType,
            &Arg.CredConfig,
            &Arg.CertHash,
            &Arg.CertHashStore,
            &Arg.CertFile,
            &Arg.CertFileProtected,
            &Arg.Pkcs12,
            NULL));
    Arg.CredConfig.Flags =
        GetParam().CertType == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT ?
            QUIC_CREDENTIAL_FLAG_CLIENT :
            QUIC_CREDENTIAL_FLAG_NONE;
    ASSERT_TRUE(GetParam().CertType == CXPLAT_TEST_CERT_SELF_SIGNED_SERVER ||
        GetParam().CertType == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT);

    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CRED_TYPE_VALIDATION, Arg));
    } else {
        QuicTestCredentialLoad(&Arg.CredConfig);
    }

    CxPlatFreeTestCert(&Arg.CredConfig);
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(Basic, RegistrationOpenClose) {
    TestLogger Logger("QuicTestRegistrationOpenClose");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRegistrationOpenClose)));
    } else {
        QuicTestRegistrationOpenClose();
    }
}
#endif

TEST(Basic, CreateListener) {
    TestLogger Logger("QuicTestCreateListener");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCreateListener)));
    } else {
        QuicTestCreateListener();
    }
}

TEST(Basic, StartListener) {
    TestLogger Logger("QuicTestStartListener");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStartListener)));
    } else {
        QuicTestStartListener();
    }
}

TEST(Basic, StartListenerMultiAlpns) {
    TestLogger Logger("QuicTestStartListenerMultiAlpns");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStartListenerMultiAlpns)));
    } else {
        QuicTestStartListenerMultiAlpns();
    }
}

TEST_P(WithFamilyArgs, StartListenerImplicit) {
    TestLoggerT<ParamType> Logger("QuicTestStartListenerImplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStartListenerImplicit), GetParam()));
    } else {
        QuicTestStartListenerImplicit(GetParam());
    }
}

TEST(Basic, StartTwoListeners) {
    TestLogger Logger("QuicTestStartTwoListeners");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStartTwoListeners)));
    } else {
        QuicTestStartTwoListeners();
    }
}

TEST(Basic, StartTwoListenersSameALPN) {
    TestLogger Logger("QuicTestStartTwoListenersSameALPN");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStartTwoListenersSameALPN)));
    } else {
        QuicTestStartTwoListenersSameALPN();
    }
}

TEST_P(WithFamilyArgs, StartListenerExplicit) {
    TestLoggerT<ParamType> Logger("QuicTestStartListenerExplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStartListenerExplicit), GetParam()));
    } else {
        QuicTestStartListenerExplicit(GetParam());
    }
}

TEST(Basic, CreateConnection) {
    TestLogger Logger("QuicTestCreateConnection");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCreateConnection)));
    } else {
        QuicTestCreateConnection();
    }
}

TEST(Basic, ConnectionCloseFromCallback) {
    TestLogger Logger("QuicTestConnectionCloseFromCallback");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectionCloseFromCallback)));
    } else {
        QuicTestConnectionCloseFromCallback();
    }
}

TEST_P(WithBool, RejectConnection) {
    TestLoggerT<ParamType> Logger("QuicTestConnectionRejection", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectionRejection), GetParam()));
    } else {
        QuicTestConnectionRejection(GetParam());
    }
}

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithFamilyArgs, Ecn) {
    TestLoggerT<ParamType> Logger("Ecn", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestEcn), GetParam()));
    } else {
        QuicTestEcn(GetParam());
    }
}

TEST_P(WithFamilyArgs, LocalPathChanges) {
    TestLoggerT<ParamType> Logger("QuicTestLocalPathChanges", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestLocalPathChanges), GetParam()));
    } else {
        QuicTestLocalPathChanges(GetParam());
    }
}

TEST(Mtu, Settings) {
    TestLogger Logger("QuicTestMtuSettings");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestMtuSettings)));
    } else {
        QuicTestMtuSettings();
    }
}

TEST_P(WithMtuArgs, MtuDiscovery) {
    TestLoggerT<ParamType> Logger("QuicTestMtuDiscovery", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestMtuDiscovery), GetParam()));
    }
    else {
        QuicTestMtuDiscovery(GetParam());
    }
}

#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

TEST(Alpn, ValidAlpnLengths) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLogger Logger("QuicTestValidAlpnLengths");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestValidAlpnLengths)));
    } else {
        QuicTestValidAlpnLengths();
    }
}

TEST(Alpn, InvalidAlpnLengths) {
    TestLogger Logger("QuicTestInvalidAlpnLengths");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestInvalidAlpnLengths)));
    } else {
        QuicTestInvalidAlpnLengths();
    }
}

TEST(Alpn, ChangeAlpn) {
    TestLogger Logger("QuicTestChangeAlpn");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestChangeAlpn)));
    } else {
        QuicTestChangeAlpn();
    }
}


TEST_P(WithFamilyArgs, BindConnectionImplicit) {
    TestLoggerT<ParamType> Logger("QuicTestBindConnectionImplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestBindConnectionImplicit), GetParam()));
    } else {
        QuicTestBindConnectionImplicit(GetParam());
    }
}

TEST_P(WithFamilyArgs, BindConnectionExplicit) {
    TestLoggerT<ParamType> Logger("QuicTestBindConnectionExplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestBindConnectionExplicit), GetParam()));
    } else {
        QuicTestBindConnectionExplicit(GetParam());
    }
}

TEST_P(WithFamilyArgs, TestAddrFunctions) {
    TestLoggerT<ParamType> Logger("QuicTestAddrFunctions", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAddrFunctions), GetParam()));
    }
    else {
        QuicTestAddrFunctions(GetParam());
    }
}

struct WithHandshakeArgs1 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs> {

    static ::std::vector<HandshakeArgs> Generate() {
        ::std::vector<HandshakeArgs> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
        for (bool GreaseQuicBitExtension : { false, true })
            list.push_back({ Family, ServerStatelessRetry, MultipleALPNs, MultiPacketClientInitial, GreaseQuicBitExtension });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultipleALPNs ? "MultipleALPNs" : "SingleALPN") << "/" <<
        (args.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial") << "/" <<
        (args.GreaseQuicBitExtension ? "Grease" : "NoGrease");
}

TEST_P(WithHandshakeArgs1, Connect) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-Connect", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_Connect), GetParam()));
    } else {
        QuicTestConnect_Connect(GetParam());
    }
}

#ifndef QUIC_DISABLE_RESUMPTION
TEST_P(WithHandshakeArgs1, Resume) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-Resume", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_Resume), GetParam()));
    } else {
        QuicTestConnect_Resume(GetParam());
    }
}

TEST_P(WithHandshakeArgs1, ResumeAsync) {
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeAsync", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_ResumeAsync), GetParam()));
    } else {
        QuicTestConnect_ResumeAsync(GetParam());
    }
}

TEST_P(WithHandshakeArgs1, ResumeRejection) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeRejection", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_ResumeRejection), GetParam()));
    } else {
        QuicTestConnect_ResumeRejection(GetParam());
    }
}

TEST_P(WithHandshakeArgs1, ResumeRejectionByServerApp) {
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeRejectionByServerApp", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_ResumeRejectionByServerApp), GetParam()));
    } else {
        QuicTestConnect_ResumeRejectionByServerApp(GetParam());
    }
}

TEST_P(WithHandshakeArgs1, ResumeRejectionByServerAppAsync) {
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeRejectionByServerAppAsync", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_ResumeRejectionByServerAppAsync), GetParam()));
    } else {
        QuicTestConnect_ResumeRejectionByServerAppAsync(GetParam());
    }
}
#endif // QUIC_DISABLE_RESUMPTION

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs1,
    testing::ValuesIn(WithHandshakeArgs1::Generate()));


#ifndef QUIC_DISABLE_SHARED_PORT_TESTS
TEST_P(WithFamilyArgs, ClientSharedLocalPort) {
    TestLoggerT<ParamType> Logger("QuicTestClientSharedLocalPort", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestClientSharedLocalPort), GetParam()));
    } else {
        QuicTestClientSharedLocalPort(GetParam());
    }
}
#endif

TEST_P(WithFamilyArgs, InterfaceBinding) {
    TestLoggerT<ParamType> Logger("QuicTestInterfaceBinding", GetParam());
    if (UseDuoNic) {
        GTEST_SKIP_("DuoNIC is not supported");
    }
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestInterfaceBinding), GetParam()));
    } else {
        QuicTestInterfaceBinding(GetParam());
    }
}

TEST_P(WithFamilyArgs, RetryMemoryLimitConnect) {
    TestLoggerT<ParamType> Logger("QuicTestRetryMemoryLimitConnect", GetParam());
    if (UseDuoNic) {
        GTEST_SKIP_("DuoNIC is not supported");
    }
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRetryMemoryLimitConnect), GetParam()));
    } else {
        QuicTestRetryMemoryLimitConnect(GetParam());
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

struct WithHandshakeArgs2 :
    public testing::TestWithParam<HandshakeArgs> {

    static ::std::vector<HandshakeArgs> Generate() {
        ::std::vector<HandshakeArgs> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
            list.push_back({ Family, ServerStatelessRetry, false, false, false });
        return list;
    }
};

TEST_P(WithHandshakeArgs2, OldVersion) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-OldVersion", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_OldVersion), GetParam()));
    } else {
        QuicTestConnect_OldVersion(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs2,
    testing::ValuesIn(WithHandshakeArgs2::Generate()));
#endif

struct WithHandshakeArgs3 :
    public testing::TestWithParam<HandshakeArgs> {

    static ::std::vector<HandshakeArgs> Generate() {
        ::std::vector<HandshakeArgs> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
            list.push_back({ Family, ServerStatelessRetry, MultipleALPNs, false, false });
        return list;
    }
};

TEST_P(WithHandshakeArgs3, AsyncSecurityConfig) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-AsyncSecurityConfig", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_AsyncSecurityConfig), GetParam()));
    } else {
        QuicTestConnect_AsyncSecurityConfig(GetParam());
    }
}

TEST_P(WithHandshakeArgs3, AsyncSecurityConfig_Delayed) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-AsyncSecurityConfig_Delayed", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_AsyncSecurityConfig_Delayed), GetParam()));
    } else {
        QuicTestConnect_AsyncSecurityConfig_Delayed(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs3,
    testing::ValuesIn(WithHandshakeArgs3::Generate()));

// Version negociation tests

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

struct WithVersionNegotiationExtArgs : public testing::Test,
    public testing::WithParamInterface<VersionNegotiationExtArgs> {

    static ::std::vector<VersionNegotiationExtArgs> Generate() {
        ::std::vector<VersionNegotiationExtArgs> list;
        for (int Family : { 4, 6 })
        for (bool DisableVNEClient : { false, true })
        for (bool DisableVNEServer : { false, true })
            list.push_back({ Family, DisableVNEClient, DisableVNEServer });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const VersionNegotiationExtArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.DisableVNEClient ? "DisableClient" : "EnableClient") << "/" <<
        (args.DisableVNEServer ? "DisableServer" : "EnableServer");
}

TEST_P(WithFamilyArgs, VersionNegotiation) {
    TestLoggerT<ParamType> Logger("QuicTestVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVersionNegotiation), GetParam()));
    } else {
        QuicTestVersionNegotiation(GetParam());
    }
}

TEST_P(WithFamilyArgs, VersionNegotiationRetry) {
    TestLoggerT<ParamType> Logger("QuicTestVersionNegotiationRetry", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVersionNegotiationRetry), GetParam()));
    } else {
        QuicTestVersionNegotiationRetry(GetParam());
    }
}

TEST_P(WithFamilyArgs, CompatibleVersionNegotiationRetry) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiationRetry", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCompatibleVersionNegotiationRetry), GetParam()));
    } else {
        QuicTestCompatibleVersionNegotiationRetry(GetParam());
    }
}

TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiation) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCompatibleVersionNegotiation), GetParam()));
    } else {
        QuicTestCompatibleVersionNegotiation(GetParam());
    }
}

TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultServer) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiationDefaultServer", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCompatibleVersionNegotiationDefaultServer), GetParam()));
    } else {
        QuicTestCompatibleVersionNegotiationDefaultServer(GetParam());
    }
}

TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultClient) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiationDefaultClient", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCompatibleVersionNegotiationDefaultClient), GetParam()));
    } else {
        QuicTestCompatibleVersionNegotiationDefaultClient(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithVersionNegotiationExtArgs,
    testing::ValuesIn(WithVersionNegotiationExtArgs::Generate()));

TEST_P(WithFamilyArgs, IncompatibleVersionNegotiation) {
    TestLoggerT<ParamType> Logger("IncompatibleVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestIncompatibleVersionNegotiation), GetParam()));
    } else {
        QuicTestIncompatibleVersionNegotiation(GetParam());
    }
}

TEST_P(WithFamilyArgs, FailedVersionNegotiation) {
    TestLoggerT<ParamType> Logger("FailedeVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestFailedVersionNegotiation), GetParam()));
    } else {
        QuicTestFailedVersionNegotiation(GetParam());
    }
}

TEST_P(WithFeatureSupportArgs, ReliableResetNegotiation) {
    TestLoggerT<ParamType> Logger("ReliableResetNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestReliableResetNegotiation), GetParam()));
    } else {
        QuicTestReliableResetNegotiation(GetParam());
    }
}

TEST_P(WithFeatureSupportArgs, OneWayDelayNegotiation) {
    TestLoggerT<ParamType> Logger("OneWayDelayNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestOneWayDelayNegotiation), GetParam()));
    } else {
        QuicTestOneWayDelayNegotiation(GetParam());
    }
}

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

struct WithCustomCertificateValidationArgs :
    public testing::TestWithParam<CustomCertValidationArgs> {

    static ::std::vector<CustomCertValidationArgs> Generate() {
        ::std::vector<CustomCertValidationArgs> list;
        for (bool AcceptCert : { false, true })
        for (bool AsyncValidation : { false, true })
            list.push_back({ AcceptCert, AsyncValidation });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const CustomCertValidationArgs& args) {
    return o <<
        (args.AcceptCert ? "Accept" : "Reject") << "/" <<
        (args.AsyncValidation ? "Async" : "Sync");
}


TEST_P(WithCustomCertificateValidationArgs, CustomServerCertificateValidation) {
    TestLoggerT<ParamType> Logger("QuicTestCustomServerCertificateValidation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCustomServerCertificateValidation), GetParam()));
    } else {
        QuicTestCustomServerCertificateValidation(GetParam());
    }
}

TEST_P(WithCustomCertificateValidationArgs, CustomClientCertificateValidation) {
    TestLoggerT<ParamType> Logger("QuicTestCustomClientCertificateValidation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCustomClientCertificateValidation), GetParam()));
    } else {
        QuicTestCustomClientCertificateValidation(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithCustomCertificateValidationArgs,
    testing::ValuesIn(WithCustomCertificateValidationArgs::Generate()));

struct WithClientCertificateArgs : 
    public testing::TestWithParam<ClientCertificateArgs> {

    static ::std::vector<ClientCertificateArgs> Generate() {
        ::std::vector<ClientCertificateArgs> list;
        for (int Family : { 4, 6 })
        for (bool UseClientCertificate : { false, true })
            list.push_back({ Family, UseClientCertificate });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ClientCertificateArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.UseClientCertificate ? "Cert" : "NoCert");
}

TEST_P(WithClientCertificateArgs, ConnectClientCertificate) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnectClientCertificate", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectClientCertificate), GetParam()));
    } else {
        QuicTestConnectClientCertificate(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithClientCertificateArgs,
    testing::ValuesIn(WithClientCertificateArgs::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES


struct WithCibirExtensionParams :
    public testing::TestWithParam<CibirExtensionParams> {

    static ::std::vector<CibirExtensionParams> Generate() {
        ::std::vector<CibirExtensionParams> list;
        for (int Family : { 4, 6 })
        for (uint8_t Mode : { 0, 1, 2, 3 })
            list.push_back({ Family, Mode });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const CibirExtensionParams& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.Mode & 1 ? "Client/" : "") <<
        (args.Mode & 2 ? "Server/" : "");
}

TEST_P(WithCibirExtensionParams, CibirExtension) {
    TestLoggerT<ParamType> Logger("QuicTestCibirExtension", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCibirExtension), GetParam()));
    } else {
        QuicTestCibirExtension(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithCibirExtensionParams,
    testing::ValuesIn(WithCibirExtensionParams::Generate()));

#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION

struct WithOddSizeVnTpParams :
    public testing::TestWithParam<OddSizeVnTpParams> {

    static ::std::vector<OddSizeVnTpParams> Generate() {
        ::std::vector<OddSizeVnTpParams> list;
        for (bool TestServer : { false, true })
        for (uint8_t VnTpSize: { 0, 2, 7, 9 })
            list.push_back({TestServer, VnTpSize});
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const OddSizeVnTpParams& args) {
    return o <<
        (args.TestServer ? "server" : "client") << "/" <<
        (int)args.VnTpSize;
}

TEST_P(WithOddSizeVnTpParams, OddSizeVnTp) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPOddSize", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_VN_TP_ODD_SIZE_PARAMS Params = {
            GetParam().TestServer,
            GetParam().VnTpSize
        };
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVNTPOddSize), GetParam()));
    } else {
        QuicTestVNTPOddSize(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithOddSizeVnTpParams,
    testing::ValuesIn(WithOddSizeVnTpParams::Generate()));

class WithVpnVersionParams : public testing::Test,
    public testing::WithParamInterface<bool> {
};

TEST_P(WithVpnVersionParams, VnTpChosenVersionMismatch) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPChosenVersionMismatch", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVNTPChosenVersionMismatch), GetParam()));
    } else {
        QuicTestVNTPChosenVersionMismatch(GetParam());
    }
}

TEST_P(WithVpnVersionParams, VnTpChosenVersionZero) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPChosenVersionZero", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVNTPChosenVersionZero), GetParam()));
    } else {
        QuicTestVNTPChosenVersionZero(GetParam());
    }
}

TEST_P(WithVpnVersionParams, VnTpOtherVersionZero) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPOtherVersionZero", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVNTPOtherVersionZero), GetParam()));
    } else {
        QuicTestVNTPOtherVersionZero(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithVpnVersionParams,
    ::testing::Values(false, true));

#endif
#endif

#if QUIC_TEST_FAILING_TEST_CERTIFICATES
TEST(CredValidation, ConnectExpiredServerCertificate) {
    QUIC_RUN_CRED_VALIDATION Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_EXPIRED_SERVER,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        if (TestingKernelMode) {
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_EXPIRED_SERVER_CERT, Params));
        } else {
            QuicTestConnectExpiredServerCertificate(&Params.CredConfig);
        }
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }


    if (!TestingKernelMode) {
        //
        // Test cert context in user mode only.
        //
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_EXPIRED_SERVER,
            CXPLAT_SELF_SIGN_CERT_USER,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        QuicTestConnectExpiredServerCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST(CredValidation, ConnectValidServerCertificate) {
    QUIC_RUN_CRED_VALIDATION Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_VALID_SERVER,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        if (TestingKernelMode) {
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALID_SERVER_CERT, Params));
        } else {
            QuicTestConnectValidServerCertificate(&Params.CredConfig);
        }
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }

    if (!TestingKernelMode) {
        //
        // Test cert context in user mode only.
        //
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_VALID_SERVER,
            CXPLAT_SELF_SIGN_CERT_USER,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        QuicTestConnectValidServerCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST(CredValidation, ConnectExpiredClientCertificate) {
    QUIC_RUN_CRED_VALIDATION Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_EXPIRED_CLIENT,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

        if (TestingKernelMode) {
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_EXPIRED_CLIENT_CERT, Params));
        } else {
            QuicTestConnectExpiredClientCertificate(&Params.CredConfig);
        }
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }

    if (!TestingKernelMode) {
        //
        // Test cert context in user mode only.
        //
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_EXPIRED_CLIENT,
            CXPLAT_SELF_SIGN_CERT_USER,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        QuicTestConnectExpiredClientCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST(CredValidation, ConnectValidClientCertificate) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022() || IsWindows2025()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    QUIC_RUN_CRED_VALIDATION Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_VALID_CLIENT,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

        if (TestingKernelMode) {
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALID_CLIENT_CERT, Params));
        } else {
            QuicTestConnectValidClientCertificate(&Params.CredConfig);
        }
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }

    if (!TestingKernelMode) {
        //
        // Test cert context in user mode only.
        //
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_VALID_CLIENT,
            CXPLAT_SELF_SIGN_CERT_USER,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
            &Params.CredConfig,
            &Params.CertHash,
            &Params.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        QuicTestConnectValidClientCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}
#endif // QUIC_TEST_FAILING_TEST_CERTIFICATES

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithHandshakeArgs4, RandomLoss) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-RandomLoss", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            0,  // MultipleALPNs
            0,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_DISABLED,
            GetParam().RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            false,  // MultipleALPNs,
            false,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_DISABLED,
            GetParam().RandomLossPercentage);
    }
}
#ifndef QUIC_DISABLE_RESUMPTION
TEST_P(WithHandshakeArgs4, RandomLossResume) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-RandomLossResume", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            0,  // MultipleALPNs
            0,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_ENABLED,
            GetParam().RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            false,  // MultipleALPNs,
            false,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_ENABLED,
            GetParam().RandomLossPercentage);
    }
}
TEST_P(WithHandshakeArgs4, RandomLossResumeRejection) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-RandomLossResumeRejection", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            0,  // MultipleALPNs
            0,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED,
            GetParam().RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            false,  // MultipleALPNs,
            false,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED,
            GetParam().RandomLossPercentage);
    }
}
#endif // QUIC_DISABLE_RESUMPTION
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

TEST_P(WithFamilyArgs, Unreachable) {
    if (GetParam().Family == 4 && IsWindows2019()) GTEST_SKIP(); // IPv4 unreachable doesn't work on 2019
    TestLoggerT<ParamType> Logger("QuicTestConnectUnreachable", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectUnreachable), GetParam()));
    } else {
        QuicTestConnectUnreachable(GetParam());
    }
}

TEST(HandshakeTest, InvalidAddress) {
    TestLogger Logger("QuicTestConnectInvalidAddress");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectInvalidAddress)));
    } else {
        QuicTestConnectInvalidAddress();
    }
}

TEST_P(WithFamilyArgs, BadALPN) {
    TestLoggerT<ParamType> Logger("QuicTestConnectBadAlpn", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectBadAlpn), GetParam()));
    } else {
        QuicTestConnectBadAlpn(GetParam());
    }
}

TEST_P(WithFamilyArgs, BadSNI) {
    TestLoggerT<ParamType> Logger("QuicTestConnectBadSni", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectBadSni), GetParam()));
    } else {
        QuicTestConnectBadSni(GetParam());
    }
}

TEST_P(WithFamilyArgs, ServerRejected) {
    TestLoggerT<ParamType> Logger("QuicTestConnectServerRejected", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectServerRejected), GetParam()));
    } else {
        QuicTestConnectServerRejected(GetParam());
    }
}

TEST_P(WithFamilyArgs, ClientBlockedSourcePort) {
    TestLoggerT<ParamType> Logger("QuicTestClientBlockedSourcePort", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestClientBlockedSourcePort), GetParam()));
    } else {
        QuicTestClientBlockedSourcePort(GetParam());
    }
}

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithFamilyArgs, RebindPort) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // NAT rebind doesn't make sense for TCP and QTIP.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("QuicTestNatPortRebind", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_REBIND_PARAMS Params = {
            GetParam().Family,
            0
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_NAT_PORT_REBIND, Params));
    } else {
        QuicTestNatPortRebind(GetParam().Family, 0);
    }
}

TEST_P(WithRebindPaddingArgs, RebindPortPadded) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // NAT rebind doesn't make sense for TCP and QTIP.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("QuicTestNatPortRebind(pad)", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_REBIND_PARAMS Params = {
            GetParam().Family,
            GetParam().Padding
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_NAT_PORT_REBIND, Params));
    } else {
        QuicTestNatPortRebind(GetParam().Family, GetParam().Padding);
    }
}

TEST_P(WithFamilyArgs, RebindAddr) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // NAT rebind doesn't make sense for TCP and QTIP.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("QuicTestNatAddrRebind", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_REBIND_PARAMS Params = {
            GetParam().Family,
            0
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_NAT_ADDR_REBIND, Params));
    } else {
        QuicTestNatAddrRebind(GetParam().Family, 0, FALSE);
    }
}

TEST_P(WithFamilyArgs, RebindDatapathAddr) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP || !UseDuoNic) {
        //
        // NAT rebind doesn't make sense for TCP and QTIP.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("QuicTestNatAddrRebind(datapath)", GetParam());
    if (!TestingKernelMode) {
        QuicTestNatAddrRebind(GetParam().Family, 0, TRUE);
    }
}

TEST_P(WithRebindPaddingArgs, RebindAddrPadded) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // NAT rebind doesn't make sense for TCP and QTIP.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("QuicTestNatAddrRebind(pad)", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_REBIND_PARAMS Params = {
            GetParam().Family,
            GetParam().Padding
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_NAT_PORT_REBIND, Params));
    } else {
        QuicTestNatAddrRebind(GetParam().Family, GetParam().Padding, FALSE);
    }
}

TEST_P(WithFamilyArgs, PathValidationTimeout) {
    TestLoggerT<ParamType> Logger("QuicTestPathValidationTimeout", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestPathValidationTimeout), GetParam()));
    } else {
        QuicTestPathValidationTimeout(GetParam());
    }
}
#endif

TEST_P(WithFamilyArgs, ChangeMaxStreamIDs) {
    TestLoggerT<ParamType> Logger("QuicTestChangeMaxStreamID", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestChangeMaxStreamID), GetParam()));
    } else {
        QuicTestChangeMaxStreamID(GetParam());
    }
}

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithFamilyArgs, LoadBalanced) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestLoadBalancedHandshake", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestLoadBalancedHandshake), GetParam()));
    } else {
        QuicTestLoadBalancedHandshake(GetParam());
    }
}

TEST_P(WithHandshakeArgs10, HandshakeSpecificLossPatterns) {
    TestLoggerT<ParamType> Logger("QuicTestHandshakeSpecificLossPatterns", GetParam());
    if (TestingKernelMode) {
        QUIC_HANDSHAKE_LOSS_PARAMS Params = {
            GetParam().Family,
            GetParam().CcAlgo
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_HANDSHAKE_SPECIFIC_LOSS_PATTERNS, Params));
    } else {
        QuicTestHandshakeSpecificLossPatterns(GetParam().Family, GetParam().CcAlgo);
    }
}
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

TEST_P(WithHandshakeArgs11, ShutdownDuringHandshake) {
    TestLoggerT<ParamType> Logger("QuicTestShutdownDuringHandshake", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_HANDSHAKE_SHUTDOWN, GetParam().ClientShutdown ? TRUE : FALSE));
    } else {
        QuicTestShutdownDuringHandshake(GetParam().ClientShutdown);
    }
}

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
TEST_P(WithHandshakeArgs12, ConnectionPoolCreate) {
    TestLoggerT<ParamType> Logger("QuicTestConnectionPoolCreate", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECTION_POOL_CREATE_PARAMS Params = {
            GetParam().Family,
            GetParam().NumberOfConnections,
            GetParam().XdpSupported,
            GetParam().TestCibirSupport
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECTION_POOL_CREATE, Params));
    } else {
        QuicTestConnectionPoolCreate(
            GetParam().Family,
            GetParam().NumberOfConnections,
            GetParam().XdpSupported,
            GetParam().TestCibirSupport);
    }
}
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

TEST_P(WithSendArgs1, Send) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPing", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
            GetParam().Family,
            GetParam().Length,
            GetParam().ConnectionCount,
            GetParam().StreamCount,
            1,  // StreamBurstCount
            0,  // StreamBurstDelayMs
            0,  // ServerStatelessRetry
            0,  // ClientRebind
            0,  // ClientZeroRtt
            0,  // ServerRejectZeroRtt
            (uint8_t)GetParam().UseSendBuffer,
            (uint8_t)GetParam().UnidirectionalStreams,
            (uint8_t)GetParam().ServerInitiatedStreams,
            0,   // FifoScheduling
            0    // SendUdpToQtipListener
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_PING, Params));
    } else {
        QuicTestConnectAndPing(
            GetParam().Family,
            GetParam().Length,
            GetParam().ConnectionCount,
            GetParam().StreamCount,
            1,      // StreamBurstCount
            0,      // StreamBurstDelayMs
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            false,  // ClientZeroRtt
            false,  // ServerRejectZeroRtt
            GetParam().UseSendBuffer,
            GetParam().UnidirectionalStreams,
            GetParam().ServerInitiatedStreams,
            false,  // FifoScheduling
            false); // SendUdpToQtipListener
    }
}

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
TEST_P(WithSendArgs1, SendQtip) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPingOverQtip", GetParam());
    if (!TestingKernelMode && UseQTIP) {
        QuicTestConnectAndPing(
            GetParam().Family,
            GetParam().Length,
            GetParam().ConnectionCount,
            GetParam().StreamCount,
            1,      // StreamBurstCount
            0,      // StreamBurstDelayMs
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            false,  // ClientZeroRtt
            false,  // ServerRejectZeroRtt
            GetParam().UseSendBuffer,
            GetParam().UnidirectionalStreams,
            GetParam().ServerInitiatedStreams,
            false,  // FifoScheduling
            true); // SendUdpToQtipListener
    }
}
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

TEST_P(WithSendArgs2, SendLarge) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPing", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
            GetParam().Family,
            100000000llu,
            1,  // ConnectionCount
            1,  // StreamCount
            1,  // StreamBurstCount
            0,  // StreamBurstDelayMs
            0,  // ServerStatelessRetry
            0,  // ClientRebind
            (uint8_t)GetParam().UseZeroRtt,
            0,  // ServerRejectZeroRtt
            (uint8_t)GetParam().UseSendBuffer,
            0,  // UnidirectionalStreams
            0,  // ServerInitiatedStreams
            1,  // FifoScheduling
            0   // SendUdpToQtipListener
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_PING, Params));
    } else {
        QuicTestConnectAndPing(
            GetParam().Family,
            100000000llu,
            1,      // ConnectionCount
            1,      // StreamCount
            1,      // StreamBurstCount
            0,      // StreamBurstDelayMs
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            GetParam().UseZeroRtt,
            false,  // ServerRejectZeroRtt
            GetParam().UseSendBuffer,
            false,  // UnidirectionalStreams
            false,  // ServerInitiatedStreams
            true,   // FifoScheduling
            false); // SendUdpToQtipListener
    }
}

TEST_P(WithSendArgs3, SendIntermittently) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPing", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
            GetParam().Family,
            GetParam().Length,
            1,  // ConnectionCount
            1,  // StreamCount
            GetParam().BurstCount,
            GetParam().BurstDelay,
            0,  // ServerStatelessRetry
            0,  // ClientRebind
            0,  // ClientZeroRtt
            0,  // ServerRejectZeroRtt
            (uint8_t)GetParam().UseSendBuffer,
            0,  // UnidirectionalStreams
            0,  // ServerInitiatedStreams
            0,  // FifoScheduling
            0   // SendUdpToQtipListener
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_PING, Params));
    } else {
        QuicTestConnectAndPing(
            GetParam().Family,
            GetParam().Length,
            1,  // ConnectionCount
            1,  // StreamCount
            GetParam().BurstCount,
            GetParam().BurstDelay,
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            false,  // ClientZeroRtt
            false,  // ServerRejectZeroRtt
            GetParam().UseSendBuffer,
            false,  // UnidirectionalStreams
            false,  // ServerInitiatedStreams
            false,  // FifoScheduling
            false); // SendUdpToQtipListener
    }
}

#ifndef QUIC_DISABLE_0RTT_TESTS

TEST_P(WithSend0RttArgs1, Send0Rtt) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // QTIP doesn't work with 0-RTT. QTIP only pauses and caches 1 packet during
        // TCP handshake.
        //
        return;
    }
#endif

    TestLoggerT<ParamType> Logger("Send0Rtt", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
            GetParam().Family,
            GetParam().Length,
            GetParam().ConnectionCount,
            GetParam().StreamCount,
            1,  // StreamBurstCount
            0,  // StreamBurstDelayMs
            0,  // ServerStatelessRetry
            0,  // ClientRebind
            1,  // ClientZeroRtt,
            0,  // ServerRejectZeroRtt
            (uint8_t)GetParam().UseSendBuffer,
            (uint8_t)GetParam().UnidirectionalStreams,
            0,  // ServerInitiatedStreams
            0,  // FifoScheduling
            0   // SendUdpToQtipListener
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_PING, Params));
    } else {
        QuicTestConnectAndPing(
            GetParam().Family,
            GetParam().Length,
            GetParam().ConnectionCount,
            GetParam().StreamCount,
            1,      // StreamBurstCount
            0,      // StreamBurstDelayMs
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            true,   // ClientZeroRtt
            false,  // ServerRejectZeroRtt
            GetParam().UseSendBuffer,
            GetParam().UnidirectionalStreams,
            false,  // ServerInitiatedStreams
            false,  // FifoScheduling
            false); // SendUdpToQtipListener
    }
}

TEST_P(WithSend0RttArgs2, Reject0Rtt) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // QTIP doesn't work with 0-RTT. QTIP only pauses and caches 1 packet during
        // TCP handshake.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("Reject0Rtt", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_AND_PING_PARAMS Params = {
            GetParam().Family,
            GetParam().Length,
            1,  // StreamCount
            1,  // StreamBurstCount
            1,  // StreamBurstCount
            0,  // StreamBurstDelayMs
            0,  // ServerStatelessRetry
            0,  // ClientRebind
            1,  // ClientZeroRtt,
            1,  // ServerRejectZeroRtt
            0,  // UseSendBuffer
            0,  // UnidirectionalStreams
            0,  // ServerInitiatedStreams
            0,  // FifoScheduling
            0   // SendUdpToQtipListener
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_PING, Params));
    } else {
        QuicTestConnectAndPing(
            GetParam().Family,
            GetParam().Length,
            1,      // StreamCount
            1,      // StreamBurstCount
            1,      // StreamBurstCount
            0,      // StreamBurstDelayMs
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            true,   // ClientZeroRtt
            true,   // ServerRejectZeroRtt
            false,  // UseSendBuffer
            false,  // UnidirectionalStreams
            false,  // ServerInitiatedStreams
            false,  // FifoScheduling
            false); // SendUdpToQtipListener
    }
}

#endif // QUIC_DISABLE_0RTT_TESTS

TEST_P(WithBool, IdleTimeout) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndIdle", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectAndIdle), GetParam()));
    } else {
        QuicTestConnectAndIdle(GetParam());
    }
}

TEST(Misc, IdleDestCidChange) {
    TestLogger Logger("QuicTestConnectAndIdleDestCidChange");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectAndIdleForDestCidChange)));
    } else {
        QuicTestConnectAndIdleForDestCidChange();
    }
}

TEST(Misc, ServerDisconnect) {
    TestLogger Logger("QuicTestServerDisconnect");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestServerDisconnect)));
    } else {
        QuicTestServerDisconnect();
    }
}

TEST(Misc, ClientDisconnect) {
    TestLogger Logger("QuicTestClientDisconnect");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestClientDisconnect), false));
    } else {
        QuicTestClientDisconnect(false); // TODO - Support true, when race condition is fixed.
    }
}

TEST(Misc, StatelessResetKey) {
    TestLogger Logger("QuicTestStatelessResetKey");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStatelessResetKey)));
    } else {
        QuicTestStatelessResetKey();
    }
}

TEST_P(WithFamilyArgs, ForcedKeyUpdate) {
    TestLoggerT<ParamType> Logger("QuicTestForceKeyUpdate", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestForceKeyUpdate), GetParam()));
    } else {
        QuicTestForceKeyUpdate(GetParam());
    }
}

TEST_P(WithFamilyArgs, KeyUpdate) {
    TestLoggerT<ParamType> Logger("QuicTestKeyUpdate", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestKeyUpdate), GetParam()));
    } else {
        QuicTestKeyUpdate(GetParam());
    }
}

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithKeyUpdateArgs2, RandomLoss) {
    TestLoggerT<ParamType> Logger("QuicTestKeyUpdateRandomLoss", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS Params = {
            GetParam().Family,
            GetParam().RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_KEY_UPDATE_RANDOM_LOSS, Params));
    } else {
        QuicTestKeyUpdateRandomLoss(
            GetParam().Family,
            GetParam().RandomLossPercentage);
    }
}
#endif

TEST_P(WithAbortiveArgs, AbortiveShutdown) {
    TestLoggerT<ParamType> Logger("QuicAbortiveTransfers", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS Params = {
            GetParam().Family,
            GetParam().Flags
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN, Params));
    } else {
        QuicAbortiveTransfers(GetParam().Family, GetParam().Flags);
    }
}

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithCancelOnLossArgs, CancelOnLossSend) {
    TestLoggerT<ParamType> Logger("QuicCancelOnLossSend", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CANCEL_ON_LOSS_PARAMS Params = {
            GetParam().DropPackets
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CANCEL_ON_LOSS, Params));
    } else {
        QuicCancelOnLossSend(GetParam().DropPackets);
    }
}
#endif

TEST_P(WithCidUpdateArgs, CidUpdate) {
    TestLoggerT<ParamType> Logger("QuicTestCidUpdate", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CID_UPDATE_PARAMS Params = {
            GetParam().Family,
            GetParam().Iterations
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CID_UPDATE, Params));
    } else {
        QuicTestCidUpdate(GetParam().Family, GetParam().Iterations);
    }
}

TEST_P(WithReceiveResumeArgs, ReceiveResume) {
    TestLoggerT<ParamType> Logger("QuicTestReceiveResume", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_RECEIVE_RESUME_PARAMS Params = {
            GetParam().Family,
            GetParam().SendBytes,
            GetParam().ConsumeBytes,
            GetParam().ShutdownType,
            GetParam().PauseType,
            (uint8_t)GetParam().PauseFirst
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_RECEIVE_RESUME, Params));
    } else {
        QuicTestReceiveResume(
            GetParam().Family,
            GetParam().SendBytes,
            GetParam().ConsumeBytes,
            GetParam().ShutdownType,
            GetParam().PauseType,
            GetParam().PauseFirst);
    }
}

TEST_P(WithReceiveResumeNoDataArgs, ReceiveResumeNoData) {
    TestLoggerT<ParamType> Logger("QuicTestReceiveResumeNoData", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_RECEIVE_RESUME_PARAMS Params = {
            GetParam().Family,
            0,
            0,
            GetParam().ShutdownType,
            ReturnConsumedBytes,
            0
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA, Params));
    } else {
        QuicTestReceiveResumeNoData(GetParam().Family, GetParam().ShutdownType);
    }
}

TEST_P(WithFamilyArgs, AckSendDelay) {
    TestLogger Logger("QuicTestAckSendDelay");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAckSendDelay), GetParam()));
    } else {
        QuicTestAckSendDelay(GetParam());
    }
}

TEST(Misc, AbortPausedReceive) {
    TestLogger Logger("AbortPausedReceive");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAbortReceive_Paused)));
    } else {
        QuicTestAbortReceive_Paused();
    }
}

TEST(Misc, AbortPendingReceive) {
    TestLogger Logger("AbortPendingReceive");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAbortReceive_Pending)));
    } else {
        QuicTestAbortReceive_Pending();
    }
}

TEST(Misc, AbortIncompleteReceive) {
    TestLogger Logger("AbortIncompleteReceive");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAbortReceive_Incomplete)));
    } else {
        QuicTestAbortReceive_Incomplete();
    }
}

TEST(Misc, SlowReceive) {
    TestLogger Logger("SlowReceive");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestSlowReceive)));
    } else {
        QuicTestSlowReceive();
    }
}

#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL
TEST(Misc, NthAllocFail) {
    TestLogger Logger("NthAllocFail");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestNthAllocFail)));
    } else {
        QuicTestNthAllocFail();
    }
}
#endif // QUIC_TEST_OPENSSL_FLAGS
#endif // QUIC_TEST_ALLOC_FAILURES_ENABLED

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST(Misc, NthPacketDrop) {
    TestLogger Logger("NthPacketDrop");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestNthPacketDrop)));
    } else {
        QuicTestNthPacketDrop();
    }
}
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

TEST(Misc, StreamPriority) {
    TestLogger Logger("StreamPriority");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamPriority)));
    } else {
        QuicTestStreamPriority();
    }
}

TEST(Misc, StreamPriorityInfiniteLoop) {
    TestLogger Logger("StreamPriorityInfiniteLoop");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamPriorityInfiniteLoop)));
    } else {
        QuicTestStreamPriorityInfiniteLoop();
    }
}

TEST(Misc, StreamDifferentAbortErrors) {
    TestLogger Logger("StreamDifferentAbortErrors");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamDifferentAbortErrors)));
    } else {
        QuicTestStreamDifferentAbortErrors();
    }
}

TEST(Misc, StreamAbortRecvFinRace) {
    TestLogger Logger("StreamAbortRecvFinRace");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAbortRecvFinRace)));
    } else {
        QuicTestStreamAbortRecvFinRace();
    }
}

#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
TEST(Misc, StreamReliableReset) {
    TestLogger Logger("StreamReliableReset");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamReliableReset)));
    } else {
        QuicTestStreamReliableReset();
    }
}

TEST(Misc, StreamReliableResetMultipleSends) {
    TestLogger Logger("StreamReliableResetMultipleSends");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamReliableResetMultipleSends)));
    } else {
        QuicTestStreamReliableResetMultipleSends();
    }
}
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(Misc, StreamMultiReceive) {
    TestLogger Logger("StreamMultiReceive");
    if (TestingKernelMode) {
        // TODO: Why?? This should be enabled.
        GTEST_SKIP();
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamMultiReceive)));
    } else {
        QuicTestStreamMultiReceive();
    }
}

// App-provided receive buffer tests

struct WithAppProvidedBuffersConfigArgs: public testing::TestWithParam<AppProvidedBuffersConfig> {
    static ::std::vector<AppProvidedBuffersConfig> Generate() {
        return {
            { 8, 0x500, 8, 0x500}, // Base scenario
            { 1, 100, 1, 100}, // Small buffers
            { 150, 0x50, 150, 0x50}, // Many buffers
        };
    }
};

std::ostream& operator << (std::ostream& o, const AppProvidedBuffersConfig& args) {
    return o <<
        "Start:" << args.StreamStartBuffersNum << " buffers of" << args.StreamStartBuffersSize << "bytes," <<
        "Additional:" << args.AdditionalBuffersNum << " buffers of " << args.AdditionalBuffersSize << "bytes.";
}

TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffers_ClientSend) {
    TestLoggerT<ParamType> Logger("StreamAppProvidedBuffers_ClientSend", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAppProvidedBuffers_ClientSend), GetParam()));
    } else {
        QuicTestStreamAppProvidedBuffers_ClientSend(GetParam());
    }
}

TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffers_ServerSend) {
    TestLoggerT<ParamType> Logger("StreamAppProvidedBuffers_ServerSend", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAppProvidedBuffers_ServerSend), GetParam()));
    } else {
        QuicTestStreamAppProvidedBuffers_ServerSend(GetParam());
    }
}

TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream) {
    TestLoggerT<ParamType> Logger("StreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream), GetParam()));
    } else {
        QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream(GetParam());
    }
}

TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer) {
    TestLoggerT<ParamType> Logger("StreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer), GetParam()));
    } else {
        QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer(GetParam());
    }
}

TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream) {
    TestLoggerT<ParamType> Logger("StreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream), GetParam()));
    } else {
        QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream(GetParam());
    }
}

TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer) {
    TestLoggerT<ParamType> Logger("StreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer), GetParam()));
    } else {
        QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithAppProvidedBuffersConfigArgs,
    testing::ValuesIn(WithAppProvidedBuffersConfigArgs::Generate()));

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

TEST(Misc, StreamBlockUnblockBidiConnFlowControl) {
    TestLogger Logger("StreamBlockUnblockBidiConnFlowControl");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamBlockUnblockConnFlowControl_Bidi)));
    } else {
        QuicTestStreamBlockUnblockConnFlowControl_Bidi();
    }
}

TEST(Misc, StreamBlockUnblockUnidiConnFlowControl) {
    TestLogger Logger("StreamBlockUnblockUnidiConnFlowControl");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamBlockUnblockConnFlowControl_Unidi)));
    } else {
        QuicTestStreamBlockUnblockConnFlowControl_Unidi();
    }
}

TEST(Misc, StreamAbortConnFlowControl) {
    TestLogger Logger("StreamAbortConnFlowControl");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStreamAbortConnFlowControl)));
    } else {
        QuicTestStreamAbortConnFlowControl();
    }
}

TEST(Basic, OperationPriority) {
    TestLogger Logger("OperationPriority");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestOperationPriority)));
    } else {
        QuicTestOperationPriority();
    }
}

TEST(Basic, ConnectionPriority) {
    TestLogger Logger("ConnectionPriority");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectionPriority)));
    } else {
        QuicTestConnectionPriority();
    }
}

// Drill tests

TEST(Drill, VarIntEncoder) {
    TestLogger Logger("QuicDrillTestVarIntEncoder");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicDrillTestVarIntEncoder)));
    } else {
        QuicDrillTestVarIntEncoder();
    }
}

struct WithDrillInitialPacketCidArgs:
    public testing::TestWithParam<DrillInitialPacketCidArgs> {

    static ::std::vector<DrillInitialPacketCidArgs> Generate() {
        ::std::vector<DrillInitialPacketCidArgs> list;
        for (int Family : { 4, 6 })
        for (bool SourceOrDest : { true, false })
        for (bool ActualCidLengthValid : { true, false })
        for (bool ShortCidLength : { true, false })
        for (bool CidLengthFieldValid : { true, false })
            list.push_back({ Family, SourceOrDest, ActualCidLengthValid, ShortCidLength, CidLengthFieldValid });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const DrillInitialPacketCidArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.SourceOrDest ? "SourceCid" : "DestCid") << "/" <<
        (args.ActualCidLengthValid ? "Valid" : "Invalid") << "/" <<
        (args.ShortCidLength ? "Short" : "Long") << "/" <<
        (args.CidLengthFieldValid ? "Valid" : "Invalid") << " length";
}

TEST_P(WithDrillInitialPacketCidArgs, DrillInitialPacketCids) {
    TestLoggerT<ParamType> Logger("QuicDrillInitialPacketCids", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicDrillTestInitialCid), GetParam()));
    } else {
        QuicDrillTestInitialCid(GetParam());
    }
}

struct WithDrillInitialPacketTokenArgs:
    public testing::TestWithParam<DrillInitialPacketTokenArgs> {

    static ::std::vector<DrillInitialPacketTokenArgs> Generate() {
        ::std::vector<DrillInitialPacketTokenArgs> list;
        for (int Family : { 4, 6 })
            list.push_back({ Family, });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const DrillInitialPacketTokenArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6");
}

TEST_P(WithDrillInitialPacketTokenArgs, DrillInitialPacketToken) {
    TestLoggerT<ParamType> Logger("QuicDrillInitialPacketToken", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicDrillTestInitialToken), GetParam()));
    } else {
        QuicDrillTestInitialToken(GetParam());
    }
}

TEST_P(WithDrillInitialPacketTokenArgs, QuicDrillTestServerVNPacket) {
    TestLoggerT<ParamType> Logger("QuicDrillTestServerVNPacket", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicDrillTestServerVNPacket), GetParam()));
    } else {
        QuicDrillTestServerVNPacket(GetParam());
    }
}

TEST_P(WithDrillInitialPacketTokenArgs, QuicDrillTestKeyUpdateDuringHandshake) {
    TestLoggerT<ParamType> Logger("QuicDrillTestKeyUpdateDuringHandshake", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicDrillTestKeyUpdateDuringHandshake), GetParam()));
    } else {
        QuicDrillTestKeyUpdateDuringHandshake(GetParam());
    }
}

struct WithDatagramNegotiationArgs :
    public testing::TestWithParam<DatagramNegotiationArgs> {

    static ::std::vector<DatagramNegotiationArgs> Generate() {
        ::std::vector<DatagramNegotiationArgs> list;
        for (int Family : { 4, 6 })
        for (bool DatagramReceiveEnabled : { false, true })
            list.push_back({ Family, DatagramReceiveEnabled });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const DatagramNegotiationArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.DatagramReceiveEnabled ? "DatagramReceiveEnabled" : "DatagramReceiveDisabled");
}

TEST_P(WithDatagramNegotiationArgs, DatagramNegotiation) {
    TestLoggerT<ParamType> Logger("QuicTestDatagramNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestDatagramNegotiation), GetParam()));
    } else {
        QuicTestDatagramNegotiation(GetParam());
    }
}

TEST_P(WithFamilyArgs, DatagramSend) {
    TestLoggerT<ParamType> Logger("QuicTestDatagramSend", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestDatagramSend), GetParam()));
    } else {
        QuicTestDatagramSend(GetParam());
    }
}

TEST_P(WithFamilyArgs, DatagramDrop) {
    TestLoggerT<ParamType> Logger("QuicTestDatagramDrop", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestDatagramDrop), GetParam()));
    } else {
        QuicTestDatagramDrop(GetParam());
    }
}

#ifdef _WIN32 // Storage tests only supported on Windows

static BOOLEAN CanRunStorageTests = FALSE;

TEST(Basic, TestStorage) {
    if (!CanRunStorageTests) {
        GTEST_SKIP();
    }

    TestLogger Logger("QuicTestStorage");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestStorage)));
    } else {
        QuicTestStorage();
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(Basic, TestVersionStorage) {
    if (!CanRunStorageTests) {
        GTEST_SKIP();
    }

    TestLogger Logger("QuicTestVersionStorage");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestVersionStorage)));
    } else {
        QuicTestVersionStorage();
    }
}
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

#ifdef DEBUG // This test needs a GetParam API that is only available in debug builds.
TEST(ParameterValidation, RetryConfigSetting)
{
    if (!CanRunStorageTests) {
        GTEST_SKIP();
    }

    TestLogger Logger("QuicTestRetryConfigSetting");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestRetryConfigSetting)));
    } else {
        QuicTestRetryConfigSetting();
    }
}
#endif // DEBUG

#endif // _WIN32

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithBool,
    ::testing::Values(false, true));

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateConnectionEventArgs,
    testing::ValuesIn(WithValidateConnectionEventArgs::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateNetStatsConnEventArgs,
    testing::ValuesIn(WithValidateNetStatsConnEventArgs::Generate()));
#endif

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateStreamEventArgs,
    testing::ValuesIn(WithValidateStreamEventArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateTlsConfigArgs,
    testing::ValuesIn(TlsConfigArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithFamilyArgs,
    ::testing::ValuesIn(WithFamilyArgs::Generate()));

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED

INSTANTIATE_TEST_SUITE_P(
    Mtu,
    WithMtuArgs,
    ::testing::ValuesIn(WithMtuArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithRebindPaddingArgs,
    ::testing::ValuesIn(RebindPaddingArgs::Generate()));

#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs4,
    testing::ValuesIn(HandshakeArgs4::Generate()));

#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithFeatureSupportArgs,
    testing::ValuesIn(WithFeatureSupportArgs::Generate()));
#endif

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs10,
    testing::ValuesIn(HandshakeArgs10::Generate()));
#endif

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs11,
    testing::ValuesIn(HandshakeArgs11::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs12,
    testing::ValuesIn(HandshakeArgs12::Generate()));
#endif

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSendArgs1,
    testing::ValuesIn(SendArgs1::Generate()));

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSendArgs2,
    testing::ValuesIn(SendArgs2::Generate()));

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSendArgs3,
    testing::ValuesIn(SendArgs3::Generate()));

#ifndef QUIC_DISABLE_0RTT_TESTS

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSend0RttArgs1,
    testing::ValuesIn(Send0RttArgs1::Generate()));

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSend0RttArgs2,
    testing::ValuesIn(Send0RttArgs2::Generate()));

#endif

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithKeyUpdateArgs2,
    testing::ValuesIn(KeyUpdateArgs2::Generate()));

#endif

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithAbortiveArgs,
    testing::ValuesIn(AbortiveArgs::Generate()));

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithCancelOnLossArgs,
    testing::ValuesIn(CancelOnLossArgs::Generate()));

#endif

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithCidUpdateArgs,
    testing::ValuesIn(CidUpdateArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithReceiveResumeArgs,
    testing::ValuesIn(ReceiveResumeArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithReceiveResumeNoDataArgs,
    testing::ValuesIn(ReceiveResumeNoDataArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithDatagramNegotiationArgs,
    testing::ValuesIn(WithDatagramNegotiationArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Drill,
    WithDrillInitialPacketCidArgs,
    testing::ValuesIn(WithDrillInitialPacketCidArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Drill,
    WithDrillInitialPacketTokenArgs,
    testing::ValuesIn(WithDrillInitialPacketTokenArgs::Generate()));

int main(int argc, char** argv) {
#ifdef _WIN32
    //
    // Try to create settings registry key
    //
    HKEY Key;
    DWORD Result =
        RegCreateKeyA(
            HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\MsQuicStorageTest",
            &Key);
    CanRunStorageTests = Result == NO_ERROR;
    RegCloseKey(Key);
#endif

    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0 || strcmp("--kernelPriv", argv[i]) == 0) {
            TestingKernelMode = true;
            if (strcmp("--kernelPriv", argv[i]) == 0) {
                PrivateTestLibrary = true;
            }
        } else if (strcmp("--duoNic", argv[i]) == 0) {
            UseDuoNic = true;
        } else if (strcmp("--useQTIP", argv[i]) == 0) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            UseQTIP = true;
#else
            printf("QTIP is not supported in this build.\n");
            return -1;
#endif
        } else if (strstr(argv[i], "--osRunner")) {
            OsRunner = argv[i] + sizeof("--osRunner");
        } else if (strcmp("--timeout", argv[i]) == 0) {
            if (i + 1 < argc) {
                Timeout = atoi(argv[i + 1]);
                ++i;
            }
        }
    }
    ::testing::AddGlobalTestEnvironment(new QuicTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}