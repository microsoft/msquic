/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.cpp.clog.h"
#endif

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
#pragma message("Test compiled with datapath hooks enabled")
#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#pragma message("Test compiled with preview features enabled")
#endif

bool TestingKernelMode = false;
bool PrivateTestLibrary = false;
bool UseDuoNic = false;
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

bool IsWindows2019() { return OsRunner && strcmp(OsRunner, "windows-2019") == 0; }
bool IsWindows2022() { return OsRunner && strcmp(OsRunner, "windows-2022") == 0; }

class QuicTestEnvironment : public ::testing::Environment {
    QuicDriverService DriverService;
    const QUIC_CREDENTIAL_CONFIG* SelfSignedCertParams;
    const QUIC_CREDENTIAL_CONFIG* ClientCertParams;
    CxPlatWatchdog* watchdog {nullptr};
public:
    void SetUp() override {
        CxPlatSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatInitialize()));
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
            };
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_TEST_CONFIGURATION, Params));

        } else {
            printf("Initializing for User Mode tests\n");
            MsQuic = new(std::nothrow) MsQuicApi();
            ASSERT_TRUE(QUIC_SUCCEEDED(MsQuic->GetInitStatus()));
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            if (UseQTIP) {
                QUIC_EXECUTION_CONFIG Config = {QUIC_EXECUTION_CONFIG_FLAG_QTIP, 10000, 0, {0}};
                ASSERT_TRUE(QUIC_SUCCEEDED(
                    MsQuic->SetParam(
                        nullptr,
                        QUIC_PARAM_GLOBAL_EXECUTION_CONFIG,
                        sizeof(Config),
                        &Config)));
            }
#endif
            memcpy(&ServerSelfSignedCredConfig, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            memcpy(&ServerSelfSignedCredConfigClientAuth, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ServerSelfSignedCredConfigClientAuth.Flags |=
                QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
                QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
            memcpy(&ClientCertCredConfig, ClientCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ClientCertCredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
            QuicTestInitialize();
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

TEST(ParameterValidation, ValidateApi) {
    TestLogger Logger("QuicTestValidateApi");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_API));
    } else {
        QuicTestValidateApi();
    }
}

TEST(ParameterValidation, ValidateRegistration) {
    TestLogger Logger("QuicTestValidateRegistration");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_REGISTRATION));
    } else {
        QuicTestValidateRegistration();
    }
}

TEST(ParameterValidation, ValidateGlobalParam) {
    TestLogger Logger("QuicTestValidateGlobalParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_GLOBAL_PARAM));
    } else {
        QuicTestGlobalParam();
    }
}

TEST(ParameterValidation, ValidateCommonParam) {
    TestLogger Logger("QuicTestValidateCommonParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_COMMON_PARAM));
    } else {
        QuicTestCommonParam();
    }
}

TEST(ParameterValidation, ValidateRegistrationParam) {
    TestLogger Logger("QuicTestValidateRegistrationParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_REGISTRATION_PARAM));
    } else {
        QuicTestRegistrationParam();
    }
}

TEST(ParameterValidation, ValidateConfigurationParam) {
    TestLogger Logger("QuicTestValidateConfigurationParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_CONFIGURATION_PARAM));
    } else {
        QuicTestConfigurationParam();
    }
}

TEST(ParameterValidation, ValidateListenerParam) {
    TestLogger Logger("QuicTestValidateListenerParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_LISTENER_PARAM));
    } else {
        QuicTestListenerParam();
    }
}

TEST(ParameterValidation, ValidateConnectionParam) {
    TestLogger Logger("QuicTestValidateConnectionParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_CONNECTION_PARAM));
    } else {
        QuicTestConnectionParam();
    }
}

TEST(ParameterValidation, ValidateTlsParam) {
    TestLogger Logger("QuicTestValidateTlsParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_TLS_PARAM));
    } else {
        QuicTestTlsParam();
    }
}

TEST(ParameterValidation, ValidateStreamParam) {
    TestLogger Logger("QuicTestValidateStreamParam");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_STREAM_PARAM));
    } else {
        QuicTestStreamParam();
    }
}

TEST(ParameterValidation, ValidateGetPerfCounters) {
    TestLogger Logger("QuicTestGetPerfCounters");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_GET_PERF_COUNTERS));
    } else {
        QuicTestGetPerfCounters();
    }
}

TEST(ParameterValidation, ValidateConfiguration) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLogger Logger("QuicTestValidateConfiguration");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_CONFIGURATION));
    } else {
        QuicTestValidateConfiguration();
    }
}

TEST(ParameterValidation, ValidateListener) {
    TestLogger Logger("QuicTestValidateListener");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_LISTENER));
    } else {
        QuicTestValidateListener();
    }
}

TEST(ParameterValidation, ValidateConnection) {
    TestLogger Logger("QuicTestValidateConnection");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_CONNECTION));
    } else {
        QuicTestValidateConnection();
    }
}

TEST(OwnershipValidation, RegistrationShutdownBeforeConnOpen) {
    TestLogger Logger("RegistrationShutdownBeforeConnOpen");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN__REG_SHUTDOWN_BEFORE_OPEN));
    } else {
        QuicTestRegistrationShutdownBeforeConnOpen();
    }
}

TEST(OwnershipValidation, RegistrationShutdownAfterConnOpen) {
    TestLogger Logger("RegistrationShutdownAfterConnOpen");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN));
    } else {
        QuicTestRegistrationShutdownAfterConnOpen();
    }
}

TEST(OwnershipValidation, RegistrationShutdownAfterConnOpenBeforeStart) {
    TestLogger Logger("RegistrationShutdownAfterConnOpenBeforeStart");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN_BEFORE_START));
    } else {
        QuicTestRegistrationShutdownAfterConnOpenBeforeStart();
    }
}

TEST(OwnershipValidation, RegistrationShutdownAfterConnOpenAndStart) {
    TestLogger Logger("RegistrationShutdownAfterConnOpenAndStart");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN_AND_START));
    } else {
        QuicTestRegistrationShutdownAfterConnOpenAndStart();
    }
}

TEST(OwnershipValidation, ConnectionCloseBeforeStreamClose) {
    TestLogger Logger("ConnectionCloseBeforeStreamClose");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONN_CLOSE_BEFORE_STREAM_CLOSE));
    } else {
        QuicTestConnectionCloseBeforeStreamClose();
    }
}

TEST_P(WithBool, ValidateStream) {
    TestLoggerT<ParamType> Logger("QuicTestValidateStream", GetParam());
    if (TestingKernelMode) {
        uint8_t Param = (uint8_t)GetParam();
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_STREAM, Param));
    } else {
        QuicTestValidateStream(GetParam());
    }
}

TEST(ParameterValidation, CloseConnBeforeStreamFlush) {
    TestLogger Logger("QuicTestCloseConnBeforeStreamFlush");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CLOSE_CONN_BEFORE_STREAM_FLUSH));
    } else {
        QuicTestCloseConnBeforeStreamFlush();
    }
}

TEST_P(WithValidateConnectionEventArgs, ValidateConnectionEvents) {
    TestLoggerT<ParamType> Logger("QuicTestValidateConnectionEvents", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run<uint32_t>(IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS, GetParam().Test));
    } else {
        QuicTestValidateConnectionEvents(GetParam().Test);
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST_P(WithValidateNetStatsConnEventArgs, ValidateNetStatConnEvent) {
    TestLoggerT<ParamType> Logger("QuicTestValidateNetStatsConnEvent", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run<uint32_t>(IOCTL_QUIC_RUN_VALIDATE_NET_STATS_CONN_EVENT, GetParam().Test));
    } else {
        QuicTestValidateNetStatsConnEvent(GetParam().Test);
    }
}
#endif

TEST_P(WithValidateStreamEventArgs, ValidateStreamEvents) {
    TestLoggerT<ParamType> Logger("QuicTestValidateStreamEvents", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run<uint32_t>(IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS, GetParam().Test));
    } else {
        QuicTestValidateStreamEvents(GetParam().Test);
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST(ParameterValidation, ValidateVersionSettings) {
    TestLogger Logger("QuicTestVersionSettings");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_VERSION_SETTINGS_SETTINGS));
    } else {
        QuicTestVersionSettings();
    }
}
#endif

TEST(ParameterValidation, ValidateParamApi) {
    TestLogger Logger("QuicTestValidateParamApi");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_PARAM_API));
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

TEST(Basic, CreateListener) {
    TestLogger Logger("QuicTestCreateListener");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CREATE_LISTENER));
    } else {
        QuicTestCreateListener();
    }
}

TEST(Basic, StartListener) {
    TestLogger Logger("QuicTestStartListener");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_START_LISTENER));
    } else {
        QuicTestStartListener();
    }
}

TEST(Basic, StartListenerMultiAlpns) {
    TestLogger Logger("QuicTestStartListenerMultiAlpns");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_START_LISTENER_MULTI_ALPN));
    } else {
        QuicTestStartListenerMultiAlpns();
    }
}

TEST_P(WithFamilyArgs, StartListenerImplicit) {
    TestLoggerT<ParamType> Logger("QuicTestStartListenerImplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT, GetParam().Family));
    } else {
        QuicTestStartListenerImplicit(GetParam().Family);
    }
}

TEST(Basic, StartTwoListeners) {
    TestLogger Logger("QuicTestStartTwoListeners");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_START_TWO_LISTENERS));
    } else {
        QuicTestStartTwoListeners();
    }
}

TEST(Basic, StartTwoListenersSameALPN) {
    TestLogger Logger("QuicTestStartTwoListenersSameALPN");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN));
    } else {
        QuicTestStartTwoListenersSameALPN();
    }
}

TEST_P(WithFamilyArgs, StartListenerExplicit) {
    TestLoggerT<ParamType> Logger("QuicTestStartListenerExplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT, GetParam().Family));
    } else {
        QuicTestStartListenerExplicit(GetParam().Family);
    }
}

TEST(Basic, CreateConnection) {
    TestLogger Logger("QuicTestCreateConnection");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CREATE_CONNECTION));
    } else {
        QuicTestCreateConnection();
    }
}

TEST(Basic, ConnectionCloseFromCallback) {
    TestLogger Logger("QuicTestConnectionCloseFromCallback");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECTION_CLOSE_FROM_CALLBACK));
    } else {
        QuicTestConnectionCloseFromCallback();
    }
}

TEST_P(WithBool, RejectConnection) {
    TestLoggerT<ParamType> Logger("QuicTestConnectionRejection", GetParam());
    if (TestingKernelMode) {
        uint8_t Param = (uint8_t)GetParam();
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECTION_REJECTION, Param));
    } else {
        QuicTestConnectionRejection(GetParam());
    }
}

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithFamilyArgs, Ecn) {
    TestLoggerT<ParamType> Logger("Ecn", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_ECN, GetParam().Family));
    } else {
        QuicTestEcn(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, LocalPathChanges) {
    TestLoggerT<ParamType> Logger("QuicTestLocalPathChanges", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CLIENT_LOCAL_PATH_CHANGES, GetParam().Family));
    } else {
        QuicTestLocalPathChanges(GetParam().Family);
    }
}

TEST(Mtu, Settings) {
    TestLogger Logger("QuicTestMtuSettings");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_MTU_SETTINGS));
    } else {
        QuicTestMtuSettings();
    }
}

TEST_P(WithMtuArgs, MtuDiscovery) {
    TestLoggerT<ParamType> Logger("QuicTestMtuDiscovery", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_MTU_DISCOVERY_PARAMS Params = {
            GetParam().Family,
            (uint8_t)(GetParam().DropMode & 1),
            (uint8_t)(GetParam().DropMode & 2),
            (uint8_t)GetParam().RaiseMinimum
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_MTU_DISCOVERY, Params));
    }
    else {
        QuicTestMtuDiscovery(
            GetParam().Family,
            GetParam().DropMode & 1,
            GetParam().DropMode & 2,
            GetParam().RaiseMinimum);
    }
}

#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

TEST(Alpn, ValidAlpnLengths) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLogger Logger("QuicTestValidAlpnLengths");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALID_ALPN_LENGTHS));
    } else {
        QuicTestValidAlpnLengths();
    }
}

TEST(Alpn, InvalidAlpnLengths) {
    TestLogger Logger("QuicTestInvalidAlpnLengths");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_INVALID_ALPN_LENGTHS));
    } else {
        QuicTestInvalidAlpnLengths();
    }
}

TEST(Alpn, ChangeAlpn) {
    TestLogger Logger("QuicTestChangeAlpn");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CHANGE_ALPN));
    } else {
        QuicTestChangeAlpn();
    }
}


TEST_P(WithFamilyArgs, BindConnectionImplicit) {
    TestLoggerT<ParamType> Logger("QuicTestBindConnectionImplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT, GetParam().Family));
    } else {
        QuicTestBindConnectionImplicit(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, BindConnectionExplicit) {
    TestLoggerT<ParamType> Logger("QuicTestBindConnectionExplicit", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT, GetParam().Family));
    } else {
        QuicTestBindConnectionExplicit(GetParam().Family);
    }
}

TEST_P(WithHandshakeArgs1, Connect) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-Connect", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            (uint8_t)GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_DISABLED,
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_DISABLED,
            0);     // RandomLossPercentage
    }
}

#ifndef QUIC_DISABLE_RESUMPTION
TEST_P(WithHandshakeArgs1, Resume) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-Resume", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            (uint8_t)GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_ENABLED,
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_ENABLED,
            0);     // RandomLossPercentage
    }
}

TEST_P(WithHandshakeArgs1, ResumeAsync) {
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeAsync", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            (uint8_t)GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_ENABLED_ASYNC,
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_ENABLED_ASYNC,
            0);     // RandomLossPercentage
    }
}

TEST_P(WithHandshakeArgs1, ResumeRejection) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeRejection", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            (uint8_t)GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED,
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED,
            0);     // RandomLossPercentage
    }
}

TEST_P(WithHandshakeArgs1, ResumeRejectionByServerApp) {
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeRejectionByServerApp", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            (uint8_t)GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED_BY_SERVER_APP,
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED_BY_SERVER_APP,
            0);     // RandomLossPercentage
    }
}

TEST_P(WithHandshakeArgs1, ResumeRejectionByServerAppAsync) {
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-ResumeRejectionByServerAppAsync", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            (uint8_t)GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            (uint8_t)GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED_BY_SERVER_APP_ASYNC,
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            GetParam().GreaseQuicBitExtension,
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            GetParam().MultiPacketClientInitial,
            QUIC_TEST_RESUMPTION_REJECTED_BY_SERVER_APP_ASYNC,
            0);     // RandomLossPercentage
    }
}
#endif // QUIC_DISABLE_RESUMPTION

#ifndef QUIC_DISABLE_SHARED_PORT_TESTS
TEST_P(WithFamilyArgs, ClientSharedLocalPort) {
    TestLoggerT<ParamType> Logger("QuicTestClientSharedLocalPort", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CLIENT_SHARED_LOCAL_PORT, GetParam().Family));
    } else {
        QuicTestClientSharedLocalPort(GetParam().Family);
    }
}
#endif

TEST_P(WithFamilyArgs, InterfaceBinding) {
    TestLoggerT<ParamType> Logger("QuicTestInterfaceBinding", GetParam());
    if (UseDuoNic) {
        GTEST_SKIP_("DuoNIC is not supported");
    }
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_INTERFACE_BINDING, GetParam().Family));
    } else {
        QuicTestInterfaceBinding(GetParam().Family);
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST_P(WithHandshakeArgs2, OldVersion) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-OldVersion", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            1,  // ClientUsesOldVersion
            0,  // MultipleALPNs
            0,  // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            0,  // MultiPacketClientInitial
            QUIC_TEST_RESUMPTION_DISABLED,  // SessionResumption
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            true,  // ClientUsesOldVersion
            false, // MultipleALPNs
            false, // GreaseQuicBitExtension
            QUIC_TEST_ASYNC_CONFIG_DISABLED,
            false,  // MultiPacketClientInitial
            QUIC_TEST_RESUMPTION_DISABLED,  // SessionResumption
            0);     // RandomLossPercentage
    }
}
#endif

TEST_P(WithHandshakeArgs3, AsyncSecurityConfig) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-AsyncSecurityConfig", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            (uint8_t)GetParam().MultipleALPNs,
            0,  // GreaseQuicBitExtension
            GetParam().DelayedAsyncConfig ? (uint8_t)QUIC_TEST_ASYNC_CONFIG_DELAYED : (uint8_t)QUIC_TEST_ASYNC_CONFIG_ENABLED,
            0,  // MultiPacketClientInitial
            QUIC_TEST_RESUMPTION_DISABLED,  // SessionResumption
            0   // RandomLossPercentage
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
        QuicTestConnect(
            GetParam().Family,
            GetParam().ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            GetParam().MultipleALPNs,
            false,  // GreaseQuicBitExtension
            GetParam().DelayedAsyncConfig ? QUIC_TEST_ASYNC_CONFIG_DELAYED : QUIC_TEST_ASYNC_CONFIG_ENABLED,
            false,  // MultiPacketClientInitial
            QUIC_TEST_RESUMPTION_DISABLED,  // SessionResumption
            0);     // RandomLossPercentage
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST_P(WithFamilyArgs, VersionNegotiation) {
    TestLoggerT<ParamType> Logger("QuicTestVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VERSION_NEGOTIATION, GetParam().Family));
    } else {
        QuicTestVersionNegotiation(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, VersionNegotiationRetry) {
    TestLoggerT<ParamType> Logger("QuicTestVersionNegotiationRetry", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VERSION_NEGOTIATION_RETRY, GetParam().Family));
    } else {
        QuicTestVersionNegotiationRetry(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, CompatibleVersionNegotiationRetry) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiationRetry", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_RETRY, GetParam().Family));
    } else {
        QuicTestCompatibleVersionNegotiationRetry(GetParam().Family);
    }
}

TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiation) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_VERSION_NEGOTIATION_EXT Params = {
            GetParam().Family,
            GetParam().DisableVNEClient,
            GetParam().DisableVNEServer
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION, Params));
    } else {
        QuicTestCompatibleVersionNegotiation(
            GetParam().Family,
            GetParam().DisableVNEClient,
            GetParam().DisableVNEServer);
    }
}

TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultServer) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiationDefaultServer", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_VERSION_NEGOTIATION_EXT Params = {
            GetParam().Family,
            GetParam().DisableVNEClient,
            GetParam().DisableVNEServer
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_SERVER, Params));
    } else {
        QuicTestCompatibleVersionNegotiationDefaultServer(
            GetParam().Family,
            GetParam().DisableVNEClient,
            GetParam().DisableVNEServer);
    }
}

TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultClient) {
    TestLoggerT<ParamType> Logger("CompatibleVersionNegotiationDefaultClient", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_VERSION_NEGOTIATION_EXT Params = {
            GetParam().Family,
            GetParam().DisableVNEClient,
            GetParam().DisableVNEServer
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_CLIENT, Params));
    } else {
        QuicTestCompatibleVersionNegotiationDefaultClient(
            GetParam().Family,
            GetParam().DisableVNEClient,
            GetParam().DisableVNEServer);
    }
}

TEST_P(WithFamilyArgs, IncompatibleVersionNegotiation) {
    TestLoggerT<ParamType> Logger("IncompatibleVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_INCOMPATIBLE_VERSION_NEGOTIATION, GetParam().Family));
    } else {
        QuicTestIncompatibleVersionNegotiation(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, FailedVersionNegotiation) {
    TestLoggerT<ParamType> Logger("FailedeVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_FAILED_VERSION_NEGOTIATION, GetParam().Family));
    } else {
        QuicTestFailedVersionNegotiation(GetParam().Family);
    }
}

TEST_P(WithFeatureSupportArgs, ReliableResetNegotiation) {
    TestLoggerT<ParamType> Logger("ReliableResetNegotiation", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_FEATURE_NEGOTIATION Params = {
            GetParam().Family,
            GetParam().ServerSupport,
            GetParam().ClientSupport
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RELIABLE_RESET_NEGOTIATION, Params));
    } else {
        QuicTestReliableResetNegotiation(GetParam().Family, GetParam().ServerSupport, GetParam().ClientSupport);
    }
}

TEST_P(WithFeatureSupportArgs, OneWayDelayNegotiation) {
    TestLoggerT<ParamType> Logger("OneWayDelayNegotiation", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_FEATURE_NEGOTIATION Params = {
            GetParam().Family,
            GetParam().ServerSupport,
            GetParam().ClientSupport
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_ONE_WAY_DELAY_NEGOTIATION, Params));
    } else {
        QuicTestOneWayDelayNegotiation(GetParam().Family, GetParam().ServerSupport, GetParam().ClientSupport);
    }
}

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

TEST_P(WithHandshakeArgs5, CustomServerCertificateValidation) {
    TestLoggerT<ParamType> Logger("QuicTestCustomServerCertificateValidation", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CUSTOM_CERT_VALIDATION Params = {
            GetParam().AcceptCert,
            GetParam().AsyncValidation
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CUSTOM_SERVER_CERT_VALIDATION, Params));
    } else {
        QuicTestCustomServerCertificateValidation(GetParam().AcceptCert, GetParam().AsyncValidation);
    }
}

TEST_P(WithHandshakeArgs5, CustomClientCertificateValidation) {
    TestLoggerT<ParamType> Logger("QuicTestCustomClientCertificateValidation", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CUSTOM_CERT_VALIDATION Params = {
            GetParam().AcceptCert,
            GetParam().AsyncValidation
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CUSTOM_CLIENT_CERT_VALIDATION, Params));
    } else {
        QuicTestCustomClientCertificateValidation(GetParam().AcceptCert, GetParam().AsyncValidation);
    }
}

TEST_P(WithHandshakeArgs6, ConnectClientCertificate) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnectClientCertificate", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_CLIENT_CERT Params = {
            GetParam().Family,
            (uint8_t)GetParam().UseClientCertificate
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_CLIENT_CERT, Params));
    } else {
        QuicTestConnectClientCertificate(GetParam().Family, GetParam().UseClientCertificate);
    }
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST_P(WithHandshakeArgs7, CibirExtension) {
    TestLoggerT<ParamType> Logger("QuicTestCibirExtension", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CIBIR_EXTENSION Params = {
            GetParam().Family,
            GetParam().Mode
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CIBIR_EXTENSION, Params));
    } else {
        QuicTestCibirExtension(GetParam().Family, GetParam().Mode);
    }
}
#endif

// TEST(Handshake, ResumptionAcrossVersions) {
//     if (TestingKernelMode) {
//         ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_RESUMPTION_ACROSS_VERSIONS));
//     } else {
//         QuicTestResumptionAcrossVersions();
//     }
// }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
TEST_P(WithHandshakeArgs8, OddSizeVnTp) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPOddSize", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_VN_TP_ODD_SIZE_PARAMS Params = {
            GetParam().TestServer,
            GetParam().VnTpSize
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VN_TP_ODD_SIZE, Params));
    } else {
        QuicTestVNTPOddSize(GetParam().TestServer, GetParam().VnTpSize);
    }
}

TEST_P(WithHandshakeArgs9, VnTpChosenVersionMismatch) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPChosenVersionMismatch", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(
            DriverClient.Run(
                IOCTL_QUIC_RUN_VN_TP_CHOSEN_VERSION_MISMATCH,
                (uint8_t)GetParam()));
    } else {
        QuicTestVNTPChosenVersionMismatch(GetParam());
    }
}

TEST_P(WithHandshakeArgs9, VnTpChosenVersionZero) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPChosenVersionZero", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(
            DriverClient.Run(
                IOCTL_QUIC_RUN_VN_TP_CHOSEN_VERSION_ZERO,
                (uint8_t)GetParam()));
    } else {
        QuicTestVNTPChosenVersionZero(GetParam());
    }
}

TEST_P(WithHandshakeArgs9, VnTpOtherVersionZero) {
    TestLoggerT<ParamType> Logger("QuicTestVNTPOtherVersionZero", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(
            DriverClient.Run(
                IOCTL_QUIC_RUN_VN_TP_OTHER_VERSION_ZERO,
                (uint8_t)GetParam()));
    } else {
        QuicTestVNTPOtherVersionZero(GetParam());
    }
}
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
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
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
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_UNREACHABLE, GetParam().Family));
    } else {
        QuicTestConnectUnreachable(GetParam().Family);
    }
}

TEST(HandshakeTest, InvalidAddress) {
    TestLogger Logger("QuicTestConnectInvalidAddress");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_INVALID_ADDRESS));
    } else {
        QuicTestConnectInvalidAddress();
    }
}

TEST_P(WithFamilyArgs, BadALPN) {
    TestLoggerT<ParamType> Logger("QuicTestConnectBadAlpn", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_BAD_ALPN, GetParam().Family));
    } else {
        QuicTestConnectBadAlpn(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, BadSNI) {
    TestLoggerT<ParamType> Logger("QuicTestConnectBadSni", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_BAD_SNI, GetParam().Family));
    } else {
        QuicTestConnectBadSni(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, ServerRejected) {
    TestLoggerT<ParamType> Logger("QuicTestConnectServerRejected", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED, GetParam().Family));
    } else {
        QuicTestConnectServerRejected(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, ClientBlockedSourcePort) {
    TestLoggerT<ParamType> Logger("QuicTestClientBlockedSourcePort", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CLIENT_BLOCKED_SOURCE_PORT, GetParam().Family));
    } else {
        QuicTestClientBlockedSourcePort(GetParam().Family);
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
    if (UseQTIP) {
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
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_PATH_VALIDATION_TIMEOUT, GetParam().Family));
    } else {
        QuicTestPathValidationTimeout(GetParam().Family);
    }
}
#endif

TEST_P(WithFamilyArgs, ChangeMaxStreamIDs) {
    TestLoggerT<ParamType> Logger("QuicTestChangeMaxStreamID", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CHANGE_MAX_STREAM_ID, GetParam().Family));
    } else {
        QuicTestChangeMaxStreamID(GetParam().Family);
    }
}

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
TEST_P(WithFamilyArgs, LoadBalanced) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestLoadBalancedHandshake", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_LOAD_BALANCED_HANDSHAKE, GetParam().Family));
    } else {
        QuicTestLoadBalancedHandshake(GetParam().Family);
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
            0   // FifoScheduling
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
            false); // FifoScheduling
    }
}

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
            1   // FifoScheduling
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
            true);  // FifoScheduling
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
            0   // FifoScheduling
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
            false); // FifoScheduling
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
            0   // FifoScheduling
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
            false); // FifoScheduling
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
            0   // FifoScheduling
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
            false); // FifoScheduling
    }
}

#endif // QUIC_DISABLE_0RTT_TESTS

TEST_P(WithBool, IdleTimeout) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndIdle", GetParam());
    if (TestingKernelMode) {
        uint8_t Param = (uint8_t)GetParam();
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_IDLE, Param));
    } else {
        QuicTestConnectAndIdle(GetParam());
    }
}

TEST(Misc, IdleDestCidChange) {
    TestLogger Logger("QuicTestConnectAndIdleDestCidChange");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_IDLE_FOR_DEST_CID_CHANGE));
    } else {
        QuicTestConnectAndIdleForDestCidChange();
    }
}

TEST(Misc, ServerDisconnect) {
    TestLogger Logger("QuicTestServerDisconnect");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_SERVER_DISCONNECT));
    } else {
        QuicTestServerDisconnect();
    }
}

TEST(Misc, ClientDisconnect) {
    TestLogger Logger("QuicTestClientDisconnect");
    if (TestingKernelMode) {
        uint8_t Param = 0;
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CLIENT_DISCONNECT, Param));
    } else {
        QuicTestClientDisconnect(false); // TODO - Support true, when race condition is fixed.
    }
}

TEST(Misc, StatelessResetKey) {
    TestLogger Logger("QuicTestStatelessResetKey");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STATELESS_RESET_KEY));
    } else {
        QuicTestStatelessResetKey();
    }
}

TEST_P(WithKeyUpdateArgs1, KeyUpdate) {
    TestLoggerT<ParamType> Logger("QuicTestKeyUpdate", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_KEY_UPDATE_PARAMS Params = {
            GetParam().Family,
            (uint16_t)(GetParam().KeyUpdate == 0 ? 5 : 1),  // Iterations
            0,                                              // KeyUpdateBytes
            (uint8_t)(GetParam().KeyUpdate == 0),           // UseKeyUpdateBytes
            (uint8_t)(GetParam().KeyUpdate & 1),            // ClientKeyUpdate
            (uint8_t)(GetParam().KeyUpdate & 2)             // ServerKeyUpdate
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_KEY_UPDATE, Params));
    } else {
        QuicTestKeyUpdate(
            GetParam().Family,
            GetParam().KeyUpdate == 0 ? 5 : 1,  // Iterations
            0,                                  // KeyUpdateBytes
            GetParam().KeyUpdate == 0,          // UseKeyUpdateBytes
            GetParam().KeyUpdate & 1,           // ClientKeyUpdate
            GetParam().KeyUpdate & 2);          // ServerKeyUpdate
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
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_ACK_SEND_DELAY, GetParam().Family));
    } else {
        QuicTestAckSendDelay(GetParam().Family);
    }
}

TEST(Misc, AbortPausedReceive) {
    TestLogger Logger("AbortPausedReceive");
    if (TestingKernelMode) {
        QUIC_ABORT_RECEIVE_TYPE Type = QUIC_ABORT_RECEIVE_PAUSED;
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_ABORT_RECEIVE, Type));
    } else {
        QuicTestAbortReceive(QUIC_ABORT_RECEIVE_PAUSED);
    }
}

TEST(Misc, AbortPendingReceive) {
    TestLogger Logger("AbortPendingReceive");
    if (TestingKernelMode) {
        QUIC_ABORT_RECEIVE_TYPE Type = QUIC_ABORT_RECEIVE_PENDING;
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_ABORT_RECEIVE, Type));
    } else {
        QuicTestAbortReceive(QUIC_ABORT_RECEIVE_PENDING);
    }
}

TEST(Misc, AbortIncompleteReceive) {
    TestLogger Logger("AbortIncompleteReceive");
    if (TestingKernelMode) {
        QUIC_ABORT_RECEIVE_TYPE Type = QUIC_ABORT_RECEIVE_INCOMPLETE;
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_ABORT_RECEIVE, Type));
    } else {
        QuicTestAbortReceive(QUIC_ABORT_RECEIVE_INCOMPLETE);
    }
}

TEST(Misc, SlowReceive) {
    TestLogger Logger("SlowReceive");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_SLOW_RECEIVE));
    } else {
        QuicTestSlowReceive();
    }
}

#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL
TEST(Misc, NthAllocFail) {
    TestLogger Logger("NthAllocFail");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_NTH_ALLOC_FAIL));
    } else {
        QuicTestNthAllocFail();
    }
}
#endif // QUIC_TEST_OPENSSL_FLAGS
#endif // QUIC_TEST_ALLOC_FAILURES_ENABLED

TEST(Misc, StreamPriority) {
    TestLogger Logger("StreamPriority");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_PRIORITY));
    } else {
        QuicTestStreamPriority();
    }
}

TEST(Misc, StreamPriorityInfiniteLoop) {
    TestLogger Logger("StreamPriorityInfiniteLoop");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_PRIORITY_INFINITE_LOOP));
    } else {
        QuicTestStreamPriorityInfiniteLoop();
    }
}

TEST(Misc, StreamDifferentAbortErrors) {
    TestLogger Logger("StreamDifferentAbortErrors");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_DIFFERENT_ABORT_ERRORS));
    } else {
        QuicTestStreamDifferentAbortErrors();
    }
}

TEST(Misc, StreamAbortRecvFinRace) {
    TestLogger Logger("StreamAbortRecvFinRace");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_ABORT_RECV_FIN_RACE));
    } else {
        QuicTestStreamAbortRecvFinRace();
    }
}

TEST(Misc, StreamBlockUnblockBidiConnFlowControl) {
    TestLogger Logger("StreamBlockUnblockBidiConnFlowControl");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_BLOCK_UNBLOCK_CONN_FLOW_CONTROL, TRUE));
    } else {
        QuicTestStreamBlockUnblockConnFlowControl(TRUE);
    }
}

#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
TEST(Misc, StreamReliableReset) {
    TestLogger Logger("StreamReliableReset");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_RELIABLE_RESET));
    } else {
        QuicTestStreamReliableReset();
    }
}

TEST(Misc, StreamReliableResetMultipleSends) {
    TestLogger Logger("StreamReliableResetMultipleSends");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_RELIABLE_RESET_MULTIPLE_SENDS));
    } else {
        QuicTestStreamReliableResetMultipleSends();
    }
}
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET

TEST(Misc, StreamBlockUnblockUnidiConnFlowControl) {
    TestLogger Logger("StreamBlockUnblockUnidiConnFlowControl");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_BLOCK_UNBLOCK_CONN_FLOW_CONTROL, FALSE));
    } else {
        QuicTestStreamBlockUnblockConnFlowControl(FALSE);
    }
}

TEST(Misc, StreamAbortConnFlowControl) {
    TestLogger Logger("StreamAbortConnFlowControl");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STREAM_ABORT_CONN_FLOW_CONTROL));
    } else {
        QuicTestStreamAbortConnFlowControl();
    }
}

TEST(Drill, VarIntEncoder) {
    TestLogger Logger("QuicDrillTestVarIntEncoder");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_DRILL_ENCODE_VAR_INT));
    } else {
        QuicDrillTestVarIntEncoder();
    }
}

TEST_P(WithDrillInitialPacketCidArgs, DrillInitialPacketCids) {
    TestLoggerT<ParamType> Logger("QuicDrillInitialPacketCids", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().SourceOrDest,
            (uint8_t)GetParam().ActualCidLengthValid,
            (uint8_t)GetParam().ShortCidLength,
            (uint8_t)GetParam().CidLengthFieldValid
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_CID, Params));
    } else {
        QuicDrillTestInitialCid(
            GetParam().Family,
            GetParam().SourceOrDest,
            GetParam().ActualCidLengthValid,
            GetParam().ShortCidLength,
            GetParam().CidLengthFieldValid);
    }
}

TEST_P(WithDrillInitialPacketTokenArgs, DrillInitialPacketToken) {
    TestLoggerT<ParamType> Logger("QuicDrillInitialPacketToken", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN, GetParam().Family));
    } else {
        QuicDrillTestInitialToken(GetParam().Family);
    }
}

TEST_P(WithDrillInitialPacketTokenArgs, QuicDrillTestServerVNPacket) {
    TestLoggerT<ParamType> Logger("QuicDrillTestServerVNPacket", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_DRILL_VN_PACKET_TOKEN, GetParam().Family));
    } else {
        QuicDrillTestServerVNPacket(GetParam().Family);
    }
}

TEST_P(WithDatagramNegotiationArgs, DatagramNegotiation) {
    TestLoggerT<ParamType> Logger("QuicTestDatagramNegotiation", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_DATAGRAM_NEGOTIATION Params = {
            GetParam().Family,
            GetParam().DatagramReceiveEnabled
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_DATAGRAM_NEGOTIATION, Params));
    } else {
        QuicTestDatagramNegotiation(GetParam().Family, GetParam().DatagramReceiveEnabled);
    }
}

TEST_P(WithFamilyArgs, DatagramSend) {
    TestLoggerT<ParamType> Logger("QuicTestDatagramSend", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_DATAGRAM_SEND, GetParam().Family));
    } else {
        QuicTestDatagramSend(GetParam().Family);
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
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STORAGE));
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
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_STORAGE));
    } else {
        QuicTestVersionStorage();
    }
}
#endif

#endif // _WIN32

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithBool,
    ::testing::Values(false, true));

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateConnectionEventArgs,
    testing::ValuesIn(ValidateConnectionEventArgs::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateNetStatsConnEventArgs,
    testing::ValuesIn(ValidateNetStatsConnEventArgs::Generate()));
#endif

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateStreamEventArgs,
    testing::ValuesIn(ValidateStreamEventArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateTlsConfigArgs,
    testing::ValuesIn(TlsConfigArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithFamilyArgs,
    ::testing::ValuesIn(FamilyArgs::Generate()));

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED

INSTANTIATE_TEST_SUITE_P(
    Mtu,
    WithMtuArgs,
    ::testing::ValuesIn(MtuArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithRebindPaddingArgs,
    ::testing::ValuesIn(RebindPaddingArgs::Generate()));

#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithVersionNegotiationExtArgs,
    testing::ValuesIn(VersionNegotiationExtArgs::Generate()));
#endif

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs1,
    testing::ValuesIn(HandshakeArgs1::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs2,
    testing::ValuesIn(HandshakeArgs2::Generate()));
#endif

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs3,
    testing::ValuesIn(HandshakeArgs3::Generate()));

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs4,
    testing::ValuesIn(HandshakeArgs4::Generate()));

#endif

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs5,
    testing::ValuesIn(HandshakeArgs5::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs6,
    testing::ValuesIn(HandshakeArgs6::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs7,
    testing::ValuesIn(HandshakeArgs7::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithFeatureSupportArgs,
    testing::ValuesIn(FeatureSupportArgs::Generate()));
#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs8,
    testing::ValuesIn(HandshakeArgs8::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs9,
    ::testing::Values(false, true));
#endif
#endif

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs10,
    testing::ValuesIn(HandshakeArgs10::Generate()));
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

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithKeyUpdateArgs1,
    testing::ValuesIn(KeyUpdateArgs1::Generate()));

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
    testing::ValuesIn(DatagramNegotiationArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Drill,
    WithDrillInitialPacketCidArgs,
    testing::ValuesIn(DrillInitialPacketCidArgs::Generate()));

INSTANTIATE_TEST_SUITE_P(
    Drill,
    WithDrillInitialPacketTokenArgs,
    testing::ValuesIn(DrillInitialPacketTokenArgs::Generate()));

int main(int argc, char** argv) {
#ifdef _WIN32
    //
    // Try to create settings registry key
    //
    HKEY Key;
    DWORD Result =
        RegCreateKeyA(
            HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\MsQuic\\Parameters\\Apps\\StorageTest",
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
