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
#include <vector>

#if defined(_WIN32) && defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
#define XDP_API_VERSION 3
#define XDP_INCLUDE_WINCOMMON
#include <xdp/wincommon.h>
#include <xdpapi.h>
#include "XdpMapModeHelpers.h"
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
            memcpy(&ServerSelfSignedCredConfig, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            memcpy(&ServerSelfSignedCredConfigClientAuth, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ServerSelfSignedCredConfigClientAuth.Flags |=
                QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
                QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
            memcpy(&ClientCertCredConfig, ClientCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ClientCertCredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

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

//
// Macros that generate the standard test body boilerplate:
// logger + kernel-mode dispatch + user-mode call.
//
#define QUIC_TEST_F(Suite, Name, Func)                                  \
    TEST_F(Suite, Name) {                                               \
        TestLogger Logger(#Func);                                       \
        if (TestingKernelMode) {                                        \
            ASSERT_TRUE(InvokeKernelTest(FUNC(Func)));                  \
        } else { Func(); }                                              \
    }

#define QUIC_TEST_P(Suite, Name, Func)                                  \
    TEST_P(Suite, Name) {                                               \
        TestLoggerT<ParamType> Logger(#Func, GetParam());               \
        if (TestingKernelMode) {                                        \
            ASSERT_TRUE(InvokeKernelTest(FUNC(Func), GetParam()));      \
        } else { Func(GetParam()); }                                    \
    }

//
// Base test fixture that owns the MsQuic library lifecycle.
// Each test suite gets its own init/teardown via SetUpTestSuite/TearDownTestSuite.
//
class QuicTestFixture : public ::testing::Test {
protected:
    //
    // Creates the global MsQuicApi instance and applies XDP/QTIP settings.
    //
    static void InitMsQuicLibrary() {
        MsQuic = new(std::nothrow) MsQuicApi();
        ASSERT_NE(MsQuic, nullptr);
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
    }

    //
    // Enables DSCP on the receive path (needed for DSCP send-path tests).
    //
    static void ConfigureDscp() {
        BOOLEAN Option = TRUE;
        ASSERT_TRUE(QUIC_SUCCEEDED(MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_DATAPATH_DSCP_RECV_ENABLED,
            sizeof(BOOLEAN),
            &Option)));
    }

    //
    // Tears down the global MsQuicApi instance.
    //
    static void UninitMsQuicLibrary() {
        QuicTestUninitialize();
        delete MsQuic;
        MsQuic = nullptr;
    }

    static void SetUpTestSuite() {
        if (TestingKernelMode) return;
        InitMsQuicLibrary();
        ConfigureDscp();
        QuicTestInitialize();
    }
    static void TearDownTestSuite() {
        if (TestingKernelMode) return;
        UninitMsQuicLibrary();
    }
};

//
// Fixture classes for plain test suites (TEST_F).
//
class ParameterValidation : public QuicTestFixture {};
class Basic : public QuicTestFixture {};
class Misc : public QuicTestFixture {};
class OwnershipValidation : public QuicTestFixture {};
class CredValidation : public QuicTestFixture {};
class Handshake : public QuicTestFixture {};
class Alpn : public QuicTestFixture {};
class Mtu : public QuicTestFixture {};
class HandshakeTest : public QuicTestFixture {};
class Drill : public QuicTestFixture {};

//
// Common parameterized test fixtures.
//
class WithBool : public QuicTestFixture,
    public testing::WithParamInterface<bool> {
};

struct WithFamilyArgs :
    public QuicTestFixture,
    public testing::WithParamInterface<FamilyArgs> {

    static ::std::vector<FamilyArgs> Generate() {
        return {{4}, {6}};
    }
};

QUIC_TEST_F(ParameterValidation, ValidateApi, QuicTestValidateApi)

QUIC_TEST_F(ParameterValidation, ValidateRegistration, QuicTestValidateRegistration)

QUIC_TEST_F(ParameterValidation, ValidateGlobalParam, QuicTestGlobalParam)

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
TEST_F(ParameterValidation, ValidateXdpMapConfigParam) {
    //
    // User-mode only: QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG is set-once before the
    // library's lazy initialization. In kernel mode the test driver shares one
    // MsQuicLib across all tests in the run, so earlier tests have already
    // triggered lazy init and this test cannot exercise the success paths.
    // This is a test harness limitation today.
    //
    if (TestingKernelMode) {
        GTEST_SKIP() << "QuicTestXdpMapConfigParam is user-mode only.";
    }
    TestLogger Logger("QuicTestValidateXdpMapConfigParam");
    QuicTestXdpMapConfigParam();
}
#endif

#if defined(_WIN32) && defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
struct WithXdpMapModeArgs : public QuicTestFixture,
    public ::testing::WithParamInterface<XdpMapModeArgs> {

    static bool SuiteSkip;
    static const char* SuiteSkipReason;
    static bool SuiteFailed;
    static const char* SuiteFailureReason;

    static void SetUpTestSuite() {
        SuiteSkip = false;
        SuiteSkipReason = nullptr;
        SuiteFailed = false;
        SuiteFailureReason = nullptr;

        if (TestingKernelMode) {
            SuiteSkip = true;
            SuiteSkipReason = "XDP map mode doesn't apply to kernel mode.";
            return;
        }

        if (!UseDuoNic) {
            SuiteSkip = true;
            SuiteSkipReason = "XDP Map Mode requires DuoNic (--duoNic)";
            return;
        }

        auto IfIndices = DiscoverDuoNicInterfaces();
        if (IfIndices.empty()) {
            SuiteSkip = true;
            SuiteSkipReason = "No DuoNic interfaces found";
            return;
        }

        //
        // Probe whether the XDP driver supports map mode.
        //
        HANDLE ProbeMap = nullptr;
        HRESULT Hr = XdpMapCreate(&ProbeMap, XDP_MAP_TYPE_XSKMAP);
        if (FAILED(Hr)) {
            SuiteSkip = true;
            SuiteSkipReason = "XDP driver does not support map mode (XdpMapCreate failed)";
            return;
        }
        CloseHandle(ProbeMap);

        //
        // Create XSKMAPs for each interface.
        //
        XdpMapState.InterfaceCount = (uint32_t)IfIndices.size();
        memcpy(XdpMapState.IfIndices, IfIndices.data(),
            sizeof(uint32_t) * IfIndices.size());
        printf("WithXdpMapModeArgs: discovered %u DuoNic interface(s)\n",
            XdpMapState.InterfaceCount);

        for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
            Hr = XdpMapCreate(&XdpMapState.XskMaps[i], XDP_MAP_TYPE_XSKMAP);
            if (FAILED(Hr)) {
                for (uint32_t j = 0; j < i; j++) {
                    CloseHandle(XdpMapState.XskMaps[j]);
                    XdpMapState.XskMaps[j] = nullptr;
                }
                XdpMapState.InterfaceCount = 0;
                SuiteFailed = true;
                SuiteFailureReason = "XdpMapCreate failed for interface XSKMAP";
                return;
            }
            printf("  IfIndex=%u, XskMap=%p\n",
                XdpMapState.IfIndices[i], XdpMapState.XskMaps[i]);
        }

        //
        // Initialize MsQuic with XDP/QTIP settings, then apply map config.
        //
        InitMsQuicLibrary();

        QUIC_XDP_MAP_CONFIG MapConfigs[XDP_MAP_MODE_MAX_INTERFACES];
        for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
            MapConfigs[i].InterfaceIndex = XdpMapState.IfIndices[i];
            MapConfigs[i].MapHandle = (QUIC_XDP_MAP_HANDLE)XdpMapState.XskMaps[i];
        }
        if (QUIC_FAILED(MsQuic->SetParam(
                nullptr,
                QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG,
                XdpMapState.InterfaceCount * sizeof(QUIC_XDP_MAP_CONFIG),
                MapConfigs))) {
            SuiteFailed = true;
            SuiteFailureReason = "SetParam XDP_MAP_CONFIG failed";
            return;
        }

        ConfigureDscp();
        QuicTestInitialize();
    }

    static void CleanupMaps() {
        for (uint32_t i = 0; i < XdpMapState.InterfaceCount; i++) {
            if (XdpMapState.XskMaps[i]) {
                CloseHandle(XdpMapState.XskMaps[i]);
                XdpMapState.XskMaps[i] = nullptr;
            }
        }
        XdpMapState.InterfaceCount = 0;
    }

    static void TearDownTestSuite() {
        if (SuiteSkip || TestingKernelMode) return;
        if (SuiteFailed) {
            CleanupMaps();
            if (MsQuic) {
                delete MsQuic;
                MsQuic = nullptr;
            }
            return;
        }
        UninitMsQuicLibrary();
        CleanupMaps();
    }

    static ::std::vector<XdpMapModeArgs> Generate() {
        ::std::vector<XdpMapModeArgs> list;
        for (int Family : { 4, 6 })
        for (bool UseCibir : { false, true })
            list.push_back({ Family, 0, 0, UseCibir });
        return list;
    }
};

bool WithXdpMapModeArgs::SuiteSkip = false;
const char* WithXdpMapModeArgs::SuiteSkipReason = nullptr;
bool WithXdpMapModeArgs::SuiteFailed = false;
const char* WithXdpMapModeArgs::SuiteFailureReason = nullptr;

std::ostream& operator << (std::ostream& o, const XdpMapModeArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.UseCibir ? "Cibir" : "NoCibir") << "/" <<
        "ServerPort:" << (args.ServerPort) << "/" <<
        "ClientPort:" << (args.ClientPort);
}

TEST_P(WithXdpMapModeArgs, Handshake) {
    if (SuiteSkip) {
        GTEST_SKIP() << SuiteSkipReason;
    }
    ASSERT_FALSE(SuiteFailed) << SuiteFailureReason;

    auto Params = GetParam();
    XdpMapModeRuleScope Scope(Params.UseCibir, UseQTIP);
    Params.ClientPort = Scope.GetClientPort();
    Params.ServerPort = Scope.GetServerPort();

    TestLoggerT<ParamType> Logger("QuicTestXdpMapModeHandshake", Params);

    QuicTestXdpMapModeHandshake(Params);
}

INSTANTIATE_TEST_SUITE_P(
    XdpMapMode,
    WithXdpMapModeArgs,
    ::testing::ValuesIn(WithXdpMapModeArgs::Generate()));
#endif // _WIN32 && QUIC_API_ENABLE_PREVIEW_FEATURES

QUIC_TEST_F(ParameterValidation, ValidateCommonParam, QuicTestCommonParam)

QUIC_TEST_F(ParameterValidation, ValidateRegistrationParam, QuicTestRegistrationParam)

QUIC_TEST_F(ParameterValidation, ValidateConfigurationParam, QuicTestConfigurationParam)

QUIC_TEST_F(ParameterValidation, ValidateListenerParam, QuicTestListenerParam)

QUIC_TEST_F(ParameterValidation, ValidateConnectionParam, QuicTestConnectionParam)

QUIC_TEST_F(ParameterValidation, ValidateTlsParam, QuicTestTlsParam)

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

QUIC_TEST_F(ParameterValidation, ValidateStreamParam, QuicTestStreamParam)

QUIC_TEST_F(ParameterValidation, ValidateGetPerfCounters, QuicTestGetPerfCounters)

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
QUIC_TEST_F(ParameterValidation, ValidateEncryptDecryptPerfCounters, QuicTestValidateEncryptDecryptPerfCounters)

QUIC_TEST_F(ParameterValidation, ConnQueueDelayStatistics, QuicTestConnQueueDelayStatistics)
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

TEST_F(ParameterValidation, ValidateConfiguration) {
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

QUIC_TEST_F(ParameterValidation, ValidateListener, QuicTestValidateListener)

QUIC_TEST_F(ParameterValidation, ValidateConnection, QuicTestValidateConnection)

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
QUIC_TEST_F(Handshake, ConnectionExportKeyingMaterial, QuicTestConnectionExportKeyingMaterial)

QUIC_TEST_F(ParameterValidation, ValidateConnectionExportKeyingMaterial, QuicTestValidateConnectionExportKeyingMaterial)

QUIC_TEST_F(ParameterValidation, ValidateConnectionPoolCreate, QuicTestValidateConnectionPoolCreate)

QUIC_TEST_F(ParameterValidation, ValidateExecutionContext, QuicTestValidateExecutionContext)
QUIC_TEST_F(ParameterValidation, ValidatePartition, QuicTestValidatePartition)
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

QUIC_TEST_F(OwnershipValidation, RegistrationShutdownBeforeConnOpen, QuicTestRegistrationShutdownBeforeConnOpen)

QUIC_TEST_F(OwnershipValidation, RegistrationShutdownAfterConnOpen, QuicTestRegistrationShutdownAfterConnOpen)

QUIC_TEST_F(OwnershipValidation, RegistrationShutdownAfterConnOpenBeforeStart, QuicTestRegistrationShutdownAfterConnOpenBeforeStart)

QUIC_TEST_F(OwnershipValidation, RegistrationShutdownAfterConnOpenAndStart, QuicTestRegistrationShutdownAfterConnOpenAndStart)

QUIC_TEST_F(OwnershipValidation, ConnectionCloseBeforeStreamClose, QuicTestConnectionCloseBeforeStreamClose)

QUIC_TEST_P(WithBool, ValidateStream, QuicTestValidateStream)

QUIC_TEST_F(ParameterValidation, CloseConnBeforeStreamFlush, QuicTestCloseConnBeforeStreamFlush)

struct WithValidateConnectionEventArgs :
    public QuicTestFixture, public testing::WithParamInterface<ValidateConnectionEventArgs> {
    static ::std::vector<ValidateConnectionEventArgs> Generate() {
        ::std::vector<ValidateConnectionEventArgs> list;
        for (uint32_t Test = 0; Test < 3; ++Test)
            list.push_back({ Test });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ValidateConnectionEventArgs& args) {
    return o << args.Test;
}

QUIC_TEST_P(WithValidateConnectionEventArgs, ValidateConnectionEvents, QuicTestValidateConnectionEvents)

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateConnectionEventArgs,
    testing::ValuesIn(WithValidateConnectionEventArgs::Generate()));


#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

struct WithValidateNetStatsConnEventArgs : public QuicTestFixture, public testing::WithParamInterface<ValidateNetStatsConnEventArgs> {
    static ::std::vector<ValidateNetStatsConnEventArgs> Generate() {
        ::std::vector<ValidateNetStatsConnEventArgs> list;
        for (uint32_t Test = 0; Test < 2; ++Test)
            list.push_back({ Test });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ValidateNetStatsConnEventArgs& args) {
    return o << args.Test;
}

QUIC_TEST_P(WithValidateNetStatsConnEventArgs, ValidateNetStatConnEvent, QuicTestValidateNetStatsConnEvent)

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateNetStatsConnEventArgs,
    testing::ValuesIn(WithValidateNetStatsConnEventArgs::Generate()));

#endif

struct WithValidateStreamEventArgs : public QuicTestFixture, public testing::WithParamInterface<ValidateStreamEventArgs> {
    static ::std::vector<ValidateStreamEventArgs> Generate() {
        ::std::vector<ValidateStreamEventArgs> list;
        for (uint32_t Test = 0; Test < 9; ++Test)
            list.push_back({ Test });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ValidateStreamEventArgs& args) {
    return o << args.Test;
}

QUIC_TEST_P(WithValidateStreamEventArgs, ValidateStreamEvents, QuicTestValidateStreamEvents)

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateStreamEventArgs,
    testing::ValuesIn(WithValidateStreamEventArgs::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
QUIC_TEST_F(ParameterValidation, ValidateVersionSettings, QuicTestVersionSettings)
#endif

QUIC_TEST_F(ParameterValidation, ValidateParamApi, QuicTestValidateParamApi)

struct TlsConfigArgs {
    QUIC_CREDENTIAL_TYPE CredType;
    CXPLAT_TEST_CERT_TYPE CertType;
};

std::ostream& operator << (std::ostream& o, const CXPLAT_TEST_CERT_TYPE& type) {
    switch (type) {
    case CXPLAT_TEST_CERT_VALID_SERVER:
        return o << "Valid Server";
    case CXPLAT_TEST_CERT_VALID_CLIENT:
        return o << "Valid Client";
    case CXPLAT_TEST_CERT_EXPIRED_SERVER:
        return o << "Expired Server";
    case CXPLAT_TEST_CERT_EXPIRED_CLIENT:
        return o << "Expired Client";
    case CXPLAT_TEST_CERT_SELF_SIGNED_SERVER:
        return o << "Self-signed Server";
    case CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT:
        return o << "Self-signed Client";
    default:
        return o << "Unknown";
    }
}

std::ostream& operator << (std::ostream& o, const QUIC_CREDENTIAL_TYPE& type) {
    switch (type) {
    case QUIC_CREDENTIAL_TYPE_NONE:
        return o << "None";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
        return o << "Hash";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
        return o << "HashStore";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
        return o << "Context";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
        return o << "File";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
        return o << "FileProtected";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
        return o << "Pkcs12";
    default:
        return o << "Unknown";
    }
}

std::ostream& operator << (std::ostream& o, const TlsConfigArgs& args) {
    return o << args.CredType << "/" << args.CertType;
}

struct WithValidateTlsConfigArgs :
    public QuicTestFixture, public testing::WithParamInterface<TlsConfigArgs> {

    static ::std::vector<TlsConfigArgs> Generate() {
        ::std::vector<TlsConfigArgs> List;
        for (auto CredType : {
#ifdef _WIN32
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
#else
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12
#endif
        })
        for (auto CertType : {CXPLAT_TEST_CERT_SELF_SIGNED_SERVER, CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT}) {
            List.push_back({CredType, CertType});
        }
        return List;
    }
};

TEST_P(WithValidateTlsConfigArgs, ValidateTlsConfig) {
    TestLogger Logger("QuicTestCredentialLoad");

    if (TestingKernelMode &&
        GetParam().CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        GTEST_SKIP_("Cert Context not supported in kernel mode");
    }

    QUIC_CREDENTIAL_BLOB Arg{};

    ASSERT_TRUE(
        CxPlatGetTestCertificate(
            GetParam().CertType,
            TestingKernelMode ? CXPLAT_SELF_SIGN_CERT_MACHINE : CXPLAT_SELF_SIGN_CERT_USER,
            GetParam().CredType,
            &Arg.CredConfig,
            &Arg.Storage.CertHash,
            &Arg.Storage.CertHashStore,
            &Arg.Storage.CertFile,
            &Arg.Storage.CertFileProtected,
            &Arg.Storage.Pkcs12,
            NULL));

    Arg.CredConfig.Flags =
        GetParam().CertType == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT ?
            QUIC_CREDENTIAL_FLAG_CLIENT :
            QUIC_CREDENTIAL_FLAG_NONE;

    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCredentialLoad), Arg));
    } else {
        QuicTestCredentialLoad(Arg);
    }

    CxPlatFreeTestCert(&Arg.CredConfig);
}

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithValidateTlsConfigArgs,
    testing::ValuesIn(WithValidateTlsConfigArgs::Generate()));

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
QUIC_TEST_F(Basic, RegistrationOpenClose, QuicTestRegistrationOpenClose)
#endif

QUIC_TEST_F(Basic, CreateListener, QuicTestCreateListener)

QUIC_TEST_F(Basic, StartListener, QuicTestStartListener)

QUIC_TEST_F(Basic, StartListenerMultiAlpns, QuicTestStartListenerMultiAlpns)

QUIC_TEST_P(WithFamilyArgs, StartListenerImplicit, QuicTestStartListenerImplicit)

QUIC_TEST_F(Basic, StartTwoListeners, QuicTestStartTwoListeners)

QUIC_TEST_F(Basic, StartTwoListenersSameALPN, QuicTestStartTwoListenersSameALPN)

QUIC_TEST_P(WithFamilyArgs, StartListenerExplicit, QuicTestStartListenerExplicit)

QUIC_TEST_F(Basic, CreateConnection, QuicTestCreateConnection)

QUIC_TEST_F(Basic, ConnectionCloseFromCallback, QuicTestConnectionCloseFromCallback)

QUIC_TEST_P(WithBool, RejectConnection, QuicTestConnectionRejection)

#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_P(WithFamilyArgs, Ecn, QuicTestEcn)

QUIC_TEST_P(WithFamilyArgs, LocalPathChanges, QuicTestLocalPathChanges)

QUIC_TEST_F(Mtu, Settings, QuicTestMtuSettings)

struct WithMtuArgs : public QuicTestFixture, public testing::WithParamInterface<MtuArgs> {
    static ::std::vector<MtuArgs> Generate() {
        ::std::vector<MtuArgs> list;
        for (int Family : { 4, 6 })
        for (uint8_t DropMode : {0, 1, 2, 3})
        for (uint8_t RaiseMinimum : {0, 1})
            list.push_back({ Family, DropMode, RaiseMinimum });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const MtuArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.DropMode << "/" << args.RaiseMinimum << "/";
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

INSTANTIATE_TEST_SUITE_P(
    Mtu,
    WithMtuArgs,
    ::testing::ValuesIn(WithMtuArgs::Generate()));

#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

TEST_F(Alpn, ValidAlpnLengths) {
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

QUIC_TEST_F(Alpn, InvalidAlpnLengths, QuicTestInvalidAlpnLengths)

QUIC_TEST_F(Alpn, ChangeAlpn, QuicTestChangeAlpn)


QUIC_TEST_P(WithFamilyArgs, BindConnectionImplicit, QuicTestBindConnectionImplicit)

QUIC_TEST_P(WithFamilyArgs, BindConnectionExplicit, QuicTestBindConnectionExplicit)

TEST_P(WithFamilyArgs, TestAddrFunctions) {
    TestLoggerT<ParamType> Logger("QuicTestAddrFunctions", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAddrFunctions), GetParam()));
    }
    else {
        QuicTestAddrFunctions(GetParam());
    }
}

struct WithHandshakeArgs1 : public QuicTestFixture, public testing::WithParamInterface<HandshakeArgs> {

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
QUIC_TEST_P(WithFamilyArgs, ClientSharedLocalPort, QuicTestClientSharedLocalPort)
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
    public QuicTestFixture, public testing::WithParamInterface<HandshakeArgs> {

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
    public QuicTestFixture, public testing::WithParamInterface<HandshakeArgs> {

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

struct WithVersionNegotiationExtArgs : public QuicTestFixture, public testing::WithParamInterface<VersionNegotiationExtArgs> {

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

QUIC_TEST_P(WithFamilyArgs, VersionNegotiation, QuicTestVersionNegotiation)

QUIC_TEST_P(WithFamilyArgs, VersionNegotiationRetry, QuicTestVersionNegotiationRetry)

QUIC_TEST_P(WithFamilyArgs, CompatibleVersionNegotiationRetry, QuicTestCompatibleVersionNegotiationRetry)

QUIC_TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiation, QuicTestCompatibleVersionNegotiation)

QUIC_TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultServer, QuicTestCompatibleVersionNegotiationDefaultServer)

QUIC_TEST_P(WithVersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultClient, QuicTestCompatibleVersionNegotiationDefaultClient)

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithVersionNegotiationExtArgs,
    testing::ValuesIn(WithVersionNegotiationExtArgs::Generate()));

QUIC_TEST_P(WithFamilyArgs, IncompatibleVersionNegotiation, QuicTestIncompatibleVersionNegotiation)

QUIC_TEST_P(WithFamilyArgs, FailedVersionNegotiation, QuicTestFailedVersionNegotiation)

struct WithFeatureSupportArgs : public QuicTestFixture, public testing::WithParamInterface<FeatureSupportArgs> {

    static ::std::vector<FeatureSupportArgs> Generate() {
        ::std::vector<FeatureSupportArgs> list;
        for (int Family : { 4, 6 })
        for (bool ServerSupport : { false, true })
        for (bool ClientSupport : { false, true })
            list.push_back({ Family, ServerSupport, ClientSupport });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const FeatureSupportArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerSupport ? "Server Yes" : "Server No") << "/" <<
        (args.ClientSupport ? "Client Yes" : "Client No");
}

QUIC_TEST_P(WithFeatureSupportArgs, ReliableResetNegotiation, QuicTestReliableResetNegotiation)

QUIC_TEST_P(WithFeatureSupportArgs, OneWayDelayNegotiation, QuicTestOneWayDelayNegotiation)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithFeatureSupportArgs,
    testing::ValuesIn(WithFeatureSupportArgs::Generate()));

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

struct WithCustomCertificateValidationArgs :
    public QuicTestFixture, public testing::WithParamInterface<CustomCertValidationArgs> {

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


QUIC_TEST_P(WithCustomCertificateValidationArgs, CustomServerCertificateValidation, QuicTestCustomServerCertificateValidation)

QUIC_TEST_P(WithCustomCertificateValidationArgs, CustomClientCertificateValidation, QuicTestCustomClientCertificateValidation)

QUIC_TEST_F(Handshake, CustomServerCertValidationAfterShutdown, QuicTestCustomServerCertValidationAfterShutdown)

QUIC_TEST_F(Handshake, CustomClientCertValidationAfterShutdown, QuicTestCustomClientCertValidationAfterShutdown)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithCustomCertificateValidationArgs,
    testing::ValuesIn(WithCustomCertificateValidationArgs::Generate()));

struct WithAcceptTicket :
    public QuicTestFixture, public testing::WithParamInterface<bool> {
};

TEST_P(WithAcceptTicket, CustomTicketValidationAfterShutdown) {
    TestLogger Logger("QuicTestCustomTicketValidationAfterShutdown");
#ifdef QUIC_DISABLE_0RTT_TESTS
    GTEST_SKIP_("Schannel doesn't support 0RTT yet");
#endif
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestCustomTicketValidationAfterShutdown), GetParam()));
    } else {
        QuicTestCustomTicketValidationAfterShutdown(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithAcceptTicket,
    testing::Values(true, false),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "Accept" : "Reject";
    });

struct WithClientCertificateArgs :
    public QuicTestFixture, public testing::WithParamInterface<ClientCertificateArgs> {

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
    public QuicTestFixture, public testing::WithParamInterface<CibirExtensionParams> {

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

QUIC_TEST_P(WithCibirExtensionParams, CibirExtension, QuicTestCibirExtension)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithCibirExtensionParams,
    testing::ValuesIn(WithCibirExtensionParams::Generate()));

#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION

struct WithOddSizeVnTpParams :
    public QuicTestFixture, public testing::WithParamInterface<OddSizeVnTpParams> {

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

QUIC_TEST_P(WithOddSizeVnTpParams, OddSizeVnTp, QuicTestVNTPOddSize)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithOddSizeVnTpParams,
    testing::ValuesIn(WithOddSizeVnTpParams::Generate()));

class WithVpnVersionParams : public QuicTestFixture, public testing::WithParamInterface<bool> {
};

QUIC_TEST_P(WithVpnVersionParams, VnTpChosenVersionMismatch, QuicTestVNTPChosenVersionMismatch)

QUIC_TEST_P(WithVpnVersionParams, VnTpChosenVersionZero, QuicTestVNTPChosenVersionZero)

QUIC_TEST_P(WithVpnVersionParams, VnTpOtherVersionZero, QuicTestVNTPOtherVersionZero)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithVpnVersionParams,
    ::testing::Values(false, true));

#endif
#endif

#if QUIC_TEST_FAILING_TEST_CERTIFICATES
TEST_F(CredValidation, ConnectExpiredServerCertificate) {
    QUIC_CREDENTIAL_BLOB Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_EXPIRED_SERVER,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        if (TestingKernelMode) {
            ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectExpiredServerCertificate), Params));
        } else {
            QuicTestConnectExpiredServerCertificate(Params);
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
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        QuicTestConnectExpiredServerCertificate(Params);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST_F(CredValidation, ConnectValidServerCertificate) {
    QUIC_CREDENTIAL_BLOB Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_VALID_SERVER,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        if (TestingKernelMode) {
            ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectValidServerCertificate), Params));
        } else {
            QuicTestConnectValidServerCertificate(Params);
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
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        QuicTestConnectValidServerCertificate(Params);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST_F(CredValidation, ConnectExpiredClientCertificate) {
    QUIC_CREDENTIAL_BLOB Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_EXPIRED_CLIENT,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

        if (TestingKernelMode) {
            ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectExpiredClientCertificate), Params));
        } else {
            QuicTestConnectExpiredClientCertificate(Params);
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
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        QuicTestConnectExpiredClientCertificate(Params);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST_F(CredValidation, ConnectValidClientCertificate) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022() || IsWindows2025()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    QUIC_CREDENTIAL_BLOB Params;
    for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
        ASSERT_TRUE(CxPlatGetTestCertificate(
            CXPLAT_TEST_CERT_VALID_CLIENT,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Params.CredConfig,
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

        if (TestingKernelMode) {
            ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectValidClientCertificate), Params));
        } else {
            QuicTestConnectValidClientCertificate(Params);
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
            &Params.Storage.CertHash,
            &Params.Storage.CertHashStore,
            NULL,
            NULL,
            NULL,
            (char*)Params.Storage.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        QuicTestConnectValidClientCertificate(Params);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}
#endif // QUIC_TEST_FAILING_TEST_CERTIFICATES

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED

struct WithHandshakeArgs4 :
    public QuicTestFixture, public testing::WithParamInterface<HandshakeArgs4> {

    static ::std::vector<HandshakeArgs4> Generate() {
        ::std::vector<HandshakeArgs4> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
        for (uint8_t RandomLossPercentage : { 1, 5, 10 })
            list.push_back({ Family, ServerStatelessRetry, MultiPacketClientInitial, RandomLossPercentage });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs4& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial") << "/" <<
        (uint32_t)args.RandomLossPercentage << "% loss";
}

TEST_P(WithHandshakeArgs4, RandomLoss) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-RandomLoss", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_RandomLoss), GetParam()));
    } else {
        QuicTestConnect_RandomLoss(GetParam());
    }
}

#ifndef QUIC_DISABLE_RESUMPTION
TEST_P(WithHandshakeArgs4, RandomLossResume) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-RandomLossResume", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_RandomLossResume), GetParam()));
    } else {
        QuicTestConnect_RandomLossResume(GetParam());
    }
}

TEST_P(WithHandshakeArgs4, RandomLossResumeRejection) {
#ifdef QUIC_TEST_SCHANNEL_FLAGS
    if (IsWindows2022()) GTEST_SKIP(); // Not supported with Schannel on WS2022
#endif
    TestLoggerT<ParamType> Logger("QuicTestConnect-RandomLossResumeRejection", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnect_RandomLossResumeRejection), GetParam()));
    } else {
        QuicTestConnect_RandomLossResumeRejection(GetParam());
    }
}
#endif // QUIC_DISABLE_RESUMPTION

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeArgs4,
    testing::ValuesIn(WithHandshakeArgs4::Generate()));

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

QUIC_TEST_F(HandshakeTest, InvalidAddress, QuicTestConnectInvalidAddress)

QUIC_TEST_P(WithFamilyArgs, BadALPN, QuicTestConnectBadAlpn)

QUIC_TEST_P(WithFamilyArgs, BadSNI, QuicTestConnectBadSni)

QUIC_TEST_P(WithFamilyArgs, IpSNI, QuicTestConnectIpSni)

QUIC_TEST_P(WithFamilyArgs, ServerRejected, QuicTestConnectServerRejected)

QUIC_TEST_P(WithFamilyArgs, ClientBlockedSourcePort, QuicTestClientBlockedSourcePort)

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
    TestLoggerT<ParamType> Logger("QuicTestNatPortRebind_NoPadding", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestNatPortRebind_NoPadding), GetParam()));
    } else {
        QuicTestNatPortRebind_NoPadding(GetParam());
    }
}

struct WithRebindPaddingArgs :
    public QuicTestFixture, public testing::WithParamInterface<RebindPaddingArgs> {

    static ::std::vector<RebindPaddingArgs> Generate() {
        ::std::vector<RebindPaddingArgs> list;
        for (int Family : { 4, 6 })
        for (uint16_t Padding = 1; Padding < 75; ++Padding)
            list.push_back({ Family, Padding });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const RebindPaddingArgs& args) {
    return o << (args.Family == 4 ? "v4" : "v6") << "/"
        << args.Padding;
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
    TestLoggerT<ParamType> Logger("QuicTestNatPortRebind_WithPadding", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestNatPortRebind_WithPadding), GetParam()));
    } else {
        QuicTestNatPortRebind_WithPadding(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithRebindPaddingArgs,
    ::testing::ValuesIn(WithRebindPaddingArgs::Generate()));

TEST_P(WithFamilyArgs, RebindAddr) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    if (UseQTIP) {
        //
        // NAT rebind doesn't make sense for TCP and QTIP.
        //
        return;
    }
#endif
    TestLoggerT<ParamType> Logger("QuicTestNatAddrRebind_NoPadding", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestNatAddrRebind_NoPadding), GetParam()));
    } else {
        QuicTestNatAddrRebind_NoPadding(GetParam());
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
    TestLoggerT<ParamType> Logger("QuicTestNatAddrRebind_WithPadding", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestNatAddrRebind_WithPadding), GetParam()));
    } else {
        QuicTestNatAddrRebind_WithPadding(GetParam());
    }
}

QUIC_TEST_P(WithFamilyArgs, PathValidationTimeout, QuicTestPathValidationTimeout)

QUIC_TEST_P(WithFamilyArgs, PathValidationLastPathClose, QuicTestPathValidationLastPathClose)
#endif

QUIC_TEST_P(WithFamilyArgs, ChangeMaxStreamIDs, QuicTestChangeMaxStreamID)

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

struct WithHandshakeLossPatternsArgs :
    public QuicTestFixture, public testing::WithParamInterface<HandshakeLossPatternsArgs> {

    static ::std::vector<HandshakeLossPatternsArgs> Generate() {
        ::std::vector<HandshakeLossPatternsArgs> list;
        for (int Family : { 4, 6 })
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        for (auto CcAlgo : { QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, QUIC_CONGESTION_CONTROL_ALGORITHM_BBR })
#else
        for (auto CcAlgo : { QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC })
#endif
            list.push_back({ Family, CcAlgo });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeLossPatternsArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.CcAlgo == QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC ? "cubic" : "bbr");
}

QUIC_TEST_P(WithHandshakeLossPatternsArgs, HandshakeSpecificLossPatterns, QuicTestHandshakeSpecificLossPatterns)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithHandshakeLossPatternsArgs,
    testing::ValuesIn(WithHandshakeLossPatternsArgs::Generate()));
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

struct WithShutdownDuringHandshakeArgs :
    public QuicTestFixture, public testing::WithParamInterface<ShutdownDuringHandshakeArgs> {

    static ::std::vector<ShutdownDuringHandshakeArgs> Generate() {
        ::std::vector<ShutdownDuringHandshakeArgs> list;
        for (bool ClientShutdown : { false, true })
            list.push_back({ ClientShutdown });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ShutdownDuringHandshakeArgs& args) {
    return o << (args.ClientShutdown ? "Client" : "Server");
}

QUIC_TEST_P(WithShutdownDuringHandshakeArgs, ShutdownDuringHandshake, QuicTestShutdownDuringHandshake)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithShutdownDuringHandshakeArgs,
    testing::ValuesIn(WithShutdownDuringHandshakeArgs::Generate()));

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)

struct WithConnectionPoolCreateArgs :
    public QuicTestFixture, public testing::WithParamInterface<ConnectionPoolCreateArgs> {

    static ::std::vector<ConnectionPoolCreateArgs> Generate() {
        ::std::vector<ConnectionPoolCreateArgs> list;
        for (int Family : { 4, 6 })
        for (uint16_t NumberOfConnections : { 1, 2, 4 })
        for (bool TestCibir : { false, true })
        for (bool XdpSupported : { false, true }) {
#if !defined(_WIN32)
            if (XdpSupported) continue;
#endif
            if (!UseDuoNic && XdpSupported) {
                continue;
            }
            list.push_back({ Family, NumberOfConnections, XdpSupported, TestCibir });
        }
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ConnectionPoolCreateArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.NumberOfConnections << "/" <<
        (args.XdpSupported ? "XDP" : "NoXDP") << "/" <<
        (args.TestCibirSupport ? "TestCibir" : "NoCibir");
}

QUIC_TEST_P(WithConnectionPoolCreateArgs, ConnectionPoolCreate, QuicTestConnectionPoolCreate)

INSTANTIATE_TEST_SUITE_P(
    Handshake,
    WithConnectionPoolCreateArgs,
    testing::ValuesIn(WithConnectionPoolCreateArgs::Generate()));
#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

struct WithSendArgs :
    public QuicTestFixture, public testing::WithParamInterface<SendArgs> {

    static ::std::vector<SendArgs> Generate() {
        ::std::vector<SendArgs> list;
        for (int Family : { 4, 6 })
        for (uint64_t Length : { 0, 1000, 10000 })
        for (uint32_t ConnectionCount : { 1, 2, 4 })
        for (uint32_t StreamCount : { 1, 2, 4 })
        for (bool UseSendBuffer : { false, true })
        for (bool UnidirectionalStreams : { false, true })
        for (bool ServerInitiatedStreams : { false, true })
            list.push_back({ Family, Length, ConnectionCount, StreamCount, UseSendBuffer, UnidirectionalStreams, ServerInitiatedStreams });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const SendArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length << "/" <<
        args.ConnectionCount << "/" <<
        args.StreamCount << "/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.UnidirectionalStreams ? "Uni" : "Bidi") << "/" <<
        (args.ServerInitiatedStreams ? "Server" : "Client");
}

QUIC_TEST_P(WithSendArgs, Send, QuicTestConnectAndPing_Send)

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSendArgs,
    testing::ValuesIn(WithSendArgs::Generate()));

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
TEST_P(WithSendArgs, SendQtip) {
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

struct WithSendLargeArgs :
    public QuicTestFixture, public testing::WithParamInterface<SendLargeArgs> {

    static ::std::vector<SendLargeArgs> Generate() {
        ::std::vector<SendLargeArgs> list;
        for (int Family : { 4, 6 })
        for (bool UseSendBuffer : { false, true })
#ifndef QUIC_DISABLE_0RTT_TESTS
        for (bool UseZeroRtt : { false, true })
#else
        for (bool UseZeroRtt : { false })
#endif
        {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            if (UseQTIP && UseZeroRtt) {
                continue;
            }
#endif
            list.push_back({ Family, UseSendBuffer, UseZeroRtt });
        }
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const SendLargeArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.UseZeroRtt ? "0-RTT" : "1-RTT");
}

QUIC_TEST_P(WithSendLargeArgs, SendLarge, QuicTestConnectAndPing_SendLarge)

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSendLargeArgs,
    testing::ValuesIn(WithSendLargeArgs::Generate()));

struct WithSendIntermittentlyArgs :
    public QuicTestFixture, public testing::WithParamInterface<SendIntermittentlyArgs> {

    static ::std::vector<SendIntermittentlyArgs> Generate() {
        ::std::vector<SendIntermittentlyArgs> list;
        for (int Family : { 4, 6 })
        for (uint64_t Length : { 1000, 10000 })
        for (uint32_t BurstCount : { 2, 4, 8 })
        for (uint32_t BurstDelay : { 100, 500, 1000 })
        for (bool UseSendBuffer : { false, true })
            list.push_back({ Family, Length, BurstCount, BurstDelay, UseSendBuffer });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const SendIntermittentlyArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length << "/" <<
        args.BurstCount << "/" <<
        args.BurstDelay << "ms/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer");
}

QUIC_TEST_P(WithSendIntermittentlyArgs, SendIntermittently, QuicTestConnectAndPing_SendIntermittently)

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSendIntermittentlyArgs,
    testing::ValuesIn(WithSendIntermittentlyArgs::Generate()));

#ifndef QUIC_DISABLE_0RTT_TESTS

struct WithSend0RttArgs1 :
    public QuicTestFixture, public testing::WithParamInterface<Send0RttArgs1> {

    static ::std::vector<Send0RttArgs1> Generate() {
        ::std::vector<Send0RttArgs1> list;
        for (int Family : { 4, 6 })
        for (uint64_t Length : { 0, 100, 1000, 2000 })
        for (uint32_t ConnectionCount : { 1, 2, 4 })
        for (uint32_t StreamCount : { 1, 2, 4 })
        for (bool UseSendBuffer : { false, true })
        for (bool UnidirectionalStreams : { false, true })
            list.push_back({ Family, Length, ConnectionCount, StreamCount, UseSendBuffer, UnidirectionalStreams });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const Send0RttArgs1& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length << "/" <<
        args.ConnectionCount << "/" <<
        args.StreamCount << "/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.UnidirectionalStreams ? "Uni" : "Bidi");
}

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
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectAndPing_Send0Rtt), GetParam()));
    } else {
        QuicTestConnectAndPing_Send0Rtt(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSend0RttArgs1,
    testing::ValuesIn(WithSend0RttArgs1::Generate()));

struct WithSend0RttArgs2 :
    public QuicTestFixture, public testing::WithParamInterface<Send0RttArgs2> {

    static ::std::vector<Send0RttArgs2> Generate() {
        ::std::vector<Send0RttArgs2> list;
        for (int Family : { 4, 6 })
        for (uint64_t Length : { 0, 1000, 10000, 20000 })
            list.push_back({ Family, Length });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const Send0RttArgs2& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length;
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
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestConnectAndPing_Reject0Rtt), GetParam()));
    } else {
        QuicTestConnectAndPing_Reject0Rtt(GetParam());
    }
}

INSTANTIATE_TEST_SUITE_P(
    AppData,
    WithSend0RttArgs2,
    testing::ValuesIn(WithSend0RttArgs2::Generate()));

#endif // QUIC_DISABLE_0RTT_TESTS

QUIC_TEST_P(WithBool, IdleTimeout, QuicTestConnectAndIdle)

QUIC_TEST_F(Misc, IdleDestCidChange, QuicTestConnectAndIdleForDestCidChange)

QUIC_TEST_F(Misc, ServerDisconnect, QuicTestServerDisconnect)

TEST_F(Misc, ClientDisconnect) {
    TestLogger Logger("QuicTestClientDisconnect");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestClientDisconnect), false));
    } else {
        QuicTestClientDisconnect(false); // TODO - Support true, when race condition is fixed.
    }
}

QUIC_TEST_F(Misc, StatelessResetKey, QuicTestStatelessResetKey)

QUIC_TEST_P(WithFamilyArgs, ForcedKeyUpdate, QuicTestForceKeyUpdate)

QUIC_TEST_P(WithFamilyArgs, KeyUpdate, QuicTestKeyUpdate)

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED

struct WithKeyUpdateRandomLossArgs :
    public QuicTestFixture, public testing::WithParamInterface<KeyUpdateRandomLossArgs> {

    static ::std::vector<KeyUpdateRandomLossArgs> Generate() {
        ::std::vector<KeyUpdateRandomLossArgs> list;
        for (int Family : { 4, 6 })
        for (int RandomLossPercentage : { 1, 5, 10 })
            list.push_back({ Family, (uint8_t)RandomLossPercentage });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const KeyUpdateRandomLossArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.RandomLossPercentage;
}

QUIC_TEST_P(WithKeyUpdateRandomLossArgs, RandomLoss, QuicTestKeyUpdateRandomLoss)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithKeyUpdateRandomLossArgs,
    testing::ValuesIn(WithKeyUpdateRandomLossArgs::Generate()));

#endif

struct WithAbortiveArgs :
    public QuicTestFixture, public testing::WithParamInterface<AbortiveArgs> {

    static ::std::vector<AbortiveArgs> Generate() {
        ::std::vector<AbortiveArgs> list;
        for (int Family : { 4, 6 })
        for (uint32_t DelayStreamCreation : { 0, 1 })
        for (uint32_t SendDataOnStream : { 0, 1 })
        for (uint32_t ClientShutdown : { 0, 1 })
        for (uint32_t DelayClientShutdown : { 0, 1 })
        for (uint32_t WaitForStream : { 1 })
        for (uint32_t ShutdownDirection : { 0, 1, 2 })
        for (uint32_t UnidirectionStream : { 0, 1 })
        for (uint32_t PauseReceive : { 0, 1 })
        for (uint32_t PendReceive : { 0, 1 })
            list.push_back({ Family, {{ DelayStreamCreation, SendDataOnStream, ClientShutdown, DelayClientShutdown, WaitForStream, ShutdownDirection, UnidirectionStream, PauseReceive, PendReceive }} });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const AbortiveArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Flags.DelayStreamCreation << "/" <<
        args.Flags.SendDataOnStream << "/" <<
        args.Flags.ClientShutdown << "/" <<
        args.Flags.DelayClientShutdown << "/" <<
        args.Flags.WaitForStream << "/" <<
        args.Flags.ShutdownDirection << "/" <<
        args.Flags.UnidirectionalStream << "/" <<
        args.Flags.PauseReceive << "/" <<
        args.Flags.PendReceive;
}

QUIC_TEST_P(WithAbortiveArgs, AbortiveShutdown, QuicAbortiveTransfers)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithAbortiveArgs,
    testing::ValuesIn(WithAbortiveArgs::Generate()));

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED

struct WithCancelOnLossArgs :
    public QuicTestFixture, public testing::WithParamInterface<CancelOnLossArgs> {

    static ::std::vector<CancelOnLossArgs> Generate() {
        ::std::vector<CancelOnLossArgs> list;
        for (bool DropPackets : {false, true})
            list.push_back({ DropPackets });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const CancelOnLossArgs& args) {
    return o << "DropPackets: " << (args.DropPackets ? "true" : "false");
}

QUIC_TEST_P(WithCancelOnLossArgs, CancelOnLossSend, QuicCancelOnLossSend)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithCancelOnLossArgs,
    testing::ValuesIn(WithCancelOnLossArgs::Generate()));

#endif

struct WithCidUpdateArgs :
    public QuicTestFixture, public testing::WithParamInterface<CidUpdateArgs> {

    static ::std::vector<CidUpdateArgs> Generate() {
        ::std::vector<CidUpdateArgs> list;
        for (int Family : { 4, 6 })
        for (int Iterations : { 1, 2, 4 })
            list.push_back({ Family, (uint16_t)Iterations });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const CidUpdateArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Iterations;
}

QUIC_TEST_P(WithCidUpdateArgs, CidUpdate, QuicTestCidUpdate)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithCidUpdateArgs,
    testing::ValuesIn(WithCidUpdateArgs::Generate()));

struct WithReceiveResumeArgs :
    public QuicTestFixture, public testing::WithParamInterface<ReceiveResumeArgs> {

    static ::std::vector<ReceiveResumeArgs> Generate() {
        ::std::vector<ReceiveResumeArgs> list;
        for (int SendBytes : { 100 })
        for (int Family : { 4, 6 })
        for (bool PauseFirst : { false, true })
        for (int ConsumeBytes : { 0, 1, 99 })
        for (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType : { NoShutdown, GracefulShutdown, AbortShutdown })
        for (QUIC_RECEIVE_RESUME_TYPE PauseType : { ReturnConsumedBytes, ReturnStatusPending, ReturnStatusContinue })
            list.push_back({ Family, SendBytes, ConsumeBytes, ShutdownType, PauseType, PauseFirst });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ReceiveResumeArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.SendBytes << "/" <<
        args.ConsumeBytes << "/" <<
        (args.ShutdownType ? (args.ShutdownType == AbortShutdown ? "Abort" : "Graceful") : "NoShutdown") << "/" <<
        (args.PauseType ? (args.PauseType == ReturnStatusPending ? "ReturnPending" : "ReturnContinue") : "ConsumePartial") << "/" <<
        (args.PauseFirst ? "PauseBeforeSend" : "PauseAfterSend");
}

QUIC_TEST_P(WithReceiveResumeArgs, ReceiveResume, QuicTestReceiveResume)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithReceiveResumeArgs,
    testing::ValuesIn(WithReceiveResumeArgs::Generate()));

struct WithReceiveResumeNoDataArgs :
    public QuicTestFixture, public testing::WithParamInterface<ReceiveResumeNoDataArgs> {

    static ::std::vector<ReceiveResumeNoDataArgs> Generate() {
        ::std::vector<ReceiveResumeNoDataArgs> list;
        for (int Family : { 4, 6 })
        for (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType : { GracefulShutdown, AbortShutdown })
            list.push_back({ Family, ShutdownType });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ReceiveResumeNoDataArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ShutdownType ? (args.ShutdownType == AbortShutdown ? "Abort" : "Graceful") : "NoShutdown");
}

QUIC_TEST_P(WithReceiveResumeNoDataArgs, ReceiveResumeNoData, QuicTestReceiveResumeNoData)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithReceiveResumeNoDataArgs,
    testing::ValuesIn(WithReceiveResumeNoDataArgs::Generate()));

TEST_P(WithFamilyArgs, AckSendDelay) {
    TestLogger Logger("QuicTestAckSendDelay");
    if (TestingKernelMode) {
        ASSERT_TRUE(InvokeKernelTest(FUNC(QuicTestAckSendDelay), GetParam()));
    } else {
        QuicTestAckSendDelay(GetParam());
    }
}

QUIC_TEST_F(Misc, AbortPausedReceive, QuicTestAbortReceive_Paused)

QUIC_TEST_F(Misc, AbortPendingReceive, QuicTestAbortReceive_Pending)

QUIC_TEST_F(Misc, AbortIncompleteReceive, QuicTestAbortReceive_Incomplete)

QUIC_TEST_F(Misc, SlowReceive, QuicTestSlowReceive)

#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL
QUIC_TEST_F(Misc, NthAllocFail, QuicTestNthAllocFail)
#endif // QUIC_TEST_OPENSSL_FLAGS
#endif // QUIC_TEST_ALLOC_FAILURES_ENABLED

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_F(Misc, NthPacketDrop, QuicTestNthPacketDrop)
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED

QUIC_TEST_F(Misc, StreamPriority, QuicTestStreamPriority)

QUIC_TEST_F(Misc, StreamPriorityInfiniteLoop, QuicTestStreamPriorityInfiniteLoop)

QUIC_TEST_F(Misc, StreamDifferentAbortErrors, QuicTestStreamDifferentAbortErrors)

QUIC_TEST_F(Misc, StreamAbortRecvFinRace, QuicTestStreamAbortRecvFinRace)

#ifdef QUIC_PARAM_STREAM_RELIABLE_OFFSET
QUIC_TEST_F(Misc, StreamReliableReset, QuicTestStreamReliableReset)

QUIC_TEST_F(Misc, StreamReliableResetMultipleSends, QuicTestStreamReliableResetMultipleSends)
#endif // QUIC_PARAM_STREAM_RELIABLE_OFFSET

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
QUIC_TEST_F(Misc, StreamMultiReceive, QuicTestStreamMultiReceive)

// App-provided receive buffer tests

struct WithAppProvidedBuffersConfigArgs: public QuicTestFixture, public testing::WithParamInterface<AppProvidedBuffersConfig> {
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

QUIC_TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffers_ClientSend, QuicTestStreamAppProvidedBuffers_ClientSend)

QUIC_TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffers_ServerSend, QuicTestStreamAppProvidedBuffers_ServerSend)

QUIC_TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream, QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream)

QUIC_TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer, QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer)

QUIC_TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream, QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream)

QUIC_TEST_P(WithAppProvidedBuffersConfigArgs, StreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer, QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithAppProvidedBuffersConfigArgs,
    testing::ValuesIn(WithAppProvidedBuffersConfigArgs::Generate()));

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES

QUIC_TEST_F(Misc, StreamBlockUnblockBidiConnFlowControl, QuicTestStreamBlockUnblockConnFlowControl_Bidi)

QUIC_TEST_F(Misc, StreamBlockUnblockUnidiConnFlowControl, QuicTestStreamBlockUnblockConnFlowControl_Unidi)

QUIC_TEST_F(Misc, StreamAbortConnFlowControl, QuicTestStreamAbortConnFlowControl)

QUIC_TEST_F(Basic, OperationPriority, QuicTestOperationPriority)

QUIC_TEST_F(Basic, ConnectionPriority, QuicTestConnectionPriority)

// Drill tests

QUIC_TEST_F(Drill, VarIntEncoder, QuicDrillTestVarIntEncoder)

struct WithDrillInitialPacketCidArgs:
    public QuicTestFixture, public testing::WithParamInterface<DrillInitialPacketCidArgs> {

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

QUIC_TEST_P(WithDrillInitialPacketCidArgs, DrillInitialPacketCids, QuicDrillTestInitialCid)

INSTANTIATE_TEST_SUITE_P(
    Drill,
    WithDrillInitialPacketCidArgs,
    testing::ValuesIn(WithDrillInitialPacketCidArgs::Generate()));

struct WithDrillInitialPacketTokenArgs:
    public QuicTestFixture, public testing::WithParamInterface<DrillInitialPacketTokenArgs> {

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

QUIC_TEST_P(WithDrillInitialPacketTokenArgs, DrillInitialPacketToken, QuicDrillTestInitialToken)

QUIC_TEST_P(WithDrillInitialPacketTokenArgs, QuicDrillTestServerVNPacket, QuicDrillTestServerVNPacket)

QUIC_TEST_P(WithDrillInitialPacketTokenArgs, QuicDrillTestKeyUpdateDuringHandshake, QuicDrillTestKeyUpdateDuringHandshake)

INSTANTIATE_TEST_SUITE_P(
    Drill,
    WithDrillInitialPacketTokenArgs,
    testing::ValuesIn(WithDrillInitialPacketTokenArgs::Generate()));

struct WithDatagramNegotiationArgs :
    public QuicTestFixture, public testing::WithParamInterface<DatagramNegotiationArgs> {

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

QUIC_TEST_P(WithDatagramNegotiationArgs, DatagramNegotiation, QuicTestDatagramNegotiation)

INSTANTIATE_TEST_SUITE_P(
    Misc,
    WithDatagramNegotiationArgs,
    testing::ValuesIn(WithDatagramNegotiationArgs::Generate()));

QUIC_TEST_P(WithFamilyArgs, DatagramSend, QuicTestDatagramSend)

QUIC_TEST_P(WithFamilyArgs, DatagramDrop, QuicTestDatagramDrop)

#ifdef _WIN32 // Storage tests only supported on Windows

static BOOLEAN CanRunStorageTests = FALSE;

TEST_F(Basic, TestStorage) {
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
TEST_F(Basic, TestVersionStorage) {
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
TEST_F(ParameterValidation, RetryConfigSetting)
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

//
// Instantiate test suites with common parameters.
//

INSTANTIATE_TEST_SUITE_P(
    ParameterValidation,
    WithBool,
    ::testing::Values(false, true));

INSTANTIATE_TEST_SUITE_P(
    Basic,
    WithFamilyArgs,
    ::testing::ValuesIn(WithFamilyArgs::Generate()));

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
