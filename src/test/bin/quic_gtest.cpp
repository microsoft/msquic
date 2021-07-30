/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.cpp.clog.h"
#endif

bool TestingKernelMode = false;
bool PrivateTestLibrary = false;
const MsQuicApi* MsQuic;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;
QuicDriverClient DriverClient;

class QuicTestEnvironment : public ::testing::Environment {
    QuicDriverService DriverService;
    const QUIC_CREDENTIAL_CONFIG* SelfSignedCertParams;
    const QUIC_CREDENTIAL_CONFIG* ClientCertParams;
public:
    void SetUp() override {
        CxPlatSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatInitialize()));
        ASSERT_TRUE((SelfSignedCertParams =
            CxPlatGetSelfSignedCert(
                TestingKernelMode ?
                    CXPLAT_SELF_SIGN_CERT_MACHINE :
                    CXPLAT_SELF_SIGN_CERT_USER,
                FALSE
                )) != nullptr);

#ifndef QUIC_DISABLE_CLIENT_CERT_TESTS
        ASSERT_TRUE((ClientCertParams =
            CxPlatGetSelfSignedCert(
                TestingKernelMode ?
                    CXPLAT_SELF_SIGN_CERT_MACHINE :
                    CXPLAT_SELF_SIGN_CERT_USER,
                TRUE
                )) != nullptr);
#endif
        if (TestingKernelMode) {
            printf("Initializing for Kernel Mode tests\n");
            const char* DriverName;
            const char* DependentDriverNames;
            QUIC_DRIVER_ARGS_SET_CERTIFICATE Args;
            CxPlatCopyMemory(
                &Args.ServerCertHash.ShaHash,
                (QUIC_CERTIFICATE_HASH*)(SelfSignedCertParams + 1),
                sizeof(QUIC_CERTIFICATE_HASH));
            CxPlatCopyMemory(
                &Args.ClientCertHash.ShaHash,
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
            ASSERT_TRUE(DriverClient.Initialize(&Args, DriverName));
        } else {
            printf("Initializing for User Mode tests\n");
            MsQuic = new(std::nothrow) MsQuicApi();
            ASSERT_TRUE(QUIC_SUCCEEDED(MsQuic->GetInitStatus()));
            memcpy(&ServerSelfSignedCredConfig, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            memcpy(&ServerSelfSignedCredConfigClientAuth, SelfSignedCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ServerSelfSignedCredConfigClientAuth.Flags |=
                QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
                QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
#ifndef QUIC_DISABLE_CLIENT_CERT_TESTS
            memcpy(&ClientCertCredConfig, ClientCertParams, sizeof(QUIC_CREDENTIAL_CONFIG));
            ClientCertCredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
#endif
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
#ifndef QUIC_DISABLE_CLIENT_CERT_TESTS
        CxPlatFreeSelfSignedCert(ClientCertParams);
#endif
        CxPlatUninitialize();
        CxPlatSystemUnload();
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
    char Buffer[128];
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

const QUIC_TEST_ARGS NullArgs = {QUIC_TEST_TYPE_NULL, 0};

//
// Abstraction for calling a test with no special args.
//
#define QUIC_TEST_RUN(suite, test) \
    TEST(suite, test) { \
        TestLogger Logger(#test); \
        if (TestingKernelMode) { \
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_##test, NullArgs)); \
        } else { \
            QuicTest##test(&NullArgs); \
        } \
    }

//
// Abstraction for calling a test with specific args.
//
#define QUIC_TEST_RUN_P(suite, test) \
    TEST_P(suite, test) { \
        TestLoggerT<ParamType> Logger(#test, GetParam()); \
        if (TestingKernelMode) { \
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_##test, GetParam())); \
        } else { \
            QuicTest##test(&GetParam()); \
        } \
    }

//
// Abstraction for calling a test with specific args and a different name.
//
#define QUIC_TEST_RUN_P2(suite, test, name) \
    TEST_P(suite, name) { \
        TestLoggerT<ParamType> Logger(#test, GetParam()); \
        if (TestingKernelMode) { \
            ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_##test, GetParam())); \
        } else { \
            QuicTest##test(&GetParam()); \
        } \
    }

QUIC_TEST_RUN(ParameterValidation, ValidateApi)
QUIC_TEST_RUN(ParameterValidation, ValidateRegistration)
QUIC_TEST_RUN(ParameterValidation, GetPerfCounters)
QUIC_TEST_RUN(ParameterValidation, ValidateConfiguration)
QUIC_TEST_RUN(ParameterValidation, ValidateListener)
QUIC_TEST_RUN(ParameterValidation, ValidateConnection)
QUIC_TEST_RUN_P(BooleanArgs, ValidateStream)
QUIC_TEST_RUN_P(ValidateConnectionEventArgs, ValidateConnectionEvents)
QUIC_TEST_RUN_P(ValidateStreamEventArgs, ValidateStreamEvents)
QUIC_TEST_RUN(ParameterValidation, DesiredVersionSettings)
QUIC_TEST_RUN(ParameterValidation, ValidateParamApi)
QUIC_TEST_RUN_P(BooleanArgs, ConnectionRejection)
QUIC_TEST_RUN(Basic, CreateListener)
QUIC_TEST_RUN(Basic, StartListener)
QUIC_TEST_RUN(Basic, StartListenerMultiAlpns)
QUIC_TEST_RUN(Basic, StartListenerImplicit)
QUIC_TEST_RUN(Basic, StartTwoListeners)
QUIC_TEST_RUN(Basic, StartTwoListenersSameALPN)
QUIC_TEST_RUN_P(FamilyArgs, StartListenerExplicit)
QUIC_TEST_RUN(Basic, CreateConnection)
#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P(FamilyArgs, LocalPathChanges)
QUIC_TEST_RUN(Mtu, MtuSettings)
QUIC_TEST_RUN_P(MtuArgs, MtuDiscovery)
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P(FamilyArgs, AckSendDelay)
QUIC_TEST_RUN_P(FamilyArgs, DrillInitialToken)
QUIC_TEST_RUN_P(FamilyArgs, DatagramSend)
QUIC_TEST_RUN(Alpn, ValidAlpnLengths);
QUIC_TEST_RUN(Alpn, InvalidAlpnLengths);
QUIC_TEST_RUN_P(FamilyArgs, BindConnectionImplicit)
QUIC_TEST_RUN_P(FamilyArgs, BindConnectionExplicit)
QUIC_TEST_RUN_P2(HandshakeArgs1, Connect, Connect);
#ifndef QUIC_DISABLE_RESUMPTION
QUIC_TEST_RUN_P2(HandshakeArgs1, Connect, Resume);
QUIC_TEST_RUN_P2(HandshakeArgs1, Connect, ResumeRejection);
#endif // QUIC_DISABLE_RESUMPTION
#ifndef QUIC_DISABLE_SHARED_PORT_TESTS
QUIC_TEST_RUN_P(FamilyArgs, ClientSharedLocalPort)
#endif
QUIC_TEST_RUN_P(FamilyArgs, InterfaceBinding)
QUIC_TEST_RUN_P2(HandshakeArgs2, Connect, OldVersion);
QUIC_TEST_RUN_P2(HandshakeArgs3, Connect, AsyncSecurityConfig);
QUIC_TEST_RUN_P(FamilyArgs, VersionNegotiation);
QUIC_TEST_RUN_P(FamilyArgs, VersionNegotiationRetry);
QUIC_TEST_RUN_P(FamilyArgs, CompatibleVersionNegotiationRetry);
QUIC_TEST_RUN_P(VersionNegotiationExtArgs, CompatibleVersionNegotiation);
QUIC_TEST_RUN_P(VersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultServer);
QUIC_TEST_RUN_P(VersionNegotiationExtArgs, CompatibleVersionNegotiationDefaultClient);
QUIC_TEST_RUN_P(FamilyArgs, IncompatibleVersionNegotiation)
QUIC_TEST_RUN_P(FamilyArgs, FailedVersionNegotiation)
QUIC_TEST_RUN_P(CustomCertArgs, CustomCertificateValidation);
#ifndef QUIC_DISABLE_CLIENT_CERT_TESTS
QUIC_TEST_RUN_P(ConnectClientCertArgs, ConnectClientCertificate);
#endif
#if QUIC_TEST_FAILING_TEST_CERTIFICATES
TEST(CredValidation, ConnectExpiredServerCertificate) {
    QUIC_TEST_ARGS_CRED_VALIDATION Params;
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
        ASSERT_TRUE(
            CxPlatGetTestCertificate(
                CXPLAT_TEST_CERT_EXPIRED_SERVER,
                CXPLAT_SELF_SIGN_CERT_USER,
                QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
                &Params.CredConfig,
                &Params.CertHash,
                &Params.CertHashStore,
                (char*)Params.PrincipalString));
        QuicTestConnectExpiredServerCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST(CredValidation, ConnectValidServerCertificate) {
    QUIC_TEST_ARGS_CRED_VALIDATION Params;
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
            (char*)Params.PrincipalString));
        QuicTestConnectValidServerCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST(CredValidation, ConnectExpiredClientCertificate) {
    QUIC_TEST_ARGS_CRED_VALIDATION Params;
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
            (char*)Params.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        QuicTestConnectExpiredClientCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}

TEST(CredValidation, ConnectValidClientCertificate) {
    QUIC_TEST_ARGS_CRED_VALIDATION Params;
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
            (char*)Params.PrincipalString));
        Params.CredConfig.Flags =
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        QuicTestConnectValidClientCertificate(&Params.CredConfig);
        CxPlatFreeTestCert((QUIC_CREDENTIAL_CONFIG*)&Params.CredConfig);
    }
}
#endif // QUIC_TEST_FAILING_TEST_CERTIFICATES

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P2(HandshakeArgs4, Connect, RandomLoss);
#ifndef QUIC_DISABLE_RESUMPTION
QUIC_TEST_RUN_P2(HandshakeArgs4, Connect, RandomLossResume);
QUIC_TEST_RUN_P2(HandshakeArgs4, Connect, RandomLossResumeRejection);
#endif // QUIC_DISABLE_RESUMPTION
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P(FamilyArgs, ConnectUnreachable)
QUIC_TEST_RUN_P(FamilyArgs, ConnectBadAlpn)
QUIC_TEST_RUN_P(FamilyArgs, ConnectBadSni)
QUIC_TEST_RUN_P(FamilyArgs, ConnectServerRejected)
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P(RebindArgs, NatPortRebind);
//QUIC_TEST_RUN_P(RebindPaddingArgs, NatPortRebind, RebindPortPadded);
QUIC_TEST_RUN_P(RebindArgs, NatAddrRebind);
//QUIC_TEST_RUN_P(RebindPaddingArgs, NatAddrRebind, RebindAddrPadded);
QUIC_TEST_RUN_P(FamilyArgs, PathValidationTimeout)
#endif
QUIC_TEST_RUN_P(FamilyArgs, ChangeMaxStreamID)
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P(FamilyArgs, LoadBalancedHandshake)
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P2(SendArgs1, ConnectAndPing, Send);
QUIC_TEST_RUN_P2(SendArgs2, ConnectAndPing, SendLarge);
QUIC_TEST_RUN_P2(SendArgs3, ConnectAndPing, SendIntermittently);
#ifndef QUIC_DISABLE_0RTT_TESTS
QUIC_TEST_RUN_P2(Send0RttArgs1, ConnectAndPing, Send0Rtt);
QUIC_TEST_RUN_P2(Send0RttArgs2, ConnectAndPing, Reject0Rtt);
#endif // QUIC_DISABLE_0RTT_TESTS
QUIC_TEST_RUN_P(BooleanArgs, ConnectAndIdle);
QUIC_TEST_RUN(Misc, ServerDisconnect);
QUIC_TEST_RUN(Misc, ClientDisconnect);
QUIC_TEST_RUN_P(KeyUpdateArgs1, KeyUpdate)
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_RUN_P(KeyUpdateArgs2, KeyUpdateRandomLoss)
#endif
QUIC_TEST_RUN_P(AbortiveArgs, AbortiveTransfers);
QUIC_TEST_RUN_P(CidUpdateArgs, CidUpdate);
QUIC_TEST_RUN_P(ReceiveResumeArgs, ReceiveResume);
QUIC_TEST_RUN_P(ReceiveResumeNoDataArgs, ReceiveResumeNoData);
QUIC_TEST_RUN_P(AbortReceiveArgs, AbortReceive);
QUIC_TEST_RUN(Misc, SlowReceive);
#ifdef QUIC_TEST_ALLOC_FAILURES_ENABLED
QUIC_TEST_RUN(Misc, NthAllocFail);
#endif
QUIC_TEST_RUN(Misc, StreamPriority);
QUIC_TEST_RUN(Misc, StreamDifferentAbortErrors);
QUIC_TEST_RUN(Misc, DrillVarIntEncoder);
QUIC_TEST_RUN_P(DrillInitialPacketCidArgs, DrillInitialCid);
QUIC_TEST_RUN_P(DatagramNegotiationArgs, DatagramNegotiation);

//
// Test suites with parameters.
//

#define QUIC_TEST_SUITE(suite, args) \
    INSTANTIATE_TEST_SUITE_P(suite, args, testing::ValuesIn(args::Generate()))

QUIC_TEST_SUITE(ParameterValidation, BooleanArgs);
QUIC_TEST_SUITE(Basic, FamilyArgs);
#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_SUITE(Mtu, MtuArgs);
//QUIC_TEST_SUITE(Basic, RebindPaddingArgs);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_SUITE(ParameterValidation, ValidateConnectionEventArgs);
QUIC_TEST_SUITE(ParameterValidation, ValidateStreamEventArgs);
QUIC_TEST_SUITE(Basic, VersionNegotiationExtArgs);
QUIC_TEST_SUITE(Handshake, HandshakeArgs1);
QUIC_TEST_SUITE(Handshake, HandshakeArgs2);
QUIC_TEST_SUITE(Handshake, HandshakeArgs3);
#ifdef QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_SUITE(Handshake, HandshakeArgs4);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_SUITE(Handshake, CustomCertArgs);
#ifndef QUIC_DISABLE_CLIENT_CERT_TESTS
QUIC_TEST_SUITE(Handshake, ConnectClientCertArgs);
#endif // QUIC_DISABLE_CLIENT_CERT_TESTS
QUIC_TEST_SUITE(AppData, SendArgs1);
QUIC_TEST_SUITE(AppData, SendArgs2);
QUIC_TEST_SUITE(AppData, SendArgs3);
#ifndef QUIC_DISABLE_0RTT_TESTS
QUIC_TEST_SUITE(AppData, Send0RttArgs1);
QUIC_TEST_SUITE(AppData, Send0RttArgs2);
#endif // QUIC_DISABLE_0RTT_TESTS
QUIC_TEST_SUITE(Misc, KeyUpdateArgs1);
#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_SUITE(Misc, KeyUpdateArgs2);
#endif // QUIC_TEST_DATAPATH_HOOKS_ENABLED
QUIC_TEST_SUITE(Misc, AbortiveArgs);
QUIC_TEST_SUITE(Misc, CidUpdateArgs);
QUIC_TEST_SUITE(Misc, ReceiveResumeArgs);
QUIC_TEST_SUITE(Misc, ReceiveResumeNoDataArgs);
QUIC_TEST_SUITE(Misc, DatagramNegotiationArgs);
QUIC_TEST_SUITE(Drill, DrillInitialPacketCidArgs);
QUIC_TEST_SUITE(Misc, AbortReceiveArgs);

//
// Main entry point.
//

int main(int argc, char** argv) {
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0 || strcmp("--kernelPriv", argv[i]) == 0) {
            TestingKernelMode = true;
            if (strcmp("--kernelPriv", argv[i]) == 0) {
                PrivateTestLibrary = true;
            }
        }
    }
    ::testing::AddGlobalTestEnvironment(new QuicTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
