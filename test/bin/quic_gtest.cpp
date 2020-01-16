/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_gtest.h"

#ifdef QUIC_LOGS_WPP
#include "quic_gtest.tmh"
#endif

QUIC_API_V1* MsQuic;
HQUIC Registration;
QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams;
QUIC_SEC_CONFIG* SecurityConfig;

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

class QuicTestEnvironment : public ::testing::Environment {
    bool PlatformInitialized;
public:
    void SetUp() override {
        if (QUIC_FAILED(QuicPlatformInitialize())) {
            return; // TODO - FAIL SetUp
        }
        PlatformInitialized = true;
        if (QUIC_FAILED(MsQuicOpenV1(&MsQuic))) {
            return; // TODO - FAIL SetUp
        }
        if (QUIC_FAILED(MsQuic->RegistrationOpen("MsQuicBVT", &Registration))) {
            MsQuicClose(MsQuic);
            return; // TODO - FAIL SetUp
        }
        if ((SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER)) == nullptr) {
            MsQuic->RegistrationClose(Registration);
            MsQuicClose(MsQuic);
            return; // TODO - FAIL SetUp
        }
        if (!LoadSecConfig()) {
            QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
            MsQuic->RegistrationClose(Registration);
            MsQuicClose(MsQuic);
            return; // TODO - FAIL SetUp
        }
        QuicTestInitialize();
    }
    void TearDown() override {
        QuicTestCleanup();
        MsQuic->SecConfigDelete(SecurityConfig);
        SecurityConfig = nullptr;
        QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
        SelfSignedCertParams = nullptr;
        MsQuic->RegistrationClose(Registration);
        Registration = nullptr;
        MsQuicClose(MsQuic);
        MsQuic = nullptr;
        if (PlatformInitialized) {
            QuicPlatformUninitialize();
        }
    }
    _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
    static void
    QUIC_API
    GetSecConfigComplete(
        _In_opt_ void* Context,
        _In_ QUIC_STATUS /* Status */,
        _In_opt_ QUIC_SEC_CONFIG* SecConfig
        )
    {
        _Analysis_assume_(Context);
        auto Event = (QUIC_EVENT*)Context;
        SecurityConfig = SecConfig;
        QuicEventSet(*Event);
    }
    bool LoadSecConfig() {
        QUIC_EVENT Event;
        QuicEventInitialize(&Event, FALSE, FALSE);
        if (QUIC_SUCCEEDED(
            MsQuic->SecConfigCreate(
                Registration,
                (QUIC_SEC_CONFIG_FLAGS)SelfSignedCertParams->Flags,
                SelfSignedCertParams->Certificate,
                SelfSignedCertParams->Principal,
                &Event,
                GetSecConfigComplete))) {
            QuicEventWaitForever(Event);
        }
        QuicEventUninitialize(Event);
        return SecurityConfig != nullptr;
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
    char Buffer[128];
    va_list Args;
    va_start(Args, Format);
    (void)_vsnprintf_s(Buffer, sizeof(Buffer), _TRUNCATE, Format, Args);
    va_end(Args);
    QuicTraceLogError("[test] FAILURE - %s:%d - %s", File, Line, Buffer);
    GTEST_MESSAGE_AT_(File, Line, Buffer, ::testing::TestPartResult::kFatalFailure);
}

struct TestLogger {
    const char* TestName;
    TestLogger(const char* Name) : TestName(Name) {
        QuicTraceLogInfo("[test] START %s", TestName);
    }
    ~TestLogger() {
        QuicTraceLogInfo("[test] END %s", TestName);
    }
};

template<class T>
struct TestLoggerT {
    const char* TestName;
    TestLoggerT(const char* Name, const T& Params) : TestName(Name) {
        std::ostringstream stream; stream << Params;
        QuicTraceLogInfo("[test] START %s, %s", TestName, stream.str().c_str());
    }
    ~TestLoggerT() {
        QuicTraceLogInfo("[test] END %s", TestName);
    }
};

TEST(ParameterValidation, ValidateApi) {
    TestLogger Logger("QuicTestValidateApi");
    QuicTestValidateApi();
}

TEST(ParameterValidation, ValidateRegistration) {
    TestLogger Logger("QuicTestValidateRegistration");
    QuicTestValidateRegistration();
}

#if _WIN32
TEST(ParameterValidation, ValidateServerSecConfig) {
    TestLogger Logger("QuicTestValidateServerSecConfig");
    QUIC_CERTIFICATE_HASH_STORE CertHashStore = { QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE };
    memcpy(CertHashStore.ShaHash, SelfSignedCertParams->Thumbprint, sizeof(CertHashStore.ShaHash));
    memcpy(CertHashStore.StoreName, "My", 2);
    QuicTestValidateServerSecConfig(SelfSignedCertParams->Certificate, &CertHashStore, "localhost");
}
#endif // _WIN32

TEST(ParameterValidation, ValidateSession) {
    TestLogger Logger("QuicTestValidateSession");
    QuicTestValidateSession();
}

TEST(ParameterValidation, ValidateListener) {
    TestLogger Logger("QuicTestValidateListener");
    QuicTestValidateListener();
}

TEST(ParameterValidation, ValidateConnection) {
    TestLogger Logger("QuicTestValidateConnection");
    QuicTestValidateConnection();
}

TEST_P(WithBool, ValidateStream) {
    TestLoggerT<ParamType> Logger("QuicTestValidateStream", GetParam());
    QuicTestValidateStream(GetParam());
}

TEST(Basic, CreateListener) {
    TestLogger Logger("QuicTestCreateListener");
    QuicTestCreateListener();
}

TEST(Basic, StartListener) {
    TestLogger Logger("QuicTestStartListener");
    QuicTestStartListener();
}

TEST_P(WithFamilyArgs, StartListenerImplicit) {
    TestLoggerT<ParamType> Logger("QuicTestStartListenerImplicit", GetParam());
    QuicTestStartListenerImplicit(GetParam().Family);
}

TEST(Basic, StartTwoListeners) {
    TestLogger Logger("QuicTestStartTwoListeners");
    QuicTestStartTwoListeners();
}

TEST(Basic, StartTwoListenersSameALPN) {
    TestLogger Logger("QuicTestStartTwoListenersSameALPN");
    QuicTestStartTwoListenersSameALPN();
}

TEST_P(WithFamilyArgs, StartListenerExplicit) {
    TestLoggerT<ParamType> Logger("QuicTestStartListenerImplicit", GetParam());
    QuicTestStartListenerExplicit(GetParam().Family);
}

TEST(Basic, CreateConnection) {
    TestLogger Logger("QuicTestCreateConnection");
    QuicTestCreateConnection();
}

TEST_P(WithFamilyArgs, BindConnectionImplicit) {
    TestLoggerT<ParamType> Logger("QuicTestBindConnectionImplicit", GetParam());
    QuicTestBindConnectionImplicit(GetParam().Family);
}

TEST_P(WithFamilyArgs, BindConnectionExplicit) {
    TestLoggerT<ParamType> Logger("QuicTestBindConnectionExplicit", GetParam());
    QuicTestBindConnectionExplicit(GetParam().Family);
}

TEST_P(WithHandshakeArgs1, Connect) {
    TestLoggerT<ParamType> Logger("QuicTestConnect", GetParam());
    QuicTestConnect(
        GetParam().Family,
        GetParam().ServerStatelessRetry,
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        false,  // ChangeMaxStreamID
        GetParam().MultipleALPNs,
        false,  // AsyncSecConfig
        GetParam().MultiPacketClientInitial,
        GetParam().SessionResumption);
}

TEST_P(WithHandshakeArgs2, OldVersion) {
    TestLoggerT<ParamType> Logger("QuicTestConnect", GetParam());
    QuicTestConnect(
        GetParam().Family,
        GetParam().ServerStatelessRetry,
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        false,  // ChangeMaxStreamID
        false,  // MultipleALPNs
        false,  // AsyncSecConfig
        false,  // MultiPacketClientInitial
        false); // SessionResumption
}

TEST_P(WithFamilyArgs, VersionNegotiation) {
    TestLoggerT<ParamType> Logger("QuicTestVersionNegotiation", GetParam());
    QuicTestVersionNegotiation(GetParam().Family);
}

TEST_P(WithFamilyArgs, Rebind) {
    TestLoggerT<ParamType> Logger("QuicTestConnect", GetParam());
    QuicTestConnect(
        GetParam().Family,
        false,  // ServerStatelessRetry
        false,  // ClientUsesOldVersion
        true,   // ClientRebind
        false,  // ChangeMaxStreamID
        false,  // MultipleALPNs
        false,  // AsyncSecConfig
        false,  // MultiPacketClientInitial
        false); // SessionResumption
}

TEST_P(WithFamilyArgs, ChangeMaxStreamIDs) {
    TestLoggerT<ParamType> Logger("QuicTestConnect", GetParam());
    QuicTestConnect(
        GetParam().Family,
        false,  // ServerStatelessRetry
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        true,   // ChangeMaxStreamID
        false,  // MultipleALPNs
        false,  // AsyncSecConfig
        false,  // MultiPacketClientInitial
        false); // SessionResumption
}

TEST_P(WithHandshakeArgs1, AsyncSecurityConfig) {
    TestLoggerT<ParamType> Logger("QuicTestConnect", GetParam());
    QuicTestConnect(
        GetParam().Family,
        GetParam().ServerStatelessRetry,
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        false,  // ChangeMaxStreamID
        GetParam().MultipleALPNs,
        true,   // AsyncSecConfig
        false,  // MultiPacketClientInitial
        false); // SessionResumption
}

TEST_P(WithFamilyArgs, Unreachable) {
    TestLoggerT<ParamType> Logger("QuicTestConnectUnreachable", GetParam());
    QuicTestConnectUnreachable(GetParam().Family);
}

TEST_P(WithFamilyArgs, BadALPN) {
    TestLoggerT<ParamType> Logger("QuicTestConnectBadAlpn", GetParam());
    QuicTestConnectBadAlpn(GetParam().Family);
}

TEST_P(WithFamilyArgs, BadSNI) {
    TestLoggerT<ParamType> Logger("QuicTestConnectBadSni", GetParam());
    QuicTestConnectBadSni(GetParam().Family);
}

TEST_P(WithFamilyArgs, ServerRejected) {
    TestLoggerT<ParamType> Logger("QuicTestConnectServerRejected", GetParam());
    QuicTestConnectServerRejected(GetParam().Family);
}

TEST_P(WithSendArgs1, Send) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPing", GetParam());
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
        GetParam().ServerInitiatedStreams);
}

#ifndef QUIC_DISABLE_0RTT
// TODO - Send0Rtt
// TODO - Reject0Rtt
#endif

TEST_P(WithSendArgs2, SendLarge) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPing", GetParam());
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
        false); // ServerInitiatedStreams
}

TEST_P(WithSendArgs3, SendIntermittently) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndPing", GetParam());
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
        false); // ServerInitiatedStreams
}

TEST_P(WithBool, IdleTimeout) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndIdle", GetParam());
    QuicTestConnectAndIdle(GetParam());
}

TEST(Misc, ServerDisconnect) {
    TestLogger Logger("QuicTestServerDisconnect");
    QuicTestServerDisconnect();
}

TEST(Misc, ClientDisconnect) {
    TestLogger Logger("QuicTestClientDisconnect");
    QuicTestClientDisconnect(false); // TODO - Support true, when race condition is fixed.
}

TEST_P(WithKeyUpdateArgs1, KeyUpdate) {
    TestLoggerT<ParamType> Logger("QuicTestKeyUpdate", GetParam());
    QuicTestKeyUpdate(
        GetParam().Family,
        GetParam().KeyUpdate == 0 ? 5 : 1,  // Iterations
        0,                                  // KeyUpdateBytes
        GetParam().KeyUpdate == 0,          // UseKeyUpdateBytes
        GetParam().KeyUpdate & 1,           // ClientKeyUpdate
        GetParam().KeyUpdate & 2);          // ServerKeyUpdate
}

TEST_P(WithAbortiveArgs, AbortiveShutdown) {
    TestLoggerT<ParamType> Logger("QuicAbortiveTransfers", GetParam());
    QuicAbortiveTransfers(GetParam().Family, GetParam().Flags);
}

TEST_P(WithCidUpdateArgs, CidUpdate) {
    TestLoggerT<ParamType> Logger("QuicTestCidUpdate", GetParam());
    QuicTestCidUpdate(GetParam().Family, GetParam().Iterations);
}

TEST_P(WithReceiveResumeArgs, ReceiveResume) {
    TestLoggerT<ParamType> Logger("QuicTestReceiveResume", GetParam());
    QuicTestReceiveResume(
        GetParam().Family,
        GetParam().SendBytes,
        GetParam().ConsumeBytes,
        GetParam().ShutdownType,
        GetParam().PauseType,
        GetParam().PauseFirst);
}

TEST_P(WithReceiveResumeNoDataArgs, ReceiveResumeNoData) {
    TestLoggerT<ParamType> Logger("QuicTestReceiveResumeNoData", GetParam());
    QuicTestReceiveResumeNoData(GetParam().Family, GetParam().ShutdownType);
}

TEST_P(WithDrillInitialPacketCidArgs, DrillInitialPacketCids) {
    TestLoggerT<ParamType> Logger("QuicDrillInitialPacketCids", GetParam());
    QuicDrillTestInitialCid(
        GetParam().Family,
        GetParam().SourceOrDest,
        GetParam().ActualCidLengthValid,
        GetParam().ShortCidLength,
        GetParam().CidLengthFieldValid);
}

TEST_P(WithDrillInitialPacketTokenArgs, DrillInitialPacketToken) {
    TestLoggerT<ParamType> Logger("QuicDrillInitialPacketToken", GetParam());
    QuicDrillTestInitialToken(GetParam().Family);
}

INSTANTIATE_TEST_CASE_P(
    ParameterValidation,
    WithBool,
    ::testing::Values(false, true));

INSTANTIATE_TEST_CASE_P(
    Basic,
    WithFamilyArgs,
    ::testing::ValuesIn(FamilyArgs::Generate()));

INSTANTIATE_TEST_CASE_P(
    Handshake,
    WithHandshakeArgs1,
    testing::ValuesIn(HandshakeArgs1::Generate()));

INSTANTIATE_TEST_CASE_P(
    Handshake,
    WithHandshakeArgs2,
    testing::ValuesIn(HandshakeArgs2::Generate()));

INSTANTIATE_TEST_CASE_P(
    AppData,
    WithSendArgs1,
    testing::ValuesIn(SendArgs1::Generate()));

INSTANTIATE_TEST_CASE_P(
    AppData,
    WithSendArgs2,
    testing::ValuesIn(SendArgs2::Generate()));

INSTANTIATE_TEST_CASE_P(
    AppData,
    WithSendArgs3,
    testing::ValuesIn(SendArgs3::Generate()));

INSTANTIATE_TEST_CASE_P(
    Misc,
    WithKeyUpdateArgs1,
    testing::ValuesIn(KeyUpdateArgs1::Generate()));

INSTANTIATE_TEST_CASE_P(
    Misc,
    WithAbortiveArgs,
    testing::ValuesIn(AbortiveArgs::Generate()));

INSTANTIATE_TEST_CASE_P(
    Misc,
    WithCidUpdateArgs,
    testing::ValuesIn(CidUpdateArgs::Generate()));

INSTANTIATE_TEST_CASE_P(
    Misc,
    WithReceiveResumeArgs,
    testing::ValuesIn(ReceiveResumeArgs::Generate()));

INSTANTIATE_TEST_CASE_P(
    Misc,
    WithReceiveResumeNoDataArgs,
    testing::ValuesIn(ReceiveResumeNoDataArgs::Generate()));

INSTANTIATE_TEST_CASE_P(
    Drill,
    WithDrillInitialPacketCidArgs,
    testing::ValuesIn(DrillInitialPacketCidArgs::Generate()));

INSTANTIATE_TEST_CASE_P(
    Drill,
    WithDrillInitialPacketTokenArgs,
    testing::ValuesIn(DrillInitialPacketTokenArgs::Generate()));

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
