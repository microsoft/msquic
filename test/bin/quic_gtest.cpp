/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_gtest.h"

QUIC_API_V1* MsQuic;
HQUIC Registration;
QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams;
QUIC_SEC_CONFIG* SecurityConfig;

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

class QuicTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
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
    GTEST_MESSAGE_AT_(File, Line, Buffer, ::testing::TestPartResult::kFatalFailure);
}

TEST(ParameterValidation, ValidateApi) {
    QuicTestValidateApi();
}

TEST(ParameterValidation, ValidateRegistration) {
    QuicTestValidateRegistration();
}

#if _WIN32
TEST(ParameterValidation, ValidateServerSecConfig) {
    QUIC_CERTIFICATE_HASH_STORE CertHashStore = { QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE };
    memcpy(CertHashStore.ShaHash, SelfSignedCertParams->Thumbprint, sizeof(CertHashStore.ShaHash));
    memcpy(CertHashStore.StoreName, "My", 2);
    QuicTestValidateServerSecConfig(
        false, SelfSignedCertParams->Certificate, &CertHashStore, "localhost");
}
#endif // _WIN32

TEST(ParameterValidation, ValidateSession) {
    QuicTestValidateSession();
}

TEST(ParameterValidation, ValidateListener) {
    QuicTestValidateListener();
}

TEST(ParameterValidation, ValidateConnection) {
    QuicTestValidateConnection();
}

TEST_P(WithBool, ValidateStream) {
    QuicTestValidateStream(GetParam());
}

TEST(Basic, CreateListener) {
    QuicTestCreateListener();
}

TEST(Basic, StartListener) {
    QuicTestStartListener();
}

TEST_P(WithFamilyArgs, StartListenerImplicit) {
    QuicTestStartListenerImplicit(GetParam().Family);
}

TEST(Basic, StartTwoListeners) {
    QuicTestStartTwoListeners();
}

TEST(Basic, StartTwoListenersSameALPN) {
    QuicTestStartTwoListenersSameALPN();
}

TEST_P(WithFamilyArgs, StartListenerExplicit) {
    QuicTestStartListenerExplicit(GetParam().Family);
}

TEST(Basic, CreateConnection) {
    QuicTestCreateConnection();
}

TEST_P(WithFamilyArgs, BindConnectionImplicit) {
    QuicTestBindConnectionImplicit(GetParam().Family);
}

TEST_P(WithFamilyArgs, BindConnectionExplicit) {
    QuicTestBindConnectionExplicit(GetParam().Family);
}

TEST_P(WithHandshakeArgs1, Connect) {
    QuicTestConnect(
        GetParam().Family,
        GetParam().ServerStatelessRetry,
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        false,  // ChangeMaxStreamID
        GetParam().MultipleALPNs,
        false,  // AsyncSecConfig
        GetParam().MultiPacketClientInitial
    );
}

TEST_P(WithHandshakeArgs2, OldVersion) {
    QuicTestConnect(
        GetParam().Family,
        GetParam().ServerStatelessRetry,
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        false,  // ChangeMaxStreamID
        false,  // MultipleALPNs
        false,  // AsyncSecConfig
        false   // MultiPacketClientInitial
    );
}

TEST_P(WithFamilyArgs, VersionNegotiation) {
    QuicTestVersionNegotiation(GetParam().Family);
}

TEST_P(WithFamilyArgs, ChangeMaxStreamIDs) {
    QuicTestConnect(
        GetParam().Family,
        false,  // ServerStatelessRetry
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        true,   // ChangeMaxStreamID
        false,  // MultipleALPNs
        false,  // AsyncSecConfig
        false   // MultiPacketClientInitial
    );
}

TEST_P(WithHandshakeArgs1, AsyncSecurityConfig) {
    QuicTestConnect(
        GetParam().Family,
        GetParam().ServerStatelessRetry,
        false,  // ClientUsesOldVersion
        false,  // ClientRebind
        false,  // ChangeMaxStreamID
        GetParam().MultipleALPNs,
        true,   // AsyncSecConfig
        false   // MultiPacketClientInitial
    );
}

TEST_P(WithFamilyArgs, Unreachable) {
    QuicTestConnectUnreachable(GetParam().Family);
}

TEST_P(WithFamilyArgs, BadALPN) {
    QuicTestConnectBadAlpn(GetParam().Family);
}

TEST_P(WithFamilyArgs, BadSNI) {
    QuicTestConnectBadSni(GetParam().Family);
}

TEST_P(WithFamilyArgs, ServerRejected) {
    QuicTestConnectServerRejected(GetParam().Family);
}

TEST_P(WithSendArgs1, Send) {
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
        GetParam().ServerInitiatedStreams
    );
}

#ifndef QUIC_0RTT_UNSUPPORTED
// TODO - Send0Rtt
// TODO - Reject0Rtt
#endif

TEST_P(WithSendArgs2, SendLarge) {
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
        false   // ServerInitiatedStreams
    );
}

TEST_P(WithSendArgs3, SendIntermittently) {
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
        false   // ServerInitiatedStreams
    );
}

TEST_P(WithBool, IdleTimeout) {
    QuicTestConnectAndIdle(GetParam());
}

TEST(Misc, ServerDisconnect) {
    QuicTestServerDisconnect();
}

TEST(Misc, ClientDisconnect) {
    QuicTestClientDisconnect(false); // TODO - Support true, when race condition is fixed.
}

TEST_P(WithKeyUpdateArgs1, KeyUpdate) {
    QuicTestKeyUpdate(
        GetParam().Family,
        GetParam().KeyUpdate == 0 ? 5 : 1,  // Iterations
        0,                                  // KeyUpdateBytes
        GetParam().KeyUpdate == 0,          // UseKeyUpdateBytes
        GetParam().KeyUpdate & 1,           // ClientKeyUpdate
        GetParam().KeyUpdate & 2            // ServerKeyUpdate
    );
}

TEST_P(WithAbortiveArgs, AbortiveShutdown) {
    QuicAbortiveTransfers(GetParam().Family, GetParam().Flags);
}

TEST_P(WithCidUpdateArgs, CidUpdate) {
    QuicTestCidUpdate(GetParam().Family, GetParam().Iterations);
}

TEST_P(WithReceiveResumeArgs, ReceiveResume) {
    QuicTestReceiveResume(GetParam().Family, GetParam().SendBytes, GetParam().ConsumeBytes, GetParam().ShutdownType, GetParam().PauseType, GetParam().PauseFirst);
}

TEST_P(WithReceiveResumeNoDataArgs, ReceiveResumeNoData) {
    QuicTestReceiveResumeNoData(GetParam().Family, GetParam().ShutdownType);
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

int main(int argc, char** argv) {
    ::testing::AddGlobalTestEnvironment(new QuicTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
