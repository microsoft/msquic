/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_gtest.h"

#ifdef QUIC_LOGS_WPP
; //<-- WPP line was here
#include "quic_gtest.cpp.clog"

#endif

bool TestingKernelMode = false;
QUIC_API_V1* MsQuic;
HQUIC Registration;
QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams;
QUIC_SEC_CONFIG* SecurityConfig;
QuicDriverClient DriverClient;

extern "C" _IRQL_requires_max_(PASSIVE_LEVEL) void QuicTraceRundown(void) { }

class QuicTestEnvironment : public ::testing::Environment {
    QuicDriverService DriverService;
public:
    void SetUp() override {
        QuicPlatformSystemLoad();
        ASSERT_TRUE(QUIC_SUCCEEDED(QuicPlatformInitialize()));
        ASSERT_TRUE((SelfSignedCertParams =
            QuicPlatGetSelfSignedCert(
                TestingKernelMode ?
                    QUIC_SELF_SIGN_CERT_MACHINE :
                    QUIC_SELF_SIGN_CERT_USER
                )) != nullptr);
        if (TestingKernelMode) {
            printf("Initializing for Kernel Mode tests\n");
            ASSERT_TRUE(DriverService.Initialize());
            ASSERT_TRUE(DriverService.Start());
            ASSERT_TRUE(DriverClient.Initialize(SelfSignedCertParams));
        } else {
            printf("Initializing for User Mode tests\n");
            ASSERT_TRUE(QUIC_SUCCEEDED(MsQuicOpenV1(&MsQuic)));
            ASSERT_TRUE(QUIC_SUCCEEDED(MsQuic->RegistrationOpen("MsQuicBVT", &Registration)));
            ASSERT_TRUE(LoadSecConfig());
            QuicTestInitialize();
        }
    }
    void TearDown() override {
        if (TestingKernelMode) {
            DriverClient.Uninitialize();
            DriverService.Uninitialize();
        } else {
            QuicTestCleanup();
            MsQuic->SecConfigDelete(SecurityConfig);
            MsQuic->RegistrationClose(Registration);
            MsQuicClose(MsQuic);
        }
        QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
        QuicPlatformUninitialize();
        QuicPlatformSystemUnload();
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
    UNREFERENCED_PARAMETER(Function);
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

#if _WIN32
TEST(ParameterValidation, ValidateServerSecConfig) {
    TestLogger Logger("QuicTestValidateServerSecConfig");
    if (TestingKernelMode) {
        // Not currently supported, since certs are in user store.
        GTEST_SKIP_(":Unsupported in kernel mode");
    } else {
        QUIC_CERTIFICATE_HASH_STORE CertHashStore = { QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE };
        memcpy(CertHashStore.ShaHash, SelfSignedCertParams->Thumbprint, sizeof(CertHashStore.ShaHash));
        memcpy(CertHashStore.StoreName, "My", 2);
        QuicTestValidateServerSecConfig(SelfSignedCertParams->Certificate, &CertHashStore, "localhost");
    }
}
#endif // _WIN32

TEST(ParameterValidation, ValidateSession) {
    TestLogger Logger("QuicTestValidateSession");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_SESSION));
    } else {
        QuicTestValidateSession();
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

TEST_P(WithBool, ValidateStream) {
    TestLoggerT<ParamType> Logger("QuicTestValidateStream", GetParam());
    if (TestingKernelMode) {
        uint8_t Param = (uint8_t)GetParam();
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_STREAM, Param));
    } else {
        QuicTestValidateStream(GetParam());
    }
}

TEST(ParameterValidation, ValidateConnectionEvents) {
    TestLogger Logger("QuicTestValidateConnectionEvents");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS));
    } else {
        QuicTestValidateConnectionEvents();
    }
}

TEST(ParameterValidation, ValidateStreamEvents) {
    TestLogger Logger("QuicTestValidateStreamEvents");
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS));
    } else {
        QuicTestValidateStreamEvents();
    }
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
            0,  // ClientRebind
            0,  // ChangeMaxStreamID
            (uint8_t)GetParam().MultipleALPNs,
            0,  // AsyncSecConfig
            (uint8_t)GetParam().MultiPacketClientInitial,
            (uint8_t)GetParam().SessionResumption
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
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
}

TEST_P(WithHandshakeArgs2, OldVersion) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-OldVersion", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            1,  // ClientUsesOldVersion
            0,  // ClientRebind
            0,  // ChangeMaxStreamID
            0,  // MultipleALPNs
            0,  // AsyncSecConfig
            0   // SessionResumption
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
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
}

TEST_P(WithFamilyArgs, VersionNegotiation) {
    TestLoggerT<ParamType> Logger("QuicTestVersionNegotiation", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_VERSION_NEGOTIATION, GetParam().Family));
    } else {
        QuicTestVersionNegotiation(GetParam().Family);
    }
}

TEST_P(WithFamilyArgs, Rebind) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-Rebind", GetParam());
    if (TestingKernelMode) {
        GTEST_SKIP_(":Unsupported in kernel mode");
        /* Not supported in kernel mode yet.
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            0,  // ServerStatelessRetry
            0,  // ClientUsesOldVersion
            1,  // ClientRebind
            0,  // ChangeMaxStreamID
            0,  // MultipleALPNs
            0,  // AsyncSecConfig
            0   // SessionResumption
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));*/
    } else {
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
}

TEST_P(WithFamilyArgs, ChangeMaxStreamIDs) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-ChangeMaxStreamIDs", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            0,  // ServerStatelessRetry
            0,  // ClientUsesOldVersion
            0,  // ClientRebind
            1,  // ChangeMaxStreamID
            0,  // MultipleALPNs
            0,  // AsyncSecConfig
            0   // SessionResumption
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
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
}

TEST_P(WithHandshakeArgs1, AsyncSecurityConfig) {
    TestLoggerT<ParamType> Logger("QuicTestConnect-AsyncSecurityConfig", GetParam());
    if (TestingKernelMode) {
        QUIC_RUN_CONNECT_PARAMS Params = {
            GetParam().Family,
            (uint8_t)GetParam().ServerStatelessRetry,
            0,  // ClientUsesOldVersion
            0,  // ClientRebind
            0,  // ChangeMaxStreamID
            (uint8_t)GetParam().MultipleALPNs,
            1,  // AsyncSecConfig
            0   // SessionResumption
        };
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT, Params));
    } else {
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
}

TEST_P(WithFamilyArgs, Unreachable) {
    TestLoggerT<ParamType> Logger("QuicTestConnectUnreachable", GetParam());
    if (TestingKernelMode) {
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_UNREACHABLE, GetParam().Family));
    } else {
        QuicTestConnectUnreachable(GetParam().Family);
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
            0,  // ClientZeroRtt,
            0,  // ServerRejectZeroRtt
            (uint8_t)GetParam().UseSendBuffer,
            (uint8_t)GetParam().UnidirectionalStreams,
            (uint8_t)GetParam().ServerInitiatedStreams
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
            GetParam().ServerInitiatedStreams);
    }
}

#ifndef QUIC_DISABLE_0RTT_TESTS
// TODO - Send0Rtt
// TODO - Reject0Rtt
#endif

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
            0   // ServerInitiatedStreams
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
            false); // ServerInitiatedStreams
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
            0   // ServerInitiatedStreams
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
            false); // ServerInitiatedStreams
    }
}

TEST_P(WithBool, IdleTimeout) {
    TestLoggerT<ParamType> Logger("QuicTestConnectAndIdle", GetParam());
    if (TestingKernelMode) {
        uint8_t Param = (uint8_t)GetParam();
        ASSERT_TRUE(DriverClient.Run(IOCTL_QUIC_RUN_CONNECT_AND_IDLE, Param));
    } else {
        QuicTestConnectAndIdle(GetParam());
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
    for (int i = 0; i < argc; ++i) {
        if (strcmp("--kernel", argv[i]) == 0) {
            TestingKernelMode = true;
            break;
        }
    }
    ::testing::AddGlobalTestEnvironment(new QuicTestEnvironment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
