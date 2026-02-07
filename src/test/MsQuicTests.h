/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Interface for the Platform Independent MsQuic Tests

--*/

#pragma once

//
// Enable preview features in tests.
// N.B. Preview features can change and cause down-level test failures.
//      If it happens, disable the test case downlevel.
// TODO: Should there be a "preview" tag for easily skip preview tests? Or we accept they can fail downlevel?
//
#define QUIC_API_ENABLE_PREVIEW_FEATURES

#include "msquic.hpp"

//
// Enable tests for specific platforms/scenarios
//

//#define QUIC_COMPARTMENT_TESTS 1

extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
extern QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;

#ifndef MAX_PATH
#define MAX_PATH 260
#endif
extern char CurrentWorkingDirectory[MAX_PATH + 1];

#ifdef __cplusplus
extern "C" {
#endif

void QuicTestInitialize();
void QuicTestUninitialize();

//
// Parameter structures used by many tests
//

struct FamilyArgs {
    int Family;
};

struct QUIC_CREDENTIAL_BLOB {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
        QUIC_CERTIFICATE_PKCS12 Pkcs12;
        char PrincipalString[100];
    } Storage;
};

//
// Parameter Validation Tests
//

void QuicTestValidateApi();
void QuicTestValidateRegistration();
void QuicTestValidateConfiguration();
void QuicTestValidateListener();
void QuicTestValidateConnection();
void QuicTestValidateStream(const bool& Connect);
void QuicTestCloseConnBeforeStreamFlush();
void QuicTestGlobalParam();
void QuicTestCommonParam();
void QuicTestRegistrationParam();
void QuicTestConfigurationParam();
void QuicTestListenerParam();
void QuicTestConnectionParam();
void QuicTestTlsParam();
void QuicTestTlsHandshakeInfo(const bool& EnableResumption);
void QuicTestStreamParam();
void QuicTestGetPerfCounters();
void QuicTestVersionSettings();
void QuicTestValidateParamApi();
void QuicTestCredentialLoad(const QUIC_CREDENTIAL_BLOB& Config);
void QuicTestValidateConnectionPoolCreate();
void QuicTestValidateExecutionContext();
void QuicTestValidatePartition();
void QuicTestRetryConfigSetting();

//
// Ownership tests
//
void QuicTestRegistrationShutdownBeforeConnOpen();
void QuicTestRegistrationShutdownAfterConnOpen();
void QuicTestRegistrationShutdownAfterConnOpenBeforeStart();
void QuicTestRegistrationShutdownAfterConnOpenAndStart();
void QuicTestConnectionCloseBeforeStreamClose();

//
// Rejection Tests
//
void QuicTestConnectionRejection(const bool& RejectByClosing);

//
// Event Validation Tests
//

struct ValidateConnectionEventArgs {
    uint32_t Test;
};
void QuicTestValidateConnectionEvents(const ValidateConnectionEventArgs& Params);
struct ValidateNetStatsConnEventArgs {
    uint32_t Test;
};
void QuicTestValidateNetStatsConnEvent(const ValidateNetStatsConnEventArgs& Params);

struct ValidateStreamEventArgs {
    uint32_t Test;
};
void QuicTestValidateStreamEvents(const ValidateStreamEventArgs& Params);

//
// Basic Functionality Tests
//

void QuicTestRegistrationOpenClose();
void QuicTestCreateListener();
void QuicTestStartListener();
void QuicTestStartListenerMultiAlpns();
void QuicTestStartListenerImplicit(const FamilyArgs& Params);
void QuicTestStartTwoListeners();
void QuicTestStartTwoListenersSameALPN();
void QuicTestStartListenerExplicit(const FamilyArgs& Params);
void QuicTestCreateConnection();
void QuicTestBindConnectionImplicit(const FamilyArgs& Params);
void QuicTestBindConnectionExplicit(const FamilyArgs& Params);
void QuicTestConnectionCloseFromCallback();
void QuicTestAddrFunctions(const FamilyArgs& Params);

//
// MTU tests
//
void QuicTestMtuSettings();

struct MtuArgs {
    int Family;
    uint8_t DropMode;
    uint8_t RaiseMinimum;
};
void QuicTestMtuDiscovery(const MtuArgs& Params);

//
// Path tests
//
void
QuicTestLocalPathChanges(
    const FamilyArgs& Params
    );

//
// Handshake Tests
//

typedef enum QUIC_TEST_RESUMPTION_MODE {
    QUIC_TEST_RESUMPTION_DISABLED,
    QUIC_TEST_RESUMPTION_ENABLED,
    QUIC_TEST_RESUMPTION_ENABLED_ASYNC,
    QUIC_TEST_RESUMPTION_REJECTED,
    QUIC_TEST_RESUMPTION_REJECTED_BY_SERVER_APP,
    QUIC_TEST_RESUMPTION_REJECTED_BY_SERVER_APP_ASYNC,
} QUIC_TEST_RESUMPTION_MODE;

typedef enum QUIC_TEST_ASYNC_CONFIG_MODE {
    QUIC_TEST_ASYNC_CONFIG_DISABLED,
    QUIC_TEST_ASYNC_CONFIG_ENABLED,
    QUIC_TEST_ASYNC_CONFIG_DELAYED,
} QUIC_TEST_ASYNC_CONFIG_MODE;

void
QuicTestConnect(
    _In_ int Family,
    _In_ bool ServerStatelessRetry,
    _In_ bool ClientUsesOldVersion,
    _In_ bool MultipleALPNs,
    _In_ bool GreaseQuicBitExtension,
    _In_ QUIC_TEST_ASYNC_CONFIG_MODE AsyncConfiguration,
    _In_ bool MultiPacketClientInitial,
    _In_ QUIC_TEST_RESUMPTION_MODE SessionResumption,
    _In_ uint8_t RandomLossPercentage // 0 to 100
    );

struct HandshakeArgs {
    int Family;
    bool ServerStatelessRetry;
    bool MultipleALPNs;
    bool MultiPacketClientInitial;
    bool GreaseQuicBitExtension;
};

void
QuicTestConnect_Connect(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_Resume(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_ResumeAsync(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_ResumeRejection(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_ResumeRejectionByServerApp(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_ResumeRejectionByServerAppAsync(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_OldVersion(
    const HandshakeArgs& Params
    );

struct HandshakeArgs4 {
    int Family;
    bool ServerStatelessRetry;
    bool MultiPacketClientInitial;
    uint8_t RandomLossPercentage;
};

void
QuicTestConnect_RandomLoss(
    const HandshakeArgs4& Params
    );

void
QuicTestConnect_RandomLossResume(
    const HandshakeArgs4& Params
    );

void
QuicTestConnect_RandomLossResumeRejection(
    const HandshakeArgs4& Params
    );

void
QuicTestConnect_AsyncSecurityConfig(
    const HandshakeArgs& Params
    );

void
QuicTestConnect_AsyncSecurityConfig_Delayed(
    const HandshakeArgs& Params
    );

void
QuicTestVersionNegotiation(
    const FamilyArgs& Params
    );

void
QuicTestVersionNegotiationRetry(
    const FamilyArgs& Params
    );

void
QuicTestCompatibleVersionNegotiationRetry(
    const FamilyArgs& Params
    );

struct VersionNegotiationExtArgs {
    int Family;
    bool DisableVNEClient;
    bool DisableVNEServer;
};

void
QuicTestCompatibleVersionNegotiation(
    const VersionNegotiationExtArgs& Params
    );

void
QuicTestCompatibleVersionNegotiationDefaultClient(
    const VersionNegotiationExtArgs& Params
    );

void
QuicTestCompatibleVersionNegotiationDefaultServer(
    const VersionNegotiationExtArgs& Params
    );

void
QuicTestIncompatibleVersionNegotiation(
    const FamilyArgs& Params
    );

void
QuicTestFailedVersionNegotiation(
    const FamilyArgs& Params
    );

struct FeatureSupportArgs {
    int Family;
    bool ServerSupport;
    bool ClientSupport;
};

void
QuicTestReliableResetNegotiation(
    const FeatureSupportArgs& Params
);

void
QuicTestOneWayDelayNegotiation(
    const FeatureSupportArgs& Params
    );

struct CustomCertValidationArgs {
    bool AcceptCert;
    bool AsyncValidation;
};

void
QuicTestCustomServerCertificateValidation(
    const CustomCertValidationArgs& Params
    );

void
QuicTestCustomClientCertificateValidation(
    const CustomCertValidationArgs& Params
    );

struct ClientCertificateArgs {
    int Family;
    bool UseClientCertificate;
};

void
QuicTestConnectClientCertificate(
    const ClientCertificateArgs& Params
    );

void
QuicTestValidAlpnLengths(
    void
    );

void
QuicTestInvalidAlpnLengths(
    void
    );

void
QuicTestLoadBalancedHandshake(
    const FamilyArgs& Params
    );

void
QuicTestClientSharedLocalPort(
    const FamilyArgs& Params
    );

void
QuicTestInterfaceBinding(
    const FamilyArgs& Params
    );

void
QuicTestRetryMemoryLimitConnect(
    const FamilyArgs& Params
    );

struct CibirExtensionParams {
    int Family;
    uint8_t Mode; // server = &1, client = &2
};

void
QuicTestCibirExtension(
    const CibirExtensionParams& Params
    );

void
QuicTestChangeAlpn(
    void
    );

struct HandshakeLossPatternsArgs {
    int Family;
    QUIC_CONGESTION_CONTROL_ALGORITHM CcAlgo;
};

void
QuicTestHandshakeSpecificLossPatterns(
    const HandshakeLossPatternsArgs& Params
    );

struct ShutdownDuringHandshakeArgs {
    bool ClientShutdown;
};

void
QuicTestShutdownDuringHandshake(
    const ShutdownDuringHandshakeArgs& Params
    );

//
// Negative Handshake Tests
//

void
QuicTestConnectUnreachable(
    const FamilyArgs& Params
    );

void
QuicTestConnectInvalidAddress(
    );

void
QuicTestConnectBadAlpn(
    const FamilyArgs& Params
    );

void
QuicTestConnectBadSni(
    const FamilyArgs& Params
    );

void
QuicTestConnectServerRejected(
    const FamilyArgs& Params
    );

void
QuicTestConnectExpiredServerCertificate(
    const QUIC_CREDENTIAL_BLOB& Config
    );

void
QuicTestConnectValidServerCertificate(
    const QUIC_CREDENTIAL_BLOB& Config
    );

void
QuicTestConnectValidClientCertificate(
    const QUIC_CREDENTIAL_BLOB& Config
    );

void
QuicTestConnectExpiredClientCertificate(
    const QUIC_CREDENTIAL_BLOB& Config
    );

void
QuicTestClientBlockedSourcePort(
    const FamilyArgs& Params
    );

struct OddSizeVnTpParams {
    bool TestServer;
    uint8_t VnTpSize;
};

void
QuicTestVNTPOddSize(
    const OddSizeVnTpParams& Params
    );

void
QuicTestVNTPChosenVersionMismatch(
    const bool& TestServer
    );

void
QuicTestVNTPChosenVersionZero(
    const bool& TestServer
    );

void
QuicTestVNTPOtherVersionZero(
    const bool& TestServer
    );

struct ConnectionPoolCreateArgs {
    int Family;
    uint16_t NumberOfConnections;
    bool XdpSupported;
    bool TestCibirSupport;
};

void
QuicTestConnectionPoolCreate(
    const ConnectionPoolCreateArgs& Params
    );

//
// Post Handshake Tests
//

struct RebindPaddingArgs {
    int Family;
    uint16_t Padding;
};

void
QuicTestNatPortRebind_NoPadding(
    const FamilyArgs& Params
    );


void
QuicTestNatPortRebind_WithPadding(
    const RebindPaddingArgs& Params
    );

void
QuicTestNatAddrRebind_WithPadding(
    const RebindPaddingArgs& Params
    );

void
QuicTestNatAddrRebind_NoPadding(
    const FamilyArgs& Params
    );

void
QuicTestNatAddrRebind(
    _In_ int Family,
    _In_ uint16_t KeepAlivePaddingSize,
    _In_ bool RebindDatapathAddr
    );

void
QuicTestPathValidationTimeout(
    const FamilyArgs& Params
    );

void
QuicTestChangeMaxStreamID(
    const FamilyArgs& Params
    );

//
// Application Data Tests
//

void
QuicTestConnectAndPing(
    _In_ int Family,
    _In_ uint64_t Length,
    _In_ uint32_t ConnectionCount,
    _In_ uint32_t StreamCount,
    _In_ uint32_t StreamBurstCount,
    _In_ uint32_t StreamBurstDelayMs,
    _In_ bool ServerStatelessRetry,
    _In_ bool ClientRebind,
    _In_ bool ClientZeroRtt,
    _In_ bool ServerRejectZeroRtt,
    _In_ bool UseSendBuffer,
    _In_ bool UnidirectionalStreams,
    _In_ bool ServerInitiatedStreams,
    _In_ bool FifoScheduling,
    _In_ bool SendUdpToQtipListener
    );

struct Send0RttArgs1 {
    int Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    bool UseSendBuffer;
    bool UnidirectionalStreams;
};

void
QuicTestConnectAndPing_Send0Rtt(
    const Send0RttArgs1& Params
    );

struct Send0RttArgs2 {
    int Family;
    uint64_t Length;
};

void
QuicTestConnectAndPing_Reject0Rtt(
    const Send0RttArgs2& Params
    );

struct SendLargeArgs {
    int Family;
    bool UseSendBuffer;
    bool UseZeroRtt;
};

void
QuicTestConnectAndPing_SendLarge(
    const SendLargeArgs& Params
    );

struct SendIntermittentlyArgs {
    int Family;
    uint64_t Length;
    uint32_t BurstCount;
    uint32_t BurstDelay;
    bool UseSendBuffer;
};

void
QuicTestConnectAndPing_SendIntermittently(
    const SendIntermittentlyArgs& Params
    );

struct SendArgs {
    int Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    bool UseSendBuffer;
    bool UnidirectionalStreams;
    bool ServerInitiatedStreams;
};

void
QuicTestConnectAndPing_Send(
    const SendArgs& Params
    );

//
// Other Data Tests
//

void
QuicTestConnectAndIdle(
    const bool& EnableKeepAlive
    );

void
QuicTestConnectAndIdleForDestCidChange(
    void
    );

void
QuicTestServerDisconnect(
    void
    );

void
QuicTestClientDisconnect(
    const bool& StopListenerFirst
    );

void
QuicTestStatelessResetKey(
    void
    );

void
QuicTestForceKeyUpdate(
    const FamilyArgs& Params
    );

void
QuicTestKeyUpdate(
    const FamilyArgs& Params
    );

struct KeyUpdateRandomLossArgs {
    int Family;
    uint8_t RandomLossPercentage;
};

void
QuicTestKeyUpdateRandomLoss(
    const KeyUpdateRandomLossArgs& Params
    );

typedef enum QUIC_ABORTIVE_TRANSFER_DIRECTION {
    ShutdownBoth,
    ShutdownSend,
    ShutdownReceive
} QUIC_ABORTIVE_TRANSFER_DIRECTION;

typedef union QUIC_ABORTIVE_TRANSFER_FLAGS {
    struct {
        uint32_t DelayStreamCreation : 1;
        uint32_t SendDataOnStream : 1;
        uint32_t ClientShutdown : 1;
        uint32_t DelayClientShutdown : 1;
        uint32_t WaitForStream : 1;
        uint32_t ShutdownDirection : 2;
        uint32_t UnidirectionalStream : 1;
        uint32_t PauseReceive : 1;
        uint32_t PendReceive : 1;
    };
    uint32_t IntValue;
} QUIC_ABORTIVE_TRANSFER_FLAGS;

struct AbortiveArgs {
    int Family;
    QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
};

void
QuicAbortiveTransfers(
    const AbortiveArgs& Params
    );

struct CancelOnLossArgs {
    bool DropPackets;
};

void
QuicCancelOnLossSend(
    const CancelOnLossArgs& Params
    );

struct CidUpdateArgs {
    int Family;
    uint16_t Iterations;
};

void
QuicTestCidUpdate(
    const CidUpdateArgs& Params
    );

typedef enum QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE {
    NoShutdown,
    GracefulShutdown,
    AbortShutdown
} QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE;

typedef enum QUIC_RECEIVE_RESUME_TYPE {
    ReturnConsumedBytes,
    ReturnStatusPending,
    ReturnStatusContinue
} QUIC_RECEIVE_RESUME_TYPE;

struct ReceiveResumeArgs {
    int Family;
    int SendBytes;
    int ConsumeBytes;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    bool PauseFirst;
};

void
QuicTestReceiveResume(
    const ReceiveResumeArgs& Params
    );

struct ReceiveResumeNoDataArgs {
    int Family;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
};

void
QuicTestReceiveResumeNoData(
    const ReceiveResumeNoDataArgs& Params
    );

void
QuicTestAckSendDelay(
    const FamilyArgs& Params
    );

void
QuicTestAbortReceive_Paused(
    );

void
QuicTestAbortReceive_Pending(
    );

void
QuicTestAbortReceive_Incomplete(
    );

void
QuicTestSlowReceive(
    );

void
QuicTestNthAllocFail(
    );

void
QuicTestNthPacketDrop(
    );

void
QuicTestStreamPriority(
    );

void
QuicTestStreamPriorityInfiniteLoop(
    );

void
QuicTestStreamDifferentAbortErrors(
    );

void
QuicTestStreamAbortRecvFinRace(
    );

void
QuicTestStreamAbortConnFlowControl(
    );

void
QuicTestStreamReliableReset(
    );

void
QuicTestStreamReliableResetMultipleSends(
    );

void
QuicTestStreamMultiReceive(
    );

void
QuicTestStreamBlockUnblockConnFlowControl_Unidi(
    );

void
QuicTestStreamBlockUnblockConnFlowControl_Bidi(
    );

void
QuicTestOperationPriority(
    );

void
QuicTestConnectionPriority(
    );

void
QuicTestConnectionStreamStartSendPriority(
    );

void
QuicTestEcn(
    const FamilyArgs& Params
    );

struct AppProvidedBuffersConfig {
    uint32_t StreamStartBuffersNum;
    uint32_t StreamStartBuffersSize;
    uint32_t AdditionalBuffersNum;
    uint32_t AdditionalBuffersSize;
};

void
QuicTestStreamAppProvidedBuffers_ClientSend(
    const AppProvidedBuffersConfig& BufferConfig
    );

void
QuicTestStreamAppProvidedBuffers_ServerSend(
    const AppProvidedBuffersConfig& BufferConfig
    );

void
QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_AbortStream(
    const AppProvidedBuffersConfig& BufferConfig
    );

void
QuicTestStreamAppProvidedBuffersOutOfSpace_ClientSend_ProvideMoreBuffer(
    const AppProvidedBuffersConfig& BufferConfig
    );

void
QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_AbortStream(
    const AppProvidedBuffersConfig& BufferConfig
    );

void
QuicTestStreamAppProvidedBuffersOutOfSpace_ServerSend_ProvideMoreBuffer(
    const AppProvidedBuffersConfig& BufferConfig
    );

//
// QuicDrill tests
//
void
QuicDrillTestVarIntEncoder(
    );

struct DrillInitialPacketCidArgs {
    int Family;
    bool SourceOrDest;
    bool ActualCidLengthValid;
    bool ShortCidLength;
    bool CidLengthFieldValid;
};

void
QuicDrillTestInitialCid(
    const DrillInitialPacketCidArgs& Params
    );

struct DrillInitialPacketTokenArgs {
    int Family;
};

void
QuicDrillTestInitialToken(
    const DrillInitialPacketTokenArgs& Params
    );

void
QuicDrillTestServerVNPacket(
    const DrillInitialPacketTokenArgs& Params
    );

void
QuicDrillTestKeyUpdateDuringHandshake(
    const DrillInitialPacketTokenArgs& Params
    );

//
// Datagram tests
//
struct DatagramNegotiationArgs {
    int Family;
    bool DatagramReceiveEnabled;
};

void
QuicTestDatagramNegotiation(
    const DatagramNegotiationArgs& Params
    );

void
QuicTestDatagramSend(
    const FamilyArgs& Params
    );

void
QuicTestDatagramDrop(
    const FamilyArgs& Params
    );

//
// Storage tests
//
void
QuicTestStorage(
    );

void
QuicTestVersionStorage(
    );

//
// Platform Specific Functions
//

void
LogTestFailure(
    _In_z_ const char *File,
    _In_z_ const char *Function,
    int Line,
    _Printf_format_string_ const char *Format,
    ...
    );

#ifdef __cplusplus
}
#endif

//
// Kernel Mode Driver Interface
//

//
// Name of the driver service for msquictest.sys.
//
#define QUIC_DRIVER_NAME            "msquictest"
#define QUIC_DRIVER_NAME_PRIVATE    "msquictestpriv"

#ifdef _WIN32

//
// {85C2D886-FA01-4DDA-AAED-9A16CC7DA6CE}
//
static const GUID QUIC_TEST_DEVICE_INSTANCE =
{ 0x85c2d886, 0xfa01, 0x4dda,{ 0xaa, 0xed, 0x9a, 0x16, 0xcc, 0x7d, 0xa6, 0xce } };

#ifndef _KERNEL_MODE
#include <winioctl.h>
#endif // _KERNEL_MODE

#define QUIC_CTL_CODE(request, method, access) \
    CTL_CODE(FILE_DEVICE_NETWORK, request, method, access)

#define IoGetFunctionCodeFromCtlCode( ControlCode ) (\
    ( ControlCode >> 2) & 0x00000FFF )

#else // _WIN32

#define QUIC_CTL_CODE(request, method, access) (request)

#endif // _WIN32

//
// IOCTL Interface
//

// Set the test configuration

typedef struct {
    BOOLEAN UseDuoNic;
    char CurrentDirectory[MAX_PATH];
} QUIC_TEST_CONFIGURATION_PARAMS;

#define IOCTL_QUIC_TEST_CONFIGURATION \
    QUIC_CTL_CODE(0, METHOD_BUFFERED, FILE_WRITE_DATA)

// Set the certificate. Must be invoked first.

typedef struct {
    QUIC_CERTIFICATE_HASH ServerCertHash;
    QUIC_CERTIFICATE_HASH ClientCertHash;
} QUIC_RUN_CERTIFICATE_PARAMS;

#define IOCTL_QUIC_SET_CERT_PARAMS \
    QUIC_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CERTIFICATE_PARAMS

// Generic IOCTL for invoking functions 

struct QUIC_RUN_TEST_REQUEST {
    char FunctionName[256];
    uint32_t ParameterSize;
    // Followed by ParameterSize bytes of parameters
};

#define IOCTL_QUIC_RUN_TEST \
    QUIC_CTL_CODE(2, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_TEST_REQUEST
