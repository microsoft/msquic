/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Interface for the Platform Independent MsQuic Tests

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES

#include "msquic.hpp"

//#define QUIC_COMPARTMENT_TESTS 1

extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
extern QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;

#ifdef __cplusplus
extern "C" {
#endif

void QuicTestInitialize();
void QuicTestUninitialize();

//
// Parameter Validation Tests
//

void QuicTestValidateApi();
void QuicTestValidateRegistration();
void QuicTestValidateConfiguration();
void QuicTestValidateListener();
void QuicTestValidateConnection();
void QuicTestValidateStream(bool Connect);
void QuicTestGetPerfCounters();
void QuicTestVersionSettings();
void QuicTestValidateParamApi();
void QuicTestCredentialLoad(const QUIC_CREDENTIAL_CONFIG* Config);

//
// Ownership tests
//
void QuicTestRegistrationShutdownBeforeConnOpen();
void QuicTestRegistrationShutdownAfterConnOpen();
void QuicTestRegistrationShutdownAfterConnOpenBeforeStart();
void QuicTestRegistrationShutdownAfterConnOpenAndStart();

//
// Rejection Tests
//
void QuicTestConnectionRejection(bool RejectByClosing);

//
// Event Validation Tests
//

void QuicTestValidateConnectionEvents(uint32_t Test);
void QuicTestValidateStreamEvents(uint32_t Test);

//
// Basic Functionality Tests
//

void QuicTestCreateListener();
void QuicTestStartListener();
void QuicTestStartListenerMultiAlpns();
void QuicTestStartListenerImplicit(_In_ int Family);
void QuicTestStartTwoListeners();
void QuicTestStartTwoListenersSameALPN();
void QuicTestStartListenerExplicit(_In_ int Family);
void QuicTestCreateConnection();
void QuicTestBindConnectionImplicit(_In_ int Family);
void QuicTestBindConnectionExplicit(_In_ int Family);

//
// MTU tests
//
void QuicTestMtuSettings();
void
QuicTestMtuDiscovery(
    _In_ int Family,
    _In_ BOOLEAN DropClientProbePackets,
    _In_ BOOLEAN DropServerProbePackets,
    _In_ BOOLEAN RaiseMinimumMtu
    );

//
// Path tests
//
void
QuicTestLocalPathChanges(
    _In_ int Family
    );

//
// Handshake Tests
//

typedef enum QUIC_TEST_RESUMPTION_MODE {
    QUIC_TEST_RESUMPTION_DISABLED,
    QUIC_TEST_RESUMPTION_ENABLED,
    QUIC_TEST_RESUMPTION_REJECTED,
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
    _In_ QUIC_TEST_ASYNC_CONFIG_MODE AsyncConfiguration,
    _In_ bool MultiPacketClientInitial,
    _In_ QUIC_TEST_RESUMPTION_MODE SessionResumption,
    _In_ uint8_t RandomLossPercentage // 0 to 100
    );

void
QuicTestVersionNegotiation(
    _In_ int Family
    );

void
QuicTestVersionNegotiationRetry(
    _In_ int Family
    );

void
QuicTestCompatibleVersionNegotiationRetry(
    _In_ int Family
    );

void
QuicTestCompatibleVersionNegotiation(
    _In_ int Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    );

void
QuicTestCompatibleVersionNegotiationDefaultClient(
    _In_ int Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    );

void
QuicTestCompatibleVersionNegotiationDefaultServer(
    _In_ int Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    );

void
QuicTestIncompatibleVersionNegotiation(
    _In_ int Family
    );

void
QuicTestFailedVersionNegotiation(
    _In_ int Family
    );

void
QuicTestCustomCertificateValidation(
    _In_ bool AcceptCert,
    _In_ bool AsyncValidation
    );

void
QuicTestConnectClientCertificate(
    _In_ int Family,
    _In_ bool UseClientCertificate
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
    _In_ int Family
    );

void
QuicTestClientSharedLocalPort(
    _In_ int Family
    );

void
QuicTestInterfaceBinding(
    _In_ int Family
    );

void
QuicTestCibirExtension(
    _In_ int Family,
    _In_ uint8_t Mode // server = &1, client = &2
    );

void
QuicTestResumptionAcrossVersions();

//
// Negative Handshake Tests
//

void
QuicTestConnectUnreachable(
    _In_ int Family
    );

void
QuicTestConnectInvalidAddress(
    );

void
QuicTestConnectBadAlpn(
    _In_ int Family
    );

void
QuicTestConnectBadSni(
    _In_ int Family
    );

void
QuicTestConnectServerRejected(
    _In_ int Family
    );

void
QuicTestConnectExpiredServerCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    );

void
QuicTestConnectValidServerCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    );

void
QuicTestConnectValidClientCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    );

void
QuicTestConnectExpiredClientCertificate(
    _In_ const QUIC_CREDENTIAL_CONFIG* Config
    );

void
QuicTestClientBlockedSourcePort(
    _In_ int Family
    );

//
// Post Handshake Tests
//

void
QuicTestNatPortRebind(
    _In_ int Family,
    _In_ uint16_t KeepAlivePaddingSize
    );

void
QuicTestNatAddrRebind(
    _In_ int Family,
    _In_ uint16_t KeepAlivePaddingSize
    );

void
QuicTestPathValidationTimeout(
    _In_ int Family
    );

void
QuicTestChangeMaxStreamID(
    _In_ int Family
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
    _In_ bool FifoScheduling
    );

//
// Other Data Tests
//

void
QuicTestConnectAndIdle(
    _In_ bool EnableKeepAlive
    );

void
QuicTestServerDisconnect(
    void
    );

void
QuicTestClientDisconnect(
    bool StopListenerFirst
    );

void
QuicTestKeyUpdate(
    _In_ int Family,
    _In_ uint16_t Iterations,
    _In_ uint16_t KeyUpdateBytes,
    _In_ bool UseKeyUpdateBytes,
    _In_ bool ClientKeyUpdate,
    _In_ bool ServerKeyUpdate
    );

void
QuicTestKeyUpdateRandomLoss(
    _In_ int Family,
    _In_ uint8_t RandomLossPercentage
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

void
QuicAbortiveTransfers(
    _In_ int Family,
    _In_ QUIC_ABORTIVE_TRANSFER_FLAGS Flags
    );

void
QuicTestCidUpdate(
    _In_ int Family,
    _In_ uint16_t Iterations
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

void
QuicTestReceiveResume(
    _In_ int Family,
    _In_ int SendBytes,
    _In_ int ConsumeBytes,
    _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType,
    _In_ QUIC_RECEIVE_RESUME_TYPE PauseType,
    _In_ bool PauseFirst
    );

void
QuicTestReceiveResumeNoData(
    _In_ int Family,
    _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType
    );

void
QuicTestAckSendDelay(
    _In_ int Family
    );

typedef enum QUIC_ABORT_RECEIVE_TYPE {
    QUIC_ABORT_RECEIVE_PAUSED,
    QUIC_ABORT_RECEIVE_PENDING,
    QUIC_ABORT_RECEIVE_INCOMPLETE
} QUIC_ABORT_RECEIVE_TYPE;

void
QuicTestAbortReceive(
    _In_ QUIC_ABORT_RECEIVE_TYPE Type
    );

void
QuicTestSlowReceive(
    );

void
QuicTestNthAllocFail(
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

//
// QuicDrill tests
//
void
QuicDrillTestVarIntEncoder(
    );

void
QuicDrillTestInitialCid(
    _In_ int Family,
    _In_ bool Source, // or Dest
    _In_ bool ValidActualLength, // or invalid
    _In_ bool Short, // or long
    _In_ bool ValidLengthField // or invalid
    );

void
QuicDrillTestInitialToken(
    _In_ int Family
    );

//
// Datagram tests
//
void
QuicTestDatagramNegotiation(
    _In_ int Family,
    _In_ bool DatagramReceiveEnabled
    );

void
QuicTestDatagramSend(
    _In_ int Family
    );

//
// Storage tests
//
void
QuicTestStorage(
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

typedef struct {
    QUIC_CERTIFICATE_HASH ServerCertHash;
    QUIC_CERTIFICATE_HASH ClientCertHash;
} QUIC_RUN_CERTIFICATE_PARAMS;

#define IOCTL_QUIC_SET_CERT_PARAMS \
    QUIC_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CERTIFICATE_PARAMS

#define IOCTL_QUIC_RUN_VALIDATE_REGISTRATION \
    QUIC_CTL_CODE(2, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_CONFIGURATION \
    QUIC_CTL_CODE(3, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_LISTENER \
    QUIC_CTL_CODE(4, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_CONNECTION \
    QUIC_CTL_CODE(5, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_STREAM \
    QUIC_CTL_CODE(6, METHOD_BUFFERED, FILE_WRITE_DATA)
    // uint8_t - Connect

#define IOCTL_QUIC_RUN_CREATE_LISTENER \
    QUIC_CTL_CODE(7, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_LISTENER \
    QUIC_CTL_CODE(8, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT \
    QUIC_CTL_CODE(9, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_START_TWO_LISTENERS \
    QUIC_CTL_CODE(10, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN \
    QUIC_CTL_CODE(11, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT \
    QUIC_CTL_CODE(12, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_CREATE_CONNECTION \
    QUIC_CTL_CODE(13, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT \
    QUIC_CTL_CODE(14, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT \
    QUIC_CTL_CODE(15, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#pragma pack(push)
#pragma pack(1)

typedef struct {
    int Family;
    uint8_t ServerStatelessRetry;
    uint8_t ClientUsesOldVersion;
    uint8_t MultipleALPNs;
    uint8_t AsyncConfiguration;
    uint8_t MultiPacketClientInitial;
    uint8_t SessionResumption;
    uint8_t RandomLossPercentage;
} QUIC_RUN_CONNECT_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_CONNECT \
    QUIC_CTL_CODE(16, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CONNECT_PARAMS

#pragma pack(push)
#pragma pack(1)

typedef struct {
    int Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    uint32_t StreamBurstCount;
    uint32_t StreamBurstDelayMs;
    uint8_t ServerStatelessRetry;
    uint8_t ClientRebind;
    uint8_t ClientZeroRtt;
    uint8_t ServerRejectZeroRtt;
    uint8_t UseSendBuffer;
    uint8_t UnidirectionalStreams;
    uint8_t ServerInitiatedStreams;
    uint8_t FifoScheduling;
} QUIC_RUN_CONNECT_AND_PING_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_CONNECT_AND_PING \
    QUIC_CTL_CODE(17, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CONNECT_AND_PING_PARAMS

#define IOCTL_QUIC_RUN_CONNECT_AND_IDLE \
    QUIC_CTL_CODE(18, METHOD_BUFFERED, FILE_WRITE_DATA)
    // uint8_t - EnableKeepAlive

// 19 - Deprecated

#define IOCTL_QUIC_RUN_CONNECT_UNREACHABLE \
    QUIC_CTL_CODE(20, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_CONNECT_BAD_ALPN \
    QUIC_CTL_CODE(21, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_CONNECT_BAD_SNI \
    QUIC_CTL_CODE(22, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_SERVER_DISCONNECT \
    QUIC_CTL_CODE(23, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CLIENT_DISCONNECT \
    QUIC_CTL_CODE(24, METHOD_BUFFERED, FILE_WRITE_DATA)
    // uint8_t - StopListenerFirst

#define IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS \
    QUIC_CTL_CODE(25, METHOD_BUFFERED, FILE_WRITE_DATA)
    // uint32_t - Test

#define IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS \
    QUIC_CTL_CODE(26, METHOD_BUFFERED, FILE_WRITE_DATA)
    // uint32_t - Test

#define IOCTL_QUIC_RUN_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(27, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#pragma pack(push)
#pragma pack(1)

typedef struct {
    int Family;
    uint16_t Iterations;
    uint16_t KeyUpdateBytes;
    uint8_t UseKeyUpdateBytes;
    uint8_t ClientKeyUpdate;
    uint8_t ServerKeyUpdate;
} QUIC_RUN_KEY_UPDATE_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_KEY_UPDATE \
    QUIC_CTL_CODE(28, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_KEY_UPDATE_PARAMS

#define IOCTL_QUIC_RUN_VALIDATE_API \
    QUIC_CTL_CODE(29, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED \
    QUIC_CTL_CODE(30, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#pragma pack(push)
#pragma pack(1)

typedef struct {
    int Family;
    QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
} QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN \
    QUIC_CTL_CODE(31, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS

#pragma pack(push)
#pragma pack(1)

typedef struct {
    int Family;
    uint16_t Iterations;
} QUIC_RUN_CID_UPDATE_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_CID_UPDATE \
    QUIC_CTL_CODE(32, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CID_UPDATE_PARAMS

typedef struct {
    int Family;
    int SendBytes;
    int ConsumeBytes;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    uint8_t PauseFirst;
} QUIC_RUN_RECEIVE_RESUME_PARAMS;

#define IOCTL_QUIC_RUN_RECEIVE_RESUME \
    QUIC_CTL_CODE(33, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_RECEIVE_RESUME_PARAMS

#define IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA \
    QUIC_CTL_CODE(34, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_RECEIVE_RESUME_PARAMS

#define IOCTL_QUIC_RUN_DRILL_ENCODE_VAR_INT \
    QUIC_CTL_CODE(35, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct {
    int Family;
    BOOLEAN SourceOrDest;
    BOOLEAN ActualCidLengthValid;
    BOOLEAN ShortCidLength;
    BOOLEAN CidLengthFieldValid;
} QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS;

#define IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_CID \
    QUIC_CTL_CODE(36, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_DRILL_INITIAL_PACKET_CID_PARAMS

#define IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN \
    QUIC_CTL_CODE(37, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_START_LISTENER_MULTI_ALPN \
    QUIC_CTL_CODE(38, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct {
    int Family;
    BOOLEAN DatagramReceiveEnabled;
} QUIC_RUN_DATAGRAM_NEGOTIATION;

#define IOCTL_QUIC_RUN_DATAGRAM_NEGOTIATION \
    QUIC_CTL_CODE(39, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_DATAGRAM_NEGOTIATION

#define IOCTL_QUIC_RUN_DATAGRAM_SEND \
    QUIC_CTL_CODE(40, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

typedef struct {
    int Family;
    uint16_t Padding;
} QUIC_RUN_REBIND_PARAMS;

#define IOCTL_QUIC_RUN_NAT_PORT_REBIND \
    QUIC_CTL_CODE(41, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_REBIND_PARAMS

#define IOCTL_QUIC_RUN_NAT_ADDR_REBIND \
    QUIC_CTL_CODE(42, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_REBIND_PARAMS

#define IOCTL_QUIC_RUN_CHANGE_MAX_STREAM_ID \
    QUIC_CTL_CODE(43, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_PATH_VALIDATION_TIMEOUT \
    QUIC_CTL_CODE(44, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_VALIDATE_GET_PERF_COUNTERS \
    QUIC_CTL_CODE(45, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_ACK_SEND_DELAY \
    QUIC_CTL_CODE(46, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

typedef struct {
    BOOLEAN AcceptCert;
    BOOLEAN AsyncValidation;
} QUIC_RUN_CUSTOM_CERT_VALIDATION;

#define IOCTL_QUIC_RUN_CUSTOM_CERT_VALIDATION \
    QUIC_CTL_CODE(47, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CUSTOM_CERT_VALIDATION

#define IOCTL_QUIC_RUN_VERSION_NEGOTIATION_RETRY \
    QUIC_CTL_CODE(48, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_RETRY \
    QUIC_CTL_CODE(49, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

typedef struct {
    int Family;
    BOOLEAN DisableVNEClient;
    BOOLEAN DisableVNEServer;
} QUIC_RUN_VERSION_NEGOTIATION_EXT;

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(50, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_VERSION_NEGOTIATION_EXT

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_SERVER \
    QUIC_CTL_CODE(51, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_VERSION_NEGOTIATION_EXT

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_CLIENT \
    QUIC_CTL_CODE(52, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_VERSION_NEGOTIATION_EXT

#define IOCTL_QUIC_RUN_INCOMPATIBLE_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(53, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_FAILED_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(54, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_VALIDATE_VERSION_SETTINGS_SETTINGS \
    QUIC_CTL_CODE(55, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct {
    int Family;
    BOOLEAN UseClientCert;
} QUIC_RUN_CONNECT_CLIENT_CERT;

#define IOCTL_QUIC_RUN_CONNECT_CLIENT_CERT \
    QUIC_CTL_CODE(56, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CONNECT_CLIENT_CERT

#define IOCTL_QUIC_RUN_VALID_ALPN_LENGTHS \
    QUIC_CTL_CODE(57, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_INVALID_ALPN_LENGTHS \
    QUIC_CTL_CODE(58, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
        QUIC_CERTIFICATE_PKCS12 Pkcs12;
        char PrincipalString[100];
    };
} QUIC_RUN_CRED_VALIDATION;

#define IOCTL_QUIC_RUN_EXPIRED_SERVER_CERT \
    QUIC_CTL_CODE(59, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALID_SERVER_CERT \
    QUIC_CTL_CODE(60, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALID_CLIENT_CERT \
    QUIC_CTL_CODE(61, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_EXPIRED_CLIENT_CERT \
    QUIC_CTL_CODE(62, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_ABORT_RECEIVE \
    QUIC_CTL_CODE(63, METHOD_BUFFERED, FILE_WRITE_DATA)
    // BOOLEAN

#pragma pack(push)
#pragma pack(1)

typedef struct {
    int Family;
    uint8_t RandomLossPercentage;
} QUIC_RUN_KEY_UPDATE_RANDOM_LOSS_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_KEY_UPDATE_RANDOM_LOSS \
    QUIC_CTL_CODE(64, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_SLOW_RECEIVE \
    QUIC_CTL_CODE(65, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_NTH_ALLOC_FAIL \
    QUIC_CTL_CODE(66, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_MTU_SETTINGS \
    QUIC_CTL_CODE(67, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct {
    int Family;
    uint8_t DropClientProbePackets;
    uint8_t DropServerProbePackets;
    uint8_t RaiseMinimumMtu;
} QUIC_RUN_MTU_DISCOVERY_PARAMS;

#define IOCTL_QUIC_RUN_MTU_DISCOVERY \
    QUIC_CTL_CODE(68, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_LOAD_BALANCED_HANDSHAKE \
    QUIC_CTL_CODE(69, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_CLIENT_SHARED_LOCAL_PORT \
    QUIC_CTL_CODE(70, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_VALIDATE_PARAM_API \
    QUIC_CTL_CODE(71, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_STREAM_PRIORITY \
    QUIC_CTL_CODE(72, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CLIENT_LOCAL_PATH_CHANGES \
    QUIC_CTL_CODE(73, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_STREAM_DIFFERENT_ABORT_ERRORS \
    QUIC_CTL_CODE(74, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CONNECTION_REJECTION \
    QUIC_CTL_CODE(75, METHOD_BUFFERED, FILE_WRITE_DATA)
    // bool - RejectByClosing

#define IOCTL_QUIC_RUN_INTERFACE_BINDING \
    QUIC_CTL_CODE(76, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_CONNECT_INVALID_ADDRESS \
    QUIC_CTL_CODE(77, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_STREAM_ABORT_RECV_FIN_RACE \
    QUIC_CTL_CODE(78, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_STREAM_ABORT_CONN_FLOW_CONTROL \
    QUIC_CTL_CODE(79, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN__REG_SHUTDOWN_BEFORE_OPEN \
    QUIC_CTL_CODE(80, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN \
    QUIC_CTL_CODE(81, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN_BEFORE_START \
    QUIC_CTL_CODE(82, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_REG_SHUTDOWN_AFTER_OPEN_AND_START \
    QUIC_CTL_CODE(83, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CRED_TYPE_VALIDATION \
    QUIC_CTL_CODE(84, METHOD_BUFFERED, FILE_WRITE_DATA)

typedef struct {
    int Family;
    uint8_t Mode;
} QUIC_RUN_CIBIR_EXTENSION;

#define IOCTL_QUIC_RUN_CIBIR_EXTENSION \
    QUIC_CTL_CODE(85, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CIBIR_EXTENSION

#define IOCTL_QUIC_RUN_STREAM_PRIORITY_INFINITE_LOOP \
    QUIC_CTL_CODE(86, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_RESUMPTION_ACROSS_VERSIONS \
    QUIC_CTL_CODE(87, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CLIENT_BLOCKED_SOURCE_PORT \
    QUIC_CTL_CODE(88, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_STORAGE \
    QUIC_CTL_CODE(89, METHOD_BUFFERED, FILE_WRITE_DATA)

#define QUIC_MAX_IOCTL_FUNC_CODE 89
