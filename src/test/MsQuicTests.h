/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Interface for the Platform Independent MsQuic Tests

--*/

#include "msquic.hpp"

//#define QUIC_COMPARTMENT_TESTS 1

extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
extern QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;

#ifdef __cplusplus
extern "C" {
#endif

//
// Test initialization and clean up.
//

void QuicTestInitialize();
void QuicTestUninitialize();

//
// Test abstraction types.
//

typedef enum QUIC_TEST_RESUMPTION_MODE {
    QUIC_TEST_RESUMPTION_DISABLED,
    QUIC_TEST_RESUMPTION_ENABLED,
    QUIC_TEST_RESUMPTION_REJECTED,
} QUIC_TEST_RESUMPTION_MODE;

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

typedef enum QUIC_TEST_ARGS_ABORT_RECEIVE_TYPE {
    QUIC_ABORT_RECEIVE_PAUSED,
    QUIC_ABORT_RECEIVE_PENDING,
    QUIC_ABORT_RECEIVE_INCOMPLETE
} QUIC_TEST_ARGS_ABORT_RECEIVE_TYPE;

typedef struct {
    uint32_t Family;
    uint8_t ServerStatelessRetry;
    uint8_t ClientUsesOldVersion;
    uint8_t MultipleALPNs;
    uint8_t AsyncConfiguration;
    uint8_t MultiPacketClientInitial;
    uint8_t SessionResumption;
    uint8_t RandomLossPercentage;
} QUIC_TEST_ARGS_CONNECT;

typedef struct {
    uint32_t Family;
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
} QUIC_TEST_ARGS_CONNECT_AND_PING;

typedef struct {
    uint32_t Family;
    uint16_t Iterations;
    uint16_t KeyUpdateBytes;
    uint8_t UseKeyUpdateBytes;
    uint8_t ClientKeyUpdate;
    uint8_t ServerKeyUpdate;
} QUIC_TEST_ARGS_KEY_UPDATE;

typedef struct {
    uint32_t Family;
    QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
} QUIC_TEST_ARGS_ABORTIVE_SHUTDOWN;

typedef struct {
    uint32_t Family;
    uint16_t Iterations;
} QUIC_TEST_ARGS_CID_UPDATE;

typedef struct {
    uint32_t Family;
    int SendBytes;
    int ConsumeBytes;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    uint8_t PauseFirst;
} QUIC_TEST_ARGS_RECEIVE_RESUME;

typedef struct {
    uint32_t Family;
    BOOLEAN SourceOrDest;
    BOOLEAN ActualCidLengthValid;
    BOOLEAN ShortCidLength;
    BOOLEAN CidLengthFieldValid;
} QUIC_TEST_ARGS_DRILL_INITIAL_PACKET_CID;

typedef struct {
    uint32_t Family;
    BOOLEAN DatagramReceiveEnabled;
} QUIC_TEST_ARGS_DATAGRAM_NEGOTIATION;

typedef struct {
    uint32_t Family;
    uint16_t Padding;
} QUIC_TEST_ARGS_REBIND;

typedef struct {
    BOOLEAN AcceptCert;
    BOOLEAN AsyncValidation;
} QUIC_TEST_ARGS_CUSTOM_CERT_VALIDATION;

typedef struct {
    uint32_t Family;
    BOOLEAN DisableVNEClient;
    BOOLEAN DisableVNEServer;
} QUIC_TEST_ARGS_VERSION_NEGOTIATION_EXT;

typedef struct {
    uint32_t Family;
    BOOLEAN UseClientCert;
} QUIC_TEST_ARGS_CONNECT_CLIENT_CERT;

typedef struct {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        char PrincipalString[100];
    };
} QUIC_TEST_ARGS_CRED_VALIDATION;

typedef struct {
    uint32_t Family;
    uint8_t RandomLossPercentage;
} QUIC_TEST_ARGS_KEY_UPDATE_RANDOM_LOSS;

typedef struct {
    uint32_t Family;
    uint8_t DropClientProbePackets;
    uint8_t DropServerProbePackets;
    uint8_t RaiseMinimumMtu;
} QUIC_TEST_ARGS_MTU_DISCOVERY;

typedef enum QUIC_TEST_TYPE {
    QUIC_TEST_TYPE_NULL,
    QUIC_TEST_TYPE_BOOLEAN,
    QUIC_TEST_TYPE_FAMILY,
    QUIC_TEST_TYPE_NUMBER,
    QUIC_TEST_TYPE_CERTIFICATE_HASH_STORE,
    QUIC_TEST_TYPE_CONNECT,
    QUIC_TEST_TYPE_CONNECT_AND_PING,
    QUIC_TEST_TYPE_KEY_UPDATE,
    QUIC_TEST_TYPE_ABORTIVE_SHUTDOWN,
    QUIC_TEST_TYPE_CID_UPDATE,
    QUIC_TEST_TYPE_RECEIVE_RESUME,
    QUIC_TEST_TYPE_DRILL_INITIAL_PACKET_CID,
    QUIC_TEST_TYPE_CUSTOM_CERT_VALIDATION,
    QUIC_TEST_TYPE_VERSION_NEGOTIATION_EXT,
    QUIC_TEST_TYPE_CONNECT_CLIENT_CERT,
    QUIC_TEST_TYPE_CRED_VALIDATION,
    QUIC_TEST_TYPE_ABORT_RECEIVE_TYPE,
    QUIC_TEST_TYPE_KEY_UPDATE_RANDOM_LOSS_ARGS,
    QUIC_TEST_TYPE_MTU_DISCOVERY_ARGS,
    QUIC_TEST_TYPE_REBIND_ARGS,

} QUIC_TEST_TYPE;

typedef struct QUIC_TEST_ARGS {
    QUIC_TEST_TYPE Type;
    union {
    BOOLEAN Bool;
    uint32_t Family;
    uint32_t Number;
    QUIC_CERTIFICATE_HASH_STORE CertHashStore;
    QUIC_TEST_ARGS_CONNECT Connect;
    QUIC_TEST_ARGS_CONNECT_AND_PING ConnectAndPing;
    QUIC_TEST_ARGS_KEY_UPDATE KeyUpdate;
    QUIC_TEST_ARGS_ABORTIVE_SHUTDOWN AbortiveShutdown;
    QUIC_TEST_ARGS_CID_UPDATE CidUpdate;
    QUIC_TEST_ARGS_RECEIVE_RESUME ReceiveResume;
    QUIC_TEST_ARGS_DRILL_INITIAL_PACKET_CID Drill;
    QUIC_TEST_ARGS_DATAGRAM_NEGOTIATION DatagramNegotiation;
    QUIC_TEST_ARGS_CUSTOM_CERT_VALIDATION CustomCertValidation;
    QUIC_TEST_ARGS_VERSION_NEGOTIATION_EXT VersionNegotiationExt;
    QUIC_TEST_ARGS_CONNECT_CLIENT_CERT ConnectClientCert;
    QUIC_TEST_ARGS_CRED_VALIDATION CredValidation;
    QUIC_TEST_ARGS_ABORT_RECEIVE_TYPE AbortReceive;
    QUIC_TEST_ARGS_KEY_UPDATE_RANDOM_LOSS KeyUpdateRandomLoss;
    QUIC_TEST_ARGS_MTU_DISCOVERY MtuDiscovery;
    QUIC_TEST_ARGS_REBIND RebindParams;
    };
} QUIC_TEST_ARGS;

//
// List of test functions.
//

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_TEST)(
    _In_ const QUIC_TEST_ARGS* Args
    );

typedef QUIC_TEST *QUIC_TEST_FN;

QUIC_TEST QuicTestValidateApi;
QUIC_TEST QuicTestValidateRegistration;
QUIC_TEST QuicTestValidateConfiguration;
QUIC_TEST QuicTestValidateListener;
QUIC_TEST QuicTestValidateConnection;
QUIC_TEST QuicTestValidateStream;
QUIC_TEST QuicTestGetPerfCounters;
QUIC_TEST QuicTestDesiredVersionSettings;
QUIC_TEST QuicTestValidateParamApi;
QUIC_TEST QuicTestConnectionRejection;
QUIC_TEST QuicTestValidateConnectionEvents;
QUIC_TEST QuicTestValidateStreamEvents;
QUIC_TEST QuicTestCreateListener;
QUIC_TEST QuicTestStartListener;
QUIC_TEST QuicTestStartListenerMultiAlpns;
QUIC_TEST QuicTestStartListenerImplicit;
QUIC_TEST QuicTestStartTwoListeners;
QUIC_TEST QuicTestStartTwoListenersSameALPN;
QUIC_TEST QuicTestStartListenerExplicit;
QUIC_TEST QuicTestCreateConnection;
QUIC_TEST QuicTestBindConnectionImplicit;
QUIC_TEST QuicTestBindConnectionExplicit;
QUIC_TEST QuicTestMtuSettings;
QUIC_TEST QuicTestMtuDiscovery;
QUIC_TEST QuicTestLocalPathChanges;

//
// Handshake Tests
//

void
QuicTestConnect(
    _In_ uint32_t Family,
    _In_ bool ServerStatelessRetry,
    _In_ bool ClientUsesOldVersion,
    _In_ bool MultipleALPNs,
    _In_ bool AsyncConfiguration,
    _In_ bool MultiPacketClientInitial,
    _In_ QUIC_TEST_RESUMPTION_MODE SessionResumption,
    _In_ uint8_t RandomLossPercentage // 0 to 100
    );

QUIC_TEST QuicTestVersionNegotiation;
QUIC_TEST QuicTestVersionNegotiationRetry;
QUIC_TEST QuicTestCompatibleVersionNegotiationRetry;

void
QuicTestCompatibleVersionNegotiation(
    _In_ uint32_t Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    );

void
QuicTestCompatibleVersionNegotiationDefaultClient(
    _In_ uint32_t Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    );

void
QuicTestCompatibleVersionNegotiationDefaultServer(
    _In_ uint32_t Family,
    _In_ bool DisableVNEClient,
    _In_ bool DisableVNEServer
    );

QUIC_TEST QuicTestIncompatibleVersionNegotiation;
QUIC_TEST QuicTestFailedVersionNegotiation;

void
QuicTestCustomCertificateValidation(
    _In_ bool AcceptCert,
    _In_ bool AsyncValidation
    );

void
QuicTestConnectClientCertificate(
    _In_ uint32_t Family,
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

QUIC_TEST QuicTestLoadBalancedHandshake;
QUIC_TEST QuicTestClientSharedLocalPort;
QUIC_TEST QuicTestInterfaceBinding;
QUIC_TEST QuicTestConnectUnreachable;
QUIC_TEST QuicTestConnectBadAlpn;
QUIC_TEST QuicTestConnectBadSni;
QUIC_TEST QuicTestConnectServerRejected;

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

//
// Post Handshake Tests
//

void
QuicTestNatPortRebind(
    _In_ uint32_t Family,
    _In_ uint16_t KeepAlivePaddingSize
    );

void
QuicTestNatAddrRebind(
    _In_ uint32_t Family,
    _In_ uint16_t KeepAlivePaddingSize
    );

QUIC_TEST QuicTestPathValidationTimeout;
QUIC_TEST QuicTestChangeMaxStreamID;

//
// Application Data Tests
//

void
QuicTestConnectAndPing(
    _In_ uint32_t Family,
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
    _In_ uint32_t Family,
    _In_ uint16_t Iterations,
    _In_ uint16_t KeyUpdateBytes,
    _In_ bool UseKeyUpdateBytes,
    _In_ bool ClientKeyUpdate,
    _In_ bool ServerKeyUpdate
    );

void
QuicTestKeyUpdateRandomLoss(
    _In_ uint32_t Family,
    _In_ uint8_t RandomLossPercentage
    );

void
QuicAbortiveTransfers(
    _In_ uint32_t Family,
    _In_ QUIC_ABORTIVE_TRANSFER_FLAGS Flags
    );

void
QuicTestCidUpdate(
    _In_ uint32_t Family,
    _In_ uint16_t Iterations
    );

void
QuicTestReceiveResume(
    _In_ uint32_t Family,
    _In_ int SendBytes,
    _In_ int ConsumeBytes,
    _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType,
    _In_ QUIC_RECEIVE_RESUME_TYPE PauseType,
    _In_ bool PauseFirst
    );

void
QuicTestReceiveResumeNoData(
    _In_ uint32_t Family,
    _In_ QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType
    );

QUIC_TEST QuicTestAckSendDelay;

void
QuicTestAbortReceive(
    _In_ QUIC_TEST_ARGS_ABORT_RECEIVE_TYPE Type
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
QuicTestStreamDifferentAbortErrors(
    );

//
// QuicDrill tests
//
void
QuicDrillTestVarIntEncoder(
    );

void
QuicDrillTestInitialCid(
    _In_ uint32_t Family,
    _In_ bool Source, // or Dest
    _In_ bool ValidActualLength, // or invalid
    _In_ bool Short, // or long
    _In_ bool ValidLengthField // or invalid
    );

QUIC_TEST QuicDrillTestInitialToken;

//
// Datagram tests
//
void
QuicTestDatagramNegotiation(
    _In_ uint32_t Family,
    _In_ bool DatagramReceiveEnabled
    );

QUIC_TEST QuicTestDatagramSend;

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

#define IOCTL_QUIC_RUN_CONNECT \
    QUIC_CTL_CODE(16, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_CONNECT

#define IOCTL_QUIC_RUN_CONNECT_AND_PING \
    QUIC_CTL_CODE(17, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_CONNECT_AND_PING

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

#define IOCTL_QUIC_RUN_KEY_UPDATE \
    QUIC_CTL_CODE(28, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_KEY_UPDATE

#define IOCTL_QUIC_RUN_VALIDATE_API \
    QUIC_CTL_CODE(29, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED \
    QUIC_CTL_CODE(30, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN \
    QUIC_CTL_CODE(31, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_ABORTIVE_SHUTDOWN

#define IOCTL_QUIC_RUN_CID_UPDATE \
    QUIC_CTL_CODE(32, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_CID_UPDATE

#define IOCTL_QUIC_RUN_RECEIVE_RESUME \
    QUIC_CTL_CODE(33, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_RECEIVE_RESUME

#define IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA \
    QUIC_CTL_CODE(34, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_RECEIVE_RESUME

#define IOCTL_QUIC_RUN_DRILL_ENCODE_VAR_INT \
    QUIC_CTL_CODE(35, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_CID \
    QUIC_CTL_CODE(36, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_DRILL_INITIAL_PACKET_CID

#define IOCTL_QUIC_RUN_DRILL_INITIAL_PACKET_TOKEN \
    QUIC_CTL_CODE(37, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_START_LISTENER_MULTI_ALPN \
    QUIC_CTL_CODE(38, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_TEST_ARGS_DATAGRAM_NEGOTIATION \
    QUIC_CTL_CODE(39, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_DATAGRAM_NEGOTIATION

#define IOCTL_QUIC_RUN_DATAGRAM_SEND \
    QUIC_CTL_CODE(40, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_NAT_PORT_REBIND \
    QUIC_CTL_CODE(41, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_REBIND

#define IOCTL_QUIC_RUN_NAT_ADDR_REBIND \
    QUIC_CTL_CODE(42, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_REBIND

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

#define IOCTL_QUIC_TEST_ARGS_CUSTOM_CERT_VALIDATION \
    QUIC_CTL_CODE(47, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_CUSTOM_CERT_VALIDATION

#define IOCTL_QUIC_RUN_VERSION_NEGOTIATION_RETRY \
    QUIC_CTL_CODE(48, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_RETRY \
    QUIC_CTL_CODE(49, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(50, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_VERSION_NEGOTIATION_EXT

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_SERVER \
    QUIC_CTL_CODE(51, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_VERSION_NEGOTIATION_EXT

#define IOCTL_QUIC_RUN_COMPATIBLE_VERSION_NEGOTIATION_DEFAULT_CLIENT \
    QUIC_CTL_CODE(52, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_VERSION_NEGOTIATION_EXT

#define IOCTL_QUIC_RUN_INCOMPATIBLE_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(53, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_FAILED_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(54, METHOD_BUFFERED, FILE_WRITE_DATA)
    // int - Family

#define IOCTL_QUIC_RUN_VALIDATE_DESIRED_VERSIONS_SETTINGS \
    QUIC_CTL_CODE(55, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_TEST_ARGS_CONNECT_CLIENT_CERT \
    QUIC_CTL_CODE(56, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_TEST_ARGS_CONNECT_CLIENT_CERT

#define IOCTL_QUIC_RUN_VALID_ALPN_LENGTHS \
    QUIC_CTL_CODE(57, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_INVALID_ALPN_LENGTHS \
    QUIC_CTL_CODE(58, METHOD_BUFFERED, FILE_WRITE_DATA)

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

#define IOCTL_QUIC_RUN_KEY_UPDATE_RANDOM_LOSS \
    QUIC_CTL_CODE(64, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_SLOW_RECEIVE \
    QUIC_CTL_CODE(65, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_NTH_ALLOC_FAIL \
    QUIC_CTL_CODE(66, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_MTU_SETTINGS \
    QUIC_CTL_CODE(67, METHOD_BUFFERED, FILE_WRITE_DATA)

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

#define QUIC_MAX_IOCTL_FUNC_CODE 76
