/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Interface for the Platform Independent MsQuic Tests

--*/

#include "msquic.hpp"
#include "quic_driver_helpers.h"

//#define QUIC_COMPARTMENT_TESTS 1

extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfig;
extern QUIC_CREDENTIAL_CONFIG ServerSelfSignedCredConfigClientAuth;
extern QUIC_CREDENTIAL_CONFIG ClientCertCredConfig;

//
// Name of the driver service for msquictest.sys.
//
#define QUIC_DRIVER_NAME            "msquictest"
#define QUIC_DRIVER_NAME_PRIVATE    "msquictestpriv"

//
// Test initialization and clean up.
//

void QuicTestInitialize();
void QuicTestUninitialize();

//
// Failure abstraction interface.
//
void
LogTestFailure(
    _In_z_ const char *File,
    _In_z_ const char *Function,
    int Line,
    _Printf_format_string_ const char *Format,
    ...
    );

//
// Test functions.
//

typedef void (QUIC_TEST)(_In_ const struct QUIC_TEST_ARGS* Args);
typedef QUIC_TEST *QUIC_TEST_FN;

#define QUIC_TEST_START() \
    const uint32_t QUIC_CTL_START = __LINE__; \
    struct QuicTests { \
        static QUIC_TEST_FN List[256]; \
        static uint32_t Count; \
        QuicTests(QUIC_TEST_FN test) { List[Count++] = test; } \
    }

#if QUIC_TEST_CREATE
#define QUIC_TEST_NEW(test) \
    QUIC_TEST QuicTest##test; \
    const uint32_t IOCTL_QUIC_##test = \
        QUIC_CTL_CODE(__LINE__ - QUIC_CTL_START, METHOD_BUFFERED, FILE_WRITE_DATA); \
    QuicTests Add##test(QuicTest##test)
#else
#define QUIC_TEST_NEW(test)
#endif

#define QUIC_TEST_END() \
    const uint32_t QUIC_CTL_COUNT = __LINE__ - 1 - QUIC_CTL_START; \
    CXPLAT_STATIC_ASSERT(QUIC_CTL_COUNT <= ARRAYSIZE(QuicTests::List), "Allocate more space for QuicTests!")

//
// Declares all the test functions.
//   DO NOT ADD EMPTY NEW LINES!
//
QUIC_TEST_START();
QUIC_TEST_NEW(ValidateApi);
QUIC_TEST_NEW(ValidateRegistration);
QUIC_TEST_NEW(ValidateConfiguration);
QUIC_TEST_NEW(ValidateListener);
QUIC_TEST_NEW(ValidateConnection);
QUIC_TEST_NEW(ValidateStream);
QUIC_TEST_NEW(GetPerfCounters);
QUIC_TEST_NEW(DesiredVersionSettings);
QUIC_TEST_NEW(ValidateParamApi);
QUIC_TEST_NEW(ConnectionRejection);
QUIC_TEST_NEW(ValidateConnectionEvents);
QUIC_TEST_NEW(ValidateStreamEvents);
QUIC_TEST_NEW(CreateListener);
QUIC_TEST_NEW(StartListener);
QUIC_TEST_NEW(StartListenerMultiAlpns);
QUIC_TEST_NEW(StartListenerImplicit);
QUIC_TEST_NEW(StartTwoListeners);
QUIC_TEST_NEW(StartTwoListenersSameALPN);
QUIC_TEST_NEW(StartListenerExplicit);
QUIC_TEST_NEW(CreateConnection);
QUIC_TEST_NEW(BindConnectionImplicit);
QUIC_TEST_NEW(BindConnectionExplicit);
QUIC_TEST_NEW(MtuSettings);
QUIC_TEST_NEW(MtuDiscovery);
QUIC_TEST_NEW(LocalPathChanges);
QUIC_TEST_NEW(Connect);
QUIC_TEST_NEW(VersionNegotiation);
QUIC_TEST_NEW(VersionNegotiationRetry);
QUIC_TEST_NEW(CompatibleVersionNegotiationRetry);
QUIC_TEST_NEW(CompatibleVersionNegotiation);
QUIC_TEST_NEW(CompatibleVersionNegotiationDefaultClient);
QUIC_TEST_NEW(CompatibleVersionNegotiationDefaultServer);
QUIC_TEST_NEW(IncompatibleVersionNegotiation);
QUIC_TEST_NEW(FailedVersionNegotiation);
QUIC_TEST_NEW(CustomCertificateValidation);
QUIC_TEST_NEW(ConnectClientCertificate);
QUIC_TEST_NEW(ValidAlpnLengths);
QUIC_TEST_NEW(InvalidAlpnLengths);
QUIC_TEST_NEW(LoadBalancedHandshake);
QUIC_TEST_NEW(ClientSharedLocalPort);
QUIC_TEST_NEW(InterfaceBinding);
QUIC_TEST_NEW(ConnectUnreachable);
QUIC_TEST_NEW(ConnectBadAlpn);
QUIC_TEST_NEW(ConnectBadSni);
QUIC_TEST_NEW(ConnectServerRejected);
QUIC_TEST_NEW(ConnectExpiredServerCertificate);
QUIC_TEST_NEW(ConnectValidServerCertificate);
QUIC_TEST_NEW(ConnectValidClientCertificate);
QUIC_TEST_NEW(ConnectExpiredClientCertificate);
QUIC_TEST_NEW(NatPortRebind);
QUIC_TEST_NEW(NatAddrRebind);
QUIC_TEST_NEW(PathValidationTimeout);
QUIC_TEST_NEW(ChangeMaxStreamID);
QUIC_TEST_NEW(ConnectAndPing);
QUIC_TEST_NEW(ConnectAndIdle);
QUIC_TEST_NEW(ServerDisconnect);
QUIC_TEST_NEW(ClientDisconnect);
QUIC_TEST_NEW(KeyUpdate);
QUIC_TEST_NEW(KeyUpdateRandomLoss);
QUIC_TEST_NEW(AbortiveTransfers);
QUIC_TEST_NEW(CidUpdate);
QUIC_TEST_NEW(ReceiveResume);
QUIC_TEST_NEW(ReceiveResumeNoData);
QUIC_TEST_NEW(AckSendDelay);
QUIC_TEST_NEW(AbortReceive);
QUIC_TEST_NEW(SlowReceive);
QUIC_TEST_NEW(NthAllocFail);
QUIC_TEST_NEW(StreamPriority);
QUIC_TEST_NEW(StreamDifferentAbortErrors);
QUIC_TEST_NEW(DrillVarIntEncoder);
QUIC_TEST_NEW(DrillInitialCid);
QUIC_TEST_NEW(DrillInitialToken);
QUIC_TEST_NEW(DatagramNegotiation);
QUIC_TEST_NEW(DatagramSend);
QUIC_TEST_END();

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
    uint32_t SendBytes;
    uint32_t ConsumeBytes;
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
    QUIC_TEST_TYPE_DATAGRAM_NEGOTIATION,
    QUIC_TEST_TYPE_CUSTOM_CERT_VALIDATION,
    QUIC_TEST_TYPE_VERSION_NEGOTIATION_EXT,
    QUIC_TEST_TYPE_CONNECT_CLIENT_CERT,
    QUIC_TEST_TYPE_CRED_VALIDATION,
    QUIC_TEST_TYPE_ABORT_RECEIVE_TYPE,
    QUIC_TEST_TYPE_KEY_UPDATE_RANDOM_LOSS,
    QUIC_TEST_TYPE_MTU_DISCOVERY,
    QUIC_TEST_TYPE_REBIND,

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
    QUIC_TEST_ARGS_REBIND Rebind;
    };
} QUIC_TEST_ARGS;
