/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Interface for the Platform Independent MsQuic Tests

--*/

#include <msquic.h>

//#define QUIC_NO_ENCRYPTION 1
//#define QUIC_COMPARTMENT_TESTS 1

extern QUIC_API_V1* MsQuic;
extern HQUIC Registration;
extern QUIC_SEC_CONFIG* SecurityConfig;

#ifdef __cplusplus
extern "C" {
#endif

void QuicTestInitialize();
void QuicTestCleanup();

//
// Parameter Validation Tests
//

void QuicTestValidateApi();
void QuicTestValidateRegistration();
void QuicTestValidateSession();
void QuicTestValidateListener();
void QuicTestValidateConnection();
void QuicTestValidateStream(bool Connect);
void QuicTestValidateServerSecConfig(bool KernelMode, void* CertContext, void* CertHashStore, char* Principal);

//
// Event Validation Tests
//
void QuicTestValidateConnectionEvents();
void QuicTestValidateStreamEvents();

//
// Basic Functionality Tests
//

void QuicTestCreateListener();
void QuicTestStartListener();
void QuicTestStartListenerImplicit(_In_ int Family);
void QuicTestStartTwoListeners();
void QuicTestStartTwoListenersSameALPN();
void QuicTestStartListenerExplicit(_In_ int Family);
void QuicTestCreateConnection();
void QuicTestBindConnectionImplicit(_In_ int Family);
void QuicTestBindConnectionExplicit(_In_ int Family);

//
// Handshake Tests
//

void
QuicTestConnect(
    _In_ int Family,
    _In_ bool ServerStatelessRetry,
    _In_ bool ClientUsesOldVersion,
    _In_ bool ClientRebind,
    _In_ bool ChangeMaxStreamID,
    _In_ bool MultipleALPNs,
    _In_ bool AsyncSecConfig,
    _In_ bool MultiPacketClientInitial
    );

void
QuicTestVersionNegotiation(
    _In_ int Family
    );

//
// Negative Handshake Tests
//

void
QuicTestConnectUnreachable(
    _In_ int Family
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
    _In_ bool ServerInitiatedStreams
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

typedef enum _QUIC_ABORTIVE_TRANSFER_DIRECTION {
    ShutdownBoth,
    ShutdownSend,
    ShutdownReceive
} QUIC_ABORTIVE_TRANSFER_DIRECTION;

typedef union _QUIC_ABORTIVE_TRANSFER_FLAGS {
    struct {
        uint32_t DelayStreamCreation : 1;
        uint32_t SendDataOnStream : 1;
        uint32_t ClientShutdown : 1;
        uint32_t DelayClientShutdown : 1;
        uint32_t WaitForStream : 1;
        uint32_t ShutdownDirection : 2;
        uint32_t UnidirectionalStream : 1;
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

typedef enum _QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE {
    NoShutdown,
    GracefulShutdown,
    AbortShutdown
} QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE;

typedef enum _QUIC_RECEIVE_RESUME_TYPE {
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

#ifdef _WIN32

//
// Kernel Mode Driver Interface
//

//
// Name of the driver service for msquic_bvt.sys.
//
#define QUIC_TEST_DRIVER_NAME   "QuicTest"


#define QUIC_TEST_IOCTL_PATH    "\\\\.\\\\" QUIC_TEST_DRIVER_NAME

//
// {85C2D886-FA01-4DDA-AAED-9A16CC7DA6CE}
//
static const GUID QUIC_TEST_DEVICE_INSTANCE =
{ 0x85c2d886, 0xfa01, 0x4dda,{ 0xaa, 0xed, 0x9a, 0x16, 0xcc, 0x7d, 0xa6, 0xce } };

//
// IOCTL Interface
//

#define QUIC_CTL_CODE(request, method, access) \
    CTL_CODE(FILE_DEVICE_NETWORK, request, method, access)

#define IOCTL_QUIC_SEC_CONFIG \
    QUIC_CTL_CODE(1, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_CERTIFICATE_HASH

#define IOCTL_QUIC_RUN_VALIDATE_REGISTRATION \
    QUIC_CTL_CODE(2, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_SESSION \
    QUIC_CTL_CODE(3, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_LISTENER \
    QUIC_CTL_CODE(4, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_CONNECTION \
    QUIC_CTL_CODE(5, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_STREAM \
    QUIC_CTL_CODE(6, METHOD_BUFFERED, FILE_WRITE_DATA)
    // UINT8 - Connect

#define IOCTL_QUIC_RUN_CREATE_LISTENER \
    QUIC_CTL_CODE(7, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_LISTENER \
    QUIC_CTL_CODE(8, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_LISTENER_IMPLICIT \
    QUIC_CTL_CODE(9, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#define IOCTL_QUIC_RUN_START_TWO_LISTENERS \
    QUIC_CTL_CODE(10, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_TWO_LISTENERS_SAME_ALPN \
    QUIC_CTL_CODE(11, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_START_LISTENER_EXPLICIT \
    QUIC_CTL_CODE(12, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#define IOCTL_QUIC_RUN_CREATE_CONNECTION \
    QUIC_CTL_CODE(13, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_BIND_CONNECTION_IMPLICIT \
    QUIC_CTL_CODE(14, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#define IOCTL_QUIC_RUN_BIND_CONNECTION_EXPLICIT \
    QUIC_CTL_CODE(15, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#pragma pack(push)
#pragma pack(1)

typedef struct {
    INT32 Family;
    UINT8 ServerStatelessRetry;
    UINT8 ClientUsesOldVersion;
    UINT8 ClientRebind;
    UINT8 ChangeMaxStreamID;
    UINT8 MultipleALPNs;
    UINT8 AsyncSecConfig;
    UINT8 MultiPacketClientInitial;
} QUIC_RUN_CONNECT_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_CONNECT \
    QUIC_CTL_CODE(16, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CONNECT_PARAMS

#pragma pack(push)
#pragma pack(1)

typedef struct {
    INT32 Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    uint32_t StreamBurstCount;
    uint32_t StreamBurstDelayMs;
    UINT8 ServerStatelessRetry;
    UINT8 ClientRebind;
    UINT8 ClientZeroRtt;
    UINT8 ServerRejectZeroRtt;
    UINT8 UseSendBuffer;
    UINT8 UnidirectionalStreams;
    UINT8 ServerInitiatedStreams;
} QUIC_RUN_CONNECT_AND_PING_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_CONNECT_AND_PING \
    QUIC_CTL_CODE(17, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CONNECT_AND_PING_PARAMS

#define IOCTL_QUIC_RUN_CONNECT_AND_IDLE \
    QUIC_CTL_CODE(18, METHOD_BUFFERED, FILE_WRITE_DATA)
    // UINT8 - EnableKeepAlive

#define IOCTL_QUIC_RUN_VALIDATE_SECCONFIG \
    QUIC_CTL_CODE(19, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_CERTIFICATE_HASH_STORE

#define IOCTL_QUIC_RUN_CONNECT_UNREACHABLE \
    QUIC_CTL_CODE(20, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#define IOCTL_QUIC_RUN_CONNECT_BAD_ALPN \
    QUIC_CTL_CODE(21, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#define IOCTL_QUIC_RUN_CONNECT_BAD_SNI \
    QUIC_CTL_CODE(22, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#define IOCTL_QUIC_RUN_SERVER_DISCONNECT \
    QUIC_CTL_CODE(23, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CLIENT_DISCONNECT \
    QUIC_CTL_CODE(24, METHOD_BUFFERED, FILE_WRITE_DATA)
    // UINT8 - StopListenerFirst

#define IOCTL_QUIC_RUN_VALIDATE_CONNECTION_EVENTS \
    QUIC_CTL_CODE(25, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VALIDATE_STREAM_EVENTS \
    QUIC_CTL_CODE(26, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_VERSION_NEGOTIATION \
    QUIC_CTL_CODE(27, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#pragma pack(push)
#pragma pack(1)

typedef struct {
    INT32 Family;
    uint16_t Iterations;
    uint16_t KeyUpdateBytes;
    UINT8 UseKeyUpdateBytes;
    UINT8 ClientKeyUpdate;
    UINT8 ServerKeyUpdate;
} QUIC_RUN_KEY_UPDATE_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_KEY_UPDATE \
    QUIC_CTL_CODE(28, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_KEY_UPDATE_PARAMS

#define IOCTL_QUIC_RUN_VALIDATE_API \
    QUIC_CTL_CODE(29, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_QUIC_RUN_CONNECT_SERVER_REJECTED \
    QUIC_CTL_CODE(30, METHOD_BUFFERED, FILE_WRITE_DATA)
    // INT32 - Family

#pragma pack(push)
#pragma pack(1)

typedef struct {
    INT32 Family;
    QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
} QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_ABORTIVE_SHUTDOWN \
    QUIC_CTL_CODE(31, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_ABORTIVE_SHUTDOWN_PARAMS

#pragma pack(push)
#pragma pack(1)

typedef struct {
    INT32 Family;
    uint16_t Iterations;
} QUIC_RUN_CID_UPDATE_PARAMS;

#pragma pack(pop)

#define IOCTL_QUIC_RUN_CID_UPDATE \
    QUIC_CTL_CODE(32, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_CID_UPDATE_PARAMS

typedef struct {
    INT32 Family;
    INT32 SendBytes;
    INT32 ConsumeBytes;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    UINT8 PauseFirst;
} QUIC_RUN_RECEIVE_RESUME_PARAMS;

#define IOCTL_QUIC_RUN_RECEIVE_RESUME \
    QUIC_CTL_CODE(33, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_RECEIVE_RESUME_PARAMS

#define IOCTL_QUIC_RUN_RECEIVE_RESUME_NO_DATA \
    QUIC_CTL_CODE(34, METHOD_BUFFERED, FILE_WRITE_DATA)
    // QUIC_RUN_RECEIVE_RESUME_PARAMS

#define QUIC_MAX_IOCTL_FUNC_CODE 34

#endif // _WIN32