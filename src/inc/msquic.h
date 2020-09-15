/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Declarations for the MsQuic API, which enables applications and drivers to
    create QUIC connections as a client or server.

    For more detailed information, see ../docs/API.md

Supported Platforms:

    Windows User mode
    Windows Kernel mode
    Linux User mode

--*/

#ifndef _MSQUIC_
#define _MSQUIC_

#ifdef _WIN32
#pragma once
#endif

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4214)  // nonstandard extension used: bit field types other than int

#ifdef _KERNEL_MODE
#include "msquic_winkernel.h"
#elif _WIN32
#include "msquic_winuser.h"
#elif __linux__
#include "msquic_linux.h"
#else
#error "Unsupported Platform"
#endif

#if defined(__cplusplus)
extern "C" {
#endif


typedef struct QUIC_HANDLE *HQUIC;
typedef struct QUIC_SEC_CONFIG QUIC_SEC_CONFIG;


//
// The maximum value that can be encoded in a 62-bit integer.
//
#define QUIC_UINT62_MAX ((1ULL << 62) - 1)

//
// Represents a 62-bit integer.
//
typedef _In_range_(0, QUIC_UINT62_MAX) uint64_t QUIC_UINT62;

//
// An ALPN must not exceed 255 bytes, and must not be zero-length.
//
#define QUIC_MAX_ALPN_LENGTH            255

//
// A server name must not exceed 65535 bytes.
//
#define QUIC_MAX_SNI_LENGTH             65535

//
// The maximum number of bytes of application data a server application can
// send in a resumption ticket.
//
#define QUIC_MAX_RESUMPTION_APP_DATA_LENGTH     1000

typedef enum QUIC_EXECUTION_PROFILE {
    QUIC_EXECUTION_PROFILE_LOW_LATENCY,         // Default
    QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT,
    QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER,
    QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME
} QUIC_EXECUTION_PROFILE;

typedef enum QUIC_LOAD_BALANCING_MODE {
    QUIC_LOAD_BALANCING_DISABLED,               // Default
    QUIC_LOAD_BALANCING_SERVER_ID_IP            // Encodes IP address in Server ID
} QUIC_LOAD_BALANCING_MODE;

typedef enum QUIC_SEC_CONFIG_FLAGS {
    QUIC_SEC_CONFIG_FLAG_NONE                   = 0x00000000,
    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH       = 0x00000001,
    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE = 0x00000002,
    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT    = 0x00000004,
    QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE       = 0x00000008,
    QUIC_SEC_CONFIG_FLAG_ENABLE_OCSP            = 0x00000010
} QUIC_SEC_CONFIG_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_SEC_CONFIG_FLAGS);

typedef enum QUIC_CERTIFICATE_HASH_STORE_FLAGS {
    QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE           = 0x0000,
    QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE  = 0x0001
} QUIC_CERTIFICATE_HASH_STORE_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_CERTIFICATE_HASH_STORE_FLAGS);

typedef enum QUIC_CONNECTION_SHUTDOWN_FLAGS {
    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE      = 0x0000,
    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT    = 0x0001    // Don't send the close frame over the network.
} QUIC_CONNECTION_SHUTDOWN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_CONNECTION_SHUTDOWN_FLAGS);

typedef enum QUIC_SERVER_RESUMPTION_LEVEL {
    QUIC_SERVER_NO_RESUME,
    QUIC_SERVER_RESUME_ONLY,
    QUIC_SERVER_RESUME_AND_ZERORTT
} QUIC_SERVER_RESUMPTION_LEVEL;

typedef enum QUIC_SEND_RESUMPTION_FLAGS {
    QUIC_SEND_RESUMPTION_FLAG_NONE          = 0x0000,
    QUIC_SEND_RESUMPTION_FLAG_FINAL         = 0x0001    // Free TLS state after sending this ticket.
} QUIC_SEND_RESUMPTION_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_SEND_RESUMPTION_FLAGS);

typedef enum QUIC_STREAM_SCHEDULING_SCHEME {
    QUIC_STREAM_SCHEDULING_SCHEME_FIFO          = 0x0000,   // Sends stream data first come, first served. (Default)
    QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN   = 0x0001,   // Sends stream data evenly multiplexed.
    QUIC_STREAM_SCHEDULING_SCHEME_COUNT                     // The number of stream scheduling schemes.
} QUIC_STREAM_SCHEDULING_SCHEME;

typedef enum QUIC_STREAM_OPEN_FLAGS {
    QUIC_STREAM_OPEN_FLAG_NONE              = 0x0000,
    QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL    = 0x0001,   // Indicates the stream is unidirectional.
    QUIC_STREAM_OPEN_FLAG_0_RTT             = 0x0002    // The stream was opened via a 0-RTT packet.
} QUIC_STREAM_OPEN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_STREAM_OPEN_FLAGS);

typedef enum QUIC_STREAM_START_FLAGS {
    QUIC_STREAM_START_FLAG_NONE             = 0x0000,
    QUIC_STREAM_START_FLAG_FAIL_BLOCKED     = 0x0001,   // Only opens the stream if flow control allows.
    QUIC_STREAM_START_FLAG_IMMEDIATE        = 0x0002,   // Immediately informs peer that stream is open.
    QUIC_STREAM_START_FLAG_ASYNC            = 0x0004    // Don't block the API call to wait for completion.
} QUIC_STREAM_START_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_STREAM_START_FLAGS);

typedef enum QUIC_STREAM_SHUTDOWN_FLAGS {
    QUIC_STREAM_SHUTDOWN_FLAG_NONE          = 0x0000,
    QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL      = 0x0001,   // Cleanly closes the send path.
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND    = 0x0002,   // Abruptly closes the send path.
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE = 0x0004,   // Abruptly closes the receive path.
    QUIC_STREAM_SHUTDOWN_FLAG_ABORT         = 0x0006,   // Abruptly closes both send and receive paths.
    QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE     = 0x0008    // Immediately sends completion events to app.
} QUIC_STREAM_SHUTDOWN_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_STREAM_SHUTDOWN_FLAGS);

typedef enum QUIC_RECEIVE_FLAGS {
    QUIC_RECEIVE_FLAG_NONE                  = 0x0000,
    QUIC_RECEIVE_FLAG_0_RTT                 = 0x0001,   // Data was encrypted with 0-RTT key.
    QUIC_RECEIVE_FLAG_FIN                   = 0x0002    // FIN was included with this data.
} QUIC_RECEIVE_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_RECEIVE_FLAGS);

typedef enum QUIC_SEND_FLAGS {
    QUIC_SEND_FLAG_NONE                     = 0x0000,
    QUIC_SEND_FLAG_ALLOW_0_RTT              = 0x0001,   // Allows the use of encrypting with 0-RTT key.
    QUIC_SEND_FLAG_START                    = 0x0002,   // Asynchronously starts the stream with the sent data.
    QUIC_SEND_FLAG_FIN                      = 0x0004,   // Indicates the request is the one last sent on the stream.
    QUIC_SEND_FLAG_DGRAM_PRIORITY           = 0x0008    // Indicates the datagram is higher priority than others.
} QUIC_SEND_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(QUIC_SEND_FLAGS);

typedef enum QUIC_DATAGRAM_SEND_STATE {
    QUIC_DATAGRAM_SEND_SENT,                            // Sent and awaiting acknowledegment
    QUIC_DATAGRAM_SEND_LOST_SUSPECT,                    // Suspected as lost, but still tracked
    QUIC_DATAGRAM_SEND_LOST_DISCARDED,                  // Lost and not longer being tracked
    QUIC_DATAGRAM_SEND_ACKNOWLEDGED,                    // Acknowledged
    QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS,           // Acknowledged after being suspected lost
    QUIC_DATAGRAM_SEND_CANCELED                         // Canceled before send
} QUIC_DATAGRAM_SEND_STATE;

//
// Helper to determine if a datagrams state is final, and no longer tracked
// by MsQuic.
//
#define QUIC_DATAGRAM_SEND_STATE_IS_FINAL(State) \
    (State >= QUIC_DATAGRAM_SEND_LOST_DISCARDED)


typedef struct QUIC_REGISTRATION_CONFIG { // All fields may be NULL/zero.
    const char* AppName;
    QUIC_EXECUTION_PROFILE ExecutionProfile;
} QUIC_REGISTRATION_CONFIG;

typedef struct QUIC_CERTIFICATE_HASH {
    uint8_t ShaHash[20];
} QUIC_CERTIFICATE_HASH;

typedef struct QUIC_CERTIFICATE_HASH_STORE {
    QUIC_CERTIFICATE_HASH_STORE_FLAGS Flags;
    uint8_t ShaHash[20];
    char StoreName[128];
} QUIC_CERTIFICATE_HASH_STORE;

typedef struct QUIC_CERTIFICATE_FILE {
    char *PrivateKeyFile;
    char *CertificateFile;
} QUIC_CERTIFICATE_FILE;

//
// A single contiguous buffer.
//
typedef struct QUIC_BUFFER {
    uint32_t Length;
    _Field_size_bytes_(Length)
    uint8_t* Buffer;
} QUIC_BUFFER;

//
// All the available information describing a new incoming connection.
//
typedef struct QUIC_NEW_CONNECTION_INFO {
    uint32_t QuicVersion;
    const QUIC_ADDR* LocalAddress;
    const QUIC_ADDR* RemoteAddress;
    uint32_t CryptoBufferLength;
    uint16_t ClientAlpnListLength;
    uint16_t ServerNameLength;
    uint8_t NegotiatedAlpnLength;
    _Field_size_bytes_(CryptoBufferLength)
    const uint8_t* CryptoBuffer;
    _Field_size_bytes_(ClientAlpnListLength)
    const uint8_t* ClientAlpnList;
    _Field_size_bytes_(NegotiatedAlpnLength)
    const uint8_t* NegotiatedAlpn;
    _Field_size_bytes_opt_(ServerNameLength)
    const char* ServerName;
} QUIC_NEW_CONNECTION_INFO;

//
// All statistics available to query about a connection.
//
typedef struct QUIC_STATISTICS {
    uint64_t CorrelationId;
    uint32_t VersionNegotiation     : 1;
    uint32_t StatelessRetry         : 1;
    uint32_t ResumptionAttempted    : 1;
    uint32_t ResumptionSucceeded    : 1;
    uint32_t Rtt;                       // In microseconds
    uint32_t MinRtt;                    // In microseconds
    uint32_t MaxRtt;                    // In microseconds
    struct {
        uint64_t Start;
        uint64_t InitialFlightEnd;      // Processed all peer's Initial packets
        uint64_t HandshakeFlightEnd;    // Processed all peer's Handshake packets
    } Timing;
    struct {
        uint32_t ClientFlight1Bytes;    // Sum of TLS payloads
        uint32_t ServerFlight1Bytes;    // Sum of TLS payloads
        uint32_t ClientFlight2Bytes;    // Sum of TLS payloads
    } Handshake;
    struct {
        uint16_t PathMtu;               // Current path MTU.
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t RetransmittablePackets;
        uint64_t SuspectedLostPackets;
        uint64_t SpuriousLostPackets;   // Actual lost is (SuspectedLostPackets - SpuriousLostPackets)
        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
        uint32_t CongestionCount;       // Number of congestion events
        uint32_t PersistentCongestionCount; // Number of persistent congestion events
    } Send;
    struct {
        uint64_t TotalPackets;          // QUIC packets; could be coalesced into fewer UDP datagrams.
        uint64_t ReorderedPackets;      // Means not the expected next packet. Could indicate loss gap too.
        uint64_t DroppedPackets;        // Includes DuplicatePackets.
        uint64_t DuplicatePackets;
        uint64_t TotalBytes;            // Sum of UDP payloads
        uint64_t TotalStreamBytes;      // Sum of stream payloads
        uint64_t DecryptionFailures;    // Count of packet decryption failures.
    } Recv;
    struct {
        uint32_t KeyUpdateCount;
    } Misc;
} QUIC_STATISTICS;

typedef struct QUIC_LISTENER_STATISTICS {

    uint64_t TotalAcceptedConnections;
    uint64_t TotalRejectedConnections;

    struct {
        struct {
            uint64_t DroppedPackets;
        } Recv;
    } Binding;
} QUIC_LISTENER_STATISTICS;

typedef enum QUIC_PERFORMANCE_COUNTERS {
    QUIC_PERF_COUNTER_CONN_CREATED,         // Total connections ever allocated.
    QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL,  // Total connections that failed during handshake.
    QUIC_PERF_COUNTER_CONN_APP_REJECT,      // Total connections rejected by the application.
    QUIC_PERF_COUNTER_CONN_RESUMED,         // Total connections resumed.
    QUIC_PERF_COUNTER_CONN_ACTIVE,          // Connections currently allocated.
    QUIC_PERF_COUNTER_CONN_CONNECTED,       // Connections currently in the connected state.
    QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS, // Total connections shutdown with a protocol error.
    QUIC_PERF_COUNTER_CONN_NO_ALPN,         // Total connection attempts with no matching ALPN.
    QUIC_PERF_COUNTER_STRM_ACTIVE,          // Current streams allocated.
    QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST,  // Total suspected packets lost
    QUIC_PERF_COUNTER_PKTS_DROPPED,         // Total packets dropped for any reason.
    QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL, // Total packets with decryption failures.
    QUIC_PERF_COUNTER_UDP_RECV,             // Total UDP datagrams received.
    QUIC_PERF_COUNTER_UDP_SEND,             // Total UDP datagrams sent.
    QUIC_PERF_COUNTER_UDP_RECV_BYTES,       // Total UDP payload bytes received.
    QUIC_PERF_COUNTER_UDP_SEND_BYTES,       // Total UDP payload bytes sent.
    QUIC_PERF_COUNTER_UDP_RECV_EVENTS,      // Total UDP receive events.
    QUIC_PERF_COUNTER_UDP_SEND_CALLS,       // Total UDP send API calls.
    QUIC_PERF_COUNTER_APP_SEND_BYTES,       // Total bytes sent by applications.
    QUIC_PERF_COUNTER_APP_RECV_BYTES,       // Total bytes received by applications.
    QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH,     // Current connections queued for processing.
    QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH,// Current connection operations queued.
    QUIC_PERF_COUNTER_CONN_OPER_QUEUED,     // Total connection operations queued ever.
    QUIC_PERF_COUNTER_CONN_OPER_COMPLETED,  // Total connection operations processed ever.
    QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH,// Current worker operations queued.
    QUIC_PERF_COUNTER_WORK_OPER_QUEUED,     // Total worker operations queued ever.
    QUIC_PERF_COUNTER_WORK_OPER_COMPLETED,  // Total worker operations processed ever.
    QUIC_PERF_COUNTER_MAX
} QUIC_PERFORMANCE_COUNTERS;

typedef struct QUIC_SETTINGS {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t PacingEnabled              : 1;
            uint64_t MigrationEnabled           : 1;
            uint64_t DatagramReceiveEnabled     : 1;
            uint64_t ServerResumptionLevel      : 1;
            uint64_t MaxPartitionCount          : 1;
            uint64_t MaxOperationsPerDrain      : 1;
            uint64_t RetryMemoryLimit           : 1;
            uint64_t LoadBalancingMode          : 1;
            uint64_t MaxWorkerQueueDelayUs      : 1;
            uint64_t MaxStatelessOperations     : 1;
            uint64_t InitialWindowPackets       : 1;
            uint64_t SendIdleTimeoutMs          : 1;
            uint64_t InitialRttMs               : 1;
            uint64_t MaxAckDelayMs              : 1;
            uint64_t DisconnectTimeoutMs        : 1;
            uint64_t KeepAliveIntervalMs        : 1;
            uint64_t IdleTimeoutMs              : 1;
            uint64_t HandshakeIdleTimeoutMs     : 1;
            uint64_t PeerBidiStreamCount        : 1;
            uint64_t PeerUnidiStreamCount       : 1;
            uint64_t TlsClientMaxSendBuffer     : 1;
            uint64_t TlsServerMaxSendBuffer     : 1;
            uint64_t StreamRecvWindowDefault    : 1;
            uint64_t StreamRecvBufferDefault    : 1;
            uint64_t ConnFlowControlWindow      : 1;
            uint64_t MaxBytesPerKey             : 1;
            uint64_t RESERVED                   : 38;
        } IsSet;
    };

    uint8_t PacingEnabled           : 1;
    uint8_t MigrationEnabled        : 1;
    uint8_t DatagramReceiveEnabled  : 1;
    uint8_t ServerResumptionLevel   : 2;    // QUIC_SERVER_RESUMPTION_LEVEL
    uint8_t RESERVED                : 3;
    uint16_t MaxPartitionCount;             // Global only
    uint8_t MaxOperationsPerDrain;          // Global only
    uint16_t RetryMemoryLimit;              // Global only
    uint16_t LoadBalancingMode;             // Global only
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint64_t MaxBytesPerKey;

} QUIC_SETTINGS;

//
// Functions for associating application contexts with QUIC handles.
//

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_SET_CONTEXT_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ void* Context
    );

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void*
(QUIC_API * QUIC_GET_CONTEXT_FN)(
    _In_ _Pre_defensive_ HQUIC Handle
    );

//
// Sets the event handler for the QUIC handle. The type of the handler must be
// appropriate for the type of the handle.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_SET_CALLBACK_HANDLER_FN)(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ void* Handler,
    _In_opt_ void* Context
    );

//
// Get and Set parameters on a handle.
//

typedef enum QUIC_PARAM_LEVEL {
    QUIC_PARAM_LEVEL_GLOBAL,
    QUIC_PARAM_LEVEL_REGISTRATION,
    QUIC_PARAM_LEVEL_SESSION,
    QUIC_PARAM_LEVEL_LISTENER,
    QUIC_PARAM_LEVEL_CONNECTION,
    QUIC_PARAM_LEVEL_TLS,
    QUIC_PARAM_LEVEL_STREAM
} QUIC_PARAM_LEVEL;

//
// Parameters for QUIC_PARAM_LEVEL_GLOBAL.
//
#define QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT          0   // uint16_t
#define QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS            1   // uint32_t[] - network byte order
#define QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE            2   // uint16_t - QUIC_LOAD_BALANCING_MODE
#define QUIC_PARAM_GLOBAL_PERF_COUNTERS                 3   // uint64_t[] - Array size is QUIC_PERF_COUNTER_MAX

//
// Parameters for QUIC_PARAM_LEVEL_REGISTRATION.
//
#define QUIC_PARAM_REGISTRATION_CID_PREFIX              0   // uint8_t[]

//
// Parameters for QUIC_PARAM_LEVEL_SESSION.
//
#define QUIC_PARAM_SESSION_TLS_TICKET_KEY               0   // uint8_t[44]

//
// Parameters for QUIC_PARAM_LEVEL_LISTENER.
//
#define QUIC_PARAM_LISTENER_LOCAL_ADDRESS               0   // QUIC_ADDR
#define QUIC_PARAM_LISTENER_STATS                       1   // QUIC_LISTENER_STATISTICS

//
// Parameters for QUIC_PARAM_LEVEL_CONNECTION.
//
#define QUIC_PARAM_CONN_QUIC_VERSION                    0   // uint32_t
#define QUIC_PARAM_CONN_LOCAL_ADDRESS                   1   // QUIC_ADDR
#define QUIC_PARAM_CONN_REMOTE_ADDRESS                  2   // QUIC_ADDR
#define QUIC_PARAM_CONN_IDLE_TIMEOUT                    3   // uint64_t - milliseconds
#define QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT          4   // uint16_t
#define QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT         5   // uint16_t
#define QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT         6   // uint16_t
#define QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT        7   // uint16_t
#define QUIC_PARAM_CONN_CLOSE_REASON_PHRASE             8   // char[]
#define QUIC_PARAM_CONN_STATISTICS                      9   // QUIC_STATISTICS
#define QUIC_PARAM_CONN_STATISTICS_PLAT                 10  // QUIC_STATISTICS
#define QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS           11  // uint32_t
#define QUIC_PARAM_CONN_KEEP_ALIVE                      12  // uint32_t - milliseconds
#define QUIC_PARAM_CONN_DISCONNECT_TIMEOUT              13  // uint32_t - milliseconds
#define QUIC_PARAM_CONN_SEC_CONFIG                      14  // QUIC_SEC_CONFIG*
#define QUIC_PARAM_CONN_SEND_BUFFERING                  15  // uint8_t (BOOLEAN)
#define QUIC_PARAM_CONN_SEND_PACING                     16  // uint8_t (BOOLEAN)
#define QUIC_PARAM_CONN_SHARE_UDP_BINDING               17  // uint8_t (BOOLEAN)
#define QUIC_PARAM_CONN_IDEAL_PROCESSOR                 18  // uint16_t
#define QUIC_PARAM_CONN_MAX_STREAM_IDS                  19  // uint64_t[4]
#define QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME        20  // QUIC_STREAM_SCHEDULING_SCHEME
#define QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED        21  // uint8_t (BOOLEAN)
#define QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED           22  // uint8_t (BOOLEAN)
#ifdef QUIC_API_ENABLE_INSECURE_FEATURES
#define QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION         23  // uint8_t (BOOLEAN)
#endif

#ifdef WIN32 // Windows certificate validation ignore flags.
#define QUIC_CERTIFICATE_FLAG_IGNORE_REVOCATION                 0x00000080
#define QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA                 0x00000100
#define QUIC_CERTIFICATE_FLAG_IGNORE_WRONG_USAGE                0x00000200
#define QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID     0x00001000 // bad common name in X509 Cert.
#define QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_DATE_INVALID   0x00002000 // expired X509 Cert.
#define QUIC_CERTIFICATE_FLAG_IGNORE_WEAK_SIGNATURE             0x00010000
#endif

//
// Parameters for QUIC_PARAM_LEVEL_TLS.
//
#ifdef WIN32 // Windows Platform specific parameters
typedef struct QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W {
    unsigned long Attribute;
    void* Buffer;
} QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W;
#define QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W     0x1000000   // QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W
#endif

//
// Parameters for QUIC_PARAM_LEVEL_STREAM.
//
#define QUIC_PARAM_STREAM_ID                            0   // QUIC_UINT62
#define QUIC_PARAM_STREAM_0RTT_LENGTH                   1   // uint64_t
#define QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE        2   // uint64_t - bytes

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SET_PARAM_FN)(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_GET_PARAM_FN)(
    _When_(Level == QUIC_PARAM_LEVEL_GLOBAL, _Reserved_)
    _When_(Level != QUIC_PARAM_LEVEL_GLOBAL, _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ _Pre_defensive_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ _Pre_defensive_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    );

//
// Registration Context Interface.
//

//
// Opens a new registration.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_REGISTRATION_OPEN_FN)(
    _In_opt_ const QUIC_REGISTRATION_CONFIG* Config,
    _Outptr_ _At_(*Registration, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Registration
    );

//
// Closes the registration.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_REGISTRATION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Registration
    );

//
// Security Configuration Interface.
//

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
void
(QUIC_API QUIC_SEC_CONFIG_CREATE_COMPLETE)(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
    );

typedef QUIC_SEC_CONFIG_CREATE_COMPLETE *QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER;

//
// Create a new security config.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SEC_CONFIG_CREATE_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _In_opt_ void* Certificate,
    _In_opt_z_ const char* Principal,
    _In_opt_ void* Context,
    _In_ _Pre_defensive_
        QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    );

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_SEC_CONFIG_DELETE_FN)(
    _In_ _Pre_defensive_ QUIC_SEC_CONFIG* SecurityConfig
    );

//
// Session Context Interface.
//

//
// Opens a new session.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SESSION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_opt_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Session, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Session
    );

//
// Closes an existing session. This function synchronizes the cleanup of all
// child objects (listeners and connections). It does this by blocking until
// all those child objects have been closed by the application.
// N.B. This function will deadlock if called in any MsQuic callbacks.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_SESSION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Session
    );

//
// Calls shutdown for all connections in this session. Don't call on a MsQuic
// callback thread or it might deadlock.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_SESSION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );

//
// Listener Context Interface.
//

typedef enum QUIC_LISTENER_EVENT_TYPE {
    QUIC_LISTENER_EVENT_NEW_CONNECTION      = 0
} QUIC_LISTENER_EVENT_TYPE;

typedef struct QUIC_LISTENER_EVENT {
    QUIC_LISTENER_EVENT_TYPE Type;
    union {
        struct {
            /* in */    const QUIC_NEW_CONNECTION_INFO* Info;
            /* in */    HQUIC Connection;
            /* out */   QUIC_SEC_CONFIG* SecurityConfig;
        } NEW_CONNECTION;
    };
} QUIC_LISTENER_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_LISTENER_CALLBACK)(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    );

typedef QUIC_LISTENER_CALLBACK *QUIC_LISTENER_CALLBACK_HANDLER;

//
// Opens a new listener.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ _Pre_defensive_ QUIC_LISTENER_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Listener, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Listener
    );

//
// Closes an existing listener. N.B. This function will deadlock if called in
// a QUIC_LISTENER_CALLBACK_HANDLER callback.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_LISTENER_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Listener
    );

//
// Starts the listener processing incoming connections.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_START_FN)(
    _In_ _Pre_defensive_ HQUIC Listener,
    _In_opt_ const QUIC_ADDR* LocalAddress
    );

//
// Stops the listener from processing incoming connections.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_LISTENER_STOP_FN)(
    _In_ _Pre_defensive_ HQUIC Listener
    );

//
// Connections
//

typedef enum QUIC_CONNECTION_EVENT_TYPE {
    QUIC_CONNECTION_EVENT_CONNECTED                         = 0,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT   = 1,    // The transport started the shutdown process.
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER        = 2,    // The peer application started the shutdown process.
    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE                 = 3,    // Ready for the handle to be closed.
    QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED             = 4,
    QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED              = 5,
    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED               = 6,
    QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE                 = 7,
    QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS                = 8,
    QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED           = 9,
    QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED            = 10,
    QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED                 = 11,
    QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED       = 12,
    QUIC_CONNECTION_EVENT_RESUMED                           = 13,   // Server-only; provides resumption data, if any.
    QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED        = 14    // Client-only; provides ticket to persist, if any.
} QUIC_CONNECTION_EVENT_TYPE;

typedef struct QUIC_CONNECTION_EVENT {
    QUIC_CONNECTION_EVENT_TYPE Type;
    union {
        struct {
            BOOLEAN SessionResumed;
            uint8_t NegotiatedAlpnLength;
            _Field_size_(NegotiatedAlpnLength)
            const uint8_t* NegotiatedAlpn;
        } CONNECTED;
        struct {
            QUIC_STATUS Status;
        } SHUTDOWN_INITIATED_BY_TRANSPORT;
        struct {
            QUIC_UINT62 ErrorCode;
        } SHUTDOWN_INITIATED_BY_PEER;
        struct {
            BOOLEAN HandshakeCompleted          : 1;
            BOOLEAN PeerAcknowledgedShutdown    : 1;
            BOOLEAN AppCloseInProgress          : 1;
        } SHUTDOWN_COMPLETE;
        struct {
            const QUIC_ADDR* Address;
        } LOCAL_ADDRESS_CHANGED;
        struct {
            const QUIC_ADDR* Address;
        } PEER_ADDRESS_CHANGED;
        struct {
            HQUIC Stream;
            QUIC_STREAM_OPEN_FLAGS Flags;
        } PEER_STREAM_STARTED;
        struct {
            uint16_t BidirectionalCount;
            uint16_t UnidirectionalCount;
        } STREAMS_AVAILABLE;
        struct {
            uint16_t IdealProcessor;
        } IDEAL_PROCESSOR_CHANGED;
        struct {
            BOOLEAN SendEnabled;
            uint16_t MaxSendLength;
        } DATAGRAM_STATE_CHANGED;
        struct {
            const QUIC_BUFFER* Buffer;
            QUIC_RECEIVE_FLAGS Flags;
        } DATAGRAM_RECEIVED;
        struct {
            /* inout */ void* ClientContext;
            QUIC_DATAGRAM_SEND_STATE State;
        } DATAGRAM_SEND_STATE_CHANGED;
        struct {
            uint16_t ResumptionStateLength;
            const uint8_t* ResumptionState;
        } RESUMED;
        struct {
            uint16_t ResumptionTicketLength;
            const uint8_t* ResumptionTicket;
        } RESUMPTION_TICKET_RECEIVED;
    };
} QUIC_CONNECTION_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_CONNECTION_CALLBACK)(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    );

typedef QUIC_CONNECTION_CALLBACK *QUIC_CONNECTION_CALLBACK_HANDLER;

//
// Opens a new connection.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Session,
    _In_ _Pre_defensive_ QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Connection, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Connection
    );

//
// Closes an existing connection.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_CONNECTION_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Connection
    );

//
// Starts the shutdown process on the connection. This immediately and silently
// shuts down any open streams; which will trigger callbacks for
// QUIC_CONNECTION_EVENT_STREAM_CLOSED events. Does nothing if already shutdown.
// Can be passed either a connection or stream handle.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_CONNECTION_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );

//
// Uses the QUIC (client) handle to start a connection attempt to the
// remote server. Can be passed either a connection or stream handle.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_START_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    );

//
// Uses the QUIC (server) handle to send a resumption ticket to the remote
// client, optionally with app-specific data useful during resumption.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_SEND_RESUMPTION_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_SEND_RESUMPTION_FLAGS Flags,
    _In_ uint16_t DataLength,
    _In_reads_bytes_opt_(DataLength)
        const uint8_t* ResumptionData
    );

//
// Streams
//

typedef enum QUIC_STREAM_EVENT_TYPE {
    QUIC_STREAM_EVENT_START_COMPLETE            = 0,
    QUIC_STREAM_EVENT_RECEIVE                   = 1,
    QUIC_STREAM_EVENT_SEND_COMPLETE             = 2,
    QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN        = 3,
    QUIC_STREAM_EVENT_PEER_SEND_ABORTED         = 4,
    QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED      = 5,
    QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE    = 6,
    QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE         = 7,
    QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE    = 8
} QUIC_STREAM_EVENT_TYPE;

typedef struct QUIC_STREAM_EVENT {
    QUIC_STREAM_EVENT_TYPE Type;
    union {
        struct {
            QUIC_STATUS Status;
            QUIC_UINT62 ID;
        } START_COMPLETE;
        struct {
            /* in */    uint64_t AbsoluteOffset;
            /* inout */ uint64_t TotalBufferLength;
            _Field_size_(BufferCount)
            /* in */    const QUIC_BUFFER* Buffers;
            _Field_range_(1, UINT32_MAX)
            /* in */    uint32_t BufferCount;
            /* in */    QUIC_RECEIVE_FLAGS Flags;
        } RECEIVE;
        struct {
            BOOLEAN Canceled;
            void* ClientContext;
        } SEND_COMPLETE;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_SEND_ABORTED;
        struct {
            QUIC_UINT62 ErrorCode;
        } PEER_RECEIVE_ABORTED;
        struct {
            BOOLEAN Graceful;
        } SEND_SHUTDOWN_COMPLETE;
        struct {
            uint64_t ByteCount;
        } IDEAL_SEND_BUFFER_SIZE;
    };
} QUIC_STREAM_EVENT;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
(QUIC_API QUIC_STREAM_CALLBACK)(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    );

typedef QUIC_STREAM_CALLBACK *QUIC_STREAM_CALLBACK_HANDLER;

//
// Opens a stream on the given connection.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Stream, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Stream
    );

//
// Closes a stream handle.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_STREAM_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Stream
    );

//
// Starts processing the stream.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_START_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ QUIC_STREAM_START_FLAGS Flags
    );

//
// Shuts the stream down as specified, and waits for graceful
// shutdowns to complete. Does nothing if already shut down.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );

//
// Sends data on an open stream.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_SEND_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );

//
// Completes a previously pended receive callback.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_RECEIVE_COMPLETE_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ uint64_t BufferLength
    );

//
// Enables or disables stream receive callbacks.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_RECEIVE_SET_ENABLED_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ BOOLEAN IsEnabled
    );

//
// Datagrams
//

//
// Sends an unreliable datagram on the connection. Note, the total payload
// of the send must fit in a single QUIC packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_DATAGRAM_SEND_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );

//
// API Function Table.
//
typedef struct QUIC_API_TABLE {

    QUIC_SET_CONTEXT_FN                 SetContext;
    QUIC_GET_CONTEXT_FN                 GetContext;
    QUIC_SET_CALLBACK_HANDLER_FN        SetCallbackHandler;

    QUIC_SET_PARAM_FN                   SetParam;
    QUIC_GET_PARAM_FN                   GetParam;

    QUIC_REGISTRATION_OPEN_FN           RegistrationOpen;
    QUIC_REGISTRATION_CLOSE_FN          RegistrationClose;

    QUIC_SEC_CONFIG_CREATE_FN           SecConfigCreate;
    QUIC_SEC_CONFIG_DELETE_FN           SecConfigDelete;

    QUIC_SESSION_OPEN_FN                SessionOpen;
    QUIC_SESSION_CLOSE_FN               SessionClose;
    QUIC_SESSION_SHUTDOWN_FN            SessionShutdown;

    QUIC_LISTENER_OPEN_FN               ListenerOpen;
    QUIC_LISTENER_CLOSE_FN              ListenerClose;
    QUIC_LISTENER_START_FN              ListenerStart;
    QUIC_LISTENER_STOP_FN               ListenerStop;

    QUIC_CONNECTION_OPEN_FN             ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN            ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN         ConnectionShutdown;
    QUIC_CONNECTION_START_FN            ConnectionStart;
    QUIC_CONNECTION_SEND_RESUMPTION_FN  ConnectionSendResumptionTicket;

    QUIC_STREAM_OPEN_FN                 StreamOpen;
    QUIC_STREAM_CLOSE_FN                StreamClose;
    QUIC_STREAM_START_FN                StreamStart;
    QUIC_STREAM_SHUTDOWN_FN             StreamShutdown;
    QUIC_STREAM_SEND_FN                 StreamSend;
    QUIC_STREAM_RECEIVE_COMPLETE_FN     StreamReceiveComplete;
    QUIC_STREAM_RECEIVE_SET_ENABLED_FN  StreamReceiveSetEnabled;

    QUIC_DATAGRAM_SEND_FN               DatagramSend;

} QUIC_API_TABLE;

//
// Opens the API library and initializes it if this is the first call for the
// process. It returns API function table for the rest of the API's functions.
// MsQuicClose must be called when the app is done with the function table.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicOpen(
    _Out_ _Pre_defensive_ const QUIC_API_TABLE** QuicApi
    );

//
// Cleans up the function table returned from MsQuicOpen and releases the
// reference on the API.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicClose(
    _In_ _Pre_defensive_ const QUIC_API_TABLE* QuicApi
    );

#if defined(__cplusplus)
}
#endif

#endif // _MSQUIC_
