/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

typedef struct QUIC_BINDING QUIC_BINDING;
typedef struct QUIC_OPERATION QUIC_OPERATION;
typedef struct QUIC_WORKER QUIC_WORKER;
typedef struct QUIC_WORKER_POOL QUIC_WORKER_POOL;
typedef struct QUIC_REGISTRATION QUIC_REGISTRATION;
typedef struct QUIC_CONFIGURATION QUIC_CONFIGURATION;
typedef struct QUIC_LISTENER QUIC_LISTENER;
typedef struct QUIC_CONGESTION_CONTROL QUIC_CONGESTION_CONTROL;
typedef struct QUIC_CONNECTION QUIC_CONNECTION;
typedef struct QUIC_STREAM QUIC_STREAM;
typedef struct QUIC_PACKET_BUILDER QUIC_PACKET_BUILDER;
typedef struct QUIC_PATH QUIC_PATH;
typedef struct QUIC_RX_PACKET QUIC_RX_PACKET;

/*************************************************************
                    PROTOCOL CONSTANTS
*************************************************************/

//
// Until the first RTT sample is collected, this is the default estimate of the
// RTT.
//
#define QUIC_INITIAL_RTT                        333 // millisec

//
// The minimum (version 1) QUIC Packet Size (UDP payload size) for initial QUIC
// packets.
//
#define QUIC_MIN_INITIAL_PACKET_LENGTH          1200

//
// The minimum UDP payload size across all supported versions. Used to decide
// on whether to send a version negotiation packet in response to an unsupported
// QUIC version.
//
#define QUIC_MIN_UDP_PAYLOAD_LENGTH_FOR_VN      QUIC_MIN_INITIAL_PACKET_LENGTH

//
// The initial congestion window.
//
#define QUIC_INITIAL_WINDOW_PACKETS             10

//
// Maximum number of bytes allowed for a connection ID.
// This is used for both QUIC versions 1 and 2.
//
#define QUIC_MAX_CONNECTION_ID_LENGTH_INVARIANT 255
#define QUIC_MAX_CONNECTION_ID_LENGTH_V1        20

//
// Minimum number of bytes required for a connection ID in the client's
// Initial packet.
//
#define QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH   8

//
// The amount of packet amplification allowed by the server. Until the
// client address is validated, a server will send no more than
// QUIC_AMPLIFICATION_RATIO UDP payload bytes for each received byte.
//
#define QUIC_AMPLIFICATION_RATIO                3

//
// The max expected reordering in terms of number of packets
// (for FACK loss detection).
//
#define QUIC_PACKET_REORDER_THRESHOLD           3

//
// The max expected reordering in terms of time
// (for RACK loss detection).
//
#define QUIC_TIME_REORDER_THRESHOLD(rtt)        ((rtt) + ((rtt) / 8))

//
// Number of consecutive PTOs after which the network is considered to be
// experiencing persistent congestion.
//
#define QUIC_PERSISTENT_CONGESTION_THRESHOLD    2

//
// The number of probe timeouts' worth of time to wait in the closing period
// before timing out.
//
#define QUIC_CLOSE_PTO_COUNT                    3

//
// The congestion window to use after persistent congestion. TCP uses one
// packet, but here we use two, as recommended by the QUIC spec.
//
#define QUIC_PERSISTENT_CONGESTION_WINDOW_PACKETS   2

//
// The minimum number of ACK eliciting packets to receive before overriding ACK
// delay.
//
#define QUIC_MIN_ACK_SEND_NUMBER                2

//
// The value for Reordering threshold when no ACK_FREQUENCY frame is received.
// This means that the receiver will immediately acknowledge any out-of-order packets.
//
#define QUIC_MIN_REORDERING_THRESHOLD           1

//
// The size of the stateless reset token.
//
#define QUIC_STATELESS_RESET_TOKEN_LENGTH       16

//
// The minimum length for a stateless reset packet.
//
#define QUIC_MIN_STATELESS_RESET_PACKET_LENGTH  (5 + QUIC_STATELESS_RESET_TOKEN_LENGTH)

//
// The recommended (minimum) length for a stateless reset packet so that it is
// difficult to distinguish from other packets (by middleboxes).
//
#define QUIC_RECOMMENDED_STATELESS_RESET_PACKET_LENGTH (25 + QUIC_STATELESS_RESET_TOKEN_LENGTH)


/*************************************************************
                  IMPLEMENTATION CONSTANTS
*************************************************************/


//
// Maximum number of partitions to support.
//
#define QUIC_MAX_PARTITION_COUNT                512

//
// The number of partitions (cores) to offset from the receive (RSS) core when
// using the QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT profile.
//
#define QUIC_MAX_THROUGHPUT_PARTITION_OFFSET    2 // Two to skip over hyper-threaded cores

//
// The fraction ((0 to UINT16_MAX) / UINT16_MAX) of memory that must be
// exhausted before enabling retry.
//
#define QUIC_DEFAULT_RETRY_MEMORY_FRACTION      65 // ~0.1%

//
// The maximum amount of queue delay a worker should take on (in ms).
//
#define QUIC_MAX_WORKER_QUEUE_DELAY             250

//
// The maximum number of simultaneous stateless operations that can be queued on
// a single worker.
//
#define QUIC_MAX_STATELESS_OPERATIONS           16

//
// The maximum number of simultaneous stateless operations that can be queued on
// a single binding.
//
#define QUIC_MAX_BINDING_STATELESS_OPERATIONS   100

//
// The number of milliseconds we keep an entry in the binding stateless
// operation table before removing it.
//
#define QUIC_STATELESS_OPERATION_EXPIRATION_MS  100

//
// The maximum number of operations a connection will drain from its queue per
// call to QuicConnDrainOperations.
//
#define QUIC_MAX_OPERATIONS_PER_DRAIN           16

//
// Used as a hint for the maximum number of UDP datagrams to send for each
// FLUSH_SEND operation. The actual number will generally exceed this value up
// to the limit of the current USO buffer being filled.
//
#define QUIC_MAX_DATAGRAMS_PER_SEND             40

//
// The number of packets we write for a single stream before going to the next
// one in the round robin.
//
#define QUIC_STREAM_SEND_BATCH_COUNT            8

//
// The maximum number of received packets to batch process at a time.
//
#define QUIC_MAX_RECEIVE_BATCH_COUNT            32

//
// The maximum number of crypto operations to batch.
//
#define QUIC_MAX_CRYPTO_BATCH_COUNT             8

//
// The maximum number of received packets that may be processed in a single
// flush operation.
//
#define QUIC_MAX_RECEIVE_FLUSH_COUNT            100

//
// The maximum number of pending datagrams we will hold on to, per connection,
// per packet number space. We base our max on the expected initial window size
// of the peer with a little bit of extra.
//
#define QUIC_MAX_PENDING_DATAGRAMS              (QUIC_INITIAL_WINDOW_PACKETS + 5)

//
// The maximum crypto FC window we will use/allow for client buffers.
//
#define QUIC_MAX_TLS_CLIENT_SEND_BUFFER         (4 * 1024)

//
// The maximum crypto FC window we will use/allow for server buffers.
//
#define QUIC_MAX_TLS_SERVER_SEND_BUFFER         (8 * 1024)

//
// The initial stream FC window size reported to peers.
//
#define QUIC_DEFAULT_STREAM_FC_WINDOW_SIZE      0x10000  // 65536

//
// The initial stream receive buffer allocation size.
//
#define QUIC_DEFAULT_STREAM_RECV_BUFFER_SIZE    0x1000  // 4096

//
// The default connection flow control window value, in bytes.
//
#define QUIC_DEFAULT_CONN_FLOW_CONTROL_WINDOW   0x1000000  // 16MB

//
// Maximum memory allocated (in bytes) for different range tracking structures
//
#define QUIC_MAX_RANGE_ALLOC_SIZE               0x100000    // 1084576
#define QUIC_MAX_RANGE_DUPLICATE_PACKETS        0x1000      // 4096
#define QUIC_MAX_RANGE_ACK_PACKETS              0x800       // 2048
#define QUIC_MAX_RANGE_DECODE_ACKS              0x1000      // 4096

CXPLAT_STATIC_ASSERT(IS_POWER_OF_TWO(QUIC_MAX_RANGE_ALLOC_SIZE), "Must be power of two");
CXPLAT_STATIC_ASSERT(IS_POWER_OF_TWO(QUIC_MAX_RANGE_DUPLICATE_PACKETS), "Must be power of two");
CXPLAT_STATIC_ASSERT(IS_POWER_OF_TWO(QUIC_MAX_RANGE_ACK_PACKETS), "Must be power of two");
CXPLAT_STATIC_ASSERT(IS_POWER_OF_TWO(QUIC_MAX_RANGE_DECODE_ACKS), "Must be power of two");

//
// Minimum MTU allowed to be configured. Must be able to fit a
// QUIC_MIN_INITIAL_PACKET_LENGTH in an IPv6 datagram.
//
#define QUIC_DPLPMTUD_MIN_MTU                   (QUIC_MIN_INITIAL_PACKET_LENGTH + \
                                                CXPLAT_MIN_IPV6_HEADER_SIZE + \
                                                CXPLAT_UDP_HEADER_SIZE)

//
// The minimum size of the initial packets we send. We pad a little more than
// the spec-minimum to help with amplification limits for large server
// certificates. This MUST BE greater than or equal to
// QUIC_MIN_INITIAL_PACKET_LENGTH.
//
#define QUIC_INITIAL_PACKET_LENGTH              1240

CXPLAT_STATIC_ASSERT(QUIC_INITIAL_PACKET_LENGTH >= QUIC_MIN_INITIAL_PACKET_LENGTH, "Packet length too small");

//
// The minimum IP MTU DPLPMTUD will use by default.
//
#define QUIC_DPLPMTUD_DEFAULT_MIN_MTU           (QUIC_INITIAL_PACKET_LENGTH + \
                                                CXPLAT_MIN_IPV6_HEADER_SIZE + \
                                                CXPLAT_UDP_HEADER_SIZE)

//
// The maximum IP MTU DPLPMTUD will use by default.
//
#define QUIC_DPLPMTUD_DEFAULT_MAX_MTU           1500

//
// The maximum time an app callback can take before we log a warning.
// Apps should generally take less than a millisecond for each callback if at
// all possible, but this limit here is to catch performance issues caused by
// long running app callbacks.
//
#define QUIC_MAX_CALLBACK_TIME_WARNING          MS_TO_US(10)
#define QUIC_MAX_CALLBACK_TIME_ERROR            MS_TO_US(1000)

//
// The number of milliseconds that must elapse before a connection is
// considered disconnected; that is, the time a connection waits for an
// expected acknowledgment for packets it has sent before it considers the
// path dead.
//
#define QUIC_DEFAULT_DISCONNECT_TIMEOUT         16000   // 16 seconds, in ms

//
// The maximum allowable disconnect value that can be configured. Larger values
// need more than 32-bits to perform converted-to-microsecond calculations.
//
#define QUIC_MAX_DISCONNECT_TIMEOUT             600000  // 10 minutes, in ms

CXPLAT_STATIC_ASSERT(
    QUIC_DEFAULT_DISCONNECT_TIMEOUT <= QUIC_MAX_DISCONNECT_TIMEOUT,
    "Default disconnect timeout should always be less than max");

//
// The default connection idle timeout (in milliseconds).
//
#define QUIC_DEFAULT_IDLE_TIMEOUT               30000

//
// The default connection idle timeout during the handshake (in milliseconds).
//
#define QUIC_DEFAULT_HANDSHAKE_IDLE_TIMEOUT     10000

//
// Minimum interval (in microseconds) between CONNECTION_CLOSE responses in
// closing state.
//
#define QUIC_CLOSING_RESPONSE_MIN_INTERVAL      5000

//
// The default value for keep alives being enabled or not.
//
#define QUIC_DEFAULT_KEEP_ALIVE_ENABLE          FALSE

//
// The default connection keep alive interval (in milliseconds).
//
#define QUIC_DEFAULT_KEEP_ALIVE_INTERVAL        0

//
// The flow control window is doubled when more than (1 / ratio) of the current
// window is delivered to the app within 1 RTT.
//
#define QUIC_RECV_BUFFER_DRAIN_RATIO            4

//
// The default value for send buffering being enabled or not.
//
#define QUIC_DEFAULT_SEND_BUFFERING_ENABLE      TRUE

//
// The default ideal send buffer size (in bytes).
//
#define QUIC_DEFAULT_IDEAL_SEND_BUFFER_SIZE     0x20000 // 131072

//
// The max ideal send buffer size (in bytes). Note that this is not
// a hard max on the number of bytes buffered for the connection.
//
#define QUIC_MAX_IDEAL_SEND_BUFFER_SIZE         0x8000000 // 134217728

//
// The minimum number of bytes of send allowance we must have before we will
// send another packet.
//
#define QUIC_MIN_SEND_ALLOWANCE                 76  // Magic number to indicate a threshold of 'enough' allowance to send another packet.

//
// The minimum buffer space that we require before we will pack another
// compound packet in the UDP payload or stream into a QUIC packet.
//
#define QUIC_MIN_PACKET_SPARE_SPACE             64

//
// The maximum number of paths a single connection will keep track of.
//
#define QUIC_MAX_PATH_COUNT                     4

//
// Maximum number of connection IDs accepted from the peer.
//
#define QUIC_ACTIVE_CONNECTION_ID_LIMIT         4

CXPLAT_STATIC_ASSERT(
    2 <= QUIC_ACTIVE_CONNECTION_ID_LIMIT,
    "Should always be more than the spec minimum");

CXPLAT_STATIC_ASSERT(
    QUIC_MAX_PATH_COUNT <= QUIC_ACTIVE_CONNECTION_ID_LIMIT,
    "Should always have enough CIDs for all paths");

//
// The default value for pacing being enabled or not.
//
#define QUIC_DEFAULT_SEND_PACING                TRUE

//
// The minimum RTT, in microseconds, where pacing will be used.
//
#define QUIC_MIN_PACING_RTT                     1000

//
// The number of microseconds between pacing chunks.
//
#define QUIC_SEND_PACING_INTERVAL               1000

//
// The maximum number of bytes to send in a given key phase
// before performing a key phase update. Roughly, 274GB.
//
#define QUIC_DEFAULT_MAX_BYTES_PER_KEY          0x4000000000

//
// Default minimum time without any sends before the congestion window is reset.
//
#define QUIC_DEFAULT_SEND_IDLE_TIMEOUT_MS       1000

//
// The scaling factor used locally for AckDelay field in the ACK_FRAME.
//
#define QUIC_ACK_DELAY_EXPONENT                 8

//
// The lifetime of a QUIC stateless retry token encryption key.
// This is also the interval that generates new keys.
//
#define QUIC_STATELESS_RETRY_KEY_LIFETIME_MS    30000

//
// The default value for migration being enabled or not.
//
#define QUIC_DEFAULT_MIGRATION_ENABLED          TRUE

//
// The default value for load balancing mode.
//
#define QUIC_DEFAULT_LOAD_BALANCING_MODE        QUIC_LOAD_BALANCING_DISABLED

//
// The default value for datagrams being enabled or not.
//
#define QUIC_DEFAULT_DATAGRAM_RECEIVE_ENABLED   FALSE

//
// The default max_datagram_frame_length transport parameter value we send. Set
// to max uint16 to not explicitly limit the length of datagrams.
//
#define QUIC_DEFAULT_MAX_DATAGRAM_LENGTH        0xFFFF

//
// By default, resumption and 0-RTT are not enabled for servers.
// If an application want to use these features, it must explicitly enable them.
//
#define QUIC_DEFAULT_SERVER_RESUMPTION_LEVEL    QUIC_SERVER_NO_RESUME

//
// Version of the wire-format for resumption tickets.
// This needs to be incremented for each change in order or count of fields.
//
#define CXPLAT_TLS_RESUMPTION_TICKET_VERSION      1

//
// Version of the blob for client resumption tickets.
// This needs to be incremented for each change in order or count of fields.
//
#define CXPLAT_TLS_RESUMPTION_CLIENT_TICKET_VERSION      1

//
// By default the Version Negotiation Extension is disabled.
//
#define QUIC_DEFAULT_VERSION_NEGOTIATION_EXT_ENABLED    FALSE

//
// The AEAD Integrity limit for maximum failed decryption packets over the
// lifetime of a connection. Set to the lowest limit, which is for
// AEAD_AES_128_CCM at 2^23.5 (rounded down)
//
#define CXPLAT_AEAD_INTEGRITY_LIMIT               11863283

//
// Maximum length, in bytes, for a connection_close reason phrase.
//
#define QUIC_MAX_CONN_CLOSE_REASON_LENGTH           512

//
// The maximum number of probe packets sent before considering an MTU too large.
//
#define QUIC_DPLPMTUD_MAX_PROBES                    3

//
// The timeout time in microseconds for the DPLPMTUD wait time.
//
#define QUIC_DPLPMTUD_RAISE_TIMER_TIMEOUT           S_TO_US(600)

//
// The amount of bytes to increase our PLMTU each probe
//
#define QUIC_DPLPMTUD_INCREMENT                     80

//
// The default congestion control algorithm
//
#define QUIC_CONGESTION_CONTROL_ALGORITHM_DEFAULT   QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC

//
// The default idle timeout period after which the source CID is updated before sending again.
//
#define QUIC_DEFAULT_DEST_CID_UPDATE_IDLE_TIMEOUT_MS 20000

//
// The default value for enabling grease quic bit extension.
//
#define QUIC_DEFAULT_GREASE_QUIC_BIT_ENABLED         FALSE

//
// The default value for enabling sender-side ECN support.
//
#define QUIC_DEFAULT_ECN_ENABLED                     FALSE

//
// The default settings for enabling HyStart support.
//
#define QUIC_DEFAULT_HYSTART_ENABLED                FALSE

//
// The default settings for allowing QEO support.
//
#define QUIC_DEFAULT_ENCRYPTION_OFFLOAD_ALLOWED      FALSE

//
// The default settings for allowing Reliable Reset support.
//
#define QUIC_DEFAULT_RELIABLE_RESET_ENABLED          FALSE

//
// The default settings for allowing XDP support
//
#define QUIC_DEFAULT_XDP_ENABLED                     FALSE

//
// The default settings for allowing QTIP support
//
#define QUIC_DEFAULT_QTIP_ENABLED                    FALSE

//
// The default settings for allowing RIO support
//
#define QUIC_DEFAULT_RIO_ENABLED                     FALSE

//
// The default settings for allowing One-Way Delay support.
//
#define QUIC_DEFAULT_ONE_WAY_DELAY_ENABLED           FALSE

//
// The default settings for allowing Network Statistics event to be raised.
//
#define QUIC_DEFAULT_NET_STATS_EVENT_ENABLED         FALSE

//
// The default settings for using multiple parallel receives for streams.
//
#define QUIC_DEFAULT_STREAM_MULTI_RECEIVE_ENABLED    FALSE

//
// The number of rounds in Cubic Slow Start to sample RTT.
//
#define QUIC_HYSTART_DEFAULT_N_SAMPLING             8

//
// The minimum RTT threshold to exit Cubic Slow Start (in microseconds).
//
#define QUIC_HYSTART_DEFAULT_MIN_ETA                4000

//
// The maximum RTT threshold to exit Cubic Slow Start (in microseconds).
//
#define QUIC_HYSTART_DEFAULT_MAX_ETA                16000

//
// The number of rounds to spend in Conservative Slow Start before switching
// to Congestion Avoidance.
//
#define QUIC_CONSERVATIVE_SLOW_START_DEFAULT_ROUNDS 5

//
// The Congestion Window growth divisor during Conservative Slow Start.
//
#define QUIC_CONSERVATIVE_SLOW_START_DEFAULT_GROWTH_DIVISOR 4

/*************************************************************
                  TRANSPORT PARAMETERS
*************************************************************/

#define QUIC_TP_FLAG_INITIAL_MAX_DATA                       0x00000001
#define QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL       0x00000002
#define QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE      0x00000004
#define QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI              0x00000008
#define QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI                 0x00000010
#define QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI                  0x00000020
#define QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE                   0x00000040
#define QUIC_TP_FLAG_ACK_DELAY_EXPONENT                     0x00000080
#define QUIC_TP_FLAG_STATELESS_RESET_TOKEN                  0x00000100
#define QUIC_TP_FLAG_PREFERRED_ADDRESS                      0x00000200
#define QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION               0x00000400
#define QUIC_TP_FLAG_IDLE_TIMEOUT                           0x00000800
#define QUIC_TP_FLAG_MAX_ACK_DELAY                          0x00001000
#define QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID     0x00002000
#define QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT             0x00004000
#define QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE                0x00008000
#define QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID           0x00010000
#define QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID             0x00020000
#define QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION                0x00040000
#define QUIC_TP_FLAG_VERSION_NEGOTIATION                    0x00080000
#define QUIC_TP_FLAG_MIN_ACK_DELAY                          0x00100000
#define QUIC_TP_FLAG_CIBIR_ENCODING                         0x00200000
#define QUIC_TP_FLAG_GREASE_QUIC_BIT                        0x00400000
#define QUIC_TP_FLAG_RELIABLE_RESET_ENABLED                 0x00800000
#define QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED                 0x01000000
#define QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED                 0x02000000
#define QUIC_TP_FLAG_TIMESTAMP_SHIFT                        24

#define QUIC_TP_MAX_PACKET_SIZE_DEFAULT                     65527
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN                    1200
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX                    65527

#define QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT                  3
#define QUIC_TP_ACK_DELAY_EXPONENT_MAX                      20

#define QUIC_TP_MAX_ACK_DELAY_DEFAULT                       25 // ms
#define QUIC_TP_MAX_ACK_DELAY_MAX                           ((1 << 14) - 1)
#define QUIC_TP_MIN_ACK_DELAY_MAX                           ((1 << 24) - 1)

#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT          2
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN              2

//
// Max allowed value of a MAX_STREAMS frame or transport parameter.
// Any larger value would allow a max stream ID that cannot be expressed
// as a variable-length integer.
//
#define QUIC_TP_MAX_STREAMS_MAX                             ((1ULL << 60) - 1)

/*************************************************************
                  PERSISTENT SETTINGS
*************************************************************/

#define QUIC_SETTING_APP_KEY                        "Apps\\"

#define QUIC_SETTING_MAX_PARTITION_COUNT            "MaxPartitionCount"
#define QUIC_SETTING_RETRY_MEMORY_FRACTION          "RetryMemoryFraction"
#define QUIC_SETTING_LOAD_BALANCING_MODE            "LoadBalancingMode"
#define QUIC_SETTING_FIXED_SERVER_ID                "FixedServerID"
#define QUIC_SETTING_MAX_WORKER_QUEUE_DELAY         "MaxWorkerQueueDelayMs"
#define QUIC_SETTING_MAX_STATELESS_OPERATIONS       "MaxStatelessOperations"
#define QUIC_SETTING_MAX_BINDING_STATELESS_OPERATIONS "MaxBindingStatelessOperations"
#define QUIC_SETTING_STATELESS_OPERATION_EXPIRATION "StatelessOperationExpirationMs"
#define QUIC_SETTING_MAX_OPERATIONS_PER_DRAIN       "MaxOperationsPerDrain"

#define QUIC_SETTING_SEND_BUFFERING_DEFAULT         "SendBufferingDefault"
#define QUIC_SETTING_SEND_PACING_DEFAULT            "SendPacingDefault"
#define QUIC_SETTING_MIGRATION_ENABLED              "MigrationEnabled"
#define QUIC_SETTING_DATAGRAM_RECEIVE_ENABLED       "DatagramReceiveEnabled"
#define QUIC_SETTING_GREASE_QUIC_BIT_ENABLED        "GreaseQuicBitEnabled"
#define QUIC_SETTING_ECN_ENABLED                    "EcnEnabled"
#define QUIC_SETTING_HYSTART_ENABLED                "HyStartEnabled"
#define QUIC_SETTING_ENCRYPTION_OFFLOAD_ALLOWED     "EncryptionOffloadAllowed"
#define QUIC_SETTING_RELIABLE_RESET_ENABLED         "ReliableResetEnabled"
#define QUIC_SETTING_XDP_ENABLED                    "XdpEnabled"
#define QUIC_SETTING_QTIP_ENABLED                   "QTIPEnabled"
#define QUIC_SETTING_RIO_ENABLED                    "RioEnabled"
#define QUIC_SETTING_ONE_WAY_DELAY_ENABLED          "OneWayDelayEnabled"
#define QUIC_SETTING_NET_STATS_EVENT_ENABLED        "NetStatsEventEnabled"
#define QUIC_SETTING_STREAM_MULTI_RECEIVE_ENABLED   "StreamMultiReceiveEnabled"

#define QUIC_SETTING_INITIAL_WINDOW_PACKETS         "InitialWindowPackets"
#define QUIC_SETTING_SEND_IDLE_TIMEOUT_MS           "SendIdleTimeoutMs"
#define QUIC_SETTING_DEST_CID_UPDATE_IDLE_TIMEOUT_MS "DestCidUpdateIdleTimeoutMs"

#define QUIC_SETTING_INITIAL_RTT                    "InitialRttMs"
#define QUIC_SETTING_MAX_ACK_DELAY                  "MaxAckDelayMs"
#define QUIC_SETTING_DISCONNECT_TIMEOUT             "DisconnectTimeoutMs"
#define QUIC_SETTING_KEEP_ALIVE_INTERVAL            "KeepAliveIntervalMs"
#define QUIC_SETTING_IDLE_TIMEOUT                   "IdleTimeoutMs"
#define QUIC_SETTING_HANDSHAKE_IDLE_TIMEOUT         "HandshakeIdleTimeoutMs"

#define QUIC_SETTING_MAX_TLS_CLIENT_SEND_BUFFER     "TlsClientMaxSendBuffer"
#define QUIC_SETTING_MAX_TLS_SERVER_SEND_BUFFER     "TlsServerMaxSendBuffer"
#define QUIC_SETTING_STREAM_FC_WINDOW_SIZE          "StreamRecvWindowDefault"
#define QUIC_SETTING_STREAM_FC_BIDI_LOCAL_WINDOW_SIZE "StreamRecvWindowBidiLocalDefault"
#define QUIC_SETTING_STREAM_FC_BIDI_REMOTE_WINDOW_SIZE "StreamRecvWindowBidiRemoteDefault"
#define QUIC_SETTING_STREAM_FC_UNIDI_WINDOW_SIZE    "StreamRecvWindowUnidiDefault"
#define QUIC_SETTING_STREAM_RECV_BUFFER_SIZE        "StreamRecvBufferDefault"
#define QUIC_SETTING_CONN_FLOW_CONTROL_WINDOW       "ConnFlowControlWindow"

#define QUIC_SETTING_MAX_BYTES_PER_KEY_PHASE        "MaxBytesPerKey"

#define QUIC_SETTING_SERVER_RESUMPTION_LEVEL        "ResumptionLevel"

#define QUIC_SETTING_VERSION_NEGOTIATION_EXT_ENABLE "VersionNegotiationExtEnabled"

#define QUIC_SETTING_ACCEPTABLE_VERSIONS            "AcceptableVersions"
#define QUIC_SETTING_OFFERED_VERSIONS               "OfferedVersions"
#define QUIC_SETTING_FULLY_DEPLOYED_VERSIONS        "FullyDeployedVersions"

#define QUIC_SETTING_MINIMUM_MTU                    "MinimumMtu"
#define QUIC_SETTING_MAXIMUM_MTU                    "MaximumMtu"
#define QUIC_SETTING_MTU_SEARCH_COMPLETE_TIMEOUT    "MtuDiscoverySearchCompleteTimeoutUs"
#define QUIC_SETTING_MTU_MISSING_PROBE_COUNT        "MtuDiscoveryMissingProbeCount"

#define QUIC_SETTING_CONGESTION_CONTROL_ALGORITHM   "CongestionControlAlgorithm"
