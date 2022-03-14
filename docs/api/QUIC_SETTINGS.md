QUIC_SETTINGS structure
======

The set of all customizable parameters for the library.

# Syntax

```C
typedef struct QUIC_SETTINGS {

    union {
        uint64_t IsSetFlags;
        struct {
            uint64_t MaxBytesPerKey                         : 1;
            uint64_t HandshakeIdleTimeoutMs                 : 1;
            uint64_t IdleTimeoutMs                          : 1;
            uint64_t MtuDiscoverySearchCompleteTimeoutUs    : 1;
            uint64_t TlsClientMaxSendBuffer                 : 1;
            uint64_t TlsServerMaxSendBuffer                 : 1;
            uint64_t StreamRecvWindowDefault                : 1;
            uint64_t StreamRecvBufferDefault                : 1;
            uint64_t ConnFlowControlWindow                  : 1;
            uint64_t MaxWorkerQueueDelayUs                  : 1;
            uint64_t MaxStatelessOperations                 : 1;
            uint64_t InitialWindowPackets                   : 1;
            uint64_t SendIdleTimeoutMs                      : 1;
            uint64_t InitialRttMs                           : 1;
            uint64_t MaxAckDelayMs                          : 1;
            uint64_t DisconnectTimeoutMs                    : 1;
            uint64_t KeepAliveIntervalMs                    : 1;
            uint64_t CongestionControlAlgorithm             : 1;
            uint64_t PeerBidiStreamCount                    : 1;
            uint64_t PeerUnidiStreamCount                   : 1;
            uint64_t MaxBindingStatelessOperations          : 1;
            uint64_t StatelessOperationExpirationMs         : 1;
            uint64_t MinimumMtu                             : 1;
            uint64_t MaximumMtu                             : 1;
            uint64_t SendBufferingEnabled                   : 1;
            uint64_t PacingEnabled                          : 1;
            uint64_t MigrationEnabled                       : 1;
            uint64_t DatagramReceiveEnabled                 : 1;
            uint64_t ServerResumptionLevel                  : 1;
            uint64_t MaxOperationsPerDrain                  : 1;
            uint64_t MtuDiscoveryMissingProbeCount          : 1;
            uint64_t RESERVED                               : 33;
        } IsSet;
    };

    uint64_t MaxBytesPerKey;
    uint64_t HandshakeIdleTimeoutMs;
    uint64_t IdleTimeoutMs;
    uint64_t MtuDiscoverySearchCompleteTimeoutUs;
    uint32_t TlsClientMaxSendBuffer;
    uint32_t TlsServerMaxSendBuffer;
    uint32_t StreamRecvWindowDefault;
    uint32_t StreamRecvBufferDefault;
    uint32_t ConnFlowControlWindow;
    uint32_t MaxWorkerQueueDelayUs;
    uint32_t MaxStatelessOperations;
    uint32_t InitialWindowPackets;
    uint32_t SendIdleTimeoutMs;
    uint32_t InitialRttMs;
    uint32_t MaxAckDelayMs;
    uint32_t DisconnectTimeoutMs;
    uint32_t KeepAliveIntervalMs;
    uint16_t CongestionControlAlgorithm; // QUIC_CONGESTION_CONTROL_ALGORITHM
    uint16_t PeerBidiStreamCount;
    uint16_t PeerUnidiStreamCount;
    uint16_t MaxBindingStatelessOperations;
    uint16_t StatelessOperationExpirationMs;
    uint16_t MinimumMtu;
    uint16_t MaximumMtu;
    uint8_t SendBufferingEnabled            : 1;
    uint8_t PacingEnabled                   : 1;
    uint8_t MigrationEnabled                : 1;
    uint8_t DatagramReceiveEnabled          : 1;
    uint8_t ServerResumptionLevel           : 2;    // QUIC_SERVER_RESUMPTION_LEVEL
    uint8_t RESERVED                        : 2;
    uint8_t MaxOperationsPerDrain;
    uint8_t MtuDiscoveryMissingProbeCount;

} QUIC_SETTINGS;
```

# Members

`IsSetFlags`

The set of flags that indicate which other struct members are valid.

`MaxBytesPerKey`

Maximum number of bytes to encrypt with a single 1-RTT encryption key before initiating key update.

**Default value:** 274,877,906,944

`HandshakeIdleTimeoutMs`

How long a handshake can idle before it is discarded.

**Default value:** 10,000

`IdleTimeoutMs`

How long a connection can go idle before it is gracefully shut down. 0 to disable timeout.

**Default value:** 30,000

`TlsClientMaxSendBuffer`

How much client TLS data to buffer.  If the application expects large client certificates, or long client certificate chains, this value should be increased.

**Default value:** 4,096

`TlsServerMaxSendBuffer`

How much server TLS data to buffer.  If the application expects very large server certificates, or long server certificate chains, this value should be increased.

**Default value:**  8,192

`StreamRecvWindowDefault`

Initial stream receive window size.

**Default value:** 32,768

`StreamRecvBufferDefault`

Stream initial buffer size.

**Default value:** 4,096

`ConnFlowControlWindow`

Connection-wide flow control window.

**Default value:** 16,777,216

`MaxWorkerQueueDelayUs`

The maximum queue delay (in microseconds) allowed for a worker thread. This affects loss detection and probe timeouts.

**Default value:** 250,000

`MaxStatelessOperations`

The maximum number of stateless operations that may be queued on a worker at any one time.

**Default value:** 16

`InitialWindowPackets`

The size (in packets) of the initial congestion window for a connection.

**Default value:** 10

`SendIdleTimeoutMs`

Reset congestion control after being idle `SendIdleTimeoutMs` milliseconds.

**Default value:** 1,000

`InitialRttMs`

Initial RTT estimate.

**Default value:** 333

`MaxAckDelayMs`

How long to wait after receiving data before sending an ACK. This controls batch sending ACKs, to get higher throughput with less overhead. Too long causes retransmits from the peer, too short wastefully sends ACKs.

**Default value:** 25

`DisconnectTimeoutMs`

How long to wait for an ACK before declaring a path dead and disconnecting.

**Default value:** 16,000

`KeepAliveIntervalMs`

How often to send PING frames to keep a connection alive. This also helps keep NAT table entries from expiring.

**Default value:** 0 (disabled)

`PeerBidiStreamCount`

Number of bidirectional streams to allow the peer to open. Must be non-zero to allow the peer to open any streams at all.

**Default value:** 0

`PeerUnidiStreamCount`

Number of unidirectional streams to allow the peer to open. Must be non-zero to allow the peer to open any streams at all.

**Default value:** 0

`RetryMemoryLimit`

The percentage of available memory usable for handshake connections before stateless retry is used. Calculated as `N/65535`. Global setting, not per-connection/configuration.

**Default value:** 65 (~0.1%)

`LoadBalancingMode`

 Global setting, not per-connection/configuration.

**Default value:** 0 (disabled)

`MaxOperationsPerDrain`

The maximum number of operations to drain per connection quantum.

**Default value:** 16

`SendBufferingEnabled`

Buffer send data within MsQuic instead of holding application buffers until sent data is acknowledged.

**Default value:** 1 (`TRUE`)

`PacingEnabled`

Pace sending to avoid overfilling buffers on the path.

**Default value:** 1 (`TRUE`)

`MigrationEnabled`

Enable clients to migrate IP addresses and tuples. Requires the server to be behind a cooperative load-balancer, or behind no load-balancer.

**Default value:** 1 (`TRUE`)

`DatagramReceiveEnabled`

Advertise support for QUIC datagram extension. Both sides of a connection need to set this to `TRUE` for [DatagramSend](DatagramSend.md) to be functional and supported.

**Default value:** 0 (`FALSE`)

`ServerResumptionLevel`

Server only. Controls resumption tickets and/or 0-RTT server support. `QUIC_SERVER_RESUME_ONLY` enables sending and receiving TLS resumption tickets. The server app must call [ConnectionSendResumptionTicket](./ConnectionSendResumptionTicket.md) to send a resumption ticket to the client. `QUIC_SERVER_RESUME_AND_ZERORTT` enables sending and receiving TLS resumption tickets and generating 0-RTT keys and receiving 0-RTT payloads. The server app may decide accept/reject each 0-RTT payload individually.

**Default value:** `QUIC_SERVER_NO_RESUME` (disabled)

`MinimumMtu`

The minimum MTU supported by a connection. This will be used as the starting MTU.

**Default value:** 1248

`MaximumMtu`

The maximum MTU supported by a connection. This will be the maximum probed value.

**Default value:** 1500

`MtuDiscoverySearchCompleteTimeoutUs`

The time in microseconds to wait before reattempting MTU probing if max was not reached.

**Default value:** 600000000

`MtuDiscoveryMissingProbeCount`

The number of MTU probes to retry before exiting MTU probing.

**Default value:** 3

`MaxBindingStatelessOperations`

The maximum number of stateless operations that may be queued on a binding at any one time.

**Default value:** 100

`StatelessOperationExpirationMs`

The time limit between operations for the same endpoint, in milliseconds.

**Default value:** 100

# Remarks

When setting new values for the settings, the app must set the corresponding `.IsSet.*` parameter for each actual parameter that is being set or updated. For example:

```C
QUIC_SETTINGS Settings {0};

//
// Configures the server's idle timeout.
//
Settings.IdleTimeoutMs = 60000; // 60 seconds
Settings.IsSet.IdleTimeoutMs = TRUE;

//
// Configures the server's resumption level to allow for resumption and 0-RTT.
//
Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
Settings.IsSet.ServerResumptionLevel = TRUE;
```

# See Also

[ConfigurationOpen](ConfigurationOpen.md)<br>
[GetParam](GetParam.md)<br>
[SetParam](SetParam.md)<br>
