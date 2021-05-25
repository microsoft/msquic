# MsQuic Settings

MsQuic supports a number of configuration knobs (or settings). These settings can either be set dynamically (via the [`QUIC_SETTINGS`](.\api\QUIC_SETTINGS.md) structure) or via persistent storage (e.g. registry on Windows).

> **Important** - Generally MsQuic already choses the best / most correct default values for all settings. Settings should only be changed after due diligence and A/B testing is performed.

MsQuic settings are available on most MsQuic objects. Here we'll provide an overview of them with links to further details.

## Windows Registry

MsQuic supports most of the settings in the QUIC_SETTINGS struct in the registry to be loaded as defaults when the MsQuic library is loaded in a process.  These registry settings only provide the defaults; the application is free to change the settings with a call to `SetParam` or in `QUIC_SETTINGS` structs passed into `ConfigurationOpen`.

In kernel mode, the default settings are updated automatically in the process when changing the registry, assuming the application hasn't already changed the setting. which overrides the registry value.

Note: MaxWorkerQueueDelay uses **milliseconds** in the registry, but uses microseconds (us) in the `QUIC_SETTINGS` struct.

The following settings are unique to the registry:

| Setting                            | Type     | Registry Name           | Default           | Description                                                                                                 |
|------------------------------------|----------|-------------------------|-------------------|-------------------------------------------------------------------------------------------------------------|
| Max Worker Queue Delay             | uint32_t | MaxWorkerQueueDelayMs   |               250 | The maximum queue delay (in ms) allowed for a worker thread.                                                |
| Max Partition Count                | uint16_t | MaxPartitionCount       |  System CPU count | The maximum processor count used for partitioning work in MsQuic. Max 512. **Restart is required.**         |

## QUIC_SETTINGS

For more details see [`QUIC_SETTINGS`](.\api\QUIC_SETTINGS.md).

| Setting                            | Type     | Registry Name                 | Default           | Description                                                                                        |
|------------------------------------|----------|-------------------------------|-------------------|----------------------------------------------------------------------------------------------------|
| Max Bytes per Key                  | uint64_t | MaxBytesPerKey                |   274,877,906,944 | Maximum number of bytes to send using a given 1-RTT encryption key before initiating key change.   |
| Handshake Idle Timeout             | uint64_t | HandshakeIdleTimeoutMs        |            10,000 |                                                                                                    |
| Idle Timeout                       | uint64_t | IdleTimeoutMs                 |            30,000 |                                                                                                    |
| Max TLS Send Buffer (Client)       | uint32_t | TlsClientMaxSendBuffer        |             4,096 |                                                                                                    |
| Max TLS Send Buffer (Server)       | uint32_t | TlsServerMaxSendBuffer        |             8,192 |                                                                                                    |
| Stream Receive Window              | uint32_t | StreamRecvWindowDefault       |            32,768 |                                                                                                    |
| Stream Receive Buffer              | uint32_t | StreamRecvBufferDefault       |             4,096 |                                                                                                    |
| Flow Control Window                | uint32_t | ConnFlowControlWindow         |        16,777,216 |                                                                                                    |
| Max Worker Queue Delay             | uint32_t | MaxWorkerQueueDelayUs         |           250,000 | The maximum queue delay (in us) allowed for a worker thread.                                       |
| Max Stateless Operations           | uint32_t | MaxStatelessOperations        |                16 | The maximum number of stateless operations that may be queued at any one time.                     |
| Initial Window                     | uint32_t | InitialWindowPackets          |                10 | The size (in packets) of the initial congestion window for a connection.                           |
| Send Idle Timeout                  | uint32_t | SendIdleTimeoutMs             |             1,000 |                                                                                                    |
| Initial RTT                        | uint32_t | InitialRttMs                  |               333 |                                                                                                    |
| Max ACK Delay                      | uint32_t | MaxAckDelayMs                 |                25 |                                                                                                    |
| Disconnect Timeout                 | uint32_t | DisconnectTimeoutMs           |            16,000 |                                                                                                    |
| Keep Alive Interval                | uint32_t | KeepAliveIntervalMs           |      0 (disabled) |                                                                                                    |
| Peer Stream Count (Bidirectional)  | uint16_t | PeerBidiStreamCount           |                 0 |                                                                                                    |
| Peer Stream Count (Unidirectional) | uint16_t | PeerUnidiStreamCount          |                 0 |                                                                                                    |
| Retry Memory Limit                 | uint16_t | RetryMemoryFraction           |                65 | The percentage of available memory usable for handshake connections before stateless retry is used.|
| Load Balancing Mode                | uint16_t | LoadBalancingMode             |      0 (disabled) | Global setting; affects all connections.                                                           |
| Max Operations per Drain           | uint8_t  | MaxOperationsPerDrain         |                16 | The maximum number of operations to drain per connection quantum.                                  |
| Send Buffering                     | uint8_t  | SendBufferingEnabled          |          1 (TRUE) |                                                                                                    |
| Send Pacing                        | uint8_t  | PacingEnabled                 |          1 (TRUE) |                                                                                                    |
| Client Migration Support           | uint8_t  | MigrationEnabled              |          1 (TRUE) |                                                                                                    |
| Datagram Receive Support           | uint8_t  | DatagramReceiveEnabled        |         0 (FALSE) |                                                                                                    |
| Server Resumption Level            | uint8_t  | ServerResumptionLevel         | 0 (No resumption) |                                                                                                    |
| Version Negotiation Extension      | uint8_t  | VersionNegotiationExtEnabled  |         0 (FALSE) |                                                                                                    |
| Desired Versions List              | uint32_t*| N/A                           |              NULL | Only takes effect if Version Negotiation is enabled.                                               |
| Desired Versions List Length       | uint32_t | N/A                           |                 0 | Number of QUIC protocol versions in the DesiredVersionsList.                                       |

## Global Parameters

| Setting                                           | Type          | Get/Set   | Description                                                                                           |
|---------------------------------------------------|---------------|-----------|-------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT`<br> 0    | uint16_t      | Both      | The percentage of available memory usable for handshake connections before stateless retry is used.   |
| `QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS`<br> 1      | uint32_t[]    | Get-only  | List of QUIC protocol versions supported in network byte order.                                       |
| `QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE`<br> 2      | uint16_t      | Both      | Must be a `QUIC_LOAD_BALANCING_MODE`.                                                                 |
| `QUIC_PARAM_GLOBAL_PERF_COUNTERS`<br> 3           | uint64_t[]    | Get-only  | Array size is QUIC_PERF_COUNTER_MAX.                                                                  |
| `QUIC_PARAM_GLOBAL_SETTINGS`<br> 4                | QUIC_SETTINGS | Both      | Globally change default settings for all connections.                                                 |
| `QUIC_PARAM_GLOBAL_VERSION`<br> 5                 | uint32_t[4]   | Get-only  | MsQuic API version.                                                                                   |

## Registration Parameters

| Setting                                           | Type          | Get/Set   | Description                                                                                           |
|---------------------------------------------------|---------------|-----------|-------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_REGISTRATION_CID_PREFIX`<br> 0        | uint8_t[]     | Both      | CID prefix to prepend to all CIDs. Used for load balancing.                                           |

## Configuration Parameters

| Setting                                           | Type                      | Get/Set   | Description                                                                               |
|---------------------------------------------------|---------------------------|-----------|-------------------------------------------------------------------------------------------|
| `QUIC_PARAM_CONFIGURATION_SETTINGS`<br> 0         | QUIC_SETTINGS             | Both      |                                                                                           |
| `QUIC_PARAM_CONFIGURATION_TICKET_KEYS`<br> 1      | QUIC_TICKET_KEY_CONFIG[]  | Set-only  | Resumption ticket encryption keys. Server-side only.                                      |

## Listener Parameters

| Setting                                           | Type                      | Get/Set   | Description                                                                               |
|---------------------------------------------------|---------------------------|-----------|-------------------------------------------------------------------------------------------|
| `QUIC_PARAM_LISTENER_LOCAL_ADDRESS`<br> 0         | QUIC_ADDR                 | Get-only  | Get the full address tuple the server is listening on.                                    |
| `QUIC_PARAM_LISTENER_STATS`<br> 1                 | QUIC_LISTENER_STATISTICS  | Get-only  |                                                                                           |

## Connection Parameters

| Setting                                           | Type                          | Get/Set   | Description                                                                           |
|---------------------------------------------------|-------------------------------|-----------|---------------------------------------------------------------------------------------|
| `QUIC_PARAM_CONN_QUIC_VERSION`<br> 0              | uint32_t                      | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_LOCAL_ADDRESS`<br> 1             | QUIC_ADDR                     | Both      |                                                                                       |
| `QUIC_PARAM_CONN_REMOTE_ADDRESS`<br> 2            | QUIC_ADDR                     | Both      | Set on client only.                                                                   |
| `QUIC_PARAM_CONN_IDEAL_PROCESSOR`<br> 3           | uint16_t                      | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_SETTINGS`<br> 4                  | QUIC_SETTINGS                 | Both      |                                                                                       |
| `QUIC_PARAM_CONN_STATISTICS`<br> 5                | QUIC_STATISTICS               | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_STATISTICS_PLAT`<br> 6           | QUIC_STATISTICS               | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_SHARE_UDP_BINDING`<br> 7         | uint8_t (BOOLEAN)             | Both      | Set on client  only.                                                                  |
| `QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT`<br> 8   | uint16_t                      | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT`<br> 9  | uint16_t                      | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_MAX_STREAM_IDS`<br> 10           | uint64_t[4]                   | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_CLOSE_REASON_PHRASE`<br> 11      | char[]                        | Both      | Max length 512 chars.                                                                 |
| `QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME`<br> 12 | QUIC_STREAM_SCHEDULING_SCHEME | Both      |                                                                                       |
| `QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED`<br> 13 | uint8_t (BOOLEAN)             | Both      |                                                                                       |
| `QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED`<br> 14    | uint8_t (BOOLEAN)             | Get-only  |                                                                                       |
| `QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION`<br> 15  | uint8_t (BOOLEAN)             | Both      | Application must define `QUIC_API_ENABLE_INSECURE_FEATURES` before including msquic.h.|
| `QUIC_PARAM_CONN_RESUMPTION_TICKET`<br> 16        | uint8_t[]                     | Set-only  | Must be set on client before starting connection.                                     |
| `QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID`<br> 17   | uint8_t (BOOLEAN)             | Set-only  | Used for asynchronous custom certificate validation.                                  |

## See Also

[QUIC_SETTINGS](.\api\QUIC_SETTINGS.md)<br>
[GetParam](.\api\GetParam.md)<br>
[SetParam](.\api\SetParam.md)<br>