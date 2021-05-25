# MsQuic Settings

MsQuic supports a number of configuration knobs (or settings). These settings can either be set dynamically (via the [`QUIC_SETTINGS`](.\api\QUIC_SETTINGS.md) structure) or via persistent storage (e.g. registry on Windows).

> **Important** - Generally MsQuic already choses the best / most correct default values for all settings. Settings should only be changed after due diligence and A/B testing is performed.

MsQuic settings are available on most MsQuic objects. Here we'll provide an overview of them with links to further details.

## Windows Registry

MsQuic supports most of the settings in the QUIC_SETTINGS struct in the registry to be loaded as defaults when the MsQuic library is loaded in a process.  These registry settings only provide the defaults; the application is free to change the settings with a call to `SetParam` or in `QUIC_SETTINGS` structs passed into `ConfigurationOpen`.

In kernel mode, the default settings are updated automatically in the process when changing the registry, assuming the application hasn't already changed the setting. which overrides the registry value.

Note: MaxWorkerQueueDelay uses **milliseconds** in the registry, but uses microseconds (us) in the `QUIC_SETTINGS` struct.

The following settings are unique to the registry:

| Setting                            | Type     | Registry Name           | Description                                                                                        |
| Max Worker Queue Delay             | uint32_t | MaxWorkerQueueDelayMs   | The maximum queue delay (in ms) allowed for a worker thread.                                       |
| Max Partition Count                | uint16_t | MaxPartitionCount       | The maximum processor count used for partitioning work in MsQuic. **Restart is required.**         |

## QUIC_SETTINGS

For more details see [`QUIC_SETTINGS`](.\api\QUIC_SETTINGS.md).

| Setting                            | Type     | Registry Name                 | Description                                                                                        |
|------------------------------------|----------|-------------------------------|----------------------------------------------------------------------------------------------------|
| Max Bytes per Key                  | uint64_t | MaxBytesPerKey                | Maximum number of bytes to send using a given 1-RTT encryption key before initiating key change.   |
| Handshake Idle Timeout             | uint64_t | HandshakeIdleTimeoutMs        |                                                                                                    |
| Idle Timeout                       | uint64_t | IdleTimeoutMs                 |                                                                                                    |
| Max TLS Send Buffer (Client)       | uint32_t | TlsClientMaxSendBuffer        |                                                                                                    |
| Max TLS Send Buffer (Server)       | uint32_t | TlsServerMaxSendBuffer        |                                                                                                    |
| Stream Receive Window              | uint32_t | StreamRecvWindowDefault       |                                                                                                    |
| Stream Receive Buffer              | uint32_t | StreamRecvBufferDefault       |                                                                                                    |
| Flow Control Window                | uint32_t | ConnFlowControlWindow         |                                                                                                    |
| Max Worker Queue Delay             | uint32_t | MaxWorkerQueueDelayUs         | The maximum queue delay (in us) allowed for a worker thread.                                       |
| Max Stateless Operations           | uint32_t | MaxStatelessOperations        | The maximum number of stateless operations that may be queued at any one time.                     |
| Initial Window                     | uint32_t | InitialWindowPackets          | The size (in packets) of the initial congestion window for a connection.                           |
| Send Idle Timeout                  | uint32_t | SendIdleTimeoutMs             |                                                                                                    |
| Initial RTT                        | uint32_t | InitialRttMs                  |                                                                                                    |
| Max ACK Delay                      | uint32_t | MaxAckDelayMs                 |                                                                                                    |
| Disconnect Timeout                 | uint32_t | DisconnectTimeoutMs           |                                                                                                    |
| Keep Alive Interval                | uint32_t | KeepAliveIntervalMs           |                                                                                                    |
| Peer Stream Count (Bidirectional)  | uint16_t | PeerBidiStreamCount           |                                                                                                    |
| Peer Stream Count (Unidirectional) | uint16_t | PeerUnidiStreamCount          |                                                                                                    |
| Retry Memory Limit                 | uint16_t | RetryMemoryFraction           | The percentage of available memory usable for handshake connections before stateless retry is used.|
| Load Balancing Mode                | uint16_t | LoadBalancingMode             | Global setting; affects all connections.                                                           |
| Max Operations per Drain           | uint8_t  | MaxOperationsPerDrain         | The maximum number of operations to drain per connection quantum.                                  |
| Send Buffering                     | uint8_t  | SendBufferingEnabled          |                                                                                                    |
| Send Pacing                        | uint8_t  | PacingEnabled                 |                                                                                                    |
| Client Migration Support           | uint8_t  | MigrationEnabled              |                                                                                                    |
| Datagram Receive Support           | uint8_t  | DatagramReceiveEnabled        |                                                                                                    |
| Server Resumption Level            | uint8_t  | ServerResumptionLevel         |                                                                                                    |
| Version Negotiation Extension      | uint8_t  | VersionNegotiationExtEnabled  |                                                                                                    |
| Desired Versions List              | uint32_t*| N/A                           | Only takes effect if Version Negotiation is enabled.                                               |
| Desired Versions List Length       | uint32_t | N/A                           | Number of QUIC protocol versions in the DesiredVersionsList.                                       |

## Global Parameters

| Setting                                           | Type          | Get/Set   | Description                                                                                           |
|---------------------------------------------------|---------------|-----------|-------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT`<br> 0    | uint16_t      | Both      | The percentage of available memory usable for handshake connections before stateless retry is used.   |
| `QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS`<br> 1      | uint32_t[]    | Both      | List of QUIC protocol versions supported in network byte order.                                       |
| `QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE`<br> 2      | uint16_t      | Both      | Must be a `QUIC_LOAD_BALANCING_MODE`.                                                                 |
| `QUIC_PARAM_GLOBAL_PERF_COUNTERS`<br> 3           | uint64_t[]    | Get-only  | Array size is QUIC_PERF_COUNTER_MAX.                                                                  |
| `QUIC_PARAM_GLOBAL_SETTINGS`<br> 4                | QUIC_SETTINGS | Both      | Globally change settings for all connections.                                                         |
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