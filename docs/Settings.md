# MsQuic Settings

MsQuic supports a number of configuration knobs (or settings). These settings can either be set dynamically (via the [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) structure) or via persistent storage (e.g. registry on Windows).

> **Warning**
> Generally MsQuic already choses the best / most correct default values for all settings. Settings should only be changed after due diligence and A/B testing is performed.

MsQuic settings are available on most MsQuic API objects. [Here](#api-object-parameters) we'll provide an overview of them with links to further details.

## Windows Registry

MsQuic supports most of the settings in the QUIC_SETTINGS struct in the registry to be loaded as defaults when the MsQuic library is loaded in a process.  These registry settings only provide the defaults; the application is free to change the settings with a call to [SetParam](./api/SetParam.md) or in [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) structs passed into [ConfigurationOpen](./api/ConfigurationOpen.md).

The default settings are updated automatically in the application when changing the registry, assuming the application hasn't already changed the setting, which overrides the registry value. However, this does not change the settings on Connections which are already established, or Configurations which are already created.

Note: MaxWorkerQueueDelay uses **milliseconds** in the registry, but uses microseconds (us) in the [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) struct.

The following settings are unique to the registry:

| Setting                            | Type     | Registry Name           | Default           | Description                                                                                                 |
|------------------------------------|----------|-------------------------|-------------------|-------------------------------------------------------------------------------------------------------------|
| Max Worker Queue Delay             | uint32_t | MaxWorkerQueueDelayMs   |               250 | The maximum queue delay (in ms) allowed for a worker thread.                                                |
| Max Partition Count                | uint16_t | MaxPartitionCount       |  System CPU count | The maximum processor count used for partitioning work in MsQuic. Max 512. **Restart is required.**         |

The following settings are available via registry as well as via [QUIC_SETTINGS](./api/QUIC_SETTINGS.md):

| Setting                            | Type       | Registry Name               | Default           | Description                                                                                                                   |
|------------------------------------|------------|-----------------------------|-------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Max Bytes per Key                  | uint64_t   | MaxBytesPerKey              |   274,877,906,944 | Maximum number of bytes to encrypt with a single 1-RTT encryption key before initiating key update.                           |
| Handshake Idle Timeout             | uint64_t   | HandshakeIdleTimeoutMs      |            10,000 | How long a handshake can idle before it is discarded.                                                                         |
| Idle Timeout                       | uint64_t   | IdleTimeoutMs               |            30,000 | How long a connection can go idle before it is silently shut down. 0 to disable timeout                                       |
| Max TLS Send Buffer (Client)       | uint32_t   | TlsClientMaxSendBuffer      |             4,096 | How much client TLS data to buffer.                                                                                           |
| Max TLS Send Buffer (Server)       | uint32_t   | TlsServerMaxSendBuffer      |             8,192 | How much server TLS data to buffer.                                                                                           |
| Stream Receive Window              | uint32_t   | StreamRecvWindowDefault     |            65,536 | Initial stream receive window size for all stream types.                                                                      |
| Stream Receive Window (Bidirectional, locally created) | uint32_t   | StreamRecvWindowBidiLocalDefault |            - | If set, overrides stream receive window size for locally initiated bidirectional streams.                                     |
| Stream Receive Window (Bidirectional, remotely created) | uint32_t   | StreamRecvWindowBidiRemoteDefault |            - | If set, overrides stream receive window size for remote initiated bidirectional streams.                                     |
| Stream Receive Window (Unidirectional) | uint32_t   | StreamRecvWindowUnidiDefault |            - | If set, overrides stream receive window size for remote initiated unidirectional streams.                                     |
| Stream Receive Buffer              | uint32_t   | StreamRecvBufferDefault     |             4,096 | Stream initial buffer size.                                                                                                   |
| Flow Control Window                | uint32_t   | ConnFlowControlWindow       |        16,777,216 | Connection-wide flow control window.                                                                                          |
| Max Stateless Operations           | uint32_t   | MaxStatelessOperations      |                16 | The maximum number of stateless operations that may be queued on a worker at any one time.                                    |
| Initial Window                     | uint32_t   | InitialWindowPackets        |                10 | The size (in packets) of the initial congestion window for a connection.                                                      |
| Send Idle Timeout                  | uint32_t   | SendIdleTimeoutMs           |             1,000 | Reset congestion control after being idle `SendIdleTimeoutMs` milliseconds.                                                   |
| Initial RTT                        | uint32_t   | InitialRttMs                |               333 | Initial RTT estimate.                                                                                                         |
| Max ACK Delay                      | uint32_t   | MaxAckDelayMs               |                25 | How long to wait after receiving data before sending an ACK.                                                                  |
| Disconnect Timeout                 | uint32_t   | DisconnectTimeoutMs         |            16,000 | How long to wait for an ACK before declaring a path dead and disconnecting.                                                   |
| Keep Alive Interval                | uint32_t   | KeepAliveIntervalMs         |      0 (disabled) | How often to send PING frames to keep a connection alive.                                                                     |
| Idle Timeout Period Changes DestCid| uint32_t   | DestCidUpdateIdleTimeoutMs  |            20,000 | Idle timeout period after which the destination CID is updated before sending again.                                          |
| Peer Stream Count (Bidirectional)  | uint16_t   | PeerBidiStreamCount         |                 0 | Number of bidirectional streams to allow the peer to open.                                                                    |
| Peer Stream Count (Unidirectional) | uint16_t   | PeerUnidiStreamCount        |                 0 | Number of unidirectional streams to allow the peer to open.                                                                   |
| Retry Memory Limit                 | uint16_t   | RetryMemoryFraction         |        65 (~0.1%) | The percentage of available memory usable for handshake connections before stateless retry is used. Calculated as `N/65535`.  |
| Load Balancing Mode                | uint16_t   | LoadBalancingMode           |      0 (disabled) | Global setting, not per-connection/configuration.                                                                             |
| Max Operations per Drain           | uint8_t    | MaxOperationsPerDrain       |                16 | The maximum number of operations to drain per connection quantum.                                                             |
| Send Buffering                     | uint8_t    | SendBufferingEnabled        |          1 (TRUE) | Buffer send data within MsQuic instead of holding application buffers until sent data is acknowledged.                        |
| Send Pacing                        | uint8_t    | PacingEnabled               |          1 (TRUE) | Pace sending to avoid overfilling buffers on the path.                                                                        |
| Client Migration Support           | uint8_t    | MigrationEnabled            |          1 (TRUE) | Enable clients to migrate IP addresses and tuples. Requires a cooperative load-balancer, or no load-balancer.                 |
| Datagram Receive Support           | uint8_t    | DatagramReceiveEnabled      |         0 (FALSE) | Advertise support for QUIC datagram extension.                                                                                |
| Server Resumption Level            | uint8_t    | ServerResumptionLevel       | 0 (No resumption) | Server only. Controls resumption tickets and/or 0-RTT server support.                                                         |
| Grease Quic Bit Support            | uint8_t    | GreaseQuicBitEnabled        |         0 (FALSE) | Advertise support for Grease QUIC Bit extension.                                                                              |
| Minimum MTU                        | uint16_t   | MinimumMtu                  |              1288 | The minimum MTU supported by a connection. This will be used as the starting MTU.                                             |
| Maximum MTU                        | uint16_t   | MaximumMtu                  |              1500 | The maximum MTU supported by a connection. This will be the maximum probed value.                                             |
| MTU Discovery Search Timeout       | uint64_t   | MtuDiscoverySearchCompleteTimeoutUs | 600000000 | The time in microseconds to wait before reattempting MTU probing if max was not reached.                                      |
| MTU Discovery Missing Probe Count  | uint8_t    | MtuDiscoveryMissingProbeCount  |              3 | The number of MTU probes to retry before exiting MTU probing.                                                                 |
| Max Binding Stateless Operations   | uint16_t   | MaxBindingStatelessOperations  |            100 | The maximum number of stateless operations that may be queued on a binding at any one time.                                   |
| Stateless Operation Expiration     | uint16_t   | StatelessOperationExpirationMs |            100 | The time limit between operations for the same endpoint, in milliseconds.                                                     |
| Congestion Control Algorithm       | uint16_t   | CongestionControlAlgorithm  |         0 (Cubic) | The congestion control algorithm used for the connection.                                                                     |
| ECN                                | uint8_t    | EcnEnabled                  |         0 (FALSE) | Enable sender-side ECN support.                                                                                               |
| Stream Multi Receive               | uint8_t    | StreamMultiReceiveEnabled   |         0 (FALSE) | Enable multi receive support                                                                                                  |
| XDP                                | uint8_t    | XdpEnabled                  |         0 (FALSE) | Enable XDP. |
| QTIP                               | uint8_t    | QTIPEnabled                 |         0 (FALSE) | Enable QTIP. XDP must be used. Clients will only send/recv QTIP xor UDP traffic, listeners accept both. [More info](./QTIP.md)|
| RIO                                | uint8_t    | RioEnabled                  |         0 (FALSE) | Enable RIO. |

The types map to registry types as follows:
  - `uint64_t` is a `REG_QWORD`.
  - `uint32_t`, `uint16_t`, and `uint8_t` are `REG_DWORD`.

While `REG_DWORD` can hold values larger than `uint16_t`, the administrator should ensure they do not exceed the maximum value of 65,535 when configuring a `uint16_t` setting via the Windows Registry.

The following settings are available via registry as well as via [QUIC_VERSION_SETTINGS](./Versions.md):

| Setting                           | Type       | Registry Name                | Default           | Description                                                                                                                   |
|-----------------------------------|------------|------------------------------|-------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Acceptable Versions List          | uint32_t[] | AcceptableVersions           | Unset             | Sets the list of versions that a given server instance will use if a client sends a first flight using them. |
| Offered Versions List             | uint32_t[] | OfferedVersions              | Unset             | Sets the list of versions that a given server instance will send in a Version Negotiation packet if it receives a first flight from an unknown version. This list will most often be equal to the Acceptable Versions list. |
| Fully-Deployed Versions List      | uint32_t[] | FullyDeployedVersions        | Unset             | Sets the list of QUIC versions that is supported and negotiated by every single QUIC server instance in this deployment. Used to generate the AvailableVersions list in the Version Negotiation Extension Transport Parameter. |
| Version Negotiation Ext. Enabled  | uint32_t   | VersionNegotiationExtEnabled | 0 (FALSE)         | Enables the Version Negotiation Extension. |

The `uint32_t[]` type is a `REG_BINARY` blob of the versions list, with each version in little-endian format.

All restrictions and effects on the versions mentioned in [QUIC_VERSION_SETTINGS](./Versions.md) apply to the registry-set versions as well.

Particularly, on server, these must be set **GLOBALLY** if you want them to take effect for servers.

## QUIC_SETTINGS

A [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) struct is used to configure settings on a `Configuration` handle, `Connection` handle, or globally.

For more details see [QUIC_SETTINGS](./api/QUIC_SETTINGS.md).

# API Object Parameters

MsQuic API Objects have a number of settings, or parameters, which can be queried via [GetParam](api/GetParam.md), or can be set/modifed via [SetParam](api/SetParam.md).

## Global Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_GLOBAL_*` and a `NULL` object handle.

| Setting                                           | Type                    | Get/Set   | Description                                                                                           |
|---------------------------------------------------|-------------------------|-----------|-------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT`<br> 0    | uint16_t                | Both      | The percentage of available memory usable for handshake connections before stateless retry is used.   |
| `QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS`<br> 1      | uint32_t[]              | Get-only  | List of QUIC protocol versions supported in network byte order.                                       |
| `QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE`<br> 2      | uint16_t                | Both      | Must be a `QUIC_LOAD_BALANCING_MODE`.                                                                 |
| `QUIC_PARAM_GLOBAL_PERF_COUNTERS`<br> 3           | uint64_t[]              | Get-only  | Array size is QUIC_PERF_COUNTER_MAX.                                                                  |
| `QUIC_PARAM_GLOBAL_LIBRARY_VERSION`<br> 4         | uint32_t[4]             | Get-only  | MsQuic API version.                                                                                   |
| `QUIC_PARAM_GLOBAL_SETTINGS`<br> 5                | QUIC_SETTINGS           | Both      | Globally change settings for all subsequent connections.                                              |
| `QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS`<br> 6         | QUIC_GLOBAL_SETTINGS    | Both      | Globally change global only settings.                                                                 |
| `QUIC_PARAM_GLOBAL_VERSION_SETTINGS`<br> 7        | QUIC_VERSIONS_SETTINGS  | Both      | Globally change version settings for all subsequent connections.                                      |
| `QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH`<br> 8        | char[64]                | Get-only  | Git hash used to build MsQuic (null terminated string)                                                |
| `QUIC_PARAM_GLOBAL_EXECUTION_CONFIG`<br> 9 (preview)        | QUIC_GLOBAL_EXECUTION_CONFIG   | Both      | Globally configure the execution model used for QUIC. Must be set before opening registration.        |
| `QUIC_PARAM_GLOBAL_TLS_PROVIDER`<br> 10           | QUIC_TLS_PROVIDER       | Get-Only  | The TLS provider being used by MsQuic for the TLS handshake.                                          |
| `QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY`<br> 11    | uint8_t[]               | Set-Only  | Globally change the stateless reset key for all subsequent connections.                               |
| `QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES`<br> 12    | uint32_t[]               | Get-only  | Array of well-known sizes for each version of the QUIC_STATISTICS_V2 struct. The output array length is variable; pass a buffer of uint32_t and check BufferLength for the number of sizes returned. See GetParam documentation for usage details. |
| `QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED`<br> (preview) | uint8_t (BOOLEAN) | Both | Globally enable the version negotiation extension for all client and server connections. |

## Registration Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_REGISTRATION_*` and a Registration object handle.

| Setting                                           | Type          | Get/Set   | Description                                                                                           |
|---------------------------------------------------|---------------|-----------|-------------------------------------------------------------------------------------------------------|

## Configuration Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_CONFIGURATION_*` and a Configuration object handle.

| Setting                                                          | Type                                   | Get/Set   | Description                                                                                                       |
|------------------------------------------------------------------|----------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_CONFIGURATION_SETTINGS`<br> 0                        | QUIC_SETTINGS                          | Both      | Settings to use for all connections sharing this Configuration. See [QUIC_SETTINGS](./api/QUIC_SETTINGS.md).      |
| `QUIC_PARAM_CONFIGURATION_TICKET_KEYS`<br> 1                     | QUIC_TICKET_KEY_CONFIG[]               | Set-only  | Resumption ticket encryption keys. Server-side only.                                                              |
| `QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS`<br> 2                | QUIC_VERSIONS_SETTINGS                 | Both      | Change version settings for all connections on the configuration.                                                 |
| `QUIC_PARAM_CONFIGURATION_SCHANNEL_CREDENTIAL_ATTRIBUTE_W`<br> 3 | QUIC_SCHANNEL_CREDENTIAL_ATTRIBUTE_W   | Set-only  | Calls `SetCredentialsAttributesW` with the supplied attribute and buffer on the credential handle. Schannel-only. Only valid once the credential has been loaded.  |
| `QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED`<br> (preview)     | uint8_t (BOOLEAN)                      | Both      | Enables the version negotiation extension for all client connections on the configuration. |

## Listener Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_LISTENER_*` and a Listener object handle.

| Setting                                   | Type                      | Get/Set   | Description                                               |
|-------------------------------------------|---------------------------|-----------|-----------------------------------------------------------|
| `QUIC_PARAM_LISTENER_LOCAL_ADDRESS`<br> 0 | QUIC_ADDR                 | Get-only  | Get the full address tuple the server is listening on.    |
| `QUIC_PARAM_LISTENER_STATS`<br> 1         | QUIC_LISTENER_STATISTICS  | Get-only  | Get statistics specific to this Listener instance.        |
| `QUIC_PARAM_LISTENER_CIBIR_ID`<br> 2      | uint8_t[]                 | Both      | The CIBIR well-known idenfitier.                          |
| `QUIC_PARAM_DOS_MODE_EVENTS`<br> 2        | BOOLEAN                   | Both      | The Listener opted in for DoS Mode event.                 |

## Connection Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_CONNECTION_*` and a Connection object handle.

| Setting                                           | Type                          | Get/Set   | Description                                                                               |
|---------------------------------------------------|-------------------------------|-----------|-------------------------------------------------------------------------------------------|
| `QUIC_PARAM_CONN_QUIC_VERSION`<br> 0              | uint32_t                      | Get-only  | Negotiated QUIC protocol version                                                          |
| `QUIC_PARAM_CONN_LOCAL_ADDRESS`<br> 1             | QUIC_ADDR                     | Both      | Set on client only. Must be set before start or after handshake confirmed.                |
| `QUIC_PARAM_CONN_REMOTE_ADDRESS`<br> 2            | QUIC_ADDR                     | Both      | Set on client only. Must be set before start.                                             |
| `QUIC_PARAM_CONN_IDEAL_PROCESSOR`<br> 3           | uint16_t                      | Get-only  | Ideal processor for the app to send from.                                                 |
| `QUIC_PARAM_CONN_SETTINGS`<br> 4                  | QUIC_SETTINGS                 | Both      | Connection settings. See [QUIC_SETTINGS](./api/QUIC_SETTINGS.md)                          |
| `QUIC_PARAM_CONN_STATISTICS`<br> 5                | QUIC_STATISTICS               | Get-only  | Connection-level statistics.                                                              |
| `QUIC_PARAM_CONN_STATISTICS_PLAT`<br> 6           | QUIC_STATISTICS               | Get-only  | Connection-level statistics with platform-specific time format.                           |
| `QUIC_PARAM_CONN_SHARE_UDP_BINDING`<br> 7         | uint8_t (BOOLEAN)             | Both      | Set on client only. Must be called before start.                                          |
| `QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT`<br> 8   | uint16_t                      | Get-only  | Number of bidirectional streams available.                                                |
| `QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT`<br> 9  | uint16_t                      | Get-only  | Number of unidirectional streams available.                                               |
| `QUIC_PARAM_CONN_MAX_STREAM_IDS`<br> 10           | uint64_t[4]                   | Get-only  | Array of number of client and server, bidirectional and unidirectional streams.           |
| `QUIC_PARAM_CONN_CLOSE_REASON_PHRASE`<br> 11      | char[]                        | Both      | Max length 512 chars.                                                                     |
| `QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME`<br> 12 | QUIC_STREAM_SCHEDULING_SCHEME | Both      | Whether to use FIFO or round-robin stream scheduling.                                     |
| `QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED`<br> 13 | uint8_t (BOOLEAN)             | Both      | Indicate/query support for QUIC datagram extension. Must be set before start.             |
| `QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED`<br> 14    | uint8_t (BOOLEAN)             | Get-only  | Indicates peer advertised support for QUIC datagram extension. Call after connected.      |
| `QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION`<br> 15  | uint8_t (BOOLEAN)             | Both      | Application must `#define QUIC_API_ENABLE_INSECURE_FEATURES` before including msquic.h.   |
| `QUIC_PARAM_CONN_RESUMPTION_TICKET`<br> 16        | uint8_t[]                     | Set-only  | Must be set on client before starting connection.                                         |
| `QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID`<br> 17   | uint8_t (BOOLEAN)             | Set-only  | Used for asynchronous custom certificate validation. *Deprecated soon. Replaced by [ConnectionCertificateValidationComplete]*                                     |
| `QUIC_PARAM_CONN_LOCAL_INTERFACE`<br> 18          | uint32_t                      | Set-only  | The local interface index to bind to.                                                     |
| `QUIC_PARAM_CONN_TLS_SECRETS`<br> 19              | QUIC_TLS_SECRETS              | Set-only  | The TLS secrets struct to be populated by MsQuic.                                         |
| `QUIC_PARAM_CONN_VERSION_SETTINGS`<br> 20         | QUIC_VERSION_SETTINGS         | Both      | The desired QUIC versions for the connection.                                             |
| `QUIC_PARAM_CONN_CIBIR_ID`<br> 21                 | uint8_t[]                     | Set-only  | The CIBIR well-known identifier.                                                          |
| `QUIC_PARAM_CONN_STATISTICS_V2`<br> 22            | QUIC_STATISTICS_V2            | Get-only  | Connection-level statistics, version 2.                                                   |
| `QUIC_PARAM_CONN_STATISTICS_V2_PLAT`<br> 23       | QUIC_STATISTICS_V2            | Get-only  | Connection-level statistics with platform-specific time format, version 2.                |
| `QUIC_PARAM_CONN_ORIG_DEST_CID` <br> 24           | uint8_t[]                     | Get-only  | The original destination connection ID used by the client to connect to the server.       |
| `QUIC_PARAM_CONN_SEND_DSCP` <br> 25               | uint8_t                       | Both      | The DiffServ Code Point put in the DiffServ field (formerly TypeOfService/TrafficClass) on packets sent from this connection. |

### QUIC_PARAM_CONN_STATISTICS_V2

Querying the `QUIC_STATISTICS_V2` struct via `QUIC_PARAM_CONN_STATISTICS_V2` or `QUIC_PARAM_CONN_STATISTICS_V2_PLAT` should be aware of possible changes in the size of the struct, depending on the version of MsQuic the app using at runtime, not just what it was compiled against.

The minimum size of the struct will always be `QUIC_STATISTICS_V2_SIZE_1`. Future version of MsQuic will append new fields to the end of the struct, so the maximum possible size will increase.

When an app queries for the statistics, it must always supply an input buffer of length at least `QUIC_STATISTICS_V2_SIZE_1`, but `sizeof(QUIC_STATISTICS_V2)` will always work as well. MsQuic will support older callers that supply at least that buffer size, even if the maximum size of the struct has grown in a future version of MsQuic. MsQuic will only write the fields that can completely fit in the buffer supplied by the app.

## TLS Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_TLS_*` and a Connection object handle.

| Setting                                   | Type                      | Get/Set   | Description                                                                                                               |
|-------------------------------------------|---------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_TLS_HANDSHAKE_INFO`<br> 0     | QUIC_HANDSHAKE_INFO       | Get-only  | Called in the `QUIC_CONNECTION_EVENT_CONNECTED` event to get the cryptographic parameters negotiated in the handshake.    |
| `QUIC_PARAM_TLS_NEGOTIATED_ALPN`<br> 1    | uint8_t[] (max 255 bytes) | Get-only  | Called in the `QUIC_CONNECTION_EVENT_CONNECTED` event to get the negotiated ALPN.                                         |

## Schannel-only TLS Parameters

These parameters are access by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_TLS_SCHANNEL_*` and a Connection object handle.

| Setting                                                | Type                                 | Get/Set   | Description                                                                                                                                                   |
|--------------------------------------------------------|--------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W`<br> 0    | QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W    | Get-only  | Calls `QueryContextAttributesW` for the given attribute and buffer. Only valid until the `QUIC_CONNECTION_EVENT_CONNECTED` event, or when TLS is cleaned up.   |
| `QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W`<br> 1 | QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W | Get-only  | Calls `QueryContextAttributesExW` for the given attribute and buffer. Only valid until the `QUIC_CONNECTION_EVENT_CONNECTED` event, or when TLS is cleaned up. |
| `QUIC_PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN`<br> 2 | HANDLE                               | Get-only  | Calls `QuerySecurityContextToken` on the Schannel handle. Only valid until the `QUIC_CONNECTION_EVENT_CONNECTED` event, or when TLS is cleaned up.            |

## Stream Parameters

These parameters are access by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_STREAM_*` and a Stream object handle.

| Setting                                           | Type              | Get/Set   | Description                                                                           |
|---------------------------------------------------|-------------------|-----------|---------------------------------------------------------------------------------------|
| `QUIC_PARAM_STREAM_ID`<br> 0                      | QUIC_UINT62       | Get-only  | Must be called on a stream after [StreamStart](./api/StreamStart.md) is called.      |
| `QUIC_PARAM_STREAM_0RTT_LENGTH`<br> 1             | uint64_t          | Get-only  | Length of 0-RTT data received from peer.                                              |
| `QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE`<br> 2  | uint64_t - bytes  | Get-only  | Ideal buffer size to queue to the stream. Assumes only one stream sends steadily.     |
| `QUIC_PARAM_STREAM_PRIORITY` <br> 3               | uint16_t          | Get/Set   | A value from 0x0 to 0xFFFF that indicates the Stream priority. 0xFFFF is highest priority. Data on higher priority stream get sent first. All streams start with priority 0x7FFF by default.  |
| `QUIC_PARAM_STREAM_STATISTICS` <br> 4             | QUIC_STREAM_STATISTICS | Get-only  | Stream-level statistics. |
| `QUIC_PARAM_STREAM_RELIABLE_OFFSET` <br> 5        | uint64_t          | Get/Set   | Part of the new Reliable Reset preview feature. Sets/Gets the number of bytes a sender must send before closing SEND path.

## See Also

[QUIC_SETTINGS](./api/QUIC_SETTINGS.md)<br>
[GetParam](./api/GetParam.md)<br>
[SetParam](./api/SetParam.md)<br>

[ConnectionCertificateValidationComplete]: ./api/ConnectionCertificateValidationComplete.md
