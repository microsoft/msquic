# Deploying MsQuic

MsQuic is used as the basis for several different protocols (HTTP, SMB, etc.), but they all have several things in common when it comes time to deploy them. This document outlines the various things that must be taken into account whenever deploying an MsQuic based solution.

# Configuration

MsQuic supports a number of configuration knobs (or settings). These settings can either be set dynamically (via the `QUIC_SETTINGS` structure) or via persistent storage (e.g. registry on Windows).

| Setting                  | Type     | Name                   | Description                                                                                           | Restart<br>Required |
|--------------------------|----------|------------------------|-------------------------------------------------------------------------------------------------------|---------------------|
| Max Partition Count      | uint16_t | MaxPartitionCount      | The maximum processor count used for partitioning work in MsQuic                                      | Yes                 |
| Max Operations per Drain | uint8_t  | MaxOperationsPerDrain  | The maximum number of operations to drain per connection quantum                                      | No                  |
| Retry Memory Limit       | uint16_t | RetryMemoryFraction    | The percentage of available memory usable for handshake connections before stateless retry is used    | No                  |
| Max Worker Queue Delay   | uint32_t | MaxWorkerQueueDelayMs  | The maximum queue delay (in ms) allowed for a worker thread                                           | No                  |
| Max Stateless Operations | uint32_t | MaxStatelessOperations | The maximum number of stateless operations that may be queued at any one time                         | No                  |
| Initial Window Size      | uint32_t | InitialWindowPackets   | The size (in packets) of the initial congestion window for a connection                               | No                  |
|                          |          |                        |                                                                                                       |                    |

**TODO** - Finish list above

## Windows

On Windows, these settings can set via the registry. The main registry path for the keys is:

> HKLM:\System\CurrentControlSet\Services\MsQuic\Parameters

The settings can also be set per "app-name" (as indicated in `RegistrationOpen`):

> HKLM:\System\CurrentControlSet\Services\MsQuic\Parameters\app-name

The `DWORD` type should be used for all 32-bit or less types. For 64-bit types, `DWORD` or `QWORD` may be used. If invalid types or values are used, they will be ignored and the built-in default will be used instead.

For example, to set the **Initial Window Size** setting to `20` packets, you may do the following:
```
reg.exe add "HKLM\System\CurrentControlSet\Services\MsQuic\Parameters" /v InitialWindowPackets /t REG_DWORD /d 20
```

# Cipher Suites

## Windows

By default, the new cipher suite `TLS_CHACHA20_POLY1305_SHA256` is disabled. It can be enabled via the following command:

```PowerShell
Enable-TlsCipherSuite -Name TLS_CHACHA20_POLY1305_SHA256
```

# Firewall

## Windows

In order to configure the Windows firewall to allow inbound QUIC traffic efficiently, use a command such as the one below.

```PowerShell
New-NetFirewallRule -DisplayName "Allow QUIC" -Direction Inbound -Protocol UDP -LocalPort 433 -Action Allow -LocalOnlyMapping $true
```

Note the use of the `-LocalOnlyMapping $true` argument. This is a performance optimizing feature that should be used for UDP based protocols (like QUIC). See [MSDN](https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) for additional details.

# Load Balancing

MsQuic currently supports a load balancing mode where the server encodes the local IPv4 address or IPv6 suffix into bytes 1 through 4 of the connection IDs it creates. You can read more details about the general encoding in [draft-ietf-quic-load-balancers](https://github.com/quicwg/load-balancers/blob/master/draft-ietf-quic-load-balancers.md#plaintext-cid-algorithm-plaintext-cid-algorithm).

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  First octet  |             Server ID (X=8..152)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Any (0..152-X)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`Server ID` is 4 bytes long, as encodes the complete IPv4 address OR the last 4 bytes of the IPv6 address.

This encoding is **not enabled by default**. To configure it, set the `LoadBalancingMode` setting to `1`. **Note** - The server must be restarted for this setting to take effect.

# DoS Mitigations

MsQuic has a few built in DoS mitigations (server side).

## Stateless Retry

MsQuic tracks the number of outstanding connections currently in the handshake state. When that reaches a certain threshold, MsQuic will start forcing clients to retry before the connection will be accepted. This entails the following:

- The server sends back a "Stateless Retry" packet with an encrypted token to the client.
- The server drops the incoming packet and doesn't save any state.
- The client must then reply back with its initial packet, this time including the encrypted token.
- The server validates the token, and only if successful, accept the connection.

This protects the server from naive attackers trying to flood the server with new connection attempts; especially in scenarios where the client is spoofing its source IP address in an attempt to avoid attribution.

The threshold mentioned above is currently tracked as a percentage of total avaialble (nonpaged pool) memory. This percentage of avaiable memory can be configured via the `RetryMemoryFraction` setting.

## Overloaded Worker Threads

MsQuic uses worker threads internally to execute the QUIC protocol logic. For each worker thread, MsQuic tracks the average queue delay for any work done on one of these threads. This queue delay is simply the time from when the work is added to the queue to when the work is removed from the queue. If this delay hits a certain threshold, then existing connections can start to suffer (i.e. spurious packet loss, decreased throughput, or even connection failures). In order to prevent this, new connections are rejected with the SERVER_BUSY error, when this threshold is reached.

The queue delay threshold can be configured via the `MaxWorkerQueueDelayMs` setting.
