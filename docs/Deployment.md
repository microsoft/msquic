# Deploying MsQuic

MsQuic is used as the basis for several different protocols (HTTP, SMB, etc.), but they all have several things in common when it comes time to deploy them. This document outlines the various things that must be taken into account whenever deploying an MsQuic based solution.

## Configuration

MsQuic supports a number of configuration knobs (or settings). These settings can either be set dynamically (via the `QUIC_SETTINGS` structure) or via persistent storage (e.g. registry on Windows).

| Setting                  | Type     | Name                   | Description                                                      |
|--------------------------|----------|------------------------|------------------------------------------------------------------|
| Max Partition Count      | uint16_t | MaxPartitionCount      | The maximum processor count used for partitioning work in MsQuic |
| Max Operations per Drain | uint8_t  | MaxOperationsPerDrain  | The maximum number of operations to drain per connection quantum |
| Retry Memory Limit       | uint16_t | RetryMemoryFraction    |                                                                  |
| Max Worker Queue Delay   | uint32_t | MaxWorkerQueueDelayMs  |                                                                  |
| Max Stateless Operations | uint32_t | MaxStatelessOperations |                                                                  |
| Initial Window Size      | uint32_t | InitialWindowPackets   |                                                                  |

**TODO** - Finish list above

### Windows

On Windows, these settings can set via the registry. The main registry path for the keys is:

> HKLM:\System\CurrentControlSet\Services\MsQuic\Parameters

The settings can also be set per "app-name" (as indicated in `RegistrationOpen`):

> HKLM:\System\CurrentControlSet\Services\MsQuic\Parameters\app-name

## Cipher Suites

### Windows

By default, the new cipher suite `TLS_CHACHA20_POLY1305_SHA256` is disabled. It can be enabled via the following command:

```PowerShell
Enable-TlsCipherSuite -Name TLS_CHACHA20_POLY1305_SHA256
```

## Firewall

### Windows

In order to configure the Windows firewall to allow inbound QUIC traffic efficiently, use a command such as the one below.

```PowerShell
New-NetFirewallRule -DisplayName "Allow QUIC" -Direction Inbound -Protocol UDP -LocalPort 433 -Action Allow -LocalOnlyMapping $true
```

Note the use of the `-LocalOnlyMapping $true` argument. This is a performance optimizing feature that should be used for UDP based protocols (like QUIC).

## Load Balancing

MsQuic currently supports a load balancing mode where the server encodes the local IPv4 address or IPv6 suffix into bytes 1 through 4 of the connection IDs it creates. You can read more details about the general encoding [here](https://github.com/quicwg/load-balancers/blob/master/draft-ietf-quic-load-balancers.md#plaintext-cid-algorithm-plaintext-cid-algorithm).

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

This encoding is **not enabled by default**. To configure it, set the `LoadBalancingMode` configuration knob (type `uint32_t`) to `1`. **Note** - The server must be restarted for this setting to take effect.

## DoS Mitigation

MsQuic has a few built in DoS mitigations.

- **Retry** -

- **Drop New Connections** -
