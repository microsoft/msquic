# Deploying MsQuic

MsQuic is used as the basis for several different protocols (HTTP, SMB, etc.), but they all have several things in common when it comes time to deploy them. This document outlines the various things that must be taken into account whenever deploying an MsQuic based solution.

## Deploying QUIC

Generally, for any existing TCP based deployments that are adding QUIC support, there are a number of things to be considered. Many things are different between a TCP based solution and a QUIC based one, including breaking some pretty "core" assumptions made for TCP:

- QUIC uses UDP instead of TCP.
  - Any firewalls or other network devices must take this into account, and make sure this traffic is allowed.
- QUIC traffic is designed to be generally indistinguishable from other UDP traffic.
  - Network devices must not assume UDP traffic on any port is QUIC unless explicitly configured.
- Current QUIC based protocols primarily use port 443 on the server, but not necessarily exclusively.
  - HTTP and SMB use this port, but other protocols (e.g. DNS over QUIC) likely will not.
- QUIC is versioned and extensible, and thus is expected to be very dynamic on the network.
  - Network devices must not assume anything about the structure of a QUIC packet beyond what is stated in the [Invariants RFC](https://datatracker.ietf.org/doc/html/rfc8999).
- QUIC is completely encrypted end to end.
  - Most information that might have been viewable on a TCP connection is now only visible to the endpoints.
- A single UDP flow or tuple (address + port) does not necessarily map to a single connection.
  - A single QUIC connection may span multiple flows.
  - Multiple QUIC connections may share a single flow.
- NAT bindings for UDP flows on the internet generally timeout much quicker than TCP; resulting in flow changes much more often.
  - QUIC, as a protocol, is able to survive these changes, unlike TCP.

For more details, please see the [Manageability draft](https://tools.ietf.org/html/draft-ietf-quic-manageability).

# Configuration

Please see [Settings](Settings.md) for information on MsQuic configuration.

## Windows

On Windows, these settings can set via the registry and will persist across reboots and build upgrades. For most settings, a reboot is not required for them to immediately take effect. Also note that updated settings will only affect new connections (not existing ones).

The main registry path for the keys is:

> HKLM:\System\CurrentControlSet\Services\MsQuic\Parameters

The settings can also be set per "app-name" (as indicated in [RegistrationOpen](.\api\RegistrationOpen.md)):

> HKLM:\System\CurrentControlSet\Services\MsQuic\Parameters\app-name

The `DWORD` type should be used for all 32-bit or less types. For 64-bit types, `DWORD` or `QWORD` may be used. If invalid types or values are used, they will be ignored and the built-in default will be used instead.

For example, to set the **Initial Window Size** setting to `20` packets, you may do the following:
```
reg.exe add "HKLM\System\CurrentControlSet\Services\MsQuic\Parameters" /v InitialWindowPackets /t REG_DWORD /d 20
```

# Cipher Suites

## Windows

> **Important** - ChaCha20-Poly1305 is not yet supported with MsQuic and Schannel, so this doesn't do anything yet.

By default, the new cipher suite `TLS_CHACHA20_POLY1305_SHA256` is disabled. It can be enabled via the following command:

```PowerShell
Enable-TlsCipherSuite -Name TLS_CHACHA20_POLY1305_SHA256
```

# Firewall

## Windows

In order to configure the Windows firewall to allow inbound QUIC traffic efficiently, use a command such as the one below. Generally, the firewall rule should be applied for all scenarios, unless a layer below you (e.g. IIS) is already doing it on your behalf.

```PowerShell
New-NetFirewallRule -DisplayName "Allow QUIC" -Direction Inbound -Protocol UDP -LocalPort 443 -Action Allow -LocalOnlyMapping $true
```

Note the use of the `-LocalOnlyMapping $true` argument. This is a performance optimizing feature that should be used for UDP based protocols (like QUIC). See [MSDN](https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule) for additional details.

# Load Balancing

MsQuic currently supports a load balancing mode where the server encodes the local IPv4 address or IPv6 suffix into bytes 1 through 4 of the connection IDs it creates. You can read more details about the general encoding in [Load Balancers draft](https://tools.ietf.org/html/draft-ietf-quic-load-balancers-04#section-4.1).

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

To use this load balancing model, the load balancer must support the model described above and be explicitly configured to enable it for your endpoint.

# Client Migration

Client migration is a key feature in the QUIC protocol that allows for the connection to survive changes in the client's IP address or UDP port. MsQuic generally supports this but it requires QUIC load balancing support (when using a load balancer). QUIC encodes a connection identifier (connection ID or CID) in every packet it sends. This CID allows a server to encode routing information that a coordinating load balancer can use to route the packet, instead of using the IP tuple as most existing load balancers currently use to route UDP traffic.

## NAT Rebindings without Load Balancing Support

If your deployment does not have QUIC load balancing support then you will not be able to make sure of the client migration feature described above to survive any NAT rebindings that change the client's IP tuple (from the server's perspective). This can be especially painful for any services migrating from a TCP based solution to QUIC, since most middleboxes on the internet have a much smaller timeout period for UDP (20 to 30 seconds) compared to TCP. This means any QUIC connection that goes idle for greater than ~20 seconds runs the risk of getting rebound by the NAT the next time the client sends a packet, resulting in a tuple change, and then likely resulting in the packet getting routed to the incorrect load balanced server.

The mitigation to this problem is to enable QUIC keep alives. They can be enabled on either the client or server side, but only need to be enabled on one side. They can be enabled either dynamically in the code or globally via the settings. To enable keep alives via the settings, set the `KeepAliveIntervalMs` setting to a reasonable value, such as `20000` (20 seconds).

# DoS Mitigations

MsQuic has a few built-in denial of service mitigations (server side).

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

# Diagnostics

For details on how to diagnose any issues with your deployment at the MsQuic layer see [Diagnostics](Diagnostics.md).
