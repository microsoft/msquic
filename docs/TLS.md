MsQuic TLS Abstraction Layer
======

MsQuic includes TLS in the general "Platform Abstraction Layer" or PAL. This interface provides all the functionality required of TLS by the QUIC protocol, as defined by the IETF [QUIC-TLS](https://datatracker.ietf.org/doc/html/rfc9001) spec.

# High-Level Overview

At the TLS abstraction layer there is only one core interface/function that does most all the work: `CxPlatTlsProcessData`. The `ProcessData` function takes a number of parameters on input and then provides all the necessary output. The execution of this function drives the TLS state machine.

This function executes very similarly to many existing (non-QUIC) TLS APIs with the following exceptions:

1. The TLS record layer is not included.
2. TLS exposes the encryption key material to QUIC to secure its own packets.

Generally, the calling pattern for the function starts with the client calling `ProcessData` with a `null` input. It then takes the output data, encrypts it accordingly and sends it to the server. The server decrypts it and passes the data to TLS (via its own `ProcesData` call) and then gets its own output. This goes back and forth until the handshake is complete, and TLS has no other data it needs to exchange.

### Input

- The TLS context pointer.
- The CRYPTO buffer received from the peer. This is null/empty for the client's initial call.

### Output

- Any CRYPTO buffer to send to the peer. This may be null/empty.
- The associated encryption level at which the CRYPTO buffer must be secured.
- Any new read or write encryption key material.
- Any other state or meta information, such as negotiated ALPN, handshake completion, session resumption, alerts, etc.

## Additional Functionality

Beyond the core functionality described above, there are a few other functions:

### QUIC Transport Parameters

QUIC has a custom TLS extension it uses on client and server to exchange QUIC specific configuration. The TLS library must support setting and retrieving this information.

### Session Resumption Tickets

When a TLS session is resumed, QUIC is required to use the same QUIC layer configuration previously exchanged in the Transport Parameters. This allows QUIC to do things like apply the appropriate flow control limits to 0-RTT data. In order for this functionality to be achieved at the QUIC layer, the TLS library must allow for QUIC to embed QUIC information in the session resumption ticket (NST) and recall it on session resumption.

# Implementations

MsQuic has a number of implementations for the TLS abstraction layer to support out various platforms and scenarios.

## Schannel

[Schannel](https://docs.microsoft.com/en-us/windows/win32/com/schannel) is officially supported for Windows user mode and Windows kernel mode. It requires the latest Windows versions (Windows Server 2022 or Insider Preview) to function. Only the newest versions support TLS 1.3 and the necessary APIs for QUIC functionality. Currently, 0-RTT is not supported, and resumption is only partially supported.

## OpenSSL

[OpenSSL](https://www.openssl.org/) is the primary TLS library by MsQuic on Linux. It is also works on Windows, but Schannel is preferred if supported by your OS build.

> **Important** - Currently, OpenSSL doesn't officially have QUIC API support (hopefully coming soon), so MsQuic **temporarily** relies on a [fork of OpenSSL](https://github.com/quictls/openssl) that is purely a fork + a set of (unapproved by OMC) changes to expose some QUIC functionality. This fork is only a **stopgap solution** until OpenSSL officially supports QUIC, at which MsQuic will immediately switch to it.

# Detailed Design

TO-DO
