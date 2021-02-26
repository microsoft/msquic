MsQuic TLS Abstraction Layer
======

MsQuic includes TLS in the general "platform abstraction layer" or PAL. This interface provides all the functionality required of TLS by the QUIC protocol, as defined by the IETF [QUIC-TLS](https://tools.ietf.org/html/draft-ietf-quic-tls) spec.

# High-Level Overview

At the TLS abstaction layer there is only one core interface/function that does most all the work: `CxPlatTlsProcessData`. The `ProcessData` function takes a number of things on input and then provides all the necessary output. The execution of this function drives the TLS state machine.

This function executes very similar to many existing (non-QUIC) TLS APIs with the following exceptions:

1. The TLS record layer is not included.
2. TLS exposes the encryption key material to QUIC to secure its own packets.

Generally, the calling pattern for the function starts with the client calling `ProcessData` with a `null` input. It takes the output data, encrypts it accordingly and sends it to the server. The server decrypts it, and passes the data to TLS (via its own `ProcesData` call) and then gets its own output. This goes back and forth until the handshake is complete and TLS has no other data it needs to exchange.

### Input

- The TLS context pointer.
- The CRYPTO buffer received from the peer. This is null/empty for the client's initial call.

### Output

- Any CRYPTO buffer to send to the peer. This may be null/empty.
- The associated encryption level the CRYPTO buffer must be secured at.
- Any new read or write encryption key material.
- Any other state or meta information, such as neogiated ALPN, handshake completion, session resumption, alerts, etc.

## Additional Functionality

Beyond the core functionality described above, there are a few other functions:

### QUIC Transport Parameters

QUIC has a custom TLS extension it uses on client and server to exchange QUIC specific configuration. The TLS library must support setting and retrieving this information.

### Session Resumption Tickets

When a TLS session is resumed, QUIC is required to use the same QUIC layer configuration previously exchanged in the Transport Parameters. This allows QUIC to do thing like apply the appropriate flow control limits to 0-RTT data. In order for this functionality to be achieved at the QUIC layer, the TLS library must allow for QUIC to embed QUIC information in the session resumption ticket (NST) and recall it on session resumption.

# Detailed Design

TO-DO
