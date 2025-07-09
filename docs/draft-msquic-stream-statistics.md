# QUIC Stream Timing Statistics Extension

## Abstract

This document defines a QUIC extension that enables endpoints to exchange stream timing statistics, allowing each peer to gain insight into the time spent in various stream and connection states. This information is useful for performance diagnostics and optimization.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of BCP 78 and BCP 79.

## Introduction

QUIC endpoints currently maintain and expose various timing statistics related to stream and connection state, such as time spent blocked by flow control or congestion control. However, these statistics are only available locally. This extension defines a mechanism for endpoints to send their stream timing statistics to their peer, enabling improved diagnostics and performance analysis.

## Motivation

By sharing timing statistics, endpoints (e.g., servers) can better understand where time is being spent on the peer (e.g., client), such as time blocked by flow control, congestion control, or application-level events. This can help identify bottlenecks and optimize performance.

## Protocol Overview

This extension defines a new QUIC frame, the STREAM_STATISTICS frame, which is sent by an endpoint when it shuts down the send path of a stream. The frame carries timing statistics for the stream, using a standardized format.

## Frame Definition

The STREAM_STATISTICS frame is defined as follows:

```
STREAM_STATISTICS Frame {
  Type (i) = 0xFB,
  StreamId (i),
  ConnBlockedBySchedulingUs (i),
  ConnBlockedByPacingUs (i),
  ConnBlockedByAmplificationProtUs (i),
  ConnBlockedByCongestionControlUs (i),
  ConnBlockedByFlowControlUs (i),
  StreamBlockedByIdFlowControlUs (i),
  StreamBlockedByFlowControlUs (i),
  StreamBlockedByAppUs (i),
}
```

All fields are encoded as QUIC variable-length integers (see [QUIC Transport, Section 16](https://datatracker.ietf.org/doc/html/rfc9000#section-16)), representing microseconds spent in each state.

> **Note:** The frame type value 0xFB is a temporary assignment for development and discussion purposes. The final value will be determined through IANA registration.

## Transport Parameter Negotiation

Support for the STREAM_STATISTICS extension is negotiated using a new transport parameter, `stream_statistics` (0x73FB) [TEMPORARY VALUE]. An endpoint includes this transport parameter during the handshake to indicate support for sending and receiving the STREAM_STATISTICS frame.

The `stream_statistics` transport parameter is encoded as an empty value (i.e., zero-length), serving as a flag. If both endpoints send this transport parameter, the extension is enabled for the connection and both endpoints MUST send the STREAM_STATISTICS frame as specified.

If the transport parameter is not present in either endpoint's handshake, the extension is not enabled and the frame MUST NOT be sent or processed.

> **Note:** The transport parameter ID 0x73FB is a temporary assignment for development and discussion purposes. The final value will be determined through IANA registration.

## Frame Transmission

An endpoint that supports this extension sends a STREAM_STATISTICS frame on the stream when shutting down its send path. The frame is sent only once per stream, and only if the peer has indicated support for the extension during connection setup (e.g., via a transport parameter).

## Security Considerations

Exposing timing statistics may reveal information about endpoint behavior or resource usage. Implementations should consider privacy and security implications before enabling this extension.

## IANA Considerations

This document requests the assignment of a new frame type for STREAM_STATISTICS in the QUIC Frame Types registry.

## Acknowledgments

TBD

## References

TBD
