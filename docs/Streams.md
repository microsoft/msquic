Using Streams
======

Streams are the primary mechanism apps use to reliably exchange data with their peer. Streams can be opened by either peer (client or server) and can be unidirectional or bidirectional. So, there are 4 types of streams:

- Client initiated, unidirectional stream
- Server initiated, unidirectional stream
- Client initiated, bidirectional stream
- Server initiated, bidirectional stream

# Stream ID Flow Control

The QUIC protocol allows for a possibly maximum number of streams equal to 2 ^ 62. So, per stream type, the maximum number of streams is 2 ^ 60. This is obviously a very large number and no app would likely ever need to have anywhere close to this number of streams open at any point in time.

For this reason, each app controls the number of streams that the peer is allowed to open. The concept is similar to flow control of the actual data on a stream. The app tells the peer how much it's willing to accept at any point in time. Instead of a buffer size, for it's a stream count.

The actual protocol for synchronizing maximum stream count is somewhat complicated, but MsQuic simplifies the design by requiring the app to specify a number of simultaneous streams to allow the peer to open at any time. MsQuic then takes care of updating the maximum stream count for the peer as old streams get shutdown.

The app can configure the unidirection and bidirectional limit separately. **The default value for these is 0.** If the app wants to allow the peer to open any streams, it must set a value. To set the limit on a connection, the app must call [SetParam](v1/SetParam.md) for `QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT` and/or `QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT`. MsQuic currently restricts this count to a maximum of 2 ^ 16.

# Opening and Starting Streams

An app calls [StreamOpen](v1/StreamOpen.md) to allocate a new stream object. Then the app calls [StreamStart](v1/StreamStart.md) to actually start the using the stream. After that, the peer can send and receive data on the stream.

With MsQuic, the peer's stream ID flow control can have several different behaviors when starting a stream. When calling [StreamStart](v1/StreamStart.md) the app passes a set of `QUIC_STREAM_START_FLAGS` flags to control these behaviors. They have the following affect on the start call:

- `QUIC_STREAM_START_FLAG_NONE` - The stream will be started independent of the peer's flow control value. If the peer's flow control currently limits the stream from actually being started currently, the stream will just be internally queued until it can actually be started.

- `QUIC_STREAM_START_FLAG_FAIL_BLOCKED` - If the peer's flow control currently limits the stream from actually being opened, then the start will fail.

- `QUIC_STREAM_START_FLAG_IMMEDIATE` - Even if there is currently no data to send on the stream, MsQuic will inform the peer of the stream being opened. Without this flag, MsQuic will wait until data is queued on the stream.

- `QUIC_STREAM_START_FLAG_ASYNC` - The StreamStart call will not block. The result of the start can be retried from the `QUIC_STREAM_EVENT_START_COMPLETE` event.

For peer initiated streams, the app gets a `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` event on the connection. A stream is officially started when this event or the `QUIC_STREAM_EVENT_START_COMPLETE` is received. Once started, the app can immediately call [StreamSend](v1/StreamSend.md) or start getting `QUIC_STREAM_EVENT_RECEIVE` events.

# Sending

An app can send on a locally initiated unidirectional stream or a peer initiated bidirectional stream. The app uses the [StreamSend](v1/StreamSend.md) API queue data to be reliably sent. MsQuic holds on to any buffers queued via [StreamSend](v1/StreamSend.md) until they have been completed via the `QUIC_STREAM_EVENT_SEND_COMPLETE` event.

## Send Buffering

## Ideal Send Buffer

## Send Shutdown

## 0-RTT

# Receiving

**TODO**
