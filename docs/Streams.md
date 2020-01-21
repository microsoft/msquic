Using Streams
======

Streams are the primary mechanism apps use to reliably exchange data with their peer. Streams can be opened by either peer (client or server) and can be unidirectional (can only send) or bidirectional (can send and receive). So, there are 4 types of streams:

- Client initiated, unidirectional stream
- Server initiated, unidirectional stream
- Client initiated, bidirectional stream
- Server initiated, bidirectional stream

# Stream ID Flow Control

The QUIC protocol allows for a possible maximum number of streams equal to 2 ^ 62. As there are 4 unique stream types, the maximum number of streams is 2 ^ 60. No app would likely ever need to have anywhere close to this number of streams open at any point in time.

For this reason, each app controls the number of streams that the peer is allowed to open. The concept is similar to flow control of the actual data on a stream. The app tells the peer how many streams it's willing to accept at any point in time. Instead of a buffer size, for it's for a stream count.

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

There are two buffering models for sending supported by MsQuic. The first model has MsQuic buffer the stream data internally. As long as there is room to buffer the data, MsQuic will copy the data locally and then immediately complete the send back to the app, via the `QUIC_STREAM_EVENT_SEND_COMPLETE` event. If there is no room to copy the data, then MsQuic will hold onto the buffer until there is room.

With this model, the app can keep the "pipe full" using only a single send buffer. It continually keeps the send pending on the stream. If/when it gets completed by MsQuic it immediately queues the buffer again with any new data it has.

This is seen by many as the simplest design for apps, but does introduce an additional copy in the data path, which has some performance draw backs. **This is the default MsQuic behavior.**

The other buffering model supported by MsQuic requires no internal copy of the data. MsQuic holds onto the app buffers until all the data has been acknowledged by the peer.

To fill the pipe, the app is responsible for keeping enough buffers pending at all times to ensure the connection doesn't go idle. MsQuic indicates the amount of data the app should keep pending in the `QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE` event. The app should always have at least two buffers pending at a time. If only a single buffer is used, the connection can go idle for the time between that buffer is completed and the new buffer is queued.

By default, this behavior is not used. To enable this behavior, the app must call [SetParam](v1/SetParam.md) on the connection with the `QUIC_PARAM_CONN_SEND_BUFFERING` parameter set to `FALSE`.

## Send Shutdown

The send direction can be shutdown in three different ways:

- **Graceful** - The sender can gracefully shutdown the send by calling [StreamShutdown](v1/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL` flag or by including the `QUIC_SEND_FLAG_FIN` flag on the last [StreamSend](v1/StreamSend.md) call. In this scenario all data will be delivered to the peer and then the peer is informed the stream has been gracefully shutdown.

- **Sender Abort** - The sender can abortively shutdown the send by calling [StreamShutdown](v1/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND` flag. In this scenario, all outstanding sends are immediately canceled and are not delivered to the peer. The peer is immediately informed of the abort.

- **Receiver Abort** - The receiver can abortively shutdown their peer's send direction. When this happens the sender will get a `QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED` event.

When the send has been completely shutdown the app will get a `QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE` event. This will happen immediately on an abortive send or after a graceful send has been acknowledged by the peer.

## 0-RTT

An app can opt in to sending stream data with 0-RTT keys (if available) by including the `QUIC_SEND_FLAG_ALLOW_0_RTT` flag on [StreamSend](v1/StreamSend.md) call. MsQuic doesn't make any guarantees that the data will actually be sent with 0-RTT keys. There are several reasons it may not happen, such as keys not being available, packet loss, flow control, etc.

# Receiving

**TODO**
