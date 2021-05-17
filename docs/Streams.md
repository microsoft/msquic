Using Streams
======

Streams are the primary mechanism apps use to reliably exchange data with their peer. Streams can be opened by either peer (client or server) and can be unidirectional (can only send) or bidirectional (can send and receive). So, there are 4 types of streams:

- Client initiated, unidirectional stream
- Server initiated, unidirectional stream
- Client initiated, bidirectional stream
- Server initiated, bidirectional stream

# Stream ID Flow Control

The QUIC protocol allows a maximum number of streams equal to 2 ^ 62. As there are 4 unique stream types, the maximum number of streams is 2 ^ 60, per stream type. No app would likely need to have this many streams open at any point.

For this reason, each app controls the number of streams that the peer is allowed to open. The concept is similar to flow control of the actual data on a stream. The app tells the peer how many streams it's willing to accept at any point. Instead of a buffer size, it's a stream count.

The protocol for synchronizing the maximum stream count is complicated, but MsQuic simplifies it by requiring the app to specify a number of simultaneous streams to allow the peer to open at any time. MsQuic then takes care of updating the maximum stream count for the peer as old streams get shut down.

The app can configure the unidirectional and bidirectional limits separately. **The default value for these is 0.** If the app wants to allow the peer to open any streams, it must set a value. To set the limit on a connection, the app must call [SetParam](api/SetParam.md) for `QUIC_PARAM_CONN_PEER_BIDI_STREAM_COUNT` and/or `QUIC_PARAM_CONN_PEER_UNIDI_STREAM_COUNT`. MsQuic currently restricts this count to a maximum of 2 ^ 16.

# Opening and Starting Streams

An app calls [StreamOpen](api/StreamOpen.md) to allocate a new stream. The stream object returned from [StreamOpen](api/StreamOpen.md) is locally usable. The app can call any other stream API on the object, but until the stream is started all operations are essentially queued. While in this state the stream has no ID and generates no "on-wire" changes.

If a stream is closed ([StreamClose](api/StreamClose.md)) before being successfully started, the app essentially abandons the stream. No on-wire changes will ever result from that stream.

To start using the stream on-wire, the app calls [StreamStart](api/StreamStart.md). On success, all queued operations (i.e. sends or shutdown) will immediately trigger, and the stream can start receiving `QUIC_STREAM_EVENT_RECEIVE` events.

When calling [StreamStart](api/StreamStart.md) the app passes a set of `QUIC_STREAM_START_FLAGS` flags to control the behavior. Starting the stream **always** results in a `QUIC_STREAM_EVENT_START_COMPLETE` event, regardless of success/fail or synchronous/asynchronous flags.

For peer initiated streams, the app gets a `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` event on the connection. A stream is officially started when this event or the `QUIC_STREAM_EVENT_START_COMPLETE` event is received.

# Sending

An app can send on any locally initiated stream or a peer initiated bidirectional stream. The app uses the [StreamSend](api/StreamSend.md) API send data. MsQuic holds on to any buffers queued via [StreamSend](api/StreamSend.md) until they have been completed via the `QUIC_STREAM_EVENT_SEND_COMPLETE` event.

## Send Buffering

There are two buffering modes for sending supported by MsQuic. The first mode has MsQuic buffer the stream data internally. As long as there is room to buffer the data, MsQuic will copy the data locally and then immediately complete the send back to the app, via the `QUIC_STREAM_EVENT_SEND_COMPLETE` event. If there is no room to copy the data, then MsQuic will hold onto the buffer until there is room.

With this mode, the app can "keep the pipe full" using only a single outstanding send. It continually keeps a send pending on the stream. When the send is completed, the app immediately queues a send again with any new data it has.

This is seen by many as the simplest design for apps, but does introduce an additional copy in the data path, which has some performance draw backs. **This is the default MsQuic behavior.**

The other buffering mode supported by MsQuic requires no internal copy of the data. MsQuic holds onto the app buffers until all the data has been acknowledged by the peer.

To fill the pipe in this mode, the app is responsible for keeping enough sends pending at all times to ensure the connection doesn't go idle. MsQuic indicates the amount of data the app should keep pending in the `QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE` event. The app should always have at least two sends pending at a time. If only a single send is used, the connection can go idle for the time between that send is completed and the new send is queued.

By default, this mode is not used. To enable this mode, the app must call [SetParam](api/SetParam.md) on the connection with the `QUIC_PARAM_CONN_SEND_BUFFERING` parameter set to `FALSE`.

## Send Shutdown

The send direction can be shut down in three different ways:

- **Graceful** - The sender can gracefully shut down the send direction by calling [StreamShutdown](api/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL` flag or by including the `QUIC_SEND_FLAG_FIN` flag on the last [StreamSend](api/StreamSend.md) call. In this scenario all data will be delivered to the peer and then the peer is informed the stream has been gracefully shut down.

- **Sender Abort** - The sender can abortively shut down the send direction by calling [StreamShutdown](api/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND` flag. In this scenario, all outstanding sends are immediately canceled and are not delivered to the peer. The peer is immediately informed of the abort.

- **Receiver Abort** - The receiver can abortively shut down their peer's send direction. When this happens the sender will get a `QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED` event.

When the send has been completely shut down the app will get a `QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE` event. This will happen immediately on an abortive send or after a graceful send has been acknowledged by the peer.

## 0-RTT

An app can opt in to sending stream data with 0-RTT keys (if available) by including the `QUIC_SEND_FLAG_ALLOW_0_RTT` flag on [StreamSend](api/StreamSend.md) call. MsQuic doesn't make any guarantees that the data will actually be sent with 0-RTT keys. There are several reasons it may not happen, such as keys not being available, packet loss, flow control, etc.

# Receiving

Data is received and delivered to apps via the `QUIC_STREAM_EVENT_RECEIVE` event. The event indicates one or more contiguous buffers up to the application. The app then may respond to the event in a number of ways:

## Synchronous vs Asynchronous

The app has the option of either processing the received data in the callback (synchronous) or queuing the work to a separate thread (asynchronous). If the app processes the data synchronously it must do so in a timely manner. Any significant delays will delay other QUIC processing (such as sending acknowledgements), which can cause protocol issues (dropped connections).

If the app wants to queue the data to a separate thread, the app must return `QUIC_STATUS_PENDING` from the receive callback. This informs MsQuic that the app still has an outstanding reference on the buffers, and it will not modify or free them. Once the app is done with the buffers it must call [StreamReceiveComplete](api/StreamReceiveComplete.md).

## Partial Data Acceptance

Whenever the app gets the `QUIC_STREAM_EVENT_RECEIVE` event, it can partially accept/consume the received data.

For synchronous receives, the app indicates how much of the data it accepted via the **TotalBufferLength** variable in the payload of the `QUIC_STREAM_EVENT_RECEIVE` event. On input, that variable indicates the total amount of data being indicated. On output (return from the callback), the variable is taken as how much data the app consumed. By default, if the variable is left unmodified, then all data is assumed to be accepted.

For asynchronous receives, the app indicates how much of the data it accepted via the **BufferLength** parameter passed into the [StreamReceiveComplete](api/StreamReceiveComplete.md) API.

Any value less than or equal to the initial **TotalBufferLength** value is allowed, including zero.

Whenever a receive isn't fully accepted by the app, additional receive events are immediately disabled. The app is assumed to be at capacity and not able to consume more until further indication. To re-enable receive callbacks, the app must call [StreamReceiveSetEnabled](api/StreamReceiveSetEnabled.md).

There are cases where an app may want to partially accept the current data, but still immediately get a callback with the rest of the data. To do this (only works in the synchronous flow) the app must return `QUIC_STATUS_CONTINUE`.