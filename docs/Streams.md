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

The app can configure the unidirectional and bidirectional limits separately. **The default value for these is 0.** If the app wants to allow the peer to open any streams, it must set a value. To set the limit on a connection, the app must configure the `PeerBidiStreamCount` and/or `PeerUnidiStreamCount` fields in [QUIC_SETTINGS](api/QUIC_SETTINGS.md) and apply them using [SetParam](api/SetParam.md) with `QUIC_PARAM_CONN_SETTINGS`, or provide them to [ConfigurationOpen](api/ConfigurationOpen.md). MsQuic currently restricts this count to a maximum of 65,535.

# Opening and Starting Streams

An app calls [StreamOpen](api/StreamOpen.md) to allocate a new stream. The stream object returned from [StreamOpen](api/StreamOpen.md) is locally usable. The app can call any other stream API on the object, but until the stream is started all operations are essentially queued. While in this state the stream has no ID and generates no "on-wire" changes.

If a stream is closed ([StreamClose](api/StreamClose.md)) before being successfully started, the app essentially abandons the stream. No on-wire changes will ever result from that stream.

To start using the stream on-wire, the app calls [StreamStart](api/StreamStart.md). On success, all queued operations (i.e. sends or shutdown) will immediately trigger, and the stream can start receiving `QUIC_STREAM_EVENT_RECEIVE` events.

When calling [StreamStart](api/StreamStart.md) the app passes a set of `QUIC_STREAM_START_FLAGS` flags to control the behavior. Starting the stream **always** results in a `QUIC_STREAM_EVENT_START_COMPLETE` event, regardless of success/fail or synchronous/asynchronous flags.

For peer initiated streams, the app gets a `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` event on the connection. A stream is officially started when this event or the `QUIC_STREAM_EVENT_START_COMPLETE` event is received.

# Sending

An app can send on any locally initiated stream or a peer initiated bidirectional stream. The app uses the [StreamSend](api/StreamSend.md) API to send data.

MsQuic takes ownership of any buffers successfully queued via [StreamSend](api/StreamSend.md). Buffer ownership is
returned to the application via the `QUIC_STREAM_EVENT_SEND_COMPLETE` event. The application must not free, reuse or
otherwise access a buffer provided to [StreamSend](api/StreamSend.md) until the matching
`QUIC_STREAM_EVENT_SEND_COMPLETE` event.

![Note]
> `QUIC_STREAM_EVENT_SEND_COMPLETE` does not mean the data has been received by the peer application layer.
> It only means that MsQuic no longer needs the app send buffer and give the owernship back to the application. The app
> should *not* assume the data has been successfully transmitted based on this notification.

## Send Buffering

**By default**, MsQuic buffers the stream data internally when [StreamSend](api/StreamSend.md) is called by an app.
As long as there is room to buffer the data, MsQuic will copy the data locally and then immediately complete the send back to the app, via the `QUIC_STREAM_EVENT_SEND_COMPLETE` event.
If there is no room to copy the data, then MsQuic will hold onto the buffer until there is room.

With this mode, the app can easily "keep the pipe full" using only a single outstanding send: It continually keeps a single send pending on the stream. As soon as the send is completed, the app immediately queues a new send again with any new data it needs to transmit.

This is seen by many as the simplest design for apps, and it allows great performances by ensuring MsQuic send path never runs idle.
However, internal buffering introduces an additional copy in the data path, which can be a performance draw back for some application.

MsQuic also supports another buffering mode that requires no internal copy of the data: MsQuic holds onto the app buffers until all the data has been acknowledged by the peer.

To fill the pipe in this mode, the app is responsible for keeping enough sends pending at all times to ensure the connection doesn't go idle.
MsQuic indicates the amount of data the app should keep pending in the `QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE` event.
The app should always have at least two sends pending at a time: If only a single send is used, the connection will go idle for the interval of time between when a send is completed and a new send is queued.

To disable internal send buffering and use the second mode, the app must set `SendBufferingEnabled` to `FALSE` through [MsQuic settings](Settings.md).

## Send Shutdown

The send direction can be shut down in three different ways:

- **Graceful** - The sender can gracefully shut down the send direction by calling [StreamShutdown](api/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL` flag or by including the `QUIC_SEND_FLAG_FIN` flag on the last [StreamSend](api/StreamSend.md) call. In this scenario all data will first be delivered to the peer, then the peer is informed the stream has been gracefully shut down.

- **Sender Abort** - The sender can abortively shut down the send direction by calling [StreamShutdown](api/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND` flag. In this scenario, all outstanding sends are immediately canceled and are not delivered to the peer. The peer is immediately informed of the abort.

- **Receiver Abort** - The receiver can abortively shut down their peer's send direction. When this happens the sender will get a `QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED` event.

When the send has been completely shut down the app will get a `QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE` event. This will happen immediately on an abortive send or after a graceful send has been acknowledged by the peer.

## 0-RTT

An app can opt in to sending stream data with 0-RTT keys (if available) by including the `QUIC_SEND_FLAG_ALLOW_0_RTT` flag on [StreamSend](api/StreamSend.md) call. MsQuic doesn't make any guarantees that the data will actually be sent with 0-RTT keys. There are several reasons it may not happen, such as keys not being available, packet loss, flow control, etc.

## Cancel On Loss

In case it is desirable to cancel a stream when packet loss is deteced instead of retransmitting the affected packets, the `QUIC_SEND_FLAG_CANCEL_ON_LOSS` can be supplied on a [StreamSend](api/StreamSend.md) call. Doing so will irreversibly switch the associated stream to this behavior. This includes *every* subsequent send call on the same stream, even if the call itself does not include the above flag.

If a stream gets canceled because it is in 'cancel on loss' mode, a `QUIC_STREAM_EVENT_CANCEL_ON_LOSS` event will get emitted. The event allows the app to provide an error code that is communicated to the peer via a `QUIC_STREAM_EVENT_PEER_SEND_ABORTED` event.

# Receiving

Data is received and delivered to apps via the `QUIC_STREAM_EVENT_RECEIVE` event. The event indicates zero, one or more contiguous buffers up to the application.

When using default settings, the buffer count is 1 the majority of the time, which means that most events will include a single buffer containing the received data.
The application can optimize its processing for that case but should be ready to handle any number of `QUIC_BUFFER`s.

When the buffer count is 0, it signifies the reception of a QUIC frame with empty data, which also indicates the end of stream data.

## Summary - Common handling of receive data events

Here is a quick overview of receiving data in _some_ common scenarios.

If the application...
 - processes all the received data synchronously in the stream event handler, `QUIC_STREAM_EVENT.RECEIVE.TotalBufferLength` parameter must be left unchanged and `QUIC_STATUS_SUCCESS` must be returned from the handler.
 - could process only part of the received buffer synchronously in the stream event handler call and wants to process the remaining data in a subsequent event handler call, it **must** be indicated to MsQuic by setting this parameter to the byte count processed and returning `QUIC_STATUS_CONTINUE` from this call.
 - desires to process the received data asynchronously, it should return `QUIC_STATUS_PENDING` from the event handler call.

Read on further for details on all possible scenarios of receiving data using the MsQuic library.

## Handling a receive event

The app then may respond to the event in a number of ways:

### Synchronous vs Asynchronous

The app has the option of either processing the received data in the callback (synchronous) or queuing the work to a separate thread (asynchronous). If the app processes the data synchronously it must do so in a timely manner. Any significant delays will delay other QUIC processing (such as sending acknowledgments), which can cause protocol issues (dropped connections).

If the app wants to queue the data to a separate thread, the app must return `QUIC_STATUS_PENDING` from the receive callback. This informs MsQuic that the app still has an outstanding reference on the buffers, and it will not modify or free them. Once the app is done with the buffers it must call [StreamReceiveComplete](api/StreamReceiveComplete.md).

The lifetime of the `QUIC_BUFFER`s themselves is limited to the scope of the callback: when handling the received data
asynchronously, the `QUIC_BUFFER`s must be copied.

### Partial Data Acceptance

Whenever the app gets the `QUIC_STREAM_EVENT_RECEIVE` event, it can partially accept/consume the received data.

For synchronous receives, the app indicates how much of the data it accepted via the `TotalBufferLength` variable in the payload of the `QUIC_STREAM_EVENT_RECEIVE` event. On input, that variable indicates the total amount of data being indicated. On output (return from the callback), the variable is taken as how much data the app consumed. By default, if the variable is left unmodified, then all data is assumed to be accepted.

For asynchronous receives, the app indicates how much of the data it accepted via the `BufferLength` parameter passed into the [StreamReceiveComplete](api/StreamReceiveComplete.md) API.

Any value less than or equal to the initial **TotalBufferLength** value is allowed, including zero.

Whenever a receive isn't fully accepted by the app, additional receive events are immediately disabled. The app is assumed to be at capacity and not able to consume more until further indication. To re-enable receive callbacks, the app must call [StreamReceiveSetEnabled](api/StreamReceiveSetEnabled.md).

There are cases where an app may want to partially accept the current data, but still immediately get a callback with the rest of the data. To do this (only works in the synchronous flow) the app must return `QUIC_STATUS_CONTINUE`.

## Receive Modes

Options can be used to alter MsQuic default receive notification behavior:

### Multi-Receive Mode

Multi-receive mode is a connection wide option allowing multiple receive notification to be pending simultaneously.
It is enabled by setting [`StreamMultiReceiveEnabled`](./api/QUIC_SETTINGS.md) in connection parameters.

For streams created when the connection is in Multi-mode receive, MsQuic can keep indicating `QUIC_STREAM_EVENT_RECEIVE` before the application completes the previous one.
This means that the application must be able to handle a new `QUIC_STREAM_EVENT_RECEIVE` even if it returned `QUIC_STATUS_PENDING` previously and has not called [`StreamReceiveComplete`](api/StreamReceiveComplete.md) yet.

MsQuic will also keep indicating receive notifications when the application accepts the data partially. The bytes that have not been accepted by the application won't be indicated again: the application must call [StreamReceiveComplete](api/StreamReceiveComplete.md) in the future to accept them.

To handle multi-receive mode properly, the application must keep track of the total number of bytes received on the stream (the sum of all `TotalBufferLength`).
The number of calls to [`StreamReceiveComplete`](api/StreamReceiveComplete.md) does not need to be equal to the number of receive notification, but the total number of bytes completed must eventually be equal to the total number of bytes received.

Multi-receive mode manages its internal receive buffer differently and is more efficient for continuous receiving with asynchronous processing.

### App-Owned Buffer Mode

App-owned buffer mode is a per-stream option allowing the application to provide its own receive memory buffers.
Enabling app-owned mode is done differently depending on whether the stream is created locally or from the peer and is discussed below.

When in app-owned mode, the application can call [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) to provide a list of memory buffers to MsQuic.
[`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) can be called at any time on a valid stream in app-owned mode, potentially inline from a notification handler.
If called several times, the buffer provided through subsequent calls are added to the list.

MsQuic will fill the provided buffer(s) with received data, in the order they have been provided. Receive notifications will be emitted as normal,
indicating a list of `QUIC_BUFFER`s pointing to the application provided buffer(s).
Note that up to the number of buffers the application provided can be indicated at once, and that only part of a buffer can be indicated.
There is no guarantee the `QUIC_BUFFER`s indicated in a receive notification will match the ones the application provided.

The application is responsible for tracking the amount of data received and when a buffer it provided has been fully used.
The application regains full ownership of a buffer after it get a receive notification for all bytes in the buffer and accept them by calling [StreamReceiveComplete](api/StreamReceiveComplete.md).
If the application accepts all the buffer's bytes **inline** from the receive notification, by returning `QUIC_STATUS_SUCCESS` and setting `TotalBufferLength` appropriately,
it can free or reuse the buffer while in the notification handler.

If more data is received on the stream than buffer space was provided by the application, MsQuic will emit a `QUIC_STREAM_EVENT_RECEIVE_BUFFER_NEEDED` notification.
When receiving this notification, the app can:
- provide a sufficient amount of buffer space **inline** from the callback using [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md)
- shutdown the stream receive direction of the stream **inline** by calling [`StreamShutdown`](api/StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_INLINE` flag

When the callback returns, if the stream has not been shutdown and a sufficient amount of memory is not available, the connection is closed abortively.
Providing memory in reaction to `QUIC_STREAM_EVENT_RECEIVE_BUFFER_NEEDED` can impact performances negatively.

For an application, providing receive buffers can improve performances by saving a copy: MsQuic places data directly in its final destination.
However, it comes with a large complexity overhead for the application, both in term of memory management and in term of flow control: an application providing too much or too little buffer space could negatively impact performances.
Because of this, app-owned mode should be considered an advanced feature and used with caution.

> **Note**: As of now, app-owned buffer mode is not compatible with multi-receive mode. If multi-receive mode is enabled for the connection and app-owned mode is enabled on a stream, that specific stream will behave as if multi-receive mode was disabled. This may change in the future.

#### Locally Initiated Streams

To use app-owned buffers on a locally created stream, the flag `QUIC_STREAM_OPEN_FLAG_APP_OWNED_BUFFERS` must be provided to the [`StreamOpen`](./api/StreamOpen.md).

Before starting the stream with [`StreamStart`](./api/StreamStart.md), the application should call [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) to provide some initial buffers.

> **Note**: This is only relevant for a bidirectional stream, since a locally created unidirectional stream cannot receive data.

#### Peer Initiated Streams

To use app-owned buffers on a peer initiated stream, the application must call [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) inline when handling the `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` notification.

When called inline while handling `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED`, [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) enables app-owned buffers and provides some initial buffers. This is the only situation where it is allowed to call [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) on a stream that is not already in app-owned buffers mode. After this initial call, [`StreamProvideReceiveBuffers`](./api/StreamProvideReceiveBuffers.md) can be called at any time to provide more buffer space, until the stream is closed.

#### Initial Buffer Space

As part of the connection establishment, QUIC exchanges initial stream flow control limit as part of the transport parameters, defining the amount of data that each peer will be allowed to send on a newly created stream. An application can define these limits through `StreamRecvWindowBidiLocalDefault`, `StreamRecvWindowBidiRemoteDefault` and `StreamRecvWindowUnidiDefault` in [`QUIC_SETTINGS`](./api/QUIC_SETTINGS.md).

When using a stream in app-owned mode, the application should generally provide enough buffer space to fully contain the initial receive window, since a peer could imediately send that amount of data.
MsQuic does not enforce it, and it is legal for an application to provide less buffer space than the initial receive window if it is confident that the amount of buffer provided is large enough to handle all the data sent by the peer. However, if more data is received than can be stored in the buffers provided by the application, the entire **connection** will be terminated.

After the initial receive window is full, flow control will ensure that the peer does not send more data than there is buffer space available.
However, the application should still provide enough buffer space to keep flow control from impacting performances.

## Receive Shutdown

The receiver can abortively shutdown a stream receive direction by calling [`StreamShutdown`](api/StreamShutdown.md) 
with the `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE` option.

# Closing a Stream

Once a stream has been shutdown (in both direction for a bi-directional stream), the application receives a
`QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` event.

The application must then close the stream using [`StreamClose`](api/StreamClose.md), and can release its context
pointer safely once the call returns.

If the app closes a stream before it is shutdown, the stream will be shutdown abortively with an error code of `0`.
This should be avoided; instead the app should abortively shutdown the stream first with a meaningful error code.
It is possible for an application to abortively shutdown a stream and immediately close it from the same thread,
without waiting for the `QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` event.
