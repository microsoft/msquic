StreamStart function
======

Assigns an ID and starts processing the stream.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_START_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ QUIC_STREAM_START_FLAGS Flags
    );
```

# Parameters

`Stream`

The valid handle to an open stream object.

`Flags`

The set of flags the controls the behavior of `StreamStart`:

Value | Meaning
--- | ---
**QUIC_STREAM_START_FLAG_NONE**<br>0 | No special behavior. Executes as a blocking call, returning only after the operation has completed. The peer is not informed of the stream starting until the app sends data.
**QUIC_STREAM_START_FLAG_IMMEDIATE**<br>1 | Indicates that the peer should be immediately informed of the stream opening (or at least as soon as flow control allows) and not wait for any data to be sent first.
**QUIC_STREAM_START_FLAG_FAIL_BLOCKED**<br>2 | Only opens the stream if flow control (from the peer) allows. If the stream count limit has currently been reached the start will fail with `QUIC_STATUS_STREAM_LIMIT_REACHED`.
**QUIC_STREAM_START_FLAG_SHUTDOWN_ON_FAIL**<br>4 | Causes the stream to immediate shutdown (abortive) if the start operation fails.
**QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT**<br>8 | Indicates the app wants the `QUIC_STREAM_EVENT_PEER_ACCEPTED` event to be delivered if the stream isn't initially accepted (allowed by flow control) at start completion.

# Return Value

The function returns a [QUIC_STATUS](../v0/QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function starts the processing of the stream by the connection. Once called, the stream can start receiving events to the handler passed into [StreamOpen](StreamOpen.md). If the start operation fails, the **only** event that will be delivered is `QUIC_STREAM_EVENT_START_COMPLETE` with the failure status code.

The first step of the start process is assigning the stream an identifier (stream ID). The stream ID space is flow controlled, meaning the peer is able to control how many streams the app can open (on-wire). Though, even if the peer won't accept any more streams currently, this API (by default) allows the app to still start the stream and assigns a local stream ID. But in this case, the stream is just queued locally until the peer will accept it.

If the app does not want the queuing behavior, and wishes to fail instead, it can use the `QUIC_STREAM_START_FLAG_FAIL_BLOCKED` flag. If there is not enough flow control to allow the stream to be sent on the wire, then the start will fail (via a `QUIC_STREAM_EVENT_START_COMPLETE` event) with the `QUIC_STATUS_STREAM_LIMIT_REACHED` status.

The `QUIC_STREAM_START_FLAG_INDICATE_PEER_ACCEPT` flag can be used to get the `QUIC_STREAM_EVENT_PEER_ACCEPTED` event to know when the stream becomes unblocked by flow control. If the peer already provided enough flow control to accept the stream when it was initially started, the `QUIC_STREAM_EVENT_PEER_ACCEPTED` event is not delivered and the `QUIC_STREAM_EVENT_START_COMPLETE`'s `PeerAccepted` field will be `TRUE`. If is not initially accepted, if/once the peer provides enough flow control to allow the stream to be sent on the wire, then the `QUIC_STREAM_EVENT_PEER_ACCEPTED` event will be indicated to the app.

The stream can also be started via the `QUIC_SEND_FLAG_START` flag. See [StreamSend](StreamSend.md) for more details.

**Important** - No events are delivered on the stream until the app calls `StreamStart` (because of the race conditions that could occur) and it succeeds. This means that if the parent connection is shutdown (e.g. idle timeout or peer initiated) before calling `StreamStart` then the `QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` will not be delivered. So, apps that rely on that event to trigger clean up of the stream **must** handle the case where `StreamStart` is either not ever called or fails and clean up directly.

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
