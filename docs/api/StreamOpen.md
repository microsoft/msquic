StreamOpen function
======

Creates a new stream.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_STREAM_OPEN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_STREAM_CALLBACK_HANDLER Handler,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Stream, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Stream
    );
```

# Parameters

`Connection`

The valid handle to an open connection object. The connection does **not** need to be started via [ConnectionStart](ConnectionStart.md).

`Flags`

A set of flags that control the behavior of `StreamOpen`:

Value | Meaning
--- | ---
**QUIC_STREAM_OPEN_FLAG_NONE**<br>0 | No special behavior. Defaults to bidirectional stream.
**QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL**<br>1 | Opens a unidirectional stream.
**QUIC_STREAM_OPEN_FLAG_0_RTT**<br>2 | Indicates that the stream may be sent in 0-RTT.

`Handler`

A pointer to the app's callback handler to be invoked for all stream events.

`Context`

The app context pointer (possibly null) to be associated with the stream object and passed back to the app's handler when invoked.

`Stream`

On success, returns a handle to the newly created stream.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function is used to allocate a new stream object of the desired directionality; either bidirectional (both sides send and receive) or unidirectional (opener sends and peer receives). This function simply allocates the object and does not assign a stream ID or inform the peer that the stream was created.

As indicated above, the parent connection object does not need to be started before the stream can be created. In fact, the MsQuic API is expressly designed to allow for the app to open streams, start them and queue data to be sent *before* starting the stream. In the 0-RTT scenario, this is practically required to ensure all the data is packed into the same UDP datagram(s).

**Important** - No events are delivered on the stream until the app calls [StreamStart](StreamStart.md) (because of the race conditions that could occur) and it succeeds. This means that if the parent connection is shutdown (e.g. idle timeout or peer initiated) before calling [StreamStart](StreamStart.md) then the `QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` will not be delivered. So, apps that rely on that event to trigger clean up of the stream **must** handle the case where [StreamStart](StreamStart.md) is either not ever called or fails and clean up directly.

# See Also

[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
