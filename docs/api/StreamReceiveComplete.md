StreamReceiveComplete function
======

Completes a receive that was previously pended.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_STREAM_RECEIVE_COMPLETE_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ uint64_t BufferLength
    );
```

# Parameters

- `Stream`: A handle to a valid stream
- `BufferLength`: The number of bytes processed by the application

# Remarks

This is an asynchronous API but can run inline if called in a callback.

## Default behavior

The application must ensure that for each `QUIC_STREAM_EVENT_RECEIVE` processed asynchronously (`QUIC_STATUS_PENDING`
was returned from the callback), `StreamReceiveComplete` is called exactly once.

The application must ensure it calls `StreamReceiveComplete` a single time for every `QUIC_STREAM_EVENT_RECEIVE`
processed asynchronously. Duplicate `StreamReceiveComplete` calls are ignored silently if no `QUIC_STREAM_EVENT_RECEIVE`
is pending when the call is processed, but they could race with a new `QUIC_STREAM_EVENT_RECEIVE` event and complete it,
likely breaking the app data processing.

If `BufferLength` is smaller than the number of bytes indicated in the matching `QUIC_STREAM_EVENT_RECEIVE`, MsQuic will
stop indicating new `QUIC_STREAM_EVENT_RECEIVE` events until a call to [`StreamReceiveSetEnabled`](StreamReceiveSetEnabled.md).

## Multi-receive Mode

If Multi-receive mode has been enabled on the connection, the behavior is different from default behavior detailed above.

In Multi-receive mode, calls to `StreamReceiveComplete` do not need to match `QUIC_STREAM_EVENT_RECEIVE`: there can be
either more or fewer calls to `StreamReceiveComplete` than `QUIC_STREAM_EVENT_RECEIVE` events.

MsQuic will keep on indicating `QUIC_STREAM_EVENT_RECEIVE` irrespectively from calls to `StreamReceiveComplete` and the
value of `BufferLength`.

The application must keep track of the accumulated `TotalBufferLength` from `QUIC_STREAM_EVENT_RECEIVE` events and
ensure that:
- the sum of all `BufferLength` parameters in `StreamReceiveComplete` calls is always smaller or equal than the number
    of bytes received on the stream
- all bytes received are eventually completed in `StreamReceiveComplete` call OR the stream is aborted.

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
