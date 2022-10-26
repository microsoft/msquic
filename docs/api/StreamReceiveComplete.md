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

**TODO**

# Remarks

This is an asynchronous API but can run inline if called in a callback.
The application must ensure that one `StreamReceiveComplete` call corresponds to one `QUIC_STREAM_EVENT_RECEIVE` event.
Duplicate `StreamReceiveComplete` calls after one `QUIC_STREAM_EVENT_RECEIVE` event are ignored silently even with different `BufferLength`.

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
