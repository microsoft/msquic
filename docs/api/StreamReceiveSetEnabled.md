StreamReceiveSetEnabled function
======

Enables or disables receive callbacks on a stream.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_RECEIVE_SET_ENABLED_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ BOOLEAN IsEnabled
    );
```

# Parameters

**TODO**

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function always delegates to the worker queue, even if called from a quic worker thread. This matters if disabling receives, as there could be a receive in the queue before this call is processed, and that receive would still indicated to the app. To disable receives reliably, reject a receive by draining 0 bytes in the `QUIC_STREAM_EVENT_RECEIVE` callback.

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
