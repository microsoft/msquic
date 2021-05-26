StreamClose function
======

Closes an existing stream.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_API * QUIC_STREAM_CLOSE_FN)(
    _In_ _Pre_defensive_ __drv_freesMem(Mem)
        HQUIC Stream
    );
```

# Parameters

`Stream`

A Stream handle from a previous call to [StreamOpen](StreamOpen.md).

# Remarks

The application should only close a stream after it has been completely shut down or it was never successfully started. Closing a stream before it has been completely shut down produces **undefined behavior** because clean up of the stream **must** be reflected on the wire with an application specific error code. When the app closes a stream without first shutting down, MsQuic has to guess which error code to use (currently uses `0`) when sending the state change to the peer.

If the application needs to quickly discard all stream state and doesn't care about the result, it should first call [StreamShutdown](StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_ABORT` and `QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE` flags, specifying an appropriate error code. Then, only after the `QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` should the app call close. This event will happen immediately.

`StreamClose` may be called on any callback, including one for the stream being closed.

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
