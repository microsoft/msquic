StreamShutdown function
======

Starts the shutdown process on a stream.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_SHUTDOWN_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ QUIC_STREAM_SHUTDOWN_FLAGS Flags,
    _In_ _Pre_defensive_ QUIC_UINT62 ErrorCode // Application defined error code
    );
```

# Parameters

`Stream`

The valid handle to an open and started stream object.

`Flags`

The set of flags that controls the type and behavior of shutdown:

Value | Meaning
--- | ---
**QUIC_STREAM_SHUTDOWN_FLAG_NONE**<br>0 | **Invalid** option for `StreamShutdown`.
**QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL**<br>1 | Indicates the app is gracefully shutting down the stream in the send direction.
**QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND**<br>2 | Indicates the app is abortively shutting down the stream in the send direction.
**QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE**<br>4 | Indicates the app is abortively shutting down the stream in the receive direction.
**QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE**<br>8 | Indicates the app does not want to wait for the acknowledgement of the shutdown before getting the `QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` event. Only allowed for abortive shutdowns.

`QUIC_STREAM_SHUTDOWN_FLAG_ABORT` is provided as a helper and is simply a logic OR of `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND` and `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE`.

`ErrorCode`

Used for the abortive shutdown cases (`QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND` and `QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE`) to indicate the reason why the abort happened to the peer.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function allows an app to (either gracefully or abortively) shut down one or both directions of a stream. For abortive shutdowns, the app specifies an `ErrorCode` that is transmitted to the peer to indicate why the shutdown happened. Graceful shutdowns have no error code as they are implied to be the normal operation of a stream.

If the app doesn't care to wait for the acknowledgement of an abortive shutdown, it can use the `QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE` flag, which will result in MsQuic immediately (not necessarily inline to the call though) indicating the `QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE` event to the app, after which, the app may safely [StreamClose](StreamClose.md) the stream. MsQuic will internally maintain the stream for as long as necessary and then clean it up.

The stream can also be gracefully shutdown via the `QUIC_SEND_FLAG_FIN` flag. See [StreamSend](StreamSend.md) for more details.

Any stream (even one that hasn't been started) may be called to shutdown. If the stream has not been started yet, then the shutdown is effectively queued. If the app never calls [StreamStart](StreamStart.md) then the shutdown will never been sent out on the wire.

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
