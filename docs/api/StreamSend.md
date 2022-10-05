StreamSend function
======

Queues app data to be sent on a stream.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_SEND_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );
```

# Parameters

`Stream`

The valid handle to an open stream object.

`Buffers`

An array of `QUIC_BUFFER` structs that each contain a pointer and length to app data to send on the stream. This may be `NULL` **only** if `BufferCount` is zero.

`BufferCount`

The number of `QUIC_BUFFER` structs in the `Buffers` array. This may be zero.

`Flags`

The set of flags the controls the behavior of `StreamSend`:

Value | Meaning
--- | ---
**QUIC_SEND_FLAG_NONE**<br>0 | No special behavior. Data is not allowed in 0-RTT by default.
**QUIC_SEND_FLAG_ALLOW_0_RTT**<br>1 | Indicates that the data is allowed to be sent in 0-RTT (if available). Makes no guarantee the data will be sent in 0-RTT. Additionally, even if 0-RTT keys are available the data may end up being sent in 1-RTT for multiple reasons.
**QUIC_SEND_FLAG_START**<br>2 | Indicates that the stream should asynchronously start (equivalent to calling [StreamStart](StreamStart.md)).
**QUIC_SEND_FLAG_FIN**<br>4 | Indicates the the stream send is the last or final data to be sent on the stream and should be gracefully shutdown (equivalent to calling [StreamShutdown](StreamShutdown.md) with the `QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL` flag).
**QUIC_SEND_FLAG_DGRAM_PRIORITY**<br>8 | **Unused and ignored** for `StreamSend`
**QUIC_SEND_FLAG_DELAY_SEND**<br>16 | Provides a hint to MsQuic to indicate the data does not need to be sent immediately, likely because more is soon to follow.

`ClientSendContext`

The app context pointer (possibly null) to be associated with the send.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

This function is used to queue data on a stream to be sent. The function itself is non-blocking and simply queues the data and returns. The app may pass zero or more buffers of data that will be sent on the stream in the order they are passed. The buffers (both the `QUIC_BUFFER`s and the memory they reference) are "owned" by MsQuic (and must not be modified by the app) until MsQuic indicates the `QUIC_STREAM_EVENT_SEND_COMPLETE` event for the send.

By default, data queued via `StreamSend` is not allowed to be sent in 0-RTT packets, but the app may override this by passing the `QUIC_SEND_FLAG_ALLOW_0_RTT` flag. This flag indicates that the data is acceptable to be sent in a 0-RTT packet, but does not guarantee that data will be sent in 0-RTT. There are several reasons it may not be sent in 0-RTT:

- The 0-RTT keys were not available.
- The server rejected 0-RTT data for some reason.
- Too much data was queued and it couldn't all fit.
- The data was sent, but eventually found to have been lost and retransmitted in a 1-RTT packet.

Some apps may open and send on many different streams at a very high rate. In these scenarios, having to call [StreamStart](StreamStart.md) and [StreamShutdown](StreamShutdown.md) for every stream adds unwanted performance overhead. In order to optimize these scenarios, `StreamStart` supports the `QUIC_SEND_FLAG_START` and `QUIC_SEND_FLAG_FIN` flags, which allows the app to do something like this:

```c
HQUIC Stream;
MsQuic->StreamOpen(
    Connection,
    QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
    AppHandler,
    AppContext,
    &Stream);
MsQuic->StreamSend(
    Stream,
    &AppData,
    1,
    QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN,
    AppSendContext);
```

> **Note**
> For the sake of brevity, error handling and clean up has been omitted.

This example opens a new unidirectional stream, and queues a send that starts the stream, sends some app data and gracefully closes the stream.

In some scenarios, the app may know that additional data (possibly on a different stream) will soon be queued after the current call to `StreamSend`. In these cases it may be helpful for the app to pass the `QUIC_SEND_FLAG_DELAY_SEND` flag to hint that MsQuic should wait for more data before flushing the connection-wide send queue. **Note** that anything else on the connection *might* still end up triggering the send to flush. The app may call `StreamSend` (on any stream) with a null/empty buffer with `QUIC_SEND_FLAG_DELAY_SEND` **unset** to force a flush.

**Important:** Data queued via `StreamSend` with the `QUIC_SEND_FLAG_DELAY_SEND` flag is not guaranteed to be sent until a subsequent `StreamSend` call on any stream is performed without the `QUIC_SEND_FLAG_DELAY_SEND` flag.

For additional information on sending on streams see [here](../Streams.md#Sending).

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
