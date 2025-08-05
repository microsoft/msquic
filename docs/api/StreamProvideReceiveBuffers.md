StreamProvideReceiveBuffers function
======

**Preview feature**: This API is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

Provide application-owned buffers to MsQuic to store received data.
It should be called only for a stream in app-owned buffer mode.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_STREAM_PROVIDE_RECEIVE_BUFFERS_FN)(
    _In_ _Pre_defensive_ HQUIC Stream,
    _In_ uint32_t BufferCount,
    _In_reads_(BufferCount) const QUIC_BUFFER* Buffers
    );
```

# Parameters

- `Stream`: A handle to the stream
- `BufferCount`: The number of buffers provided
- `Buffers`: An array of `QUIC_BUFFER`s pointing to the memory buffers

# Remarks

This is an asynchronous API but it can run inline if called in a callback.

If called inline when handling a `QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED` event, it will convert
the stream to app-owned buffer mode.

If called inline when handling a `QUIC_STREAM_EVENT_RECEIVE_BUFFER_NEEDED` event, the provided
memory buffers will be used to store the received data.

# See also

[Streams](../Streams.md)<br>
[StreamOpen](StreamOpen.md)<br>
[Preview Features](../PreviewFeatures.md)<br>
