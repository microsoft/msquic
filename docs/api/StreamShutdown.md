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

**TODO**

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
