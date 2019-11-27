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

**TODO**

# Return Value

The function returns a [QUIC_STATUS](../v0/QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamClose](StreamClose.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
