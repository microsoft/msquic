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

**TODO**

# Remarks

**TODO**

# See Also

[StreamOpen](StreamOpen.md)<br>
[StreamStart](StreamStart.md)<br>
[StreamShutdown](StreamShutdown.md)<br>
[StreamSend](StreamSend.md)<br>
[StreamReceiveComplete](StreamReceiveComplete.md)<br>
[StreamReceiveSetEnabled](StreamReceiveSetEnabled.md)<br>
