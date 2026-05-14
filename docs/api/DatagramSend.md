DatagramSend function
======

Queues app data to be sent unreliably in a datagram.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_DATAGRAM_SEND_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_reads_(BufferCount) _Pre_defensive_
        const QUIC_BUFFER* const Buffers,
    _In_ uint32_t BufferCount,
    _In_ QUIC_SEND_FLAGS Flags,
    _In_opt_ void* ClientSendContext
    );
```

# Parameters

`Connection`

The current established connection.

`Buffers`

An array of `QUIC_BUFFER` structs that each contain a pointer and length to app data to send on the stream. This may be `NULL` **only** if `BufferCount` is zero.

`BufferCount`

The number of `QUIC_BUFFER` structs in the `Buffers` array. This may be zero.

`Flags`

The set of flags that controls the behavior of `DatagramSend`:

Value | Meaning
--- | ---
**QUIC_SEND_FLAG_NONE**<br>0 | No special behavior. Data is not allowed in 0-RTT by default.
**QUIC_SEND_FLAG_ALLOW_0_RTT**<br>1 | Indicates that the data is allowed to be sent in 0-RTT (if available). Makes no guarantee the data will be sent in 0-RTT. Additionally, even if 0-RTT keys are available the data may end up being sent in 1-RTT for multiple reasons.
**QUIC_SEND_FLAG_START**<br>2 | **Unused and ignored** for `DatagramSend`
**QUIC_SEND_FLAG_FIN**<br>4 | **Unused and ignored** for `DatagramSend`
**QUIC_SEND_FLAG_DGRAM_PRIORITY**<br>8 | Sets a priority to ensure a datagram is sent before others.
**QUIC_SEND_FLAG_DELAY_SEND**<br>16 | **Unused and ignored** for `DatagramSend`
**QUIC_SEND_FLAG_CANCEL_ON_LOSS**<br>32 | **Unused and ignored** for `DatagramSend`
**QUIC_SEND_FLAG_CANCEL_ON_BLOCKED**<br>64 | Allows MsQuic to drop frames when all the data that could be sent has been flushed out, but there are still some frames remaining in the queue.

`ClientSendContext`

The app context pointer (possibly null) to be associated with the send.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**
