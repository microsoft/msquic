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

**TODO**

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**
