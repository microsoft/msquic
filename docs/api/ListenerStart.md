ListenerStart function
======

Starts listening for incoming connection requests.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_LISTENER_START_FN)(
    _In_ _Pre_defensive_ HQUIC Listener,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ const QUIC_ADDR* LocalAddress
    );
```

# Parameters

**TODO**

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ListenerOpen](ListenerOpen.md)<br>
[ListenerClose](ListenerClose.md)<br>
[ListenerStop](ListenerStop.md)<br>
