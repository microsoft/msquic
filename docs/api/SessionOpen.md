SessionOpen function
======

Creates a new session.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SESSION_OPEN_FN)(
    _In_ _Pre_defensive_ HQUIC Registration,
    _In_ uint32_t SettingsSize,
    _In_reads_bytes_opt_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_opt_ void* Context,
    _Outptr_ _At_(*Session, __drv_allocatesMem(Mem)) _Pre_defensive_
        HQUIC* Session
    );
```

# Parameters

`Registration`

The valid handle to an open registration object.

`AlpnBuffers`

A contiguous array of QUIC_BUFFERs containing all the Application-Layer Protocol Negotiation (ALPN) buffers.

`AlpnBufferCount`

The number of QUIC_BUFFERS in the AlpnBuffers array.

`Context`

The app context pointer to be associated with the session object.

`Connection`

On success, returns a handle to the newly opened session object.


# Return Value

The function returns a [QUIC_STATUS](../api/QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[SessionClose](SessionClose.md)<br>
[SessionShutdown](SessionShutdown.md)<br>
