ConnectionSendResumptionTicket function
======

Uses the QUIC (server) handle to send a resumption ticket to the remote client, optionally with app-specific data useful during resumption.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_SEND_RESUMPTION_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_SEND_RESUMPTION_FLAGS Flags,
    _In_ uint16_t DataLength,
    _In_reads_bytes_opt_(DataLength)
        const uint8_t* ResumptionData
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

`Flags`

TODO

`DataLength`

TODO

`ResumptionData`

TODO

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ConnectionOpen](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
