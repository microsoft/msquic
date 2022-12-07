ConnectionResumptionTicketValidationComplete function
======

Uses the QUIC (server) handle to complete resumption ticket validation. This must be called after server app handles ticket validation and then return QUIC_STATUS_PENDING.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_COMP_RESUMPTION_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ BOOLEAN Result
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

`Result`

Ticket validation result.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

- Schannel doesn't support this feature.
- Available from v2.2

# See Also

[ConnectionOpen](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
