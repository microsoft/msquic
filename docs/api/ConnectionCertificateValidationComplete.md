ConnectionCertificateValidationComplete function
======

Uses the QUIC handle to complete certificate validation. This must be called after the app receives `QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED` and returns QUIC_STATUS_PENDING. The app should complete certificate validation and call this before the idle timeout and disconnect timeouts occur.

# Syntax

```C
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_COMP_CERT_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ BOOLEAN Result,
    _In_ QUIC_TLS_ALERT_CODES TlsAlert
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

`Result`

Certificate validation result.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

- Available from v2.2

# See Also

[ConnectionOpen](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
