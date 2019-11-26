ConnectionStart function
======

Starts connecting to the server.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_CONNECTION_START_FN)(
    _In_ _Pre_defensive_ HQUIC Connection,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_opt_z_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    );
```

# Parameters

**TODO**

# Return Value

The function returns a `QUIC_STATUS`. The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ConnectionOpen](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
