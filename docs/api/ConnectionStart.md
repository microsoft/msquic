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

`Connection`

The valid handle to an open connection object.

`Family`

The address family to use for resolving the IP address of the *ServerName* parameter. Supported values are as follows:

Value | Meaning
--- | ---
**AF_UNSPEC**<br>0 | Unspecified address family.
**AF_INET**<br>2 | Version 4 IP address family.
**AF_INET6**<br>23 | Version 6 IP address family.

`ServerName`

The name of the server to connect to. It may also be an IP literal.

`ServerPort`

The UDP port, in host byte order, to connect to on the server.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

# See Also

[ConnectionOpen](ConnectionStart.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
