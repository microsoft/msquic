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
    _In_ _Pre_defensive_ HQUIC Configuration,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_reads_or_z_opt_(QUIC_MAX_SNI_LENGTH)
        const char* ServerName,
    _In_ uint16_t ServerPort // Host byte order
    );
```

# Parameters

`Connection`

The valid handle to an open connection object.

`Configuration`

The valid handle to an open and loaded configuration object.

`Family`

The address family to use for resolving the IP address of the *ServerName* parameter. Supported values definitions are supported (The values are platform specific):

Value | Meaning
--- | ---
**QUIC_ADDRESS_FAMILY_UNSPEC**<br> |Unspecified address family.
**QUIC_ADDRESS_FAMILY_INET**<br> | Version 4 IP address family.
**QUIC_ADDRESS_FAMILY_INET6**<br> | Version 6 IP address family.

`ServerName`

The name of the server to connect to. It may also be an IP literal.

`ServerPort`

The UDP port, in host byte order, to connect to on the server.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

`ConnectionStart` initiates the connection from the client application. A server application doesn't start its side of the connection until it returns `QUIC_STATUS_SUCCESS` from the `QUIC_LISTENER_EVENT_NEW_CONNECTION` event.

No packets are sent until `ConnectionStart` is called, which starts the handshake, generates the initial cryptographic keys, frames 0-RTT data if present, and then sends the initial flight of packets to the server.

Since 0-RTT data is opportunistically sent during the connection handshake, it should be queued for send **BEFORE** calling `ConnectionStart` otherwise it may be sent after the handshake. Queueing 0-RTT data after calling `ConnectionStart` will race with the creation of the inital flight of packets and may not consistently be sent as 0-RTT data.

Some settings on the `Configuration`, and on the `Connection`, only take effect if set before `ConnectionStart` is called. See [ConfigurationOpen](ConfigurationOpen.md) and [SetParam](SetParam.md) for more details about settings.

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
