QUIC_CONNECTION_POOL_CONFIG structure
======

The configuration for creating a connection pool.

> [!WARNING]
> This API is still in preview and may change in the future!

# Syntax

```C
typedef enum QUIC_CONNECTION_POOL_FLAGS {
    QUIC_CONNECTION_POOL_FLAG_NONE =                            0x00000000,
    QUIC_CONNECTION_POOL_FLAG_CLOSE_CONNECTIONS_ON_FAILURE =    0x00000001,
} QUIC_CONNECTION_POOL_FLAGS;

typedef struct QUIC_CONNECTION_POOL_CONFIG {
    HQUIC Registration;
    HQUIC Configuration;
    QUIC_CONNECTION_CALLBACK_HANDLER Handler;
    _Field_size_opt_(NumberOfConnections)
        void** Context;                         // Optional
    _Field_z_ const char* ServerName;
    const QUIC_ADDR* ServerAddress;             // Optional
    QUIC_ADDRESS_FAMILY Family;
    uint16_t ServerPort;
    uint16_t NumberOfConnections;
    _At_buffer_(_Curr_, _Iter_, NumberOfConnections, _Field_size_(CibirIdLength))
    _Field_size_opt_(NumberOfConnections)
        uint8_t** CibirIds;                     // Optional
    uint8_t CibirIdLength;                      // Zero if not using CIBIR
    QUIC_CONNECTION_POOL_FLAGS Flags;
} QUIC_CONNECTION_POOL_CONFIG;
```

# Members

`Registration`

The valid handle to an open registration object.

`Configuration`

The valid handle to an open and loaded configuration object that is used to create each connection in the pool.

`Handler`

A pointer to the app's callback handler to be invoked for all connection events.

`Context`

The array of app context pointers (possibly null). The first is associated with the first connection created, the second with the second connection, etc.

`ServerName`

The name of the server to connect to. It may also be an IP literal.

`ServerAddress`

An optional pointer to a `QUIC_ADDR` specifying the specific IP address to connect to. Takes precedence over the resolved `ServerName` address.

`Family`

The address family to use for resolving the IP address of the *ServerName* parameter. Supported values definitions are supported (The values are platform specific):

Value | Meaning
--- | ---
**QUIC_ADDRESS_FAMILY_UNSPEC**<br> | Unspecified address family.
**QUIC_ADDRESS_FAMILY_INET**<br> | Version 4 IP address family.
**QUIC_ADDRESS_FAMILY_INET6**<br> | Version 6 IP address family.

`ServerPort`

The UDP port, in host byte order, to connect to on the server.

`NumberOfConnections`

The number of connections to create in this connection pool.
If this number is greater than the number of RSS CPUs configured on the system, then multiple connections will end up on the same CPU, potentially hurting performance.

`CibirIds`

An optional pointer to an array of pointers to `uint8_t`s specifying the [CIBIR ID](https://datatracker.ietf.org/doc/html/draft-banks-quic-cibir) to use for each connection. All CIBIR IDs must be the same length.  Not allowed to be non-NULL if `CibirIdLength` is zero.

`CibirIdLength`

The number of bytes in each CIBIR ID. Not allowed to be zero if `CibirIds` is non-NULL.

`Flags`

Flags which affect settings on the connections or how the pool is created.
| Flag | Effect |
|------|--------|
| QUIC_CONNECTION_POOL_FLAG_NONE | Nothing |
| QUIC_CONNECTION_POOL_FLAG_CLOSE_CONNECTIONS_ON_FAILURE | Tells the API to close all *started* connections in the pool if an error occurrs while creating the pool. **Note:** The application must be able to handle having connections suddenly closed. Without this flag, the application is expected to clean up non-NULL connections when an error is returned from `ConnectionPoolCreate`. |

# See Also

[ConnectionPoolCreate](ConnectionPoolCreate.md)<br>
[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[QUIC_CONNECTION_CALLBACK](QUIC_CONNECTION_CALLBACK.md)<br>
[QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md)<br>
[QUIC_SETTINGS](QUIC_SETTINGS.md)<br>
