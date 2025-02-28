QUIC_CONNECTION_POOL_CONFIG structure
======

The configuration for creating a connection pool.

# Syntax

```C
typedef enum QUIC_CONNECTION_POOL_FLAGS {
    QUIC_CONNECTION_POOL_FLAG_NONE =                            0x00000000,
    QUIC_CONNECTION_POOL_FLAG_CLOSE_CONNECTIONS_ON_FAILURE =    0x00000001,
} QUIC_CONNECTION_POOL_FLAGS;

typedef struct QUIC_CONNECTION_POOL_CONFIG {
    _In_ HQUIC Registration;
    _In_ HQUIC Configuration;
    _In_ QUIC_CONNECTION_CALLBACK_HANDLER Handler;
    _Field_size_opt_(NumberOfConnections)
        void** Context;                         // Optional
    _In_ const char* ServerName;
    _In_opt_ const QUIC_ADDR* ServerAddress;    // Optional
    _In_ QUIC_ADDRESS_FAMILY Family;
    _In_ uint16_t ServerPort;
    _In_ uint16_t NumberOfConnections;
    _At_buffer_(_Curr_, _Iter_, NumberOfConnections, _Field_size_(CibirIdLength))
    _Field_size_opt_(NumberOfConnections)
        uint8_t** CibirIds;                     // Optional
    _In_ uint8_t CibirIdLength;                 // Optional
    _In_ QUIC_CONNECTION_POOL_FLAGS Flags;
} QUIC_CONNECTION_POOL_CONFIG;
```

# Members

`Registration`

An opened Registration for creating the connection in.

`Configuration`

An opened Configuration that provides the settings used to create each connection in the pool.

`Handler`

The connection callback handler to set on each connection in the pool.

`Context`

An optional array of context pointers. The first is used with the first connection created, the second with the second connection, etc.

`ServerName`

The server name to connect each connection to.

`ServerAddress`

An optional pointer to a `QUIC_ADDR` specifying the specific IP address to connect to. Takes precedence over the resolved `ServerName` address.

`Family`

The `QUIC_ADDRESS_FAMILY` to use for the connections.

`ServerPort`

The UDP port on the server to connect to, in host byte order.

`NumberOfConnections`

The number of connections to create in this connection pool.
If this number is greater than the number of RSS CPUs configured on the system, then multiple connections will end up on the same CPU, potentially hurting performance.

`CibirIds`

An optional pointer to an array of pointers to `uint8_t`s specifying the CIBIR ID to use for each connection. All CIBIR IDs must be the same length.

`CibirIdLength`

The number of bytes in each CIBIR ID. Not allowed to be zero if `CibirIds` is non-NULL.

`Flags`

Flags which affect settings on the connections or how the pool is created.
| Flag | Effect |
|------|--------|
| QUIC_CONNECTION_POOL_FLAG_NONE | Nothing |
| QUIC_CONNECTION_POOL_FLAG_CLOSE_CONNECTIONS_ON_FAILURE | Tells the API to clean up any created *and started* connections in the pool if an error occurrs. **Note:** The application must be able to handle having connections suddenly closed with this flag. Without this flag, the application is expected to clean up remaining connections. |

# See Also
[ConnectionPoolCreate](ConnectionPoolCreate.md)<br>
[QUIC_SETTINGS](QUIC_SETTINGS.md)<br>
