ConnectionPoolCreate function
======

Creates a pool of connections spread across RSS cores.
> [!WARNING]
> This API is still in preview and may change in the future!

> [!IMPORTANT]
> Currently only supported on Windows with XDP.

# Syntax

```C

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
_Check_return_
QUIC_STATUS
(QUIC_API * QUIC_CONN_POOL_CREATE_FN)(
    _In_ QUIC_CONNECTION_POOL_CONFIG* Config,
    _Out_writes_(Config->NumberOfConnections)
        HQUIC* ConnectionPool
    );
```

# Parameters

`Config`

The configuration parameters for creating the connection pool. See [QUIC_CONNECTION_POOL_CONFIG](QUIC_CONNECTION_POOL_CONFIG.md) for details.

`ConnectionPool`

A pointer to an array that will receive all the connection handles. Must be large enough to hold `NumberOfConnections` connection handles (`HQUIC`s).

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

Any failure return value could mean the connection pool is partially created.
If the flag `QUIC_CONNECTION_POOL_FLAG_CLOSE_CONNECTIONS_ON_FAILURE` is not set, the caller will need to go through the `ConnectionPool` array and `ConnectionClose()` all non-NULL handles.

# Remarks

MsQuic is designed such that a given connection is only processed on a single CPU. Some scenarios need more performance than a single CPU can deliver, and this API is for those scenarios.
It creates `NumberOfConnections` connections and distributes them evenly across the configured RSS CPUs.
This ensures received traffic can be processed in parallel as long as the `NumberOfConnections` is less than the number of configured RSS CPUs.

The API accomplishes this in a few steps:

1. Quering the hardware for the RSS configuration information, including the RSS secret key and indirection table.
2. Resolving the ServerName to an address and `connect`ing a socket to acquire a local address and starting port to use in the RSS hashing calculation.
3. Computing the Toeplitz hash of the source/destination addresses and ports using the RSS secret key, to determine which CPU will process a connection.
    By varying the source port, the API can control which CPU processes a connection.
4. Creating a connection using that local address and port, and starting the connection.
    If the address+port is in use, find a new port that hashes to the same CPU and try again.

The API depends on retrieving the RSS configuration from hardware, which depends on XDP support at this time.
An application that can't use this API can perform the same steps as above and achieve the same result.

# See Also

[ConnectionOpen](ConnectionOpen.md)<br>
[ConnectionStart](ConnectionStart.md)<br>
[ConnectionShutdown](ConnectionShutdown.md)<br>
[ConnectionClose](ConnectionClose.md)<br>
[QUIC_CONNECTION_CALLBACK](QUIC_CONNECTION_CALLBACK.md)<br>
[QUIC_CONNECTION_EVENT](QUIC_CONNECTION_EVENT.md)<br>
[QUIC_SETTINGS](QUIC_SETTINGS.md)<br>
[QUIC_CONNECTION_POOL_CONFIG](QUIC_CONNECTION_POOL_CONFIG.md)<br>
