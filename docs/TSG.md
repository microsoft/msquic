# Trouble Shooting Guide

This document is meant to be a step-by-step guide for trouble shooting any issues while using MsQuic.

## What kind of Issue are you having?

1. [I am debugging a crash.](#debugging-a-crash)
2. [Something is not functionally working as I expect.](#trouble-shooting-a-functional-issue)
3. [Performance is not what I expect it to be.](#trouble-shooting-a-performance-issue)

# Debugging a Crash

> TODO

# Trouble Shooting a Functional Issue

1. [I am getting an error code I don't understand.](#understanding-error-codes)
2. [The connection is unexpectedly shutting down.](#why-is-the-connection-shutting-down)
3. [No application (stream) data seems to be flowing.](#why-isnt-application-data-flowing)

## Understanding Error Codes

Some error codes are MsQuic specific (`QUIC_STATUS_*`), and some are simply a passthrough from the platform. You can find the MsQuic specific error codes in the platform specific header ([msquic_posix.h](../src/inc/msquic_posix.h), [msquic_winkernel.h](../src/inc/msquic_winkernel.h), or [msquic_winuser.h](../src/inc/msquic_winuser.h)).

From [msquic_winuser.h](../src/inc/msquic_winuser.h):
```C
#ifndef ERROR_QUIC_HANDSHAKE_FAILURE
#define ERROR_QUIC_HANDSHAKE_FAILURE    _HRESULT_TYPEDEF_(0x80410000L)
#endif

#ifndef ERROR_QUIC_VER_NEG_FAILURE
#define ERROR_QUIC_VER_NEG_FAILURE      _HRESULT_TYPEDEF_(0x80410001L)
#endif

...
```

### Linux File Handle Limit Too Small

In many Linux setups, the default per-process file handle limit is relatively small (~1024). In scenarios where lots of (usually client) connection are opened, a large number of sockets (a type of file handle) are created. Eventually the handle limit is reached and connections start failing (error codes `0x16` or `0xbebc202`) because new sockets cannot be created. To fix this, you will need to increase the handle limit.

To query the maximum limit you may set:
```
ulimit -Hn
```

To set a new limit (up to the max):
```
ulimit -n newValue
```

## Why is the connection shutting down?

1. [What does this QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT event mean?](#understanding-shutdown-by-transport)
2. [What does this QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_APP event mean?](#understanding-shutdown-by-app)

### Understanding shutdown by Transport.

There are two ways for a connection to be shutdown, either by the application layer or by the transport layer (i.e. the QUIC layer). The `QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT` event occurs when the transport shuts the connection down. Generally, the transport shuts down the connection either when there's some kind of error or if the negotiated idle period has elapsed.

```
[2]6F30.34B0::2021/04/13-09:22:48.297449100 [Microsoft-Quic][conn][0x1CF25AC46B0] Transport Shutdown: 18446744071566327813 (Remote=0) (QS=1)
```

Above is an example event collected during an attempt to connect to a non-existent server. Eventually the connection failed and the transport indicated the event with the appropriate error code. This error code (`18446744071566327813`) maps to `0xFFFFFFFF80410005`, which specifically refers to the `QUIC_STATUS` (indicated by `QS=1`) for `0x80410005`; which indicates `ERROR_QUIC_CONNECTION_IDLE`. For more details for understanding error codes see [here](#understanding-error-codes).

### Understanding shutdown by App.

As indicated in [Understanding shutdown by Transport](#understanding-shutdown-by-transport), there are two ways for connections to be shutdown. The `QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_APP` event occurs when the peer application has explicitly shut down the connection. In MsQuic API terms, this would mean the app called [ConnectionShutdown](./api/connectionshutdown.md).

> TODO - Add an example event

The error code indicated in this event is completely application defined (type of `QUIC_UINT62`). The transport has no understanding of the meaning of this value. It never generates these error codes itself. So, to map these values to some meaning will require the application protocol documentation.

## Why isn't application data flowing?

> TODO

# Trouble Shooting a Performance Issue

1. [Is it a problem with just a single (or very few) connection?](#why-in-performance-bad-for-my-connection)
2. [Is it a problem multiple (lots) of connections?](#why-is-performance-bad-across-all-my-connections)

## Why is Performance bad for my Connection?

> TODO

## Why is Performance bad across all my Connections?

1. [The work load isn't spreading evenly across cores.](#diagnosing-rss-issues)
2.

### Diagnosing RSS Issues

> TODO
