QUIC_STATUS type
======

The status type MsQuic uses for all API return codes.

# Syntax

## Windows (User Mode)

```C
#define QUIC_STATUS                     HRESULT
#define QUIC_FAILED(X)                  FAILED(X)
#define QUIC_SUCCEEDED(X)               SUCCEEDED(X)
```

## Linux

```C
#define QUIC_STATUS                     unsigned long
#define QUIC_FAILED(X)                  ((int)(X) > 0)
#define QUIC_SUCCEEDED(X)               ((int)(X) <= 0)
```

# Remarks

The **QUIC_STATUS** type is a cross platform abstraction of the current platform's error code space. It allows for both success and failure values, which can be easily determined by the `QUIC_SUCCEEDED` and `QUIC_FAILED` macros.

The MsQuic headers define a number of different possible values for this (see below) but this list is not exhaustive. The platform specific functionality (for example UDP sockets) may also return platform specific error codes up to the app.

## Well-Known Status Codes

Value | Meaning
--- | ---
**QUIC_STATUS_SUCCESS** | The operation completed successfully.
**QUIC_STATUS_PENDING** | The operation is pending.
**QUIC_STATUS_CONTINUE** | The operation will continue.
**QUIC_STATUS_OUT_OF_MEMORY** | Allocation of memory failed.
**QUIC_STATUS_INVALID_PARAMETER** | An invalid parameter was encountered.
**QUIC_STATUS_INVALID_STATE** | The current state was not valid for this operation.
**QUIC_STATUS_NOT_SUPPORTED** | The operation was not supported.
**QUIC_STATUS_NOT_FOUND** | The object was not found.
**QUIC_STATUS_BUFFER_TOO_SMALL** | The buffer was too small for the operation.
**QUIC_STATUS_HANDSHAKE_FAILURE** | The connection handshake failed.
**QUIC_STATUS_ABORTED** | The connection or stream was aborted.
**QUIC_STATUS_ADDRESS_IN_USE** | The local address is already in use.
**QUIC_STATUS_INVALID_ADDRESS** | Binding to socket failed, likely caused by a family mismatch between local and remote address.
**QUIC_STATUS_CONNECTION_TIMEOUT** | The connection timed out waiting for a response from the peer.
**QUIC_STATUS_CONNECTION_IDLE** | The connection timed out from inactivity.
**QUIC_STATUS_INTERNAL_ERROR** | An internal error was encountered.
**QUIC_STATUS_UNREACHABLE** | The server is currently unreachable.
**QUIC_STATUS_CONNECTION_REFUSED** | The server refused the connection.
**QUIC_STATUS_PROTOCOL_ERROR** | A protocol error was encountered.
**QUIC_STATUS_VER_NEG_ERROR** | A version negotiation error was encountered.
**QUIC_STATUS_USER_CANCELED** | The peer app/user canceled the connection during the handshake.
**QUIC_STATUS_ALPN_NEG_FAILURE** | The connection handshake failed to negotiate a common ALPN.
**QUIC_STATUS_STREAM_LIMIT_REACHED** | A stream failed to start because the peer doesn't allow any more to be open at this time.
