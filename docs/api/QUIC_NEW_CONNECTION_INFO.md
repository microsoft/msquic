QUIC_NEW_CONNECTION_INFO structure
======

All available information for new incoming QUIC connection.

```C
//
// All the available information describing a new incoming connection.
//
typedef struct QUIC_NEW_CONNECTION_INFO {
    uint32_t QuicVersion;
    const QUIC_ADDR* LocalAddress;
    const QUIC_ADDR* RemoteAddress;
    uint32_t CryptoBufferLength;
    uint16_t ClientAlpnListLength;
    uint16_t ServerNameLength;
    uint8_t NegotiatedAlpnLength;
    _Field_size_bytes_(CryptoBufferLength)
    const uint8_t* CryptoBuffer;
    _Field_size_bytes_(ClientAlpnListLength)
    const uint8_t* ClientAlpnList;
    _Field_size_bytes_(NegotiatedAlpnLength)
    const uint8_t* NegotiatedAlpn;
    _Field_size_bytes_opt_(ServerNameLength)
    const char* ServerName;
} QUIC_NEW_CONNECTION_INFO;
```

# Parameters

`QuicVersion`

The QUIC version negotiated for the new incoming connection.

`LocalAddress`

This field indicates the local address of the new incoming connection.

`RemoteAddress`

This field indicates the remote address of the new incoming connection.

`CryptoBufferLength`

This field indicates the length of the crypto buffer.

`ClientAlpnListLength`

This field indicates the total bytes of the client ALPN list.

`ServerNameLength`

This field indicates the length of the server name (SNI).

`NegotiatedAlpnLength`

This field indicates the length of the negotiated ALPN.

`CryptoBuffer`

This pointer indicates the crypto buffer for the new incoming connection.

`ClientAlpnList`

This pointer indicates the sent ALPN list from the client via the new incoming connection.

`NegotiatedAlpn`

This pointer indicates the negotiated ALPN between server and client.

`ServerName`

This pointer indicates the server name (SNI) of the new incoming connection.

> Note: this buffer comes directly from the TLS ClientHello, and its format is governed by TLS.
> From [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066#section-3):
> > "HostName" contains the fully qualified DNS hostname of the server,
> > as understood by the client.  The hostname is represented as a byte
> > string using ASCII encoding without a trailing dot.  This allows the
> > support of internationalized domain names through the use of A-labels
> > defined in [[RFC5890](https://www.rfc-editor.org/rfc/rfc5890)].  DNS hostnames are case-insensitive.  The
> > algorithm to compare hostnames is described in [[RFC5890, Section 2.3.2.4](https://www.rfc-editor.org/rfc/rfc5890#section-2.3.2.4)].

# See Also

[QUIC_LISTENER_CALLBACK](QUIC_LISTENER_CALLBACK.md)<br>
[QUIC_LISTENER_EVENT](QUIC_LISTENER_EVENT.md)<br>
