# SEERA MsQuic

> This is a fork based on [MsQuic](https://github.com/microsoft/msquic), maintained
> by [SEERA-Networks](https://github.com/seera-networks).
<!-- > Currently published to crates.io under `seera-msquic`. -->

## Protocol Features

[![](https://img.shields.io/static/v1?label=RFC&message=9000&color=brightgreen)](https://tools.ietf.org/html/rfc9000)
[![](https://img.shields.io/static/v1?label=RFC&message=9001&color=brightgreen)](https://tools.ietf.org/html/rfc9001)
[![](https://img.shields.io/static/v1?label=RFC&message=9002&color=brightgreen)](https://tools.ietf.org/html/rfc9002)
[![](https://img.shields.io/static/v1?label=RFC&message=9221&color=brightgreen)](https://tools.ietf.org/html/rfc9221)
[![](https://img.shields.io/static/v1?label=RFC&message=9287&color=brightgreen)](https://tools.ietf.org/html/rfc9287)
[![](https://img.shields.io/static/v1?label=RFC&message=9368&color=brightgreen)](https://tools.ietf.org/html/rfc9368)
[![](https://img.shields.io/static/v1?label=RFC&message=9369&color=brightgreen)](https://tools.ietf.org/html/rfc9369)
[![](https://img.shields.io/static/v1?label=Draft&message=Load%20Balancers&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-load-balancers)
[![](https://img.shields.io/static/v1?label=Draft&message=ACK%20Frequency&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-ack-frequency)
[![](https://img.shields.io/static/v1?label=Draft&message=ReliableReset&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-reliable-stream-reset/)
[![](https://img.shields.io/static/v1?label=Draft&message=AddressDiscovery&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-address-discovery/)
[![](https://img.shields.io/static/v1?label=Draft&message=Disable%20Encryption&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-disable-encryption)
[![](https://img.shields.io/static/v1?label=Draft&message=Performance&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-performance)
[![](https://img.shields.io/static/v1?label=Draft&message=CIBIR&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-cibir)
[![](https://img.shields.io/static/v1?label=Draft&message=Timestamps&color=blueviolet)](https://tools.ietf.org/html/draft-huitema-quic-ts)
[![](https://img.shields.io/static/v1?label=Draft&message=ServerMigration&color=blueviolet)](https://datatracker.ietf.org/doc/html/draft-kozuka-quic-server-migration/)
[![](https://img.shields.io/static/v1?label=Draft&message=NAT-Traversal&color=blueviolet)](https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal/)


## Main differences to upstream MsQuic

- Client Initiated Migration
- Implements additional QUIC extensions
  - Address Discovery
  - Server Initiated Migration
  - NAT-T
