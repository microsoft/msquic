<h1 align="center"><img src="docs/images/readme_logo.png" width="500" alt="MsQuic logo"/></h1>

[![Documentation](https://img.shields.io/static/v1?label=Documentation&message=Dashboard&color=blue)](https://microsoft.github.io/msquic/msquicdocs/docs/API.html)
[![Perf Dashboard](https://img.shields.io/static/v1?label=Performance&message=Dashboard&color=blue)](https://microsoft.github.io/msquic/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/microsoft/msquic/build.yml?query=branch%3Amain&label=Build)](https://github.com/microsoft/msquic/actions/workflows/build.yml?query=branch%3Amain)
[![Test Status](https://img.shields.io/github/actions/workflow/status/microsoft/msquic/test.yml?query=branch%3Amain&label=Test)](https://github.com/microsoft/msquic/actions/workflows/test.yml?query=branch%3Amain)
[![Stress Status](https://img.shields.io/github/actions/workflow/status/microsoft/msquic/stress.yml?query=branch%3Amain&label=Stress)](https://github.com/microsoft/msquic/actions/workflows/stress.yml?query=branch%3Amain)
[![codecov](https://codecov.io/github/microsoft/msquic/branch/main/graph/badge.svg?token=xAjIMDn7wy)](https://codecov.io/github/microsoft/msquic)
![CodeQL](https://github.com/microsoft/msquic/workflows/CodeQL/badge.svg?branch=main)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/4846/badge)](https://bestpractices.coreinfrastructure.org/projects/4846)
[![Discord](https://img.shields.io/discord/827744285595271168?label=Discord&logo=discord&logoColor=white&color=7289DA)](https://discord.gg/YGAtCwTSsc)
[![crates.io](https://img.shields.io/crates/v/msquic)](https://crates.io/crates/msquic)
[![nuget](https://img.shields.io/nuget/vpre/Microsoft.Native.Quic.MsQuic.Schannel?style=plastic)](https://www.nuget.org/profiles/msquic)

MsQuic is a Microsoft implementation of the [IETF QUIC](https://datatracker.ietf.org/wg/quic/about/)
protocol. It is cross-platform, written in C and designed to be a general purpose QUIC library. MsQuic also has C++ API wrapper classes and exposes interop layers for both Rust and C#.

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
[![](https://img.shields.io/static/v1?label=Draft&message=Disable%20Encryption&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-disable-encryption)
[![](https://img.shields.io/static/v1?label=Draft&message=Performance&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-performance)
[![](https://img.shields.io/static/v1?label=Draft&message=CIBIR&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-cibir)
[![](https://img.shields.io/static/v1?label=Draft&message=Timestamps&color=blueviolet)](https://tools.ietf.org/html/draft-huitema-quic-ts)
[![](https://img.shields.io/static/v1?label=Draft&message=ReliableReset&color=blueviolet)](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/)

QUIC has many benefits when compared to existing "TLS over TCP" scenarios:

  * All packets are encrypted and handshake is authenticated with TLS 1.3.
  * Parallel streams of (reliable and unreliable) application data.
  * Exchange application data in the first round trip (0-RTT).
  * Improved congestion control and loss recovery.
  * Survives a change in the clients IP address or port.
  * Stateless load balancing.
  * Easily extendable for new features and extensions.

## Library Features

MsQuic has several features that differentiates it from other QUIC implementations:

  * Optimized for client and server.
  * Optimized for maximal throughput and minimal latency.
  * Asynchronous IO.
  * Receive side scaling ([RSS](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-receive-side-scaling)) support.
  * UDP send and receive coalescing support.

# Documentation

  * For platform support details, see the [Platforms docs](./docs/Platforms.md).
  * For release details, see the [Release docs](./docs/Release.md).
  * For performance data, see the [Performance dashboard](https://aka.ms/msquicperformance).
  * For building the library, see the [Build docs](./docs/BUILD.md).
  * For testing the library, see the [Testing docs](./docs/TEST.md).
  * For using the API, see the [API docs](./docs/API.md) or the [Sample](./src/tools/sample/sample.c).
  * For running a sample server and client app, see the [Quick Start Guide](./docs/Sample.md).
  * For deploying QUIC, see the [Deployment docs](./docs/Deployment.md).
  * For diagnosing issues, see the [Diagnostics docs](./docs/Diagnostics.md) and the [Trouble Shooting Guide](./docs/TSG.md).
  * For other frequently asked questions, see the [FAQs](./docs/FAQ.md).

# Contributing

For information on contributing, please see our [contribution guidelines](./.github/CONTRIBUTING.md). Feel free to take a look at our [Good First Issues](https://github.com/microsoft/msquic/labels/good%20first%20issue) list if you're looking for somewhere to start. If you'd just like to talk, come chat with us [on Discord](https://discord.gg/YGAtCwTSsc).
