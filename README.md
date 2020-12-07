MsQuic
======

MsQuic is a Microsoft implementation of the [IETF QUIC](https://datatracker.ietf.org/wg/quic/about/)
protocol. It is cross platform, written in C and designed to be a general purpose QUIC library.

> **Important** The QUIC protocol is currently in IETF last call (not RFC quite yet). MsQuic implements the latest published drafts.

IETF Drafts: [Transport](https://tools.ietf.org/html/draft-ietf-quic-transport), [TLS](https://tools.ietf.org/html/draft-ietf-quic-tls), [Recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery), [Datagram](https://tools.ietf.org/html/draft-ietf-quic-datagram), [Load Balancing](https://tools.ietf.org/html/draft-ietf-quic-load-balancers)

[![Build Status](https://dev.azure.com/ms/msquic/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=main) [![Test Status](https://img.shields.io/azure-devops/tests/ms/msquic/347/main)](https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=main) [![Code Coverage](https://img.shields.io/azure-devops/coverage/ms/msquic/347/main)](https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=main) ![CodeQL](https://github.com/microsoft/msquic/workflows/CodeQL/badge.svg?branch=main) [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/microsoft/msquic.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/microsoft/msquic/context:cpp)

## Protocol Features

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

  * For frequently asked questions, see the [FAQs](./docs/FAQ.md).
  * For platform support details, see the [Platforms docs](./docs/Platforms.md).
  * For release details, see the [Release docs](./docs/Release.md).
  * For performance data, see the [Performance dashboard](https://aka.ms/msquicperformance).
  * For building the MsQuic library, see the [Build docs](./docs/BUILD.md).
  * For using the MsQuic API, see the [API docs](./docs/API.md) or the [Sample](./src/tools/sample/sample.cpp).
  * For deploying with MsQuic, see the [Deployment docs](./docs/Deployment.md).
  * For diagnosing MsQuic, see the [Diagnostics docs](./docs/Diagnostics.md).

# Contributing

For information on contributing, please see our [contribution guidlines](./.github/CONTRIBUTING.md).
