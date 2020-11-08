MsQuic
======

MsQuic is a Microsoft implementation of the [IETF QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport)
protocol. It is cross platform, written in C and designed to be a general purpose QUIC library.

> **Important** The QUIC protocol is currently in IETF last call (not RFC quite yet). MsQuic implements the latest published drafts.

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

Drafts: [Transport](https://tools.ietf.org/html/draft-ietf-quic-transport), [TLS](https://tools.ietf.org/html/draft-ietf-quic-tls), [Recovery](https://tools.ietf.org/html/draft-ietf-quic-recovery), [Datagram](https://tools.ietf.org/html/draft-ietf-quic-datagram), [Load Balancing](https://tools.ietf.org/html/draft-ietf-quic-load-balancers)

> **Important** Several QUIC protocol features are not yet fully implemented:
>
>  * 0-RTT
>  * Client-side Migration
>  * Server Preferred Address
>  * Path MTU Discovery

## Library Features

  * Cross-platform support.
  * Optimized for client and server.
  * Optimized for maximal throughput and minimal latency.
  * Asynchronous IO.
  * Receive side scaling (RSS).
  * UDP send and receive coalescing support.

# Platform Support

MsQuic currently officially supports the following platform configurations. Information on support for MsQuic itself is located in [Support.md.](./docs/Support.md)

## Windows 10

On Windows 10, MsQuic relies on built-in support from [Schannel](https://docs.microsoft.com/en-us/windows/win32/com/schannel) for TLS 1.3 functionality. MsQuic is shipped in-box in the Windows kernel in the form of the `msquic.sys` driver, to support built-in HTTP and SMB features. User mode applications use `msquic.dll` (built from here) and package it with their app.

> **Important** This configuration requires running the latest [Windows Insider Preview Builds](https://insider.windows.com/en-us/) for Schannel's TLS 1.3 support.

> **Important** This configuration does not support 0-RTT due to Schannel's current lack of support.

## Linux

On Linux, MsQuic relies on [OpenSSL](https://www.openssl.org/) for TLS 1.3 functionality.

> **Important** This configuration relies on a fork of OpenSSL for QUIC/TLS support. It is still currently unknown as to when mainline will support QUIC. See [here](https://www.openssl.org/blog/blog/2020/02/17/QUIC-and-OpenSSL/) for more details.

> **Important** This configuration does not support 0-RTT. Complete integration with OpenSSL is an ongoing effort.

## Other

For testing or experimentation purposes, MsQuic may be built with other configurations, but they are not to be considered officially supported unless they are listed above. Any bugs found while using these configurations may be looked at, but no guarantees are provided that they will be fixed.

# Documentation

  * For frequently asked questions, see the [FAQs](./docs/FAQ.md).
  * For building the MsQuic library, see the [Build docs](./docs/BUILD.md).
  * For using the MsQuic API, see the [API docs](./docs/API.md) or the [Sample](./src/tools/sample/sample.cpp).
  * For deploying with MsQuic, see the [Deployment docs](./docs/Deployment.md).
  * For diagnosing MsQuic, see the [Diagnostics docs](./docs/Diagnostics.md).

# Contributing

For information on contributing, please see our [contribution guidlines](./.github/CONTRIBUTING.md).

> **Important** - We are still bringing up important regression tests for the core code. Until they are onboarded, any external contributions to the [core](./src/core) or kernel mode files in the [platform](./src/platform) will not be accepted. This is only a **temporary restriction** and we are working to complete it by the end of 2020.
