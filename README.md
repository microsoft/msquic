MsQuic
======

MsQuic is a Microsoft implementation of the [IETF QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport)
protocol. It is cross platform, written in C and designed to be a general purpose QUIC library.

> **Important** The MsQuic library, as well as the protocol itself, is still a work in progress. Version 1 is not yet finalized and may continue to experience breaking changes until it is finalized.

[![Build Status](https://dev.azure.com/ms/msquic/_apis/build/status/microsoft.msquic?branchName=master)](https://dev.azure.com/ms/msquic/_build/latest?definitionId=347&branchName=master)

## Protocol Features

QUIC has many benefits when compared to existing TLS over TCP scenarios:

  * Handshake authenticated with TLS 1.3
  * All packets are encrypted
  * Parallel streams of application data.
  * Improved (compared to TCP) congestion control and loss recovery.
  * Exchange application data in the first round trip (0-RTT).
  * Survives a change in the clients IP address or port.
  * Easily extendable for new features (such as unreliable delivery).

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

MsQuic currently officially supports the following platform configurations.
Information on support for MsQuic itself is located [here.](./docs/Support.md)

## Windows 10

On Windows 10, MsQuic relies on built-in support from [Schannel](https://docs.microsoft.com/en-us/windows/win32/com/schannel) for TLS 1.3 functionality. MsQuic is shipped in-box in the Windows kernel in the form of the `msquic.sys` driver, to support built-in HTTP and SMB features. User mode applications use `msquic.dll` (built from here) and package it with their app.

> **Important** This configuration requires running the latest [Windows Insider Preview Builds](https://insider.windows.com/en-us/) for Schannel's TLS 1.3 support.

> **Important** This configuration does not support 0-RTT due to Schannel's current lack of support.

## Linux

On Linux, MsQuic relies on [OpenSSL](https://www.openssl.org/) for TLS 1.3 functionality.

> **Important** This configuration relies on an [outstanding pull request](https://github.com/openssl/openssl/pull/8797) to OpenSSL master for QUIC/TLS support. It is still currently unknown as to when it will be merged into master. See [here](https://www.openssl.org/blog/blog/2020/02/17/QUIC-and-OpenSSL/) for more details.

> **Important** This configuration does not support 0-RTT. Complete integration with OpenSSL is an ongoing effort.

## Other

For testing or experimentation purposes, MsQuic may be built with other configurations, but they are not to be considered officially supported unless they are listed above. Any bugs found while using these configurations may be looked at, but no guarantees are provided that they will be fixed.

# Documentation

  * For building the library, see the [Build docs](./docs/BUILD.md).
  * For using the library, see the [API docs](./docs/API.md) or the [Sample](./src/tools/sample/sample.cpp).
  * For other frequently asked questions, see the [FAQs](./docs/FAQ.md).

# Contributing

> For the time being, **external code contributions will not be accepted**. We are still
working on setting up internal repository sycnhronization, continuous integration,
and generally ironing out our processes.

Most contributions require you to agree to a Contributor License Agreement (CLA)
declaring that you have the right to, and actually do, grant us the rights to use
your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you
need to provide a CLA and decorate the PR appropriately (e.g., status check, comment).
Simply follow the instructions provided by the bot. You will only need to do this
once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
