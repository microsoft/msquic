MsQuic
======

MsQuic is a Microsoft implementation of the [IETF QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport)
protocol. It is cross platform, written in C and designed to be a general purpose QUIC library.

> **Important** The MsQuic library, as well as the protocol itself, is still a work in progress. Version 1 is not yet finalized and may continue to experience breaking changes until it is finalized.

[![Build Status](https://microsoft.visualstudio.com/OS/_apis/build/status/microsoft.msquic?branchName=master)](https://microsoft.visualstudio.com/OS/_build/latest?definitionId=45975&branchName=master)

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
>  * 0-RTT with Schannel and OpenSSL
>  * NAT Rebinding
>  * Client Migration
>  * Server Preferred Address
>  * Path MTU Discovery

## Library Features

  * Optimized for maximal throughput and minimal latency.
  * Asychronous IO.
  * Receive side scaling (RSS).
  * UDP send and receive coalescing support.

## Building

You can find detailed instructions for building the library [here](./docs/BUILD.md).

## Documentation

You can find more detailed information on how to use MsQuic in the [the API documentation](./docs/API.md).

## Source Code

The source is divided into several directories:

  * `bin` - Packages up all static libraries into the platform specific binaries.
  * `core` - Platform independent code that implements the QUIC protocol.
  * `docs` - All MsQuic documentation.
  * `inc` - Header files used by all the other directories.
  * `manifest` - Windows [ETW manifest](https://docs.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest) and related files.
  * `platform` - Platform specific code for OS types, sockets and TLS.
  * `submodules` - All the modules that MsQuic depends on.
  * `test` - Test code for the MsQuic API / protocol.
  * `tools` - Tools for exercising MsQuic.
    * `attack` - Adversarial tool for exploiting protocol weaknesses.
    * `etw` - Windows specific tool for processing MsQuic ETW logs.
    * `interop` - Runs through the [IETF interop scenarios](https://github.com/quicwg/base-drafts/wiki/15th-Implementation-Draft).
    * `ping` - Simple tool for gathering throughput measurements. Read more [here](./tools/ping/readme.md).
    * `sample` - Minimal example of how to use the MsQuic API.
    * `spin` - Randomly executes the MsQuic API to discover bugs.

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
