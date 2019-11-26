MsQuic
======

MsQuic is a Microsoft implementation of the [IETF QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport)
protocol. It is cross platform, written in C and designed to be a general purpose QUIC library.

[![Build Status](https://microsoft.visualstudio.com/OS/_apis/build/status/microsoft.msquic?branchName=master)](https://microsoft.visualstudio.com/OS/_build/latest?definitionId=45975&branchName=master)

## Protocol Features

QUIC has many benefits when compared to existing TLS over TCP scenarios:

  * Handshake authenticated with TLS 1.3
  * All packets are encrypted
  * Parallel streams of application data.
  * Improved (compared to TCP) congestion control and loss recovery.
  * 0-RTT (support depends on TLS library)

**Note** - Several QUIC protocol features are not fully implemented:

  * NAT Rebinding
  * Client Migration
  * Server Preferred Address
  * Full Path MTU Discovery

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
  * `platform` - Platform specific code for OS types, sockets and TLS.
  * `manifest` - Windows ETW manifest and related files.
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

For the time being, **external contributions will not be accepted**. We are still
working on setting up internal repository sycnhronization and continuous integration,
and until that happens, this repository will be a simple copy of the Microsoft internal
one.

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
