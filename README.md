MsQuic
======

MsQuic is an implementation of the [IETF QUIC](https://tools.ietf.org/html/draft-ietf-quic-transport)
protocol by Microsoft. It is a cross platform, general purpose QUIC library written in C.

## Protocol Features

QUIC has many benefits when compared to existing TLS over TCP scenarios:

  * Handshake authenticated with TLS 1.3
  * All packets are encrypted
  * Parallel streams of application data.
  * Improved (compared to TCP) congestion control and loss recovery.
  * 0-RTT (_support depends on TLS library_)

**Note** - Several QUIC protocol features are still unimplemented:

  * NAT Rebinding
  * Client Migration
  * Server Preferred Address
  * Full Path MTU Discovery

## Library Features

  * Optimized for throughput performance and minimal latency.
  * Asychronous IO.
  * Receive side scaling (RSS).
  * UDP send and receive coalescing.

# Source Code

The source is divided into several directories:

  * `bin` - Packages up all static libraries into the platform specific binaries.
  * `core` - The platform independent code that implements the QUIC protocol.
  * `inc` - Header files used by all the other directories.
  * `platform` - Platform specific code for OS types, sockets and TLS.
  * `test` - Test code for the MsQuic API / protocol.
  * `tools` - Several tools for exercising MsQuic.

# Building

## Building on Windows

**Requirements**
  * [Visual Studio 2019](https://www.visualstudio.com/vs/) or higher
  * Latest [Windows Insider](https://insider.windows.com/en-us/) builds.

Open `msquic.sln` in Visual Studio 2019.

### Running the tests

Either use the [Test Explorer](https://docs.microsoft.com/en-us/visualstudio/test/run-unit-tests-with-test-explorer?view=vs-2019) or run `test_bin.exe` manually.

## Building on Linux (or [WSL](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install))

Run `make install` (openssl) or `make install_with_stub` (stub TLS).

### Running the tests

Run `./apitestrunner 6` to run all the tests.

# Contributing

For the near future, **external contributions will not be accepted**. We are still
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
