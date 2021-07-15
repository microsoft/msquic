# Frequently Asked Questions

> Will the rest of Windows also go open source?

At this time there is no plan to open source the rest of Windows.

> When is this shipping with Windows?

The kernel mode version, msquic.sys, ships in Windows. For more details see our [support and release documentation](Release.md).

> Why isn’t there an HTTP/3 implementation along with MsQuic?

MsQuic is designed as a generic QUIC transport for any application protocol. Several HTTP/3 stacks that use MsQuic exist, both internal to Windows and external (.NET Core).

> Do you plan to support other platforms?

MsQuic currently supports Windows, Linux and macOS. In the future support for other platforms may be added.

> Isn’t QUIC a Google product?

QUIC was started by Google, but then was picked up by the IETF to be standardized (see [here](https://datatracker.ietf.org/wg/quic/about/)). MsQuic is an implementation of that standard.

> Does this mean Microsoft will stop investing in TCP?

TCP will continue to be used widely for a long time and we will continue to improve it as necessary.

> Why is MsQuic written in C?

Windows Kernel mode is one of the supported platforms, and while it supports some C++ features, it does not support all of them. So, it was decided to use just pure C to reduce complexity.
