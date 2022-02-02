# Frequently Asked Questions

> Will the rest of Windows also go open source?

At this time there is no plan to open source the rest of Windows.

> When is this shipping with Windows?

The kernel mode version, msquic.sys, ships in Windows (Server 2022 and Windows 11). At this time, there is no plan to ship msquic.dll in Windows. For more details see our [platform support documentation](Platforms.md).

> Why isn’t there an HTTP/3 implementation along with MsQuic?

MsQuic is designed as a generic QUIC transport for any application protocol. Several HTTP/3 stacks that use MsQuic exist, both internal to Windows (http.sys) and external (.NET Core).

> What platforms does MsQuic support?

MsQuic currently supports Windows (including Xbox), Linux (including Android) and macOS (alpha) based platforms.

> Isn’t QUIC a Google product?

QUIC was started by Google, but then was standardized by the IETF (see [here](https://datatracker.ietf.org/wg/quic/about/)). MsQuic is an implementation of that standard.

> Does this mean Microsoft will stop investing in TCP?

TCP will continue to be used widely for a long time and we will continue to improve it as necessary.

> Why is MsQuic written in C?

Windows Kernel mode is one of the supported platforms, and while it supports some C++ features, it does not support all of them. So, it was decided to use just pure C to reduce complexity. The MsQuic API is exposed/projected into several other languages, including C++, C# and Rust.
