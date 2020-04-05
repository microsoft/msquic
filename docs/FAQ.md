# Frequently Asked Questions

> Will rest of Windows also go open source?

At this time there is no plan to open source the rest of Windows.

> When is this shipping with Windows?

The kernel mode version, msquic.sys, will ship in future Windows releases. For more details see our [support and release documentation](Support.md).

> Why isn’t there an HTTP/3 implementation along with MsQuic?

MsQuic is designed as a generic QUIC transport for any application protocol. Several HTTP/3 stacks that use MsQuic exist, both internal to Windows and external (.NET).

> Do you plan to support other platforms?

MsQuic currently supports Windows and Linux (in preview). In the future MacOS support may be added.

> Why aren't you allowing community contributions?

External contributions will be allowed once we stabilize our build and integration processes.

> Isn’t QUIC a Google product?

QUIC was started by Google, but then was picked up by the IETF to be standardized (see [here](https://datatracker.ietf.org/wg/quic/about/)). MsQuic is an implementation of that standard.

> Isn’t releasing MsQuic premature given that the standard has not finalized?

The tradition of the IETF is to implement a protocol and see it perform in the real world before calling the protocol finished.

> Do you have any performance data?

We don't have any performance numbers to share at this time.

> Does this mean Microsoft will stop investing in TCP?

TCP will continue to be used widely for a long time and we will continue to improve it as necessary.

> How can I block QUIC?

This is not recommended, as QUIC is seen as more secure than TCP/TLS. QUIC is a UDP based protocol that may run on any UDP port. The only sure fire way to block QUIC would be to block UDP.

> Why is MsQuic written in C?

Windows Kernel mode is one of the supported platforms, and while it supports some C++ features, it does not support all of them. So, it was decided to use just pure C to reduce complexities.
