Architecture
======

MsQuic has primarily two high-level layers: QUIC and the platform. The platform layer includes
abstractions for TLS, UDP and OS stuff (like threads and locks). The QUIC layer is platform
independent logic, built on the platform abstraction layers.

# Platform Abstraction Layer

The platform abstraction layer (or PAL) supports the following platforms:

- Windows (User and Kernel)
- Linux
- FreeBSD
- macOS



# QUIC

