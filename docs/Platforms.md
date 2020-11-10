# Platform Support

MsQuic currently officially supports the following platform configurations. Information on support for MsQuic itself is located in [Release.md.](./docs/Release.md)

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
