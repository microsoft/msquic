# QTIP

## What?

QTIP is an MsQuic specific concept that allows MsQuic to exercise the QUIC protocol over XDP using TCP packets.

To be specific, QTIP adds a TCP header to the QUIC packet instead of a UDP header. It doesn't follow the TCP protocol after the initial handshake: headers are generated with good enough data to be compatible with most networks and leverage TCP specific optimizations, but are not used to operate the protocol.

You can think of it as disguising QUIC packets as TCP packets!

## Why?

Certain hardware / networks / cloud environments are optimized for TCP traffic. Instead of pushing for those environments to also optimize for UDP, QTIP allows us to leverage existing hardware with MsQuic.

## How?

To use QTIP, you first must be running XDP. The setting is ignored if XDP is not enabled.

QTIPEnabled in [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) controls whether client connections exclusively use QTIP, and whether listeners will optionally accept QTIP traffic.

Opt in to use QTIP for listeners by setting QTIPEnabled to true at a global level prior to starting the listener. Additionally, all client connections created thereafter will send/recv data over QTIP.
This setting can be overridden per client connection, allowing you to create some client connections that send QTIP or UDP traffic.

> [!IMPORTANT]
> Crucial information necessary for users to succeed.

Using QTIP will initialize a TCP socket and attempt to bind to your listener's local address. This is to reserve a TCP port for your listener to ensure
XDP does not steal any TCP traffic from your other processes later. That also means you need to ensure no other processes are listening on the same TCP port as your listener's local address prior
to starting your listener, otherwise the OS will throw a socket access denied / address in use error,
and your listener will fail to initialize.
