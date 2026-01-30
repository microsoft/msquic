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

Listeners with QTIP enabled will initialize a TCP and UDP socket and attempt to bind to your listener's local address. This is to reserve a TCP/UDP port for your listener to ensure
XDP does not steal any traffic from your other processes later. That also means you need to ensure no other processes are listening on the same port as your listener's local address prior
to starting your listener, otherwise the OS will throw a socket access denied / address in use error,
and your listener will fail to initialize.

**Client connections with different QTIP enablements CAN exist on the same local port.**

MsQuic connections over UDP XDP creates an OS UDP socket only and relies on the OS to assign the app an ephemeral UDP port to reserve them and configure XDP to snoop UDP traffic on that port.

MsQuic connections over QTIP XDP creates an OS TCP socket only and relies on the OS to assign the app an ephemeral TCP port to reserve them and configure XDP to snoop TCP traffic on that port.

But since apps can create many client connections with different QTIP enablements, sometimes the OS assigns
the same TCP and UDP port. This isn't necessarily a problem but may be confusing when debugging logs. Apps should
expect in rare cases some client connections will have the same local port when using different QTIP enablements.


**Listeners with different QTIP enablements shall NOT be able to exist on the same local port.**

A QTIP-enabled listener will reserve both UDP/TCP ports equal to the local port of the listener
and configure XDP to intercept UDP/TCP packets on that local port. A non-QTIP listener will just reserve a UDP port
and have XDP intercept UDP packets on that port. To avoid conflicting traffic, we disallow 2 listeners with the same
local port but different QTIP enablements to exist.
