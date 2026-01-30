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

**Client connections with different QTIP enablements CAN exist on the same local port.**

MsQuic over vanilla XDP relies on the OS to assign us ephemeral UDP ports to reserve them and configure XDP to snoop UDP traffic on that port.

MsQuic over QTIP XDP relies on the OS to assign us ephemeral TCP ports to reserve them and configure XDP to snoop TCP traffic on that port.

But since we can create many client connections with different QTIP enablements, sometimes the OS assigns us
the same TCP and UDP port. This isn't necessarily a problem but may be confusing when debugging logs and
you observe 2 client connections on the same local port. It is important to differentiate the transport.


**Listeners with different QTIP enablements shall NOT be able to exist on the same local port.**

A QTIP-enabled listener will reserve both UDP/TCP ports equal to the local port of the listener
and configure XDP to snoop UDP/TCP packets on that local port. A non-QTIP listener will just reserve a UDP port
and have XDP snoop UDP packets on that port. To avoid conflicting traffic, we disallow 2 listeners with the same
local port but different QTIP enablements to exist.

In general, listeners should either be ALL QTIP enabled, or none of them are. Since QTIP enablement is controlled via the global setting, You should NOT alter the global settings for QTIP once you start a listener to avoid other listeners
started thereafter having different QTIP enablements.





