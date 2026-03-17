# MsQuic over XDP

To avoid confusion, "XDP" refers to [XDP-for-windows](https://github.com/microsoft/xdp-for-windows). While Linux XDP has been experimented
upon in the past and shown some promise for running MsQuic, it is NOT a stable datapath actively being maintained today.

## What is XDP

XDP enables received packets to completely bypass the OS networking stack.

Applications can subscribe to XDP ring buffers to post packets to send,
and process packets that are received through AF_XDP sockets.

Additionally, applications can program XDP to determine the
logic for which packets to filter for, and what to do with them.

For instance: "drop all packets with a UDP header and destination port
42."

## Port reservation logic

The type of logic MsQuic programs into XDP looks like:
 "redirect all packets with a destination port X to an AF_XDP socket."

This runs into the issue of **packet stealing.** If there was an unrelated process
that binds an OS socket to the same port MsQuic used to program XDP, XDP will steal
that traffic from underneath it.

Which is why MsQuic will always create an OS UDP socket on the same port as the AF_XDP
socket to play nice with the rest of the stack.

There are *exceptions* to this port reservation.

- Sometimes, MsQuic may create a TCP OS socket instead, or both TCP and UDP (see [QTIP](./QTIP.md)).
- Sometimes, MsQuic may NOT create any OS sockets at all (see [CIBIR](./CIBIR.md)).


## MsQuic over XDP general architecture:

```mermaid
flowchart TB

%% =========================
%% NIC + RSS
%% =========================
NIC["NIC interface"]

RSS1["RSS queue"]
RSS2["RSS queue"]

NIC --> RSS1
NIC --> RSS2

%% =========================
%% XDP FILTER ENGINE
%% =========================
subgraph XDP_ENGINE["XDP FILTER ENGINE"]

    XDP_PROG1["XDP::XDP program"]
    XDP_PROG2["XDP::XDP program"]

    XDP_RULES["XDP::XDP RULES"]

    AFXDP1["AF_XDP Socket"]
    AFXDP2["AF_XDP Socket"]

    RSS1 -->|packet data| XDP_PROG1
    RSS2 -->|packet data| XDP_PROG2

    XDP_PROG1 --> XDP_RULES
    XDP_PROG2 --> XDP_RULES

    XDP_RULES --> AFXDP1
    XDP_RULES --> AFXDP2

end

%% =========================
%% PACKET DEMUX
%% =========================
DEMUX["Packet DE-MUX logic"]

AFXDP1 --> DEMUX
AFXDP2 --> DEMUX

%% =========================
%% CXPLAT SOCKET POOL
%% =========================
subgraph CXPLAT_POOL["CXPLAT SOCKET POOL HASH TABLE"]

    CX1["CXPLAT Socket"]
    CX2["CXPLAT Socket"]
    CX3["CXPLAT Socket"]
    CX4["CXPLAT Socket"]

end

DEMUX --> CX1
DEMUX --> CX2
DEMUX --> CX3
DEMUX --> CX4

%% =========================
%% FIND BINDING LOGIC
%% =========================
BIND["FIND BINDING LOGIC"]

CX1 --> BIND
CX2 --> BIND
CX3 --> BIND
CX4 --> BIND

%% =========================
%% MSQUIC OBJECTS
%% =========================
subgraph MSQUIC_OBJECTS["MSQUIC OBJECTS"]

    CONN1["Connection"]
    CONN2["Connection"]
    CONN3["Connection"]
    LIST1["Listener"]
    LIST2["Listener"]

end

BIND --> CONN1
BIND --> CONN2
BIND --> CONN3
BIND --> LIST1
BIND --> LIST2
```
