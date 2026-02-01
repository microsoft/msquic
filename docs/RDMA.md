# RDMA Datapath Proposal

Important: This article is the proposed API design for how applications consume MsQuic over RDMA.
This datapath is still very much a work in progress. Application developers should not expect any support until
otherwise indicated.


## General Datapath Consumption

Today, applications control whether to use MsQuic over XDP or normal OS UDP sockets via `XdpEnabled` in `QUIC_SETTINGS`.
Set an instance of `QUIC_SETTINGS` where `XdpEnabled=true` (false by default) globally via the SetParam `QUIC_PARAM_GLOBAL_SETTINGS`, and all `QUIC_CONNECTION`
clients and `QUIC_LISTENER` servers initialized thereafter will inherit the global `XdpEnabled==true` setting, and use the XDP datapath.
Note that applications may override `QUIC_SETTINGS` for each instance of a `QUIC_CONNECTION`, and so you can have some client connections using XDP,
some using normal OS sockets. Server listeners purely derive their datapath usage from the global settings.

During the datapath initialization step, we **always** attempt to initialize the XDP datapath on
a best-effort basis.


## RDMA Datapath Consumption

The model for using MsQuic over the RDMA datapath can **not**
easily inherit from the general model using `QUIC_SETTINGS`.

This is primarily due to the RDMA datapath impacting the core logic of MsQuic itself (much of MsQuic loss detection logic can be disabled), along with major updates to core MsQuic structures and the entire datapath initialization stack.
With how fluid `QUIC_SETTINGS` can change based on many different contexts,
the integration logic for RDMA will be very complex.

Having multiple connections or listeners with varying RDMA settings is a non-goal.


Thus the `RdmaEnabled` option should live at the registration level; to give maximal control
over datapath initialization and worker thread allocation.

If applications would like to use XDP, normal OS sockets, and RDMA on the same machine, they
should create multiple registrations.


## RDMA facts

RDMA over RoCEv2, which is what MsQuic will use,
 intercepts packets and redirects them at the hardware level.
The RNIC is programmed by the provider driver (MANA or Mellanox) to redirect all packets matching a specific well known port X (usually 4791) and DMA them into the RDMA datapath then de-muxed using the QPN (queue pair number) into specific queue pairs (QP). A QP is a socket-like endpoint for applications using RDMA.

This implies major updates will need to occur all the way from the datapath to the binding
to the core layers to be QPN aware.

On a bright note, MsQuic does not need to reserve any UDP ports when using RDMA datapath unlike the XDP datapath which may steal traffic on ports reserved for AF_XDP sockets.
