# RDMA Datapath Proposal

Important: This article is a work-in-progress document for implementing
the RDMA datapath.

Application developers should not expect any support until
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
easily inherit from the general model where MsQuic lazily initializes RDMA on a best effort basis and the datapath implicitly reads from `QUIC_SETTINGS`.

This is primarily due to MsQuic requiring the adapter IP address prior
to initializing the datapath. Along with the RDMA datapath impacting the core logic of QUIC itself (much of MsQuic loss detection logic can be disabled), along with major updates to core MsQuic structures and the entire datapath initialization stack.
With how fluid `QUIC_SETTINGS` can update based on many different contexts,
the integration logic for RDMA will be very complex.
Having multiple connections or listeners with varying RDMA settings is a non-goal.


Thus the `RdmaEnabled` option should live at the registration level; to give maximal control
over datapath initialization and worker thread allocation.

Additionally, MsQuic requires the RNIC adapter interface IPv4/IPv6 address for datapath initialization.

Proposed API design:
```C
typedef struct RDMA_DATAPATH_CONFIG {
    BOOLEAN RdmaEnabled;
    QUIC_ADDR RdmaInterfaceAdapterIp;
}

typedef struct QUIC_REGISTRATION_CONFIG {
    const char* AppName;
    QUIC_EXECUTION_PROFILE ExecutionProfile;
    RDMA_DATAPATH_CONFIG RdmaConfig;
} QUIC_REGISTRATION_CONFIG;
```


If applications would like to use XDP, normal OS sockets, and RDMA on the same machine, they
should create multiple registrations. 

## RDMA facts

RDMA over RoCEv2, which is what MsQuic will use,
 intercepts packets and redirects them at the hardware level.
The RNIC is programmed by the provider driver to redirect all packets matching a specific well known port X (usually 4791) and DMA them into the RDMA datapath then de-muxed using the QPN (queue pair number) into specific queue pairs (QP). A QP is a socket-like endpoint for applications using RDMA.

This implies major updates will need to occur all the way from the datapath to the binding
to the core layers to be QPN aware.

On a bright note, MsQuic does not need to reserve any UDP ports when using RDMA datapath unlike the XDP datapath which may steal traffic on ports reserved for AF_XDP sockets. The
provider driver will handle port reservations / collision logic.
