# CIBIR

## What is it

See [XDP](./XDP.md) first to understand the context.

When CIBIR is used, rather than programming XDP to filter packets on port numbers,
we now filter and de-mux packets based on QUIC connection ID.

CIBIR (CID-Based Identification and Routing) is just a prefix substring that XDP
will use to match and filter all packets with a QUIC CID that contains the prefix substring equal to CIBIR.

What using CIBIR also enables is allowing 2 separate server processes to share a single
port. As long as the CIBIR configuration used by each process is different, XDP can
properly de-mux and dispatch received packets to the right process.

## Port reservation
The first process that uses CIBIR will still need to reserve the OS ports to avoid
non-CIBIR applications from getting their traffic stolen. The second (and so on) processes
using CIBIR thereafter will skip reserving OS socket ports.


CIBIR usage is controlled by setting the `QUIC_PARAM_LISTENER_CIBIR_ID` setparam.

CIBIR does 2 things when set:
1. XDP will now steer packets to the correct process/listener by matching the CIBIR prefix within the packet QUIC Connection ID.

2. In the case of a port collision when reserving OS UDP/TCP sockets, MsQuic will continue with initializing the datapath. If XDP is not available/enabled, then no traffic will flow for the listener that experiences a collision.


