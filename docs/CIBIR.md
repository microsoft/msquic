# CIBIR

CIBIR usage is controlled by setting the `QUIC_PARAM_LISTENER_CIBIR_ID` setparam.

CIBIR does 2 things when set:
1. XDP will now steer packets to the correct process/listener by matching the CIBIR prefix within the packet QUIC Connection ID.

2. In the case of a port collision when reserving OS UDP/TCP sockets, MsQuic will continue with initializing the datapath. If XDP is not available/enabled, then no traffic will flow for the listener that experiences a collision.

