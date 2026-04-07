# CIBIR

## What is it

See [XDP](./XDP.md) first to understand the context.

When CIBIR is used, rather than programming XDP to filter and demux packets based on on address and port number,
XDP with CIBIR will instead filter and de-mux packets based on address, port number, and QUIC connection ID.

What CIBIR allows for is 2 or more separate server processes to share a single
port on the same machine, as long as their CIBIR ID is different.

## CIBIR port sharing logic
- Applications must provide a well-known local port for server sockets when using CIBIR and XDP.
- **IMPORTANT:** MsQuic will **NOT** reserve an OS port for server sockets when both CIBIR and XDP is enabled and available.
    > Client sockets can never share ports, so MsQuic will reserve an OS port in that scenario.
- The responsbility of book-keeping shared ports and ensuring robust protection for those shared ports is delegated to the application.


## Port protection recommendation for shared ports

MsQuic strongly recommends applications leverage the Windows [persistent port reservations API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createpersistentudpportreservation) to secure shared CIBIR ports prior to serving multi-process CIBIR traffic on a shared port.
- One time setup by a system admin to create the persistent reservation.
    > A good option for book-keeping persistent port reservations is via registry keys.
- Persistent port reservations survive reboots, allowing for robust portection in the event of crashes.
- Having a persistent reservation makes sure critical ports are taken out of the ephemeral port pool, so an unsuspecting application process won't get accidently assigned an ephemeral port that collides with a CIBIR port.
