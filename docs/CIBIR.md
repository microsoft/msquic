# CIBIR

## What is it

See [XDP](./XDP.md) first to understand the context.

When CIBIR is used, rather than programming XDP to filter packets on port numbers,
we now filter and de-mux packets based on QUIC connection ID.

CIBIR (CID-Based Identification and Routing) is just a prefix substring that XDP
will use to match and filter all packets with a QUIC CID that contains the prefix substring equal to CIBIR.

What using CIBIR also enables is allowing 2 or more separate server processes to share a single
port. As long as the CIBIR configuration used by each process is different, XDP can
properly de-mux and dispatch received packets to the right process.

## Port sharing rules
- **IMPORTANT:** MsQuic will **NOT** reserve OS ports for server sockets using CIBIR+XDP.
- Applications should be aware that if other processes on the system aren't collaborative, then traffic stealing is very possible if some other non-cibir server process binds to the shared port.
- Applications must also provide a well-known local port for listeners using cibir+XDP.
- MsQuic client connections may **NOT** share ports, thus MsQuic will create OS port reservations
for cibir+xdp clients.

## Port protection options

There are a variety of options applications can leverage to protect these cibir shared ports from stealing traffic.

- Persistent reservations:
 https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createpersistentudpportreservation API, to allow sysadmins to pre-allocate a block of ports and disallow other applications from binding to it. Blocks of ports reserved are safe from reboots.
- A well known CIBIR registry key can be used to detail shared ports, and sysadmins can coordinate their system such that other apps will not bind to those ports.
- ALE policies; applications can configure WFP to block certain ports from being binded to by other apps.