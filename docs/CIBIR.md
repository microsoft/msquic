# CIBIR

## What is it

See the [draft IETF](https://datatracker.ietf.org/doc/html/draft-banks-quic-cibir) for CIBIR.

When CIBIR is used, rather than programming [XDP](./XDP.md) to filter and demux packets based on on address and port number,
XDP with CIBIR will instead filter and de-mux packets based on address, port number, and QUIC connection ID.

What CIBIR allows for is 2 or more separate server processes to share a single
port on the same machine, as long as their CIBIR ID is different.

## CIBIR port sharing logic
- Applications must provide a well-known local port for server sockets when using CIBIR and XDP.
- **IMPORTANT:** MsQuic will **NOT** reserve an OS port for server sockets when both CIBIR and XDP is enabled and available.
    - Client sockets can never share ports, so MsQuic will reserve an OS port in that scenario.
- The responsibility of book-keeping shared ports and ensuring robust protection for those shared ports is delegated to the application.


## Port protection recommendations for shared ports

### Option 1: Persistent port reservations (Recommended)

MsQuic strongly recommends applications leverage the Windows [persistent port reservations API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createpersistentudpportreservation) to secure shared CIBIR ports prior to serving multi-process CIBIR traffic on a shared port.
- One time setup by a system admin to create the persistent reservation.
    - A good option for book-keeping persistent port reservations is via registry keys.
- Persistent port reservations survive reboots, allowing for robust protection in the event of crashes.
- Having a persistent reservation makes sure CIBIR ports are taken out of the ephemeral port pool and forbids sockets from binding to it unless it is associated with a persistent reservation token, which can only happen in an elevated process.
    - This way, an unsuspecting application process won't get accidently assigned an ephemeral port that collides with a CIBIR port.

### Option 2: WFP ALE (Application Layer Enforcement) filters

As an alternative, applications can use the [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) to create ALE filters that block unauthorized bind attempts to CIBIR ports.

ALE filters operate at the [bind and connect authorization layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers) (`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`, `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4/V6`). A filter can be configured to block any process from binding to a specific UDP port unless it matches an allowed application path or security descriptor.
