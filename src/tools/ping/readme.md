Quic Ping
========================

The following details how to use quicping to exercise QUIC. quicping allows for
creating either a client or server that can send and/or receive random streams
of data of variable length.

Common Configuration
------------------------

There are a number parameters that are common ot both client and server.

**OPTIONAL PARAMETERS**

    alpn        The TLS application layer protocol negotiation to use.
                [default: ping]

    port        The UDP port to listen on (server) or connect to (client).
                [default: 4433]

    encrypt     Enable/disable encryption for the QUIC connection. If encryption
                is disabled, then only quicping servers that also have
                encryption disabled will allow the client to connect.
                [default: 1]

    sendbuf     Enable/disable send buffering logic when sending on a stream.
                [default: 1]

    pacing      Enable/disable pacing for the QUIC connection(s).
                [default: 1]

    stats       Enable/disable printing of statistics after a connection ends.
                [default: 0]

    uni         The number of unidirectional streams to open.
                [default: 0]

    bidi        The number of bidirectional streams to open.
                [default: 0]

    peer_uni    The number of unidirectional streams to allow the peer to open.
                [default: 0]

    peer_bidi   The number of bidirectional streams to allow the peer to open.
                [default: 0]

    length      The number of bytes to send per stream.
                [default: 0]

    iosize      The size of each send request queued.
                [buffered default: 0x10000]
                [nonbuffered default: 0x100000]

    iocount     The number of outstanding send requests to queue per stream.
                [buffered default: 1]
                [nonbuffered default: 8]

    timeout     The disconnect timeout to use. Units of milliseconds.
                [default: 10000]

    idle        The idle timeout to use. Units of milliseconds.
                [default: 1000]

    key_bytes   The number of bytes encrypted per key.

Server Configuration
------------------------

    quicping.exe -listen:127.0.0.1 -port:443 -thumbprint:175342733b39d81c997817296c9b691172ca6b6e

When running quicping.exe as a server, there are a number of configuration
parameters that are important to note:

**REQUIRED PARAMETERS**

    listen      The local IP (v4 or v6) address the server will be listening on.

    thumbprint  The hash or thumbprint of the certificate (in current user's MY
                store) to use.

**EXAMPLE CONFIGURATIONS**

The following example configures quicping to listen on the local IP and UDP
port 127.0.0.1:443. It allows the client to open up to 100 bidirectional
streams and if the client allows it, the server will open up to 100
unidirectional streams.

    quicping.exe -listen:127.0.0.1 -port:443 -thumbprint:175342733b39d81c997817296c9b691172ca6b6e

The following example configures quicping to listen on the localhost IP
address with the default port of 4433. It also disables encryption so only
clients that also disable encryption will be able to connect.

    quicping.exe -listen:127.0.0.1 -encrypt:0 -thumbprint:175342733b39d81c997817296c9b691172ca6b6e

**SERVER CERTIFICATE**

The following Powershell command can be used to create self-signed certificates:

    New-SelfSignedCertificate -DnsName <comma separated names and IP addresses> -FriendlyName MsQuic-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider"

Client Configuration
------------------------

    quicping.exe -target:localhost -ip:4 -port:443 -uni:0

When running quicping.exe as a client, there are a number of configuration
parameters that are important to note:

**REQUIRED PARAMETERS**

    target      The hostname or IP address of the target machine to connect to.

**OPTIONAL PARAMETERS**

    ip          The hint to use for resolving a hostname via DNS to either an
                IPv4 (4) or IPv6 (6) address. A value of 0 indicates
                unspecified.
                [default: 0]

    remote      A remote IP address to connect to.
                [default: N/A]

    bind        The local IP address to bind to before starting the connection
                to the target machine.
                [default: N/A]

    ver         The initial version to set when connecting.
                [default: N/A]

    connections The number of parallel connections to open.
                [default: 1]

    resume      A 0-RTT resumption ticket to use for the connection. The ticket
                is from a previous connection attempt, and should be written to
                the console if it was successful.
                [default: N/A]

**EXAMPLE CONFIGURATIONS**

The following example configures the client to attempt to the IPv4 localhost
address of the local machine (127.0.0.1) on port 443. It will not open any
unidirectional or bidirectional streams to the server, nor will it allow for
the server to open any back to the client. After successfully connecting it
will exit.

    quicping.exe -target:localhost -ip:4 -port:443

The following example configures the client to attempt to a test Microsoft
server running quicping as a server. It opens two unidirectional streams and
sends 1 MB on each of them.

    quicping.exe -target:quic.westus.cloudapp.azure.com -port:4433 -uni:2 -length:1000000

Example Output:

    [75212a5493c6b5db][2] Opened.
    [75212a5493c6b5db][6] Opened.
    [75212a5493c6b5db] Connected in 117.731 milliseconds.
    [75212a5493c6b5db][6] Closed [Complete] after 268.246 ms. (TX 1000000 bytes @ 29124 kbps | RX 0 bytes @ 0 kbps).
    [75212a5493c6b5db][2] Closed [Complete] after 283.97 ms. (TX 1000000 bytes @ 27596 kbps | RX 0 bytes @ 0 kbps).
    Total Rate for all Connections & Streams: 56720 kbps.
    [75212a5493c6b5db] Resumption ticket (106 bytes):
    42007BBE3E070D5555487B5DBDAC6C7B426F2B950B3D6972F5FE83FA254F881D2106BC583C2D08A6C3C6AD1E75E09F009BC1BB50DE939C420F9C259E1E83CAB6162F827C03041303002062EE266CD55AE46383F1679294D8263109620EBC12B5D048D15422031D3AFAB7
