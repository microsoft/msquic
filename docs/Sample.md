# Running Sample MsQuic Server and Client

[Sample](../src/tools/sample/sample.c) provides a very simple MsQuic API sample server and client application.

## Generate Self Signed Certificate
A certificate needs to be available for the server to function. To generate a self-signed certificate, run

### On Windows
```Powershell
New-SelfSignedCertificate -DnsName $env:computername,localhost -FriendlyName MsQuic-Test -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy Exportable
```
This works for both Schannel and OpenSSL TLS providers, assuming the KeyExportPolicy parameter is set to Exportable. The Thumbprint received from the command is then passed to the sample server at startup. Copy the thumbprint received.

### On Linux
```Powershell
openssl req  -nodes -new -x509  -keyout server.key -out server.cert
```
This works with OpenSSL TLS Provider. It can also be used for Windows OpenSSL, however we recommend the certificate store method above for ease of use. Currently key files with password protections are not supported. With these files, they can be passed to the sample server with `-cert_file:path/to/server.cert` and `-key_file path/to/server.key` parameters.


## Start the server
Locate the quicsample.exe under your `artifacts/bin` directory under repo root. Start the server providing the thumbrint obtained in the previous step.

```Powershell
quicsample.exe -server -cert_hash:FAF9B176D64930D67C372CB456BAD38E7E5689F7
```
By default, the server listens on port 4567.

## Start the client
Start the client providing the IP address for the server. Here 127.0.0.1 is used as an example.

```Powershell
quicsample.exe -client -unsecure -target:{127.0.0.1}
```

## Console Output

Here is what the console output looks like on the server and client sides after connection is established and data flows:

### Server side
```
[conn][000001C32C29CC10] Connected
[strm][000001C32C261000] Peer started
[strm][000001C32C261000] Data received
[strm][000001C32C261000] Peer shut down
[strm][000001C32C261000] Sending data...
[strm][000001C32C261000] Data sent
[strm][000001C32C261000] All done
[conn][000001C32C29CC10] Successfully shut down on idle.
[conn][000001C32C29CC10] All done
```

### Client side
```
[conn][000001BE9F0C7000] Connecting...
[conn][000001BE9F0C7000] Connected
[strm][000001BE9F0CADF0] Starting...
[strm][000001BE9F0CADF0] Sending data...
[strm][000001BE9F0CADF0] Data sent
[conn][000001BE9F0C7000] Resumption ticket received (56 bytes):
01000000013100010243E8030245C00404810000000504800100000604800100000704800100000801010E0104C0000000FF03DE1A027E80
[strm][000001BE9F0CADF0] Data received
[strm][000001BE9F0CADF0] Peer shut down
[strm][000001BE9F0CADF0] All done
[conn][000001BE9F0C7000] Successfully shut down on idle.
[conn][000001BE9F0C7000] All done
```

## Description

The quicsample app implements a simple protocol (ALPN "sample") where the client connects to the server, opens a single bidirectional stream, sends some data and shuts down the stream in the send direction. On the server side all connections, streams and data are accepted. After the stream is shut down, the server then sends its own data and shuts down its send direction. The connection only shuts down when the 1 second idle timeout triggers.


