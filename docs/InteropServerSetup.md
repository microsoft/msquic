# Setting Up an MsQuic Interop Server

One of the tools in the MsQuic repo is `quicinteropserver` ([source](../src/tools/interopserver)). It is our server solution used for QUIC interoperability testing. You can find the general requirements for this on the [QUIC WG Wiki](https://github.com/quicwg/base-drafts/wiki/18th-Implementation-Draft).

# Building

The tool is automatically built with the rest of the repo. See complete build instructions [here](BUILD.md).

There are a few additional things to note beyond the default build instructions. Currently, 0-RTT is only supported on Windows, when using the OpenSSL TLS library. To build for OpenSSL, you must use the `-Tls openssl` option when calling `build.ps`. If 0-RTT is not required/needed, then `-Tls schannel` should be fine to use on Windows, and `-Tls openssl` for Linux.

Once built, you can find the `quicinteropserver` in (assuming PowerShell is used to build):

```
./artifacts/bin/{platform}/{arch}_{config}_{tls}
```

For example, if you build with `build.ps1 -Config Release -Tls openssl` on Windows, the output would be in:

```
./artifacts/bin/windows/x64_release_openssl
```

The directory contains all the build artifacts, including the base MsQuic library (`msquic.dll` or `libmsquic.so`).

# Deploying

To deploy quicinteropserver both the base MsQuic library and the application binary itself will have to be copied to the server machine. If you run quicinteropserver without any arguments, you will get the default usage text. For instance:

```
quicinteropserver is simple http 0.9/1.1 server.

Usage:
  quicinteropserver -listen:<addr or *> -root:<path> [-thumbprint:<cert_thumbprint>] [-name:<cert_name>] [-file:<cert_filepath> AND -key:<cert_key_filepath>] [-port:<####> (def:4433)]  [-retry:<0/1> (def:0)] [-upload:<path>]

Examples:
  quicinteropserver -listen:127.0.0.1 -name:localhost -port:443 -root:c:\temp
  quicinteropserver -listen:* -retry:1 -thumbprint:175342733b39d81c997817296c9b691172ca6b6e -root:c:\temp
```

Please see [Deployment.md](Deployment.md) for additional deployment considerations.

## Windows Instructions

The simplest and quickest way to set up the server on Windows is to use a self-signed certificate. The following PowerShell command can easily create one for you:

```PowerShell
New-SelfSignedCertificate -DnsName $env:computername,localhost,{DnsName} -FriendlyName QuicInteropServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider"
```

Make sure to replace `{DnsName}` with the actual public domain name of the server, if you have one. If not available, you may just omit the parameter all together.

The PowerShell command will dump the new certificate's thumbprint/hash to the console. You can then use that to start the server. For example:

```
quicinteropserver.exe -listen:* -port:4433 -thumbprint:{thumbprint} -root:{html_root_dir}
```

Make sure to replace `{thumbprint}` with the thumbprint of the certificate and `{html_root_dir}` with the full path of directory containing the HTML files you which to serve. It's recommended to include an `index.html` at the very least in this directory.

Also make sure to configure both any necessary firewalls to allow incoming UDP traffic on the configured port (`4433` in the case above). The following PowerShell command can easily open up the port in the Windows firewall:

```PowerShell
New-NetFirewallRule -DisplayName "QuicInteropServer" -Direction Inbound -Protocol UDP -LocalPort 4433 -Action Allow
```

## Linux Instructions

> TO-DO

# Enabling Dump Collection

It is a good idea to enable dump collection for any possible crashes, since this is only a test application, and not actual production quality.

## Windows Instructions

You can easily configure WER (Windows Error Reporting) to collect dump files and save them locally, in the directory of you're choosing, via the following PowerShell registry commands:

```PowerShell
$OutputDir = "C:\dumps"
$WerDumpRegPath = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\quicinteropserver.exe"
if (!(Test-Path $WerDumpRegPath)) {
    New-Item -Path $WerDumpRegPath -Force | Out-Null
}
New-ItemProperty -Path $WerDumpRegPath -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
New-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -PropertyType ExpandString -Value $OutputDir -Force | Out-Null
```

Feel free to update `$OutputDir` to whatever local directory you wish.

## Linux Instructions

The following commands (run as root) should configure core dumps to be created in the local directory:

```sh
# Enable core dumps for the system.
sudo sh -c "echo 'root soft core unlimited' >> /etc/security/limits.conf"
sudo sh -c "echo 'root hard core unlimited' >> /etc/security/limits.conf"
sudo sh -c "echo '* soft core unlimited' >> /etc/security/limits.conf"
sudo sh -c "echo '* hard core unlimited' >> /etc/security/limits.conf"

# Set the core dump pattern.
sudo sh -c "echo -n '%e.%p.%t.core' > /proc/sys/kernel/core_pattern"
```

The following are sudo basd run especially for using XDP
```sh
# Increase the number of file descriptors.
sudo sh -c "echo 'root soft nofile 1048576' >> /etc/security/limits.conf"
sudo sh -c "echo 'root hard nofile 1048576' >> /etc/security/limits.conf"
sudo sh -c "echo '* soft nofile 1048576' >> /etc/security/limits.conf"
sudo sh -c "echo '* hard nofile 1048576' >> /etc/security/limits.conf"
```