# MsQuic and FIPS 140

FIPS 140 certification only applies to cryptographic primitives, and thus neither the TLS implementation, nor MsQuic, needs FIPS certification itself.  This means that as long as the cryptographic library used by MsQuic's TLS layer is FIPS certified, MsQuic is compliant.

## Windows and FIPS 140

Information about the Microsoft Windows(tm) FIPS certification process can be found [here](https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation).

## Linux and FIPS 140

On Linux, FIPS is more complicated. The system-provided `libcrypto` needs to be FIPS certified, and MsQuic needs to be built to use the system-provided `libcrypto` instead of staticly linking it into the MsQuic library.

To accomplish this on Linux, MsQuic must be built using the following flags:
`pwsh ./build.ps1 -Tls OpenSSL -UseSystemOpenSSLCrypto`

After that, the system that MsQuic will run on must be configured to use FIPS.
An incomplete list below is provided with steps for enabling FIPS mode on known Linux distributions.

### RHEL 8

Steps and documentation can be found [here](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening).

