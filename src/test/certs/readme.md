Certificates contained in this directory were created using the following commands in powershell.

Note: Don't run these commands on a leap day and commit the resulting files.

```
# Create Root cert
$RootCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestRoot" -FriendlyName MsQuicTestRoot -KeyUsageProperty Sign -KeyUsage CertSign,DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy ExportableEncrypted -KeyAlgorithm ECDSA_nistP521 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}ca=1&pathlength=0") -Type Custom

# Create Server Cert
$ServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestServer" -DnsName localhost,"127.0.0.1","::1" -FriendlyName MsQuicTestServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy ExportableEncrypted -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert

# Create Expired Server Cert
$ExpiredServerCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestExpiredServer" -DnsName localhost,"127.0.0.1","::1" -FriendlyName MsQuicTestExpiredServer -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy ExportableEncrypted -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotBefore (Get-Date).AddYears(-2) -NotAfter(Get-Date).AddYears(-1) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.1") -Signer $RootCert

#Create Client Cert
$ClientCert = New-SelfSignedCertificate -Subject "CN=MsQuicTestClient" -FriendlyName MsQuicTestClient -KeyUsageProperty Sign -KeyUsage DigitalSignature -CertStoreLocation cert:\CurrentUser\My -HashAlgorithm SHA256 -Provider "Microsoft Software Key Storage Provider" -KeyExportPolicy ExportableEncrypted -KeyAlgorithm ECDSA_nistP256 -CurveExport CurveName -NotAfter(Get-Date).AddYears(5) -TextExtension @("2.5.29.19 = {text}","2.5.29.37 = {text}1.3.6.1.5.5.7.3.2") -Signer $RootCert

Export-Certificate -Type CERT -Cert $RootCert -FilePath MsQuicTestRootCert.cer

$PfxPassword = ConvertTo-SecureString -String "TestCert" -Force -AsPlainText
Export-PfxCertificate -Cert $ServerCert -Password $PfxPassword -FilePath MsQuicTestServerCert.pfx
Export-PfxCertificate -Cert $ExpiredServerCert -Password $PfxPassword -FilePath MsQuicTestExpiredServerCert.pfx
Export-PfxCertificate -Cert $ClientCert -Password $PfxPassword -FilePath MsQuicTestClientCert.pfx
```
