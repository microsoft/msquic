<#

.SYNOPSIS
This script provides helpers to generate test certificate for MsQuic tests.

.PARAMETER OutputFile
    Specifies the build configuration to test.

.EXAMPLE
    install-test-certificates.ps1 -OutputFile ./artifacts/bin/macos/x64_Debug_openssl/test.pfx

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$OutputFile = ""
)

$Subject = [X500DistinguishedName]::new("CN=localhost")
[System.DateTimeOffset]$NotBefore = [System.DateTimeOffset]::Now.AddDays(-1)
[System.DateTimeOffset]$NotAfter = [System.DateTimeOffset]::Now.AddDays(365)

# EKU
$EkuOidCollection = [System.Security.Cryptography.OidCollection]::new()
$EkuOidCollection.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1", "Server Authentication"))
$EnhancedKeyUsages = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($EkuOidCollection, <# critical #> $false)

# Create Basic Constraints
$BasicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
    <# certificateAuthority #> $false,
    <# hasPathLengthConstraint #> $false,
    <# pathLengthConstraint #> 0,
    <# critical #> $false)

$Extensions = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Extension]]::new()
$Extensions.Add($EnhancedKeyUsages)
$Extensions.Add($BasicConstraints)

$PrivateKey = [System.Security.Cryptography.RSA]::Create(2048)

# Create Certificate Request
$CertRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $PrivateKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

 # Create the Subject Key Identifier extension
$SubjectKeyIdentifier = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new(
            $CertRequest.PublicKey,
            <# critical #> $false)
$Extensions.Add($SubjectKeyIdentifier)

foreach ($Extension in $Extensions)
{
    $CertRequest.CertificateExtensions.Add($Extension)
}

$CertificateWithKey = $CertRequest.CreateSelfSigned($NotBefore, $NotAfter)

$Pfx = $CertificateWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "PLACEHOLDER");

Set-Content $OutputFile -Value $Pfx -AsByteStream

Write-Output "Generated $OutputFile"

