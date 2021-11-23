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

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

[System.DateTimeOffset]$NotBefore = [System.DateTimeOffset]::Now.AddDays(-1)
[System.DateTimeOffset]$NotAfter = [System.DateTimeOffset]::Now.AddDays(365)

function CreateRootCertificate() {
    $Subject = [X500DistinguishedName]::new("CN=MsQuicPkcs12Root")

    # KU
    $KeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature +
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign,
        $true)

    # Create Basic Constraints
    $BasicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        <# certificateAuthority #> $true,
        <# hasPathLengthConstraint #> $true,
        <# pathLengthConstraint #> 1,
        <# critical #> $true)

    $Extensions = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Extension]]::new()
    $Extensions.Add($KeyUsage)
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
    return $CertificateWithKey
}

function CreateIntermediateCertificate($RootCert) {
    $Subject = [X500DistinguishedName]::new("CN=MsQuicPkcs12Intermediate")

    # KU
    $KeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature +
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign,
        $true)

    # Create Basic Constraints
    $BasicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        <# certificateAuthority #> $true,
        <# hasPathLengthConstraint #> $true,
        <# pathLengthConstraint #> 0,
        <# critical #> $true)

    $Extensions = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Extension]]::new()
    $Extensions.Add($KeyUsage)
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

    $Serial = [byte[]]::new(16)
    $Random = [System.Random]::new()
    $Random.NextBytes($Serial)

    $Cert = $CertRequest.Create($RootCert, $NotBefore, $NotAfter, $Serial)
    return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($Cert, $PrivateKey)
}

function CreateLeafCert($Signer) {
    $Subject = [X500DistinguishedName]::new("CN=localhost")

    # EKU
    $EkuOidCollection = [System.Security.Cryptography.OidCollection]::new()
    $EkuOidCollection.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1", "Server Authentication"))
    $EnhancedKeyUsages = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($EkuOidCollection, <# critical #> $true)

    $KeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
        $true)

    # Create Basic Constraints
    $BasicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        <# certificateAuthority #> $false,
        <# hasPathLengthConstraint #> $false,
        <# pathLengthConstraint #> 0,
        <# critical #> $true)

    $SanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $SanBuilder.AddDnsName("localhost")
    $SanBuilder.AddIpAddress([System.Net.IPAddress]::Parse("127.0.0.1"))
    $SanBuilder.AddIpAddress([System.Net.IPAddress]::Parse("::1"))

    $Extensions = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Extension]]::new()
    $Extensions.Add($SanBuilder.Build())
    $Extensions.Add($KeyUsage)
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

    $Serial = [byte[]]::new(16)
    $Random = [System.Random]::new()
    $Random.NextBytes($Serial)

    $Cert = $CertRequest.Create($Signer, $NotBefore, $NotAfter, $Serial)
    return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($Cert, $PrivateKey)
}

$Root = CreateRootCertificate
$IntermediateSigner = CreateIntermediateCertificate $Root
$Leaf = CreateLeafCert $IntermediateSigner

$Collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()

$Collection.Add($Leaf[1]) | Out-Null # TODO(AnRossi):Why is $Leaf an array of an Int and the Cert?
#Export the intermediate and root certs and then import them to drop their private keys.
$Collection.Import($IntermediateSigner.rawData)
$Collection.Import($Root.rawData)

$Pfx = $Collection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "PLACEHOLDER");

Set-Content $OutputFile -Value $Pfx -AsByteStream

Write-Output "Generated $OutputFile"

# Clean up the signer's private keys
$Root.PrivateKey.Clear()
$IntermediateSigner.PrivateKey.Clear()
