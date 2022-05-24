# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
<#
.Synopsis
    Install (or uninstall) XDP on Windows.
.Parameter Destination
    The installation path of XDP.
.Parameter Uninstall
    Uninstall XDP if installed. If not set, install XDP.
.EXAMPLE
    Invoke this script directly from the web
    iex "& { $(irm https://aka.ms/xdp-install) }"
#>
param(
    [Parameter(Mandatory = $false)]
    [string] $Destination = ".\",

    [Parameter(Mandatory = $false)]
    [switch] $Uninstall,

    [Parameter(Mandatory = $false)]
    [switch] $SkipCerts
)

#Requires -RunAsAdministrator

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$NetworkPath = (irm "https://raw.githubusercontent.com/microsoft/msquic/main/scripts/xdp-devkit.json").path
$ZipPath = Join-Path $Destination "xdp.zip"
$XdpPath = Join-Path $Destination "xdp"
$XdpInstalled = Test-Path "$XdpPath\bin\xdp.inf"

if (!$Uninstall) {
    # Clean up any previous install. Don't delete the old directory as it might
    # contain some other non-XDP files.
    if ($XdpInstalled) {
        Write-Output "Uninstalling old XDP driver"
        try {
            netcfg.exe -u ms_xdp
            pnputil.exe /delete-driver "$XdpPath\bin\xdp.inf"
        } catch { }
    }

    # Download and extract the latest version of the XDP kit (overwriting as
    # necessary).
    Write-Host "Downloading and extracting $NetworkPath"
    Invoke-WebRequest -Uri $NetworkPath -OutFile $ZipPath
    Expand-Archive -Path $ZipPath -DestinationPath $XdpPath -Force
    Remove-Item -Path $ZipPath

    if (!$SkipCerts) {
        # Install the certificates to the necessary stores.
        Write-Host "Installing certificates"
        CertUtil.exe -addstore Root "$XdpPath\bin\CoreNetSignRoot.cer"
        CertUtil.exe -addstore TrustedPublisher "$XdpPath\bin\CoreNetSignRoot.cer"
    }

    # Install the XDP driver.
    Write-Host "Installing XDP driver"
    netcfg.exe -l "$XdpPath\bin\xdp.inf" -c s -i ms_xdp

} elseif ($XdpInstalled) {
    # Uninstall the XDP driver and delete the folder.
    Write-Output "Uninstalling XDP driver"
    try {
        netcfg.exe -u ms_xdp
        pnputil.exe /delete-driver "$XdpPath\bin\xdp.inf"
    } catch { }
    Remove-Item -Path $XdpPath -Recurse -Force
}
