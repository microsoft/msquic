param(
    # Build path
    [Parameter(Mandatory=$true)]
    [string]$BuildPath,

    # MsQuic location
    [Parameter(Mandatory=$true)]
    [string]$MsQuicPath,

    # CPU Architecture
    [Parameter(Mandatory=$false)]
    [ValidateSet("amd64", "x86", "arm", "arm64")]
    [string]$Arch="amd64"
)

$PgoBasePath = "$($BuildPath)\$($Arch)fre\pgo"

if (!(Test-Path -Path "c:\pgo_collection")) {
    New-Item -Path "c:\pgo_collection" -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$($PgoBasePath)\pgoapi\*" -Filter *.ps1 -Destination "C:\pgo_collection"
Copy-Item -Path "$($BuildPath)\$($Arch)fre\bin\idw\signTool.exe" -Destination "C:\pgo_collection"
Copy-Item -Path "$($BuildPath)\$($Arch)fre\bin\idw\signTool.dll" -Destination "C:\pgo_collection"

if (!(Test-Path -Path "c:\pgo_collection\sweep")) {
    New-Item -Path "c:\pgo_collection\sweep" -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$($PgoBasePath)\kmode\system32\pgosweep.exe"          -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\kmode\system32\vcruntime140.dll"      -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\kmode\system32\drivers\pgodriver.sys" -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\bbttools\bbtlddll.exe"                -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\bbttools\createdir.sys"               -Destination "C:\pgo_collection\sweep"
Copy-Item -Path "$($PgoBasePath)\tools\pgort140.dll"                   -Destination "C:\pgo_collection\sweep"

# Install PGO
powershell -NonInteractive -NoProfile -File "c:\pgo_collection\install-pgo.ps1" -PgoChunkPath $PgoBasePath -PgoChunkNativePath $PgoBasePath -PgoCollectionDir "c:\pgo_collection" -SignTool "c:\pgo_collection\signtool.exe" -PGOArch $Arch

# Fix PGODriver
sc.exe config pgodriver start= auto

# Copy MsQuic
if ($arch -eq "amd64") {
    $QuicArch = "x64"
} else {
    $QuicArch = $Arch
}

$WindowsBinPath = "artifacts\bin\windows\$($QuicArch)_Release_schannel"
$WinKernelBinPath = "artifacts\bin\winKernel\$($QuicArch)_Release_schannel"

if (!(Test-Path -Path "c:\msquic\$($WindowsBinPath)")) {
    New-Item -Path "c:\msquic\$($WindowsBinPath)" -ItemType Directory -Force | Out-Null
}

if (!(Test-Path -Path "c:\msquic\$($WinKernelBinPath)")) {
    New-Item -Path "c:\msquic\$($WinKernelBinPath)" -ItemType Directory -Force | Out-Null
}

Copy-Item -Path "$($MsQuicPath)\$($WindowsBinPath)\*"   -Destination "c:\msquic\$($WindowsBinPath)"
Copy-Item -Path "$($MsQuicPath)\$($WinKernelBinPath)\*" -Destination "c:\msquic\$($WinKernelBinPath)"

sc.exe create "msquicpriv" type= kernel binpath= "C:\msquic\$($WinKernelBinPath)\msquicpriv.sys" start= demand

New-NetFirewallRule -DisplayName "Allow QuicPerf" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol UDP -LocalPort 4433

bcdedit /debug on

Write-Host Now Reboot the machine

# To collect the training data run this:
# pgosweep.exe /driver msquicpriv.sys .\msquicpriv.pgc
