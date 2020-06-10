<#

.SYNOPSIS
This script runs spinquic locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Path to the spinquic exectuable.
$PingClient = $null
if ($IsWindows) {
    $PingClient = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\quicping.exe"
} else {
    $PingClient = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/quicping"
}

# Make sure the build is present.
if (!(Test-Path $PingClient)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

function Start-Background-Executable($File, $Arguments) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $File
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardInput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    return $p
}

function Stop-Background-Executable($Process) {
    $Process.StandardInput.WriteLine("")
    $Process.StandardInput.Flush()
    $Process.WaitForExit()
    Write-Host $Process.StandardOutput.ReadToEnd()
}

function Run-Foreground-Executable($File, $Arguments) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $File
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    return $p.StandardOutput.ReadToEnd()
}

function Parse-Results($Results) {
    #Unused variable on purpose
    $m = $Results -match "Total rate.*\(TX.*bytes @ (.*) kbps \|"
    return $Matches[1]
}

$proc = Start-Background-Executable -File $PingClient -Arguments "-listen:* -selfsign:1 -peer_uni:1"

Start-Sleep 4

$allRunsResults = @()

1..6 | ForEach-Object {
    $runResult = Run-Foreground-Executable -File $PingClient -Arguments "-target:localhost -uni:1 -length:100000000"
    $parsedRunResult = Parse-Results -Results $runResult
    $allRunsResults += $parsedRunResult
    Write-Host $runResult
    Write-Host $parsedRunResult
}



Stop-Background-Executable -Process $proc

Write-Host $allRunsResults

$sum = 0
$allRunsResults | ForEach-Object { $sum += $_ }

Write-Host $sum

$average = $sum / $allRunsResults.Length

Write-Host $average
