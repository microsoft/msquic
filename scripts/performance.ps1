<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

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

$OsPlat = "Linux"
if ($IsWindows) {
    $OsPlat = "Windows"
}
$Platform = "$($OsPlat)_$($Arch)_$($Tls)"

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

function Parse-Loopback-Results($Results) {
    #Unused variable on purpose
    $m = $Results -match "Total rate.*\(TX.*bytes @ (.*) kbps \|"
    return $Matches[1]
}

function Get-Latest-Test-Results($Platform, $Test) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/performance/$Platform/$Test"
    Write-Host "Requesting: $Uri"
    $LatestResult =  Invoke-RestMethod -Uri $Uri
    Write-Host "Result: $LatestResult"
    return $LatestResult
}

function Median-Test-Results($FullResults) {
    $sorted = $FullResults | Sort-Object
    return $sorted[[int](($sorted.Length - 1) / 2)]
}

class TestPublishResult {
    [string]$PlatformName
    [string]$TestName
    [string]$CommitHash
    [double[]]$IndividualRunResults
}

$currentLoc = Get-Location
Set-Location -Path $RootDir
$env:GIT_REDIRECT_STDERR = '2>&1'
$CurrentCommitHash = git rev-parse HEAD
Set-Location -Path $currentLoc

function Run-Loopback-Test() {
    Write-Host "Running Loopback Test"
    $proc = Start-Background-Executable -File $PingClient -Arguments "-listen:* -selfsign:1 -peer_uni:1"
    Start-Sleep 4

    $allRunsResults = @()

    1..10 | ForEach-Object {
        $runResult = Run-Foreground-Executable -File $PingClient -Arguments "-target:localhost -uni:1 -length:100000000"
        $parsedRunResult = Parse-Loopback-Results -Results $runResult
        $allRunsResults += $parsedRunResult
        Write-Host "Client $_ Finished"
    }

    Stop-Background-Executable -Process $proc

    $MedianCurrentResult = Median-Test-Results -FullResults $allRunsResults

    $fullLastResult = Get-Latest-Test-Results -Platform $Platform -Test "loopback"
    $MedianLastResult = 0
    if ($fullLastResult -ne "") {
        $MedianLastResult = Median-Test-Results -FullResults $fullLastResult.individualRunResults
    }

    $ToPublishResults = [TestPublishResult]::new()

    $ToPublishResults.CommitHash = $CurrentCommitHash.Substring(0, 7)
    $ToPublishResults.PlatformName = $Platform
    $ToPublishResults.TestName = "loopback"
    $ToPublishResults.IndividualRunResults = $allRunsResults

    $ResultsFolderRoot = "$Platform/loopback"
    $ResultsFileName = "/results.json"

    Write-Host $env:AGENT_MACHINENAME

    $NewFilePath = Join-Path $RootDir "artifacts/PerfDataResults/$ResultsFolderRoot"
    $NewFileLocation = Join-Path $NewFilePath $ResultsFileName
    New-Item $NewFilePath -ItemType Directory -Force

    $ToPublishResults | ConvertTo-Json | Out-File $NewFileLocation

    Write-Host "Current Run: $MedianCurrentResult kbps"
    Write-Host "Last Master Run: $MedianLastResult kbps"
}

Run-Loopback-Test
