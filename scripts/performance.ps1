<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

.PARAMETER Runs
    The number of runs to execute.

.PARAMETER Length
    The length of the data to transfer for each run.

.PARAMETER Publish
    Publishes the results to the artifacts directory.

.PARAMETER PGO
    Uses pgomgr to merge the resulting .pgc files back to the .pgd.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [Int32]$Runs = 10,

    [Parameter(Mandatory = $false)]
    [Int64]$Length = 100000000,

    [Parameter(Mandatory = $false)]
    [switch]$Publish = $false,

    [Parameter(Mandatory = $false)]
    [switch]$PGO = $false
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

# Path to the build artifacts.
$Artifacts = $null
$QuicPing = $null
if ($IsWindows) {
    $Artifacts = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)"
    $QuicPing = "quicping.exe"
} else {
    $Artifacts = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)"
    $QuicPing = "quicping"
}

# Make sure the build is present.
if (!(Test-Path (Join-Path $Artifacts $QuicPing))) {
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
    return $Process.StandardOutput.ReadToEnd()
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
    try {
        # Unused variable on purpose
        $m = $Results -match "Closed.*\(TX.*bytes @ (.*) kbps \|"
        return $Matches[1]
    } catch {
        Write-Host "Error Processing Results:`n`n$Results"
        throw
    }
}

function Get-Latest-Test-Results($Platform, $Test) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/performance/$Platform/$Test"
    Write-Debug "Requesting: $Uri"
    $LatestResult = Invoke-RestMethod -Uri $Uri
    Write-Debug "Result: $LatestResult"
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

function Merge-PGO-Counts($Path) {
    $Command = "$Artifacts\pgomgr.exe /merge $Path $Artifacts\msquic.pgd"
    Invoke-Expression $Command | Write-Debug
    Remove-Item "$Path\*.pgc" | Out-Null
}

function Run-Loopback-Test() {
    Write-Host "Running Loopback Test"

    # Run server in it's own directory.
    $ServerDir = "$($Artifacts)_server"
    if (!(Test-Path $ServerDir)) { New-Item -Path $ServerDir -ItemType Directory -Force | Out-Null }
    Copy-Item "$Artifacts\*" $ServerDir

    $proc = Start-Background-Executable -File (Join-Path $ServerDir $QuicPing) -Arguments "-listen:* -port:4433 -selfsign:1 -peer_uni:1"
    Start-Sleep 4

    $allRunsResults = @()

    try {
        1..$Runs | ForEach-Object {
            $clientOutput = Run-Foreground-Executable -File (Join-Path $Artifacts $QuicPing) -Arguments "-target:localhost -port:4433 -uni:1 -length:$Length"
            $parsedRunResult = Parse-Loopback-Results -Results $clientOutput
            $allRunsResults += $parsedRunResult
            if ($PGO) {
                # Merge client PGO counts.
                Merge-PGO-Counts $Artifacts
            }
            Write-Host "Run $($_): $parsedRunResult kbps"
            $clientOutput | Write-Debug
        }

        $serverOutput = Stop-Background-Executable -Process $proc
    } catch {
        Stop-Background-Executable -Process $proc | Write-Host
        throw
    }
    if ($PGO) {
        # Merge server PGO counts.
        Merge-PGO-Counts $ServerDir
    }
    Remove-Item $ServerDir -Recurse -Force | Out-Null

    $MedianCurrentResult = Median-Test-Results -FullResults $allRunsResults

    $fullLastResult = Get-Latest-Test-Results -Platform $Platform -Test "loopback"
    if ($fullLastResult -ne "") {
        $MedianLastResult = Median-Test-Results -FullResults $fullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Host "Median: $MedianCurrentResult kbps ($PercentDiffStr%)"
        Write-Host "Master: $MedianLastResult kbps"
    } else {
        Write-Host "Median: $MedianCurrentResult kbps"
    }
    # Write server output so we can detect possible failures early.
    Write-Debug $serverOutput

    if ($Publish) {
        Write-Host "Copying results.json out for publishing."
        $ToPublishResults = [TestPublishResult]::new()
        $ToPublishResults.CommitHash = $CurrentCommitHash.Substring(0, 7)
        $ToPublishResults.PlatformName = $Platform
        $ToPublishResults.TestName = "loopback"
        $ToPublishResults.IndividualRunResults = $allRunsResults

        $ResultsFolderRoot = "$Platform/loopback"
        $ResultsFileName = "/results.json"

        $NewFilePath = Join-Path $RootDir "artifacts/PerfDataResults/$ResultsFolderRoot"
        $NewFileLocation = Join-Path $NewFilePath $ResultsFileName
        New-Item $NewFilePath -ItemType Directory -Force | Out-Null

        $ToPublishResults | ConvertTo-Json | Out-File $NewFileLocation
    }
}

Run-Loopback-Test

if ($PGO) {
    Write-Host "Copying msquic.pgd out for publishing."
    $OutPath = Join-Path $RootDir "\artifacts\PerfDataResults\winuser\pgo_$($Arch)"
    if (!(Test-Path $OutPath)) { New-Item -Path $OutPath -ItemType Directory -Force | Write-Debug }
    Copy-Item "$Artifacts\msquic.pgd" $OutPath
}
