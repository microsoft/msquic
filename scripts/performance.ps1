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

.PARAMETER Record
    Records the run to collect performance information for analysis.

.PARAMETER SkipAPIPA
    Skip setting the APIPA Settings.

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
    [Int64]$Length = 2000000000, # 2 GB

    [Parameter(Mandatory = $false)]
    [switch]$Publish = $false,

    [Parameter(Mandatory = $false)]
    [switch]$PGO = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Record = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAPIPA = $false
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

if (!$IsWindows) {
    if ($PGO) {
        Write-Error "'-PGO' is not supported on this platform!"
    }
    if ($Record) {
        Write-Error "'-Record' is not supported on this platform!"
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

# QuicPing arguments
$ServerArgs = "-listen:* -port:4433 -selfsign:1 -peer_uni:1 -connections:$Runs"
$ClientArgs = "-target:localhost -port:4433 -sendbuf:0 -uni:1 -length:$Length"
if ($IsWindows) {
    # Always use the same local address and core to provide more consistent results.
    $ClientArgs += " -bind:127.0.0.1:4434 -ip:4 -core:0"
}

# Base output path.
$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults/$Platform"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

# Make sure the build is present.
if (!(Test-Path (Join-Path $Artifacts $QuicPing))) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

# WPA Profile for collecting stacks.
$WpaStackWalkProfileXml = `
@"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0" Author="MsQuic" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
  <Profiles>
    <SystemCollector Id="SC_HighVolume" Realtime="false">
      <BufferSize Value="1024"/>
      <Buffers Value="20"/>
    </SystemCollector>
    <SystemProvider Id="SP_CPU">
      <Keywords>
        <Keyword Value="CpuConfig"/>
        <Keyword Value="Loader"/>
        <Keyword Value="ProcessThread"/>
        <Keyword Value="SampledProfile"/>
      </Keywords>
      <Stacks>
        <Stack Value="SampledProfile"/>
      </Stacks>
    </SystemProvider>
    <Profile Id="CPU.Light.File" Name="CPU" Description="CPU Stacks" LoggingMode="File" DetailLevel="Light">
      <Collectors>
        <SystemCollectorId Value="SC_HighVolume">
          <SystemProviderId Value="SP_CPU" />
        </SystemCollectorId>
      </Collectors>
    </Profile>
  </Profiles>
</WindowsPerformanceRecorder>
"@
$WpaStackWalkProfile = Join-Path $Artifacts "stackwalk.wprp"
if ($Record) {
    if ($IsWindows) {
        $WpaStackWalkProfileXml | Out-File $WpaStackWalkProfile
    }
}

function Start-Background-Executable($File, $Arguments) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $File
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    return $p
}

function Stop-Background-Executable($Process) {
    if (!$Process.WaitForExit(2000)) {
        $Process.Kill()
        Write-Debug "Server Failed to Exit"
    }
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
$CurrentCommitHash = $null
try {
    $CurrentCommitHash = git rev-parse HEAD
} catch {
    Write-Debug "Failed to get commit hash from git"
}
Set-Location -Path $currentLoc

function Merge-PGO-Counts($Path) {
    $Command = "$Artifacts\pgomgr.exe /merge $Path $Artifacts\msquic.pgd"
    Invoke-Expression $Command | Write-Debug
    Remove-Item "$Path\*.pgc" | Out-Null
}

function Run-Loopback-Test() {
    Write-Host "Running Loopback Test"

    $LoopbackOutputDir = Join-Path $OutputDir "loopback"
    New-Item $LoopbackOutputDir -ItemType Directory -Force | Out-Null

    $apipaInterfaces = $null
    Write-Host $SkipAPIPA
    if ($IsWindows -and !$SkipAPIPA) {
        $apipaAddr = Get-NetIPAddress 169.254.*
        if ($null -ne $apipaAddr) {
            # Disable all the APIPA interfaces for URO perf.
            Write-Debug "Temporarily disabling APIPA interfaces"
            $apipaInterfaces = (Get-NetAdapter -InterfaceIndex $apipaAddr.InterfaceIndex) | where {$_.AdminStatus -eq "Up"}
            $apipaInterfaces | Disable-NetAdapter -Confirm:$false
        }
    }

    $ServerDir = $Artifacts
    if ($PGO) {
        # PGO needs the server and client executing out of separate directories.
        $ServerDir = "$($Artifacts)_server"
        New-Item -Path $ServerDir -ItemType Directory -Force | Out-Null
        Copy-Item "$Artifacts\*" $ServerDir
    }

    if ($Record) {
        # Start collecting performance information.
        if ($IsWindows) {
            wpr.exe -start $WpaStackWalkProfile -filemode
        }
    }

    $allRunsResults = @()
    $serverOutput = $null
    try {

        # Start the server.
        $proc = Start-Background-Executable -File (Join-Path $ServerDir $QuicPing) -Arguments $ServerArgs
        Start-Sleep 4

        try {
            1..$Runs | ForEach-Object {
                $clientOutput = Run-Foreground-Executable -File (Join-Path $Artifacts $QuicPing) -Arguments $ClientArgs
                $parsedRunResult = Parse-Loopback-Results -Results $clientOutput
                $allRunsResults += $parsedRunResult
                if ($PGO) {
                    # Merge client PGO counts.
                    Merge-PGO-Counts $Artifacts
                }
                Write-Host "Run $($_): $parsedRunResult kbps"
                $clientOutput | Write-Debug
            }

            # Stop the server.
            $serverOutput = Stop-Background-Executable -Process $proc

        } catch {
            if ($Record) {
                if ($IsWindows) {
                    wpr.exe -cancel
                }
            }
            Stop-Background-Executable -Process $proc | Write-Host
            throw
        }

    } finally {

        if ($Record) {
            # Stop the performance collection.
            if ($IsWindows) {
                Write-Host "Saving perf.etl out for publishing."
                wpr.exe -stop "$(Join-Path $LoopbackOutputDir perf.etl)"
            }
        }

        if ($PGO) {
            # Merge server PGO counts.
            Merge-PGO-Counts $ServerDir
            # Clean up server directory.
            Remove-Item $ServerDir -Recurse -Force | Out-Null
        }

        if ($null -ne $apipaInterfaces) {
            # Re-enable the interfaces we disabled earlier.
            Write-Debug "Re-enabling APIPA interfaces"
            $apipaInterfaces | Enable-NetAdapter
        }
    }

    # Print current and latest master results to console.
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

    if ($Publish -and ($CurrentCommitHash -ne $null)) {
        Write-Host "Saving results.json out for publishing."
        $Results = [TestPublishResult]::new()
        $Results.CommitHash = $CurrentCommitHash.Substring(0, 7)
        $Results.PlatformName = $Platform
        $Results.TestName = "loopback"
        $Results.IndividualRunResults = $allRunsResults

        $ResultFile = Join-Path $LoopbackOutputDir "results.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif ($Publish -and ($CurrentCommitHash -eq $null)) {
        Write-Debug "Failed to publish because of missing commit hash"
    }
}

# Run through all the test scenarios.
Run-Loopback-Test

if ($PGO) {
    Write-Host "Saving msquic.pgd out for publishing."
    Copy-Item "$Artifacts\msquic.pgd" $OutputDir
}
